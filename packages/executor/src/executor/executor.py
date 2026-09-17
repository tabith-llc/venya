# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Command execution and pipeline orchestration.

Orchestrates the full execution pipeline:
  1. Validate command against policy
  2. Retrieve secrets from server
  3. Inject credentials (memfd FDs or tmpfs mounts for sandbox)
  4. Execute command (direct subprocess OR sandbox)
  5. Capture and filter output (Stage 1 + Stage 2)
  6. Clean up (delete secrets, revoke tokens)
"""

import base64
import hashlib
import logging
import os
import re
import select
import shlex
import subprocess  # nosec B404 — executor requires subprocess to run commands
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLogger
from .bundles import SecretBundle
from .command_validator import CommandValidator
from .filter import filter_and_redact
from .injector import (
    SentinelRegistry,
    scan_open_fds,
    set_cloexec,
    strip_sentinel,
    verify_fd_whitelist,
)
from .strategies.base import InjectionResult, InjectionStrategy
from .strategies.sbx_strategy import SbxStrategy

logger = logging.getLogger("venya.executor")


@dataclass
class CommandResult:
    """Result of a command execution."""

    command: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    masked_secret_ids: list[str] = field(default_factory=list)
    output_truncated: bool = False
    original_stdout_size: int = 0
    original_stderr_size: int = 0


MAX_OUTPUT_BYTES = 262144  # 256 KB per stream
TRUNCATION_MARKER = "... [OUTPUT TRUNCATED: {n} bytes discarded]\n"

# How long to wait for sandbox commands
SBX_TIMEOUT = 3600  # 1 hour max

# Shell metacharacters that are not permitted in executor commands.
# The executor runs commands without shell interpretation (shell=False),
# so these characters are rejected outright. Users needing pipes, redirects,
# or other shell features should provide a script file.
SHELL_METACHARS = set("|;&$`(){}<>!*?\n\r")


def _validate_command_structure(command: str) -> list[str]:
    """Split command into arguments and reject shell metacharacters.

    Args:
        command: The command string to validate and split.

    Returns:
        List of command arguments from shlex.split().

    Raises:
        ValueError: If the command contains shell metacharacters or is empty.
    """
    if not command or not command.strip():
        raise ValueError("Empty command")

    if any(c in command for c in SHELL_METACHARS):
        raise ValueError(
            "Shell metacharacters are not permitted. "
            "Wrap complex commands in a script file and execute that instead."
        )

    args = shlex.split(command)
    if not args:
        raise ValueError("Empty command after parsing")

    return args


@dataclass
class Executor:
    """Main executor — orchestrates command execution pipeline.

    Uses Docker Sandboxes (sbx) microVM with tmpfs-mounted secrets
    and policy-based network access.

    NOTE: Executor processes commands sequentially. The _injection_result
    field is per-execution state that assumes one active command at a time.
    """

    command_validator: CommandValidator
    session_id: str
    injection_strategy: InjectionStrategy = field(default_factory=SbxStrategy)
    allowed_fds: set[int] = field(default_factory=lambda: {0, 1, 2})
    audit_logger: AuditLogger | None = None
    _sentinel_registry: SentinelRegistry | None = None
    http_client: Any = None  # httpx2.Client for server API calls
    config: Any = None  # ExecutorConfig for timeout access
    _injection_result: InjectionResult | None = field(init=False, default=None)
    _bundles: list[SecretBundle] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        """Validate the injection strategy before first use."""
        self.injection_strategy.validate()

    @property
    def sentinel_registry(self) -> SentinelRegistry:
        """Lazy-init sentinel registry for this session."""
        if self._sentinel_registry is None:
            self._sentinel_registry = SentinelRegistry(session_id=self.session_id)
        return self._sentinel_registry

    def execute(
        self,
        command: str,
        secrets: list[dict[str, Any]],
        env_override: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        """Execute a command with secret injection and output filtering.

        Args:
            command: The command to execute.
            secrets: List of secret dicts with 'secret_id', 'value', 'wrapped_value'.
            env_override: Environment variables to set (not for secrets).
            cwd: Working directory for the command.

        Returns:
            CommandResult with exit code, filtered output, and audit data.
        """
        # Step 1: Validate command
        is_valid, reason = self.command_validator.validate(command)
        if not is_valid:
            if self.audit_logger:
                self.audit_logger.emit("command_rejected", command=command, reason=reason)
            raise ValueError(f"Command rejected: {reason}")

        logger.info("Executing command: %s", command)
        start_time = time.time()

        # Step 2: Prepare secret injections
        injections: list[SecretBundle] = []
        try:
            injections = self._prepare_injections(secrets)

            # Audit: credential_injected
            if self.audit_logger:
                audit_data = {
                    "command": command,
                    "strategy": self.injection_strategy.name(),
                    "fd_count": len(injections),
                    "secret_ids": [s.secret_id for s in injections],
                }
                self.audit_logger.emit("credential_injected", **audit_data)

            # Step 3: Execute with injected secrets (sbx only)
            result = self._run_command_sbx(command, injections, env_override, cwd)

            # Audit: command_executed
            if self.audit_logger:
                duration_ms = (time.time() - start_time) * 1000
                self.audit_logger.emit(
                    "command_executed",
                    command=command,
                    exit_code=result.exit_code,
                    duration_ms=round(duration_ms, 2),
                )

            return result

        finally:
            # Step 4: Cleanup (always runs)
            secret_ids = [s.secret_id for s in injections]
            self._cleanup_injections()
            self.revoke_tokens(secret_ids)

    def _prepare_injections(self, secrets: list[dict[str, Any]]) -> list[SecretBundle]:
        """Prepare secret injections for all provided secrets.

        Strips sentinels, registers hashes, builds SecretBundles,
        then delegates actual injection to the strategy.

        Args:
            secrets: List of secret dicts.

        Returns:
            List of SecretBundle objects.
        """
        self._bundles = []

        for secret in secrets:
            # DB secret PKs are Integer and arrive via the relay payload as
            # JSON ints; the engine contract is str everywhere downstream
            # (SecretBundle, Stage-1 Rust filter, revoke) — normalize at the
            # API boundary. An int leaking through raised
            # TypeError: 'int' object cannot be converted to 'PyString' in
            # the filter (seen in physical e2e 2026-09-03).
            secret_id = str(secret["secret_id"])
            wrapped_value = secret.get("wrapped_value", b"")

            # Strip sentinel to get plaintext
            plaintext = strip_sentinel(wrapped_value) if wrapped_value else secret.get("value", b"")

            # Parse sentinel hash for registry
            sentinel_hash = ""
            if wrapped_value:
                match = None
                for m in re.finditer(rb"\[VENYA:([a-f0-9]{8})\]", wrapped_value):
                    match = m
                    break
                if match:
                    sentinel_hash = match.group(1).decode()
                    self.sentinel_registry.register(secret_id, sentinel_hash)

            bundle = SecretBundle(
                secret_id=secret_id,
                value=plaintext,
                wrapped_value=wrapped_value,
                hash=hashlib.sha256(plaintext).hexdigest(),
            )
            self._bundles.append(bundle)

        # Delegate actual injection to strategy
        self._injection_result = self.injection_strategy.prepare(self._bundles, self.session_id)
        logger.info(
            "Injected %d secrets via strategy '%s'",
            len(self._bundles),
            self.injection_strategy.name(),
        )

        return self._bundles

    # ================================================================
    # DIRECT EXECUTION (existing memfd path — unchanged)
    # ================================================================

    def _run_command_direct(
        self,
        command: str,
        injections: list[SecretBundle],
        env_override: dict[str, str] | None,
        cwd: str | None,
    ) -> CommandResult:
        """Run command directly via subprocess.Popen (memfd strategy).

        This is the existing execution path. Kept for backwards compat.
        """
        # Build process environment
        env = os.environ.copy()
        if env_override:
            env.update(env_override)

        # Determine FDs to pass to child process
        pass_fds: set[int] = set()
        if self._injection_result:
            pass_fds.update(self._injection_result.extra_fds)

        # Validate command structure (rejects shell metacharacters)
        args = _validate_command_structure(command)

        # Create subprocess — shell=False for security
        process = subprocess.Popen(
            args,
            shell=False,  # nosec B603 — shell explicitly disabled for security
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            start_new_session=True,
            pass_fds=pass_fds,
        )

        # Set CLOEXEC on all executor FDs to prevent leakage
        proc_fds: set[int] = {
            process.stdin.fileno() if process.stdin else -1,  # type: ignore[union-attr]
            process.stdout.fileno() if process.stdout else -1,  # type: ignore[union-attr]
            process.stderr.fileno() if process.stderr else -1,  # type: ignore[union-attr]
        }
        proc_fds.discard(-1)
        allowed = {0, 1, 2} | proc_fds
        for fd_num in scan_open_fds():
            if fd_num not in allowed:
                set_cloexec(fd_num)

        # Verify FD whitelist
        open_fds = scan_open_fds()
        unexpected = verify_fd_whitelist(open_fds, self.allowed_fds)
        if unexpected:
            logger.warning("Unexpected open FDs before exec: %s", unexpected)

        # Capture output with size limit
        stdout, stderr = self._capture_output(process)

        # Wait for process to complete
        exit_code = process.wait()

        return self._filter_and_build_result(command, exit_code, stdout, stderr, injections)

    def _capture_output(self, process: subprocess.Popen) -> tuple[bytes, bytes]:
        """Capture stdout/stderr with batch mode and size limit.

        Args:
            process: The subprocess to capture from.

        Returns:
            Tuple of (stdout, stderr) bytes, truncated if needed.
        """
        stdout_truncated = False
        stderr_truncated = False
        stdout_total = 0
        stderr_total = 0

        stdout_fd = process.stdout  # type: ignore[union-attr]
        stderr_fd = process.stderr  # type: ignore[union-attr]

        if stdout_fd is None or stderr_fd is None:
            process.wait()
            return b"", b""

        fd_map = {stdout_fd.fileno(): "stdout", stderr_fd.fileno(): "stderr"}
        chunk_buffers: dict[int, bytearray] = {
            stdout_fd.fileno(): bytearray(),
            stderr_fd.fileno(): bytearray(),
        }
        fd_active: dict[int, bool] = {stdout_fd.fileno(): True, stderr_fd.fileno(): True}

        deadline = time.time() + SBX_TIMEOUT

        while any(fd_active.values()):
            if time.time() > deadline:
                logger.warning("Output capture timed out after %d seconds", SBX_TIMEOUT)
                break

            readable_fds = [fd for fd, active in fd_active.items() if active]
            if not readable_fds:
                break

            try:
                readable, _, _ = select.select(readable_fds, [], [], 1.0)
            except OSError:
                break

            if not readable:
                # Timeout — check if process is still running
                if process.poll() is not None:
                    break
                continue

            for fd in readable:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    fd_active[fd] = False
                    continue

                if not chunk:
                    # EOF
                    fd_active[fd] = False
                    continue

                buf = chunk_buffers[fd]
                stream_name = fd_map[fd]

                if stream_name == "stdout":
                    stdout_total += len(chunk)
                else:
                    stderr_total += len(chunk)

                if len(buf) + len(chunk) > MAX_OUTPUT_BYTES:
                    remaining = MAX_OUTPUT_BYTES - len(buf)
                    if remaining > 0:
                        buf.extend(chunk[:remaining])
                    if stream_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    fd_active[fd] = False
                else:
                    buf.extend(chunk)

        stdout = bytes(chunk_buffers[stdout_fd.fileno()])
        stderr = bytes(chunk_buffers[stderr_fd.fileno()])

        # Apply truncation markers
        if stdout_truncated and stdout:
            discarded = max(0, stdout_total - MAX_OUTPUT_BYTES)
            marker = TRUNCATION_MARKER.format(discarded).encode()
            stdout = stdout[:MAX_OUTPUT_BYTES] + marker
        if stderr_truncated and stderr:
            discarded = max(0, stderr_total - MAX_OUTPUT_BYTES)
            marker = TRUNCATION_MARKER.format(discarded).encode()
            stderr = stderr[:MAX_OUTPUT_BYTES] + marker

        return stdout, stderr

    # ================================================================
    # SBX SANDBOX EXECUTION
    # ================================================================

    def _run_command_sbx(
        self,
        command: str,
        injections: list[SecretBundle],
        env_override: dict[str, str] | None,
        cwd: str | None,
    ) -> CommandResult:
        """Run command inside a Docker Sandbox (microVM).

        Key security properties:
        - Network egress controlled by allowlist file via sbx policy
        - Secrets are copied into sandbox via sbx cp (tmpfs-backed)
        - Sandbox provides hypervisor isolation (separate kernel)
        - stdout/stderr captured from sbx exec output

        Args:
            command: The command to execute inside the sandbox.
            injections: Secret bundles (for filtering reference).
            env_override: Environment variables to set.
            cwd: Working directory (sandbox uses its workspace).

        Returns:
            CommandResult with filtered output.
        """
        if not isinstance(self.injection_strategy, SbxStrategy):
            raise TypeError(f"SBX strategy required but got: {type(self.injection_strategy).__name__}")

        strategy = self.injection_strategy
        session_uuid = uuid.uuid4().hex[:12]
        sandbox_name = f"venya-{self.session_id}-{session_uuid}"

        # Create the sandbox. When cwd is None the strategy creates a
        # per-run disk-backed workspace (a missing path makes sbx create
        # prompt and fail with "user cancelled operation" in a non-TTY
        # subprocess).
        logger.info("Creating Docker Sandbox: %s", sandbox_name)
        strategy.create_sandbox(sandbox_name, cwd)

        # Copy secrets into sandbox
        if self._injection_result:
            strategy.copy_secrets_into_sandbox(self._injection_result.secret_mounts)

        # Apply network policy from allowlist file
        strategy.apply_network_policy(sandbox_name)

        try:
            # Execute command inside sandbox
            logger.info("Executing in sandbox: %s", command)
            result = strategy.execute_command(command)

            stdout = result.stdout[:MAX_OUTPUT_BYTES]
            stderr = result.stderr[:MAX_OUTPUT_BYTES]

            logger.info(
                "Sandbox command exited: code=%d, stdout=%d bytes, stderr=%d bytes",
                result.returncode,
                len(stdout),
                len(stderr),
            )

            # Stage 1 + Stage 2 filtering (same as direct path)
            return self._filter_and_build_result(command, result.returncode, stdout, stderr, injections)

        except subprocess.TimeoutExpired:
            logger.error("Sandbox command timed out after %d seconds", SBX_TIMEOUT)
            return CommandResult(
                command=command,
                exit_code=-1,
                stdout=b"",
                stderr=f"Command timed out after {SBX_TIMEOUT} seconds".encode(),
            )
        except Exception:
            logger.exception("Sandbox execution failed")
            raise
        finally:
            # Always remove the sandbox
            strategy.remove_sandbox()

    # ================================================================
    # SHARED FILTERING (used by both execution paths)
    # ================================================================

    def _filter_and_build_result(
        self,
        command: str,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
        injections: list[SecretBundle],
    ) -> CommandResult:
        """Run Stage 1 + Stage 2 filtering and build CommandResult.

        This is the shared post-processing path for both direct subprocess
        and sandbox execution. The filtering logic is identical
        regardless of how the process was launched.

        Args:
            command: Original command string.
            exit_code: Process exit code.
            stdout: Raw stdout bytes.
            stderr: Raw stderr bytes.
            injections: Secret bundles for filtering reference.

        Returns:
            CommandResult with filtered output.
        """
        # Stage 1: Local filtering (Rust extension) — needs raw value for matching
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            stdout,
            stderr,
            [{"secret_id": s.secret_id, "value": s.value} for s in injections],
        )

        all_masked_ids = sorted(set(stdout_ids + stderr_ids))

        # Stage 2: Server-side definitive filtering
        stage2_stdout = masked_stdout
        stage2_stderr = masked_stderr
        stage2_masked_ids = all_masked_ids

        if self.http_client is not None:
            try:
                stage2_stdout, stage2_stderr, stage2_masked_ids = self._send_to_stage2(
                    stdout,
                    stderr,
                    [{"secret_id": s.secret_id, "hash": s.hash} for s in injections],
                )
            except Exception:
                logger.exception("Stage 2 filter failed — using Stage 1 results")

        stdout_truncated = len(stdout) > MAX_OUTPUT_BYTES
        stderr_truncated = len(stderr) > MAX_OUTPUT_BYTES

        logger.info(
            "Command exited with code %d, %d secrets masked",
            exit_code,
            len(stage2_masked_ids),
        )

        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stage2_stdout,
            stderr=stage2_stderr,
            masked_secret_ids=stage2_masked_ids,
            output_truncated=stdout_truncated or stderr_truncated,
            original_stdout_size=len(stdout),
            original_stderr_size=len(stderr),
        )

    # ================================================================
    # CLEANUP (unchanged)
    # ================================================================

    def _cleanup_injections(self) -> None:
        """Clean up all secret injections.

        Runs strategy cleanup functions, zeros secret values, clears registry.
        """
        if self._injection_result:
            self._injection_result.cleanup()
            self._injection_result = None

        # Zero secret values in all bundles
        for bundle in self._bundles:
            if bundle.value:
                bundle.value = b"\x00" * len(bundle.value)

        # Clear sentinel registry for this session
        if self._sentinel_registry:
            self._sentinel_registry.clear()

        logger.info("Cleanup complete")

    def revoke_tokens(self, secret_ids: list[str]) -> None:
        """Revoke tokens for given secrets.

        Called after execution to revoke short-lived scoped credentials.

        Args:
            secret_ids: List of secret IDs to revoke.
        """
        if not secret_ids:
            return

        if self.http_client is None:
            logger.warning(
                "No HTTP client available — skipping server token revocation for %d secrets",
                len(secret_ids),
            )
            return

        try:
            timeout = self.config.network.request_timeout_seconds if self.config else 10
            self.http_client.post(
                f"/api/v1/sessions/{self.session_id}/secrets/revoke",
                json={"secret_ids": secret_ids},
                timeout=timeout,
            )
            logger.info(
                "Revoked tokens for %d secrets in session %s",
                len(secret_ids),
                self.session_id,
            )
        except Exception:
            logger.exception(
                "Failed to revoke tokens for secrets in session %s",
                self.session_id,
            )
            if self.audit_logger:
                self.audit_logger.emit(
                    "token_revocation_failed",
                    session_id=self.session_id,
                    secret_ids=secret_ids,
                )

    def _send_to_stage2(
        self,
        stdout: bytes,
        stderr: bytes,
        secret_entries: list[dict[str, Any]],
    ) -> tuple[bytes, bytes, list[str]]:
        """Send captured output to Stage 2 server-side filter.

        Args:
            stdout: Raw stdout bytes.
            stderr: Raw stderr bytes.
            secret_entries: List of secret dicts for session context.

        Returns:
            Tuple of (filtered_stdout, filtered_stderr, masked_secret_ids).

        Raises:
            Exception: If server communication fails.
        """
        payload = {
            "stdout": base64.b64encode(stdout).decode(),
            "stderr": base64.b64encode(stderr).decode(),
            "secrets": secret_entries,
        }

        timeout = self.config.network.request_timeout_seconds if self.config else 30
        response = self.http_client.post(
            f"/api/v1/sessions/{self.session_id}/filter",
            json=payload,
            timeout=timeout,
        )
        data = response.json()

        filtered_stdout = base64.b64decode(data["stdout"])
        filtered_stderr = base64.b64decode(data["stderr"])
        masked_ids = sorted(set(data.get("masked_hashes", [])))

        return filtered_stdout, filtered_stderr, masked_ids
