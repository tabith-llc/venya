"""Command execution and pipeline orchestration.

Orchestrates the full execution pipeline:
  1. Validate command against policy
  2. Retrieve secrets from server
  3. Inject credentials (memfd FDs or tmpfs mounts for gVisor)
  4. Execute command (direct subprocess OR gVisor sandbox)
  5. Capture and filter output (Stage 1 + Stage 2)
  6. Clean up (delete secrets, revoke tokens)
"""

from __future__ import annotations

import base64
import logging
import os
import re
import select
import subprocess
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
from .strategies.base import InjectionResult, InjectionStrategy, SecretMount
from .strategies.gvisor_strategy import GvisorStrategy
from .strategies.memfd_strategy import MemfdStrategy

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

# gVisor container image — minimal, no network tools
GVISOR_IMAGE = "venya-executor:minimal"

# How long to wait for a container to finish
CONTAINER_TIMEOUT = 3600  # 1 hour max


@dataclass
class Executor:
    """Main executor — orchestrates command execution pipeline.

    Supports two execution modes:
    - memfd: Direct subprocess with FD-passed secrets (existing behavior)
    - gvisor: gVisor-sandboxed Docker container with tmpfs-mounted secrets
              and no network access

    The mode is determined by the injection strategy's name().

    NOTE: Executor processes commands sequentially. The _injection_result
    field is per-execution state that assumes one active command at a time.
    """

    command_validator: CommandValidator
    session_id: str
    injection_strategy: InjectionStrategy = field(default_factory=MemfdStrategy)
    allowed_fds: set[int] = field(default_factory=lambda: {0, 1, 2})
    audit_logger: AuditLogger | None = None
    _sentinel_registry: SentinelRegistry | None = None
    http_client: Any = None  # httpx.Client for server API calls
    _injection_result: InjectionResult | None = field(init=False, default=None)
    _bundles: list[SecretBundle] = field(init=False, default_factory=list)
    _egress_chain_name: str | None = field(init=False, default=None)

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
                self.audit_logger.emit(
                    "credential_injected",
                    command=command,
                    strategy=self.injection_strategy.name(),
                    fd_count=len(injections),
                    secret_ids=[s.secret_id for s in injections],
                )

            # Step 3: Execute with injected secrets
            # Branch based on strategy type
            if self.injection_strategy.name() == "gvisor":
                result = self._run_command_gvisor(
                    command, injections, env_override, cwd
                )
            else:
                result = self._run_command_direct(
                    command, injections, env_override, cwd
                )

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
            secret_id = secret["secret_id"]
            wrapped_value = secret.get("wrapped_value", b"")

            # Strip sentinel to get plaintext
            plaintext = strip_sentinel(wrapped_value) if wrapped_value else secret.get("value", b"")

            # Parse sentinel hash for registry
            sentinel_hash = ""
            if wrapped_value:
                match = None
                for m in re.finditer(
                    rb"\[VENYA:([a-f0-9]{8})\]", wrapped_value
                ):
                    match = m
                    break
                if match:
                    sentinel_hash = match.group(1).decode()
                    self.sentinel_registry.register(secret_id, sentinel_hash)

            bundle = SecretBundle(
                secret_id=secret_id,
                value=plaintext,
                wrapped_value=wrapped_value,
            )
            self._bundles.append(bundle)

        # Delegate actual injection to strategy
        self._injection_result = self.injection_strategy.prepare(self._bundles)
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

        # Create subprocess
        process = subprocess.Popen(
            command,
            shell=True,
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

        # Stage 1: Local filtering
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
                    [{"secret_id": s.secret_id, "value": s.value} for s in injections],
                )
            except Exception:
                logger.exception("Stage 2 filter failed — using Stage 1 results")

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
            output_truncated=(len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES),
            original_stdout_size=len(stdout),
            original_stderr_size=len(stderr),
        )

    def _capture_output(self, process: subprocess.Popen) -> tuple[bytes, bytes]:
        """Capture stdout/stderr with batch mode and size limit.

        Args:
            process: The subprocess to capture from.

        Returns:
            Tuple of (stdout, stderr) bytes, truncated if needed.
        """
        stdout_truncated = False
        stderr_truncated = False

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

        while any(fd_active.values()):
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

                if len(chunk) > MAX_OUTPUT_BYTES:
                    buf.extend(chunk[:MAX_OUTPUT_BYTES])
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
            marker = TRUNCATION_MARKER.format(len(stdout) - MAX_OUTPUT_BYTES).encode()
            stdout = stdout[:MAX_OUTPUT_BYTES] + marker
        if stderr_truncated and stderr:
            marker = TRUNCATION_MARKER.format(len(stderr) - MAX_OUTPUT_BYTES).encode()
            stderr = stderr[:MAX_OUTPUT_BYTES] + marker

        return stdout, stderr

    # ================================================================
    # gVisor SANDBOX EXECUTION (new path)
    # ================================================================

    def _run_command_gvisor(
        self,
        command: str,
        injections: list[SecretBundle],
        env_override: dict[str, str] | None,
        cwd: str | None,
        allowed_hosts: list[dict[str, Any]] | None = None,
    ) -> CommandResult:
        """Run command inside a gVisor-sandboxed Docker container.

        Key security properties:
        - When allowed_hosts is None/empty: network_mode="none" (no network)
        - When allowed_hosts is provided: bridge network + iptables egress whitelist
        - Secrets are mounted as read-only tmpfs files
        - gVisor's Sentry intercepts syscalls (no direct host kernel access)
        - stdout/stderr are captured from container logs

        Args:
            command: The command to execute inside the container.
            injections: Secret bundles (for filtering reference).
            env_override: Environment variables to set.
            cwd: Working directory (mapped into container).
            allowed_hosts: List of {host, port} dicts for egress whitelist.

        Returns:
            CommandResult with filtered output.
        """
        import docker  # type: ignore[import-not-found]

        # Build volume mounts for secrets
        secret_mounts: list[SecretMount] = []
        if self._injection_result:
            secret_mounts = self._injection_result.secret_mounts

        volumes: dict[str, dict[str, str]] = {}
        for mount in secret_mounts:
            volumes[mount.path] = {
                "bind": mount.container_path,
                "mode": "ro",
            }

        # Build environment (excluding secrets — they come from files)
        container_env: list[str] = []
        if env_override:
            for k, v in env_override.items():
                container_env.append(f"{k}={v}")

        # Connect to Docker daemon (needed for network creation)
        client = docker.from_env()

        # Determine network mode
        network_mode: str | Any = "none"
        docker_network = None
        session_uuid = uuid.uuid4().hex

        if allowed_hosts:
            network_name = f"venya-net-{session_uuid}"
            logger.info("Creating Docker network: %s", network_name)
            docker_network = client.networks.create(network_name, driver="bridge")
            network_mode = docker_network.name  # SDK expects string
        else:
            logger.info("No allowed_hosts — using network_mode=none")

        # Unique container name for this session
        container_name = f"venya-{self.session_id}-{session_uuid}"

        if allowed_hosts:
            logger.info(
                "Launching gVisor container: name=%s, mounts=%d, network=%s, allowed_hosts=%d",
                container_name,
                len(secret_mounts),
                network_mode,
                len(allowed_hosts),
            )
        else:
            logger.info(
                "Launching gVisor container: name=%s, mounts=%d, network=none",
                container_name,
                len(secret_mounts),
            )

        # Track resources so cleanup can remove them
        container = None

        try:
            # Launch container with gVisor runtime
            container = client.containers.run(
                image=GVISOR_IMAGE,
                runtime="runsc",          # gVisor sandbox
                command=["sh", "-c", command],
                name=container_name,
                detach=True,
                stdin_open=False,
                tty=False,
                network_mode=network_mode,
                volumes=volumes,
                environment=container_env,
                working_dir=cwd or "/work",
                auto_remove=False,        # We'll remove manually after capturing logs
                mem_limit="512m",         # Prevent resource exhaustion
                cpu_quota=100000,         # 1 CPU max
                pids_limit=100,           # Prevent fork bombs
                read_only=False,          # Need writable /tmp inside container
                tmpfs={"/tmp": "size=64m,mode=1777"},  # Writable tmpfs inside container
            )

            # Apply egress rules if allowed_hosts was provided
            if allowed_hosts and docker_network:
                self._apply_egress_rules(allowed_hosts, docker_network.name, session_uuid)

            # Wait for container to finish
            result = container.wait(timeout=CONTAINER_TIMEOUT)
            exit_code = result.get("StatusCode", -1)

            # Capture stdout/stderr from container logs
            stdout, stderr = self._capture_container_output(container)

            logger.info(
                "gVisor container exited: code=%d, stdout=%d bytes, stderr=%d bytes",
                exit_code,
                len(stdout),
                len(stderr),
            )

            # Stage 1 + Stage 2 filtering (same as direct path)
            return self._filter_and_build_result(
                command, exit_code, stdout, stderr, injections
            )

        except docker.errors.ContainerError as e:
            logger.error("gVisor container error: %s", e)
            return CommandResult(
                command=command,
                exit_code=-1,
                stdout=b"",
                stderr=str(e).encode(),
            )
        except docker.errors.ImageNotFound:
            logger.error("Container image not found: %s", GVISOR_IMAGE)
            raise RuntimeError(
                f"Container image {GVISOR_IMAGE} not found. "
                f"Build it with: docker build -t {GVISOR_IMAGE} ."
            )
        except Exception as e:
            logger.exception("gVisor execution failed")
            raise
        finally:
            # Always remove the container
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.warning("Failed to remove container %s", container_name)

            # Clean up Docker network if created
            if docker_network is not None:
                try:
                    docker_network.remove()
                    logger.info("Removed Docker network: %s", docker_network.name)
                except Exception:
                    logger.warning("Failed to remove network %s", docker_network.name)

            # Clean up iptables egress rules
            self._cleanup_egress_rules()

    def _apply_egress_rules(
        self,
        allowed_hosts: list[dict[str, Any]],
        network_name: str,
        session_uuid: str,
    ) -> None:
        """Apply iptables egress rules for gVisor container network.

        Creates a unique iptables chain with:
        1. ACCEPT rules for DNS (UDP/TCP port 53)
        2. ACCEPT rules for each allowed host:port
        3. DROP ALL as default policy

        The chain is attached to the Docker bridge's FORWARD chain.

        Args:
            allowed_hosts: List of {host, port} dicts for allowed destinations.
            network_name: Docker network name (used to derive bridge interface).
            session_uuid: UUID for unique chain naming.

        Raises:
            RuntimeError: If iptables commands fail.
        """
        chain_name = f"VENYA_EGRESS_{session_uuid}"
        bridge_name = f"br-{network_name[:12]}"

        commands = [
            # Create chain
            ["iptables", "-N", chain_name],
            # DNS rules (UDP + TCP port 53)
            ["iptables", "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ]

        # Add rules for each allowed host
        for host in allowed_hosts:
            host_ip = host["host"]
            host_port = host["port"]
            commands.append([
                "iptables", "-A", chain_name,
                "-d", host_ip,
                "-p", "tcp",
                "--dport", str(host_port),
                "-j", "ACCEPT",
            ])

        # Default DROP all
        commands.append(["iptables", "-A", chain_name, "-j", "DROP"])

        # Attach chain to FORWARD
        commands.append([
            "iptables", "-I", "FORWARD",
            "-o", bridge_name,
            "-j", chain_name,
        ])

        # Execute all commands
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    self._egress_chain_name = None
                    raise RuntimeError(
                        f"iptables failed: {' '.join(cmd)}: {result.stderr.decode()}"
                    )
            except subprocess.CalledProcessError as e:
                self._egress_chain_name = None
                raise RuntimeError(
                    f"iptables egress rule failed: {' '.join(e.cmd)}: {e.stderr.decode()}"
                ) from e
            except subprocess.TimeoutExpired:
                self._egress_chain_name = None
                raise RuntimeError(
                    f"iptables timed out: {' '.join(cmd)}"
                )

        self._egress_chain_name = chain_name
        logger.info("Applied egress rules: chain=%s, hosts=%d", chain_name, len(allowed_hosts))

    def _cleanup_egress_rules(self) -> None:
        """Clean up iptables egress rules.

        Flushes the chain and removes it. No-op if no chain was created.
        """
        if not self._egress_chain_name:
            return

        try:
            subprocess.run(
                ["iptables", "-F", self._egress_chain_name],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["iptables", "-X", self._egress_chain_name],
                capture_output=True,
                timeout=10,
            )
            logger.info("Cleaned up egress rules: chain=%s", self._egress_chain_name)
        except subprocess.SubprocessError:
            logger.warning("Failed to clean up egress rules: chain=%s", self._egress_chain_name)
        finally:
            self._egress_chain_name = None

    def _capture_container_output(self, container: Any) -> tuple[bytes, bytes]:
        """Capture stdout and stderr from a Docker container.

        Docker combines stdout/stderr in logs when tty=False.
        We separate them using the stream attribute.

        Args:
            container: Docker container object.

        Returns:
            Tuple of (stdout_bytes, stderr_bytes).
        """
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        try:
            logs = container.logs(stream=True, follow=False)
            for chunk in logs:
                # Docker log entries have an 8-byte header when stream=True
                # First byte indicates stream: 1=stdout, 2=stderr
                if len(chunk) > 8 and chunk[0:1] in (b"\x01", b"\x02"):
                    payload = chunk[8:]
                    if chunk[0:1] == b"\x01":
                        stdout_chunks.append(payload)
                    else:
                        stderr_chunks.append(payload)
                else:
                    # No header — treat as stdout
                    stdout_chunks.append(chunk)
        except Exception:
            logger.warning("Failed to capture container logs", exc_info=True)

        stdout = b"".join(stdout_chunks)[:MAX_OUTPUT_BYTES]
        stderr = b"".join(stderr_chunks)[:MAX_OUTPUT_BYTES]

        return stdout, stderr

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
        and gVisor container execution. The filtering logic is identical
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
        # Stage 1: Local filtering (Rust extension)
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
                    [{"secret_id": s.secret_id, "value": s.value} for s in injections],
                )
            except Exception:
                logger.exception("Stage 2 filter failed — using Stage 1 results")

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
            output_truncated=(
                len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES
            ),
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
            self.http_client.post(
                f"/api/v1/sessions/{self.session_id}/secrets/revoke",
                json={"secret_ids": secret_ids},
                timeout=10.0,
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

        response = self.http_client.post(
            f"/api/v1/sessions/{self.session_id}/filter",
            json=payload,
            timeout=30.0,
        )
        data = response.json()

        filtered_stdout = base64.b64decode(data["stdout"])
        filtered_stderr = base64.b64decode(data["stderr"])
        masked_ids = sorted(set(data.get("masked_hashes", [])))

        return filtered_stdout, filtered_stderr, masked_ids
