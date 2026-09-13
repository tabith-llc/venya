"""Docker Sandboxes (sbx) injection strategy.

Uses Docker's sbx CLI to create microVM sandboxes with
hypervisor-level isolation and built-in network policies.

Secrets are written to host tmpfs (/dev/shm) and injected into
the sandbox over stdin (`sbx exec -i ... tee`) so the in-sandbox
file is owned by the secret-reading user. Network access is
restricted via `sbx policy allow/deny` rules.

For HTTP-based API keys, `sbx secret set` can be used to have
the proxy inject credentials into HTTP headers — the raw value
never enters the VM.
"""

import logging
import os
import shutil
import subprocess  # nosec B404 — sandbox strategy requires subprocess for sbx commands
import tempfile
from collections.abc import Callable
from pathlib import Path

from .base import InjectionResult, InjectionStrategy, SecretMount

logger = logging.getLogger("venya.executor.strategies.sbx")

# tmpfs base on host — secrets never touch disk
SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"  # nosec

# Disk-backed base for per-run sandboxes' host workspace. Must NOT be tmpfs
# (/dev/shm): sbx bind-mounts the workspace into the microVM via virtio-fs,
# which cannot share a tmpfs path ("workspace ... was not mounted into the
# sandbox"). Ephemeral, non-secret, deleted per-run and swept on daemon start.
WORKSPACE_BASE = str(Path.home() / ".venya-workspaces")  # nosec

# Where secrets appear inside the sandbox. The shell agent runs as non-root
# (uid 1000) and /run is root-owned, so the dir must live under the image's
# 1777 /run/secrets.
CONTAINER_SECRET_DIR = "/run/secrets/venya"  # nosec

# How long to wait for sandbox commands
SBX_TIMEOUT = 3600  # 1 hour

# How long to wait for the agent-template pull + microVM create (`sbx create`).
# Measured (2026-09-02, fast uplink): cold *first-ever* pull of the multi-GB
# `shell-docker` template = 65s; warm (cached) create = ~5.5s. Held **inside** the
# core's relay read budget (executors.py `httpx2.AsyncClient(timeout=300)`) so a slow
# pull times out on the executor with a precise local error before the core's connection
# timeout fires and leaves a doomed create running orphaned in the executor daemon.
# Override per-network: `VENYA_SBX_CREATE_TIMEOUT` (seconds). Durable fix (pre-pull the
# template at enrollment) is tracked in `venya-dev/tickets/sbx-cold-start-prepull.md`.
SBX_CREATE_TIMEOUT = 240


def sweep_workspace_base(base: str = WORKSPACE_BASE) -> int:
    """Delete orphaned ws_* workspace directories from dead daemon runs.

    The host workspace base survives daemon kills and reboots but sandboxes
    never do, so at daemon start every ws_* directory in the base is by
    definition an orphan.
    Unconditional sweep is safe: nothing but this package creates ws_* dirs
    there (alpha deployment: one executor daemon per host). Best-effort —
    failures are logged, not raised.
    """
    swept = 0
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
        for entry in os.listdir(base):
            path = os.path.join(base, entry)
            if entry.startswith("ws_") and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                swept += 1
    except OSError:
        logger.exception("Failed to sweep workspace base: %s", base)
    return swept


class SbxStrategy(InjectionStrategy):
    """Docker Sandboxes strategy using microVM isolation.

    Creates a Docker Sandbox (microVM with separate kernel) for
    each command execution. Secrets are written to host tmpfs and
    injected into the sandbox over stdin (`sbx exec -i ... tee`).
    Network access is controlled via `sbx policy` rules
    (deny-by-default).

    Key properties:
    - Hypervisor isolation (separate kernel per sandbox)
    - Network: SOCKS5 proxy with policy-based allow/deny
    - Secrets: tmpfs on host -> stdin-tee into sandbox (RAM-backed)
    - Cleanup: sandbox destroyed, tmpfs deleted, secrets zeroed
    """

    def __init__(self, secret_base_fd: int = 100) -> None:
        self.secret_base_fd = secret_base_fd
        self._session_dir: str | None = None
        self._sandbox_name: str | None = None
        self._workspace_dir: str | None = None

    def name(self) -> str:
        return "sbx"

    def validate(self) -> None:
        """Check that sbx CLI is installed."""
        if shutil.which("sbx") is None:
            raise RuntimeError(
                "sbx CLI not found. Install with: "
                "curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && "
                "sudo apt-get install docker-sbx && "
                "sudo usermod -aG kvm $USER && newgrp kvm"
            )

    def prepare(self, secrets: list) -> InjectionResult:
        """Write secrets to host tmpfs.

        Each secret is written to:
            /dev/shm/venya-secrets/{session_uuid}/{secret_id}

        And will be copied into the sandbox at:
            /run/secrets/venya/{secret_id}

        The sandbox is NOT created here — that happens in the executor.

        Args:
            secrets: List of SecretBundle objects.

        Returns:
            InjectionResult with secret mounts and cleanup functions.
        """
        # Create unique session directory on tmpfs (base is self-provisioned —
        # a fresh install has no /dev/shm/venya-secrets)
        os.makedirs(SECRET_TMPFS_BASE, mode=0o700, exist_ok=True)
        self._session_dir = tempfile.mkdtemp(prefix="session_", dir=SECRET_TMPFS_BASE)
        os.chmod(self._session_dir, 0o700)

        mounts: list[SecretMount] = []
        cleanup_funcs: list[Callable[[], None]] = []

        for bundle in secrets:
            secret_path = os.path.join(self._session_dir, str(bundle.secret_id))

            # Write secret to tmpfs file
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT, 0o400)
            try:
                os.write(fd, bundle.value)
            finally:
                os.close(fd)

            # Lock down permissions
            os.chmod(secret_path, 0o400)

            mount = SecretMount(
                secret_id=bundle.secret_id,
                path=secret_path,
                container_path=f"{CONTAINER_SECRET_DIR}/{bundle.secret_id}",
            )
            mounts.append(mount)

            logger.debug(
                "Wrote secret %s to tmpfs: %s -> %s",
                bundle.secret_id,
                secret_path,
                mount.container_path,
            )

        # Cleanup: remove entire session directory from tmpfs
        session_dir = self._session_dir

        def _cleanup():
            if session_dir and os.path.exists(session_dir):
                shutil.rmtree(session_dir, ignore_errors=True)
                logger.debug("Cleaned up tmpfs session dir: %s", session_dir)

        cleanup_funcs.append(_cleanup)

        return InjectionResult(
            extra_fds=[],  # No FDs — using file copies instead
            secret_mounts=mounts,
            cleanup_funcs=cleanup_funcs,
        )

    def create_sandbox(self, sandbox_name: str, workspace: str | None = None) -> None:
        """Create a Docker Sandbox (microVM).

        Args:
            sandbox_name: Unique name for the sandbox.
            workspace: Host directory to mount as the sandbox workspace.
                When None, a per-run directory is created under
                WORKSPACE_BASE and tracked in self._workspace_dir so
                remove_sandbox deletes it. Ownership rule: the strategy
                deletes only what it created — a caller-supplied workspace
                is always passed through untouched and never deleted.
        """
        created_workspace = False
        if workspace is None:
            # Existing path is mandatory: sbx create prompts interactively
            # ("create it? (y/N)") for a missing workspace, which reads EOF
            # in a non-TTY subprocess and fails with "user cancelled operation".
            os.makedirs(WORKSPACE_BASE, mode=0o700, exist_ok=True)
            workspace = tempfile.mkdtemp(prefix="ws_", dir=WORKSPACE_BASE)
            self._workspace_dir = workspace
            created_workspace = True

        cmd = ["sbx", "create", "--name", sandbox_name, "shell", workspace]
        create_timeout = int(os.environ.get("VENYA_SBX_CREATE_TIMEOUT", SBX_CREATE_TIMEOUT))
        result = subprocess.run(  # nosec
            cmd,
            capture_output=True,
            text=True,
            timeout=create_timeout,
            check=False,
        )
        if result.returncode != 0:
            logger.error("sbx create failed: %s", result.stderr)
            if created_workspace:
                shutil.rmtree(workspace, ignore_errors=True)
                self._workspace_dir = None
            raise RuntimeError(f"Failed to create sandbox: {result.stderr}")

        self._sandbox_name = sandbox_name
        logger.info("Created Docker Sandbox: %s", sandbox_name)
        self._copy_sshpass(sandbox_name)

    def _copy_sshpass(self, sandbox_name: str) -> None:
        """Copy sshpass binary into the sandbox (no-op if not on host)."""
        host_sshpass = shutil.which("sshpass")
        if not host_sshpass:
            logger.debug("sshpass not found on host; skipping sandbox copy")
            return
        with open(host_sshpass, "rb") as fh:
            binary = fh.read()
        result = subprocess.run(  # nosec
            ["sbx", "exec", "-i", sandbox_name, "tee", "/usr/local/bin/sshpass"],
            input=binary,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("Failed to copy sshpass into sandbox: %s", result.stderr)
            return
        subprocess.run(  # nosec
            ["sbx", "exec", sandbox_name, "chmod", "+x", "/usr/local/bin/sshpass"],
            capture_output=True,
            timeout=5,
            check=False,
        )

    def copy_secrets_into_sandbox(self, mounts: list[SecretMount]) -> None:
        """Copy secrets from host tmpfs into the sandbox.

        Args:
            mounts: List of SecretMount objects with host and container paths.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        # Create secrets directory inside sandbox. Fail-closed: a swallowed
        # mkdir failure surfaces later as an opaque tee execution error.
        mkdir_result = subprocess.run(  # nosec
            ["sbx", "exec", self._sandbox_name, "mkdir", "-p", CONTAINER_SECRET_DIR],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if mkdir_result.returncode != 0:
            logger.error(
                "mkdir %s in sandbox %s failed: %s",
                CONTAINER_SECRET_DIR,
                self._sandbox_name,
                mkdir_result.stderr,
            )
            raise RuntimeError(f"Failed to create secrets directory {CONTAINER_SECRET_DIR} in sandbox")

        copied_paths: list[str] = []
        for mount in mounts:
            container_path = mount.container_path

            # Pipe the secret over stdin to `tee`: the file is created as the
            # sandbox exec user (uid 1000) and so stays readable by the command
            # that runs as uid 1000. `sbx cp` would tar-preserve the host uid
            # (the daemon user), leaving a 0400 file the uid-1000 runner cannot
            # open. stdin (not argv) keeps the secret out of process listings.
            with open(mount.path, "rb") as fh:
                secret_bytes = fh.read()
            result = subprocess.run(  # nosec
                ["sbx", "exec", "-i", self._sandbox_name, "tee", container_path],
                input=secret_bytes,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                logger.error(
                    "inject secret %s into sandbox failed: %s",
                    mount.secret_id,
                    (result.stderr or b"").decode(errors="replace"),
                )
                for copied in copied_paths + [container_path]:
                    subprocess.run(  # nosec
                        ["sbx", "exec", self._sandbox_name, "rm", "-f", copied],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                raise RuntimeError(f"Failed to copy secret {mount.secret_id} into sandbox")

            copied_paths.append(container_path)

            # Set read-only permissions inside sandbox. Fail-closed (L-65): if
            # chmod fails, roll back everything copied and abort — a secret left
            # at default perms (potentially world-readable) must not be injected.
            chmod_result = subprocess.run(  # nosec
                ["sbx", "exec", self._sandbox_name, "chmod", "400", container_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if chmod_result.returncode != 0:
                logger.error("sbx chmod failed for %s: %s", mount.secret_id, chmod_result.stderr)
                for copied in copied_paths:
                    subprocess.run(  # nosec
                        ["sbx", "exec", self._sandbox_name, "rm", "-f", copied],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                raise RuntimeError(f"Failed to set read-only permissions on secret {mount.secret_id} in sandbox")

            logger.debug("Copied secret %s into sandbox: %s", mount.secret_id, container_path)

    def apply_network_policy(self, sandbox_name: str) -> None:
        """Apply egress allowlist to sandbox.

        Reads /etc/venya/egress-allowlist.txt and allows each entry
        via sbx policy allow network <host>. DNS resolver is always allowed.

        Missing/empty allowlist -> only DNS resolver allowed (fail-closed).

        Args:
            sandbox_name: Name of the sandbox to apply policies to.
        """
        from ..egress_filter import EgressFilter

        # Use default config values if no config available
        egress_path = "/etc/venya/egress-allowlist.txt"
        dns_resolver = "10.27.28.1"

        egress = EgressFilter(
            allowlist_path=Path(egress_path),
            dns_resolver=dns_resolver,
        )

        for host in egress.get_allowed_hosts():
            result = subprocess.run(  # nosec B603 B607
                [
                    "sudo",
                    "sbx",
                    "policy",
                    "allow",
                    "network",
                    host,
                    "--name",
                    sandbox_name,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                logger.error(
                    "Failed to allow network %s for sandbox %s: %s",
                    host,
                    sandbox_name,
                    result.stderr,
                )
            else:
                logger.debug("Allowed network %s for sandbox %s", host, sandbox_name)

    def execute_command(self, command: str) -> subprocess.CompletedProcess:
        """Execute a command inside the sandbox.

        Args:
            command: The command to execute inside the sandbox.

        Returns:
            CompletedProcess with stdout, stderr, and returncode.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        result = subprocess.run(  # nosec
            ["sbx", "exec", self._sandbox_name, "sh", "-c", command],
            capture_output=True,
            timeout=SBX_TIMEOUT,
            check=False,
        )
        return result

    def remove_sandbox(self) -> None:
        """Remove the sandbox and all its contents.

        Also deletes the per-run workspace this strategy created (ownership
        rule: only what it created). A caller-supplied workspace is left
        in place — the base directory itself always survives.
        """
        if self._sandbox_name:
            result = subprocess.run(  # nosec
                ["sbx", "rm", "--force", self._sandbox_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                logger.debug("Removed sandbox: %s", self._sandbox_name)
            else:
                logger.warning("Failed to remove sandbox %s: %s", self._sandbox_name, result.stderr)

        if self._workspace_dir:
            shutil.rmtree(self._workspace_dir, ignore_errors=True)
            logger.debug("Removed per-run workspace: %s", self._workspace_dir)
            self._workspace_dir = None

    def store_http_secret(self, secret_id: str, value: str) -> None:
        """Store an HTTP API key in sbx's proxy for header injection.

        The secret is injected into outbound HTTP requests by the
        host-side proxy. The raw value NEVER enters the sandbox VM.

        Args:
            secret_id: Service name (e.g., "openai", "github").
            value: The API key value.
        """
        # Write value to stdin for non-interactive storage
        result = subprocess.run(  # nosec
            ["sbx", "secret", "set", secret_id],
            input=value,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to store HTTP secret {secret_id}: {result.stderr}")

        logger.info("Injected HTTP secret via proxy (never enters VM): %s", secret_id)
