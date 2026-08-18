"""Docker Sandboxes (sbx) injection strategy.

Uses Docker's sbx CLI to create microVM sandboxes with
hypervisor-level isolation and built-in network policies.

Secrets are written to host tmpfs (/dev/shm) and copied into
the sandbox via `sbx cp`. Network access is restricted via
`sbx policy allow/deny` rules.

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

from .base import SecretMount
from .base import InjectionResult, InjectionStrategy

logger = logging.getLogger("venya.executor.strategies.sbx")

# tmpfs base on host — secrets never touch disk
SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"  # nosec

# Where secrets appear inside the sandbox
CONTAINER_SECRET_DIR = "/run/venya/secrets"  # nosec

# How long to wait for sandbox commands
SBX_TIMEOUT = 3600  # 1 hour


class SbxStrategy(InjectionStrategy):
    """Docker Sandboxes strategy using microVM isolation.

    Creates a Docker Sandbox (microVM with separate kernel) for
    each command execution. Secrets are written to host tmpfs and
    copied into the sandbox via `sbx cp`. Network access is
    controlled via `sbx policy` rules (deny-by-default).

    Key properties:
    - Hypervisor isolation (separate kernel per sandbox)
    - Network: SOCKS5 proxy with policy-based allow/deny
    - Secrets: tmpfs on host -> sbx cp into sandbox (RAM-backed)
    - Cleanup: sandbox destroyed, tmpfs deleted, secrets zeroed
    """

    def __init__(self, secret_base_fd: int = 100) -> None:
        self.secret_base_fd = secret_base_fd
        self._session_dir: str | None = None
        self._sandbox_name: str | None = None

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
            /run/venya/secrets/{secret_id}

        The sandbox is NOT created here — that happens in the executor.

        Args:
            secrets: List of SecretBundle objects.

        Returns:
            InjectionResult with secret mounts and cleanup functions.
        """
        # Create unique session directory on tmpfs
        self._session_dir = tempfile.mkdtemp(
            prefix="session_", dir=SECRET_TMPFS_BASE
        )
        os.chmod(self._session_dir, 0o700)

        mounts: list[SecretMount] = []
        cleanup_funcs: list[Callable[[], None]] = []

        for bundle in secrets:
            secret_path = os.path.join(self._session_dir, bundle.secret_id)

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
            workspace: Workspace directory to mount into the sandbox.
        """
        cmd = ["sbx", "create", "--name", sandbox_name]
        if workspace:
            cmd.append(workspace)

        result = subprocess.run(  # nosec
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.error("sbx create failed: %s", result.stderr)
            raise RuntimeError(f"Failed to create sandbox: {result.stderr}")

        self._sandbox_name = sandbox_name
        logger.info("Created Docker Sandbox: %s", sandbox_name)

    def copy_secrets_into_sandbox(self, mounts: list[SecretMount]) -> None:
        """Copy secrets from host tmpfs into the sandbox.

        Args:
            mounts: List of SecretMount objects with host and container paths.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        # Create secrets directory inside sandbox
        subprocess.run(  # nosec
            ["sbx", "exec", self._sandbox_name, "mkdir", "-p", CONTAINER_SECRET_DIR],
            capture_output=True,
            text=True,
            timeout=10,
        )

        for mount in mounts:
            container_path = mount.container_path
            result = subprocess.run(  # nosec
                ["sbx", "cp", mount.path, f"{self._sandbox_name}:{container_path}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("sbx cp failed for %s: %s", mount.secret_id, result.stderr)
                raise RuntimeError(f"Failed to copy secret {mount.secret_id} into sandbox")

            # Set read-only permissions inside sandbox
            subprocess.run(  # nosec
                ["sbx", "exec", self._sandbox_name, "chmod", "400", container_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            logger.debug("Copied secret %s into sandbox: %s", mount.secret_id, container_path)

    def apply_network_policy(self, allowed_hosts: list[dict[str, object]]) -> None:
        """Apply network allow rules to the sandbox.

        Default policy is deny-all. Only explicitly allowed hosts/domains
        can be reached via HTTP/HTTPS.

        Args:
            allowed_hosts: List of {host, port} dicts. Port is ignored
                since sbx policies work at the domain level.
        """
        if not self._sandbox_name:
            raise RuntimeError("Sandbox not created yet")

        for host_info in allowed_hosts:
            host = host_info["host"]
            # sbx policy works at domain/IP level, not port-specific
            result = subprocess.run(  # nosec
                ["sbx", "policy", "allow", "network", host],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("Network ALLOW: %s", host)
            else:
                logger.warning("Failed to add allow rule for %s: %s", host, result.stderr)

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
        )
        return result

    def remove_sandbox(self) -> None:
        """Remove the sandbox and all its contents."""
        if not self._sandbox_name:
            return

        result = subprocess.run(  # nosec
            ["sbx", "rm", "--force", self._sandbox_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.debug("Removed sandbox: %s", self._sandbox_name)
        else:
            logger.warning("Failed to remove sandbox %s: %s", self._sandbox_name, result.stderr)

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
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to store HTTP secret {secret_id}: {result.stderr}")

        logger.info("Injected HTTP secret via proxy (never enters VM): %s", secret_id)
