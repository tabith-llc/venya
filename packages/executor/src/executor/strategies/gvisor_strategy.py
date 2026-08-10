"""gVisor-sandboxed injection strategy.

Writes secrets to tmpfs files (RAM-backed) and returns mount paths
for use with Docker --runtime=runsc containers.

Unlike MemfdStrategy which passes FDs directly to a subprocess,
this strategy exposes secrets as read-only files mounted into a
gVisor-sandboxed container with no network access.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Callable

from .base import SecretMount
from .base import InjectionResult, InjectionStrategy

logger = logging.getLogger("venya.executor.strategies.gvisor")

# tmpfs base — secrets never touch disk
SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"

# Where secrets appear inside the container
CONTAINER_SECRET_DIR = "/run/venya/secrets"


class GvisorStrategy(InjectionStrategy):
    """Secret injection via tmpfs files for gVisor container execution.

    Secrets are written to /dev/shm (kernel-managed tmpfs, RAM-only).
    Each secret gets a subdirectory with restrictive permissions.
    The executor mounts these as read-only volumes into a gVisor
    container running with --network=none.
    """

    def __init__(self, secret_base_fd: int = 100) -> None:
        self.secret_base_fd = secret_base_fd
        self._session_dir: str | None = None

    def name(self) -> str:
        return "gvisor"

    def validate(self) -> None:
        """Check that tmpfs is available and Docker is installed."""
        if not os.path.isdir("/dev/shm"):
            raise RuntimeError(
                "/dev/shm not available — gVisor strategy requires tmpfs support"
            )

        # Check Docker availability (non-fatal at init, fatal at execute time)
        docker_path = shutil.which("docker")
        if docker_path is None:
            raise RuntimeError(
                "Docker not found — gVisor strategy requires Docker with runsc runtime"
            )

    def prepare(self, secrets: list) -> InjectionResult:
        """Write secrets to tmpfs and return mount specifications.

        Each secret is written to:
            /dev/shm/venya-secrets/{session_uuid}/{secret_id}

        And will be mounted inside the container at:
            /run/venya/secrets/{secret_id}
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
                "Injected secret %s via tmpfs for gVisor: %s -> %s",
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
            extra_fds=[],  # No FDs — using volume mounts instead
            secret_mounts=mounts,
            cleanup_funcs=cleanup_funcs,
        )
