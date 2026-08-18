"""Abstract base class and result type for injection strategies."""


import abc
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..bundles import SecretBundle

logger = logging.getLogger("venya.executor.strategies")


@dataclass
class SecretMount:
    """A secret made available at a filesystem path (for sandbox mounts).

    Used by SbxStrategy to expose secrets as read-only files
    inside a Docker Sandbox microVM.
    """

    secret_id: str
    path: str  # Host-side path (on tmpfs) to mount into container
    container_path: str  # Path inside the sandbox where the secret appears


@dataclass
class InjectionResult:
    """Result of preparing secret injections for one command execution.

    Injected at the executor level to reflect the unit-of-work lifecycle:
    prepare all injections together, execute one command, then clean up.

    Attributes:
        extra_fds: File descriptors to pass to the subprocess via pass_fds.
        secret_mounts: Filesystem mounts for sandbox-based execution
                       (used by SbxStrategy, ignored by MemfdStrategy).
        cleanup_funcs: Functions to call on cleanup. Each takes no arguments.

    NOTE: Executor processes commands sequentially. This is per-execution
    state that assumes one active command at a time.
    """

    extra_fds: list[int] = field(default_factory=list)
    secret_mounts: list[SecretMount] = field(default_factory=list)
    cleanup_funcs: list[Callable[[], None]] = field(default_factory=list)

    def cleanup(self) -> None:
        """Run all cleanup functions, suppressing individual exceptions."""
        for func in self.cleanup_funcs:
            try:
                func()
            except Exception:
                logger.warning("Injection cleanup error", exc_info=True)


class InjectionStrategy(abc.ABC):
    """Interface for secret injection methods.

    Each strategy is responsible for:
    - Validating platform availability (validate)
    - Preparing the secret injection (prepare)
    - Returning an InjectionResult with everything the executor needs
    - Registering cleanup functions to destroy injected secrets
    """

    def __init__(self, secret_base_fd: int = 100) -> None:
        self.secret_base_fd = secret_base_fd

    @abc.abstractmethod
    def prepare(self, secrets: list[SecretBundle]) -> InjectionResult:
        """Prepare injection resources. Returns result with cleanup funcs."""

    @abc.abstractmethod
    def validate(self) -> None:
        """Check this strategy is available on current platform."""

    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique identifier for this strategy."""
