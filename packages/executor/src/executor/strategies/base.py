"""Abstract base class and result type for injection strategies."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .executor import SecretBundle

logger = logging.getLogger("venya.executor.strategies")


@dataclass
class InjectionResult:
    """Result of preparing secret injections for one command execution.

    Injected at the executor level to reflect the unit-of-work lifecycle:
    prepare all injections together, execute one command, then clean up.

    Attributes:
        env_vars: Environment variables to merge into the child process
            environment (usually empty for memfd strategy).
        extra_fds: File descriptors to pass to the subprocess via pass_fds.
        cleanup_funcs: Functions to call on cleanup. Each takes no arguments.

    NOTE: Executor processes commands sequentially. This is per-execution
    state that assumes one active command at a time.
    """

    env_vars: dict[str, str] = field(default_factory=dict)
    extra_fds: list[int] = field(default_factory=list)
    cleanup_funcs: list[Callable[[], None]] = field(default_factory=list)

    def cleanup(self) -> None:
        """Run all cleanup functions, suppressing individual exceptions."""
        for func in self.cleanup_funcs:
            try:
                func()
            except Exception:
                logger.debug("Cleanup function raised exception", exc_info=True)


class InjectionStrategy(abc.ABC):
    """Abstract base class for secret injection methods.

    Each strategy is responsible for:
    - Preparing the secret injection (creating FDs, files, env vars, etc.)
    - Returning an InjectionResult with everything the executor needs
    - Registering cleanup functions to destroy injected secrets
    """

    @abc.abstractmethod
    def prepare(self, secrets: list[SecretBundle]) -> InjectionResult:
        """Prepare the environment for execution.

        Args:
            secrets: List of SecretBundle objects whose plaintext ``value``
                fields contain the unwrapped secret bytes to inject.

        Returns:
            An InjectionResult containing env vars, extra FDs, and
            cleanup functions needed to run the command.
        """

    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique identifier for this strategy.

        Examples: ``"memfd"``, ``"fifo"``, ``"env"``.
        """
