"""Abstract base class and result type for injection strategies."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .executor import SecretBundle


@dataclass
class InjectionResult:
    """Result returned by an injection strategy's prepare() method.

    Attributes:
        env_vars: Safe environment variables to merge into the child process
            environment (e.g. paths to tmpfs files for the file strategy).
        extra_fds: Extra file descriptors to pass to the child process
            (e.g. memfd FDs for the memfd strategy).
        cleanup_funcs: Functions to call after execution completes.
            Each receives the InjectionResult as its sole argument.
    """

    env_vars: dict[str, str] = field(default_factory=dict)
    extra_fds: list[int] = field(default_factory=list)
    cleanup_funcs: list[Callable[[InjectionResult], None]] = field(default_factory=list)


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
