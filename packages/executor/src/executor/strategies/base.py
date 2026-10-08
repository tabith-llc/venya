# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
class CleanupFailure:
    """One secret-destroy step that did not complete.

    Recorded by :meth:`InjectionResult.cleanup` so a failed destroy is visible
    in the result instead of only in a log line.

    Attributes:
        index: Position of the cleanup callable in ``cleanup_funcs``.
        label: Best-effort name for the callable that failed.
        error: Exception class and message, formatted for the log line.
    """

    index: int
    label: str
    error: str


def _cleanup_label(func: Callable[[], None], index: int) -> str:
    """Name a cleanup callable as well as it can be named at this layer.

    Strategies register plain closures, so the qualname is the most specific
    handle available here; the caller adds the resident resources, which carry
    the secret ids and mount paths.
    """
    qualname = getattr(func, "__qualname__", None)
    if isinstance(qualname, str) and qualname:
        return f"cleanup[{index}] ({qualname})"
    return f"cleanup[{index}] ({type(func).__name__})"


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
        cleanup_failures: Destroy steps that raised, recorded by the most
                       recent ``cleanup()`` call. Empty means every step
                       completed.

    NOTE: Executor processes commands sequentially. This is per-execution
    state that assumes one active command at a time.
    """

    extra_fds: list[int] = field(default_factory=list)
    secret_mounts: list[SecretMount] = field(default_factory=list)
    cleanup_funcs: list[Callable[[], None]] = field(default_factory=list)
    cleanup_failures: list[CleanupFailure] = field(default_factory=list)

    @property
    def all_clean(self) -> bool:
        """True when the last cleanup run had no failures."""
        return not self.cleanup_failures

    @property
    def degraded(self) -> bool:
        """True when at least one destroy step failed, so secret material may
        still be resident."""
        return bool(self.cleanup_failures)

    def resident_resources(self) -> str:
        """Human-readable list of what is still held open or on disk."""
        parts = [f"secret={mount.secret_id} at {mount.path}" for mount in self.secret_mounts]
        parts.extend(f"fd={fd}" for fd in self.extra_fds)
        return ", ".join(parts) if parts else "unknown"

    def cleanup(self) -> list[CleanupFailure]:
        """Run every cleanup function, recording the ones that raise.

        A failing step never stops the remaining steps: skipping them would
        leak more than it reports. Failures land in ``cleanup_failures`` so the
        caller can surface them in the result rather than only in the log.
        Exceptions derived from ``BaseException`` but not ``Exception`` (for
        example ``KeyboardInterrupt``) are not caught here.

        Returns:
            The failures recorded by this run, in the order the callables ran.
        """
        self.cleanup_failures = []
        for index, func in enumerate(self.cleanup_funcs):
            try:
                func()
            except Exception as exc:
                failure = CleanupFailure(
                    index=index,
                    label=_cleanup_label(func, index),
                    error=f"{type(exc).__name__}: {exc}",
                )
                self.cleanup_failures.append(failure)
                logger.warning(
                    "Injection cleanup FAILED for %s; still resident: %s",
                    failure.label,
                    self.resident_resources(),
                    exc_info=True,
                )
        return self.cleanup_failures


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
    def prepare(self, secrets: list[SecretBundle], session_id: str) -> InjectionResult:
        """Prepare injection resources for the given execution session.

        session_id is the server execution-session id; implementations that
        stage secrets on disk embed it in the staging path so the daemon
        reaper can attribute orphan cleanup/revocation to the real session.
        """

    @abc.abstractmethod
    def validate(self) -> None:
        """Check this strategy is available on current platform."""

    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique identifier for this strategy."""
