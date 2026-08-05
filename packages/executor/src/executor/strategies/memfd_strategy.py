"""Memfd-based secret injection strategy.

Creates anonymous memory-backed file descriptors via memfd_create().
No disk residency. Linux-only.
"""

from __future__ import annotations

import collections.abc
import ctypes
import ctypes.util
import logging
import os
from typing import Callable

from .base import InjectionResult, InjectionStrategy

logger = logging.getLogger("venya.executor.strategies.memfd")

MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002


class MemfdStrategy(InjectionStrategy):
    """Inject secrets via memfd_create syscall.

    Secrets are written to anonymous memory-backed file descriptors.
    They never touch disk. FDs are marked CLOEXEC so they are automatically
    closed on exec().
    """

    def name(self) -> str:
        return "memfd"

    def prepare(self, secrets: list) -> InjectionResult:
        """Prepare memfd injection for the given secrets.

        Args:
            secrets: List of SecretBundle objects whose ``value`` attribute
                contains the plaintext secret bytes.

        Returns:
            InjectionResult with extra_fds populated and a cleanup function
            that closes all created memfd FDs.

        Raises:
            NotImplementedError: If memfd_create is unavailable on this platform.
        """
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        memfd_create = libc.memfd_create
        memfd_create.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        memfd_create.restype = ctypes.c_int

        fds: list[int] = []

        for bundle in secrets:
            fd = memfd_create(b"venya_secret\x00", MFD_CLOEXEC | MFD_ALLOW_SEALING)
            if fd < 0:
                errno = ctypes.get_errno()
                raise OSError(errno, f"memfd_create failed: {os.strerror(errno)}")

            try:
                os.write(fd, bundle.value)
            except Exception:
                os.close(fd)
                raise

            fds.append(fd)
            logger.debug("Injected secret %s via memfd: fd=%d", bundle.secret_id, fd)

        cleanup_funcs = [_make_memfd_closer(fds)]

        return InjectionResult(
            extra_fds=fds,
            cleanup_funcs=cleanup_funcs,
        )


def _make_memfd_closer(fds: list[int]) -> Callable[[], None]:
    """Return a cleanup function that closes all given FDs."""

    def closer() -> None:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                logger.debug("Failed to close memfd fd=%d", fd, exc_info=True)

    return closer
