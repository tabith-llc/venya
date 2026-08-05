"""Memfd-based secret injection strategy.

Creates anonymous memory-backed file descriptors via memfd_create().
No disk residency. Linux-only.
"""

from __future__ import annotations

import ctypes
import logging
import os

from .base import InjectionResult, InjectionStrategy

logger = logging.getLogger("venya.executor.strategies.memfd")

MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002


class MemfdStrategy(InjectionStrategy):
    """memfd-based injection (Linux only)."""

    SECRET_BASE_FD = 100

    def name(self) -> str:
        return "memfd"

    def validate(self) -> None:
        """Raise if memfd_create not available."""
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if not hasattr(libc, "memfd_create"):
                raise RuntimeError("memfd_create unavailable - Linux kernel too old")
        except (ImportError, FileNotFoundError) as e:
            raise RuntimeError(f"memfd_create required but not available: {e}")

    def prepare(self, secrets: list) -> InjectionResult:
        """Create memfd for each secret value."""
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        memfd_create = libc.memfd_create
        memfd_create.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        memfd_create.restype = ctypes.c_int

        extra_fds: list[int] = []
        cleanup_funcs: list[callable] = []  # type: ignore[type-arg]

        for i, bundle in enumerate(secrets):
            fd = memfd_create(b"venya_secret\x00", MFD_CLOEXEC | MFD_ALLOW_SEALING)
            if fd < 0:
                errno = ctypes.get_errno()
                raise OSError(errno, "memfd_create failed")

            os.write(fd, bundle.value)
            os.lseek(fd, 0, os.SEEK_SET)

            logical_fd = self.SECRET_BASE_FD + i
            extra_fds.append(fd)  # Actual OS FD for pass_fds
            cleanup_funcs.append(lambda f=fd: os.close(f))

            logger.debug(
                "Injected secret %s via memfd: logical_fd=%d os_fd=%d",
                bundle.secret_id,
                logical_fd,
                fd,
            )

        return InjectionResult(
            extra_fds=extra_fds,
            cleanup_funcs=cleanup_funcs,
        )
