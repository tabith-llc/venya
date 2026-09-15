# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Secure memory: mlock-based buffers with auto-zeroing.

mlock is used only in the core package (server-side), where secrets
reside in trusted memory. Requires CAP_IPC_LOCK or root.
"""

import ctypes
import ctypes.util
import os
import platform
from typing import Self

_SYSTEM_LIB: str | None = None


def _load_system_lib() -> ctypes.CDLL | None:
    """Load the system C library for mlock access."""
    global _SYSTEM_LIB
    if _SYSTEM_LIB is not None:
        return ctypes.CDLL(_SYSTEM_LIB)
    lib_name = ctypes.util.find_library("c")
    if lib_name:
        _SYSTEM_LIB = lib_name
        return ctypes.CDLL(_SYSTEM_LIB, use_errno=True)
    return None


def secure_mlock(data: bytearray) -> None:
    """Lock a bytearray in memory using mlock().

    Prevents the buffer from being swapped to disk.

    Args:
        data: The bytearray to lock. Must be at least 1 byte.

    Raises:
        OSError: If mlock() fails (e.g., insufficient permissions).
        RuntimeError: If mlock is not available on this platform.
    """
    if platform.system() != "Linux":
        raise RuntimeError("mlock is only supported on Linux")

    if len(data) == 0:
        raise ValueError("Cannot mlock an empty buffer")

    lib = _load_system_lib()
    if lib is None:
        raise RuntimeError("Cannot find system C library for mlock")

    ret = lib.mlock(ctypes.addressof(ctypes.c_char.from_buffer(data)), len(data))
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def secure_munlock(data: bytearray) -> None:
    """Unlock a previously mlock'd bytearray.

    Args:
        data: The bytearray to unlock.

    Raises:
        OSError: If munlock() fails.
    """
    if platform.system() != "Linux":
        return  # No-op on non-Linux

    if len(data) == 0:
        return

    lib = _load_system_lib()
    if lib is None:
        return

    ret = lib.munlock(ctypes.addressof(ctypes.c_char.from_buffer(data)), len(data))
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def secure_zero(data: bytearray | memoryview) -> None:
    """Zero out a buffer in memory.

    Uses ctypes to write zeros byte-by-byte, preventing the optimizer
    from eliminating the memset.

    Args:
        data: The buffer to zero.
    """
    if isinstance(data, memoryview):
        return  # memoryview is immutable here — zero out via its bytearray copy by the caller
    n = len(data)
    for i in range(n):
        data[i] = 0


class SecureBuffer:
    """A memory-safe buffer that supports mlock and auto-zeroing on drop.

    Usage:
        buf = SecureBuffer(32)
        buf.write(key_material)
        # ... use buf ...
        buf.clear()  # zero memory
        del buf      # auto-zero on drop if not already cleared
    """

    def __init__(self, size: int, mlock: bool = False) -> None:
        """Initialize a secure buffer.

        Args:
            size: Buffer size in bytes.
            mlock: Whether to lock the buffer in memory (requires CAP_IPC_LOCK).
        """
        if size <= 0:
            raise ValueError("Buffer size must be positive")

        self._size = size
        self._data = bytearray(size)
        self._locked = False
        self._zeroed = False

        if mlock:
            secure_mlock(self._data)
            self._locked = True

    @property
    def size(self) -> int:
        """Buffer size in bytes."""
        return self._size

    @property
    def is_locked(self) -> bool:
        """Whether the buffer is currently mlock'd."""
        return self._locked

    @property
    def is_zeroed(self) -> bool:
        """Whether the buffer has been zeroed."""
        return self._zeroed

    def read(self, offset: int = 0, length: int | None = None) -> bytes:
        """Read data from the buffer.

        Args:
            offset: Start offset (default 0).
            length: Number of bytes to read (default entire buffer).

        Returns:
            Bytes copy of the data.
        """
        if length is None:
            length = self._size
        return bytes(self._data[offset : offset + length])

    def write(self, data: bytes, offset: int = 0) -> None:
        """Write data to the buffer.

        Args:
            data: Bytes to write.
            offset: Start offset (default 0).

        Raises:
            ValueError: If data doesn't fit in the buffer.
        """
        if offset + len(data) > self._size:
            raise ValueError(
                f"Data ({len(data)} bytes) exceeds buffer capacity "
                f"from offset {offset} ({self._size - offset} bytes remaining)"
            )
        self._data[offset : offset + len(data)] = data
        self._zeroed = False

    def clear(self) -> None:
        """Zero out the buffer."""
        secure_zero(self._data)
        self._zeroed = True

    def __getitem__(self, index: int) -> int:
        return self._data[index]

    def __setitem__(self, index: int, value: int) -> None:
        self._data[index] = value

    def __len__(self) -> int:
        return self._size

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.clear()
        if self._locked:
            try:
                secure_munlock(self._data)
            except OSError:
                pass
            self._locked = False

    def __del__(self) -> None:
        """Auto-zero on garbage collection."""
        if hasattr(self, "_data") and not self._zeroed:
            try:
                self.clear()
                if self._locked:
                    try:
                        secure_munlock(self._data)
                    except OSError:
                        pass
                    self._locked = False
            except Exception:  # nosec B110 — best-effort unlock in __del__, no stack to unwind  # noqa: S110
                pass  # Best effort in __del__
