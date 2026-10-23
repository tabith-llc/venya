# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Secure memory: mlock-based buffers with auto-zeroing.

mlock is used only in the core package (server-side), where secrets
reside in trusted memory. Requires CAP_IPC_LOCK or root.

What this does and what it does not do: a pinned buffer is not swapped,
and it is erased on release. It is not a defence against a same-uid
``ptrace`` or ``/proc/<pid>/mem`` reader, and it does not keep the page out
of a core dump or a hibernation image.
"""

import ctypes
import ctypes.util
import logging
import os
import platform
import resource
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final, Self

logger = logging.getLogger(__name__)

#: Fallback page size for the mlock cost report when the query fails.
#: Report-only: correctness never depends on it.
_PAGE_SIZE_FALLBACK: Final[int] = 4096

_SYSTEM_LIB: str | None = None


def _page_size() -> int:
    """System page size in bytes (mlock cost is page-rounded)."""
    try:
        page = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        return _PAGE_SIZE_FALLBACK
    if not isinstance(page, int) or page <= 0:
        return _PAGE_SIZE_FALLBACK
    return page


def _locked_memory_budget_kib() -> int | None:
    """RLIMIT_MEMLOCK soft limit in KiB, or None when the limit is unlimited."""
    try:
        soft = resource.getrlimit(resource.RLIMIT_MEMLOCK)[0]
    except (ValueError, OSError):
        return None
    if soft == resource.RLIM_INFINITY:
        return None
    return soft // 1024


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


def secure_zero(data: bytearray) -> None:
    """Zero out a buffer in memory.

    Writes zeros byte-by-byte in a plain Python loop (``data[i] = 0``), so
    the erase goes through the object that owns the bytes.

    Args:
        data: The bytearray to zero.

    Raises:
        TypeError: If ``data`` is a memoryview. A view is not the owner of
            the memory, and this function must not quietly do nothing: the
            release log line reports whether the buffer was zeroized, and a
            silent no-op would make that line claim more than happened.
    """
    if isinstance(data, memoryview):
        raise TypeError("secure_zero needs the owning bytearray, not a memoryview")
    n = len(data)
    for i in range(n):
        data[i] = 0


class SecureBufferReleasedError(RuntimeError):
    """Key material was asked for from a cache that holds none.

    Raised by the one accessor that hands out key material. Deliberately NOT
    an ``EncryptionError``/``DecryptionError`` subclass: those are caught on
    the key paths and would be read as "wrong passphrase" — a quiet wrong
    verdict for what is a bug (#472).
    """


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

    def readonly_view(self) -> memoryview:
        """A read-only memoryview over the buffer contents.

        The caller owns the returned view and must release it; an
        unreleased view exports the bytearray and blocks it from being
        resized. Readers get this, never the buffer itself.
        """
        return memoryview(self._data).toreadonly()

    def lock(self) -> None:
        """mlock this buffer's bytes.

        Raises:
            OSError: If mlock() fails (permissions, budget).
            RuntimeError: If mlock is unavailable on this platform.
        """
        secure_mlock(self._data)
        self._locked = True

    def unlock(self) -> None:
        """munlock the buffer and record the unlocked state.

        Raises:
            OSError: If munlock() fails (see :func:`secure_munlock`).
        """
        secure_munlock(self._data)
        self._locked = False

    def is_all_zero(self) -> bool:
        """Objective check that every byte reads as zero.

        Asked after :meth:`clear` so the release report describes what the
        buffer holds, not what the code intended.
        """
        return all(byte == 0 for byte in self._data)

    def write(self, data: bytes, offset: int = 0) -> None:
        """Write data into the buffer.

        Args:
            data: Bytes to write.
            offset: Start offset (default 0).

        Raises:
            ValueError: If data doesn't fit in the buffer, or if a locked
                buffer is written anything other than a full-size value.
        """
        if offset + len(data) > self._size:
            raise ValueError(
                f"Data ({len(data)} bytes) exceeds buffer capacity "
                f"from offset {offset} ({self._size - offset} bytes remaining)"
            )
        if self._locked and (offset != 0 or len(data) != self._size):
            # Never resize a pinned buffer: a moved bytearray would silently
            # un-pin the key while the cache still reported it locked (#472).
            raise ValueError(
                f"A locked buffer takes a full {self._size}-byte write " f"(got {len(data)} bytes at offset {offset})"
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


class KekCache:
    """The resident KEK: one protected buffer, one owner (#472).

    The cache holds the single :class:`SecureBuffer` that the key encryption
    key lives in. Readers never get the buffer and never get ``bytes``: they
    get a scoped read-only ``memoryview`` from :meth:`view`, valid only
    inside that block.

    Pinning is attempted and reported, never fatal — see :mod:`docs/design-
    secure-memory-kek.md` section 5. Until a served VM proves the pin, the
    honest description is "erased on release, not pinned".
    """

    def __init__(self, size: int, mlock: bool = True) -> None:
        """Create the cache and, when asked, attempt to pin it.

        Args:
            size: Buffer size in bytes (the KEK: 32).
            mlock: Whether to attempt ``mlock``. The outcome is captured and
                logged; a failure never propagates.
        """
        self._buffer = SecureBuffer(size)
        self._populated = False
        self._released = False
        self._zeroized: bool | None = None
        self.pin_attempted = False
        self.pin_active = False
        self.pin_errno: int | None = None
        self.pin_reason: str | None = None

        if mlock:
            self._attempt_pin()
            self._log_pin()

    def _attempt_pin(self) -> None:
        """Try to mlock the buffer; keep going whatever the answer is."""
        self.pin_attempted = True
        try:
            self._buffer.lock()
        except (OSError, RuntimeError, ValueError) as exc:
            if isinstance(exc, OSError) and exc.errno is not None:
                self.pin_errno = exc.errno
                self.pin_reason = os.strerror(exc.errno)
            else:
                self.pin_reason = str(exc)
            return
        self.pin_active = True

    def _log_pin(self) -> None:
        """One startup line naming what is ACTIVE on this host. No key material."""
        if self.pin_active:
            page = _page_size()
            rounded_kib = ((self._buffer.size + page - 1) // page) * page // 1024
            budget = _locked_memory_budget_kib()
            logger.info(
                "kek cache: pin=active (mlock %d bytes, page-rounded to %d KiB, budget %s)",
                self._buffer.size,
                rounded_kib,
                f"{budget} KiB" if budget is not None else "unlimited",
            )
        else:
            logger.info(
                "kek cache: pin=inactive (mlock failed errno=%s %s) -- key material is "
                "erased on release but NOT pinned; grant CAP_IPC_LOCK or raise the "
                "locked-memory limit",
                self.pin_errno,
                self.pin_reason,
            )

    @property
    def size(self) -> int:
        """Buffer size in bytes."""
        return self._buffer.size

    @property
    def is_populated(self) -> bool:
        """Whether the cache currently holds key material."""
        return self._populated and not self._released

    @property
    def is_pinned(self) -> bool:
        """Whether the buffer is mlock'd right now."""
        return self._buffer.is_locked

    @property
    def is_zeroed(self) -> bool:
        """Whether the last release attempt reported the buffer zeroed."""
        return bool(self._buffer.is_zeroed) if self._zeroized is None else self._zeroized

    def populate(self, key_material: bytes) -> None:
        """Copy key material into the buffer.

        Args:
            key_material: Exactly ``size`` bytes.

        Raises:
            ValueError: If the cache is released, or the material is not the
                buffer size.
        """
        if self._released:
            raise ValueError("cannot populate a released KEK cache")
        if len(key_material) != self._buffer.size:
            raise ValueError(f"KEK cache takes exactly {self._buffer.size} bytes, got {len(key_material)}")
        self._buffer.write(key_material)
        self._populated = True

    @contextmanager
    def view(self) -> Iterator[memoryview]:
        """Hand out a read-only view of the key material for one block.

        The only accessor that reaches key material, and the only place
        :class:`SecureBufferReleasedError` is raised. The view is released on
        exit, so a view stashed out of the block cannot be read afterwards.

        Raises:
            SecureBufferReleasedError: If the cache was released or was never
                populated — the alternative is handing out zero bytes, which
                is a valid AES-256 key.
        """
        if not self.is_populated:
            raise SecureBufferReleasedError("KEK cache holds no key material (released, or never populated)")
        kek_view = self._buffer.readonly_view()
        try:
            yield kek_view
        finally:
            kek_view.release()

    def release(self) -> bool:
        """Zeroize the buffer, then attempt to unlock it. Reports the attempt.

        Idempotent. Returns whether the buffer was observed zeroed.
        """
        if self._released:
            return self.is_zeroed

        try:
            self._buffer.clear()
            zeroized = self._buffer.is_zeroed and self._buffer.is_all_zero()
        except Exception:
            zeroized = False
            logger.warning("kek cache: release could not zeroize the buffer", exc_info=True)
        self._zeroized = zeroized
        self._released = True
        self._populated = False

        if self._buffer.is_locked:
            try:
                self._buffer.unlock()
                unlock = "ok"
            except OSError as exc:
                unlock = f"failed errno={exc.errno} {os.strerror(exc.errno) if exc.errno else exc}"
        else:
            unlock = "not locked"

        logger.info(
            "kek cache: released zeroized=%s pin=%s munlock=%s",
            "yes" if zeroized else "no",
            "active" if self.pin_active else "inactive",
            unlock,
        )
        return zeroized

    def __del__(self) -> None:
        """Backstop only: release on garbage collection if nothing else did.

        The primary release point is ``Backend.dispose()``; a reference cycle
        or interpreter teardown can skip this one, which is why no claim here
        says the key is gone.
        """
        if getattr(self, "_released", True):
            return
        try:
            self.release()
        except Exception as exc:
            logger.warning("kek cache: release on garbage collection did not complete: %s", exc)

    @classmethod
    def from_bytes(cls, key_material: bytes, mlock: bool = True) -> KekCache:
        """Build a populated cache in one step (the size is the key's size).

        Args:
            key_material: The key bytes to hold.
            mlock: Whether to attempt pinning; the outcome is reported, never
                raised.
        """
        cache = cls(len(key_material), mlock=mlock)
        cache.populate(key_material)
        return cache
