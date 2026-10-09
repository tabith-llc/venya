# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at this file's repository root. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""A short-lived holder for one plaintext secret in the workstation CLI (#538).

``venya admin export-ca-key`` has to see the root CA private key as plaintext in
this process: the at-rest envelope is opened here and the operator's backup
envelope is sealed here. Before this module the plaintext lived in an ordinary
Python ``bytes`` that nothing ever erased, and the window ran from the unwrap
all the way past the two ``getpass`` prompts to the end of the command — a
human-scale, unbounded window on a laptop with no service unit and no capability
grant. This module owns that copy and erases it on release.

**What this covers, and what it does not.** The guarantee is erasure, not
residency. On an operator workstation the kernel normally refuses the pin, so
this module does one thing and says exactly that. **It erases the copy it owns
on release; it does not pin, and it does not remove copies made by other code.**

Read that sentence as the whole claim:

* the copy we own is zeroized when the holder is released (``release``,
  ``__exit__``, and a ``__del__`` backstop);
* the pin is *attempted*, *reported*, and *never fatal* — see ``pin_attempted``,
  ``pin_active``, ``pin_errno`` and ``pin_reason``. Whether a pin is granted is
  the machine's answer, not a property of this code: on some hosts the
  page-rounded buffer does get pinned, and that outcome is reported as ACTIVE and
  nothing more. What no caller may assume is residency — the claim that holds on
  every host is the erase. #538 exists precisely because a docstring once
  claimed more than the mechanism delivered, so the wording here is deliberately
  the weaker one;
* ``cryptography`` allocates the plaintext we are handed (its serializer returns
  ``bytes``; there is no serialize-into-the-caller-buffer API), so this holder is
  necessarily the SECOND copy, and Python copies ``bytes`` freely. Deleting our
  name does not erase somebody else's copy. No caller may read this module as
  "the key is scrubbed" or "the key is protected in memory".

Two homes, one contract. The core package has its own protected buffer for the
server side, and it stays the semantics of record; the design that governs both
is ``docs/design-secure-memory-kek.md``. This module is deliberately NOT a copy
of that one: the CLI ships to operator laptops and a shipped isolation guard
(``packages/cli/tests/test_capability_isolation.py``, mirrored in
``packages/core/tests/test_capability_isolation.py``) forbids the core module's
file name and its primitive names anywhere under ``venya_cli``. So the same three
behaviours — a scoped read-only view, erase-on-release, an
attempt-and-report pin that never raises — are spelled here under different
names, and ``packages/cli/tests/test_secret_holder_538.py`` carries a parity
cell over the behavioural contract rather than over this file's internals.

Stdlib only (``ctypes``, ``os``, ``platform``, ``logging``, ``contextlib``,
``typing``, ``collections.abc``): the CLI dependency set does not grow (#538
Option B, ruled after Options A and C were measured and rejected on cost and on
scope).
"""

import ctypes
import ctypes.util
import logging
import os
import platform
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final, Self

logger = logging.getLogger(__name__)

#: Fallback page size, used only when the query fails. Report-only: correctness
#: never depends on it.
_PAGE_SIZE_FALLBACK: Final[int] = 4096

#: Cached C-library path so the pin is looked up once per process.
_LIB_NAME: str | None = None


def _page_size() -> int:
    """Page size in bytes (the pin and the allocation are page-rounded)."""
    try:
        page = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        return _PAGE_SIZE_FALLBACK
    if not isinstance(page, int) or page <= 0:
        return _PAGE_SIZE_FALLBACK
    return page


def _round_to_page(size: int) -> int:
    """Round ``size`` up to a whole number of pages (minimum one page)."""
    page = _page_size()
    return ((size + page - 1) // page) * page


def _load_libc() -> ctypes.CDLL | None:
    """Locate the system C library, or ``None`` when it cannot be found."""
    global _LIB_NAME
    if _LIB_NAME is not None:
        return ctypes.CDLL(_LIB_NAME, use_errno=True)
    found = ctypes.util.find_library("c")
    if not found:
        return None
    _LIB_NAME = found
    return ctypes.CDLL(_LIB_NAME, use_errno=True)


def _pin(data: bytearray) -> None:
    """Ask the kernel to keep ``data`` resident.

    Raises:
        RuntimeError: Not Linux, or no C library to ask.
        ValueError: Empty buffer — there is nothing to pin.
        OSError: The kernel refused (permissions, shared budget). Carries
            ``errno``, which is what ``pin_reason`` reports.
    """
    if platform.system() != "Linux":
        raise RuntimeError("the memory pin is only available on Linux")
    if len(data) == 0:
        raise ValueError("cannot pin an empty buffer")
    libc = _load_libc()
    if libc is None:
        raise RuntimeError("cannot find the system C library to pin memory")
    ret = libc.mlock(ctypes.addressof(ctypes.c_char.from_buffer(data)), len(data))
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _unpin(data: bytearray) -> None:
    """Release a pin taken by :func:`_pin`. A no-op when nothing was pinned."""
    if platform.system() != "Linux" or len(data) == 0:
        return
    libc = _load_libc()
    if libc is None:
        return
    ret = libc.munlock(ctypes.addressof(ctypes.c_char.from_buffer(data)), len(data))
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _erase(data: bytearray) -> None:
    """Overwrite every byte of the buffer that OWNS the memory with zeros.

    A plain index loop, so the write goes through the owning object.

    Raises:
        TypeError: Given a ``memoryview`` instead of the owner. A view is not the
            owner, and a silent no-op here would make the release report claim
            more than happened.
    """
    if isinstance(data, memoryview):
        raise TypeError("erase needs the owning bytearray, not a memoryview")
    for i in range(len(data)):
        data[i] = 0


class SecretHolderReleasedError(RuntimeError):
    """Key material was asked for from a holder that holds none.

    Raised by :meth:`SecretHolder.view` after release. Deliberately a plain
    ``RuntimeError`` and not a value/passphrase error: a released holder is a
    bug in the caller, and it must never be read as "wrong passphrase".
    """


class SecretHolder:
    """One secret, one owner, one scoped read-only view at a time.

    Usage::

        with SecretHolder(plaintext) as holder:
            with holder.view() as key_bytes:
                sealed = AESGCM(derived_key).encrypt(nonce, key_bytes, None)

    The construction is the only place the key is copied, :meth:`view` is the
    only place it is read, and leaving the ``with`` block erases it. Readers get
    a ``memoryview``, never ``bytes`` back out, and they never hold the buffer:
    the view is released on the way out, so a view stashed in a global raises
    instead of reading stale memory.

    The allocation is page-ROUNDED, not key-sized. A request the size of one PEM
    (241 bytes for the product's SECP256R1 key) lands in a region the kernel will
    not pin on a workstation, while a page-sized request is pinnable; rounding
    keeps the pin half of this design reachable instead of letting the allocation
    shape decide it silently. The cost is one page per export.
    """

    def __init__(self, data: bytes | bytearray) -> None:
        """Copy ``data`` into a buffer this object owns, then try to pin it.

        Args:
            data: The secret. Must not be empty.

        Raises:
            ValueError: ``data`` is empty — an empty holder is a silent nothing.

        The pin attempt never raises out of here; see :meth:`_attempt_pin`.
        """
        length = len(data)
        if length == 0:
            raise ValueError("SecretHolder takes at least one byte")
        self._length = length
        self._data = bytearray(_round_to_page(length))
        self._data[:length] = data
        self._released = False
        self._zeroized = False
        self._pinned = False
        #: Pin accounting, read-only to callers (the same four facts the core
        #: protected buffer reports, so a report line means the same thing here).
        self.pin_attempted = False
        self.pin_active = False
        self.pin_errno: int | None = None
        self.pin_reason: str | None = None
        self._attempt_pin()

    # --- pin: attempted, reported, never fatal ------------------------------

    def _attempt_pin(self) -> None:
        """Try to pin the buffer. Record the outcome. Never propagate anything.

        A refused pin is the expected condition on an operator workstation, and
        breaking a root-CA backup over it would be its own defect. Mirrors the
        posture of the core cache: catch, record, carry on.
        """
        self.pin_attempted = True
        try:
            _pin(self._data)
        except OSError as exc:
            self.pin_errno = exc.errno
            self.pin_reason = os.strerror(exc.errno) if exc.errno else str(exc)
            return
        except (RuntimeError, ValueError) as exc:
            self.pin_reason = str(exc)
            return
        self._pinned = True
        self.pin_active = True

    @property
    def pin_state(self) -> str:
        """``"active"``, ``"inactive"`` or ``"not attempted"`` — for reports."""
        if self.pin_active:
            return "active"
        if self.pin_attempted:
            return "inactive"
        return "not attempted"

    @property
    def length(self) -> int:
        """Bytes of secret material held (not the page-rounded allocation)."""
        return self._length

    @property
    def released(self) -> bool:
        """Whether this holder has been released."""
        return self._released

    @property
    def zeroized(self) -> bool:
        """Whether release OBSERVED the buffer zeroed — never assumed."""
        return self._zeroized

    # --- the only accessor that reaches the secret --------------------------

    @contextmanager
    def view(self) -> Iterator[memoryview]:
        """Hand out a read-only view of the secret for one block.

        Raises:
            SecretHolderReleasedError: After :meth:`release`. The alternative —
                handing out the padding zeros — is a valid-looking wrong key.
        """
        if self._released:
            raise SecretHolderReleasedError("this SecretHolder holds no key material (released)")
        secret_view = memoryview(self._data)[: self._length].toreadonly()
        try:
            yield secret_view
        finally:
            secret_view.release()

    # --- release ------------------------------------------------------------

    def release(self) -> bool:
        """Erase the buffer, then try to unpin it. Idempotent; reports honestly.

        Returns whether the buffer was observed zeroed. Nothing here raises on a
        failed erase or a failed unpin — both are recorded and reported, because
        the caller is an operator command that must still finish.
        """
        if self._released:
            return self._zeroized
        try:
            _erase(self._data)
            self._zeroized = all(byte == 0 for byte in self._data)
        except Exception:
            self._zeroized = False
            logger.warning("secret holder: release could not zeroize the buffer", exc_info=True)
        self._released = True

        if self._pinned:
            try:
                _unpin(self._data)
                self._pinned = False
            except OSError as exc:
                logger.warning(
                    "secret holder: unpin refused errno=%s %s",
                    exc.errno,
                    os.strerror(exc.errno) if exc.errno else exc,
                )
        self.pin_active = False
        return self._zeroized

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.release()

    def __del__(self) -> None:
        """Backstop only: release on garbage collection if nothing else did.

        The primary release point is the ``with`` block. A reference cycle or
        interpreter teardown can skip this, which is why no claim anywhere says
        the key is gone.
        """
        try:
            self.release()
        except Exception:  # pragma: no cover - teardown path, nothing to unwind
            logger.debug("secret holder: release skipped during teardown", exc_info=True)
