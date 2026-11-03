"""#739 — the CLI pin passes the buffer address as a pointer too.

The core and the CLI carry the same four-call shape independently, so the CLI
gets its own cells. A buffer below 2 GiB passes whether or not the address is
marshalled as a pointer, because the low 32 bits then equal the whole value, so
the discriminating cells here map their buffer above that ceiling, assert that
inside the cell, and read the kernel's own ``smaps Locked:`` answer. Where the
host will not cooperate a cell skips and says so rather than passing.
"""

import ctypes
import ctypes.util
import errno
import mmap
import os
import re

import pytest
from venya_cli import secret_holder as sh

INT_CEILING: int = 2**31 - 1
HIGH_HINT: int = 0x5_0000_0000
MAP_FAILED: int = (1 << 64) - 1
_SMAPS_HEADER = re.compile(r"^[0-9a-f]+-[0-9a-f]+ ")


def _libc(declare: bool = True) -> ctypes.CDLL:
    lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    lib.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long)
    lib.mmap.restype = ctypes.c_void_p
    lib.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    lib.munmap.restype = ctypes.c_int
    if declare:
        lib.mlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        lib.mlock.restype = ctypes.c_int
    return lib


def _locked_kib(addr: int) -> int:
    """``Locked:`` KiB for the VMA holding ``addr``, or -1 when it cannot be read."""
    vma = None
    with open("/proc/self/maps") as handle:
        for line in handle:
            low, high = line.split()[0].split("-")
            if int(low, 16) <= addr < int(high, 16):
                vma = f"{low}-{high}"
                break
    if vma is None:
        return -1
    inside = False
    with open("/proc/self/smaps") as handle:
        for line in handle:
            if inside:
                if _SMAPS_HEADER.match(line):
                    break
                if line.startswith("Locked:"):
                    return int(line.split(":")[1].split()[0])
            elif line.startswith(vma + " "):
                inside = True
    return -1


@pytest.fixture
def high_buffer():
    """One page mapped above the int ceiling; yields its address, unmaps after."""
    lib = _libc()
    addr = lib.mmap(
        ctypes.c_void_p(HIGH_HINT),
        mmap.PAGESIZE,
        mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON,
        -1,
        0,
    )
    if addr is None or addr == MAP_FAILED:
        pytest.skip(
            f"SKIP-LOUDLY: the host gave no mapping at {HIGH_HINT:#x}, so no buffer here can discriminate the argument"
        )
    if addr <= INT_CEILING:
        lib.munmap(ctypes.c_void_p(addr), mmap.PAGESIZE)
        pytest.skip(
            f"SKIP-LOUDLY: the host placed the buffer at {addr:#x}, below {INT_CEILING:#x} — a buffer that low passes on both shapes and proves nothing"
        )
    yield addr
    lib.munmap(ctypes.c_void_p(addr), mmap.PAGESIZE)


class TestTheLoadedHandleDeclaresItsArguments:
    def test_mlock_and_munlock_are_declared(self):
        lib = sh._load_libc()
        assert lib.mlock.argtypes == (ctypes.c_void_p, ctypes.c_size_t), lib.mlock.argtypes
        assert lib.mlock.restype is ctypes.c_int
        assert lib.munlock.argtypes == (ctypes.c_void_p, ctypes.c_size_t), lib.munlock.argtypes
        assert lib.munlock.restype is ctypes.c_int

    def test_every_load_returns_a_handle_that_writes_errno(self):
        """The CLI caches the library NAME, so each load builds a handle.

        Each one must carry ``use_errno=True`` or the refusal the holder reports
        is the answer of whichever handle last wrote the thread's errno slot.
        """
        for lib in (sh._load_libc(), sh._load_libc()):
            ctypes.set_errno(0)
            assert lib.mlock(ctypes.c_void_p(0x1), mmap.PAGESIZE) != 0, "the control call must fail"
            assert ctypes.get_errno() == errno.ENOMEM, "a failing call reported an earlier call's errno"


class TestPinEngagesAboveTheCeiling:
    def test_cli_handle_pins_a_buffer_above_the_int_ceiling(self, high_buffer):
        addr = high_buffer
        assert addr > INT_CEILING, "the cell's own premise — a buffer below this proves nothing"
        assert (addr & 0xFFFFFFFF) != addr, "truncation to a C int must be lossy for this buffer"

        lib = sh._load_libc()
        ctypes.set_errno(0)
        ret = lib.mlock(addr, mmap.PAGESIZE)  # the plain-int call shape _pin uses
        refused = ctypes.get_errno()
        assert ret == 0, f"the kernel refused the range: rc={ret} errno={refused} {errno.errorcode.get(refused)}"
        assert _locked_kib(addr) > 0, f"mlock returned but the kernel reports {addr:#x} unlocked"

        assert lib.munlock(addr, mmap.PAGESIZE) == 0, "the typed munlock must release the same pin"
        assert _locked_kib(addr) == 0, f"{addr:#x} still reports a lock after munlock"

    def test_untyped_argument_leaves_the_same_buffer_unlocked(self, high_buffer):
        """The paired negative, same process and buffer: the ARGUMENT is the difference."""
        addr = high_buffer
        assert addr > INT_CEILING, "the cell's own premise — a buffer below this proves nothing"

        untyped = _libc(declare=False)
        assert untyped.mlock.argtypes is None, "the control must be genuinely untyped"
        ctypes.set_errno(0)
        ret = untyped.mlock(addr, mmap.PAGESIZE)
        if ret == 0 and _locked_kib(addr) > 0:
            untyped.munlock(addr, mmap.PAGESIZE)
            pytest.fail(
                f"the truncated argument pinned {addr:#x} anyway (rc={ret}): this host cannot discriminate the argument shape"
            )
        assert _locked_kib(addr) == 0, f"the untyped shape engaged the pin: rc={ret} errno={ctypes.get_errno()}"

    def test_pin_and_unpin_a_real_bytearray(self):
        """The whole ``_pin``/``_unpin`` path on a buffer mapped high, if the host allows it."""
        data = bytearray(1 << 20)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(data))
        if addr <= INT_CEILING:
            pytest.skip(
                f"SKIP-LOUDLY: the host placed the 1 MiB buffer at {addr:#x}, below {INT_CEILING:#x} — it cannot discriminate the argument"
            )
        try:
            sh._pin(data)
        except OSError as refused:
            if refused.errno in (errno.EPERM, errno.EACCES):
                pytest.skip(
                    f"SKIP-LOUDLY: this host withholds the privilege (errno={refused.errno} {refused}); nothing to observe here"
                )
            if refused.errno == errno.ENOMEM:
                # ENOMEM is also what a corrupted range answers with, so the cell
                # asks the same kernel the same question through a declared handle
                # before it is allowed to call that a host answer.
                reference = _libc()
                ctypes.set_errno(0)
                if reference.mlock(addr, len(data)) == 0:
                    reference.munlock(addr, len(data))
                    pytest.fail(
                        f"the kernel pins {addr:#x} through a declared handle but _pin was refused "
                        f"(errno={refused.errno} {refused}): the argument the CLI passes is not this address"
                    )
                pytest.skip(
                    f"SKIP-LOUDLY: this host refuses the pin for a declared handle too (errno={refused.errno} {refused}) — a budget answer, not an argument answer"
                )
            raise
        try:
            assert _locked_kib(addr) > 0, f"_pin returned but the kernel reports {addr:#x} unlocked"
        finally:
            sh._unpin(data)
        assert _locked_kib(addr) == 0, "_unpin must release the pin it took"


class TestHolderStillReportsItsOwnAnswer:
    """The holder's pin accounting describes the kernel's answer, not an assumption."""

    def test_a_refused_pin_records_the_refusing_errno(self, monkeypatch):
        class _Refusing:
            def mlock(self, addr: int, size: int) -> int:
                return -1

            def munlock(self, addr: int, size: int) -> int:
                return 0

        monkeypatch.setattr(sh.platform, "system", lambda: "Linux")
        monkeypatch.setattr(sh, "_load_libc", lambda: _Refusing())
        monkeypatch.setattr(ctypes, "get_errno", lambda: errno.EPERM)
        holder = sh.SecretHolder(b"k" * 32)
        assert holder.pin_active is False
        assert holder.pin_errno == errno.EPERM
        assert holder.pin_reason == os.strerror(errno.EPERM)
        assert holder.pin_state == "inactive"
        holder.release()
