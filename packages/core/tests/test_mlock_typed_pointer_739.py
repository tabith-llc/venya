"""#739 — the mlock address travels as a pointer, and the errno is the current one.

Why these cells are shaped like this: a buffer that happens to sit below 2 GiB
passes even when the address is marshalled as a C ``int``, because the low 32
bits then equal the whole value. So every discriminating cell here allocates
ABOVE that ceiling, asserts inside the cell that the address really is above it,
and reads the kernel's own answer (``/proc/self/smaps`` ``Locked:``) rather than
only a return code. Where the host will not hand out such an address the cell
skips and says so; it never passes on a buffer that cannot tell the two shapes
apart.
"""

import ctypes
import ctypes.util
import errno
import mmap
import re

import core.engine.secure_memory as sm
import pytest
from core.engine.secure_memory import KekCache, secure_mlock, secure_munlock

#: The whole value a C ``int`` argument can still carry: 2 GiB on this box.
INT_CEILING: int = 2**31 - 1

#: Where to ask the kernel for the discriminating buffer — far above the
#: ceiling and page-aligned. ``mmap`` honours a non-zero hint as a start point.
HIGH_HINT: int = 0x5_0000_0000

#: An address no mapping covers, so the call must refuse with ENOMEM on Linux.
UNMAPPED: int = 0x1

MAP_FAILED: int = (1 << 64) - 1
_SMAPS_HEADER = re.compile(r"^[0-9a-f]+-[0-9a-f]+ ")


def _libc(declare: bool = True) -> ctypes.CDLL:
    """A C library handle for the cells' own use — typed, or deliberately not."""
    lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    lib.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long)
    lib.mmap.restype = ctypes.c_void_p
    lib.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    lib.munmap.restype = ctypes.c_int
    if declare:
        lib.mlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        lib.mlock.restype = ctypes.c_int
        lib.munlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        lib.munlock.restype = ctypes.c_int
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
    """The handle the product loads carries the argument and return types."""

    def test_mlock_and_munlock_are_declared(self):
        lib = sm._load_system_lib()
        assert lib.mlock.argtypes == (ctypes.c_void_p, ctypes.c_size_t), lib.mlock.argtypes
        assert lib.mlock.restype is ctypes.c_int
        assert lib.munlock.argtypes == (ctypes.c_void_p, ctypes.c_size_t), lib.munlock.argtypes
        assert lib.munlock.restype is ctypes.c_int

    def test_loader_caches_the_handle_not_just_its_name(self):
        """The second call answers with the SAME handle the first one built.

        Building a fresh handle per call is what lost ``use_errno=True``: only
        the first load passed the flag, so every later refusal was reported from
        a handle that never writes the thread's errno slot.
        """
        first = sm._load_system_lib()
        second = sm._load_system_lib()
        assert second is first, "the loader must hand back the handle it built, not a new one"


class TestPinEngagesAboveTheCeiling:
    """The discriminating pair: one process, one buffer, two argument shapes."""

    def test_product_handle_pins_a_buffer_above_the_int_ceiling(self, high_buffer):
        addr = high_buffer
        assert addr > INT_CEILING, "the cell's own premise — a buffer below this proves nothing"
        assert (addr & 0xFFFFFFFF) != addr, "truncation to a C int must be lossy for this buffer"

        lib = sm._load_system_lib()
        ctypes.set_errno(0)
        ret = lib.mlock(addr, mmap.PAGESIZE)  # the plain-int call shape secure_mlock uses
        refused = ctypes.get_errno()
        assert ret == 0, f"the kernel refused the range: rc={ret} errno={refused} {errno.errorcode.get(refused)}"
        assert _locked_kib(addr) > 0, f"mlock returned but the kernel reports {addr:#x} unlocked"

        assert lib.munlock(addr, mmap.PAGESIZE) == 0, "the typed munlock must release the same pin"
        assert _locked_kib(addr) == 0, f"{addr:#x} still reports a lock after munlock"

    def test_untyped_argument_leaves_the_same_buffer_unlocked(self, high_buffer):
        """The paired negative, same process, same buffer: the refusal is the ARGUMENT.

        Without ``argtypes`` ctypes marshals the address as a C int, so the
        kernel is handed the low 32 bits of it. This cell shows the host, the
        budget, and the address are not what made the difference — the shape
        alone is, and that is what keeps the cell above honest.
        """
        addr = high_buffer
        assert addr > INT_CEILING, "the cell's own premise — a buffer below this proves nothing"

        untyped = _libc(declare=False)
        assert untyped.mlock.argtypes is None, "the control must be genuinely untyped"
        ctypes.set_errno(0)
        ret = untyped.mlock(addr, mmap.PAGESIZE)
        refused = ctypes.get_errno()
        if ret == 0 and _locked_kib(addr) > 0:
            untyped.munlock(addr, mmap.PAGESIZE)
            pytest.fail(
                f"the truncated argument pinned {addr:#x} anyway (rc={ret}, errno={refused}): this host "
                "cannot discriminate the argument shape, so these cells would prove nothing"
            )
        assert _locked_kib(addr) == 0, f"the untyped shape engaged the pin: rc={ret} errno={refused}"

    def test_secure_mlock_and_munlock_pin_a_real_bytearray(self):
        """The whole product path on a buffer that sits above the ceiling.

        A small bytearray lives in the heap, below 2 GiB, and would pass with a
        truncated argument — so the cell asks for one large enough to be mapped
        high, and skips out loud if the host hands it back low.
        """
        data = bytearray(1 << 20)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(data))
        if addr <= INT_CEILING:
            pytest.skip(
                f"SKIP-LOUDLY: the host placed the 1 MiB buffer at {addr:#x}, below {INT_CEILING:#x} — it cannot discriminate the argument"
            )
        try:
            secure_mlock(data)
        except OSError as refused:
            if refused.errno in (errno.EPERM, errno.EACCES):
                pytest.skip(
                    f"SKIP-LOUDLY: this host withholds the privilege (errno={refused.errno} {refused}); nothing to observe here"
                )
            if refused.errno == errno.ENOMEM:
                # ENOMEM is also what a corrupted range answers with, so the cell
                # cannot call it a host answer without asking the same kernel the
                # same question through a declared handle first.
                reference = _libc()
                ctypes.set_errno(0)
                if reference.mlock(addr, len(data)) == 0:
                    reference.munlock(addr, len(data))
                    pytest.fail(
                        f"the kernel pins {addr:#x} through a declared handle but secure_mlock was refused "
                        f"(errno={refused.errno} {refused}): the argument the product passes is not this address"
                    )
                pytest.skip(
                    f"SKIP-LOUDLY: this host refuses the pin for a declared handle too (errno={refused.errno} {refused}) — a budget answer, not an argument answer"
                )
            raise
        try:
            assert _locked_kib(addr) > 0, f"secure_mlock returned but the kernel reports {addr:#x} unlocked"
        finally:
            secure_munlock(data)
        assert _locked_kib(addr) == 0, "secure_munlock must release the pin it reports"


class TestErrnoIsTheCurrentOne:
    """A refusal answers with the errno of THAT refusal, on the second call and later."""

    def test_every_load_in_one_process_reports_its_own_errno(self):
        """Pre-fix, the loads after the first were built without ``use_errno=True``.

        ``ctypes.get_errno()`` reads one per-thread slot that only a
        ``use_errno`` handle writes, so a refusal through such a handle left
        whatever the last call stored there — measured on this box as
        ``[Errno 0] Success`` for a call that failed.
        """
        handles = [sm._load_system_lib(), sm._load_system_lib(), sm._load_system_lib()]
        observed = []
        for lib in handles:
            ctypes.set_errno(0)
            ret = lib.mlock(ctypes.c_void_p(UNMAPPED), mmap.PAGESIZE)
            assert ret != 0, "the control call must fail — an unmapped range is how this cell asks"
            observed.append(ctypes.get_errno())
        assert observed == [errno.ENOMEM] * len(handles), (
            f"a failing call must report its own errno; the three loads reported {observed} "
            f"({[errno.errorcode.get(e) for e in observed]})"
        )

    def test_errno_is_not_reported_from_an_earlier_call(self):
        """A stale value left in the slot must not be read as this call's answer."""
        lib = sm._load_system_lib()
        ctypes.set_errno(errno.ERANGE)
        assert lib.mlock(ctypes.c_void_p(UNMAPPED), mmap.PAGESIZE) != 0
        reported = ctypes.get_errno()
        assert reported != errno.ERANGE, "the call reported the value planted before it, not its own"
        assert (
            reported == errno.ENOMEM
        ), f"expected the kernel's own answer, got {reported} {errno.errorcode.get(reported)}"


class TestPinLogLineKeepsItsWord:
    """The startup line names the knob the kernel's answer actually points at."""

    @staticmethod
    def _refusing_lib():
        class _Lib:
            def mlock(self, addr: int, size: int) -> int:
                return -1

            def munlock(self, addr: int, size: int) -> int:
                return 0

        return _Lib()

    def _line(self, monkeypatch, caplog, reported_errno: int | None) -> str:
        monkeypatch.setattr(sm.platform, "system", lambda: "Linux")
        monkeypatch.setattr(sm, "_load_system_lib", lambda: self._refusing_lib())
        monkeypatch.setattr(sm.ctypes, "get_errno", lambda: reported_errno)
        with caplog.at_level("INFO", logger="core.engine.secure_memory"):
            cache = KekCache(32, mlock=True)
        cache.release()
        lines = [record.getMessage() for record in caplog.records if "kek cache:" in record.getMessage()]
        assert lines, "the cache logged no pin line at all"
        return lines[-1]

    def test_a_privilege_answer_names_the_capability(self, monkeypatch, caplog):
        line = self._line(monkeypatch, caplog, errno.EPERM)
        assert "pin=inactive" in line, line
        assert "NOT pinned" in line, line
        assert "errno=1" in line, line
        assert "CAP_IPC_LOCK" in line, line

    def test_a_non_privilege_answer_does_not_send_the_reader_to_capabilities(self, monkeypatch, caplog):
        line = self._line(monkeypatch, caplog, errno.EINVAL)
        assert "pin=inactive" in line, line
        assert "NOT pinned" in line, line
        assert "errno=22" in line, line
        assert "CAP_IPC_LOCK" not in line, f"a non-privilege answer printed a capability hint: {line}"

    def test_a_budget_answer_names_the_budget(self, monkeypatch, caplog):
        line = self._line(monkeypatch, caplog, errno.ENOMEM)
        assert "locked-memory limit" in line, line
