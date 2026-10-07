# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket open-fd-scan-set-cloexec-toctou-ebadf (#535).

The FD-hygiene pass in ``_run_command_direct`` enumerates open descriptors with
``scan_open_fds`` and then acts on the numbers it got back. Between those two
moments a number can stop being an open fd: the listing's OWN directory fd
appears in its own result and ``os.listdir`` closes it before the loop reaches
it, and threads churn other numbers in flight. Acting on a closed number
(``fcntl(F_GETFD)``) raises ``OSError: [Errno 9] Bad file descriptor``, which
pre-fix escaped the middle of an otherwise-healthy command spawn and aborted it.

Fix pinned here: the per-fd act is guarded by ``_mark_cloexec_or_skip_vanished``,
which SKIPS a fd that vanished in flight and lets every other error through.
The catch is narrowed to EBADF on purpose — a blanket ``except OSError`` would
be the fail-open class: it would hide a genuinely broken mark and let a secret
fd leak into the child.

Cells are deterministic by construction (an fd is opened, enumerated into the
pinned scan result, and closed before the act) — no sleeps, no timing.

Scope note (ticket N1): the containing direct path has no production caller at
this tip, so this is hardening. The cells therefore drive the path directly
with ``subprocess.Popen`` patched — no real child is ever execed.
"""

import errno
import fcntl
import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from executor import executor as executor_module
from executor.executor import Executor
from executor.injector import scan_open_fds, set_cloexec
from executor.strategies.sbx_strategy import SbxStrategy

HIGH_FD_BASE = 600


def _high_fd() -> int:
    """A real /dev/null fd numbered above the harness allow-set {0..5}."""
    raw = os.open(os.devnull, os.O_RDONLY)
    try:
        return fcntl.fcntl(raw, fcntl.F_DUPFD, HIGH_FD_BASE)
    finally:
        os.close(raw)


def _fd_is_open(fd: int) -> bool:
    return os.path.exists(f"/proc/self/fd/{fd}")


def _cloexec_flag(fd: int) -> bool:
    return bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)


def _executor() -> Executor:
    """Direct-path harness. The strategy is a stand-in because the DIRECT path
    never touches it and the real one validates the sbx CLI at construction."""
    ex = Executor(
        command_validator=MagicMock(),
        session_id="s-535",
        injection_strategy=MagicMock(spec=SbxStrategy),
    )
    ex.http_client = None
    ex._injection_result = None
    return ex


def _mock_process() -> MagicMock:
    """A child stand-in whose pipe numbers form the pass allow-set {0,1,2,3,4,5}."""
    proc = MagicMock()
    for name, number in (("stdin", 3), ("stdout", 4), ("stderr", 5)):
        stream = getattr(proc, name)
        stream.fileno.return_value = number
    proc.poll.return_value = 0
    proc.wait.return_value = 0
    proc.returncode = 0
    return proc


def _run_with_scan(first_scan_result, second_scan_result=None):
    """Run the direct path with the FD scan pinned, Popen/capture/masking mocked.

    ``first_scan_result`` is what the close-on-exec pass sees; ``second_scan_result``
    is what the whitelist verification sees (default: the clean allow-set).
    Returns the CommandResult; anything that escapes the FD bookkeeping raises
    here, which is exactly what the headline cells assert does NOT happen.
    """
    if second_scan_result is None:
        second_scan_result = {0, 1, 2, 3, 4, 5}
    calls = {"n": 0}

    def scan_double():
        calls["n"] += 1
        return first_scan_result if calls["n"] == 1 else second_scan_result

    ex = _executor()
    with patch("executor.executor.subprocess.Popen", return_value=_mock_process()):
        with patch.object(Executor, "_capture_output", return_value=(b"", b"", 0, 0)):
            with patch("executor.executor.scan_open_fds", side_effect=scan_double):
                with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
                    return ex._run_command_direct(["/bin/echo", "hi"], [], None, None)


# ---------------------------------------------------------------------------
# AC1 + AC2 — the scan→act window: a vanished fd is skipped, the pass finishes
# ---------------------------------------------------------------------------


class TestVanishedFdInCommandPath:
    def test_fd_closed_after_the_scan_does_not_abort_the_command(self):
        """AC2, the deterministic TOCTOU reproduction.

        A real fd is opened, enumerated into the scan result, then closed BEFORE
        the pass acts on it — the exact shape of the listing's own dirfd. Pre-fix
        this raises ``OSError(9, 'Bad file descriptor')`` out of the command
        path (quoted in the leg report).
        """
        vanished = _high_fd()
        try:
            os.close(vanished)
            assert not _fd_is_open(vanished)
            result = _run_with_scan([vanished])
            assert result.exit_code == 0
        finally:
            if _fd_is_open(vanished):
                os.close(vanished)

    def test_remaining_fds_still_get_cloexec_after_a_skip(self):
        """AC1, second half: skipping one vanished number does not end the pass.

        The vanished number is listed FIRST, so pre-fix the loop dies on it and
        neither live fd is ever marked; post-fix both are.
        """
        vanished = _high_fd()
        live_a = _high_fd()
        live_b = _high_fd()
        try:
            os.close(vanished)
            assert not _cloexec_flag(live_a)
            assert not _cloexec_flag(live_b)

            _run_with_scan([vanished, live_a, live_b])

            assert _cloexec_flag(live_a), "first live fd after the skip was not marked"
            assert _cloexec_flag(live_b), "second live fd after the skip was not marked"
        finally:
            for fd in (live_a, live_b):
                os.close(fd)
            if _fd_is_open(vanished):
                os.close(vanished)

    def test_real_scan_own_dirfd_number_is_tolerated(self):
        """AC3: a vanished number taken from a REAL scan_open_fds result.

        ``os.listdir("/proc/self/fd")`` opens a dirfd, so that number appears in
        the result it returns and is closed before anyone can act on it — the
        production instance of this class. The cell reproduces the same shape
        deterministically instead of betting on the dirfd's number: a fd the cell
        owns is open while the real scanner runs and is closed the instant the
        result comes back, so it is guaranteed to be an enumerated-then-closed
        number in a genuine scan result.

        Numbers the real scan reported as still open are left out on purpose:
        the cell must not rewrite FD_CLOEXEC on the pytest process's own
        descriptors.
        """
        mine = _high_fd()
        scanned = scan_open_fds()
        assert scanned is not None, "/proc/self/fd unreadable in this venue"
        assert mine in scanned, "the real scanner did not report the fd it should have seen"
        os.close(mine)

        vanished = sorted(fd for fd in scanned if not _fd_is_open(fd))
        assert mine in vanished, "the enumerated fd was not closed before the act"

        result = _run_with_scan(vanished, second_scan_result=set(scanned) | {0, 1, 2, 3, 4, 5})
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# The guard itself: what it skips, and what it still lets through
# ---------------------------------------------------------------------------


class TestMarkOrSkipGuard:
    def _mark(self, fd: int):
        guard = getattr(executor_module, "_mark_cloexec_or_skip_vanished", None)
        if guard is None:  # pre-fix: the helper does not exist yet
            pytest.fail("_mark_cloexec_or_skip_vanished is absent from executor.executor")
        return guard(fd)

    def test_live_fd_is_marked(self):
        """The unchanged half: a live fd gets FD_CLOEXEC exactly as before."""
        fd = _high_fd()
        try:
            assert not _cloexec_flag(fd)
            self._mark(fd)
            assert _cloexec_flag(fd)
        finally:
            os.close(fd)

    def test_vanished_fd_is_skipped_not_raised(self):
        """The tolerated error is EXACTLY the one that used to escape.

        Same closed number, two calls: the primitive still raises EBADF (the
        tolerance is the window's policy, not a lie inside ``set_cloexec``), and
        the guarded mark returns quietly.
        """
        fd = _high_fd()
        os.close(fd)
        assert not _fd_is_open(fd)

        with pytest.raises(OSError) as excinfo:
            set_cloexec(fd)
        assert excinfo.value.errno == errno.EBADF

        self._mark(fd)  # must not raise

    def test_other_oserror_from_the_mark_still_surfaces(self):
        """AC-paired-negative: EINVAL is NOT a vanished fd and must propagate."""

        def explode(_fd: int) -> None:
            raise OSError(errno.EINVAL, "Invalid argument")

        original = executor_module.set_cloexec
        executor_module.set_cloexec = explode  # type: ignore[assignment]
        try:
            with pytest.raises(OSError) as excinfo:
                self._mark(HIGH_FD_BASE)
        finally:
            executor_module.set_cloexec = original  # type: ignore[assignment]
        assert excinfo.value.errno == errno.EINVAL

    def test_oserror_carrying_no_errno_still_surfaces(self):
        """An OSError with errno=None is unknown, so it is never swallowed."""

        def explode(_fd: int) -> None:
            raise OSError("no errno attached")

        original = executor_module.set_cloexec
        executor_module.set_cloexec = explode  # type: ignore[assignment]
        try:
            with pytest.raises(OSError):
                self._mark(HIGH_FD_BASE)
        finally:
            executor_module.set_cloexec = original  # type: ignore[assignment]

    def test_skip_is_logged_not_silent(self, caplog):
        """A skipped mark is visible in the log (debug), never silently dropped."""
        fd = _high_fd()
        os.close(fd)
        with caplog.at_level(logging.DEBUG, logger="venya.executor"):
            self._mark(fd)
        assert str(fd) in caplog.text


# ---------------------------------------------------------------------------
# AC4 — the #453 truthfulness contract is untouched
# ---------------------------------------------------------------------------


class TestIndeterminateScanStillSkipsWholePass:
    def test_none_scan_attempts_no_marks_and_still_warns(self, caplog):
        """scan -> None (could not look) still skips the pass with its warning.

        The new per-fd tolerance must not turn "could not look" into "looked and
        found nothing": no mark is attempted, and the indeterminate warning is
        still logged.
        """
        caplog.set_level(logging.WARNING, logger="venya.executor")
        marks = []
        original = executor_module.set_cloexec
        executor_module.set_cloexec = lambda fd: marks.append(fd)  # type: ignore[assignment]
        try:
            _run_with_scan(None)
        finally:
            executor_module.set_cloexec = original  # type: ignore[assignment]

        assert marks == []
        assert "set_cloexec pass skipped" in caplog.text
