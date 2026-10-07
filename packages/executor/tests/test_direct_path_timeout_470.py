# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket direct-path-capture-timeout-untimed-wait (#470).

Pre-fix the LEGACY direct (memfd) path bounded its output capture with
``SBX_TIMEOUT``, logged a capture timeout, broke out of the loop — and then
called ``process.wait()`` with NO bound whatsoever. A child that stopped
writing but never exited therefore parked the worker indefinitely *after* the
timeout had supposedly been handled: the timeout produced a log line, not a
stop. Compounding it, the ``stdin=PIPE`` handle was never closed, so a child
reading stdin to EOF before exiting blocked on the write end the parent still
held — the pipe-buffer deadlock the row names. A wedged session held a thread
and a child process until the daemon was restarted.

Fix pinned here:
1. one bound (``VENYA_DIRECT_PATH_TIMEOUT``, default ``SBX_TIMEOUT``) covers
   capture AND the wait that follows it, read once per command so the two
   halves cannot each grant a fresh budget;
2. on expiry the child is TERMINATED — as its own process group, since it was
   spawned ``start_new_session=True`` — and reaped; the exit code reports -1
   instead of pretending the command finished on its own terms;
3. the child's stdin write end is closed before capture/wait on every branch.

Paired negatives: a normal fast command returns the same exit code / stdout /
stderr as today, and the child that reads stdin receives EOF rather than data.

NOTE ON ``_quiet_fd_scan``: these cells exercise the real subprocess path, and
``_run_command_direct`` ends its FD bookkeeping by calling ``set_cloexec`` on
every number ``scan_open_fds`` reported that is not in its allow-set. The
listing's own directory FD appears in that result and is closed before the loop
reaches it, so the real call raises EBADF in the middle of an otherwise healthy
command. That is a PRE-EXISTING defect at ``c65f26f`` (reproduced against the
unmodified HEAD source by a plain fast-command cell; reported in the leg
report, NOT fixed here — different ticket), and every existing unit of this path
in the repo already pins the scan (test_executor.py, test_executor_pipeline.py).
Pinning it does not weaken an assertion of this row: none of these cells are
about the FD scan.
"""

import contextlib
import logging
import os
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import (
    DIRECT_CHILD_REAP_SECONDS,
    DIRECT_PATH_TIMEOUT_ENV,
    SBX_TIMEOUT,
    Executor,
    _close_child_stdin,
    _direct_path_timeout,
    _terminate_child_process,
)
from executor.strategies.sbx_strategy import SbxStrategy

SHORT_BOUND = "2"
BIN_TIMEOUT = "/usr/bin/timeout"
BIN_CAT = "/usr/bin/cat"


@pytest.fixture(autouse=True)
def _bound_via_env(monkeypatch):
    """Every cell in this file runs with a 2 s direct-path bound."""
    monkeypatch.setenv(DIRECT_PATH_TIMEOUT_ENV, SHORT_BOUND)


def _executor() -> Executor:
    """Direct-path harness. The strategy is a stand-in because the DIRECT path
    never touches it and the real one validates the sbx CLI at construction
    (absent in this venue)."""
    return Executor(
        command_validator=MagicMock(),
        session_id="s-470",
        injection_strategy=MagicMock(spec=SbxStrategy),
    )


@contextlib.contextmanager
def _quiet_fd_scan():
    """Pin the FD scan to the clean set — see the module docstring NOTE."""
    with patch("executor.executor.scan_open_fds", return_value={0, 1, 2}):
        yield


def _run_direct(command: list[str]):
    ex = _executor()
    ex.http_client = None
    ex._injection_result = None
    started = time.time()
    with _quiet_fd_scan():
        result = ex._run_command_direct(command, [], None, None)
    return result, time.time() - started


def _popen_subclass():
    """A real Popen subclass usable as a patch double (records/intercepts)."""
    return type("SpyPopen", (subprocess.Popen,), {})


# ---------------------------------------------------------------------------
# AC1 — the bound: a child that never exits yields a result, and is gone
# ---------------------------------------------------------------------------


class TestBoundedWait:
    @pytest.mark.skipif(not os.path.exists(BIN_TIMEOUT), reason="coreutils /usr/bin/timeout required")
    def test_child_that_never_exits_returns_within_the_bound(self):
        """The headline: the post-capture wait is bounded AND the child dies.

        ``timeout 300 sleep 300`` writes nothing and exits only on its own
        300 s timer; with a 2 s bound the worker must come back on the bound,
        not when the child decides to.
        """
        result, elapsed = _run_direct([BIN_TIMEOUT, "300", "sleep", "300"])

        assert float(SHORT_BOUND) <= elapsed < 15, f"unbounded wait survived the fix: {elapsed:.1f}s"
        # The bound KILLED it: the honest code is the signal death (-9), not a
        # fabricated success and not the -1 reserved for a child we could not
        # reap at all.
        assert result.exit_code == -9

    @pytest.mark.skipif(not os.path.exists(BIN_TIMEOUT), reason="coreutils /usr/bin/timeout required")
    def test_paired_negative_the_child_is_really_gone(self):
        """'the process is gone afterwards' — verified against the pid itself."""
        pids = []

        class _RecordingPopen(_popen_subclass()):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                pids.append(self.pid)

        with patch("executor.executor.subprocess.Popen", _RecordingPopen):
            _run_direct([BIN_TIMEOUT, "300", "sleep", "300"])

        assert len(pids) == 1
        with pytest.raises(ProcessLookupError):
            os.kill(pids[0], 0)  # reaped: not a live process, not even a zombie

    def test_paired_negative_fast_command_is_unchanged(self):
        """AC4: a normal command returns the same exit code/stdout/stderr."""
        result = _run_direct(["/bin/echo", "hi"])[0]
        assert result.exit_code == 0
        assert result.stdout == b"hi\n"
        assert result.stderr == b""

    def test_wait_carries_a_timeout_argument(self):
        """The row's mechanism: the post-capture wait is no longer bare."""
        waits = []

        class _SpyPopen(_popen_subclass()):
            def wait(self, timeout=None):  # type: ignore[override]
                waits.append(timeout)
                return super().wait(timeout=timeout)

        with patch("executor.executor.subprocess.Popen", _SpyPopen):
            _run_direct(["/bin/echo", "hi"])

        assert waits and waits[0] is not None and waits[0] > 0

    def test_timeout_is_logged_loudly(self, caplog):
        """A terminated child is an ERROR the operator can find, not a -1."""
        import subprocess as sp

        class _Stuck(_popen_subclass()):
            def wait(self, timeout=None):  # type: ignore[override]
                raise sp.TimeoutExpired(cmd=["stuck"], timeout=timeout or 0)

        with caplog.at_level(logging.ERROR, logger="venya.executor"):
            with patch("executor.executor.subprocess.Popen", _Stuck):
                with patch("executor.executor._terminate_child_process") as term:
                    with _quiet_fd_scan():
                        ex = _executor()
                        ex.http_client = None
                        result = ex._run_command_direct(["/bin/echo", "hi"], [], None, None)
        assert "did not exit within" in caplog.text
        term.assert_called_once()
        assert result.exit_code == -1


# ---------------------------------------------------------------------------
# AC2 — stdin is closed on every branch, including the error branches
# ---------------------------------------------------------------------------


class TestStdinClosed:
    @pytest.mark.skipif(not os.path.exists(BIN_CAT), reason="coreutils /usr/bin/cat required")
    def test_child_reading_stdin_gets_eof_and_exits(self):
        """Pre-fix this parked the worker: ``cat`` waits for a parent that
        neither writes nor closes its end. EOF is the only thing that frees it."""
        result, elapsed = _run_direct([BIN_CAT])

        assert elapsed < 15, f"stdin stayed open: cat blocked {elapsed:.1f}s"
        assert result.exit_code == 0
        assert result.stdout == b""

    def test_paired_negative_close_happens_before_capture(self):
        """Every branch, and ordered: the close precedes capture and wait."""
        order = []
        ex = _executor()
        ex.http_client = None
        stdin = MagicMock(name="stdin")
        stdin.fileno.return_value = 6
        stdin.close.side_effect = lambda: order.append("stdin-close")
        proc = MagicMock(name="process")
        proc.stdin = stdin
        proc.stdout = None
        proc.stderr = None
        proc.wait.return_value = 0

        def capture(process, deadline=None):
            order.append("capture")
            return b"", b"", 0, 0

        with _quiet_fd_scan():
            with patch("executor.executor.subprocess.Popen", return_value=proc):
                with patch.object(Executor, "_capture_output", side_effect=capture):
                    ex._run_command_direct(["/bin/echo", "hi"], [], None, None)

        assert order == ["stdin-close", "capture"]

    def test_close_tolerates_an_oserror(self):
        """A pipe that refuses to close is logged, not fatal (#470 AC2)."""
        stdin = MagicMock()
        stdin.close.side_effect = OSError("bad fd")
        proc = MagicMock()
        proc.stdin = stdin
        with patch("executor.executor.logger") as log:
            _close_child_stdin(proc)
        log.exception.assert_called_once()

    def test_close_tolerates_no_stdin(self):
        proc = MagicMock()
        proc.stdin = None
        _close_child_stdin(proc)  # must not raise

    @pytest.mark.skipif(not os.path.exists(BIN_TIMEOUT), reason="coreutils /usr/bin/timeout required")
    def test_stdin_closed_on_the_timeout_branch_too(self):
        """AC2 says EVERY branch, including the one that terminates the child."""
        closed = []

        class _SpyPopen(_popen_subclass()):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                inner = self.stdin

                class _Wrap:
                    """Thin proxy over the real stdin pipe: records the close and
                    delegates everything else (communicate() touches more than
                    close/fileno, so an allowlist of methods would rot)."""

                    def __init__(self, inner):
                        self._inner = inner

                    def close(self):
                        closed.append(True)
                        self._inner.close()

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                self.stdin = _Wrap(inner)

        with patch("executor.executor.subprocess.Popen", _SpyPopen):
            _run_direct([BIN_TIMEOUT, "300", "sleep", "300"])

        # >= 1 close: ours happens on the way to the bound; communicate() may
        # close the (already-closed) pipe a second time, which is a no-op.
        assert closed, "stdin was still open on the terminate branch"


# ---------------------------------------------------------------------------
# The bound itself: one budget, read once, overridable
# ---------------------------------------------------------------------------


class TestBoundPlumbing:
    def test_default_is_the_sandbox_budget(self, monkeypatch):
        monkeypatch.delenv(DIRECT_PATH_TIMEOUT_ENV, raising=False)
        assert _direct_path_timeout() == float(SBX_TIMEOUT)

    @pytest.mark.parametrize("raw", ["7", "7.5", "0"])
    def test_env_override_is_honoured(self, monkeypatch, raw):
        monkeypatch.setenv(DIRECT_PATH_TIMEOUT_ENV, raw)
        assert _direct_path_timeout() == float(raw)

    def test_garbage_override_falls_back_loudly(self, monkeypatch, caplog):
        """Fail loudly, then use the safe default — never a silent 0."""
        monkeypatch.setenv(DIRECT_PATH_TIMEOUT_ENV, "soon")
        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            assert _direct_path_timeout() == float(SBX_TIMEOUT)
        assert "is not a number" in caplog.text

    def test_capture_and_wait_share_one_deadline(self):
        """The single-budget property: _run_command_direct hands _capture_output
        the same deadline its wait consumes, so neither half gets a fresh hour."""
        seen = {}

        ex = _executor()
        ex.http_client = None

        def fake_capture(process, deadline=None):
            seen["deadline"] = deadline
            return b"", b"", 0, 0

        proc = MagicMock()
        proc.stdin = None
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        with _quiet_fd_scan():
            with patch.object(Executor, "_capture_output", side_effect=fake_capture):
                with patch("executor.executor.subprocess.Popen", return_value=proc):
                    ex._run_command_direct(["/bin/echo", "hi"], [], None, None)

        assert seen["deadline"] is not None
        wait_timeout = proc.wait.call_args.kwargs["timeout"]
        assert 0 <= wait_timeout <= float(SHORT_BOUND)
        assert seen["deadline"] - time.time() == pytest.approx(wait_timeout, abs=1.0)


# ---------------------------------------------------------------------------
# _capture_output / terminate helpers
# ---------------------------------------------------------------------------


class TestCaptureDeadline:
    def test_expired_deadline_stops_the_loop(self, caplog):
        """A deadline already in the past ends the loop instead of polling a
        child forever (the loop's own bound was the second half of the row)."""
        proc = MagicMock()
        out, err = MagicMock(), MagicMock()
        out.fileno.return_value = 4
        err.fileno.return_value = 5
        proc.stdout = out
        proc.stderr = err

        ex = _executor()
        with patch("executor.executor.select.select") as sel:
            with caplog.at_level(logging.WARNING, logger="venya.executor"):
                stdout, stderr, total_out, total_err = ex._capture_output(proc, deadline=time.time() - 1)

        sel.assert_not_called()
        assert (stdout, stderr, total_out, total_err) == (b"", b"", 0, 0)
        assert "bound" in caplog.text

    def test_none_fds_exited_child_is_not_hung(self):
        proc = MagicMock()
        proc.stdout = None
        proc.stderr = None
        proc.wait.return_value = 3
        ex = _executor()
        assert ex._capture_output(proc) == (b"", b"", 0, 0)
        proc.wait.assert_called_once()
        # and the wait carried a bound, not a bare wait()
        assert proc.wait.call_args.kwargs["timeout"] is not None

    def test_paired_negative_none_fds_alive_child_is_terminated(self):
        """The no-pipe branch was an unbounded ``wait()`` too — bounded now."""
        proc = MagicMock()
        proc.stdout = None
        proc.stderr = None
        proc.pid = 4242
        proc.wait.side_effect = subprocess.TimeoutExpired(["x"], 0)
        ex = _executor()
        with patch("executor.executor._terminate_child_process") as term:
            out = ex._capture_output(proc, deadline=time.time() - 1)
        assert out == (b"", b"", 0, 0)
        term.assert_called_once_with(proc)


class TestTerminateHelper:
    def test_kills_the_process_group_first(self):
        proc = MagicMock()
        proc.pid = 4242
        with patch("executor.executor.os.getpgid", return_value=4242) as getpgid:
            with patch("executor.executor.os.killpg") as killpg:
                _terminate_child_process(proc)
        getpgid.assert_called_once_with(4242)
        killpg.assert_called_once_with(4242, 9)
        proc.kill.assert_not_called()

    def test_falls_back_to_the_child_when_the_group_is_gone(self):
        proc = MagicMock()
        proc.pid = 4242
        with patch("executor.executor.os.getpgid", side_effect=ProcessLookupError):
            _terminate_child_process(proc)
        proc.kill.assert_called_once()

    def test_reap_bound_is_sane(self):
        """A named constant, not a magic number inside the timeout branch."""
        assert 0 < DIRECT_CHILD_REAP_SECONDS < SBX_TIMEOUT
