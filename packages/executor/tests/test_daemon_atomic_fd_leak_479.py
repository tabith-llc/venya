# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket atomic-write-fd-leak-on-early-failure (#479).

Pre-fix: ``_atomic_write`` took the raw descriptor from ``tempfile.mkstemp`` and
handed it to ``with os.fdopen(fd, "wb")`` — but everything that failed BEFORE
that handoff (``os.fchmod`` raising EROFS/EPERM on a hardened unit, or
``os.fdopen`` itself failing) fell into the ``except BaseException`` path that
unlinks the temp and re-raises. An unlink gives a NAME back, never a descriptor,
so each such failure leaked one open descriptor in a long-lived process that
also holds the relay listener, the reaper, the heartbeat pool and the audit
forwarder — the leak compounded against the fd ceiling of exactly the process
that guards descriptors for a living (``scan_open_fds``).

Fix pinned here: the descriptor is closed on every path that does not reach the
``fdopen`` handoff, and on no path that does (AC1). The two cells below count the
process's own descriptors through the product's existing ``scan_open_fds``
helper — no new dependency. The paired negatives (AC3) hold the #478 properties
up: unique temp, exact mode pinning, single atomic replace, no residue, and the
post-handoff descriptor closed exactly once.
"""

import errno
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from executor.daemon import _atomic_write
from executor.injector import scan_open_fds

# Descriptor accounting is read straight out of procfs. Any host without it
# cannot run a count, so the count cells state that out loud rather than
# quietly passing.
requires_proc_fd = pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="descriptor counting needs /proc/self/fd",
)

FAILURES = 25  # one leak per call is invisible once; a repeated failure is not


def _fd_set() -> set[int]:
    fds = scan_open_fds()
    assert fds is not None, "scan_open_fds returned None — could not look"
    return fds


@requires_proc_fd
class TestDescriptorReturnedOnEveryPreHandoffFailure:
    """AC1/AC2: no descriptor survives a failure that happened before
    ``os.fdopen`` took ownership."""

    def test_fchmod_failure_leaks_no_descriptor(self, tmp_path: Path):
        """The AC2 cell as written on the ticket: force ``os.fchmod`` to raise
        and assert the open-descriptor count is unchanged. Run ``FAILURES``
        times so a single leaked fd cannot hide in the noise — at base this
        leaks 25."""
        target = tmp_path / "executor.key"
        before = _fd_set()
        with patch(
            "executor.daemon.os.fchmod",
            side_effect=OSError(errno.EROFS, os.strerror(errno.EROFS)),
        ):
            for _ in range(FAILURES):
                with pytest.raises(OSError) as exc:
                    _atomic_write(target, b"SECRET", 0o600)
        assert exc.value.errno == errno.EROFS, "the cause must travel, not a close error"
        assert _fd_set() == before, "descriptor leaked on the fchmod failure path"
        assert not list(tmp_path.glob("*.tmp")), "temp must still be unlinked (#478)"
        assert not target.exists()

    def test_fdopen_failure_leaks_no_descriptor(self, tmp_path: Path):
        """The second pre-handoff path the ticket names: ``os.fdopen`` itself
        failing (EMFILE on a near-exhausted process) leaked the same way."""
        target = tmp_path / "executor.crt"
        before = _fd_set()
        with patch(
            "executor.daemon.os.fdopen",
            side_effect=OSError(errno.EMFILE, os.strerror(errno.EMFILE)),
        ):
            for _ in range(FAILURES):
                with pytest.raises(OSError) as exc:
                    _atomic_write(target, b"CERT", 0o644)
        assert exc.value.errno == errno.EMFILE
        assert _fd_set() == before, "descriptor leaked when fdopen itself failed"
        assert not list(tmp_path.glob("*.tmp"))


@requires_proc_fd
class TestHandoffPathClosesExactlyOnce:
    """AC3 paired negative: a failure AFTER the handoff must not close a
    descriptor the file object already owns — a close in the outer handler would
    be a double close over a number somebody else may have been handed."""

    def test_replace_failure_closes_once_and_keeps_target(self, tmp_path: Path):
        target = tmp_path / "executor.key"
        _atomic_write(target, b"ORIGINAL", 0o600)
        before = _fd_set()
        with patch(
            "executor.daemon.os.replace",
            side_effect=OSError(errno.EXDEV, os.strerror(errno.EXDEV)),
        ):
            with pytest.raises(OSError) as exc:
                _atomic_write(target, b"NEW", 0o600)
        assert exc.value.errno == errno.EXDEV, "the replace error must travel"
        assert _fd_set() == before, "descriptor leaked (or double-closed) after the handoff"
        assert target.read_bytes() == b"ORIGINAL", "failed write must not touch the target"
        assert not list(tmp_path.glob("*.tmp")), "temp unlinked on failure (#478)"


class TestNormalWritePathUnchanged:
    """AC3: the success path is untouched — same unique temp, same exact mode
    pinning, same single atomic replace, no residue, no descriptor drift."""

    @pytest.mark.parametrize("mode", [0o600, 0o644])
    def test_payload_mode_and_no_residue(self, tmp_path: Path, mode: int):
        target = tmp_path / "executor.crt"
        _atomic_write(target, b"CERT", mode)
        assert target.read_bytes() == b"CERT"
        assert stat.S_IMODE(os.stat(target).st_mode) == mode
        assert not list(tmp_path.glob("*.tmp"))

    @requires_proc_fd
    def test_success_path_fds_stable(self, tmp_path: Path):
        target = tmp_path / "executor.key"
        before = _fd_set()
        for _ in range(FAILURES):
            _atomic_write(target, b"SECRET", 0o600)
        assert _fd_set() == before, "the success path must not move the fd set either"
