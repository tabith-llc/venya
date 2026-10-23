# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#468: spool mutation serializes across AuditLogger instances sharing one path.

The defect: ``self._lock`` was per-instance while the spool path is
process-scoped, and the daemon runs two instances over that one path (the
per-session logger in ``create_executor`` and ``audit_boot_forwarder``). One
instance could compute a rewrite from a stale read and ``os.replace`` it over
lines the other had just appended — a silent lost update of durable audit
events.

The fix under test: a process-wide registry of locks keyed by the RESOLVED
spool path (``executor.audit._spool_lock_for``).
"""

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from executor.audit import AuditLogger, _spool_lock_for
from tests.test_audit import make_cert_pair, make_config, read_spool


def _stop_forwarder(log: AuditLogger) -> None:
    """Silence the background forwarder so exactly the test drives the drains
    (the TestForward._stop_forwarder shape from tests/test_audit.py)."""
    log._shutdown = True
    log._wakeup.set()
    log._forwarder.join(timeout=2.0)


def _success_client() -> MagicMock:
    """httpx2.Client stand-in whose post() returns 200 (the success_mock shape
    from tests/test_audit.py)."""
    response = MagicMock()
    response.status_code = 200
    client = MagicMock()
    client.post.return_value = response
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


class TestSpoolLockRegistry:
    """Structural half of AC1/AC4: one resolved path → one lock; different
    paths never contend; the key is the RESOLVED path, not the spelling."""

    def test_same_path_two_instances_share_one_lock(self, tmp_path: Path):
        spool = tmp_path / "spool"
        spool.mkdir()
        log_a = AuditLogger(make_config(spool), session_id="s-a")
        log_b = AuditLogger(make_config(spool), session_id="s-b")
        try:
            assert log_a._lock is log_b._lock, "#468: two instances over ONE spool path must serialize on ONE lock"
        finally:
            log_a.shutdown()
            log_b.shutdown()

    def test_different_paths_do_not_share_a_lock(self, tmp_path: Path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        log_a = AuditLogger(make_config(dir_a), session_id="s-a")
        log_b = AuditLogger(make_config(dir_b), session_id="s-b")
        try:
            assert (
                log_a._lock is not log_b._lock
            ), "unrelated spools must not contend — one global lock is not the mechanism"
        finally:
            log_a.shutdown()
            log_b.shutdown()

    def test_registry_key_is_the_resolved_path(self, tmp_path: Path):
        """Symlink and ``..`` spellings of ONE file land on ONE lock.

        The paired negative for the registry itself: keying by the raw
        string would hand two spellings of one spool two locks — the #468
        defect reborn one layer down.
        """
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real_dir)
        plain = _spool_lock_for(real_dir / "spool.jsonl")
        through_link = _spool_lock_for(link / "spool.jsonl")
        dotted = _spool_lock_for(tmp_path / "link" / ".." / "real" / "spool.jsonl")
        assert plain is through_link is dotted
        other = _spool_lock_for(real_dir / "other-spool.jsonl")
        assert other is not plain


class TestCrossInstanceSpoolRace:
    """AC2 — the paired negative is the point: emit + drain interleaved on two
    instances over ONE spool; no line present before the race is absent after."""

    def test_drain_rewrite_cannot_eat_a_concurrent_append(self, tmp_path: Path):
        """Force the exact lost-update window: instance A sits INSIDE
        ``_remove_sent_lines`` (read taken, rewrite pending — under A's lock
        hold) while instance B emits.

        With the old per-instance locks nothing stops B's append landing in
        that window, and A's ``_rewrite_spool`` then ``os.replace``s the file
        from its stale view — B's event is gone with no error anywhere. This
        cell FAILS on the unfixed shape (the demonstration that the race is
        real and this test actually interleaves) and PASSES with the
        path-keyed shared lock: B blocks until A's rewrite completes, then
        appends onto the current file.
        """
        spool = tmp_path / "spool"
        spool.mkdir()
        cert_pair = make_cert_pair(tmp_path)
        log_a = AuditLogger(make_config(spool), session_id="drain-side", client_cert=cert_pair)
        log_b = AuditLogger(make_config(spool), session_id="emit-side")
        _stop_forwarder(log_a)
        _stop_forwarder(log_b)
        try:
            for i in range(1, 4):
                log_a.emit("credential_injected", marker=f"a{i}")

            window_open = threading.Event()
            b_finished = threading.Event()

            original_read = log_a._read_all_lines
            reads: list[list[str]] = []

            def hooked_read() -> list[str]:
                lines = original_read()
                reads.append(lines)
                if len(reads) == 2:
                    # This read is the one _remove_sent_lines takes under
                    # A's lock, immediately before the clobbering rewrite —
                    # open the window for B.
                    window_open.set()
                    b_finished.wait(timeout=0.3)
                return lines

            log_a._read_all_lines = hooked_read  # type: ignore[method-assign]

            def b_emit() -> None:
                window_open.wait(timeout=2.0)
                log_b.emit("credential_injected", marker="b1")
                b_finished.set()

            emitter = threading.Thread(target=b_emit)
            emitter.start()

            log_a._config.remote_url = "http://127.0.0.1:1/audit"
            mock_client = _success_client()
            with patch("executor.audit.httpx2.Client", return_value=mock_client):
                assert log_a._forward_once() is True
            emitter.join(timeout=5.0)
            assert not emitter.is_alive(), "B's emit never completed — lock wiring broken"

            # a1..a3 went out on the wire...
            import compression.zstd

            post = mock_client.__enter__.return_value.post
            assert post.call_count == 1
            sent = compression.zstd.decompress(post.call_args[1]["content"]).decode()
            for i in range(1, 4):
                assert f'"a{i}"' in sent

            # ...and b1 was appended DURING the drain. THE AC2 ASSERTION: no
            # line present before the race is absent after. b1 must survive
            # A's rewrite. On the per-instance-lock shape it is gone.
            assert len(reads) == 2, "interleave did not happen as designed"
            survivors = [d["marker"] for d in read_spool(spool)]
            assert survivors == [
                "b1"
            ], f"#468 lost update: expected b1 to survive the drain rewrite, spool holds {survivors}"
        finally:
            log_a.shutdown()
            log_b.shutdown()

    def test_capacity_drop_rewrite_cannot_eat_a_concurrent_append(self, tmp_path: Path):
        """The same stale-rewrite window on the drop-oldest path: emit holds
        the lock across ``_truncate_prefix``'s read+rewrite; on the old shape
        B appends between them and is clobbered."""
        spool = tmp_path / "spool"
        spool.mkdir()
        config = make_config(spool, max_buffer_size=4, max_batch_lines=4)
        log_a = AuditLogger(config, session_id="drop-side")
        log_b = AuditLogger(make_config(spool), session_id="emit-side")
        _stop_forwarder(log_a)
        _stop_forwarder(log_b)
        try:
            for i in range(1, 5):
                log_a.emit("credential_injected", marker=f"c{i}")  # count == capacity, no drop yet

            window_open = threading.Event()
            b_finished = threading.Event()

            original_read = log_a._read_all_lines
            reads: list[list[str]] = []

            def hooked_read() -> list[str]:
                lines = original_read()
                reads.append(lines)
                if len(reads) == 1:
                    # _truncate_prefix's read: rewrite pending, under A's lock.
                    window_open.set()
                    b_finished.wait(timeout=0.3)
                return lines

            log_a._read_all_lines = hooked_read  # type: ignore[method-assign]

            def b_emit() -> None:
                window_open.wait(timeout=2.0)
                log_b.emit("credential_injected", marker="d1")
                b_finished.set()

            emitter = threading.Thread(target=b_emit)
            emitter.start()
            log_a.emit("credential_injected", marker="c5")  # count 5 > 4 → drop oldest 1
            emitter.join(timeout=5.0)
            assert not emitter.is_alive(), "B's emit never completed — lock wiring broken"

            assert len(reads) == 1, "interleave did not happen as designed"
            survivors = [d["marker"] for d in read_spool(spool)]
            # d1 was appended during the drop window (present before the
            # race's rewrite) — it must be there after, on both instances'
            # final state. c5 (A's own append) must survive too. The fixed
            # shape lands on {c3,c4,c5,d1} (B's own emit then drops the
            # oldest, c2, with a warning); the old shape silently loses d1.
            assert "d1" in survivors, f"#468 lost update: d1 clobbered, spool holds {survivors}"
            assert "c5" in survivors, f"c5 lost, spool holds {survivors}"
        finally:
            log_a.shutdown()
            log_b.shutdown()
