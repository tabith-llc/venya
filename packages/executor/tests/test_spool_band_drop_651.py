# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#651 — the audit-spool band alert is edge-triggered, and every discard is counted.

The row's two truths, both from `packages/executor/src/executor/audit.py` at the tip
this leg was cut on:

1. the capacity WARNING fired from inside ``emit`` on **every audit event** while the
   spool sat in the alert band — no latch, no rate limit, so journal growth on a
   stalled forwarder buried the one line that matters;
2. a discard left **one log line naming that batch's count** and no cumulative
   record anywhere, so after log rotation a losing executor could not state that it
   had ever lost audit records.

The fix under test is observability only, per AC5: ``_SpoolObservability`` (latch +
monotonic ``dropped_total``), keyed by the RESOLVED spool path the same way
``_spool_lock_for`` is (#468's reason: the shipped daemon holds a per-session logger
AND a session-less boot forwarder over ONE file), the edge-triggered
``_statement_band``, the counter incremented at the drop decision in
``_drop_oldest``, and the boot statement in ``__init__``. The durability contract is
untouched: at-least-once below capacity, lossy above it (issue 307 R2).

The surface is the JOURNAL, on the lead's ruling of 2026-10-17: an executor-side
scrape door is foreclosed by #653 AC5 (``test_executor_plane_ships_no_door``), and
``server.metrics`` counters are a different process.
"""

import logging
from pathlib import Path

import pytest

from executor.audit import (
    _SPOOL_RESTATE_EVERY_EVENTS,
    AuditLogger,
    spool_drop_total,
)

# Every cell here builds its own spool dir and its own logger, but the observability
# registry is PROCESS-wide and keyed by resolved path — so a cell that reused a path
# would inherit another cell's latch and its drop total. These fixtures make each
# cell's path unique, which is what keeps a process-wide record testable.
CAPACITY = 10
THRESHOLD = 0.5  # alert band starts at 5 lines


def _config(spool_dir: Path, **overrides):
    from executor.config import AuditForwarderConfig

    kwargs = {
        "remote_url": None,
        "ca_cert_path": None,
        "spool_path": str(spool_dir / "spool.jsonl"),
        "max_buffer_size": CAPACITY,
        "alert_threshold": THRESHOLD,
        "max_batch_lines": 2,
    }
    kwargs.update(overrides)
    return AuditForwarderConfig(**kwargs)


def _emit(log: AuditLogger, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        log.emit("credential_injected", n=i)


def _band_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "Audit buffer at" in r.getMessage()]


def _drop_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "Audit spool full" in r.getMessage()]


@pytest.fixture
def spool_dir(tmp_path: Path) -> Path:
    d = tmp_path / "spool"
    d.mkdir()
    return d


class TestHealthySpoolIsSilent:
    """AC4 paired negative, first half: what SHOULD be rejected.

    A check that only ever proves it fires is how this row would have been "fixed"
    by logging more. Below the band there is NO capacity warning and NO increment.
    """

    def test_below_band_emits_no_warning_and_no_increment(self, spool_dir, caplog):
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.DEBUG):
                _emit(log, 4)  # 4 of 10, band starts at 5
            assert _band_lines(caplog) == [], "capacity warning fired below the alert band"
            assert _drop_lines(caplog) == []
            assert spool_drop_total(spool_dir / "spool.jsonl") == 0
            assert log.spool_depth() == 4
        finally:
            log.shutdown()

    def test_exactly_at_band_edge_warns_once(self, spool_dir, caplog):
        """The band boundary is inclusive, and the crossing is one line — the half
        that keeps the negative above from being 'the fence is just set too high'."""
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, 5)  # 5th line lands on capacity * threshold
            lines = _band_lines(caplog)
            assert len(lines) == 1, lines
            assert "cumulative dropped 0" in lines[0], "the statement must carry the counter"
        finally:
            log.shutdown()


class TestParkedSpoolIsBounded:
    """AC4 paired negative, second half — the flood this row exists to stop:
    many emits while parked in the band must cost ONE line, not one per event.
    """

    def test_many_emits_while_parked_log_exactly_once(self, spool_dir, caplog):
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                # 9 lines: inside the band (>=5) and below capacity (10), so no drop.
                _emit(log, 9)
            lines = _band_lines(caplog)
            assert len(lines) == 1, f"parked spool logged {len(lines)} lines, expected exactly 1: {lines}"
        finally:
            log.shutdown()

    def test_draining_then_filling_again_alarms_again(self, spool_dir, caplog):
        """THE RE-ARM HALF. Without it the fix is 'warn once ever', which AC1 forbids
        and which no single-flood cell can distinguish from the real thing.
        """
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, 6)  # enter band -> line 1
                assert len(_band_lines(caplog)) == 1
                log._rewrite_spool([])  # drain below the band, as a forward would
                assert log.spool_depth() == 0
                _emit(log, 6, start=100)  # re-enter the band
            lines = _band_lines(caplog)
            assert len(lines) == 2, f"re-entry must alarm again, got {len(lines)}: {lines}"
        finally:
            log.shutdown()

    def test_restatement_fires_at_the_interval_not_before(self, spool_dir, caplog, monkeypatch):
        """A long stall stays visible: the edge logs once, then one line every
        ``_SPOOL_RESTATE_EVERY_EVENTS`` events while parked.

        The interval is patched DOWN for this cell rather than emitting ~1,000 real
        lines: the shipped value is asserted separately in
        ``test_shipped_interval_is_a_hundred_events``, and what this cell proves is the
        MECHANISM (no re-statement before the interval, one after it). Emitting 2,000
        lines to test a constant would make the suite slow for no extra truth, since
        every emit re-counts the whole spool.
        """
        import executor.audit as audit_mod

        monkeypatch.setattr(audit_mod, "_SPOOL_RESTATE_EVERY_EVENTS", 3)
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, 5)  # cross into the band: edge statement (line 1)
                assert len(_band_lines(caplog)) == 1
                _emit(log, 2)  # events 1,2 of 3 — still silent
                assert len(_band_lines(caplog)) == 1, "must not restate before the interval"
                _emit(log, 1)  # event 3 of 3 — re-statement lands
                lines = _band_lines(caplog)
                assert len(lines) == 2, f"expected the interval re-statement, got {len(lines)}: {lines}"
                assert "re-states every 3 events" in lines[0], lines[0]
        finally:
            log.shutdown()

    def test_shipped_interval_is_a_hundred_events(self):
        """The constant itself, pinned so patching it in the cell above cannot hide a
        shipped value that drifted to 0 (which would put the flood right back)."""
        assert _SPOOL_RESTATE_EVERY_EVENTS == 1_000


class TestDiscardsAreCounted:
    """AC2: a cumulative, monotonic counter incremented AT the drop decision, and
    readable without opening the spool file (AC3)."""

    def test_planted_drop_moves_the_counter(self, spool_dir, caplog):
        """AC2's whole point in one cell: the NUMBER is exact even though the LINE is
        bounded. Five discards happened, so the counter says five — while the journal
        carries one drop line, not five, because a spool pinned at the ceiling discards
        one line per emit and an unbounded drop warning would put the flood this row
        exists to stop onto the drop path instead of the band path."""
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, 15)  # capacity 10 -> emits 11..15 each drop exactly 1
            assert spool_drop_total(spool_dir / "spool.jsonl") == 5
            assert log.spool_depth() == CAPACITY, "depth stays pinned at capacity by drop-oldest"
            drops = _drop_lines(caplog)
            assert len(drops) == 1, f"the drop statement must be edge-triggered too, got {len(drops)}: {drops}"
            assert "dropped 1 oldest event(s)" in drops[0], drops[0]
            assert "cumulative dropped this process: 1" in drops[0], drops[0]
        finally:
            log.shutdown()

    def test_counter_counts_every_drop_even_when_the_line_does_not(self, spool_dir, caplog):
        """The paired negative of the bound above: bounding the journal must not
        bound the truth. 5 drops, 1 line, counter 5."""
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, 15)
            assert len(_drop_lines(caplog)) == 1
            assert spool_drop_total(spool_dir / "spool.jsonl") == 5
        finally:
            log.shutdown()

    def test_counter_is_monotonic_across_separate_drops(self, spool_dir):
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            _emit(log, 12)  # first 2 dropped
            first = spool_drop_total(spool_dir / "spool.jsonl")
            log._rewrite_spool([])
            _emit(log, 12, start=100)  # drops again
            second = spool_drop_total(spool_dir / "spool.jsonl")
            assert first == 2, first
            assert second > first, f"counter must be monotonic, got {first} then {second}"
            assert second == 4, second
        finally:
            log.shutdown()

    def test_depth_is_readable_without_opening_the_file(self, spool_dir):
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            _emit(log, 3)
            assert log.spool_depth() == 3
            # and it tracks a change the file went through underneath
            log._rewrite_spool([])
            assert log.spool_depth() == 0
        finally:
            log.shutdown()

    def test_zero_drop_never_increments(self, spool_dir):
        """Negative half of the counter: a spool that never crosses capacity has
        nothing to report, so a cell asserting a number proves nothing on its own."""
        log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            _emit(log, CAPACITY - 1)
            assert spool_drop_total(spool_dir / "spool.jsonl") == 0
        finally:
            log.shutdown()


class TestLatchIsSharedBySpoolPath:
    """#468's lesson applied to #651: the shipped daemon holds TWO AuditLogger
    instances over ONE spool. A per-instance latch would alert twice per event and
    a per-instance counter would split the truth in two."""

    def test_two_instances_one_spool_share_one_latch_and_one_counter(self, spool_dir, caplog):
        a = AuditLogger(_config(spool_dir), session_id="s1")
        b = AuditLogger(_config(spool_dir), session_id="audit-boot")
        try:
            assert a._obs is b._obs, "two loggers over one path must share one record"
            with caplog.at_level(logging.WARNING):
                _emit(a, 6)  # b's boot line already stated the depth; band entry from a
                _emit(b, 2, start=100)  # same band, second instance
            assert len(_band_lines(caplog)) == 1, "the second instance must not double-alert"
            _emit(a, 6, start=200)  # push over capacity on the shared file
            assert spool_drop_total(spool_dir / "spool.jsonl") > 0
            assert a.spool_depth() == b.spool_depth()
        finally:
            a.shutdown()
            b.shutdown()

    def test_different_spool_paths_do_not_share_state(self, tmp_path):
        from executor.audit import _SPOOL_OBSERVABILITY

        one = AuditLogger(_config(tmp_path / "a"), session_id="s1")
        two = AuditLogger(_config(tmp_path / "b"), session_id="s1")
        try:
            assert one._obs is not two._obs
            _emit(one, 15)
            assert spool_drop_total(tmp_path / "a" / "spool.jsonl") == 5
            assert spool_drop_total(tmp_path / "b" / "spool.jsonl") == 0
            # The registry is process-wide and every other cell in this file has
            # registered its own path into it, so the honest assertion is about THESE
            # two keys, not about the size of the dict.
            ka = (tmp_path / "a" / "spool.jsonl").resolve()
            kb = (tmp_path / "b" / "spool.jsonl").resolve()
            assert ka in _SPOOL_OBSERVABILITY and kb in _SPOOL_OBSERVABILITY
            assert _SPOOL_OBSERVABILITY[ka] is one._obs
            assert _SPOOL_OBSERVABILITY[kb] is two._obs
        finally:
            one.shutdown()
            two.shutdown()


class TestBootPastBandIsNeverSilent:
    """The failure the lead's ruling names: a latch that starts ARMED would strand a
    spool that booted already past the band silent forever. The boot line must state
    it, on the first line."""

    def test_boot_above_band_states_the_band_on_the_journal(self, spool_dir, caplog):
        # Pre-fill the spool the way a stalled previous boot would leave it.
        spool = spool_dir / "spool.jsonl"
        spool.write_text("".join(f'{{"n": {i}}}\n' for i in range(8)))
        with caplog.at_level(logging.INFO):
            log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            boot = [r.getMessage() for r in caplog.records if "Audit spool open" in r.getMessage()]
            assert len(boot) == 1, boot
            assert "ALREADY IN THE ALERT BAND" in boot[0], boot[0]
            assert "depth 8 of 10" in boot[0], boot[0]
        finally:
            log.shutdown()

    def test_boot_below_band_does_not_claim_a_band(self, spool_dir, caplog):
        """Negative half of the boot statement — an unconditional alarm at boot would
        read as 'this row added noise' and train the operator to ignore it."""
        spool = spool_dir / "spool.jsonl"
        spool.write_text('{"n": 0}\n')
        with caplog.at_level(logging.INFO):
            log = AuditLogger(_config(spool_dir), session_id="s1")
        try:
            boot = [r.getMessage() for r in caplog.records if "Audit spool open" in r.getMessage()]
            assert len(boot) == 1
            assert "ALREADY IN THE ALERT BAND" not in boot[0]
            assert "depth 1 of 10" in boot[0]
        finally:
            log.shutdown()


class TestBandWidthChangesNothingElse:
    """AC4's last clause: widening or narrowing the band must not silently disable
    either half — the warning still fires on crossing, and drops still count."""

    @pytest.mark.parametrize(
        ("threshold", "expect_warn_at", "expect_silent_at"),
        [(0.2, 2, 1), (0.5, 5, 4), (0.9, 9, 8)],
        ids=["wide-band-0.2", "default-0.5", "narrow-band-0.9"],
    )
    def test_band_moves_but_both_halves_still_work(self, tmp_path, threshold, expect_warn_at, expect_silent_at, caplog):
        spool_dir = tmp_path / f"spool-{threshold}"
        spool_dir.mkdir()
        log = AuditLogger(_config(spool_dir, alert_threshold=threshold), session_id="s1")
        try:
            with caplog.at_level(logging.WARNING):
                _emit(log, expect_silent_at)
            assert _band_lines(caplog) == [], f"{expect_silent_at} lines must be silent at threshold {threshold}"
            with caplog.at_level(logging.WARNING):
                _emit(log, expect_warn_at - expect_silent_at, start=50)
            assert len(_band_lines(caplog)) == 1, f"crossing at {expect_warn_at} must warn (threshold {threshold})"
            # the drop half is independent of the band: capacity crossing still counts
            with caplog.at_level(logging.WARNING):
                _emit(log, CAPACITY + 5 - expect_warn_at, start=200)
            assert spool_drop_total(spool_dir / "spool.jsonl") == 5, "drop counting must track capacity, not the band"
        finally:
            log.shutdown()
