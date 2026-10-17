# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#657 — the snapshot-stale refusal counts, in the EXISTING series, under its own site.

THE DEFECT THIS FILE JUDGES. ``venya_revocation_read_refusals_total{site}`` had exactly one
call site — ``note_refusal`` inside the **lock-timeout** arm of ``bounded_read`` — while the
other stale-class arm, the one a **starved pool or a dead publisher** actually produces
(``revocation_snapshot.read_populations`` raising ``RevocationSnapshotUnavailable``), raised its
503 uncounted. Two arms share one refusal sentence and only one of them moved the metric, so the
precise condition #603 exists for — load, not outage — reached an operator as a 503 with no
increment, and the runbook row that points at the counter was contradicted by the bytes it
documents.

WHAT IS ASSERTED, IN ORDER

1. THE STALE ARM COUNTS, at the raise, in the existing series, under its own site value
   (``poll/revocation-list``). Cells 1-2 are the falsifier pair the spec named: remove the
   increment and cell 1 goes red — that is the check the lead re-runs before merging.
2. IT COUNTS AT THE DECISION, not at the route's ``except`` — cell 3 pins the ordering and the
   absence, because a refusal arm that must be remembered at every caller is a refusal arm
   missing at one (the same law ``test_revocation_read_bound_603.py::test_app_registers_one_central_refusal_arm``
   applies to the handler).
3. IT COUNTS THROUGH THE REAL ROUTE, on real SQLite, on a real HTTP request — cell 4 — so the
   claim "the series moves on the load case" is a measured fact and not a unit-path artifact.
4. CUMULATIVE, NEVER A GAUGE, NEVER LATCHED — cell 5 counts three refusals and asserts the
   warning still fires ONCE. #651's shape was a per-emit line with no record; the counter is the
   record, the latch is the courtesy.
5. AN ANSWER COSTS NOTHING — cell 6 is the truth-table negative: a poll that answers must not
   increment, or the counter could be satisfied by an unconditional bump and would measure
   requests instead of refusals.
6. THE ARMS STAY DISTINGUISHABLE — cells 7-9: the lock arm increments exactly as it did, the two
   arms land on DIFFERENT ``site`` values, and the vocabulary stays closed (no request-supplied
   label ever reaches a Prometheus series — the #603 AC1 reasoning, kept).

Time is the exception, as in ``test_revocation_snapshot_603.py``: the module's ``time`` is
swapped for a fake clock so a refusal is a ruled age and not a race.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.iam.models import Base, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server import metrics, revocation_read
from server import revocation_snapshot as rs
from server.config import ServerConfig
from server.dependencies import get_backend
from server.routes import executors as executors_routes
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

_ROOT = Path(__file__).resolve().parents[3]
_RUNBOOK = _ROOT / "docs" / "revocation-table-operations-runbook.md"

POLL_PATH = "/api/v1/executors/certs/revocation-list"
CEILING = rs.REVOCATION_SNAPSHOT_MAX_AGE_SECONDS
STALE_SITE = rs.POLL_REFUSAL_SITE


def _counter(site: str) -> float:
    """One read of one label of the shipped series — via the product's own Counter."""
    return metrics.REVOCATION_READ_REFUSALS_TOTAL.labels(site=site)._value.get()


class _FakeClock:
    """Stand-in for the ``time`` module inside ``revocation_snapshot`` only (shipped pattern)."""

    def __init__(self, mono: float = 1_000.0) -> None:
        self.mono = mono

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.mono += seconds


@pytest.fixture(autouse=True)
def _clean_state():
    """Module state is process-global; no cell inherits another's snapshot or latch."""
    rs.reset_snapshot_state()
    revocation_read.reset_read_deadline_state()
    yield
    rs.reset_snapshot_state()
    revocation_read.reset_read_deadline_state()


@pytest.fixture()
def clock(monkeypatch):
    fake = _FakeClock()
    monkeypatch.setattr(rs, "time", fake)
    return fake


@pytest.fixture()
def env(tmp_path):
    """Real-SQLite app with the publisher ARMED, so the snapshot branch is what answers.

    Same bare-app shape the shipped #603 step-2 cells use; armed here because an un-armed
    router falls back to a live read and never reaches the arm under test.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'stale.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    seed = SessionLocal()
    seed.add(User(user_id="test-user", auth_mode="password"))
    seed.commit()
    seed.close()

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-12345")
    app.state.ca_manager = MagicMock()
    app.dependency_overrides[get_backend] = lambda: backend
    app.include_router(executors_routes.router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)
    rs.arm_publisher()
    yield client, SessionLocal
    engine.dispose()
    rs.reset_snapshot_state()


def _publish(SessionLocal) -> rs.RevocationSnapshot:
    """One real publish cycle against the (empty) population, on the fake clock."""
    s = SessionLocal()
    try:
        return rs.publish_snapshot(s)
    finally:
        s.close()


def _lock_timeout_fault() -> DBAPIError:
    """A DBAPIError carrying PostgreSQL 55P03 — the shape psycopg raises on lock_timeout."""
    orig = SimpleNamespace(pgcode=revocation_read.LOCK_TIMEOUT_SQLSTATE, args=(), sqlstate="55P03")
    return DBAPIError("SELECT … FROM executor_cert_revocations", {}, orig)


class TestStaleArmCounts:
    """Criterion 1: the arm that answers nothing now records a refusal, in the SAME series."""

    def test_stale_snapshot_refusal_increments_the_existing_series(self, env, clock):
        """THE falsifier cell. Delete ``note_stale_refusal()`` from the raise and this goes red."""
        _client, SessionLocal = env
        _publish(SessionLocal)
        before = _counter(STALE_SITE)

        clock.advance(CEILING + 1)
        s = SessionLocal()
        try:
            with pytest.raises(rs.RevocationSnapshotUnavailable):
                rs.read_populations(s)
        finally:
            s.close()

        assert (
            _counter(STALE_SITE) == before + 1
        ), f"a stale-snapshot refusal moved nothing on {STALE_SITE!r} — the 503 is uncounted again"

    def test_cold_window_refusal_counts_too(self):
        """Armed publisher with nothing published yet is the same arm, so it is the same count.

        This is not a boot-time nicety: the publisher sets the running flag BEFORE its first
        publish, so every poll in that window refuses, and an uncounted cold window is exactly
        the under-report this row closes.
        """
        before = _counter(STALE_SITE)
        rs.arm_publisher()
        with pytest.raises(rs.RevocationSnapshotUnavailable):
            # No session is consulted on this branch — a missing snapshot refuses before any read
            # — so a bare double is the honest argument, not a stub the code never touches.
            rs.read_populations(MagicMock(name="unused-session"))
        assert _counter(STALE_SITE) == before + 1

    def test_count_happens_at_the_decision_not_at_the_route(self):
        """Ordering + absence, so a second caller cannot re-open the under-report.

        The increment must be BEFORE the raise (a raise-first arm counts nothing), and the
        route's ``except`` must NOT be the counter's home — if it were, every future caller of
        ``read_populations`` would silently under-report, which is the #603 central-arm law
        stated for the metric instead of the handler.
        """
        import inspect

        read_src = inspect.getsource(rs.read_populations)
        note = read_src.index("note_stale_refusal()")
        raise_at = read_src.index("raise RevocationSnapshotUnavailable")
        assert note < raise_at, "the increment moved after the raise, so it never runs"

        from server.routes import executors as ex

        poll_src = inspect.getsource(ex.get_revocation_list)
        assert (
            "note_stale_refusal" not in poll_src
        ), "the counter moved to the route's except arm — a second caller would under-report again"

    def test_the_shipped_route_moves_the_counter_on_a_real_request(self, env, clock):
        """Criterion 1 through the wire: a real 503 answer, a real increment, one request.

        This is the cell that answers the LOAD question rather than the unit question: a starved
        pool shows up as this arm, and the operator-facing series has to move for it.
        """
        client, SessionLocal = env
        _publish(SessionLocal)
        before = _counter(STALE_SITE)

        # Fresh: the poll answers, and an answer must not count (asserted below, same clock state).
        assert client.get(POLL_PATH).status_code == 200
        assert _counter(STALE_SITE) == before, "an answered poll counted — the series would be noise"

        clock.advance(CEILING + 1)
        resp = client.get(POLL_PATH)
        assert resp.status_code == 503, "the shipped stale class changed; this row does not touch it"
        assert (
            _counter(STALE_SITE) == before + 1
        ), f"the route refused but {STALE_SITE!r} did not move — the load case is still invisible"

    def test_counter_is_cumulative_and_the_warning_is_latched(self, env, clock, caplog):
        """#651's shape, asserted together: three refusals count three times, ONE journal line."""
        client, SessionLocal = env
        _publish(SessionLocal)
        clock.advance(CEILING + 1)
        before = _counter(STALE_SITE)

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            for _ in range(3):
                assert client.get(POLL_PATH).status_code == 503

        assert _counter(STALE_SITE) == before + 3, "the counter is latched — how much was lost is lost"
        stale_lines = [r for r in caplog.records if STALE_SITE in r.getMessage()]
        assert len(stale_lines) == 1, f"expected one latched line, got {len(stale_lines)}"
        text = stale_lines[0].getMessage()
        assert "not a revocation and not an all-clear" in text
        assert "ONCE per process" in text, "the latch is documented behavior, not an accident"
        assert "lock deadline" not in text.lower(), (
            "the stale line claimed a lock deadline the read never hit — a message naming an "
            "event that never happened is the class #603 has a written law about"
        )

    def test_fresh_poll_adds_nothing(self, env):
        """Truth table, positive half: the arm that ANSWERS must not move the refusal series."""
        client, SessionLocal = env
        _publish(SessionLocal)
        before = _counter(STALE_SITE)
        assert client.get(POLL_PATH).status_code == 200
        assert _counter(STALE_SITE) == before


class TestArmsStayDistinguishable:
    """Criterion 3: two arms, one series, two site values — and the lock arm unchanged."""

    def test_lock_arm_still_increments_exactly_as_it_did(self):
        """The pre-existing arm's behaviour is a regression target, not a thing I refactored."""
        before = _counter("heartbeat")
        db = MagicMock(name="session")
        db.get_bind.return_value = SimpleNamespace(dialect=postgresql.dialect())
        db.begin_nested.return_value = MagicMock(name="sp")
        with pytest.raises(revocation_read.RevocationReadUnavailable):
            with revocation_read.bounded_read(db, site="heartbeat"):
                raise _lock_timeout_fault()
        assert _counter("heartbeat") == before + 1

    def test_the_two_arms_land_on_different_site_values(self, env, clock):
        """AC3: 'locked' and 'snapshot-stale' must not collapse into one indistinguishable number.

        Both arms are driven in one cell, so a future edit that gives them the same label fails
        here rather than in an operator's alert three months from now.
        """
        client, SessionLocal = env
        db = MagicMock(name="session")
        db.get_bind.return_value = SimpleNamespace(dialect=postgresql.dialect())
        db.begin_nested.return_value = MagicMock(name="sp")

        lock_before = _counter("heartbeat")
        stale_before = _counter(STALE_SITE)
        with pytest.raises(revocation_read.RevocationReadUnavailable):
            with revocation_read.bounded_read(db, site="heartbeat"):
                raise _lock_timeout_fault()

        _publish(SessionLocal)
        clock.advance(CEILING + 1)
        assert client.get(POLL_PATH).status_code == 503

        assert STALE_SITE != "heartbeat"
        assert _counter("heartbeat") == lock_before + 1, "the lock arm's count moved onto the stale label"
        assert _counter(STALE_SITE) == stale_before + 1, "the stale arm borrowed the lock arm's label"

    def test_site_vocabulary_is_closed(self, env, clock):
        """No request-supplied value reaches a Prometheus label, ever.

        Cardinality discipline is ``metrics.py``'s own module contract, and #657 adds a value to
        a CLOSED set rather than opening the set to input: the arm calls ``note_stale_refusal()``
        with no argument, so an attacker-shaped ambient ``for_site`` label must not create a
        series. Only the labels THIS cell can cause are judged — the process-global registry is
        shared with every other module in the suite.
        """
        _client, SessionLocal = env
        before_value = _counter(STALE_SITE)
        before_labels = set(metrics.REVOCATION_READ_REFUSALS_TOTAL._metrics)

        token = revocation_read._site_label.set("/api/v1/heartbeat?executor_id=FORGED-BY-LABEL")
        try:
            _publish(SessionLocal)
            clock.advance(CEILING + 1)
            with pytest.raises(rs.RevocationSnapshotUnavailable):
                rs.read_populations(SessionLocal())
        finally:
            revocation_read._site_label.reset(token)

        # The label the refusal wrote is the module constant, never the hostile ambient value,
        # and no NEW series appeared: the vocabulary the process can hold did not grow by input.
        assert _counter(STALE_SITE) == before_value + 1
        assert set(metrics.REVOCATION_READ_REFUSALS_TOTAL._metrics) == before_labels
        emitted = {key[0] for key in metrics.REVOCATION_READ_REFUSALS_TOTAL._metrics}
        assert STALE_SITE in emitted
        assert "FORGED" not in " ".join(emitted), f"a caller-supplied value reached a label: {sorted(emitted)}"


class TestOperatorPathIsTrueOfBothArms:
    """Criterion 4, narrowed by the s132 steer: the prose that PROMISES this counter.

    #653 (merged) made the counter readable and pinned the scrape path; this row makes the
    sentence about it true of both arms. These cells pin the prose against the shipped constant,
    so a label rename or a dropped sentence fails the gate instead of misleading an operator at
    3 a.m. They do NOT re-open the #653 section — they check the one sentence #657 changes.
    """

    def test_runbook_names_the_stale_site_and_says_what_to_do_with_it(self):
        runbook = _RUNBOOK.read_text()
        assert (
            f'site="{STALE_SITE}"' in runbook
        ), "the runbook's alerting-surface row does not name the stale arm's site value"
        assert "both arms" in runbook.lower(), "the runbook still describes the counter as one-arm"
        assert "never a gauge" in runbook.lower(), "#657 AC5's reason belongs in the operator's text"
        # And the arms are told apart by a VALUE, not by a second alert the operator must remember.
        assert "one series" in runbook.lower()

    def test_scrape_help_text_names_both_arms(self):
        """The ``# HELP`` line an operator reads must not describe only one arm."""
        from prometheus_client import REGISTRY, generate_latest

        body = generate_latest(REGISTRY).decode()
        help_lines = [
            line for line in body.splitlines() if line.startswith("# HELP venya_revocation_read_refusals_total")
        ]
        assert help_lines, "the series vanished from the exposition"
        help_line = help_lines[0]
        assert (
            "lock" in help_line.lower() and "snapshot" in help_line.lower()
        ), f"the series advertises one arm only: {help_line}"

    def test_the_instrument_is_a_counter_not_a_gauge(self):
        """#657 AC5: a gauge shows the present; only a Counter can later state how much was lost.

        Also pins that this row added a VALUE and not a DIMENSION — an existing alert rule on
        ``{site}`` must keep working, and the #653 scrape cell depends on the series name.
        """
        assert metrics.REVOCATION_READ_REFUSALS_TOTAL._type == "counter"
        assert list(metrics.REVOCATION_READ_REFUSALS_TOTAL._labelnames) == [
            "site"
        ], "the label set changed — this row adds a value to a closed vocabulary, not a dimension"
