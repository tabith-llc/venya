# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#704 — an unknown dialect is no longer silent, and a clean non-PG install stays quiet.

The shipped dialect test swallowed every fault: ``_is_postgresql`` read a raising ``get_bind()`` as
the same ``False`` a real SQLite bind answers, so the seam yielded without installing either deadline
and the revocation read ran UNBOUNDED with no log line, no counter and no shipped cell modelling the
state (found on leg 465, filed as #704, made observable on leg 478).

**The behavior is deliberately unchanged.** The read still yields and still runs unbonded. Refusing
instead is an availability decision on a security surface — a core whose bind could not answer would
deny every revocation check it holds — and that is the owner's call, not this leg's. What changed is
that the fault now has its own name, its own counter and its own latched line.

The paired negatives are the point of this file, in order:

* POSITIVE — a real PostgreSQL bind installs the bound, answers a dialect NAME, and nothing is
  counted on the new series. Gated on the door, because the claim is about the shipping engine.
* CLEAN NEGATIVE — a real SQLite bind is inert AND SILENT. A unit suite or a legacy install must not
  become an operator alarm; a fix that logs here has turned normal operation into noise, which is the
  reason every latch in this module exists.
* THE FAULT — a raising ``get_bind()`` returns the third answer (``None``, "could not tell"), the read
  still completes, the counter increments EVERY time, and the warning fires ONCE.
* THE COLLAPSE GUARD — the fault and the clean negative are different values on purpose, so no later
  edit can fold them back together without reddening a cell here.

Door-OFF runs everything except ``TestPostgresRealEngine``; door-ON runs all of it. The two faces are
different faces and are reported separately (root ``AGENTS.md`` door-ON gate rule; #614).
"""

from __future__ import annotations

import inspect
import logging
import os
from unittest.mock import MagicMock

import pytest
from server import revocation_read
from server.revocation_read import bounded_read
from sqlalchemy import create_engine, event, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

PG_URL_ENV = "VENYA_TEST_PG_URL"

#: The house deadline every PG engine in a gated file must carry (#614 claim 5 covers engines by
#: SHAPE, not by class name, so a gated file that opened a bounded-less PG connection would be a
#: hang waiting to happen — the #607 s105 shape. Copied verbatim from the other gated files; one
#: name, one value, by that interlock's own rule.
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}

#: The site label every cell here uses. ``heartbeat`` is already inside the closed vocabulary
#: ``test_revocation_scan_bound_654.py`` pins, so these cells cannot widen the label set.
SITE = "heartbeat"


def _counter(site: str = SITE) -> float:
    return revocation_read.metrics.REVOCATION_READ_UNBOUNDED_TOTAL.labels(site=site)._value.get()


def _sqlite_session():
    """A REAL SQLite bind — the clean negative, not a double pretending to be one.

    The engine installs ``PRAGMA foreign_keys=ON`` on connect (#634 interlock, house shape:
    ``packages/core/tests/test_secret_delete_fk.py``). This file declares no schema, so enforcement
    cannot fire on anything it asserts — it is here so the blind-spot ratchet stays closed, not to
    change a result. The exemption table is reserved for files whose subject IS the blindness.
    """
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return sessionmaker(bind=engine)()


class _FaultingBind:
    """A session whose bind cannot be had — the #704 state, modelled rather than simulated away.

    ``get_bind`` raises the way a disposed engine or a half-torn-down pool raises. Nothing else on
    this object may be reached: the seam yields before ``flush``/``begin_nested``/``execute``, and
    ``__getattr__`` turns any reach past the gate into a named failure instead of a mock's silence.
    """

    def __init__(self) -> None:
        self.bind_calls = 0

    def get_bind(self):
        self.bind_calls += 1
        raise RuntimeError("no bind: the driver cannot say what it is talking to")

    def __getattr__(self, name: str):
        raise AssertionError(f"the seam reached past the dialect gate into {name!r} — #704 yields early")


@pytest.fixture(autouse=True)
def _reset_latches():
    revocation_read.reset_read_deadline_state()
    yield
    revocation_read.reset_read_deadline_state()


class TestCollapseGuard:
    """#704 IS the collapse: one value for "not PG" and another for "cannot tell"."""

    def test_a_real_dialect_answers_a_name_and_a_fault_answers_none(self):
        sqlite = _sqlite_session()
        try:
            assert revocation_read._dialect_name(sqlite) == "sqlite", "a real bind is a FACT"
        finally:
            sqlite.close()
        assert revocation_read._dialect_name(_FaultingBind()) is None

    def test_the_fault_is_not_the_negative_under_any_reading(self):
        """Guarded against the exact edit that would re-open the ticket.

        A future seat "simplifying" the gate back to a bool makes the fault and the clean negative
        one value again, and every assertion below goes red the moment it does — which is the point:
        the shipped bug was one value standing in for two facts, and no caller could tell an ordinary
        install from a broken one.
        """
        sqlite = _sqlite_session()
        try:
            negative = revocation_read._dialect_name(sqlite)
        finally:
            sqlite.close()
        fault = revocation_read._dialect_name(_FaultingBind())
        assert fault is None, "the fault answers NOTHING, not a name"
        assert negative == "sqlite", "the clean negative answers a NAME"
        assert fault != negative, (
            "#704 in one line: two facts, two values. The shipped bug was both facts carrying one "
            "value, which is why no caller could tell an ordinary install from a broken one"
        )
        assert not fault and negative, (
            "both readings keep the seam's posture — the gate stays falsy for each, so the read "
            "goes ahead either way; the distinction is in the value and the count, not in behaviour"
        )


class TestTheFaultIsObservable:
    def test_the_fault_counts_and_the_read_still_completes(self):
        """Nothing is refused and nothing is abstained: the enclosed read runs, the state is counted."""
        before = _counter()
        db = _FaultingBind()
        with bounded_read(db, site=SITE):
            completed = True
        assert completed, "bounding must not have become abstaining"
        assert _counter() == before + 1, "the fault is counted every occurrence, never latched"
        assert db.bind_calls == 1, "the dialect is asked once per read, not once per statement"

    def test_the_warning_names_the_site_the_series_and_its_own_limit(self, caplog):
        """A line ops cannot act on is not observability."""
        with caplog.at_level(logging.WARNING):
            with bounded_read(_FaultingBind(), site=SITE):
                pass
        assert SITE in caplog.text, f"the line must say WHICH path ran unbonded: {caplog.text!r}"
        assert "installed NO deadline" in caplog.text
        assert "venya_revocation_read_unbounded_total" in caplog.text, "the line points at the counter"
        assert "ONCE per process" in caplog.text, "the latch is documented behavior, not an accident"
        assert (
            "NOT refused" in caplog.text
        ), "#603's vocabulary law: an ops line must never imply a verdict that did not happen"

    def test_the_line_fires_once_and_the_counter_keeps_counting(self, caplog):
        """#651's pairing, applied to the new state: one human trace, a cumulative number behind it."""
        before = _counter()
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                with bounded_read(_FaultingBind(), site=SITE):
                    pass
        assert _counter() == before + 3
        assert caplog.text.count("installed NO deadline") == 1, "un-latched alarms get ignored"
        assert revocation_read.is_unbounded_dialect_warned() is True

    def test_the_reset_clears_the_new_latch_with_the_others(self):
        """A latch nobody resets is a latch that stops reporting after the first test session."""
        with bounded_read(_FaultingBind(), site=SITE):
            pass
        assert revocation_read.is_unbounded_dialect_warned() is True
        revocation_read.reset_read_deadline_state()
        assert revocation_read.is_unbounded_dialect_warned() is False

    def test_a_double_with_no_bind_surface_at_all_is_the_same_fault(self):
        """The unit-suite shape, named rather than assumed.

        ``MagicMock`` answers ANY attribute, so its ``get_bind()`` returns a mock whose dialect name
        is a mock — that is not ``POSTGRESQL_DIALECT``, so the seam treats it as a clean negative and
        stays silent. This cell pins which double shapes count and which do not, because the difference
        is exactly where a future "just log on False" would drown the unit suites in warnings.
        """
        before = _counter()
        with bounded_read(MagicMock(name="bare-session-double"), site=SITE):
            pass
        assert _counter() == before, "a bare double is not a fault; it is the shape the gate predates"

    def test_the_label_is_the_files_own_mechanism_not_a_new_argument(self, caplog):
        """The unlabelled read keeps the plane default; only a named site moves a named label."""
        default_before = _counter(site="revocation-plane")
        with caplog.at_level(logging.WARNING):
            with bounded_read(_FaultingBind()):
                pass
        assert _counter(site="revocation-plane") == default_before + 1, (
            "an unlabelled read lands on the plane default exactly as a refusal does — the site "
            "mechanism is reused, not re-invented, so the 7 shipped call sites were not touched"
        )


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason="these claims need a scratch PostgreSQL in VENYA_TEST_PG_URL (the door-ON face; #614)",
)
class TestUnboundedDialectPostgresql:
    """The positive half, on the engine that ships. Door OFF, this class is the skip set.

    Named ``*Postgresql`` because that is the shape #614's scan walks, and it opens its engine with
    the house ``_PG_DEADLINE`` for the same reason — an unbounded test connection is a hang with a
    passing-looking cell attached.
    """

    def _engine_session(self):
        return sessionmaker(bind=create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE))()

    def test_pg_reports_the_dialect_name_the_gate_compares_on(self):
        session = self._engine_session()
        try:
            assert revocation_read._dialect_name(session) == revocation_read.POSTGRESQL_DIALECT
        finally:
            session.close()

    def test_a_real_pg_read_installs_both_deadlines_and_counts_nothing(self, caplog):
        """The read the fault cell contrasts against: bounded, silent, and unchanged by this leg."""
        before = _counter()
        session = self._engine_session()
        try:
            with caplog.at_level(logging.WARNING):
                with bounded_read(session, site=SITE):
                    assert session.execute(text("SELECT 1")).scalar() == 1
                    inside = session.execute(text("SHOW lock_timeout")).scalar()
            assert (
                inside == f"{revocation_read.current_lock_timeout_ms()}ms"
            ), "the bound is held while the read runs — that is the behavior #704 must not disturb"
            assert _counter() == before, "a bounded PG read is not an unbounded one"
            assert "installed NO deadline" not in caplog.text
        finally:
            session.close()


class TestSqliteRealEngineStaysQuiet:
    """The clean negative on a REAL engine (not a double): inert, silent, uncounted."""

    def test_sqlite_is_inert_and_logs_nothing(self, caplog):
        before = _counter()
        session = _sqlite_session()
        try:
            with caplog.at_level(logging.WARNING):
                with bounded_read(session, site=SITE):
                    assert session.execute(text("SELECT 1")).scalar() == 1
        finally:
            session.close()
        assert "installed NO deadline" not in caplog.text, f"a clean non-PG install must not alarm ops: {caplog.text!r}"
        assert _counter() == before, "the clean negative is NOT counted — that is the whole point"
        assert revocation_read.is_unbounded_dialect_warned() is False

    def test_the_sqlite_name_is_the_very_string_the_gate_compares(self):
        """Pinned so the comparison is not accidentally widened to 'anything but sqlite'."""
        session = _sqlite_session()
        try:
            assert revocation_read._dialect_name(session) == "sqlite"
            assert revocation_read._dialect_name(session) != revocation_read.POSTGRESQL_DIALECT
        finally:
            session.close()


class TestSeamContractSurvives:
    """Neighbour guards: this leg added a branch OUTSIDE the bounded scope, not inside it."""

    def test_the_dialect_gate_still_precedes_every_seam_statement(self):
        """The gate is still the first thing the seam does — #704 added a branch, not an I/O act."""
        src = inspect.getsource(bounded_read)
        assert "dialect = _dialect_name(db)" in src
        assert src.index("dialect = _dialect_name(db)") < src.index(
            "db.flush()"
        ), "the dialect question must precede flush/savepoint, or the fault path starts writing"

    def test_the_pg_dialect_name_is_declared_once(self):
        """The constant exists so the two callers of the question cannot drift to two literals."""
        assert revocation_read.POSTGRESQL_DIALECT == postgresql.dialect().name
