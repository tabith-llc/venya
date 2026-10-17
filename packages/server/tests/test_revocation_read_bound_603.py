# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#603 AC1 — the bounded-time revocation read, both halves of the truth table.

The shipped 45 s freshness ceiling was proven UNREACHABLE on a core under a held
``ACCESS EXCLUSIVE`` lock: the request-path revocation reads are synchronous
SQLAlchemy inside ``async def`` handlers, so the lock stall parked the single-worker
event loop and nothing answered at all — measured as 57 seconds with zero access-log
lines, poll/health/ready all ``000``, stale-class 503 count 0
(``wave29-specs-20261016/flash2-603-liveness-offload-s129-report.md``). This file
judges the fix: the read now carries a lock deadline and a NAMED refusal.

What is asserted, in order:

* REFUSAL CLASS — a lock-wait refusal is distinguishable from a revocation, on every
  axis ops reads: status (503, never 403), the detail sentence, and the metric. It is
  also never a 200-with-revoked=false, which would be the fail-open.
* POSITIVE HALF — a real revocation still answers its own shipped bytes. The bound must
  not soften the enforcing arm.
* SCOPING — the deadline must never reach the caller's WRITE. Measured on a live core:
  a blanket engine-wide deadline refused a legitimate beat-style write at 2,033 ms that
  shipped completes at 4,037 ms, so the seam puts the deadline in a savepoint around the
  read only. The savepoint properties pinned here are the ones measured on PostgreSQL
  16.15: ``ROLLBACK TO`` reverts the setting and keeps the transaction usable, and
  ``RELEASE`` alone does NOT revert it (which is why the success path reverts explicitly).
* PENDING WRITE SURVIVAL — a caller's uncommitted write is flushed before the savepoint,
  so the refusal path cannot roll it back.
* ALERTING — a cumulative counter (never latched) plus a latched warning, because #651's
  defect shape was a per-emit warning with no counter.

Doubles subclass ``Backend`` where the reservation branch matters (same reason as
``test_liveness_reserved_path_603.py``: a bare ``MagicMock`` answers any attribute name).
"""

from __future__ import annotations

import inspect
import logging
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from server import revocation, revocation_read
from server.revocation import executor_revocation_state
from server.revocation_read import (
    LOCK_TIMEOUT_SQLSTATE,
    REVOCATION_UNAVAILABLE_DETAIL,
    RevocationReadUnavailable,
    bounded_read,
    for_site,
)
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError

SHIPPED_REVOKED_403 = "Executor mTLS authentication required"


def _lock_timeout_fault() -> DBAPIError:
    """A DBAPIError carrying PostgreSQL 55P03, the shape psycopg raises on lock_timeout."""
    orig = SimpleNamespace(pgcode=LOCK_TIMEOUT_SQLSTATE, args=(), sqlstate=LOCK_TIMEOUT_SQLSTATE)
    return DBAPIError("SELECT … FROM executor_cert_revocations", {}, orig)


def _unrelated_fault() -> RuntimeError:
    return RuntimeError("some other backend fault")


class _RecordingSavepoint:
    def __init__(self, owner) -> None:
        self.owner = owner

    def rollback(self):
        self.owner.events.append("savepoint-rollback")

    def commit(self):
        # Mirrors the product: SQLAlchemy exposes RELEASE SAVEPOINT as a nested commit, and
        # SessionTransaction has NO release() — the double must not offer a method the real
        # object lacks, or a unit suite stays green while every live read dies with
        # AttributeError (which is exactly what the first draft did on core-3).
        self.owner.events.append("savepoint-release")


class _FakePGSession:
    """A session whose bind claims the postgresql dialect, so the seam is ACTIVE.

    ``raise_on_read`` selects what the enclosed read does; the recorded event list is
    what the cells assert on, because the whole point is the ORDER of savepoint and
    SET statements, not the value read.
    """

    """A session whose bind claims the postgresql dialect, so the seam is ACTIVE.

    ``fail_read`` is what the ENCLOSED read does — the seam's own SET statements always
    succeed, so the failure under test is the read's, exactly as it is on a real core where
    the deadline kills the SELECT and not the ``SET``.
    """

    def __init__(
        self,
        *,
        raise_on_read=None,
        fail_read=None,
        rows=None,
        fail_on_clear=False,
        rows_by_name=None,
    ) -> None:
        self.events: list[str] = []
        self.statements: list[str] = []
        self._raise = raise_on_read
        self._fail_read = fail_read
        self._rows = rows if rows is not None else [("row",)]
        self._fail_on_clear = fail_on_clear
        self._in_savepoint = False
        self._rows_by_name = rows_by_name or {}
        self.read_attempts = 0

    # --- dialect gate ---------------------------------------------------------------
    def get_bind(self):
        return SimpleNamespace(dialect=postgresql.dialect())

    # --- session surface used by the seam -------------------------------------------
    def flush(self):
        self.events.append("flush")

    def begin_nested(self):
        self.events.append("savepoint-begin")
        self._in_savepoint = True
        return _RecordingSavepoint(self)

    def execute(self, statement, params=None):
        sql = str(statement)
        verb = sql.split()[0].upper() if sql.split() else "?"
        self.events.append(f"execute:{verb}")
        self.statements.append(sql)
        if self._fail_on_clear and "lock_timeout = '0'" in sql:
            raise _unrelated_fault()
        if "lock_timeout" not in sql and self._raise is not None:
            raise self._raise
        return SimpleNamespace(fetchall=lambda: self._rows, scalar=lambda: 1)

    def query(self, *a, **kw):
        """Enough of the ORM query surface for the matcher to run against this double."""
        self.read_attempts += 1
        if self._fail_read is not None:
            raise self._fail_read
        q = MagicMock(name="query")
        name = getattr(a[0], "__name__", "") if a else ""
        q.filter.return_value.first.return_value = self._rows_by_name.get(name)
        q.count.return_value = 0
        return q

    def lock_timeout_visible(self) -> list[str]:
        return [s for s in self.statements if "lock_timeout" in s]


class _FakeSQLiteSession(_FakePGSession):
    """Same shape, non-PG bind: the seam must be a NO-OP (unit suites run on SQLite)."""

    def get_bind(self):
        return SimpleNamespace(dialect=MagicMock(name="sqlite3"))


@pytest.fixture(autouse=True)
def _reset_deadline_state():
    revocation_read.reset_read_deadline_state()
    yield
    revocation_read.reset_read_deadline_state()


class TestRefusalClass:
    """The bound must produce an outcome ops can tell apart from a revocation."""

    def test_lock_wait_raises_the_named_class(self):
        db = _FakePGSession(raise_on_read=_lock_timeout_fault())
        with pytest.raises(RevocationReadUnavailable) as got:
            with bounded_read(db, site="heartbeat"):
                db.execute("SELECT 1 FROM executor_cert_revocations")
        # The message names the site AND the deadline, so a journal line is enough to act on.
        assert "heartbeat" in str(got.value)
        assert str(revocation_read.current_lock_timeout_ms()) in str(got.value)

    def test_unrelated_fault_is_not_converted_into_a_revocation_plane_refusal(self):
        """The classification is by SQLSTATE, not by 'something went wrong'. Folding an
        unrelated fault in here would relabel bugs as availability faults and hide them."""
        db = _FakePGSession(raise_on_read=_unrelated_fault())
        with pytest.raises(RuntimeError, match="some other backend fault"):
            with bounded_read(db, site="dial/execute"):
                db.execute("SELECT 1")

    def test_refusal_is_not_an_all_clear_under_any_reading(self):
        """A refusal raises; it does not return RevocationState(False). Returning "not
        revoked" from an unanswered question is the most permissive answer available and
        the exact fail-open #603 exists to close."""
        db = _FakePGSession(
            fail_read=_lock_timeout_fault(),
            rows_by_name={"Executor": SimpleNamespace(id="venya-exec-1", revoked_at=None)},
        )
        with pytest.raises(RevocationReadUnavailable):
            executor_revocation_state(db, "venya-exec-1")
        # The refusal came from the read itself, and no verdict object was produced.
        assert db.read_attempts >= 1

    def test_query_canceled_is_not_folded_into_the_lock_refusal(self):
        """AC1 criterion 1: the LOCK WAIT gets its own named outcome. 57014
        (statement_timeout) must not masquerade as 55P03, or a slow scan gets reported
        as a lock convoy and ops chase the wrong thing."""
        canceled = SimpleNamespace(pgcode="57014", sqlstate="57014")
        assert revocation_read.is_lock_timeout(DBAPIError("x", {}, canceled)) is False
        assert revocation_read.is_lock_timeout(_lock_timeout_fault()) is True

    def test_classification_walks_a_wrapped_cause(self):
        """The DBAPI can surface the code wrapped; a flat check would miss it and the
        refusal would escape the counter and the latch."""
        wrapped = _unrelated_fault()
        wrapped.__cause__ = _lock_timeout_fault()
        assert revocation_read.is_lock_timeout(wrapped) is True


class TestDeadlineScoping:
    """The deadline is scoped to the read, and reverted — never left on the connection."""

    def test_success_path_sets_reverts_then_releases(self):
        db = _FakePGSession()
        with bounded_read(db, site="heartbeat"):
            db.execute("SELECT 1 FROM executor_cert_revocations")
        locks = db.lock_timeout_visible()
        assert len(locks) == 2, f"expected a SET and an explicit revert, saw {locks}"
        assert "'300ms'" in locks[0]
        assert "= '0'" in locks[1], "the revert must clear the deadline, not re-set it"
        assert locks[0] != locks[1]
        assert db.events.index("savepoint-begin") < db.events.index("execute:SET")
        assert "savepoint-release" in db.events
        assert "savepoint-rollback" not in db.events

    def test_release_alone_is_not_treated_as_a_revert(self):
        """The measured reason the explicit revert exists: on PostgreSQL 16.15
        ``RELEASE SAVEPOINT`` left ``lock_timeout`` at 500ms. A seam that trusted release
        would leave the caller's NEXT statement — usually a write — under a deadline."""
        db = _FakePGSession()
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        last = db.lock_timeout_visible()[-1]
        assert "= '0'" in last

    def test_refusal_path_rolls_back_the_savepoint_and_reverts(self):
        db = _FakePGSession(raise_on_read=_lock_timeout_fault())
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(db, site="heartbeat"):
                db.execute("SELECT 1")
        assert db.events.count("savepoint-rollback") == 1
        # The rollback is what reverts SET LOCAL, so no second SET is issued on this path.
        assert len(db.lock_timeout_visible()) == 1

    def test_pending_caller_write_is_flushed_before_the_savepoint(self):
        """Without the entry flush, SQLAlchemy's autoflush would place the caller's
        pending write INSIDE the savepoint, and the refusal's ROLLBACK TO would silently
        discard it — turning a read deadline into data loss."""
        db = _FakePGSession(raise_on_read=_lock_timeout_fault())
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(db, site="register/rotation-prior-serial"):
                db.execute("SELECT 1")
        assert db.events.index("flush") < db.events.index(
            "savepoint-begin"
        ), f"flush must precede the savepoint, events: {db.events}"

    def test_seam_is_a_noop_on_non_postgres(self):
        """The unit suites run on SQLite, where lock_timeout does not exist. A no-op keeps
        every existing suite answering byte-for-byte, instead of erroring on the SET."""
        db = _FakeSQLiteSession()
        with bounded_read(db, site="heartbeat"):
            db.execute("SELECT 1")
        assert db.lock_timeout_visible() == []
        assert db.events == ["execute:SELECT"], db.events

    def test_deadline_is_built_from_a_validated_int_not_a_string(self):
        """The template interpolates. A non-int must not be able to smuggle SQL text."""
        assert "'250ms'" in str(revocation_read.deadline_statement(250))
        with pytest.raises((ValueError, TypeError)):
            revocation_read.deadline_statement("250ms'; DROP TABLE executors; --")

    def test_configure_ignores_zero_and_none_rather_than_disabling_the_bound(self):
        """Disabling is not a supported posture here: a config that omits the key must not
        silently remove the protection."""
        revocation_read.configure_lock_timeout(None)
        assert revocation_read.current_lock_timeout_ms() == revocation_read.DEFAULT_LOCK_TIMEOUT_MS
        revocation_read.configure_lock_timeout(0)
        assert revocation_read.current_lock_timeout_ms() == revocation_read.DEFAULT_LOCK_TIMEOUT_MS
        revocation_read.configure_lock_timeout(750)
        assert revocation_read.current_lock_timeout_ms() == 750


class TestAlerting:
    """#651's defect shape, avoided explicitly: a cumulative counter plus a LATCHED line."""

    def _counter(self, site: str) -> float:
        from server import metrics

        return metrics.REVOCATION_READ_REFUSALS_TOTAL.labels(site=site)._value.get()

    def test_every_refusal_is_counted_never_latched(self):
        start = self._counter("heartbeat")
        for _ in range(3):
            db = _FakePGSession(raise_on_read=_lock_timeout_fault())
            with pytest.raises(RevocationReadUnavailable):
                with bounded_read(db, site="heartbeat"):
                    db.execute("SELECT 1")
        assert self._counter("heartbeat") == start + 3

    def test_warning_line_fires_once_and_counter_still_counts_all(self):
        """The pairing, asserted together: the log latches so a storm is not noise, the
        counter does not, so the lost volume is still knowable after the fact."""
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(_FakePGSession(raise_on_read=_lock_timeout_fault()), site="crl"):
                raise _lock_timeout_fault()
        assert revocation_read.is_refusal_warned() is True
        first = self._counter("crl")
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(_FakePGSession(raise_on_read=_lock_timeout_fault()), site="crl"):
                raise _lock_timeout_fault()
        assert self._counter("crl") == first + 1

    def test_site_label_names_the_path_that_refused(self):
        """Ops must be able to say WHICH endpoint refused; the label is what makes the
        counter actionable rather than a bare number."""
        before = self._counter("dial/execute")
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(_FakePGSession(raise_on_read=_lock_timeout_fault()), site="dial/execute"):
                raise _lock_timeout_fault()
        assert self._counter("dial/execute") == before + 1

    def test_for_site_labels_the_matcher_without_widening_its_signature(self):
        """The matcher's parameter list is pinned by
        ``test_liveness_reserved_path_603.py::TestNoSecondImplementation`` — "the
        reservation moved the SESSION, never the call". So the label travels out of band,
        and this cell pins BOTH halves: the label works AND the signature did not grow."""
        assert list(revocation.executor_revocation_state.__code__.co_varnames[:4]) == [
            "db",
            "executor_id",
            "presented_serial",
            "executor_row",
        ]
        with for_site("heartbeat"):
            assert revocation_read.current_site() == "heartbeat"
        assert revocation_read.current_site() == "revocation-plane"

    def test_for_site_restores_the_previous_label_on_raise(self):
        with for_site("outer"):
            with pytest.raises(ValueError):
                with for_site("inner"):
                    raise ValueError("boom")
            assert revocation_read.current_site() == "outer"

    def test_refusal_detail_is_one_constant_shared_by_both_stale_arms(self):
        """The stale-snapshot 503 and the bounded-read 503 are both LIST-STATE faults and
        must read identically; a leg that re-flows the sentence is how a revocation-shaped
        message ends up naming an event that never happened."""
        from server.routes import executors as ex

        assert ex._STALE_LIST_DETAIL == REVOCATION_UNAVAILABLE_DETAIL
        assert "no revocation asserted" in REVOCATION_UNAVAILABLE_DETAIL.lower()
        # And it is NOT the revocation vocabulary: a revoked credential answers 403 with a
        # different sentence, so ops can tell the two apart.
        assert REVOCATION_UNAVAILABLE_DETAIL != SHIPPED_REVOKED_403
        assert "revoked" not in REVOCATION_UNAVAILABLE_DETAIL.lower()


class TestTruthTablePositiveHalf:
    """A real revocation must still refuse in its OWN class, unchanged."""

    def _rows(self, crl_serial):
        def factory(name):
            if name == "Executor":
                return SimpleNamespace(id="venya-exec-1", revoked_at=None)
            if name == "ExecutorCert":
                return SimpleNamespace(serial_number="0000000000000001")
            if name == "ExecutorCertRevocation":
                return None if crl_serial is None else SimpleNamespace(serial_number=crl_serial, revoked_at=None)
            return None

        return factory

    def _session_on_sqlite(self, factory):
        """A REAL SQLAlchemy session on SQLite: the positive half must produce the shipped
        ANSWER, so it cannot be judged against a query double."""
        from core.iam.models import Base, Executor, ExecutorCert, ExecutorCertRevocation
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite://")
        Base.metadata.create_all(
            engine, tables=[Executor.__table__, ExecutorCert.__table__, ExecutorCertRevocation.__table__]
        )
        db = sessionmaker(bind=engine)()
        db.add(Executor(id="venya-exec-1", hostname="exec-1.test", enrolled_at=datetime.now(UTC), revoked_at=None))
        db.add(
            ExecutorCert(
                executor_id="venya-exec-1",
                serial_number="0000000000000001",
                not_before=datetime.now(UTC),
                not_after=datetime.now(UTC),
                fingerprint="aa:bb:cc",
            )
        )
        if factory is not None:
            db.add(ExecutorCertRevocation(serial_number=factory, executor_id="other", reason="manual"))
        db.commit()
        return db

    def test_serial_on_list_still_revokes(self):
        db = self._session_on_sqlite("0000000000000001")
        assert executor_revocation_state(db, "venya-exec-1").revoked is True

    def test_serial_not_on_list_still_live(self):
        db = self._session_on_sqlite("9999999999999999")
        assert executor_revocation_state(db, "venya-exec-1").revoked is False

    def test_identity_flag_wins_and_is_reported_as_identity(self):
        from datetime import UTC, datetime

        from core.iam.models import Base, Executor, ExecutorCert
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine, tables=[Executor.__table__, ExecutorCert.__table__])
        db = sessionmaker(bind=engine)()
        db.add(
            Executor(
                id="venya-exec-9",
                hostname="exec-9.test",
                enrolled_at=datetime.now(UTC),
                revoked_at=datetime.now(UTC),
            )
        )
        db.commit()
        state = executor_revocation_state(db, "venya-exec-9")
        assert (state.revoked, state.reason) == (True, "identity")

    def test_positive_half_runs_with_the_seam_active_on_sqlite(self):
        """The no-op branch must not merely be un-involved — it has to leave the verdict
        identical, which is what makes "zero behavior delta for the unit suites" provable."""
        db = self._session_on_sqlite("0000000000000001")
        with bounded_read(db, site="heartbeat"):
            assert executor_revocation_state(db, "venya-exec-1").revoked is True


class TestSeamAgainstRealSQLAlchemy:
    """The double must not be wider than the real object it stands for.

    Booked because the first draft called ``savepoint.release()``, which does not exist on
    ``SessionTransaction``: every unit cell passed and the live core failed all four reads with
    ``AttributeError``. These cells close that gap by driving the seam against a REAL
    SQLAlchemy Session and asserting against the real class's own surface.
    """

    def test_seam_uses_only_methods_SessionTransaction_actually_has(self):
        """Parse the seam's real CALLS off the AST — a string search would be fooled by the
        prose that documents this very bug (the first draft's ``sp.release()`` survives in a
        comment), and prose is exactly what a grep-based guard reads."""
        import ast

        import server.revocation_read as module
        from sqlalchemy.orm.session import SessionTransaction

        tree = ast.parse(inspect.getsource(module))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "bounded_read")
        called = {
            node.func.attr
            for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "sp"
        }
        assert called, "the seam never touched the savepoint object at all — a broken guard"
        missing = {m for m in called if not hasattr(SessionTransaction, m)}
        assert not missing, f"seam calls savepoint methods the real class lacks: {sorted(missing)}"
        assert called <= {"commit", "rollback", "close"}, f"unexpected savepoint surface: {sorted(called)}"

    def test_seam_runs_clean_on_a_real_sqlite_session(self):
        """Non-PG bind: the seam must be inert, not merely non-raising — the real Session
        surface is exercised here (flush/begin_nested are never touched on this branch)."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite://")
        with engine.begin() as conn:
            conn.exec_driver_sql("CREATE TABLE t (id INTEGER)")
            conn.exec_driver_sql("INSERT INTO t VALUES (1)")
        db = sessionmaker(bind=engine)()
        try:
            with bounded_read(db, site="heartbeat"):
                assert db.execute(text("SELECT id FROM t")).scalar() == 1
        finally:
            db.close()


class TestPinnedWording:
    def test_warning_names_the_counter_as_the_alerting_surface(self, caplog):
        with caplog.at_level(logging.WARNING):
            with pytest.raises(RevocationReadUnavailable):
                with bounded_read(_FakePGSession(raise_on_read=_lock_timeout_fault()), site="heartbeat"):
                    raise _lock_timeout_fault()
        text = caplog.text
        assert "venya_revocation_read_refusals_total" in text, "the line must point at the counter"
        assert "ONCE per process" in text, "the latch is a documented behavior, not an accident"
        assert "not a revocation and not an all-clear" in text

    def test_config_field_exists_and_is_named_on_the_env_surface(self):
        """AC1 criterion 1: the LOCK timeout is named on the config surface (it is not
        reachable only as a constant nobody can tune, and it is not statement_timeout)."""
        from server.config import CRLConfig, ServerConfig

        field = CRLConfig.model_fields["revocation_read_lock_timeout_ms"]
        assert field.default == 300
        cfg = ServerConfig(recovery_code_pepper="p", crl={"revocation_read_lock_timeout_ms": 900})
        assert cfg.crl.revocation_read_lock_timeout_ms == 900
        # Bounds exist so a typo cannot install a deadline that outlives the ceiling it
        # guards. Named exception, not a blind one: a ValidationError is the shipped shape for
        # a pydantic field bound, and asserting "anything at all" would pass on an import error.
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_lock_timeout_ms=0)
        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_lock_timeout_ms=999_999)

    def test_app_registers_one_central_refusal_arm(self):
        """A refusal arm that must be remembered at fourteen sites is a refusal arm missing
        at one; the app owns one handler, so no site can leak the fault as an unlabeled 500."""
        import inspect

        import server.app as app_module

        src = inspect.getsource(app_module)
        assert "add_exception_handler(_ReadUnavailable" in src or "RevocationReadUnavailable" in src
        assert src.count("REVOCATION_UNAVAILABLE_DETAIL") >= 1
