# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for server.maintenance — the extracted periodic DB cleanup passes."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from server.maintenance import (
    cleanup_expired_execution_sessions,
    cleanup_expired_sessions,
    cleanup_rate_limit_counters,
    purge_admin_identity_metadata,
    run_maintenance,
)
from sqlalchemy.pool import StaticPool


def _sql(db: MagicMock) -> str:
    clause = db.execute.call_args[0][0]
    raw = getattr(clause, "text", None)
    return raw if isinstance(raw, str) else str(clause)


def _params(db: MagicMock) -> dict:
    return db.execute.call_args[0][1]


def test_cleanup_expired_sessions_runs_delete_and_commits():
    db = MagicMock()
    db.execute.return_value.rowcount = 7
    assert cleanup_expired_sessions(db) == 7
    assert "DELETE FROM sessions" in _sql(db)
    assert _params(db)["limit"] == 1000  # M-27 cap
    assert isinstance(_params(db)["threshold"], datetime)
    # #529: the hard-cap leg rides with the idle leg in the same statement.
    assert "created_at" in _sql(db)
    assert isinstance(_params(db)["cap_dead"], datetime)
    db.commit.assert_called_once()


# --- #529 behavior: the sweep must catch past-cap sessions ------------------
#
# Real SQLite (house pattern: test_admin_delete_dependencies_425.py) — the
# predicate IS the mechanism here, so which rows vanish is the assertion.
# Defaults used by the sweep: timeout 900s, cap 14400s, tolerance 60s.


@pytest.fixture()
def session_db():
    from core.iam.models import Base
    from core.iam.models import Session as SessionModel
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s._model = SessionModel  # handy for the cells
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _mk(session, created_delta, expires_delta, token):
    SessionModel = session._model
    row = SessionModel(
        user_id="u-" + token,
        created_at=datetime.now(UTC) + timedelta(seconds=created_delta),
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_delta),
        access_token=token,
    )
    session.add(row)
    session.commit()


def _surviving(session):
    session.expire_all()
    return {r.access_token for r in session.query(session._model).all()}


class TestHardCapSweep529:
    def test_extended_past_cap_is_swept(self, session_db):
        """PAIRED (the #529 defect): a session refreshed into a future
        expires_at but past created_at + max_session_duration never matched
        the idle leg and lived forever. The cap leg takes it."""
        _mk(session_db, created_delta=-5 * 3600, expires_delta=+600, token="past-cap")
        assert cleanup_expired_sessions(session_db) == 1
        assert _surviving(session_db) == set()

    def test_active_within_cap_is_kept(self, session_db):
        """Positive retained: a live, in-cap session is never touched."""
        _mk(session_db, created_delta=-3 * 3600, expires_delta=+600, token="live")
        assert cleanup_expired_sessions(session_db) == 0
        assert _surviving(session_db) == {"live"}

    def test_idle_dead_beyond_cap_still_swept(self, session_db):
        """Original idle leg behavior preserved (this row matched the old
        predicate too)."""
        _mk(session_db, created_delta=-6 * 3600, expires_delta=-5 * 3600, token="idle-dead")
        assert cleanup_expired_sessions(session_db) == 1
        assert _surviving(session_db) == set()

    def test_idle_expired_within_cap_survives(self, session_db):
        """Option A invariant (#523/#526): idle-expired INSIDE the cap is
        refresh-recoverable — the sweep must not eat it. Both legs keep:
        idle threshold is cap-minus-a-window conservative, cap leg not
        reached."""
        _mk(session_db, created_delta=-2 * 3600, expires_delta=-3600, token="recoverable")
        assert cleanup_expired_sessions(session_db) == 0
        assert _surviving(session_db) == {"recoverable"}

    def test_cap_boundary_keeps_live_side(self, session_db):
        """Tolerance side pin: created exactly at the cap is still
        refreshable (check_refresh_window: created + cap >= now), so the
        sweep keeps it — fail toward keeping live sessions."""
        _mk(session_db, created_delta=-14400, expires_delta=+600, token="at-cap")
        assert cleanup_expired_sessions(session_db) == 0
        assert _surviving(session_db) == {"at-cap"}

    def test_sweep_bounded_by_limit(self, session_db):
        """M-27 cap holds on the widened predicate: at most 1000 rows per
        tick even when 1200 are past cap."""
        for i in range(1200):
            _mk(session_db, created_delta=-5 * 3600, expires_delta=+600, token=f"bulk-{i}")
        assert cleanup_expired_sessions(session_db) == 1000
        assert len(_surviving(session_db)) == 200


def test_cleanup_expired_execution_sessions_deletes_fk_children_then_parents():
    """execution_session_secrets.session_id -> execution_sessions.id has no ON DELETE
    CASCADE, so the child rows must be deleted first or the parent DELETE raises an
    FK violation. Both deletes use the same expires_at predicate (no LIMIT) so they
    target the identical row set — a per-statement LIMIT could diverge and orphan a
    parent delete (ticket execute-stale-session-update-500 / unbounded-growth finding).
    """
    db = MagicMock()
    db.execute.return_value.rowcount = 5
    assert cleanup_expired_execution_sessions(db) == 5
    calls = db.execute.call_args_list
    assert len(calls) == 2
    child_sql, parent_sql = str(calls[0][0][0]), str(calls[1][0][0])
    assert "DELETE FROM execution_session_secrets" in child_sql  # FK child first
    assert "DELETE FROM execution_sessions" in parent_sql
    assert "expires_at" in child_sql and "expires_at" in parent_sql
    assert isinstance(calls[0][0][1]["now"], datetime)
    db.commit.assert_called_once()


def test_purge_admin_identity_metadata_runs_update_and_commits():
    db = MagicMock()
    db.execute.return_value.rowcount = 3
    assert purge_admin_identity_metadata(db) == 3
    assert "UPDATE executor_enrollment_tokens" in _sql(db)
    assert "cutoff" in _params(db)
    db.commit.assert_called_once()


def test_cleanup_rate_limit_counters_runs_delete_and_commits():
    db = MagicMock()
    db.execute.return_value.rowcount = 2
    assert cleanup_rate_limit_counters(db) == 2
    assert "DELETE FROM rate_limit_failures" in _sql(db)
    assert "threshold" in _params(db)
    db.commit.assert_called_once()


def test_run_maintenance_happy_path_runs_all_four():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    run_maintenance(db, None, None)  # config=None → defaults, must not raise
    assert db.commit.call_count == 4


def test_run_maintenance_respects_config_values():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    config = SimpleNamespace(
        session=SimpleNamespace(session_timeout=123, max_session_duration=456),
        clock_skew=SimpleNamespace(token_tolerance_seconds=7),
    )
    run_maintenance(db, config, None)
    assert db.commit.call_count == 4


def test_run_maintenance_secondary_failure_is_isolated():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    with patch(
        "server.maintenance.purge_admin_identity_metadata",
        side_effect=RuntimeError("boom"),
    ):
        run_maintenance(db, None, None)  # must NOT raise
    # sessions + execution-sessions + rate-limit commits; purge failed before its commit
    assert db.commit.call_count == 3
    db.rollback.assert_called_once()


def test_run_maintenance_primary_failure_propagates_no_rollback_here():
    db = MagicMock()
    db.execute.side_effect = RuntimeError("db down")
    with pytest.raises(RuntimeError):
        run_maintenance(db, None, None)
    # Primary failure is rolled back by the caller (app.py loop), not run_maintenance.
    db.rollback.assert_not_called()


def test_run_maintenance_revocation_purge_pass_runs():
    """5th pass RUNS when ca_manager is wired (user ruling 2026-09-21: a
    never-called pass with a defaulted-to-None manager is a quiet dead
    feature — pinned with the real signature; relocated from the public CRL
    GETs, ticket sec-sweep-low-informational #23b). Default retention 90."""
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    ca_manager = MagicMock()
    ca_manager.purge_expired_revocations.return_value = 3
    run_maintenance(db, None, ca_manager)
    ca_manager.purge_expired_revocations.assert_called_once_with(db, 90)


def test_run_maintenance_revocation_purge_retention_from_config():
    """Retention days come from config.crl when present."""
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    config = SimpleNamespace(crl=SimpleNamespace(crl_retention_days=30))
    ca_manager = MagicMock()
    ca_manager.purge_expired_revocations.return_value = 0
    run_maintenance(db, config, ca_manager)
    ca_manager.purge_expired_revocations.assert_called_once_with(db, 30)


def test_run_maintenance_purge_failure_is_isolated():
    """A purge blowup rolls back and does not abort the run (isolated-pass
    contract shared with the other secondary passes)."""
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    ca_manager = MagicMock()
    ca_manager.purge_expired_revocations.side_effect = RuntimeError("boom")
    run_maintenance(db, None, ca_manager)  # must not raise
    db.rollback.assert_called()
