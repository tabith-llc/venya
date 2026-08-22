"""Tests for server.maintenance — the extracted periodic DB cleanup passes."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from server.maintenance import (
    cleanup_expired_sessions,
    cleanup_rate_limit_counters,
    purge_admin_identity_metadata,
    run_maintenance,
)


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


def test_run_maintenance_happy_path_runs_all_three():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    run_maintenance(db, None)  # config=None → defaults, must not raise
    assert db.commit.call_count == 3


def test_run_maintenance_respects_config_values():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    config = SimpleNamespace(
        session=SimpleNamespace(session_timeout=123, max_session_duration=456),
        clock_skew=SimpleNamespace(token_tolerance_seconds=7),
    )
    run_maintenance(db, config)
    assert db.commit.call_count == 3


def test_run_maintenance_secondary_failure_is_isolated():
    db = MagicMock()
    db.execute.return_value.rowcount = 0
    with patch(
        "server.maintenance.purge_admin_identity_metadata",
        side_effect=RuntimeError("boom"),
    ):
        run_maintenance(db, None)  # must NOT raise
    # sessions + rate-limit commits only; purge failed before its commit
    assert db.commit.call_count == 2
    db.rollback.assert_called_once()


def test_run_maintenance_primary_failure_propagates_no_rollback_here():
    db = MagicMock()
    db.execute.side_effect = RuntimeError("db down")
    with pytest.raises(RuntimeError):
        run_maintenance(db, None)
    # Primary failure is rolled back by the caller (app.py loop), not run_maintenance.
    db.rollback.assert_not_called()
