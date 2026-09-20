# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Real-DB truth table for the post-relay execution_session bookkeeping.

Ticket execute-stale-session-update-500: the post-relay UPDATE used ORM-object
mutation + flush, which raises ``StaleDataError`` if the ``execution_sessions`` row
vanished mid-execute (e.g. the new TTL cleanup pass deleting an expired session
during a long relay) -> an unhandled 500 AFTER the command already ran on the
executor. The fix routes the bookkeeping through ``_mark_execution_session_completed``,
a bulk ``UPDATE ... WHERE id=`` that no-ops (rowcount 0) on a vanished row instead of
raising. A MagicMock can never raise StaleDataError (same lesson as
core/tests/test_secret_delete_fk.py — "a mock session can never raise an FK
violation"), so this binds the real helper to a real SQLite session.

Both halves of the truth table: row present -> fields persisted; row absent ->
no exception, WARNING logged, rowcount 0 (the caller still returns the result).
"""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import Base, ExecutionSession, Executor, User
from server.routes.executors import _mark_execution_session_completed
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

RESULT = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0}


@pytest.fixture()
def session():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(User(user_id="u1", status="active"))
    s.add(Executor(id="exec-1", hostname="exec-1", status="active"))
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _seed_execution_session(s, sid="sess-1"):
    now = datetime.now(UTC)
    s.add(
        ExecutionSession(
            id=sid,
            user_id="u1",
            executor_id="exec-1",
            command="",
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )
    s.commit()


def test_row_present_is_updated(session):
    """Truth-table positive half: a live row gets the result persisted."""
    _seed_execution_session(session)
    _mark_execution_session_completed(session, "sess-1", "echo hi", datetime.now(UTC), RESULT)
    session.commit()
    row = session.query(ExecutionSession).filter(ExecutionSession.id == "sess-1").one()
    assert row.command == "echo hi"
    assert row.exit_code == 0
    assert row.stdout == "ok\n"
    assert row.stderr == ""
    assert row.completed_at is not None


def test_row_absent_noops_with_warning_not_staledataerror(session, caplog):
    """Truth-table negative half: a vanished row no-ops + warns, never raises.

    This is the StaleDataError class the ORM-flush path produced (captured verbatim
    from production in results-2026-09-20-1922). The bulk UPDATE matches 0 rows.
    """
    _seed_execution_session(session)
    # Simulate the cleanup race: the row is deleted out from under the in-flight execute.
    session.query(ExecutionSession).filter(ExecutionSession.id == "sess-1").delete()
    session.commit()

    with caplog.at_level(logging.WARNING, logger="venya.server"):
        _mark_execution_session_completed(session, "sess-1", "echo hi", datetime.now(UTC), RESULT)
        session.commit()  # must not raise StaleDataError

    assert any("vanished" in r.getMessage() for r in caplog.records), [r.getMessage() for r in caplog.records]
