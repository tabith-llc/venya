# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Limited Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#411 truth table — revoke_session_secrets makes the revocation REAL.

Ruled shape (b): POST /sessions/{id}/secrets/revoke must STOP the session's
secrets resolving at call time (not just write audit and schedule the TTL
purge). Zero mocks over the DB: real SQLite, real rows, the endpoint under
test, and the SAME reader predicates the two live fetch paths use
(routes/executors.py execute-relay and routes/filter.py stage-2 masking) —
a green cell here means the reader itself sees nothing, not a mock's answer.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import (
    AuditEvent,
    Base,
    ExecutionSession,
    Executor,
    Secret,
    SessionSecret,
    User,
)
from fastapi import FastAPI
from server.dependencies import get_db
from server.maintenance import cleanup_expired_execution_sessions
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

SESSION_A = "sess-A"
SESSION_B = "sess-B"
WRAPPED_A = "[VENYA:aaaaaaaa]QUFSQVE=[/VENYA]"
WRAPPED_B = "[VENYA:bbbbbbbb]QJ9zZWNyZXQ=[/VENYA]"


def _build_revoke_env(tmp_path):
    """Real SQLite dataset: two sessions, one bound secret row each.

    Returns (client, SessionLocal, secret_id). Executor mTLS identity is set
    by middleware (the endpoint's own gate reads request.state.auth_user).
    """
    from starlette.middleware.base import BaseHTTPMiddleware

    db_path = tmp_path / "revoke411.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    now = datetime.now(UTC)
    s = SessionLocal()
    s.add_all(
        [
            User(user_id="u1"),
            Executor(id="exec1", hostname="192.0.2.14", status="active"),
            Secret(
                id=77,
                key="db-password",
                encrypted_value=b"x",
                nonce=b"n",
                wrapped_dek=b"w",
                key_version_id="v1",
                created_by="u1",
            ),
            ExecutionSession(
                id=SESSION_A,
                user_id="u1",
                executor_id="exec1",
                command="",
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            ),
            ExecutionSession(
                id=SESSION_B,
                user_id="u1",
                executor_id="exec1",
                command="",
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            ),
        ]
    )
    s.add_all(
        [
            SessionSecret(session_id=SESSION_A, secret_id=77, wrapped_value=WRAPPED_A),
            SessionSecret(session_id=SESSION_B, secret_id=77, wrapped_value=WRAPPED_B),
        ]
    )
    s.commit()
    s.close()

    app = FastAPI()
    app.include_router(secrets_routes.router, prefix="/api/v1")
    # Each request gets its own session (mirrors get_db's per-request lifecycle).
    app.dependency_overrides[get_db] = lambda: SessionLocal()

    class ExecutorAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": "exec1"}
            return await call_next(request)

    app.add_middleware(ExecutorAuthMiddleware)
    return TestClient(app, raise_server_exceptions=False), SessionLocal


def _revoke(client, session_id, secret_ids):
    return client.post(
        f"/api/v1/sessions/{session_id}/secrets/revoke",
        json={"secret_ids": secret_ids},
    )


def _reader_rows(SessionLocal, session_id):
    """The execute-relay / stage-2-filter reader predicate, verbatim shape.

    routes/executors.py:1310 and routes/filter.py:247 both query
    ``SessionSecret.session_id == <the session>`` — if this returns rows, the
    revoked values still resolve.
    """
    s = SessionLocal()
    try:
        return s.query(SessionSecret).filter(SessionSecret.session_id == session_id).all()
    finally:
        s.close()


class TestRevokeStopsResolution:
    def test_revoke_removes_rows_reader_sees_nothing_and_audit_written(self, tmp_path):
        """Positive half: after revoke the reader query returns NOTHING, the
        wrapped value is gone, audit events are still written, count honest."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        resp = _revoke(client, SESSION_A, ["77"])
        assert resp.status_code == 200
        body = resp.json()
        assert body["revoked"] is True
        assert body["count"] == 1  # honest: one row actually removed

        assert _reader_rows(SessionLocal, SESSION_A) == []

        s = SessionLocal()
        try:
            audits = s.query(AuditEvent).filter(AuditEvent.event_type == "credential_revoked").all()
            assert len(audits) == 1
            fields = json.loads(audits[0].fields)
            assert fields == {"session_id": SESSION_A, "secret_id": "77"}
            assert audits[0].user_id == "exec1"
        finally:
            s.close()

    def test_non_revoked_session_still_resolves(self, tmp_path):
        """Regression half (scope guard): revoking A must not touch B — B's
        reader query stays green with the ORIGINAL wrapped value."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        assert _revoke(client, SESSION_A, ["77"]).status_code == 200

        rows = _reader_rows(SessionLocal, SESSION_B)
        assert [r.wrapped_value for r in rows] == [WRAPPED_B]

    def test_sql_predicate_truth_table_session_scoped(self, tmp_path):
        """Predicate truth table: same secret id bound to two sessions — revoke
        by session A removes ONLY A's row (the session_id term is in the WHERE)."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        _revoke(client, SESSION_A, ["77"])

        s = SessionLocal()
        try:
            a = s.query(SessionSecret).filter(SessionSecret.session_id == SESSION_A).count()
            b = s.query(SessionSecret).filter(SessionSecret.session_id == SESSION_B).count()
        finally:
            s.close()
        assert (a, b) == (0, 1)


class TestRevokeIdempotent:
    def test_revoke_twice_second_response_is_honest(self, tmp_path):
        """Paired negative: rows already gone -> revoked=True (the state IS
        revoked) but count=0 — no vacuous 'removed 2 again'."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        first = _revoke(client, SESSION_A, ["77"])
        assert first.json()["count"] == 1

        second = _revoke(client, SESSION_A, ["77"])
        assert second.status_code == 200
        assert second.json() == {"revoked": True, "count": 0, "session_id": SESSION_A}
        assert _reader_rows(SessionLocal, SESSION_A) == []

    def test_revoke_after_ttl_purge_no_crash_honest_result(self, tmp_path):
        """Backstop coexistence: the maintenance purge already deleted the rows
        (session expired) -> revoke answers 200/count=0, no crash, audit stays."""
        client, SessionLocal = _build_revoke_env(tmp_path)

        # Expire session A and run the REAL purge pass.
        s = SessionLocal()
        try:
            row = s.query(ExecutionSession).filter(ExecutionSession.id == SESSION_A).first()
            row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
            s.commit()
        finally:
            s.close()
        assert cleanup_expired_execution_sessions(SessionLocal()) >= 1
        assert _reader_rows(SessionLocal, SESSION_A) == []

        resp = _revoke(client, SESSION_A, ["77"])
        assert resp.status_code == 200
        assert resp.json() == {"revoked": True, "count": 0, "session_id": SESSION_A}


class TestRevokeIdNormalization:
    def test_non_numeric_id_cannot_delete_anything_but_is_audited(self, tmp_path):
        """Wire carries strings (executor str()-casts, daemon reaper dir names).
        A non-numeric id matches no Integer row: the DELETE must remove nothing
        (paired negative — no implicit cast matching), audit still records it."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        resp = _revoke(client, SESSION_A, ["sec-1"])
        assert resp.status_code == 200
        assert resp.json()["count"] == 0
        # The real row survives — a junk id must not blank a valid binding.
        assert [r.wrapped_value for r in _reader_rows(SessionLocal, SESSION_A)] == [WRAPPED_A]

        s = SessionLocal()
        try:
            audits = s.query(AuditEvent).filter(AuditEvent.event_type == "credential_revoked").all()
            assert len(audits) == 1
            assert json.loads(audits[0].fields)["secret_id"] == "sec-1"
        finally:
            s.close()

    def test_mixed_ids_delete_only_the_numeric_match(self, tmp_path):
        """Truth table on the id list: real id + junk id -> count=1 (only the
        Integer match removed), junk id audited, session B untouched."""
        client, SessionLocal = _build_revoke_env(tmp_path)
        resp = _revoke(client, SESSION_A, ["77", "junk-9"])
        assert resp.json()["count"] == 1
        assert _reader_rows(SessionLocal, SESSION_A) == []
        assert [r.wrapped_value for r in _reader_rows(SessionLocal, SESSION_B)] == [WRAPPED_B]

        s = SessionLocal()
        try:
            audits = s.query(AuditEvent).filter(AuditEvent.event_type == "credential_revoked").all()
            assert {json.loads(a.fields)["secret_id"] for a in audits} == {"77", "junk-9"}
        finally:
            s.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
