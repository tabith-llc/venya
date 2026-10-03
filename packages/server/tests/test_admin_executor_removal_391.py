# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for admin executor-row removal — #391 arm (b) remove-implies-revoke.

Ruled design (ticket admin-executor-row-removal-missing #391, owner ruling
2026-10-03): single DELETE /admin/executors/{executor_id}; guards before any
write — unknown id 404; executor WITH execution-session history refused loud
(409, sessions are append-only audit evidence, never deleted or cascaded);
otherwise revoke the current record serial via the shared helper (reason
"Removed by admin"), explicitly delete executor_certs rows, delete the
executors row, audit event riding the same commit.

Real SQLite (precedent: test_executor_revocation_identity.py) — multi-table
state is the subject under test; mock DBs would pin the mocks, not the
semantics.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from core.iam.models import (
    AuditEvent,
    Base,
    ExecutionSession,
    Executor,
    ExecutorCert,
    ExecutorCertRevocation,
    User,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.dependencies import get_backend, get_current_user, require_admin
from server.revocation import executor_revocation_state
from server.routes import admin as admin_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ADMIN_USER = {"user_id": "admin-user"}


@pytest.fixture()
def env(tmp_path):
    """Real-SQLite app with the admin router; require_admin overridden."""
    engine = create_engine(f"sqlite:///{tmp_path / 'remove.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    seed = SessionLocal()
    seed.add(User(user_id=ADMIN_USER["user_id"], auth_mode="password"))
    seed.commit()
    seed.close()

    def _build(*, override_admin=True, caller=None):
        app = FastAPI()
        backend = MagicMock()
        backend.get_session.side_effect = lambda: SessionLocal()
        app.state.backend = backend
        app.dependency_overrides[get_backend] = lambda: backend
        user = caller if caller is not None else ADMIN_USER
        app.dependency_overrides[get_current_user] = lambda: user
        if override_admin:
            app.dependency_overrides[require_admin] = lambda: user
        app.include_router(admin_routes.router, prefix="/api/v1")
        return TestClient(app, raise_server_exceptions=False)

    yield SessionLocal, _build
    engine.dispose()


def _seed_executor(SessionLocal, executor_id="exec-a", revoked_at=None):
    s = SessionLocal()
    s.add(
        Executor(
            id=executor_id,
            hostname=executor_id,
            enrolled_at=datetime.now(UTC),
            revoked_at=revoked_at,
            status="active",
        )
    )
    s.commit()
    s.close()


def _seed_cert(SessionLocal, executor_id="exec-a", serial="0000000000001000"):
    s = SessionLocal()
    s.add(
        ExecutorCert(
            executor_id=executor_id,
            serial_number=serial,
            not_before=datetime.now(UTC),
            not_after=datetime.now(UTC) + timedelta(days=30),
            fingerprint="AA:BB:CC",
        )
    )
    s.commit()
    s.close()


def _seed_session(SessionLocal, executor_id="exec-a", session_id="sess-1"):
    s = SessionLocal()
    s.add(
        ExecutionSession(
            id=session_id,
            user_id=ADMIN_USER["user_id"],
            executor_id=executor_id,
            command="true",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            completed_at=datetime.now(UTC),
            exit_code=0,
        )
    )
    s.commit()
    s.close()


def _audit_rows(SessionLocal):
    s = SessionLocal()
    rows = s.query(AuditEvent).filter(AuditEvent.event_type == "executor_revoked").all()
    out = [(r.user_id, json.loads(r.fields)) for r in rows]
    s.close()
    return out


class TestRemovePositive:
    def test_remove_clears_row_and_certs_and_revokes_serial(self, env):
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client = build()

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"removed": True, "executor_id": "exec-a", "revoked_serial": "0000000000001000"}

        s = SessionLocal()
        assert s.query(Executor).filter(Executor.id == "exec-a").first() is None
        assert s.query(ExecutorCert).filter(ExecutorCert.executor_id == "exec-a").first() is None
        rev = s.query(ExecutorCertRevocation).filter(ExecutorCertRevocation.serial_number == "0000000000001000").one()
        assert rev.executor_id == "exec-a"
        assert rev.reason == "Removed by admin"
        s.close()
        assert _audit_rows(SessionLocal) == [
            (ADMIN_USER["user_id"], {"executor_id": "exec-a", "form": "remove", "already_revoked": False})
        ]

    def test_removed_id_not_terminal_for_reregistration(self, env):
        # Ruled lifecycle: re-registration of the same id after removal is
        # intended — the row-based terminal identity check dies with the row
        # and the record-serial pointer is gone with the cert rows.
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client = build()
        assert client.delete("/api/v1/admin/executors/exec-a").status_code == 200

        s = SessionLocal()
        state = executor_revocation_state(s, "exec-a")
        assert state.revoked is False
        assert state.reason != "identity"
        s.close()

    def test_remove_executor_without_cert_row_still_removes(self, env):
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        client = build()

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 200
        assert resp.json()["revoked_serial"] is None

        s = SessionLocal()
        assert s.query(Executor).count() == 0
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()


class TestRemoveNegatives:
    def test_unknown_id_404_zero_writes(self, env):
        SessionLocal, build = env
        _seed_executor(SessionLocal, "exec-a")
        _seed_cert(SessionLocal, "exec-a")
        client = build()

        resp = client.delete("/api/v1/admin/executors/ghost")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Executor not found: ghost"

        s = SessionLocal()
        assert s.query(Executor).count() == 1
        assert s.query(ExecutorCert).count() == 1
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()
        assert _audit_rows(SessionLocal) == []

    def test_sessions_retained_409_state_unchanged(self, env):
        # Paired negative demanded by the truth-table rule: sessions are
        # append-only audit evidence — removal refused, NOTHING written.
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        _seed_session(SessionLocal)
        client = build()

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 409
        assert "1 execution session(s) retained as audit evidence; removal refused" in resp.json()["detail"]

        s = SessionLocal()
        assert s.query(Executor).filter(Executor.id == "exec-a").one() is not None
        assert s.query(ExecutorCert).filter(ExecutorCert.executor_id == "exec-a").one() is not None
        assert s.query(ExecutionSession).count() == 1
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()
        assert _audit_rows(SessionLocal) == []

    def test_executor_caller_403(self, env):
        # Admin gate half 1 (require_admin denies mTLS executors outright).
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client = build(override_admin=False, caller={"caller": "executor", "executor_id": "exec-a"})

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 403

        s = SessionLocal()
        assert s.query(Executor).count() == 1
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()

    def test_human_non_admin_403(self, env):
        # Admin gate half 2: authenticated human without the admin role.
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client = build(override_admin=False, caller={"user_id": "mere-mortal"})

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 403

        s = SessionLocal()
        assert s.query(Executor).count() == 1
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()


class TestSharedHelperParity:
    def test_revoke_then_remove_removes_with_single_revocation_row(self, env):
        # T5: the revoke path and the removal path share the serial-revoke
        # helper — idempotent insert, no duplicate serial row.
        SessionLocal, build = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client = build()

        revoke = client.post("/api/v1/admin/executors/exec-a/revoke")
        assert revoke.status_code == 200

        resp = client.delete("/api/v1/admin/executors/exec-a")
        assert resp.status_code == 200

        s = SessionLocal()
        assert s.query(Executor).count() == 0
        assert s.query(ExecutorCert).count() == 0
        revs = s.query(ExecutorCertRevocation).filter(ExecutorCertRevocation.serial_number == "0000000000001000").all()
        assert len(revs) == 1  # the identity-form row survives; remove added no duplicate
        assert revs[0].reason == "Admin revocation"
        s.close()
        forms = [fields["form"] for _, fields in _audit_rows(SessionLocal)]
        assert forms == ["identity", "remove"]
        assert _audit_rows(SessionLocal)[1][1]["already_revoked"] is True
