# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Route-level truth-table tests for admin user/role deletion (#425).

DEFECT B: DELETE /admin/users/{id} on a user holding a WebAuthn credential +
role membership crashed server-side — the route cleaned memberships/sessions/
tokens but SQLAlchemy's delete-dependency machinery then tried to null-out
the NOT NULL webauthn_credentials.user_id (journal: do_executemany on the
user-delete cascade), and no CLI path could remove the user.

DEFECT A: DELETE /roles/{id} on a non-empty role surfaced the internal
blank-out assertion as a generic 400 instead of the dependency message.

Prior route tests used MagicMock sessions — a mock can never raise a
dependency violation, which is why this shipped. These cells bind the REAL
routes to a real SQLite session (PRAGMA foreign_keys=ON, StaticPool so the
TestClient thread shares the connection).
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import (
    Base,
    ElevationToken,
    EnrollmentToken,
    ExecutionSession,
    Executor,
    ExecutorCert,
    Role,
    RoleMember,
    Secret,
    SecretRole,
    Session,
    SessionSecret,
    User,
    WebAuthnCredential,
)
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db, require_admin
from server.routes import admin as admin_routes
from server.routes import roles as roles_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

ADMIN = {"user_id": "admin1"}


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    s.add(User(user_id="admin1", status="active"))
    s.add(User(user_id="rwsvc", status="active"))
    s.add(Executor(id="exec-1", hostname="exec-1", status="active"))
    s.commit()
    yield s
    s.close()
    engine.dispose()


@pytest.fixture()
def client(session):
    app = FastAPI()
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(roles_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[require_admin] = lambda: ADMIN
    app.dependency_overrides[get_db] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def _seed_credentialed_member(session):
    """rwsvc: role membership + WebAuthn credential + session + token (the #425 shape)."""
    role = Role(name="operator", permissions="read")
    session.add(role)
    session.flush()
    now = datetime.now(UTC)
    session.add_all(
        [
            RoleMember(user_id="rwsvc", role_id=role.id),
            WebAuthnCredential(user_id="rwsvc", credential_id=b"KEY_C", public_key=b"pk", label="key", created_at=now),
            Session(user_id="rwsvc", created_at=now, expires_at=now + timedelta(hours=1)),
            EnrollmentToken(user_id="rwsvc", token_hash="th", expires_at=now + timedelta(hours=1)),
            ElevationToken(user_id="rwsvc", token_hash="et", expires_at=now + timedelta(hours=1)),
            ExecutorCert(
                executor_id="rwsvc",
                serial_number="abc123",
                not_before=now,
                not_after=now + timedelta(days=1),
                fingerprint="fp",
                created_at=now,
            ),
        ]
    )
    session.commit()
    return role.id


def _counts(session):
    uid = "rwsvc"
    return {
        "users": session.query(User).filter(User.user_id == uid).count(),
        "memberships": session.query(RoleMember).filter(RoleMember.user_id == uid).count(),
        "credentials": session.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == uid).count(),
        "sessions": session.query(Session).filter(Session.user_id == uid).count(),
        "tokens": session.query(EnrollmentToken).filter(EnrollmentToken.user_id == uid).count(),
        "elevations": session.query(ElevationToken).filter(ElevationToken.user_id == uid).count(),
        "exec_certs": session.query(ExecutorCert).filter(ExecutorCert.executor_id == uid).count(),
    }


class TestAdminRemoveDependencyCascade:
    def test_remove_user_with_credential_and_membership_succeeds(self, client, session):
        """RED1: the #425 shape deletes cleanly — user gone, all dependents gone."""
        _seed_credentialed_member(session)

        resp = client.delete("/api/v1/admin/users/rwsvc")

        assert resp.status_code == 200, resp.text
        assert resp.json()["removed"] is True
        assert all(v == 0 for v in _counts(session).values()), _counts(session)

    def test_remove_user_with_secrets_and_execution_history_succeeds(self, client, session):
        """Same cascade machinery, wider graph: created secret (role-scoped,
        injected into an execution session) + execution session must go too —
        their join tables carry no DB-level cascade, so dependency order is
        pinned here."""
        _seed_credentialed_member(session)
        now = datetime.now(UTC)
        role = session.query(Role).one()
        secret = Secret(
            key="s1",
            encrypted_value=b"ct",
            nonce=b"n",
            wrapped_dek=b"d",
            key_version_id="v1",
            created_by="rwsvc",
        )
        session.add(secret)
        session.flush()
        exec_sess = ExecutionSession(user_id="rwsvc", executor_id="exec-1", expires_at=now + timedelta(minutes=10))
        session.add(exec_sess)
        session.flush()
        session.add_all(
            [
                SecretRole(secret_id=secret.id, role_id=role.id),
                SessionSecret(session_id=exec_sess.id, secret_id=secret.id, wrapped_value="w"),
            ]
        )
        session.commit()
        sid, esid = secret.id, exec_sess.id

        resp = client.delete("/api/v1/admin/users/rwsvc")

        assert resp.status_code == 200, resp.text
        assert session.get(Secret, sid) is None
        assert session.get(ExecutionSession, esid) is None
        assert session.query(SecretRole).filter(SecretRole.secret_id == sid).count() == 0
        assert session.query(SessionSecret).filter(SessionSecret.session_id == esid).count() == 0
        # The role itself survives its scope row.
        assert session.query(Role).filter(Role.id == role.id).count() == 1

    def test_remove_plain_user_still_succeeds(self, client, session):
        """Negative (truth table): unadorned users keep deleting fine."""
        session.add(User(user_id="plainjane", status="active"))
        session.commit()

        resp = client.delete("/api/v1/admin/users/plainjane")

        assert resp.status_code == 200, resp.text
        assert session.query(User).filter(User.user_id == "plainjane").count() == 0

    def test_remove_user_after_membership_and_credential_removal_succeeds(self, client, session):
        """Negative: last-member removed, credential gone -> user delete works (the manual workaround path stays open)."""
        _seed_credentialed_member(session)
        session.query(RoleMember).filter(RoleMember.user_id == "rwsvc").delete()
        session.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == "rwsvc").delete()
        session.commit()

        resp = client.delete("/api/v1/admin/users/rwsvc")

        assert resp.status_code == 200, resp.text
        assert session.query(User).filter(User.user_id == "rwsvc").count() == 0


class TestRoleDeleteDependencyMessage:
    def test_delete_nonempty_role_returns_dependency_message(self, client, session):
        """RED2 route half: 400 carries the human dependency message, not the
        generic 'Role deletion failed' assertion wrapper."""
        rid = _seed_credentialed_member(session)

        resp = client.delete(f"/api/v1/roles/{rid}")

        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "member" in detail.lower(), detail
        assert "assertion" not in detail.lower()

    def test_delete_empty_role_still_succeeds(self, client, session):
        """Negative: the empty-role delete path keeps working end to end."""
        role = Role(name="unused", permissions="read")
        session.add(role)
        session.commit()

        resp = client.delete(f"/api/v1/roles/{role.id}")

        assert resp.status_code == 200, resp.text
        assert resp.json()["deleted"] is True
        assert session.query(Role).filter(Role.id == role.id).count() == 0
