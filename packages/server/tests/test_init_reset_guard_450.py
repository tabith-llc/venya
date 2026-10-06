# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for POST /api/v1/init/reset (#450).

Before this fix the route sat in the middleware's PUBLIC_PATHS set and its one
guard counted users that ALSO had a WebAuthn credential row (INNER JOIN). An
enrolled user with no credential row — exactly what the break-glass flow
commits in routes/recovery.py — counted as zero, so an anonymous caller could
delete every user, credential, role and membership on the core.

These cells bind the REAL route and the REAL SessionMiddleware to a real
SQLite database (PRAGMA foreign_keys=ON, file-backed so the TestClient thread
shares it) and drive requests the way production does. Nothing is injected
through dependency_overrides: every identity here is one the middleware can
actually produce, and every refusal is asserted on both halves — the state
that must be refused, plus the rows that must survive it.
"""

import json
from datetime import UTC, datetime, timedelta

from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import (
    AuditEvent,
    Base,
    EnrollmentToken,
    Role,
    RoleMember,
    User,
    WebAuthnCredential,
)
from core.iam.models import (
    Session as SessionModel,
)
from fastapi import FastAPI
from server.config import ServerConfig
from server.middleware.auth import SessionMiddleware
from server.routes import init as init_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

ADMIN_BEARER = "bearer-admin-450"
PLAIN_BEARER = "bearer-plain-450"
RESET = "/api/v1/init/reset"


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite.

    SQLite has no timestamptz (the model's timezone=True is a PG-only flag), so
    the middleware's aware-now expiry comparison TypeErrors on round-tripped
    naive rows. Production (PostgreSQL) returns aware values, where this
    listener changes nothing. Same shape as the #340 real-stack helper.
    """
    from sqlalchemy import event

    if getattr(SessionModel, "_reset450_utc_loader", False):
        return
    SessionModel._reset450_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _stack(tmp_path, seed):
    """Real middleware + real init routes + real SQLite, seeded by ``seed``."""
    _sqlite_utc_loader()
    db_path = tmp_path / "reset450.db"
    engine = create_engine(f"sqlite:///{db_path}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    s = SessionLocal()
    seed(s)
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-unused")
    app.state.backend = backend
    app.include_router(init_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), SessionLocal


# --- seeders (each one a state the field can actually be in) ---


def _seed_empty(session):
    """A core nobody has initialized yet."""


def _seed_recovery_admin(session):
    """The #450 shape: an admin with enrolled_at set and NO credential row.

    routes/recovery.py commits exactly this when break-glass mints the
    replacement admin; the credential arrives in a later ceremony.
    """
    now = datetime.now(UTC)
    admin_role = Role(name="admin", permissions="read-write")
    user_role = Role(name="user", permissions="read")
    session.add_all([admin_role, user_role])
    session.flush()
    session.add_all(
        [
            User(user_id="breakglass-admin", auth_mode="security-key", status="active", enrolled_at=now),
        ]
    )
    session.flush()
    session.add(RoleMember(user_id="breakglass-admin", role_id=admin_role.id))
    session.commit()


def _seed_pending_enrollment(session):
    """init step 1 ran and the ceremony never completed (Finding B residue)."""
    admin_role = Role(name="admin", permissions="read-write")
    user_role = Role(name="user", permissions="read")
    session.add_all([admin_role, user_role])
    session.flush()
    session.add(User(user_id="pending-admin", auth_mode="security-key", status="pending_enrollment"))
    session.flush()
    session.add(RoleMember(user_id="pending-admin", role_id=admin_role.id))
    session.commit()


def _seed_enrolled(session, bearer=None, admin=True, credential=True):
    """A fully initialized core: enrolled admin, optional credential row, live session."""
    now = datetime.now(UTC)
    admin_role = Role(name="admin", permissions="read-write")
    user_role = Role(name="user", permissions="read")
    session.add_all([admin_role, user_role])
    session.flush()
    session.add(
        User(
            user_id="admin-450",
            auth_mode="webauthn",
            status="active",
            enrolled_at=now,
        )
    )
    session.flush()
    session.add(RoleMember(user_id="admin-450", role_id=admin_role.id if admin else user_role.id))
    if credential:
        session.add(
            WebAuthnCredential(
                user_id="admin-450",
                credential_id=b"CRED-450",
                public_key=b"pk",
                label="key",
                created_at=now,
            )
        )
    if bearer is not None:
        session.add(
            SessionModel(
                user_id="admin-450",
                access_token=bearer,
                access_token_jti=f"jti-{bearer}",
                created_at=now,
                expires_at=now + timedelta(minutes=15),
                access_token_expires_at=now + timedelta(minutes=5),
            )
        )
    session.commit()


def _seed_retired_credential(session):
    """A credential row that was retired, not deleted (credentials.py posture)."""
    now = datetime.now(UTC)
    session.add(User(user_id="retired-450", status="active"))
    session.flush()
    session.add(
        WebAuthnCredential(
            user_id="retired-450",
            credential_id=b"RETIRED-450",
            public_key=b"pk",
            label="retired key",
            is_active=False,
            created_at=now,
        )
    )
    session.commit()


def _audit_rows(session):
    return session.query(AuditEvent).all()


def _fields(event):
    return json.loads(event.fields) if isinstance(event.fields, str) else (event.fields or {})


# --- AC1: the route is no longer public ---


class TestRouteIsNotPublic:
    def test_reset_path_left_the_public_set(self):
        """/api/v1/init/reset is no longer waved through by the middleware."""
        assert "/api/v1/init/reset" not in SessionMiddleware.PUBLIC_PATHS
        # ...and it is on the bootstrap plane, where identity is attached when
        # offered and the handler decides (not an auth exemption).
        assert "/api/v1/init/reset" in SessionMiddleware.BOOTSTRAP_PATHS

    def test_anonymous_reset_on_initialized_core_is_refused(self, tmp_path):
        """The physical hole, at the HTTP layer: anonymous POST -> 401, nothing deleted."""
        client, SessionLocal = _stack(tmp_path, _seed_enrolled)

        resp = client.post(RESET)

        assert resp.status_code == 401, resp.text
        s = SessionLocal()
        try:
            assert s.query(User).count() == 1
            assert s.query(Role).count() == 2
            assert s.query(WebAuthnCredential).count() == 1
        finally:
            s.close()


# --- AC2 + AC3: the guard counts the right set, both halves ---


class TestInitializedPredicate:
    def test_recovery_shaped_admin_refuses_reset(self, tmp_path):
        """REGRESSION: enrolled_at set, ZERO credential rows -> REFUSED.

        The pre-fix INNER-JOIN guard saw zero fully-enrolled users here and
        wiped the core.
        """
        client, SessionLocal = _stack(tmp_path, _seed_recovery_admin)

        resp = client.post(RESET)

        assert resp.status_code == 401, resp.text
        s = SessionLocal()
        try:
            assert s.query(User).filter(User.user_id == "breakglass-admin").count() == 1
            assert s.query(Role).filter(Role.name == "admin").count() == 1
            assert s.query(RoleMember).count() == 1
        finally:
            s.close()

    def test_retired_credential_row_refuses_reset(self, tmp_path):
        """A retired (is_active=False) credential row still means initialized."""
        client, SessionLocal = _stack(tmp_path, _seed_retired_credential)

        resp = client.post(RESET)

        assert resp.status_code == 401, resp.text
        s = SessionLocal()
        try:
            assert s.query(WebAuthnCredential).count() == 1
        finally:
            s.close()

    def test_empty_core_still_permits_reset(self, tmp_path):
        """Bootstrap half: a truly empty core stays resettable, unauthenticated.

        This is the `venya init --installation-reset` window — no admin exists
        yet, so no identity can be required.
        """
        client, _ = _stack(tmp_path, _seed_empty)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        assert resp.json() == {"success": True, "message": "Core reset to pre-initialization state."}

    def test_pending_enrollment_stays_resettable(self, tmp_path):
        """Finding B posture kept: an abandoned PENDING admin is still resettable."""
        client, SessionLocal = _stack(tmp_path, _seed_pending_enrollment)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        s = SessionLocal()
        try:
            assert s.query(User).filter(User.user_id == "pending-admin").count() == 0
        finally:
            s.close()

    def test_predicate_reads_the_two_sets_directly(self, tmp_path):
        """deployment_is_initialized() answers per set, without a JOIN."""
        from server.routes.init import deployment_is_initialized

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        s = factory()
        try:
            assert deployment_is_initialized(s) is False
            now = datetime.now(UTC)
            s.add(User(user_id="enrolled-no-cred", enrolled_at=now))
            s.commit()
            assert deployment_is_initialized(s) is True
            s.query(User).delete()
            s.commit()
            assert deployment_is_initialized(s) is False
            s.add(User(user_id="u", status="active"))
            s.flush()
            s.add(
                WebAuthnCredential(user_id="u", credential_id=b"x", public_key=b"pk", created_at=now, is_active=False)
            )
            s.commit()
            assert deployment_is_initialized(s) is True
        finally:
            s.close()
            engine.dispose()


# --- AC1/AC3 negative half: an authenticated caller who is not an admin ---


class TestNonAdminRefused:
    def test_authenticated_non_admin_refused(self, tmp_path):
        """A live session that holds no admin role gets 403, and nothing is deleted."""
        client, SessionLocal = _stack(
            tmp_path,
            lambda s: _seed_enrolled(s, bearer=PLAIN_BEARER, admin=False),
        )

        resp = client.post(RESET, headers={"Authorization": f"Bearer {PLAIN_BEARER}"})

        assert resp.status_code == 403, resp.text
        s = SessionLocal()
        try:
            assert s.query(User).count() == 1
            assert s.query(RoleMember).count() == 1
        finally:
            s.close()


# --- admin authority does reset, and the wipe is audited (AC4) ---


class TestAdminReset:
    def test_admin_reset_wipes_and_audits(self, tmp_path):
        client, SessionLocal = _stack(
            tmp_path,
            lambda s: _seed_enrolled(s, bearer=ADMIN_BEARER, admin=True),
        )
        s = SessionLocal()
        s.add(EnrollmentToken(user_id="admin-450", token_hash="th", expires_at=datetime.now(UTC)))
        s.commit()
        s.close()

        resp = client.post(RESET, headers={"Authorization": f"Bearer {ADMIN_BEARER}"})

        assert resp.status_code == 200, resp.text
        s = SessionLocal()
        try:
            assert s.query(User).filter(User.user_id != "system").count() == 0
            assert s.query(Role).filter(Role.name.in_(["admin", "user"])).count() == 0
            assert s.query(RoleMember).count() == 0
            assert s.query(WebAuthnCredential).count() == 0
            assert s.query(EnrollmentToken).count() == 0
            # no live token outlives its principal
            assert s.query(SessionModel).count() == 0

            events = _audit_rows(s)
            deleted = [e for e in events if e.event_type == "user_deleted"]
            roles = [e for e in events if e.event_type == "role_deleted"]
            assert len(deleted) == 1
            assert {e.user_id for e in events} == {"admin-450"}  # the actor, named
            assert _fields(deleted[0])["target_user_id"] == "admin-450"
            assert _fields(deleted[0])["credentials_removed"] == 1
            assert _fields(deleted[0])["memberships_removed"] == 1
            assert _fields(deleted[0])["tokens_revoked"] == 1
            assert _fields(deleted[0])["sessions_revoked"] == 1
            assert {e.event_type for e in roles} == {"role_deleted"}
            assert sorted(_fields(r)["role_name"] for r in roles) == ["admin", "user"]
        finally:
            s.close()

    def test_bootstrap_reset_writes_no_lifecycle_events(self, tmp_path):
        """An empty core has no accounts and no roles to report — no rows invented."""
        client, SessionLocal = _stack(tmp_path, _seed_empty)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        s = SessionLocal()
        try:
            assert _audit_rows(s) == []
        finally:
            s.close()


# --- the bootstrap branch itself: identity is attached, not assumed ---


class TestBootstrapMiddlewareBranch:
    def test_valid_session_is_attached_as_the_caller(self, tmp_path):
        """A bearer token on this path is really validated: a bad one dies 401."""
        client, _ = _stack(tmp_path, _seed_enrolled)

        resp = client.post(RESET, headers={"Authorization": "Bearer not-a-real-session"})

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == "Invalid or expired token"

    def test_route_carries_an_admin_guard(self):
        """The route-coverage net no longer needs /api/v1/init/reset allowlisted."""
        from fastapi.routing import APIRoute
        from server.routes.init import require_admin_when_initialized

        assert require_admin_when_initialized._venya_guard == "admin"
        route = next(r for r in init_routes.router.routes if isinstance(r, APIRoute) and r.path == "/init/reset")

        def guards(dependants):
            found = []
            for d in dependants:
                marker = getattr(d.call, "_venya_guard", None)
                if marker:
                    found.append(marker)
                found.extend(guards(d.dependencies))
            return found

        assert "admin" in guards(route.dependant.dependencies)
