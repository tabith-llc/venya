# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for break-glass recovery endpoint."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import recovery as recovery_routes
from starlette.testclient import TestClient


def _create_test_app(backend=None, pepper="test-pepper"):
    """Create a minimal test app with recovery route."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend

    config = SimpleNamespace(recovery_code_pepper=pepper)
    app.state.config = config

    app.include_router(recovery_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            # Re-raise HTTPException so FastAPI handles it properly
            if hasattr(request.state, "http_exception"):
                raise request.state.http_exception
            return response

    app.add_middleware(AuthMiddleware)
    return app


class TestRecovery:
    """Tests for break-glass recovery endpoint."""

    def test_recovery_success(self):
        """POST /recovery should create new admin user with valid code."""
        import hashlib

        pepper = "test-pepper"
        code = "recovery-123"
        code_hash = hashlib.sha256((pepper + code).encode()).hexdigest()

        admin_user = SimpleNamespace(
            user_id="oldadmin",
            recovery_code_hash=code_hash,
        )
        admin_role = SimpleNamespace(id=1, name="admin")

        class MockQuery:
            def __init__(self):
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *args, **kwargs):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return admin_user
                elif self._call_count == 2:
                    return None
                return admin_role

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": code,
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["action"] == "new_admin"
        assert data["user_id"] == "newadmin"
        assert db.add.called

    def test_recovery_invalid_code(self):
        """POST /recovery should return 401 with invalid code."""
        db = MagicMock()

        class MockQuery:
            def __init__(self):
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *args, **kwargs):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return  # No matching user
                return

        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": "wrong-code",
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 401
        assert "Invalid recovery code" in resp.json()["detail"]

    def test_recovery_undeclared_body_key_422(self):
        """Paired negative for the #371 re-sweep: the #357 exemption of this
        model existed ONLY while shipped CLIs leaked --force/--confirm into
        the body; #367 made the client send just the declared fields, so the
        condition is discharged and an undeclared key must now be a loud 422
        (never the silent-drop again). Validation-layer reject — the handler
        (and any code/hash check) never runs, hence empty mocks."""
        backend = MagicMock()
        app = _create_test_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={"code": "c", "new_user_id": "newadmin", "force": True},
        )
        assert resp.status_code == 422
        assert resp.json()["detail"][0]["type"] == "extra_forbidden"

    def test_recovery_user_exists(self):
        """POST /recovery should return 400 if user already exists."""
        import hashlib

        pepper = "test-pepper"
        code = "recovery-123"
        code_hash = hashlib.sha256((pepper + code).encode()).hexdigest()

        admin_user = SimpleNamespace(
            user_id="oldadmin",
            recovery_code_hash=code_hash,
        )
        existing_user = SimpleNamespace(user_id="existing")

        class MockQuery:
            def __init__(self):
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *args, **kwargs):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return admin_user
                return existing_user

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": code,
                "new_user_id": "existing",
            },
        )
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]

    def test_recovery_no_backend(self):
        """POST /recovery should return 503 if backend not initialized."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": "recovery-123",
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 503

    def test_recovery_with_admin_role(self):
        """POST /recovery should add admin role if it exists."""
        import hashlib

        pepper = "test-pepper"
        code = "recovery-123"
        code_hash = hashlib.sha256((pepper + code).encode()).hexdigest()
        admin_role = SimpleNamespace(id=1, name="admin")

        admin_user = SimpleNamespace(
            user_id="oldadmin",
            recovery_code_hash=code_hash,
        )

        class MockQuery:
            def __init__(self):
                self._call_count = 0

            def filter(self, *args, **kwargs):
                return self

            def join(self, *args, **kwargs):
                return self

            def first(self):
                self._call_count += 1
                if self._call_count == 1:
                    return admin_user
                elif self._call_count == 2:
                    return None
                return admin_role

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": code,
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 200
        assert db.add.call_count >= 2  # User + RoleMember


def _build_real_app(tmp_path, pepper="test-pepper"):
    """Real Backend over SQLite — zero mocks in the burn path.

    Backend._create_engine is bypassed (PostgreSQL-only SET pragmas break
    SQLite); the real engine + session factory are injected instead (same
    pattern as test_key_rotation/test_secrets real-DB suites).
    """
    import hashlib

    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE
    from core.iam.models import Base, Role, RoleMember, User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_path = tmp_path / "recovery.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    code = "ABCDEF-GHIJKL"
    code_hash = hashlib.sha256((pepper + code).encode()).hexdigest()
    s = SessionLocal()
    admin_role = Role(name="admin", permissions="read-write")
    old_admin = User(user_id="oldadmin", recovery_code_hash=code_hash)
    s.add_all([admin_role, old_admin])
    s.flush()
    s.add(RoleMember(user_id="oldadmin", role_id=admin_role.id))
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal
    app = _create_test_app(backend=backend, pepper=pepper)
    return TestClient(app, raise_server_exceptions=False), SessionLocal, code


class TestRecoveryBurnRealDB:
    """Burn-on-use truth table (finding 1, ticket test-recovery-admin-enrollment-key).

    The route's docstring always claimed single-use; the burn was never
    implemented — the same code minted admins forever. Real DB, because
    mock-backed suites cannot observe persistence semantics (the miss
    mechanism behind three prior DB-semantics defects).
    """

    def test_recovery_burns_code_single_use(self, tmp_path):
        from core.iam.models import RoleMember, User

        client, SessionLocal, code = _build_real_app(tmp_path)
        resp = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "newadmin"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["success"] is True

        with SessionLocal() as s:
            old = s.query(User).filter(User.user_id == "oldadmin").one()
            assert old.recovery_code_hash is None, "code not burned — reuse would mint another admin"
            new = s.query(User).filter(User.user_id == "newadmin").one()
            assert new.recovery_code_hash is None  # re-issuance is separate scope
            assert s.query(RoleMember).filter(RoleMember.user_id == "newadmin").count() == 1

        # Paired negative: reuse of the burned code is rejected like any invalid
        # code, and mints nothing.
        reuse = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "newadmin2"})
        assert reuse.status_code == 401
        assert reuse.json()["detail"] == "Invalid recovery code"
        with SessionLocal() as s:
            assert s.query(User).count() == 2

    def test_failed_recovery_does_not_burn(self, tmp_path):
        """Guards run BEFORE the burn: a 400 (user exists) must not consume
        the code — the operator needs it for the retry."""
        from core.iam.models import User

        client, SessionLocal, code = _build_real_app(tmp_path)
        clash = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "oldadmin"})
        assert clash.status_code == 400
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is not None
        retry = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "fresh"})
        assert retry.status_code == 200

    def test_wrong_code_rejected_and_code_survives(self, tmp_path):
        """Paired negative first: a wrong code burns nothing; the real code
        still works afterwards.

        The IDs here are legal shapes: #517 put the admin-surface grammar on
        ``new_user_id``, and this cell is about code semantics, so a shape the
        request model would refuse (the single character it used to carry) now
        answers 422 before the handler and never reaches the burn path.
        """
        from core.iam.models import User

        client, SessionLocal, code = _build_real_app(tmp_path)
        bad = client.post("/api/v1/recovery", json={"code": "WRONG-CODE", "new_user_id": "xy"})
        assert bad.status_code == 401
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is not None
        good = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "xy"})
        assert good.status_code == 200


# ---------------------------------------------------------------------------
# Recovery-code REISSUE — POST /api/v1/admin/recovery-code/reissue (#296)
# ---------------------------------------------------------------------------

REISSUE_PATH = "/api/v1/admin/recovery-code/reissue"


def _assert_code_shape(code):
    import re

    assert re.fullmatch(r"[0-9A-Za-z]{6}(-[0-9A-Za-z]{6}){7}", code), f"malformed code: {code!r}"


def _seed_token(SessionLocal, token: str, user_id: str, *, used=False, valid=True):
    """Seed a real ElevationToken row (hashed per the server's consume math).
    Invalid tokens sit 300 s past expiry — clear of the 60 s skew tolerance."""
    import hashlib
    from datetime import UTC, datetime, timedelta

    from core.iam.models import ElevationToken

    s = SessionLocal()
    s.add(
        ElevationToken(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            user_id=user_id,
            used=used,
            expires_at=datetime.now(UTC) + (timedelta(seconds=60) if valid else timedelta(seconds=-300)),
        )
    )
    s.commit()
    s.close()
    return token


def _build_reissue_app(tmp_path, pepper="test-pepper", session=None):
    """Real Backend over SQLite + REAL SessionMiddleware with admin-mTLS
    ENABLED (the #340 rework — the old plant injected a session dict through
    a get_current_user override, an identity production cannot produce on
    this path when admin-mTLS is enabled). `session={"user_id": X}` now
    seeds a REAL Session row and default-authenticates the client as X's
    bearer; with admin-mTLS enabled every mint here is a genuine
    dual-credential call (cert forwarded through the #314 extfile harness).
    Zero-mock doctrine per TestRecoveryBurnRealDB unchanged."""
    import hashlib
    import os

    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE
    from core.iam.models import Base, Role, RoleMember, User
    from fastapi import FastAPI
    from server.config import AdminMTLSConfig, ServerConfig
    from server.middleware.auth import SessionMiddleware
    from server.routes import admin as admin_routes
    from server.routes import recovery as recovery_routes
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from starlette.testclient import TestClient

    try:
        from .conftest import forwarded_headers, inner_tls_config, make_cert_prefix
    except ImportError:
        from conftest import forwarded_headers, inner_tls_config, make_cert_prefix

    prefix = make_cert_prefix(tmp_path)
    _old_pp = os.environ.get("VENYA_ADMIN_CA_KEY_PASSPHRASE")
    _ca_dir, leaf = _r340_ca_and_leaf(tmp_path)
    if _old_pp is None:
        os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)
    else:
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = _old_pp

    db_path = tmp_path / "reissue.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    _sqlite_utc_loader()
    SessionLocal = sessionmaker(bind=engine)

    initial_hash = hashlib.sha256((pepper + "OLD-CODE").encode()).hexdigest()
    s = SessionLocal()
    admin_role = Role(name="admin", permissions="read-write")
    read_role = Role(name="read", permissions="read")
    audit_role = Role(name="compliance-auditor", permissions="auditor")
    s.add_all(
        [
            admin_role,
            read_role,
            audit_role,
            User(user_id="admin-user", status="active", recovery_code_hash=initial_hash),
            User(user_id="plain-user", status="active", recovery_code_hash=initial_hash),
            User(user_id="admin-nohash", status="active", recovery_code_hash=None),
            User(user_id="auditor-user", status="active", recovery_code_hash=initial_hash),
        ]
    )
    s.flush()
    members = [
        RoleMember(user_id="admin-user", role_id=admin_role.id),
        RoleMember(user_id="admin-nohash", role_id=admin_role.id),
        RoleMember(user_id="auditor-user", role_id=audit_role.id),
    ]
    session_user = (session or {}).get("user_id")
    if session_user is not None:
        # Real Session row — the bearer shape _validate_token actually reads.
        from datetime import UTC, datetime, timedelta

        from core.iam.models import Session as SessionModel

        members.append(
            SessionModel(
                user_id=session_user,
                access_token=f"bearer-{session_user}",
                access_token_jti=f"jti-{session_user}",
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
                # #342: fresh bearer-tier expiry (gate rejects NULL/aged).
                access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
    s.add_all(members)
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=True,
            ca_cert=str(_ca_dir / "admin-ca.crt"),
            known_admin_ids=["admin@example.com"],
        ),
        inner_mtls=inner_tls_config(prefix),
        recovery_code_pepper=pepper,
    )
    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.backend = backend
    app.state.config = config
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(recovery_routes.router, prefix="/api/v1")
    default_headers = forwarded_headers(prefix, leaf)
    if session_user is not None:
        default_headers["Authorization"] = f"Bearer bearer-{session_user}"
    return TestClient(app, raise_server_exceptions=False, headers=default_headers), SessionLocal, initial_hash


class TestRecoveryCodeReissue:
    """#296 A3 truth table. NEW-SURFACE CELLS: every cell is RED
    pre-implementation as a route-absent 404 (nothing exists yet to
    misbehave) — stated, not faked as defect-REDs."""

    def test_p1_reissue_replaces_hash_returns_code_once_and_audits(self, tmp_path):
        import hashlib

        from core.iam.models import AuditEvent, ElevationToken, User

        client, SessionLocal, initial = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        token = _seed_token(SessionLocal, "elev-p1", "admin-user")

        resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": token})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["user_id"] == "admin-user"
        code = body["recovery_code"]
        _assert_code_shape(code)

        with SessionLocal() as s:
            u = s.query(User).filter(User.user_id == "admin-user").one()
            assert u.recovery_code_hash == hashlib.sha256(("test-pepper" + code).encode()).hexdigest()
            assert u.recovery_code_hash != initial, "old hash survived — not replaced"

            events = s.query(AuditEvent).filter(AuditEvent.event_type == "recovery_code_reissued").all()
            assert len(events) == 1
            assert code not in str(events[0].fields), "audit row carries code material — BANNED"
            assert "admin-user" in str(events[0].fields)

            assert s.query(ElevationToken).one().used is True, "elevation token not consumed"

    def test_p1b_null_hash_admin_mints_fresh(self, tmp_path):
        """Q9: reissue over a NULL hash (post-burn or never-issued) mints
        fresh — not a refusal."""
        from core.iam.models import User

        client, SessionLocal, _ = _build_reissue_app(tmp_path, session={"user_id": "admin-nohash"})
        token = _seed_token(SessionLocal, "elev-p1b", "admin-nohash")

        resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": token})
        assert resp.status_code == 200, resp.text

        with SessionLocal() as s:
            u = s.query(User).filter(User.user_id == "admin-nohash").one()
            assert u.recovery_code_hash is not None

    def test_p1c_helper_equivalence_pins(self):
        """Q8 consolidation is provably behavior-preserving: helper == the
        old inline expression; init/recovery bind to the helper; format and
        entropy hold."""
        import hashlib

        from server.recovery_codes import generate_recovery_code, hash_recovery_code
        from server.routes import init as init_routes
        from server.routes import recovery as recovery_routes

        code = "ABCDEF-abcdef-012345-ABCDEF-abcdef-012345-ABCDEF-abcdef"
        pepper = "p3pper"
        assert hash_recovery_code(code, pepper) == hashlib.sha256((pepper + code).encode()).hexdigest()

        # init keeps its historical private names (test_init.py's surface)
        assert init_routes._generate_recovery_code is generate_recovery_code
        assert init_routes._hash_recovery_code is hash_recovery_code
        # recovery's validation leg now runs the same helper
        assert recovery_routes.hash_recovery_code is hash_recovery_code

        c1, c2 = generate_recovery_code(), generate_recovery_code()
        assert c1 != c2, "entropy source must differ per call"
        _assert_code_shape(c1)
        _assert_code_shape(c2)

    def test_n1_no_session_bearer_401(self, tmp_path):
        """N1: no bearer, no injected session -> 401 at the auth dep."""
        client, _SessionLocal, _ = _build_reissue_app(tmp_path)  # cert-only, no bearer
        resp = client.post(REISSUE_PATH, json={})
        assert resp.status_code == 401

    def test_n1b_mtls_admin_identity_cannot_pass(self, tmp_path):
        """Q2 ruling, #340-reworked onto the real stack: a cert-only call
        (no bearer) is EXACTLY how a cert-CN identity reaches this route —
        the middleware hands the handler caller=admin with no user_id, and
        the session guard must deny 401 (cert alone never mints)."""
        client, _SessionLocal, _ = _build_reissue_app(tmp_path)
        resp = client.post(REISSUE_PATH, json={})
        assert resp.status_code == 401
        assert "session authentication required" in resp.json()["detail"].lower()

    def test_n2_non_admin_session_403_with_denied_audit(self, tmp_path):
        """N2: session WITHOUT admin membership -> 403; token stays UNUSED
        (consume runs only after all prechecks), hash unchanged, denial
        audit persisted (commit-before-raise)."""
        from core.iam.models import AuditEvent, ElevationToken, User

        client, SessionLocal, initial = _build_reissue_app(tmp_path, session={"user_id": "plain-user"})
        _seed_token(SessionLocal, "elev-n2", "plain-user")

        resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": "elev-n2"})
        assert resp.status_code == 403

        with SessionLocal() as s:
            assert s.query(ElevationToken).one().used is False, "denied request burned the token"
            u = s.query(User).filter(User.user_id == "plain-user").one()
            assert u.recovery_code_hash == initial
            denials = s.query(AuditEvent).filter(AuditEvent.event_type == "recovery_code_reissue_denied").all()
            assert len(denials) == 1
            assert "plain-user" in str(denials[0].fields)

    def test_n3_tokenless_403_loud(self, tmp_path):
        """N3: admin session WITHOUT the elevation header -> loud 403, never
        a silent fall-through; stored hash untouched."""
        from core.iam.models import User

        client, SessionLocal, initial = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        resp = client.post(REISSUE_PATH, json={})
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Elevation token required to reissue a recovery code"
        with SessionLocal() as s:
            u = s.query(User).filter(User.user_id == "admin-user").one()
            assert u.recovery_code_hash == initial

    def test_n4_used_or_expired_token_401_hash_unchanged(self, tmp_path):
        """N4: burned or expired single-use tokens -> 401; stored hash
        untouched."""
        from core.iam.models import User

        client, SessionLocal, initial = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        _seed_token(SessionLocal, "elev-used", "admin-user", used=True)
        _seed_token(SessionLocal, "elev-expired", "admin-user", valid=False)

        for tok in ("elev-used", "elev-expired"):
            resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": tok})
            assert resp.status_code == 401, tok

        with SessionLocal() as s:
            u = s.query(User).filter(User.user_id == "admin-user").one()
            assert u.recovery_code_hash == initial

    def test_n4b_post_consume_failure_rolls_back_token_burn(self, tmp_path):
        """#292/H1 rollback semantics PIN: failure AFTER the consume leaves
        the elevation token UNUSED and the hash UNCHANGED — the flush-only
        burn rides get_db's rollback into nothing. This cell exists to die
        on any future 'commit the burn early' regression."""
        import hashlib

        from core.iam.models import ElevationToken, User

        client, SessionLocal, initial = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        token = _seed_token(SessionLocal, "elev-n4b", "admin-user")

        from unittest.mock import patch as _patch

        with _patch("server.recovery_codes.generate_recovery_code", side_effect=RuntimeError("mint boom")):
            resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": token})
        assert resp.status_code == 500

        with SessionLocal() as s:
            assert s.query(ElevationToken).one().used is False, "burn survived the rollback"
            u = s.query(User).filter(User.user_id == "admin-user").one()
            assert u.recovery_code_hash == initial
            old_hash = hashlib.sha256(("test-pepper" + "OLD-CODE").encode()).hexdigest()
            assert u.recovery_code_hash == old_hash

    def test_n5_auditor_tier_session_refused(self, tmp_path):
        """N5/Q7 negative: auditor-only membership dies at the admin-role
        gate (structural — SoD exclusivity makes auditor+admin impossible;
        the route carries NO bespoke auditor check)."""
        from core.iam.models import ElevationToken

        client, SessionLocal, _ = _build_reissue_app(tmp_path, session={"user_id": "auditor-user"})
        token = _seed_token(SessionLocal, "elev-n5", "auditor-user")
        resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": token})
        assert resp.status_code == 403
        assert "recovery_code" not in resp.json()
        with SessionLocal() as s:
            assert s.query(ElevationToken).one().used is False

    def test_n6_double_invoke_last_wins_one_live_code(self, tmp_path):
        """N6/Q3: sequential reissues -> both 200, exactly ONE live hash
        (last-wins replace), and liveness is proven against the REAL
        /recovery endpoint: the superseded code 401s there, the current one
        recovers (and burns)."""
        from core.iam.models import User

        client, SessionLocal, _ = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        t1 = _seed_token(SessionLocal, "elev-n6-a", "admin-user")
        t2 = _seed_token(SessionLocal, "elev-n6-b", "admin-user")

        r1 = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": t1})
        r2 = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": t2})
        assert r1.status_code == 200 and r2.status_code == 200
        code1, code2 = r1.json()["recovery_code"], r2.json()["recovery_code"]
        assert code1 != code2

        dead = client.post("/api/v1/recovery", json={"code": code1, "new_user_id": "intruder"})
        assert dead.status_code == 401, "superseded code still live — stacking"
        live = client.post("/api/v1/recovery", json={"code": code2, "new_user_id": "recovered"})
        assert live.status_code == 200, "current code must recover"

        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "admin-user").one().recovery_code_hash is None
            assert s.query(User).filter(User.user_id == "intruder").count() == 0

    def test_x1_code_never_appears_in_any_log_record(self, tmp_path, caplog):
        """BANNED-design guard: the plaintext code (success path) appears in
        NO log record at any level."""
        import logging

        client, SessionLocal, _ = _build_reissue_app(tmp_path, session={"user_id": "admin-user"})
        token = _seed_token(SessionLocal, "elev-x1", "admin-user")

        with caplog.at_level(logging.DEBUG):
            resp = client.post(REISSUE_PATH, json={}, headers={"X-Elevation-Token": token})
        assert resp.status_code == 200
        code = resp.json()["recovery_code"]
        assert code not in caplog.text, "code material reached a log record — BANNED design"


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite.

    SQLite has no timestamptz (the model's timezone=True is a PG-only flag),
    so check_expiry's aware-now comparison TypeErrors on round-tripped naive
    rows. Production (PostgreSQL) always returns aware values, where this
    listener is a no-op. Registered once per process by the #340 real-stack
    builders.
    """
    from core.iam.models import Session as SessionModel
    from sqlalchemy import event
    from sqlalchemy.orm import Session as ORMSession  # noqa: F401 (doc anchor)

    if getattr(SessionModel, "_r340_utc_loader", False):
        return
    SessionModel._r340_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        from datetime import UTC

        for field in ("created_at", "expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


# ---------------------------------------------------------------------------
# #340 ruled A: session-demanding admin routes verify the cert AND the
# presented session — the reissue mint is reachable ONLY with both.
# Real middleware stack (SessionMiddleware + forwarded-cert file per
# conftest, the #314 harness): NO bare-router plant (the legacy lesson
# this class exists to close).
# ---------------------------------------------------------------------------

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

try:  # package-relative import (pytest package mode)
    from .conftest import ADMIN_SERIAL_HEX, forwarded_headers, inner_tls_config, make_cert_prefix, make_leaf
except ImportError:  # flat import fallback (matches test_admin_mtls.py)
    from conftest import ADMIN_SERIAL_HEX, forwarded_headers, inner_tls_config, make_cert_prefix, make_leaf


def _r340_ca_and_leaf(tmp_path):
    """Initialize a real Admin CA in tmp and mint an admin@example.com leaf."""
    from server.ca import PLANE_MACHINE, AdminCAManager
    from server.config import CASecurityConfig

    ca_dir = tmp_path / "r340-admin-ca"
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
    AdminCAManager(ca_dir, CASecurityConfig(key_passphrase_env="VENYA_ADMIN_CA_KEY_PASSPHRASE")).initialize()
    ca_cert = x509.load_pem_x509_certificate((ca_dir / "admin-ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((ca_dir / "admin-ca.key").read_bytes(), password=b"test_passphrase")
    # RF-7 chunk 2: this leaf stands in for a MACHINE-plane admin certificate
    # (the identity is enumerated in known_admin_ids), so it carries the marker
    # the bootstrap mint writes at this tip (PLANE_MACHINE). Assertions are
    # untouched; the pre-two-plane markerless shape is refused by design and has
    # its own cells in test_plane_marker_middleware_rf7.py.
    return ca_dir, make_leaf(
        ca_cert, ca_key, cn="admin@example.com", serial=int(ADMIN_SERIAL_HEX, 16), plane=PLANE_MACHINE
    )


def _build_reissue_middleware_app(tmp_path, *, bearer="valid-bearer", session_expires=None):
    """Reissue route + SessionMiddleware + admin-mTLS config + real SQLite.

    Seeds what production seeds: an ACTIVE admin user, a REAL Session row
    (access_token looked up by _validate_token), and the admin router under
    its production prefix. Nothing is injected through
    dependency_overrides — every identity on this stack is one the
    middleware can actually produce.
    """
    from datetime import UTC, datetime, timedelta

    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE
    from core.iam.models import Base, Role, RoleMember, User
    from core.iam.models import Session as SessionModel
    from fastapi import FastAPI, Request
    from server.config import AdminMTLSConfig, ServerConfig
    from server.middleware.auth import SessionMiddleware
    from server.routes import admin as admin_routes
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from starlette.testclient import TestClient

    prefix = make_cert_prefix(tmp_path)
    db_path = tmp_path / "reissue-mw.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    _sqlite_utc_loader()
    SessionLocal = sessionmaker(bind=engine)
    s = SessionLocal()
    admin_role = Role(name="admin", permissions="read-write")
    s.add(admin_role)
    s.flush()
    s.add_all(
        [
            User(user_id="admin-user", status="active", recovery_code_hash=None),
            RoleMember(user_id="admin-user", role_id=admin_role.id),
            SessionModel(
                user_id="admin-user",
                access_token=bearer,
                access_token_jti="jti-r340",
                created_at=datetime.now(UTC),
                expires_at=session_expires or datetime.now(UTC) + timedelta(minutes=15),
                # #342: fresh bearer-tier expiry (gate rejects NULL/aged).
                access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
        ]
    )
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=True,
            ca_cert=str(tmp_path / "r340-admin-ca" / "admin-ca.crt"),
            known_admin_ids=["admin@example.com"],
        ),
        inner_mtls=inner_tls_config(prefix),
        recovery_code_pepper="test-pepper",
    )
    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config
    app.state.backend = backend

    @app.get("/api/v1/admin/probe")
    def probe(request: Request):
        return {"auth_user": getattr(request.state, "auth_user", None)}

    app.include_router(admin_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), SessionLocal, prefix


class TestReissueDualCredentialMiddleware:
    """#340 truth table, both halves, real middleware stack."""

    @pytest.fixture(autouse=True)
    def _clean_passphrase_env(self):
        old = os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)
        yield
        if old is not None:
            os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = old

    def test_t1_cert_plus_session_mints(self, tmp_path):
        """T1 DUAL CREDS: valid cert + valid session bearer -> 200, one new
        code, one success audit event. RED pre-#340-fix: the admin-mTLS
        short-circuit makes the middleware return before the bearer branch,
        so auth_user is the cert identity and the handler guard 401s."""
        _, leaf = _r340_ca_and_leaf(tmp_path)
        client, SessionLocal, prefix = _build_reissue_middleware_app(tmp_path)
        elev = _seed_token(SessionLocal, "elev-t1", "admin-user")

        resp = client.post(
            REISSUE_PATH,
            json={},
            headers={
                **forwarded_headers(prefix, leaf),
                "Authorization": "Bearer valid-bearer",
                "X-Elevation-Token": elev,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["user_id"] == "admin-user"
        _assert_code_shape(body["recovery_code"])

        from core.iam.models import AuditEvent

        with SessionLocal() as s:
            events = s.query(AuditEvent).filter(AuditEvent.event_type == "recovery_code_reissued").all()
            assert len(events) == 1
            assert body["recovery_code"] not in str(events[0].fields)

    def test_t2_cert_only_still_denied(self, tmp_path):
        """T2 cert-only at the mint -> 401 'session authentication
        required' (cert identity still cannot pass — ruling A half 1)."""
        _, leaf = _r340_ca_and_leaf(tmp_path)
        client, _SessionLocal, prefix = _build_reissue_middleware_app(tmp_path)

        resp = client.post(REISSUE_PATH, json={}, headers=forwarded_headers(prefix, leaf))
        assert resp.status_code == 401
        assert "session authentication required" in resp.json()["detail"].lower()

    def test_t3_session_only_channel_refused(self, tmp_path):
        """T3 valid session, NO cert -> 403: the cert-verified channel is
        required when admin-mTLS is enabled (ruling A half 2)."""
        client, _SessionLocal, _prefix = _build_reissue_middleware_app(tmp_path)
        elev = _seed_token(_SessionLocal, "elev-t3", "admin-user")

        resp = client.post(
            REISSUE_PATH, json={}, headers={"Authorization": "Bearer valid-bearer", "X-Elevation-Token": elev}
        )
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_t4_cert_only_control_route_unchanged(self, tmp_path):
        """T4 control: cert-only on a NORMAL admin path still 200 with
        caller=admin — the reissue fall-through must not disturb it."""
        _, leaf = _r340_ca_and_leaf(tmp_path)
        client, _SessionLocal, prefix = _build_reissue_middleware_app(tmp_path)

        resp = client.get("/api/v1/admin/probe", headers=forwarded_headers(prefix, leaf))
        assert resp.status_code == 200
        assert resp.json()["auth_user"]["caller"] == "admin"

    def test_t5_idle_expired_session_no_mint(self, tmp_path):
        """T5 idle-expired bearer + valid cert -> 401 invalid-or-expired
        from the session half; no mint, no success audit event."""
        from datetime import UTC, datetime, timedelta

        _, leaf = _r340_ca_and_leaf(tmp_path)
        client, SessionLocal, prefix = _build_reissue_middleware_app(
            tmp_path,
            bearer="expired-bearer",
            session_expires=datetime.now(UTC) - timedelta(minutes=1),
        )
        elev = _seed_token(SessionLocal, "elev-t5", "admin-user")

        resp = client.post(
            REISSUE_PATH,
            json={},
            headers={
                **forwarded_headers(prefix, leaf),
                "Authorization": "Bearer expired-bearer",
                "X-Elevation-Token": elev,
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

        from core.iam.models import AuditEvent

        with SessionLocal() as s:
            assert s.query(AuditEvent).filter(AuditEvent.event_type == "recovery_code_reissued").count() == 0
