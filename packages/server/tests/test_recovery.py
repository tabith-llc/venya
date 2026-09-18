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
        still works afterwards."""
        from core.iam.models import User

        client, SessionLocal, code = _build_real_app(tmp_path)
        bad = client.post("/api/v1/recovery", json={"code": "WRONG-CODE", "new_user_id": "x"})
        assert bad.status_code == 401
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is not None
        good = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "x"})
        assert good.status_code == 200
