"""Tests for break-glass recovery endpoint."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import recovery as recovery_routes


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
            from fastapi import HTTPException
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
                    return None  # No matching user
                return None

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
