"""Tests for break-glass recovery endpoint."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from venya_server.routes import recovery as recovery_routes


def _create_test_app(backend=None):
    """Create a minimal test app with recovery route."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(recovery_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestRecovery:
    """Tests for break-glass recovery endpoint."""

    def test_recovery_success(self):
        """POST /recovery should create new admin user."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": "recovery-123",
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["action"] == "new_admin"
        assert data["user_id"] == "newadmin"
        assert db.add.called

    def test_recovery_user_exists(self):
        """POST /recovery should return 400 if user already exists."""
        existing_user = SimpleNamespace(user_id="existing")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing_user

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": "recovery-123",
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
        admin_role = SimpleNamespace(id=1, name="admin")

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                if hasattr(self, '_called'):
                    self._called += 1
                    if self._called == 1:
                        return None  # First call: user not found
                    return admin_role  # Second call: admin role found
                self._called = 1
                return None

        db = MagicMock()
        db.query.return_value = MockQuery()

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/recovery",
            json={
                "code": "recovery-123",
                "new_user_id": "newadmin",
            },
        )
        assert resp.status_code == 200
        assert db.add.call_count >= 2  # User + RoleMember
