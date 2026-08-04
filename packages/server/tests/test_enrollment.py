"""Tests for enrollment flow endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from venya_server.routes import enrollment as enrollment_routes


def _create_test_app(backend=None, auth_user=None):
    """Create a minimal test app with enrollment routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.include_router(enrollment_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _make_mock_enrollment_manager(token=None, user=None, error=None):
    """Create a mock EnrollmentManager."""
    from datetime import datetime, timezone, timedelta

    em = MagicMock()
    if error:
        em.create_enrollment_token.side_effect = error
        em.consume_enrollment_token.side_effect = error
    else:
        if token:
            em.create_enrollment_token.return_value = token
        else:
            em.create_enrollment_token.return_value = SimpleNamespace(
                token="enc-token-123",
                user_id="newuser",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
        if user:
            em.consume_enrollment_token.return_value = user
        else:
            em.consume_enrollment_token.return_value = SimpleNamespace(
                user_id="newuser",
                auth_mode="security-key",
            )
    return em


class TestEnrollmentCreateToken:
    """Tests for enrollment token creation endpoint."""

    def test_create_token_success(self):
        """POST /enrollment/tokens should create token via EnrollmentManager."""
        em = _make_mock_enrollment_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/tokens",
                json={
                    "user_id": "newuser",
                    "auth_mode": "platform",
                },
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["token"] == "enc-token-123"
            assert "enrollment_url" in data
            assert "newuser" in data["enrollment_url"]

    def test_create_token_max_tokens(self):
        """POST /enrollment/tokens should return 400 if too many tokens."""
        em = _make_mock_enrollment_manager(
            error=Exception("User 'user1' already has 3 active enrollment tokens")
        )
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/tokens",
                json={"user_id": "user1"},
            )
            assert resp.status_code == 400
            assert "already has 3 active" in resp.json()["detail"]


class TestEnrollmentListTokens:
    """Tests for enrollment token listing endpoint."""

    def test_list_tokens_success(self):
        """GET /enrollment/tokens should return active tokens."""
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        token1 = SimpleNamespace(
            token="token-1",
            user_id="user1",
            expires_at=now + timedelta(hours=12),
        )
        token2 = SimpleNamespace(
            token="token-2",
            user_id="user2",
            expires_at=now + timedelta(hours=6),
        )
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def order_by(self, *args, **kwargs):
                return self
            def all(self):
                return [token1, token2]

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/enrollment/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tokens"]) == 2
        assert data["tokens"][0]["user_id"] == "user1"
        assert data["tokens"][1]["user_id"] == "user2"

    def test_list_tokens_empty(self):
        """GET /enrollment/tokens should return empty list when no active tokens."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def order_by(self, *args, **kwargs):
                return self
            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/enrollment/tokens")
        assert resp.status_code == 200
        assert resp.json()["tokens"] == []


class TestEnrollmentConfirm:
    """Tests for enrollment confirmation endpoint."""

    def test_confirm_success(self):
        """POST /enrollment/confirm should consume token and create user."""
        em = _make_mock_enrollment_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/confirm",
                json={
                    "token": "enc-token-123",
                    "user_id": "newuser",
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["enrolled"] is True
            assert data["user_id"] == "newuser"
            assert data["auth_mode"] == "security-key"

    def test_confirm_invalid_token(self):
        """POST /enrollment/confirm should return 400 for invalid token."""
        em = _make_mock_enrollment_manager(
            error=Exception("Invalid or expired enrollment token")
        )
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/confirm",
                json={
                    "token": "invalid-token",
                    "user_id": "newuser",
                },
            )
            assert resp.status_code == 400
            assert "Invalid or expired" in resp.json()["detail"]

    def test_confirm_user_exists(self):
        """POST /enrollment/confirm should return 400 if user already exists."""
        em = _make_mock_enrollment_manager(
            error=Exception("User 'existing' already exists")
        )
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/confirm",
                json={
                    "token": "enc-token-123",
                    "user_id": "existing",
                },
            )
            assert resp.status_code == 400
            assert "already exists" in resp.json()["detail"]
