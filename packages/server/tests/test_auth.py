"""Tests for auth (WebAuthn) endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import auth as auth_routes


def _create_test_app(fido2_manager=None, backend=None):
    """Create a minimal test app with auth routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if fido2_manager is None:
        fido2_manager = MagicMock()
    app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    app.include_router(auth_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestAuthRegistrationStart:
    """Tests for registration start endpoint."""

    def test_start_success(self):
        """POST /auth/registration/start should return challenge options."""
        fido2 = MagicMock()
        fido2.get_user_credentials.return_value = []
        fido2.start_registration.return_value = (
            "challenge-123",
            {"publicKey": {}},
        )
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/start",
            json={"user_id": "user1", "username": "Alice"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "challenge-123"
        assert "publicKey" in data["options"]

    def test_start_no_fido2(self):
        """POST /auth/registration/start should return 503 if FIDO2 not initialized."""
        app = _create_test_app()
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/start",
            json={"user_id": "user1", "username": "Alice"},
        )
        assert resp.status_code == 503


class TestAuthRegistrationComplete:
    """Tests for registration complete endpoint."""

    def test_complete_success(self):
        """POST /auth/registration/complete should store credential in DB."""
        cred = SimpleNamespace(
            credential_id=b"cred-123",
            user_id="user1",
            public_key=b"public-key-data",
            sign_count=0,
        )
        fido2 = MagicMock()
        fido2.finish_registration.return_value = cred

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={
                "challenge_id": "challenge-123",
                "response": {"id": "dGVzdA==", "response": {}},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["credential_id"] == "cred-123"
        # Verify credential was added to DB via backend
        assert backend.get_session.return_value.add.called

    def test_complete_no_backend(self):
        """POST /auth/registration/complete should work without backend (DB optional)."""
        cred = SimpleNamespace(
            credential_id="cred-123",
            user_id="user1",
            credential_data={"raw_id": "dGVzdA==", "response": {}, "transports": []},
            transports=[],
        )
        fido2 = MagicMock()
        fido2.finish_registration.return_value = cred
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={
                "challenge_id": "challenge-123",
                "response": {"id": "dGVzdA==", "response": {}},
            },
        )
        assert resp.status_code == 201

    def test_complete_invalid_challenge(self):
        """POST /auth/registration/complete should return 400 for invalid challenge."""
        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={
                "challenge_id": "expired",
                "response": {},
            },
        )
        assert resp.status_code == 400


class TestAuthLoginStart:
    """Tests for login start endpoint."""

    def test_login_start_success(self):
        """POST /auth/login/start should return challenge options."""
        fido2 = MagicMock()
        fido2.start_authentication.return_value = (
            "auth-challenge-123",
            {"publicKey": {}},
        )
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/start",
            json={"user_id": "user1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "auth-challenge-123"

    def test_login_start_no_fido2(self):
        """POST /auth/login/start should return 503 if FIDO2 not initialized."""
        app = _create_test_app()
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/start",
            json={},
        )
        assert resp.status_code == 503


class TestAuthLoginComplete:
    """Tests for login complete endpoint."""

    def test_login_complete_success(self):
        """POST /auth/login/complete should create session and return token."""
        fido2 = MagicMock()
        fido2.finish_authentication.return_value = {
            "user_id": "user1",
            "credential_id": "cred-123",
        }

        session_mock = SimpleNamespace(id=1, user_id="user1")
        access_token_mock = SimpleNamespace(token="access-token-xyz")

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("vault.iam.session_manager.SessionManager") as mock_sm, \
             patch("vault.iam.role_manager.RoleManager") as mock_rm:

            mock_sm.return_value.create_session.return_value = (session_mock, access_token_mock)
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app(fido2_manager=fido2, backend=backend)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/complete",
                json={
                    "challenge_id": "auth-challenge-123",
                    "response": {"id": "dGVzdA=="},
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user_id"] == "user1"
            assert data["session_token"] == "access-token-xyz"

    def test_login_complete_invalid_assertion(self):
        """POST /auth/login/complete should return 401 for invalid assertion."""
        fido2 = MagicMock()
        fido2.finish_authentication.side_effect = ValueError("Invalid assertion")
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/complete",
            json={
                "challenge_id": "auth-challenge-123",
                "response": {},
            },
        )
        assert resp.status_code == 401


class TestAuthRefresh:
    """Tests for auth refresh endpoint."""

    def test_refresh_success(self):
        """POST /auth/refresh should return new access token."""
        session_mock = SimpleNamespace(id=1, access_token_jti="old-token")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock

        new_token_mock = SimpleNamespace(token="new-access-token")

        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("vault.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_sm.return_value.refresh_token.return_value = new_token_mock

            app = _create_test_app(backend=backend)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/refresh",
                headers={"authorization": "Bearer old-token"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["access_token"] == "new-access-token"

    def test_refresh_missing_token(self):
        """POST /auth/refresh should return 401 if no token provided."""
        backend = MagicMock()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401
        assert "Missing authentication" in resp.json()["detail"]

    def test_refresh_invalid_token(self):
        """POST /auth/refresh should return 401 for invalid token."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/refresh",
            headers={"authorization": "Bearer nonexistent"},
        )
        assert resp.status_code == 401
