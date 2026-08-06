"""Tests for browser WebAuthn auth endpoints."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import auth_browser


def _create_test_app(fido2_manager=None, backend=None):
    """Create a minimal test app with browser auth routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if fido2_manager is None:
        fido2_manager = MagicMock()
    app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    app.include_router(auth_browser.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestBrowserLoginChallenge:
    """Tests for browser login challenge endpoint."""

    def test_challenge_success(self):
        """POST /auth/login/browser/challenge should return browser-formatted options."""
        fido2 = MagicMock()
        fido2.start_authentication.return_value = (
            "auth-challenge-123",
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",  # base64 for "test-challenge"
                "rpId": "example.com",
                "timeout": 60000,
                "userVerification": "discouraged",
                "allowCredentials": [
                    {"type": "public-key", "id": "Y3JlZC0xMjM="},  # base64 for "cred-123"
                ],
            },
        )
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/challenge",
            json={"user_id": "user1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "auth-challenge-123"
        # Challenge should be base64url (no padding)
        assert "=" not in data["options"]["challenge"]
        # rpId should be converted to rp object
        assert "rp" in data["options"]
        assert data["options"]["rp"]["id"] == "example.com"
        # allowCredentials should be base64url
        assert "=" not in data["options"]["allowCredentials"][0]["id"]

    def test_challenge_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        app = _create_test_app()
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/challenge",
            json={},
        )
        assert resp.status_code == 503

    def test_challenge_without_user_id(self):
        """Should work without user_id (broad challenge)."""
        fido2 = MagicMock()
        fido2.start_authentication.return_value = (
            "auth-challenge-456",
            {
                "challenge": "dGVzdA==",
                "rpId": "localhost",
                "timeout": 60000,
                "userVerification": "discouraged",
            },
        )
        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/challenge",
            json={},
        )
        assert resp.status_code == 200
        assert resp.json()["challenge_id"] == "auth-challenge-456"


class TestBrowserLoginAssert:
    """Tests for browser login assert endpoint."""

    def test_assert_success(self):
        """POST /auth/login/browser/assert should set session cookie."""
        fido2 = MagicMock()
        fido2.finish_authentication.return_value = {
            "user_id": "user1",
            "credential_id": "cred-123",
        }

        session_mock = SimpleNamespace(id=1, user_id="user1")
        token_mock = SimpleNamespace(token="access-token-xyz", jti="jti-xyz")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("vault.iam.session_manager.SessionManager") as mock_sm, \
             patch("vault.iam.role_manager.RoleManager") as mock_rm:

            mock_sm.return_value.create_session.return_value = (session_mock, token_mock)
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app(fido2_manager=fido2, backend=backend)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/browser/assert",
                json={
                    "challenge_id": "auth-challenge-123",
                    "response": {"id": "dGVzdA=="},
                },
            )
            assert resp.status_code == 200
            set_cookie = resp.headers.get("set-cookie", "")
            assert "venya_access_token=access-token-xyz" in set_cookie
            assert "HttpOnly" in set_cookie
            assert "Secure" in set_cookie
            assert "samesite=strict" in set_cookie.lower()

    def test_assert_invalid_challenge(self):
        """Should return 401 for invalid challenge."""
        fido2 = MagicMock()
        fido2.finish_authentication.side_effect = ValueError("Challenge not found or expired")

        app = _create_test_app(fido2_manager=fido2)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/assert",
            json={
                "challenge_id": "expired",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 401

    def test_assert_no_backend(self):
        """Should return 503 if backend not initialized."""
        fido2 = MagicMock()
        app = _create_test_app(fido2_manager=fido2)
        # Remove backend from state
        app.state.backend = None

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/assert",
            json={
                "challenge_id": "chal-1",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 503


class TestBrowserRefresh:
    """Tests for browser refresh endpoint."""

    def test_refresh_success(self):
        """POST /auth/refresh/browser should issue new token cookie."""
        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=1, user_id="user1", expires_at=now + timedelta(minutes=10), user=user_mock,
        )
        token_mock = SimpleNamespace(token="new-access-token", jti="new-jti")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("vault.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.refresh_token.return_value = token_mock
            mock_sm.return_value.check_expiry.return_value = True

            app = _create_test_app(backend=backend)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/refresh/browser",
                cookies={"venya_access_token": "old-token"},
            )
            assert resp.status_code == 200
            set_cookie = resp.headers.get("set-cookie", "")
            assert "venya_access_token=new-access-token" in set_cookie

    def test_refresh_no_cookie(self):
        """Should return 401 if no session cookie."""
        backend = MagicMock()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/refresh/browser")
        assert resp.status_code == 401

    def test_refresh_invalid_token(self):
        """Should return 401 for invalid token."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/refresh/browser",
            cookies={"venya_access_token": "nonexistent"},
        )
        assert resp.status_code == 401


class TestBrowserLogout:
    """Tests for browser logout endpoint."""

    def test_logout_success(self):
        """POST /auth/logout/browser should clear cookie and revoke session."""
        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=1, user_id="user1", expires_at=now + timedelta(minutes=10), user=user_mock,
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("vault.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.revoke_session.return_value = True

            app = _create_test_app(backend=backend)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/logout/browser",
                cookies={"venya_access_token": "old-token"},
            )
            assert resp.status_code == 200
            set_cookie = resp.headers.get("set-cookie", "")
            assert "venya_access_token=" in set_cookie
            assert mock_sm.return_value.revoke_session.called

    def test_logout_no_session(self):
        """Should still clear cookie even if session is invalid."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/logout/browser",
            cookies={"venya_access_token": "nonexistent"},
        )
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert "venya_access_token=" in set_cookie


class TestBrowserElevateChallenge:
    """Tests for browser elevate challenge endpoint."""

    def test_elevate_challenge_success(self):
        """POST /auth/elevate/browser/challenge should return browser-formatted options."""
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace

        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=1, user_id="user1", created_at=now,
            expires_at=now + timedelta(minutes=10), user=user_mock,
        )

        db = MagicMock()
        # Mock the chain: query(WebAuthnCredential).filter().all()
        # Return at least one credential so the challenge can be created
        mock_cred = MagicMock()
        mock_cred.credential_id = "cred-1"
        db.query.return_value.filter.return_value.all.return_value = [mock_cred]
        # For _get_session_from_cookie: query(Session).filter().first()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.start_authentication.return_value = (
            "elev-challenge-123",
            {
                "challenge": "dGVzdA==",
                "rpId": "localhost",
                "timeout": 60000,
                "userVerification": "discouraged",
            },
        )

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        client = TestClient(app, raise_server_exceptions=False, cookies={"venya_access_token": "valid-token"})
        resp = client.post("/api/v1/auth/elevate/browser/challenge")
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "elev-challenge-123"
        assert "options" in data

    def test_elevate_challenge_no_cookie(self):
        """Should return 401 if no session cookie."""
        backend = MagicMock()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/elevate/browser/challenge")
        assert resp.status_code == 401

    def test_elevate_challenge_invalid_session(self):
        """Should return 401 for invalid session cookie."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False, cookies={"venya_access_token": "invalid"})
        resp = client.post("/api/v1/auth/elevate/browser/challenge")
        assert resp.status_code == 401


class TestBrowserElevateAssert:
    """Tests for browser elevate assert endpoint."""

    def test_elevate_assert_success(self):
        """POST /auth/elevate/browser/assert should return elevation token."""
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace

        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=1, user_id="user1", created_at=now,
            expires_at=now + timedelta(minutes=10), user=user_mock,
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        db.add = MagicMock()
        db.commit = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_authentication.return_value = {"user_id": "user1", "credential_id": "cred-1"}

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        # Simulate a prior challenge being stored
        app.state._elevation_challenges = {
            "elev-challenge-123": {"session_id": 1, "user_id": "user1"}
        }

        client = TestClient(app, raise_server_exceptions=False, cookies={"venya_access_token": "valid-token"})
        resp = client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={
                "challenge_id": "elev-challenge-123",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "elevation_token" in data
        assert len(data["elevation_token"]) > 0

    def test_elevate_assert_no_cookie(self):
        """Should return 401 if no session cookie."""
        # Need a backend so get_backend() doesn't return 503
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "chal-1", "response": {"id": "dGVzdA=="}},
        )
        assert resp.status_code == 401

    def test_elevate_assert_invalid_challenge(self):
        """Should return 401 if challenge not found."""
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace

        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=1, user_id="user1", created_at=now,
            expires_at=now + timedelta(minutes=10), user=user_mock,
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)
        # No challenges stored

        client = TestClient(app, raise_server_exceptions=False, cookies={"venya_access_token": "valid-token"})
        resp = client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "nonexistent", "response": {"id": "dGVzdA=="}},
        )
        assert resp.status_code == 401

    def test_elevate_assert_session_mismatch(self):
        """Should return 401 if challenge session doesn't match."""
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace

        user_mock = SimpleNamespace(user_id="user1")
        now = datetime.now(timezone.utc)
        session_mock = SimpleNamespace(
            id=99, user_id="user1", created_at=now,
            expires_at=now + timedelta(minutes=10), user=user_mock,
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        # Challenge is for session 1, but cookie is for session 99
        app.state._elevation_challenges = {
            "chal-1": {"session_id": 1, "user_id": "user1"}
        }

        client = TestClient(app, raise_server_exceptions=False, cookies={"venya_access_token": "valid-token"})
        resp = client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "chal-1", "response": {"id": "dGVzdA=="}},
        )
        assert resp.status_code == 401
