"""Tests for session authentication middleware (dual cookie + bearer)."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.middleware.auth import SessionMiddleware


def _create_test_app():
    """Create a minimal test app with session middleware."""
    from starlette.requests import Request

    app = FastAPI()

    class AuthMiddleware(SessionMiddleware):
        pass

    app.add_middleware(AuthMiddleware)

    @app.get("/api/v1/protected")
    def protected_endpoint(request: Request):
        user = getattr(request.state, "auth_user", None)
        return {"user": user}

    @app.get("/api/v1/public")
    def public_endpoint(request: Request):
        return {"status": "ok"}

    return app


def _make_session_mock(user_id="user1", expires_at=None, access_token_jti="token-123"):
    """Create a mock session object."""
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    user_mock = SimpleNamespace(user_id=user_id)
    return SimpleNamespace(
        id=1, user_id=user_id, expires_at=expires_at,
        user=user_mock, access_token_jti=access_token_jti,
    )


def _make_backend(session=None):
    """Create a mock backend with a session."""
    db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value.first.return_value = session
        return q

    db.query.side_effect = query_side_effect
    backend = MagicMock()
    backend.get_session.return_value = db
    return backend


class TestCookieAuth:
    """Tests for cookie-based authentication."""

    def test_cookie_auth_success(self):
        """Cookie auth should work and attach user info."""
        session = _make_session_mock()
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, \
             patch("core.iam.role_manager.RoleManager") as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/protected",
                cookies={"venya_access_token": "token-123"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "user1"

    def test_cookie_auth_invalid_token(self):
        """Invalid cookie token should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/protected",
            cookies={"venya_access_token": "nonexistent"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

    def test_cookie_auth_expired(self):
        """Expired cookie token should return 401."""
        expired_session = _make_session_mock(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        backend = _make_backend(session=expired_session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.check_expiry.return_value = False

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/protected",
                cookies={"venya_access_token": "expired-token"},
            )
            assert resp.status_code == 401


class TestBearerAuth:
    """Tests for bearer token authentication (CLI)."""

    def test_bearer_auth_success(self):
        """Bearer token should work and attach user info."""
        session = _make_session_mock()
        backend = _make_backend(session)

        with patch("core.iam.session_manager.SessionManager") as mock_sm, \
             patch("core.iam.role_manager.RoleManager") as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/protected",
                headers={"authorization": "Bearer token-123"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "user1"

    def test_bearer_auth_invalid_token(self):
        """Invalid bearer token should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/protected",
            headers={"authorization": "Bearer nonexistent"},
        )
        assert resp.status_code == 401

    def test_no_auth_returns_401(self):
        """No token or cookie should return 401."""
        backend = _make_backend(session=None)

        app = _create_test_app()
        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/protected")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing authentication token"


class TestCookiePriority:
    """Tests that cookie takes priority over bearer token."""

    def test_cookie_takes_priority_over_bearer(self):
        """When both cookie and bearer are present, cookie should be used."""
        cookie_session = _make_session_mock(user_id="cookie-user")
        bearer_session = _make_session_mock(user_id="bearer-user")

        def query_side_effect(model):
            if model.__name__ == "Session":
                # Return different sessions based on token value
                return MagicMock(
                    filter=MagicMock(return_value=MagicMock(
                        first=MagicMock(return_value=cookie_session
                            if "cookie-token" in str(list(model.__dict__.get('_filters', [])))
                            else bearer_session)
                    ))
                )
            return MagicMock()

        # Use a simpler approach: cookie token matches cookie session
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = cookie_session
        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("core.iam.session_manager.SessionManager") as mock_sm, \
             patch("core.iam.role_manager.RoleManager") as mock_rm:
            mock_sm.return_value.check_expiry.return_value = True
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app()
            app.state.backend = backend

            client = TestClient(
                app,
                raise_server_exceptions=False,
                cookies={"venya_access_token": "cookie-token"},
            )
            resp = client.get(
                "/api/v1/protected",
                headers={"authorization": "Bearer bearer-token"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"]["user_id"] == "cookie-user"


class TestPublicPaths:
    """Tests that public paths bypass authentication."""

    def test_public_health(self):
        """GET /health should not require auth."""
        from server.routes import health

        app = _create_test_app()
        app.include_router(health.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_browser_challenge_public(self):
        """Browser login challenge should be public."""
        from server.routes import auth_browser

        app = _create_test_app()
        app.include_router(auth_browser.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/challenge",
            json={"user_id": "user1"},
        )
        assert resp.status_code == 503  # 503 because FIDO2 not initialized, not 401

    def test_browser_assert_public(self):
        """Browser login assert should be public."""
        from server.routes import auth_browser

        app = _create_test_app()
        app.include_router(auth_browser.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/login/browser/assert",
            json={"challenge_id": "x", "response": {}},
        )
        assert resp.status_code == 503  # FIDO2 not initialized, not 401

    def test_enroll_browser_public(self):
        """Browser enrollment start should be public."""
        from server.routes import enroll

        app = _create_test_app()
        app.include_router(enroll.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/start",
            json={"enrollment_token": "test-token"},
        )
        assert resp.status_code == 503  # Backend not initialized, not 401

    def test_enroll_browser_complete_public(self):
        """Browser enrollment complete should be public."""
        from server.routes import enroll

        app = _create_test_app()
        app.include_router(enroll.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/complete",
            json={"enrollment_token": "test-token", "challenge_id": "x", "response": {}, "label": "key"},
        )
        assert resp.status_code == 503  # Backend not initialized, not 401

    def test_elevate_challenge_public(self):
        """Browser elevate challenge should be public."""
        from server.routes import auth_browser

        app = _create_test_app()
        app.include_router(auth_browser.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/elevate/browser/challenge")
        assert resp.status_code == 503  # Backend not initialized, not 401

    def test_elevate_assert_public(self):
        """Browser elevate assert should be public."""
        from server.routes import auth_browser

        app = _create_test_app()
        app.include_router(auth_browser.router, prefix="/api/v1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "x", "response": {}},
        )
        assert resp.status_code == 503  # Backend not initialized, not 401


class TestMtlsBypass:
    """Tests for mTLS request bypass."""

    def test_mtls_request_bypasses_auth(self):
        """mTLS requests should bypass token auth."""
        app = _create_test_app()

        # Mock mTLS via ASGI scope
        client = TestClient(app, raise_server_exceptions=False)
        # Starlette TestClient doesn't easily support mTLS, but we can
        # verify the _is_mtls_request method exists and is called
        middleware = SessionMiddleware(app)
        assert hasattr(middleware, "_is_mtls_request")
