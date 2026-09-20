# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for auth (WebAuthn) endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.routes import auth as auth_routes
from starlette.testclient import TestClient


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
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(
            session_timeout=900,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        admin_mtls=SimpleNamespace(enabled=False),
    )
    app.include_router(auth_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


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

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:

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
        # backend present so get_db DI resolves; test targets the fido2 error path (D-6)
        app = _create_test_app(fido2_manager=fido2, backend=MagicMock())

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
        """POST /auth/refresh should return new access token.

        updated (mcp-refresh-path-unreachable Option A): the route gate is
        check_refresh_window (hard cap only), no longer check_expiry."""
        session_mock = SimpleNamespace(id=1, access_token="old-token", access_token_jti="uuid-hex")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock

        new_token_mock = SimpleNamespace(token="new-access-token")

        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("core.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.check_refresh_window.return_value = True
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

    def test_refresh_past_hard_cap_401(self):
        """Paired negative (Option A): past max_session_duration the refresh
        window is closed — 401 Session expired (FIDO2 re-auth required)."""
        session_mock = SimpleNamespace(id=1, access_token="old-token", access_token_jti="uuid-hex")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("core.iam.session_manager.SessionManager") as mock_sm:
            mock_sm.return_value.check_refresh_window.return_value = False

            app = _create_test_app(backend=backend)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/refresh",
                headers={"authorization": "Bearer old-token"},
            )
            assert resp.status_code == 401
            assert resp.json()["detail"] == "Session expired"

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


class TestRegistrationEndpointsRemoved:
    """Ticket sec-unauth-webauthn-registration-takeover: the legacy PUBLIC
    registration endpoints are removed — credential binding to a client-
    supplied user_id was an account-takeover primitive. Both paths 404 now;
    issuance is exclusively token-bound (enroll/init/credentials)."""

    def test_registration_start_is_gone(self):
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/start",
            json={"user_id": "victim", "username": "Alice"},
        )
        assert resp.status_code == 404

    def test_registration_complete_is_gone(self):
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={"challenge_id": "c", "response": {"id": "dGVzdA==", "response": {}}},
        )
        assert resp.status_code == 404


class TestLoginStatusGate:
    """B1 core gate surfaced at the route: create_session raising
    UserNotActiveError maps to a uniform 401 (not 500), disclosing nothing
    about account state."""

    def test_login_complete_inactive_user_401(self):
        from core.iam.session_manager import UserNotActiveError

        fido2 = MagicMock()
        fido2.finish_authentication.return_value = {"user_id": "user1", "credential_id": "cred-123"}
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm:
            mock_sm.return_value.create_session.side_effect = UserNotActiveError("user1", "disabled")
            mock_rm.return_value.get_user_roles.return_value = []

            app = _create_test_app(fido2_manager=fido2, backend=backend)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/complete",
                json={"challenge_id": "auth-challenge-123", "response": {"id": "dGVzdA=="}},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Login verification failed"

    def test_browser_assert_inactive_user_401(self):
        """Browser login path maps the same gate refusal to 401 — NOT the
        generic 500 'Failed to create session' handler below it."""
        from core.iam.session_manager import UserNotActiveError
        from server.routes import auth_browser as ab_routes

        fido2 = MagicMock()
        fido2.finish_authentication.return_value = {"user_id": "user1", "credential_id": b"cred"}
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()

        app = _create_test_app(fido2_manager=fido2, backend=backend)
        app.include_router(ab_routes.router, prefix="/api/v1")

        with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
            "core.iam.role_manager.RoleManager"
        ) as mock_rm, patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}):
            mock_sm.return_value.create_session.side_effect = UserNotActiveError("user1", "pending_enrollment")
            mock_rm.return_value.get_user_roles.return_value = []
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/browser/assert",
                json={"challenge_id": "c", "response": {"id": "dGVzdA==", "response": {}}},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Login verification failed"

    def test_gate_blocks_elevation_transitively(self):
        """CONFIRM-not-assume (user ruling 2026-09-20): elevate authenticates
        against an EXISTING session; a gate-refused login issues no token, so
        the elevate path is unreachable for a disabled/pending user — no
        session, no elevation (401 Missing authentication token)."""
        from server.routes import auth_elevation as ae_routes

        app = _create_test_app(backend=MagicMock())
        app.include_router(ae_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/elevate/challenge", json={})
        assert resp.status_code == 401
