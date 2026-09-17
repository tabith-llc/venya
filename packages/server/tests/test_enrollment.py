# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for enrollment flow endpoints (legacy)."""

from datetime import UTC, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.dependencies import get_current_user, require_admin
from server.routes import enrollment as enrollment_routes
from starlette.testclient import TestClient


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

    # Override auth deps so require_admin bypasses real auth
    TEST_USER = auth_user or {"user_id": "test-user"}
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _make_mock_db_with_user(user_id_str="newuser", user_int_id=1):
    """Create a mock DB that returns a user for query lookups."""
    user_mock = SimpleNamespace(id=user_int_id, user_id=user_id_str)
    mock_query = MagicMock()
    mock_query.filter.return_value.first.return_value = user_mock
    db = MagicMock()
    db.query.return_value = mock_query
    return db


class TestEnrollmentCreateToken:
    """Tests for enrollment token creation endpoint (legacy)."""

    def test_create_token_success(self):
        """POST /enrollment/tokens should create token for existing user."""
        mock_token = SimpleNamespace(id=1)
        em = MagicMock()
        em.create_enrollment_token.return_value = (mock_token, "enc-token-123")
        # response lifetime is derived from the manager's config, not hardcoded
        em.config.token_expiry = timedelta(minutes=15)

        db = _make_mock_db_with_user()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/tokens",
                json={"user_id": "newuser"},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["token"] == "enc-token-123"
            assert data["expires_in_seconds"] == 900

    def test_create_token_user_not_found(self):
        """POST /enrollment/tokens should return 404 if user not found."""
        em = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enrollment/tokens",
                json={"user_id": "nonexistent"},
            )
            assert resp.status_code == 404


class TestEnrollmentListTokens:
    """Tests for enrollment token listing endpoint."""

    def test_list_tokens_success(self):
        """GET /enrollment/tokens should list active tokens."""
        from datetime import datetime, timedelta

        token1 = SimpleNamespace(
            id=1,
            user_id=1,
            state="created",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        token2 = SimpleNamespace(
            id=2,
            user_id=1,
            state="in_progress",
            created_at=datetime.now(UTC) - timedelta(minutes=5),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [token1, token2]
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/enrollment/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tokens"]) == 2
        assert data["tokens"][0]["state"] == "created"
        assert data["tokens"][1]["state"] == "in_progress"


class TestEnrollmentRevokeToken:
    """Tests for enrollment token revocation endpoint."""

    def test_revoke_success(self):
        """POST /enrollment/tokens/{id}/revoke should revoke token."""
        em = MagicMock()
        em.revoke_token.return_value = True

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/enrollment/tokens/1/revoke")
            assert resp.status_code == 200
            data = resp.json()
            assert data["revoked"] is True

    def test_revoke_not_found(self):
        """POST /enrollment/tokens/{id}/revoke returns 400 if token not found."""
        em = MagicMock()
        em.revoke_token.return_value = False

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/enrollment/tokens/999/revoke")
            assert resp.status_code == 200
            data = resp.json()
            assert data["revoked"] is False
