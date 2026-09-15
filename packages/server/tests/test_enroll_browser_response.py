# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for server enroll/browser/complete response carries session_token + user_id."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.enrollment_manager import EnrollmentManager
from fastapi import FastAPI
from server.routes import enroll
from starlette.testclient import TestClient


def _create_test_app(fido2_manager=None, backend=None, config=None):
    """Create a minimal test app with browser enrollment routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if fido2_manager is None:
        fido2_manager = MagicMock()
    app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    if config is not None:
        app.state.config = config
    app.include_router(enroll.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestBrowserEnrollCompleteResponseFields:
    """Verify POST /enroll/browser/complete returns session_token + user_id."""

    def test_enroll_complete_returns_session_token_and_user_id(self):
        """Response includes session_token and user_id (in addition to status)."""

        mock_token = SimpleNamespace(
            user_id=1,
            state="in_progress",
            token_hash="test-token-hash-00000000000000000000000000000000000000000000000000000000000000000000000",
            binding_hash="test-binding-hash-0000000000000000000000000000000000000000000000000000000000000000",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(
            id=1,
            user_id="newuser",
            status="pending_enrollment",
            display_name="New User",
            roles=[],
        )
        mock_cred = SimpleNamespace(
            user_id="1",
            credential_id=b"cred-123",
            public_key=b"pub-key",
            sign_count=0,
        )
        mock_session = SimpleNamespace(id=1)
        mock_access_token = SimpleNamespace(token="access-token-xyz")

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token
        mock_em.complete_enrollment.return_value = None

        mock_sm = MagicMock()
        mock_sm.create_session.return_value = (mock_session, mock_access_token)

        mock_filter = MagicMock()
        mock_filter.filter.return_value = mock_filter
        mock_filter.first.return_value = mock_user
        db = MagicMock()
        db.query.return_value = mock_filter

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.return_value = mock_cred

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
                with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                    with patch.object(EnrollmentManager, "complete_enrollment", mock_em.complete_enrollment):
                        with patch("core.iam.session_manager.SessionManager", return_value=mock_sm):
                            client = TestClient(app, raise_server_exceptions=False)
                            resp = client.post(
                                "/api/v1/enroll/browser/complete",
                                json={
                                    "enrollment_token": "test-token",
                                    "challenge_id": "challenge-123",
                                    "response": {"id": "dGVzdA==", "response": {}},
                                    "label": "Primary key",
                                },
                            )
                            assert resp.status_code == 200
                            data = resp.json()
                            assert data["status"] == "ok"
                            assert data["session_token"] == "access-token-xyz"
                            assert data["user_id"] == "newuser"
                            set_cookie = resp.headers.get("set-cookie", "")
                            assert "venya_access_token" in set_cookie
