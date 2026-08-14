"""Tests for browser WebAuthn enrollment endpoints (Phase 2)."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import enroll
from vault.iam.enrollment_manager import EnrollmentManager


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


class TestBrowserEnrollStart:
    """Tests for POST /enroll/browser/start."""

    def test_enroll_start_success(self):
        """Should return WebAuthn challenge for valid token."""
        from vault.iam.enrollment_manager import EnrollmentManager

        # Mock token lookup
        mock_token = SimpleNamespace(
            user_id=1, state="created",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(id=1, user_id="newuser", display_name="New User")

        mock_em = MagicMock()
        mock_em.validate_token_for_start.return_value = mock_token
        mock_em.mark_token_in_progress.return_value = mock_token

        mock_filter = MagicMock()
        mock_filter.first.return_value = mock_user
        db = MagicMock()
        db.query.return_value = mock_filter

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.start_registration.return_value = (
            "challenge-123",
            {
                "challenge": "dGVzdA==",
                "rp": {"id": "localhost", "name": "Venya"},
                "user": {"id": "dW5pdA==", "name": "New User", "displayName": "New User"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "none",
            },
        )

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                with patch.object(EnrollmentManager, "mark_token_in_progress", mock_em.mark_token_in_progress):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/v1/enroll/browser/start",
                        json={"enrollment_token": "test-token"},
                    )
                    assert resp.status_code == 200
                    data = resp.json()
                    assert data["challenge_id"] == "challenge-123"
                    assert "challenge" in data["options"]
                    assert "rp" in data["options"]

    def test_enroll_start_invalid_token(self):
        """Should return 400 for invalid token."""
        from vault.iam.enrollment_manager import EnrollmentError

        mock_em = MagicMock()
        mock_em.validate_token_for_start.side_effect = EnrollmentError("Invalid enrollment token")

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/enroll/browser/start",
                    json={"enrollment_token": "bad-token"},
                )
                assert resp.status_code == 400

    def test_enroll_start_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        mock_token = SimpleNamespace(
            user_id=1, state="created",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.validate_token_for_start.return_value = mock_token
        mock_em.mark_token_in_progress.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "validate_token_for_start", mock_em.validate_token_for_start):
                with patch.object(EnrollmentManager, "mark_token_in_progress", mock_em.mark_token_in_progress):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/v1/enroll/browser/start",
                        json={"enrollment_token": "test-token"},
                    )
                    assert resp.status_code == 503


class TestBrowserEnrollComplete:
    """Tests for POST /enroll/browser/complete."""

    def test_enroll_complete_success(self):
        """Should store credential, activate user, create session."""
        from vault.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1, state="in_progress",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(
            id=1, user_id="newuser", status="pending_enrollment",
            display_name="New User", roles=[],
        )
        mock_cred = SimpleNamespace(
            user_id="1", credential_id=b"cred-123",
            public_key=b"pub-key", sign_count=0,
        )
        mock_session = SimpleNamespace(id=1)
        mock_access_token = SimpleNamespace(token="access-token-xyz")

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token
        mock_em.complete_enrollment.return_value = None

        mock_sm = MagicMock()
        mock_sm.create_session.return_value = (mock_session, mock_access_token)

        mock_filter = MagicMock()
        mock_filter.first.return_value = mock_user
        db = MagicMock()
        db.query.return_value = mock_filter

        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.return_value = mock_cred

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                with patch.object(EnrollmentManager, "complete_enrollment", mock_em.complete_enrollment):
                    with patch("vault.iam.session_manager.SessionManager", return_value=mock_sm):
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
                        # Check session cookie was set
                    set_cookie = resp.headers.get("set-cookie", "")
                    assert "venya_access_token" in set_cookie

    def test_enroll_complete_invalid_challenge(self):
        """Should return 400 for invalid WebAuthn challenge."""
        from vault.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1, state="in_progress",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/v1/enroll/browser/complete",
                    json={
                        "enrollment_token": "test-token",
                        "challenge_id": "expired",
                        "response": {"id": "dGVzdA==", "response": {}},
                        "label": "Primary key",
                    },
                )
                assert resp.status_code == 400

    def test_enroll_complete_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        from vault.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1, state="in_progress",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

        mock_em = MagicMock()
        mock_em.get_token_by_plaintext.return_value = mock_token

        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        with patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None):
            with patch.object(EnrollmentManager, "get_token_by_plaintext", mock_em.get_token_by_plaintext):
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
                assert resp.status_code == 503
