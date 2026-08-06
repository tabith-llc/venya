"""Tests for browser WebAuthn enrollment endpoints."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import enroll


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


class TestGenerateEnrollmentToken:
    """Tests for enrollment token generation."""

    def test_token_has_enrl_prefix(self):
        token = enroll._generate_enrollment_token()
        assert token.startswith("enrl_")

    def test_token_is_base62(self):
        token = enroll._generate_enrollment_token()
        prefix_free = token[5:]  # Remove "enrl_"
        for c in prefix_free:
            assert c in enroll.ALPHABET

    def test_token_has_enough_entropy(self):
        """Token should be at least 26 base62 chars (128-bit entropy)."""
        token = enroll._generate_enrollment_token()
        prefix_free = token[5:]
        assert len(prefix_free) >= 26

    def test_tokens_are_unique(self):
        tokens = {enroll._generate_enrollment_token() for _ in range(100)}
        assert len(tokens) == 100


class TestBrowserEnrollStart:
    """Tests for browser enrollment start endpoint."""

    def test_enroll_start_success(self):
        """POST /enroll/browser should return browser-formatted registration challenge."""
        fido2 = MagicMock()
        fido2.start_registration.return_value = (
            "reg-challenge-123",
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp": {"id": "example.com", "name": "Example"},
                "user": {
                    "id": "dXNlcjEyMw==",  # base64 "user123"
                    "name": "alice",
                    "displayName": "Alice",
                },
                "pubKeyCredParams": [{"type": "public-key", "alg": -257}],
                "attestation": "none",
            },
        )

        db = MagicMock()
        token_mock = MagicMock()
        token_mock.user_id = "user123"
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 0
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        config = MagicMock()
        config.fido2.enrollment_token_ttl = 15

        app = _create_test_app(fido2_manager=fido2, backend=backend, config=config)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_abc123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "reg-challenge-123"
        # Challenge should be base64url (no padding)
        assert "=" not in data["options"]["challenge"]
        # User ID should be base64url
        assert "=" not in data["options"]["user"]["id"]

    def test_enroll_start_invalid_token(self):
        """Should return 400 for invalid token."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_invalid"},
        )
        assert resp.status_code == 400
        assert "Invalid enrollment token" in resp.json()["detail"]

    def test_enroll_start_consumed_token(self):
        """Should return 400 for consumed token."""
        db = MagicMock()
        token_mock = MagicMock()
        token_mock.consumed = True
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_used"},
        )
        assert resp.status_code == 400
        assert "already been used" in resp.json()["detail"]

    def test_enroll_start_expired_token(self):
        """Should return 400 for expired token."""
        db = MagicMock()
        token_mock = MagicMock()
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_expired"},
        )
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"]

    def test_enroll_start_rate_limited(self):
        """Should return 400 after 3 failed attempts."""
        db = MagicMock()
        token_mock = MagicMock()
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 3
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_locked"},
        )
        assert resp.status_code == 400
        assert "invalidated" in resp.json()["detail"]

    def test_enroll_start_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        db = MagicMock()
        token_mock = MagicMock()
        token_mock.user_id = "user123"
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 0
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser",
            json={"token": "enrl_test"},
        )
        assert resp.status_code == 503


class TestBrowserEnrollComplete:
    """Tests for browser enrollment complete endpoint."""

    def test_enroll_complete_success(self):
        """POST /enroll/browser/complete should store credential and consume token."""
        fido2 = MagicMock()
        cred_mock = SimpleNamespace(
            credential_id="cred-123",
            user_id="user123",
            credential_data={
                "raw_id": "dGVzdA==",
                "response": {"clientDataJSON": "abc"},
                "transports": ["internal"],
            },
            transports=["internal"],
        )
        fido2.finish_registration.return_value = cred_mock

        db = MagicMock()
        token_mock = MagicMock()
        token_mock.user_id = "user123"
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 0

        user_mock = SimpleNamespace(user_id="user123", auth_mode="pending", enrolled_at=None)

        # Track query calls to return different objects
        query_calls = [0]

        def make_filter_side_effect(model):
            def filter_side_effect(*args, **kwargs):
                def first():
                    query_calls[0] += 1
                    if query_calls[0] == 1:
                        return token_mock
                    return user_mock
                return MagicMock(first=first)
            return filter_side_effect

        db.query.side_effect = lambda model: MagicMock(filter=make_filter_side_effect(model))

        backend = MagicMock()
        backend.get_session.return_value = db

        config = MagicMock()
        config.fido2.enrollment_token_ttl = 15

        app = _create_test_app(fido2_manager=fido2, backend=backend, config=config)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/complete",
            json={
                "token": "enrl_abc123",
                "challenge_id": "reg-challenge-123",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["user_id"] == "user123"
        assert token_mock.consumed is True

    def test_enroll_complete_invalid_challenge(self):
        """Should increment failed attempts on invalid challenge."""
        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")

        db = MagicMock()
        token_mock = MagicMock()
        token_mock.user_id = "user123"
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 0
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(fido2_manager=fido2, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/complete",
            json={
                "token": "enrl_abc123",
                "challenge_id": "bad-challenge",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 400
        assert token_mock.failed_attempts == 1

    def test_enroll_complete_no_fido2(self):
        """Should return 503 if FIDO2 not initialized."""
        db = MagicMock()
        token_mock = MagicMock()
        token_mock.user_id = "user123"
        token_mock.consumed = False
        token_mock.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token_mock.failed_attempts = 0
        db.query.return_value.filter.return_value.first.return_value = token_mock

        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend)
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/enroll/browser/complete",
            json={
                "token": "enrl_abc123",
                "challenge_id": "chal-1",
                "response": {"id": "dGVzdA=="},
            },
        )
        assert resp.status_code == 503
