# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for auth (WebAuthn) endpoints."""

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.fido2.manager import Fido2Manager, StoredCredential
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


class TestAuthRegistrationStart:
    """Tests for registration start endpoint."""

    def test_start_success(self):
        """POST /auth/registration/start should return challenge options."""
        fido2 = MagicMock()
        fido2.store.get_user_credentials.return_value = []
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


class TestRegistrationStartExclude:
    """Truth table for the exclude-list build in /auth/registration/start.

    Ticket registration-start-existing-credential-typeerror: auth.py built the
    exclude list from the dict-view get_user_credentials (b64 STR ids) and passed
    them to start_registration, which does base64.b64encode(cid) expecting BYTES
    -> TypeError -> 500 for any user with an existing credential. First-credential
    registration passes an empty list, so the mock suite never caught it. Real
    Fido2Manager here (not a mock): a mocked start_registration cannot trigger the
    b64encode(str) TypeError.
    """

    def _app(self):
        fm = Fido2Manager(rp_id="localhost", rp_name="Venya")
        return _create_test_app(fido2_manager=fm), fm

    def test_first_credential_empty_exclude(self):
        """Fresh user (no existing creds) -> 200, empty exclude list."""
        app, _fm = self._app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/start",
            json={"user_id": "u1", "username": "alice"},
        )
        assert resp.status_code == 200, resp.text
        assert not resp.json()["options"].get("excludeCredentials")

    def test_subsequent_credential_populates_exclude_no_typeerror(self):
        """User with an existing credential -> 200 (pre-fix: 500 TypeError);
        exclude carries the stored id as correct standard base64."""
        app, fm = self._app()
        cred_id = b"\xaa" * 32
        fm.store.store_credential(StoredCredential(user_id="u1", credential_id=cred_id, public_key=b"k"))
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/start",
            json={"user_id": "u1", "username": "alice"},
        )
        assert resp.status_code == 200, resp.text  # pre-fix: 500 (b64encode of str)
        exclude = resp.json()["options"]["excludeCredentials"]
        assert len(exclude) == 1
        assert exclude[0]["id"] == base64.b64encode(cred_id).decode("ascii")


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
        # base64url of b"cred-123", padding stripped (venya response convention)
        assert data["credential_id"] == "Y3JlZC0xMjM"
        # Verify credential was added to DB via backend
        assert backend.get_session.return_value.add.called

    def test_complete_no_backend(self):
        """POST /auth/registration/complete must fail without backend — credential must be persisted."""
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
        assert resp.status_code == 503
        assert "Backend not initialized" in resp.json()["detail"]

    def test_complete_invalid_challenge(self):
        """POST /auth/registration/complete should return 400 for invalid challenge."""
        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")
        # backend present so get_db DI resolves; test targets the fido2 error path (D-6)
        app = _create_test_app(fido2_manager=fido2, backend=MagicMock())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={
                "challenge_id": "expired",
                "response": {},
            },
        )
        assert resp.status_code == 400

    def test_complete_non_utf8_id_no_500(self):
        """A real (non-UTF-8) credential ID must serialize, not 500.

        Regression for auth-registration-complete-bytes-500: cred.credential_id
        is raw bytes; handing it to a pydantic str field UTF-8-decodes it and
        raises on binary IDs. Fix emits base64url.
        """
        raw_id = b"\xbb" * 32
        cred = SimpleNamespace(
            credential_id=raw_id,
            user_id="user1",
            public_key=b"public-key-data",
            sign_count=0,
        )
        fido2 = MagicMock()
        fido2.finish_registration.return_value = cred
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={"challenge_id": "c", "response": {"id": "dGVzdA==", "response": {}}},
        )
        assert resp.status_code == 201
        cid = resp.json()["credential_id"]
        expected = base64.urlsafe_b64encode(raw_id).rstrip(b"=").decode("ascii")
        assert cid == expected
        # base64url alphabet only: no '+', '/', and padding stripped (no '=')
        assert not any(ch in cid for ch in "+/=")
        # round-trips back to the exact raw bytes
        pad = "=" * ((4 - len(cid) % 4) % 4)
        assert base64.urlsafe_b64decode(cid + pad) == raw_id

    def test_complete_id_with_b64_special_chars_is_urlsafe(self):
        """An ID whose STANDARD b64 contains '+' and '/' must emit base64url.

        Proves the alphabet flip (not just padding): the same bytes that would
        yield '+'/'/' under base64.b64encode come back as '-'/'_' with no '='.
        """
        raw_id = bytes([0xFB, 0xEF, 0xBE, 0xFF] * 8)  # 32 bytes
        # sanity: these bytes genuinely exercise the alphabet delta
        std = base64.b64encode(raw_id).decode("ascii")
        assert "+" in std and "/" in std

        cred = SimpleNamespace(
            credential_id=raw_id,
            user_id="user1",
            public_key=b"public-key-data",
            sign_count=0,
        )
        fido2 = MagicMock()
        fido2.finish_registration.return_value = cred
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(fido2_manager=fido2, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/auth/registration/complete",
            json={"challenge_id": "c", "response": {"id": "dGVzdA==", "response": {}}},
        )
        assert resp.status_code == 201
        cid = resp.json()["credential_id"]
        assert not any(ch in cid for ch in "+/=")
        pad = "=" * ((4 - len(cid) % 4) % 4)
        assert base64.urlsafe_b64decode(cid + pad) == raw_id


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
        """POST /auth/refresh should return new access token."""
        session_mock = SimpleNamespace(id=1, access_token="old-token", access_token_jti="uuid-hex")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session_mock

        new_token_mock = SimpleNamespace(token="new-access-token")

        backend = MagicMock()
        backend.get_session.return_value = db

        with patch("core.iam.session_manager.SessionManager") as mock_sm:
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
