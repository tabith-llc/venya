# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for credential add endpoints (Phase 3)."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import credentials
from starlette.testclient import TestClient


def _create_test_app(fido2_manager=None, backend=None, auth_user=None):
    """Create a minimal test app with credential routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if fido2_manager is not None:
        app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    app.include_router(credentials.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _make_valid_elevation_db():
    """Create a mock DB that returns a valid elevation token."""
    db = MagicMock()

    class MockQuery:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            # Return a truthy object to indicate valid elevation
            return SimpleNamespace(id=1)

    db.query.return_value = MockQuery()
    return db


def _make_invalid_elevation_db():
    """Create a mock DB that returns no elevation token."""
    db = MagicMock()

    class MockQuery:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return None

    db.query.return_value = MockQuery()
    return db


class TestCredentialAddStart:
    """Tests for POST /credentials/add/browser/start."""

    def test_add_start_success(self):
        """Should return WebAuthn challenge for authenticated + elevated user."""
        SimpleNamespace(id=1, user_id="user1", display_name="User")

        mock_query = MagicMock()
        # .query(Model.column).all() returns list of tuples
        mock_query.filter.return_value.all.return_value = []

        db = MagicMock()
        db.query.return_value = mock_query
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.start_registration.return_value = (
            "challenge-456",
            {
                "challenge": "dGVzdA==",
                "rp": {"id": "localhost", "name": "Venya"},
                "user": {"id": "dW5pdA==", "name": "user1", "displayName": "User"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "none",
            },
        )

        app = _create_test_app(fido2_manager=fido2, backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Backup key"},
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenge_id"] == "challenge-456"
        assert "challenge" in data["options"]

    def test_add_start_no_auth(self):
        """Should return 401 if not authenticated."""
        app = _create_test_app(backend=MagicMock(), auth_user=None)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Backup key"},
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 401

    def test_add_start_no_elevation_token(self):
        """Should return 400 if elevation token header is missing."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Backup key"},
        )
        assert resp.status_code == 400
        assert "Elevation token required" in resp.json()["detail"]

    def test_add_start_invalid_elevation_token(self):
        """Should return 401 if elevation token is invalid or expired."""
        db = _make_invalid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Backup key"},
            headers={"X-Elevation-Token": "bad-token"},
        )
        assert resp.status_code == 401
        assert "Invalid or expired elevation token" in resp.json()["detail"]

    def test_add_start_no_fido2(self):
        """Should return 503 if FIDO2 manager not initialized."""
        db = _make_valid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(fido2_manager=MagicMock(), backend=backend, auth_user="user1")
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Backup key"},
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 503
        assert "FIDO2 manager not initialized" in resp.json()["detail"]

    def test_add_start_excludes_existing_credentials(self):
        """Should pass existing credential IDs to FIDO2 start_registration."""
        # .query(Model.column).all() returns tuples: [(col_value,), ...]
        mock_query = MagicMock()
        mock_query.filter.return_value.all.return_value = [
            (b"existing-cred-1",),
            (b"existing-cred-2",),
        ]

        db = MagicMock()
        db.query.return_value = mock_query
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.start_registration.return_value = (
            "challenge-789",
            {
                "challenge": "dGVzdA==",
                "rp": {"id": "localhost"},
                "pubKeyCredParams": [],
                "excludeCredentials": [],
                "timeout": 60000,
                "attestation": "none",
            },
        )

        app = _create_test_app(fido2_manager=fido2, backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": "Third key"},
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        call_args = fido2.start_registration.call_args
        assert call_args[1]["existing_credential_ids"] == [b"existing-cred-1", b"existing-cred-2"]


class TestCredentialAddComplete:
    """Tests for POST /credentials/add/browser/complete."""

    def test_add_complete_success(self):
        """Should store credential, return status ok."""
        mock_cred = SimpleNamespace(
            user_id="user1",
            credential_id=b"new-cred-123",
            public_key=b"pub-key-data",
            sign_count=42,
        )

        db = _make_valid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.return_value = mock_cred

        app = _create_test_app(fido2_manager=fido2, backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["credential_label"] == "Backup key"
        assert db.add.called
        assert db.commit.called

    def test_add_complete_no_auth(self):
        """Should return 401 if not authenticated."""
        app = _create_test_app(backend=MagicMock(), auth_user=None)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 401

    def test_add_complete_no_elevation_token(self):
        """Should return 400 if elevation token header is missing."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
        )
        assert resp.status_code == 400
        assert "Elevation token required" in resp.json()["detail"]

    def test_add_complete_invalid_elevation_token(self):
        """Should return 401 if elevation token is invalid."""
        db = _make_invalid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
            headers={"X-Elevation-Token": "bad-token"},
        )
        assert resp.status_code == 401
        assert "Invalid or expired elevation token" in resp.json()["detail"]

    def test_add_complete_no_fido2(self):
        """Should return 503 if FIDO2 manager not initialized."""
        db = _make_valid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(fido2_manager=MagicMock(), backend=backend, auth_user="user1")
        del app.state.fido2_manager

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 503
        assert "FIDO2 manager not initialized" in resp.json()["detail"]

    def test_add_complete_invalid_webauthn_challenge(self):
        """Should return 400 for invalid WebAuthn challenge."""
        db = _make_valid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.side_effect = ValueError("Challenge not found or expired")

        app = _create_test_app(fido2_manager=fido2, backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "expired-challenge",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Backup key",
            },
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 400
        assert "Challenge not found or expired" in resp.json()["detail"]

    def test_add_complete_stores_credential_correctly(self):
        """Should create WebAuthnCredential with correct fields."""
        mock_cred = SimpleNamespace(
            user_id="user1",
            credential_id=b"cred-bytes",
            public_key=b"pub-key",
            sign_count=10,
        )

        db = _make_valid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db

        fido2 = MagicMock()
        fido2.finish_registration.return_value = mock_cred

        app = _create_test_app(fido2_manager=fido2, backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": "challenge-456",
                "response": {"id": "dGVzdA==", "response": {}},
                "label": "Test key",
            },
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        add_call = db.add.call_args
        cred_obj = add_call[0][0]
        assert cred_obj.user_id == "user1"
        assert cred_obj.credential_id == b"cred-bytes"
        assert cred_obj.public_key == b"pub-key"
        assert cred_obj.sign_count == 10
        assert cred_obj.label == "Test key"
        assert cred_obj.is_active is True


class TestCredentialRemove:
    """Tests for DELETE /credentials/{credential_id}."""

    def test_remove_success(self):
        """Should soft-delete credential and return removed=True."""
        mock_cred = SimpleNamespace(id=5, is_active=True)
        active_creds = [SimpleNamespace(id=1, is_active=True), mock_cred]

        db = MagicMock()

        call_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def with_for_update(self):
                return self

            def all(self):
                call_num[0] += 1
                if call_num[0] == 1:
                    return active_creds
                return [mock_cred]

            def first(self):
                return mock_cred

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db

        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/credentials/5",
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["removed"] is True
        assert data["credential_id"] == 5
        assert mock_cred.is_active is False
        assert db.commit.called

    def test_remove_no_auth(self):
        """Should return 401 if not authenticated."""
        app = _create_test_app(backend=MagicMock(), auth_user=None)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/credentials/5",
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 401

    def test_remove_no_elevation_token(self):
        """Should return 400 if elevation token header is missing."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/credentials/5")
        assert resp.status_code == 400
        assert "Elevation token required" in resp.json()["detail"]

    def test_remove_invalid_elevation_token(self):
        """Should return 401 if elevation token is invalid."""
        db = _make_invalid_elevation_db()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/credentials/5",
            headers={"X-Elevation-Token": "bad-token"},
        )
        assert resp.status_code == 401
        assert "Invalid or expired elevation token" in resp.json()["detail"]

    def test_remove_not_found(self):
        """Should return 404 if credential does not belong to user."""
        db = MagicMock()

        query_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                query_num[0] += 1
                # First call is elevation token check (return valid)
                if query_num[0] == 1:
                    return SimpleNamespace(id=1)
                # Second call is credential lookup (return None)
                return None

            def count(self):
                return 0

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/credentials/999",
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 404
        assert "Credential not found" in resp.json()["detail"]

    def test_remove_last_active_credential(self):
        """Should return 400 if this is the last active credential."""
        mock_cred = SimpleNamespace(id=5, is_active=True)

        db = MagicMock()

        call_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def with_for_update(self):
                return self

            def all(self):
                call_num[0] += 1
                if call_num[0] == 1:
                    return [mock_cred]  # only 1 active credential
                return [mock_cred]

            def first(self):
                return mock_cred

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/credentials/5",
            headers={"X-Elevation-Token": "elev-token-123"},
        )
        assert resp.status_code == 400
        assert "Cannot remove the last active credential" in resp.json()["detail"]
        # Credential should NOT be deactivated (rejection happens before modification)
        assert mock_cred.is_active is True
        assert not db.commit.called


class TestCredentialList:
    """Tests for GET /credentials."""

    def test_list_success(self):
        """Should return list of active credentials ordered by created_at desc."""

        now = datetime.now(UTC)
        cred1 = SimpleNamespace(
            id=1,
            label="Primary key",
            created_at=now,
            last_used_at=now,
        )
        cred2 = SimpleNamespace(
            id=3,
            label="Backup key",
            created_at=now,
            last_used_at=None,
        )
        cred3 = SimpleNamespace(
            id=2,
            label="Work laptop",
            created_at=now,
            last_used_at=now,
        )

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return [cred1, cred2, cred3]

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/credentials")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["credentials"]) == 3
        assert data["credentials"][0]["id"] == 1
        assert data["credentials"][0]["label"] == "Primary key"
        assert data["credentials"][0]["last_used_at"] is not None
        assert data["credentials"][1]["id"] == 3
        assert data["credentials"][1]["label"] == "Backup key"
        assert data["credentials"][1]["last_used_at"] is None
        assert data["credentials"][2]["id"] == 2
        assert data["credentials"][2]["label"] == "Work laptop"

    def test_list_no_auth(self):
        """Should return 401 if not authenticated."""
        app = _create_test_app(backend=MagicMock(), auth_user=None)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/credentials")
        assert resp.status_code == 401

    def test_list_empty(self):
        """Should return empty list when user has no credentials."""
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
        app = _create_test_app(backend=backend, auth_user="user1")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/credentials")
        assert resp.status_code == 200
        data = resp.json()
        assert data["credentials"] == []
