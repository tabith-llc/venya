"""Tests for secrets CRUD endpoints."""

from unittest.mock import MagicMock, patch

from fastapi import FastAPI, APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

from server.routes import secrets as secrets_routes


def _create_test_app(vault=None, backend=None, auth_user=None):
    """Create a minimal test app with secrets routes.

    Args:
        vault: Vault instance mock. Pass None to test "vault not initialized".
        backend: Backend instance mock.
        auth_user: User dict to set on request state, or None to skip auth.
    """
    app = FastAPI()
    if vault is not None:
        app.state.vault = vault

    if backend is not None:
        backend.get_session.return_value = MagicMock()
        app.state.backend = backend

    app.include_router(secrets_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)

    return app


def _make_mock_vault():
    """Create a mock vault with realistic behavior."""
    vault = MagicMock()

    vault.put.return_value = MagicMock(
        id=42,
        key="test-key",
        role_ids=["dev"],
    )

    vault.get.return_value = "\u2022" * 8

    vault.list.return_value = [
        MagicMock(
            id=42,
            key="test-key",
            key_version_id="v1",
            created_by="user1",
            created_at=None,
            role_ids=["dev"],
            encrypted_value=b"encrypted",
            nonce=b"nonce",
            wrapped_dek=b"wrapped",
        )
    ]

    vault.delete.return_value = True

    return vault


class TestSecretsCreate:
    """Tests for secret creation endpoint."""

    def test_create_success(self):
        """POST /secrets should create a secret via vault.put()."""
        vault = _make_mock_vault()
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "super-secret",
                "roles": ["dev"],
                "key_version_id": "v1",
            },
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["role_ids"] == ["dev"]
        assert data["id"] == 42

        vault.put.assert_called_once_with(
            key="db-password",
            value=b"super-secret",
            user_id="test-user",
            role_ids=["dev"],
            key_version_id="v1",
        )

    def test_create_unauthenticated(self):
        """POST /secrets should return 401 without auth."""
        vault = _make_mock_vault()
        app = _create_test_app(vault=vault)

        # Remove auth_user from request state by not adding middleware
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
            },
        )
        # Without auth middleware, auth_user is None -> 401
        assert resp.status_code == 401

    def test_create_vault_not_initialized(self):
        """POST /secrets should return 503 if vault not initialized."""
        app = _create_test_app(vault=None, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
            },
        )
        assert resp.status_code == 503
        assert "Vault not initialized" in resp.json()["detail"]

    def test_create_vault_error(self):
        """POST /secrets should return 400 on vault error."""
        vault = MagicMock()
        vault.put.side_effect = Exception("Role not found: invalid-role")
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["invalid-role"],
                "key_version_id": "v1",
            },
        )
        assert resp.status_code == 400
        assert "Role not found" in resp.json()["detail"]


class TestSecretsGet:
    """Tests for secret retrieval endpoint."""

    def test_get_success_human_masked(self):
        """GET /secrets/{key} should return masked value for human."""
        vault = _make_mock_vault()
        vault.get.return_value = "\u2022" * 8
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password")
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["value"] == "\u2022" * 8
        assert data["masked"] is True

        vault.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=False,
            user_id="test-user",
        )

    def test_get_success_human_unmasked(self):
        """GET /secrets/{key}?unmask=true should return plaintext for human."""
        vault = _make_mock_vault()
        vault.get.return_value = "plaintext-secret"
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"unmask": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["value"] == "plaintext-secret"
        assert data["masked"] is False

    def test_get_success_executor(self):
        """GET /secrets/{key}?caller=executor should return plaintext."""
        vault = _make_mock_vault()
        vault.get.return_value = "plaintext-secret"
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"caller": "executor"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "plaintext-secret"
        assert data["masked"] is False

    def test_get_not_found(self):
        """GET /secrets/{key} should return 404 for missing secret."""
        vault = MagicMock()
        vault.get.side_effect = Exception("Secret not found: missing-key")
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/missing-key")
        assert resp.status_code == 404


class TestSecretsGetExecutor:
    """Tests for executor secret retrieval endpoint."""

    def test_executor_returns_sentinel_wrapped(self):
        """GET /secrets/{key}/executor should return sentinel-wrapped value."""
        vault = MagicMock()
        vault.get.return_value = "my-api-key"
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/api-key/executor")
        assert resp.status_code == 200
        data = resp.json()
        assert data["secret_id"] == "api-key"
        assert data["wrapped_value"].startswith("[VENYA:")
        assert data["wrapped_value"].endswith("[/VENYA]")
        assert len(data["detection_hashes"]) >= 1

        vault.get.assert_called_once_with(
            secret_key="api-key",
            caller="executor",
        )

    def test_executor_not_found(self):
        """GET /secrets/{key}/executor should return 404 for missing secret."""
        vault = MagicMock()
        vault.get.side_effect = Exception("Secret not found: missing-key")
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/missing-key/executor")
        assert resp.status_code == 404


class TestSecretsList:
    """Tests for secrets listing endpoint."""

    def test_list_success(self):
        """GET /secrets should return list of secrets."""
        vault = _make_mock_vault()
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "test-key"
        assert data["secrets"][0]["id"] == 42
        assert data["secrets"][0]["role_ids"] == ["dev"]

        vault.list.assert_called_once_with(
            prefix=None,
            user_id="test-user",
        )

    def test_list_with_prefix(self):
        """GET /secrets?prefix= should filter by prefix."""
        vault = _make_mock_vault()
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"prefix": "db-"})
        assert resp.status_code == 200

        vault.list.assert_called_once_with(
            prefix="db-",
            user_id="test-user",
        )

    def test_list_empty(self):
        """GET /secrets should return empty list when no secrets."""
        vault = MagicMock()
        vault.list.return_value = []
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200
        assert resp.json()["secrets"] == []


class TestSecretsDelete:
    """Tests for secret deletion endpoint."""

    def test_delete_success(self):
        """DELETE /secrets/{key} should delete the secret."""
        vault = _make_mock_vault()
        vault.delete.return_value = True
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/db-password")
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"] is True
        assert data["key"] == "db-password"

        vault.delete.assert_called_once_with(
            key="db-password",
            user_id="test-user",
        )

    def test_delete_not_found(self):
        """DELETE /secrets/{key} should return deleted=false for missing secret."""
        vault = MagicMock()
        vault.delete.return_value = False
        app = _create_test_app(vault=vault, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/missing-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"] is False

    def test_delete_vault_error(self):
        """DELETE /secrets/{key} should return 503 if vault not initialized."""
        app = _create_test_app(vault=None, auth_user={"user_id": "test-user"})
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/db-password")
        assert resp.status_code == 503


class TestRevokeSessionSecrets:
    """Tests for session secret revocation endpoint."""

    def test_revoke_executor_success(self):
        """POST /sessions/{id}/secrets/revoke should work for executor."""
        vault = _make_mock_vault()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(vault=vault, backend=backend, auth_user=None)

        # Mock AuditEvent import (import is local to the endpoint function)
        mock_audit_event = MagicMock()
        with patch("vault.iam.models.AuditEvent", mock_audit_event):
            # Simulate executor auth via request state
            class ExecutorAuthMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request: Request, call_next):
                    request.state.auth_user = {
                        "caller": "executor",
                        "executor_id": "exec1",
                    }
                    return await call_next(request)

            app.add_middleware(ExecutorAuthMiddleware)
            client = TestClient(app, raise_server_exceptions=False)

            resp = client.post(
                "/api/v1/sessions/sess-123/secrets/revoke",
                json={"secret_ids": ["sec-1", "sec-2"]},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["revoked"] is True
            assert data["count"] == 2
            assert data["session_id"] == "sess-123"

    def test_revoke_non_executor_denied(self):
        """POST /sessions/{id}/secrets/revoke should deny non-executor."""
        vault = _make_mock_vault()
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(vault=vault, backend=backend, auth_user=None)

        mock_audit_event = MagicMock()
        with patch("vault.iam.models.AuditEvent", mock_audit_event):
            client = TestClient(app, raise_server_exceptions=False)

            resp = client.post(
                "/api/v1/sessions/sess-123/secrets/revoke",
                json={"secret_ids": ["sec-1"]},
            )
            assert resp.status_code == 403
            assert "Executor mTLS authentication required" in resp.json()["detail"]
