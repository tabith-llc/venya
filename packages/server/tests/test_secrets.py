"""Tests for secrets CRUD endpoints."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

from server.routes import secrets as secrets_routes
from server.dependencies import get_current_user

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Default: every user holds a read-write role.

    All secrets CRUD routes enforce require_role (C-06 adoption). This
    fixture lets existing tests pass the check; tests that need a
    different mapping re-patch server.dependencies.RoleManager.
    """
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


def _create_test_app(core=None, backend=None, auth_user=None):
    """Create a minimal test app with secrets routes.

    Args:
        core: Core instance mock. Pass None to test "core not initialized".
        backend: Backend instance mock. Defaults to a MagicMock so the
            require_role dependency can resolve get_backend.
        auth_user: User dict to set on request state, or None to skip auth.
    """
    app = FastAPI()
    if core is not None:
        app.state.core = core

    if backend is None:
        backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    app.include_router(secrets_routes.router, prefix="/api/v1")

    # Override get_current_user so require_role doesn't need a Bearer token.
    # The real get_current_user checks for an Authorization: Bearer header
    # first; the override bypasses that check and returns a fixed user dict.
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    return app


def _make_mock_core():
    """Create a mock core with realistic behavior."""
    core = MagicMock()

    core.put.return_value = MagicMock(
        id=42,
        key="test-key",
        role_names=["dev"],
    )

    core.get.return_value = "\u2022" * 8

    core.list.return_value = [
        MagicMock(
            id=42,
            key="test-key",
            key_version_id="v1",
            created_by="user1",
            created_at=None,
            role_names=["dev"],
            encrypted_value=b"encrypted",
            nonce=b"nonce",
            wrapped_dek=b"wrapped",
        )
    ]

    core.delete.return_value = True

    return core


class TestSecretsCreate:
    """Tests for secret creation endpoint."""

    def test_create_success(self):
        """POST /secrets should create a secret via core.put()."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
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
        assert data["role_names"] == ["dev"]
        assert data["id"] == 42

        core.put.assert_called_once_with(
            key="db-password",
            value=b"super-secret",
            user_id="test-user",
            role_names=["dev"],
            key_version_id="v1",
        )

    def test_create_unauthenticated(self):
        """POST /secrets should return 401 without auth."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
        # Remove the override to test unauthenticated access
        del app.dependency_overrides[get_current_user]

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
        assert resp.status_code == 401

    def test_create_core_not_initialized(self):
        """POST /secrets should return 503 if core not initialized."""
        app = _create_test_app(core=None)
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
        assert "Core not initialized" in resp.json()["detail"]

    def test_create_core_error(self):
        """POST /secrets should return 400 on core error."""
        core = MagicMock()
        core.put.side_effect = Exception("Role not found: invalid-role")
        app = _create_test_app(core=core)
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
        core = _make_mock_core()
        core.get.return_value = "\u2022" * 8
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password")
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["value"] == "\u2022" * 8
        assert data["masked"] is True

        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=False,
            user_id="test-user",
        )

    def test_get_success_human_unmasked(self):
        """GET /secrets/{key}?unmask=true should return plaintext for human."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"unmask": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["value"] == "plaintext-secret"
        assert data["masked"] is False

    def test_get_success_executor(self):
        """GET /secrets/{key}?caller=executor should return plaintext."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"caller": "executor"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "plaintext-secret"
        assert data["masked"] is False

    def test_get_not_found(self):
        """GET /secrets/{key} should return 404 for missing secret."""
        core = MagicMock()
        core.get.side_effect = Exception("Secret not found: missing-key")
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/missing-key")
        assert resp.status_code == 404


class TestSecretsGetExecutor:
    """Tests for executor secret retrieval endpoint."""

    def test_executor_returns_sentinel_wrapped(self):
        """GET /secrets/{key}/executor should return sentinel-wrapped value."""
        core = MagicMock()
        core.get.return_value = "my-api-key"
        app = _create_test_app(core=core)
        # Override to return executor user_info
        app.dependency_overrides[get_current_user] = lambda: {
            "caller": "executor",
            "executor_id": "exec-1",
        }
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/api-key/executor")
        assert resp.status_code == 200
        data = resp.json()
        assert data["secret_id"] == "api-key"
        assert data["wrapped_value"].startswith("[VENYA:")
        assert data["wrapped_value"].endswith("[/VENYA]")
        assert len(data["detection_hashes"]) >= 1

        core.get.assert_called_once_with(
            secret_key="api-key",
            caller="executor",
        )

    def test_executor_denied_for_human_user(self):
        """GET /secrets/{key}/executor should deny non-executor callers."""
        core = MagicMock()
        core.get.return_value = "my-api-key"
        app = _create_test_app(core=core)
        # Default TEST_USER is human
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/api-key/executor")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Executor mTLS authentication required"

    def test_executor_not_found(self):
        """GET /secrets/{key}/executor should return 404 for missing secret."""
        core = MagicMock()
        core.get.side_effect = Exception("Secret not found: missing-key")
        app = _create_test_app(core=core)
        app.dependency_overrides[get_current_user] = lambda: {
            "caller": "executor",
            "executor_id": "exec-1",
        }
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/missing-key/executor")
        assert resp.status_code == 404


class TestSecretsList:
    """Tests for secrets listing endpoint."""

    def test_list_success(self):
        """GET /secrets should return list of secrets."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "test-key"
        assert data["secrets"][0]["id"] == 42
        assert data["secrets"][0]["role_names"] == ["dev"]

        core.list.assert_called_once_with(
            prefix=None,
            user_id="test-user",
        )

    def test_list_with_prefix(self):
        """GET /secrets?prefix= should filter by prefix."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"prefix": "db-"})
        assert resp.status_code == 200

        core.list.assert_called_once_with(
            prefix="db-",
            user_id="test-user",
        )

    def test_list_empty(self):
        """GET /secrets should return empty list when no secrets."""
        core = MagicMock()
        core.list.return_value = []
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200
        assert resp.json()["secrets"] == []


class TestSecretsDelete:
    """Tests for secret deletion endpoint."""

    def test_delete_success(self):
        """DELETE /secrets/{key} should delete the secret."""
        core = _make_mock_core()
        core.delete.return_value = True
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/db-password")
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"] is True
        assert data["key"] == "db-password"

        core.delete.assert_called_once_with(
            key="db-password",
            user_id="test-user",
        )

    def test_delete_not_found(self):
        """DELETE /secrets/{key} returns 404 for missing or non-owned secret.

        Same response whether the secret doesn't exist or exists under a
        different owner — avoids leaking existence.
        """
        core = MagicMock()
        core.delete.return_value = False
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/missing-key")
        assert resp.status_code == 404

    def test_delete_core_error(self):
        """DELETE /secrets/{key} should return 503 if core not initialized."""
        app = _create_test_app(core=None)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/secrets/db-password")
        assert resp.status_code == 503


class TestSecretsRoleEnforcement:
    """Tests for require_role adoption on secrets CRUD routes (C-06).

    Verifies the dependency is actually wired to the routes: the wrong
    permission tier must be rejected before any core call is made.
    """

    def test_create_denied_for_read_only_user(self):
        """POST /secrets requires read-write; a read-only user gets 403."""
        core = _make_mock_core()
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {1: "read"}
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_test_app(core=core)
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
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"
        core.put.assert_not_called()

    def test_delete_denied_for_read_only_user(self):
        """DELETE /secrets/{key} requires read-write; a read-only user gets 403."""
        core = _make_mock_core()
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {1: "read"}
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_test_app(core=core)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/secrets/db-password")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"
        core.delete.assert_not_called()

    def test_get_denied_for_user_with_no_roles(self):
        """GET /secrets/{key} requires any role; zero roles gets 403."""
        core = _make_mock_core()
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {}
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_test_app(core=core)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/secrets/db-password")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"
        core.get.assert_not_called()

    def test_list_denied_for_user_with_no_roles(self):
        """GET /secrets requires any role; zero roles gets 403."""
        core = _make_mock_core()
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {}
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_test_app(core=core)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/secrets")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"
        core.list.assert_not_called()

    def test_executor_bypasses_role_check(self):
        """Executor (mTLS) passes the role check without a RoleManager lookup."""
        core = _make_mock_core()
        rm = MagicMock()
        rm.get_user_permissions.side_effect = AssertionError(
            "role lookup must not run for executors"
        )
        app = _create_test_app(core=core)
        app.dependency_overrides[get_current_user] = lambda: {
            "caller": "executor",
            "executor_id": "exec-1",
        }
        with patch("server.dependencies.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200
        rm.get_user_permissions.assert_not_called()


class TestRevokeSessionSecrets:
    """Tests for session secret revocation endpoint."""

    def test_revoke_executor_success(self):
        """POST /sessions/{id}/secrets/revoke should work for executor."""
        core = _make_mock_core()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(core=core, backend=backend)

        # Mock AuditEvent import (import is local to the endpoint function)
        mock_audit_event = MagicMock()
        with patch("core.iam.models.AuditEvent", mock_audit_event):
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
        core = _make_mock_core()
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(core=core, backend=backend)

        mock_audit_event = MagicMock()
        with patch("core.iam.models.AuditEvent", mock_audit_event):
            client = TestClient(app, raise_server_exceptions=False)

            resp = client.post(
                "/api/v1/sessions/sess-123/secrets/revoke",
                json={"secret_ids": ["sec-1"]},
            )
            assert resp.status_code == 403
            assert "Executor mTLS authentication required" in resp.json()["detail"]

    def test_get_active_key_version_success(self):
        """GET /key-versions/active should return active key version."""
        backend = MagicMock()
        mock_version = MagicMock()
        mock_version.version_label = "kv-2026-08-16"
        mock_version.created_at = None
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.first.return_value = mock_version
        mock_query.filter.return_value = mock_filtered
        mock_session = MagicMock()
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session
        app = _create_test_app(backend=backend)
        # Re-set after _create_test_app which overwrites it
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/key-versions/active")

        assert resp.status_code == 200
        data = resp.json()
        assert data["key_version_id"] == "kv-2026-08-16"
        assert "created_at" in data

    def test_get_active_key_version_not_found(self):
        """GET /key-versions/active should return 503 if no active version."""
        backend = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None
        mock_session = MagicMock()
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session
        app = _create_test_app(backend=backend)
        # Re-set after _create_test_app which overwrites it
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/key-versions/active")

        assert resp.status_code == 503
        assert "No active key version" in resp.json()["detail"]
