# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for secrets CRUD endpoints."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import secrets as secrets_routes
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

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


def _build_orm_backed_app(tmp_path):
    """Build a test app with a REAL Core + Backend over SQLite (zero mocks).

    Exercises the exact path the unit mocks hid: core.list() returns real
    SecretRecord objects into the shared response loop. A MagicMock record
    auto-generates .meta and masks the AttributeError a real record raised.

    Backend._create_engine is bypassed: it issues PostgreSQL-only SET pragmas
    that break SQLite. The real engine + session factory are injected instead.
    """
    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE, encrypt_secret
    from core.iam.models import Base, Role, Secret, SecretRole, User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_path = tmp_path / "list_meta.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    s = SessionLocal()
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"top-secret")
    user = User(user_id="user1")
    role = Role(name="dev", permissions="read-write")
    s.add_all([user, role])
    s.flush()
    secret = Secret(
        key="db-password",
        encrypted_value=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        key_version_id="v1",
        created_by="user1",
        meta={"executor": "web-server-3", "purpose": "ssh_login"},
    )
    s.add(secret)
    s.flush()
    s.add(SecretRole(secret_id=secret.id, role_id=role.id))
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal
    core = backend.get_core()

    # Build the app directly: the shared _create_test_app patch-mocks
    # backend.get_session, which a real Backend must not have replaced.
    app = FastAPI()
    app.state.core = core
    app.state.backend = backend
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    return app, engine


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
            meta={},
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

    def test_list_no_filter_returns_metadata_orm_backed(self, tmp_path):
        """Bare GET /secrets (no filters) returns metadata via the real core.list path.

        Regression: SecretRecord had no .meta field, so the shared response
        loop's `r.meta if r.meta is not None else {}` raised AttributeError ->
        HTTP 500 on the bare-list path. Unit tests used a MagicMock record
        (which auto-generates .meta) and masked the bug; the physical 4d run
        caught it.
        """
        app, engine = _build_orm_backed_app(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        secret = data["secrets"][0]
        assert secret["key"] == "db-password"
        assert secret["metadata"] == {"executor": "web-server-3", "purpose": "ssh_login"}
        engine.dispose()


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
        rm.get_user_permissions.side_effect = AssertionError("role lookup must not run for executors")
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


class TestSecretsMetadata:
    """Tests for secret metadata feature."""

    def test_post_secret_with_metadata(self):
        """POST /secrets should store and return metadata."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session
        app = _create_test_app(core=core, backend=backend)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
                "metadata": {"executor": "web-server-3", "purpose": "ssh_login"},
            },
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["metadata"] == {"executor": "web-server-3", "purpose": "ssh_login"}

    def test_post_secret_without_metadata(self):
        """POST /secrets without metadata should return None."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        backend.get_session.return_value = mock_session
        app = _create_test_app(core=core, backend=backend)
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

        assert resp.status_code == 201
        data = resp.json()
        assert data["key"] == "db-password"
        assert data["metadata"] == {}

    def test_create_metadata_with_custom_fields(self):
        """Create with standard + custom metadata fields. extra='allow' survives."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
                "metadata": {
                    "executor": "web-server-3",
                    "custom_port": 5432,
                    "environment": "prod",
                },
            },
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["metadata"]["executor"] == "web-server-3"
        assert data["metadata"]["custom_port"] == 5432
        assert data["metadata"]["environment"] == "prod"

    def test_create_metadata_invalid_type_returns_422(self):
        """Create with non-string executor → 422, not a silent store."""
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "db-password",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
                "metadata": {"executor": 123},
            },
        )

        assert resp.status_code == 422

    def test_filter_by_executor(self):
        """GET /secrets?executor= should filter by executor metadata."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret1 = MagicMock()
        mock_secret1.id = 1
        mock_secret1.key = "secret-1"
        mock_secret1.key_version_id = "v1"
        mock_secret1.created_by = "user1"
        mock_secret1.created_at = None
        mock_secret1.role_names = ["dev"]
        mock_secret1.meta = {"executor": "web-server-3"}
        mock_secret1.roles = []
        mock_secret2 = MagicMock()
        mock_secret2.id = 2
        mock_secret2.key = "secret-2"
        mock_secret2.key_version_id = "v1"
        mock_secret2.created_by = "user1"
        mock_secret2.created_at = None
        mock_secret2.role_names = ["dev"]
        mock_secret2.meta = {"executor": "other-server"}
        mock_secret2.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret1]
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "secret-1"
        assert data["secrets"][0]["metadata"] == {"executor": "web-server-3"}

    def test_filter_by_purpose(self):
        """GET /secrets?purpose= should filter by purpose metadata."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "api-key"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "user1"
        mock_secret.created_at = None
        mock_secret.role_names = ["dev"]
        mock_secret.meta = {"purpose": "api_key"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret]
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"purpose": "api_key"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "api-key"

    def test_filter_combined_executor_and_purpose(self):
        """GET /secrets?executor=&purpose= should AND-combine filters."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "ssh-key"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "user1"
        mock_secret.created_at = None
        mock_secret.role_names = ["dev"]
        mock_secret.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret]
        mock_filtered.filter.return_value = mock_filtered  # chain filter calls
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets",
            params={"executor": "web-server-3", "purpose": "ssh_login"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "ssh-key"

    def test_patch_metadata_merge(self):
        """PATCH /secrets/{key}/metadata should merge with existing metadata."""
        core = MagicMock()
        core.get.return_value = "\u2022" * 8
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "db-password"
        mock_secret.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = mock_secret
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.patch(
            "/api/v1/secrets/db-password/metadata",
            json={"metadata": {"username": "bot"}},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["executor"] == "web-server-3"
        assert data["metadata"]["purpose"] == "ssh_login"
        assert data["metadata"]["username"] == "bot"

    def test_patch_metadata_overwrites(self):
        """PATCH /secrets/{key}/metadata should overwrite existing fields."""
        core = MagicMock()
        core.get.return_value = "\u2022" * 8
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "db-password"
        mock_secret.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = mock_secret
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.patch(
            "/api/v1/secrets/db-password/metadata",
            json={"metadata": {"purpose": "api_key"}},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["executor"] == "web-server-3"
        assert data["metadata"]["purpose"] == "api_key"

    def test_patch_metadata_not_found(self):
        """PATCH /secrets/{key}/metadata should return 404 for missing secret."""
        core = MagicMock()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.patch(
            "/api/v1/secrets/missing-key/metadata",
            json={"metadata": {"executor": "web-server-3"}},
        )

        assert resp.status_code == 404

    def test_patch_metadata_db_error_returns_500(self):
        """PATCH triggering a DB failure → 500, not 'Secret not found'."""
        core = MagicMock()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "db-password"
        mock_secret.meta = {"executor": "web-server-3"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = mock_secret
        mock_session.query.return_value = mock_query
        mock_session.commit.side_effect = Exception("constraint violation")
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.patch(
            "/api/v1/secrets/db-password/metadata",
            json={"metadata": {"username": "bot"}},
        )

        assert resp.status_code == 500
        assert "Secret not found" not in resp.text

    def test_list_secrets_returns_metadata(self):
        """GET /secrets should include metadata in response."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 42
        mock_secret.key = "test-key"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "user1"
        mock_secret.created_at = None
        mock_secret.role_names = ["dev"]
        mock_secret.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret]
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["metadata"]["executor"] == "web-server-3"
        assert data["secrets"][0]["metadata"]["purpose"] == "ssh_login"

    def test_cross_user_list_with_metadata_filter(self):
        """Cross-user isolation: metadata-filter path returns same results as no-filter.

        The authorization model is role-gated, not user-scoped. Any user with
        ``read`` permission sees all secrets matching the filter, regardless of
        which user created them. This is intentional for the alpha LLM discovery
        flow (operator stores a secret, LLM lists by executor to find it).

        This test pins the current semantics so a future change to user-scoping
        fails loudly instead of silently.
        """
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "admin-credentials"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "admin-user"
        mock_secret.created_at = None
        mock_secret.role_names = ["admin"]
        mock_secret.meta = {"executor": "web-server-3"}
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret]
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "admin-credentials"

    def test_list_null_meta_returns_empty_object(self):
        """List where stored meta is NULL → {}, not missing key or null."""
        core = _make_mock_core()
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "legacy-secret"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "user1"
        mock_secret.created_at = None
        mock_secret.role_names = ["dev"]
        mock_secret.meta = None  # NULL from DB (legacy row)
        mock_secret.roles = []
        mock_query = MagicMock()
        mock_filtered = MagicMock()
        mock_filtered.all.return_value = [mock_secret]
        mock_query.filter.return_value = mock_filtered
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert "metadata" in data["secrets"][0]
        assert data["secrets"][0]["metadata"] == {}
