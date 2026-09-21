# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for secrets CRUD endpoints."""

from unittest.mock import MagicMock, patch

import pytest
from core.engine.core import CoreAccessError
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
        replaced=False,
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
    from core.iam.models import Base, Role, RoleMember, Secret, SecretRole, User
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
    test_user = User(user_id="test-user")
    role = Role(name="dev", permissions="read-write")
    s.add_all([user, test_user, role])
    s.flush()
    s.add(RoleMember(user_id="test-user", role_id=role.id))
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


def _build_scoped_app(tmp_path, member_role: str):
    """ORM-backed app for role-scoping tests (ticket secret-role-scoping-unenforced).

    Dataset: 'admin-credentials' created by admin-user, scoped to role 'admin'.
    TEST_USER ('test-user') is a member of `member_role` ('admin' or 'user').
    Real core.list enforcement — no mocks in the visibility path.
    """
    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE, encrypt_secret
    from core.iam.models import Base, Role, RoleMember, Secret, SecretRole, User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_path = tmp_path / "scoped.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    s = SessionLocal()
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"top-secret")
    admin_role = Role(name="admin", permissions="read-write")
    user_role = Role(name="user", permissions="read")
    s.add_all([User(user_id="admin-user"), User(user_id="test-user"), admin_role, user_role])
    s.flush()
    member = admin_role if member_role == "admin" else user_role
    s.add(RoleMember(user_id="test-user", role_id=member.id))
    secret = Secret(
        key="admin-credentials",
        encrypted_value=ciphertext,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        key_version_id="v1",
        created_by="admin-user",
        meta={"executor": "web-server-3"},
    )
    s.add(secret)
    s.flush()
    s.add(SecretRole(secret_id=secret.id, role_id=admin_role.id))
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.state.core = backend.get_core()
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
            # caller_roles resolved fresh from the DB via RoleManager (upsert
            # visibility context); the mocked role wiring yields []. Real
            # role semantics: TestSecretUpsertRoute + core TestSecretUpsertSqlite.
            caller_roles=[],
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
        core.put.side_effect = CoreAccessError("Role not found: invalid-role")
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

    def test_create_internal_error_not_leaked(self):
        """A non-CoreAccessError exception gets the static detail — internals never echoed."""
        core = MagicMock()
        core.put.side_effect = RuntimeError("connection postgresql://user:pass@db-host/venya refused")
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
        assert resp.json()["detail"] == "Secret creation failed"
        assert "postgresql://" not in resp.text
        assert "db-host" not in resp.text


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

    def test_get_human_unmask_without_token_403(self):
        """Ticket sec-secret-caller-param-plaintext-bypass (bare-unmask half):
        `?unmask=true` WITHOUT an elevation token is a loud 403. The old
        fall-through forwarded unmask=True to core.get and returned plaintext
        — a bypass the former test_get_success_human_unmasked pinned POSITIVE.
        Tests can institutionalize a vulnerability as confidently as they can
        catch one; this rewrite is the paired negative."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"unmask": True})
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Elevation token required to unmask"
        core.get.assert_not_called()

    def test_get_caller_query_param_ignored(self):
        """Ticket sec-secret-caller-param-plaintext-bypass (ticket half):
        `?caller=executor` was client-controlled identity → plaintext (pinned
        POSITIVE by the former test_get_success_executor). The param is GONE
        from the route surface: unknown query params drop, caller stays human,
        output stays masked."""
        core = _make_mock_core()
        core.get.return_value = "\u2022" * 8
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password", params={"caller": "executor"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "\u2022" * 8
        assert data["masked"] is True
        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=False,
            user_id="test-user",
        )

    def test_get_caller_param_plus_unmask_still_403(self):
        """Paired negative — the exact old attack string
        `?caller=executor&unmask=true` from a bearer: human unmask gate →
        403, no core.get, no plaintext in the body."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets/db-password",
            params={"caller": "executor", "unmask": True},
        )
        assert resp.status_code == 403
        assert "plaintext-secret" not in resp.text
        core.get.assert_not_called()

    def test_get_executor_auth_context_never_yields_plaintext(self):
        """DEAD-BRANCH PIN (user ruling 2026-09-20): the route carries NO
        executor branch to forward. Even an auth context shaped EXACTLY like
        the middleware's cert-verified executor grant ({"caller": "executor",
        "executor_id": ...} — set only by `_validate_executor_mtls`,
        middleware/auth.py; cross-branch interlock with
        sec-executor-session-path-no-auth) cannot put caller=executor into
        core.get. Production note: the middleware never grants that shape off
        the session paths, and a real executor carries no user_id (core.get
        would 404); this pin guards the route-side invariant itself."""
        core = _make_mock_core()
        core.get.return_value = "\u2022" * 8
        app = _create_test_app(core=core)
        app.dependency_overrides[get_current_user] = lambda: {
            "caller": "executor",
            "executor_id": "exec-1",
        }
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/db-password")
        assert resp.status_code == 200
        assert resp.json()["masked"] is True
        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=False,
            user_id=None,
        )

    def test_get_unmask_with_valid_token_returns_plaintext(self):
        """Positive: valid unconsumed elevation token (atomic UPDATE
        rowcount==1) → token burned, plaintext returned, masked=False. This
        route's elevation path had NO test coverage before this ticket."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        backend = MagicMock()
        app = _create_test_app(core=core, backend=backend)
        db = backend.get_session.return_value
        db.execute.return_value.rowcount = 1
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets/db-password",
            params={"unmask": True},
            headers={"X-Elevation-Token": "elev-token-xyz"},  # header transport (#13)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "plaintext-secret"
        assert data["masked"] is False
        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=True,
            user_id="test-user",
        )
        db.commit.assert_called()

    def test_get_unmask_token_used_or_expired_masked(self):
        """Paired negative: consumed/expired/foreign token (rowcount==0) →
        masked value, never plaintext, no burn commit."""
        core = _make_mock_core()
        core.get.return_value = "\u2022" * 8
        backend = MagicMock()
        app = _create_test_app(core=core, backend=backend)
        db = backend.get_session.return_value
        db.execute.return_value.rowcount = 0
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets/db-password",
            params={"unmask": True},
            headers={"X-Elevation-Token": "stale-token"},  # header transport (#13)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "\u2022" * 8
        assert data["masked"] is True
        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=False,
            user_id="test-user",
        )

    def test_get_not_found(self):
        """GET /secrets/{key} should return 404 for missing secret."""
        core = MagicMock()
        core.get.side_effect = Exception("Secret not found: missing-key")
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets/missing-key")
        assert resp.status_code == 404

    def test_get_unmask_header_elevation_consumes_token(self):
        """#13: elevation rides the X-Elevation-Token HEADER and the token is
        consumed via the atomic conditional UPDATE (rowcount 1 = burned)."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        db = app.state.backend.get_session.return_value
        db.execute.return_value = MagicMock(rowcount=1)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets/db-password",
            params={"unmask": True},
            headers={"X-Elevation-Token": "tok-header-123"},
        )
        assert resp.status_code == 200
        assert resp.json()["masked"] is False
        assert db.execute.call_count == 1  # the conditional burn ran
        core.get.assert_called_once_with(
            secret_key="db-password",
            caller="human",
            unmask=True,
            user_id="test-user",
        )

    def test_get_elevation_query_param_is_dead_transport(self):
        """#13 negative (merged with #3): elevation_token as a QUERY PARAM is
        not a transport — it persisted tokens in nginx + uvicorn access logs.
        Post-#3 the route is human-only and tokenless unmask is a loud 403
        (sec-secret-caller-param-plaintext-bypass), so the query param now
        lands in the 403 gate with no consume attempted."""
        core = _make_mock_core()
        core.get.return_value = "plaintext-secret"
        app = _create_test_app(core=core)
        db = app.state.backend.get_session.return_value
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets/db-password",
            params={"unmask": True, "elevation_token": "tok-query-123"},
        )
        assert resp.status_code == 403
        db.execute.assert_not_called()  # no burn — query param is not a transport


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
            role_names=[],
            user_id="test-user",
            executor=None,
            purpose=None,
            username=None,
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
            role_names=[],
            user_id="test-user",
            executor=None,
            purpose=None,
            username=None,
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
            # Audit attribution (sec-executor-session-path-no-auth side effect):
            # the middleware now sets executor_id, so audit events carry the
            # real executor identity instead of the historical always-None.
            assert mock_audit_event.call_count == 2
            assert all(c.kwargs["user_id"] == "exec1" for c in mock_audit_event.call_args_list)

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
        """GET /secrets?executor= hands the filter to core.list (enforcement point).

        Real-DB filtering behavior: core suite TestSecretVisibilitySqlite.
        """
        core = _make_mock_core()
        rec = MagicMock()
        rec.id = 1
        rec.key = "secret-1"
        rec.key_version_id = "v1"
        rec.created_by = "user1"
        rec.created_at = None
        rec.role_names = ["dev"]
        rec.meta = {"executor": "web-server-3"}
        core.list.return_value = [rec]
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "secret-1"
        assert data["secrets"][0]["metadata"] == {"executor": "web-server-3"}
        assert core.list.call_args.kwargs["executor"] == "web-server-3"

    def test_filter_by_purpose(self):
        """GET /secrets?purpose= hands the filter to core.list."""
        core = _make_mock_core()
        rec = MagicMock()
        rec.id = 1
        rec.key = "api-key"
        rec.key_version_id = "v1"
        rec.created_by = "user1"
        rec.created_at = None
        rec.role_names = ["dev"]
        rec.meta = {"purpose": "api_key"}
        core.list.return_value = [rec]
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"purpose": "api_key"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "api-key"
        assert core.list.call_args.kwargs["purpose"] == "api_key"

    def test_filter_combined_executor_and_purpose(self):
        """GET /secrets?executor=&purpose= AND-combines — both reach core.list."""
        core = _make_mock_core()
        rec = MagicMock()
        rec.id = 1
        rec.key = "ssh-key"
        rec.key_version_id = "v1"
        rec.created_by = "user1"
        rec.created_at = None
        rec.role_names = ["dev"]
        rec.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        core.list.return_value = [rec]
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(
            "/api/v1/secrets",
            params={"executor": "web-server-3", "purpose": "ssh_login"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["key"] == "ssh-key"
        kwargs = core.list.call_args.kwargs
        assert kwargs["executor"] == "web-server-3"
        assert kwargs["purpose"] == "ssh_login"

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

    def test_patch_metadata_scoped_out_idor_404_no_mutation(self):
        """IDOR negative (sec-auth-elevation-authz-hardening #5, interlock 3):
        scoped-out secret + valid read-write user → 404 indistinguishable from
        nonexistent, and the metadata writer is NEVER touched (no Secret
        query, no meta mutation, no commit) — enforce-first ordering."""
        from core.engine.core import CoreAccessError

        core = MagicMock()
        core.get.side_effect = CoreAccessError("Secret not found: scoped-key")
        backend = MagicMock()
        mock_session = MagicMock()
        mock_secret = MagicMock()
        mock_secret.meta = {"executor": "web-server-3"}
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = mock_secret
        mock_session.query.return_value = mock_query
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.patch(
            "/api/v1/secrets/scoped-key/metadata",
            json={"metadata": {"purpose": "pwned"}},
        )

        assert resp.status_code == 404
        assert resp.json()["detail"] == "Secret not found"
        # enforce-first: the metadata writer never ran (the role-resolution
        # probe may query, but nothing is mutated or committed)
        mock_session.commit.assert_not_called()
        assert mock_secret.meta == {"executor": "web-server-3"}
        # the visibility probe consulted the single enforcement point
        assert core.get.call_count == 1
        assert core.get.call_args.kwargs["secret_key"] == "scoped-key"  # pragma: allowlist secret

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
        rec = MagicMock()
        rec.id = 42
        rec.key = "test-key"
        rec.key_version_id = "v1"
        rec.created_by = "user1"
        rec.created_at = None
        rec.role_names = ["dev"]
        rec.meta = {"executor": "web-server-3", "purpose": "ssh_login"}
        core.list.return_value = [rec]
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["metadata"]["executor"] == "web-server-3"
        assert data["secrets"][0]["metadata"]["purpose"] == "ssh_login"

    def test_cross_user_visibility_requires_shared_role(self, tmp_path):
        """Cross-user visibility is role-scoped (ticket secret-role-scoping-unenforced).

        REPLACES the old pin ("any user with read permission sees all secrets
        regardless of creator") — that semantics was the bug: it made
        --roles scoping decorative. A secret created by another user is
        visible iff one of the caller's roles is in its scope (or the caller
        created it). ORM-backed: real core.list enforcement path.
        """
        app, engine = _build_scoped_app(tmp_path, member_role="admin")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        keys = [s["key"] for s in resp.json()["secrets"]]
        assert "admin-credentials" in keys
        engine.dispose()

    def test_cross_user_out_of_scope_secret_hidden(self, tmp_path):
        """Paired negative: without a scoped role the other user's secret is
        invisible — the list simply omits it (indistinguishable from nonexistent)."""
        app, engine = _build_scoped_app(tmp_path, member_role="user")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets")

        assert resp.status_code == 200
        keys = [s["key"] for s in resp.json()["secrets"]]
        assert "admin-credentials" not in keys
        assert keys == []
        engine.dispose()

    def test_list_null_meta_returns_empty_object(self):
        """List where stored meta is NULL → {}, not missing key or null."""
        core = _make_mock_core()
        rec = MagicMock()
        rec.id = 1
        rec.key = "legacy-secret"
        rec.key_version_id = "v1"
        rec.created_by = "user1"
        rec.created_at = None
        rec.role_names = ["dev"]
        rec.meta = None  # NULL from DB (legacy row)
        core.list.return_value = [rec]
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/secrets", params={"executor": "web-server-3"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["secrets"]) == 1
        assert "metadata" in data["secrets"][0]
        assert data["secrets"][0]["metadata"] == {}


class TestSecretUpsertRoute:
    """Route-level upsert loop (ticket cli-store-force-field-ignored option-2).

    Real Backend over SQLite, real secrets router, real require_role chain —
    2×POST closes the loop at the endpoint, not just the engine.
    """

    def _build_app(self, tmp_path):
        from core.engine.backend import Backend, BackendConfig
        from core.engine.encryption import KEK_SIZE
        from core.iam.models import Base, Role, RoleMember, User
        from fastapi import FastAPI
        from server.dependencies import get_current_user
        from server.routes import secrets as secrets_routes
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from starlette.testclient import TestClient

        db_path = tmp_path / "upsert_route.db"
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        kek = b"k" * KEK_SIZE
        s = SessionLocal()
        role = Role(name="dev", permissions="read-write")
        s.add_all([User(user_id="test-user"), role])
        s.flush()
        s.add(RoleMember(user_id="test-user", role_id=role.id))
        s.commit()
        s.close()

        backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
        backend._engine = engine
        backend._session_factory = SessionLocal

        app = FastAPI()
        app.state.backend = backend
        app.state.core = backend.get_core()
        app.include_router(secrets_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "test-user"}
        return TestClient(app, raise_server_exceptions=False), SessionLocal, kek

    def _payload(self, value, **over):
        body = {"key": "rotating-pw", "value": value, "roles": ["dev"], "key_version_id": "v1"}
        body.update(over)
        return body

    def test_double_post_replaces_in_place(self, tmp_path):
        from core.engine.encryption import decrypt_secret
        from core.iam.models import Secret

        client, SessionLocal, kek = self._build_app(tmp_path)
        r1 = client.post("/api/v1/secrets", json=self._payload("first-value"))
        assert r1.status_code == 201, r1.text
        b1 = r1.json()
        assert b1["replaced"] is False

        r2 = client.post("/api/v1/secrets", json=self._payload("second-value"))
        assert r2.status_code == 201, r2.text
        b2 = r2.json()
        assert b2["replaced"] is True
        assert b2["id"] == b1["id"], "row id must be stable across replace (injection-path contract)"

        with SessionLocal() as s:
            rows = s.query(Secret).filter(Secret.key == "rotating-pw").all()
            assert len(rows) == 1, "replace must not duplicate the row"
            assert decrypt_secret(kek, rows[0].wrapped_dek, rows[0].nonce, rows[0].encrypted_value) == b"second-value"

    def test_scoped_out_caller_inserts_second_row_no_clobber(self, tmp_path):
        """Paired negative at the endpoint: a caller who cannot see the row
        gets a plain insert (identical 201 shape — no existence leak) and the
        original is untouched."""
        from core.engine.encryption import decrypt_secret
        from core.iam.models import Role, RoleMember, Secret, User

        client, SessionLocal, kek = self._build_app(tmp_path)
        r1 = client.post("/api/v1/secrets", json=self._payload("owner-value"))
        assert r1.status_code == 201 and r1.json()["replaced"] is False

        # Second identity: member of a different role, same key string.
        with SessionLocal() as s:
            other_role = Role(name="other", permissions="read-write")
            s.add(other_role)
            s.add(User(user_id="other-user"))
            s.flush()
            s.add(RoleMember(user_id="other-user", role_id=other_role.id))
            s.commit()
        from server.dependencies import get_current_user

        app = client.app
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "other-user"}
        r2 = client.post("/api/v1/secrets", json=self._payload("intruder-value", roles=["other"]))
        assert r2.status_code == 201
        assert r2.json()["replaced"] is False
        assert r2.json()["id"] != r1.json()["id"]

        with SessionLocal() as s:
            rows = s.query(Secret).filter(Secret.key == "rotating-pw").order_by(Secret.id).all()
            assert len(rows) == 2
            assert decrypt_secret(kek, rows[0].wrapped_dek, rows[0].nonce, rows[0].encrypted_value) == b"owner-value"


class TestShapeMetadata:
    """shape/usage metadata convention (ticket secret-shape-metadata).

    Paired cells per the truth-table rule: every accept has a reject twin.
    The reject half is the security-bearing one — a usage template that
    interpolates the secret VALUE must die at authoring time with an
    actionable 400 (institutionalization rule: never bless a bypass shape).
    Warnings are loud-not-fatal (forward-compat for custom shapes).
    """

    def _store(self, metadata):
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/secrets",
            json={
                "key": "shaped-secret",
                "value": "secret",
                "roles": ["dev"],
                "key_version_id": "v1",
                "metadata": metadata,
            },
        )

    def _patch_client(self):
        core = MagicMock()
        core.get.return_value = "\u2022" * 8
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
        app = _create_test_app(core=core, backend=backend)
        backend.get_session.return_value = mock_session
        return TestClient(app, raise_server_exceptions=False), mock_secret, mock_session

    def test_builtin_shape_and_usage_accepted_without_warnings(self):
        resp = self._store(
            {
                "shape": "ssh-password",
                "usage": "sshpass -f {secret_path} ssh {user}@{host} systemctl restart httpd",
            }
        )
        assert resp.status_code == 201
        assert resp.json()["metadata_warnings"] == []

    def test_env_shape_accepted_without_warning(self):
        # env mechanism SHIPPED (secret-shape-env-injection): env: is a builtin
        # taxonomy prefix — the former declarative-only warning left with it.
        resp = self._store({"shape": "env:AWS_SECRET_ACCESS_KEY"})
        assert resp.status_code == 201
        assert resp.json()["metadata_warnings"] == []

    def test_sudo_stdin_shape_accepted_without_warning(self):
        # Mechanism SHIPPED (narrow redirect allowance, ticket
        # secret-shape-sudo-remote option (a)) — the declarative-only warning
        # left with the last MECHANISM_PENDING_SHAPES member.
        resp = self._store({"shape": "sudo-stdin"})
        assert resp.status_code == 201
        assert resp.json()["metadata_warnings"] == []

    def test_mechanism_pending_set_is_empty_pinned(self):
        # Deliberate pin: the pending set is EMPTY — re-adding a shape to it
        # requires a ruling (comment at MECHANISM_PENDING_SHAPES).
        from server.routes.secrets import MECHANISM_PENDING_SHAPES

        assert MECHANISM_PENDING_SHAPES == frozenset()

    def test_env_shape_multiline_value_rejected_400(self):
        # The env-file format is line-based — catch multi-line values at
        # authoring time (loudest, earliest point), before persistence.
        core = _make_mock_core()
        app = _create_test_app(core=core)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/secrets",
            json={
                "key": "multi",
                "value": "line1\nline2",
                "roles": ["dev"],
                "key_version_id": "v1",
                "metadata": {"shape": "env:MY_TOKEN"},
            },
        )
        assert resp.status_code == 400
        assert "single-line" in resp.json()["detail"]
        core.put.assert_not_called()  # rejected before persistence

    def test_file_arg_shapes_never_warn_mechanism(self):
        # File injection ships today; tool availability is a deployment
        # property (sandbox template) the server cannot know — file shapes
        # must stay warning-free.
        for shape in (
            "ssh-password",
            "ssh-key",
            "http-netrc",
            "http-header-file",
            "mysql-defaults",
            "ipmi-passfile",
        ):
            resp = self._store({"shape": shape})
            assert resp.status_code == 201, shape
            assert resp.json()["metadata_warnings"] == [], shape

    def test_custom_shape_accepted_with_teaching_warning(self):
        resp = self._store({"shape": "internal-vault-cli"})
        assert resp.status_code == 201
        warnings = resp.json()["metadata_warnings"]
        assert len(warnings) == 1
        assert "CUSTOM shape" in warnings[0]
        # the warning teaches the fix: add a usage template
        assert "usage" in warnings[0] and "{secret_path}" in warnings[0]

    def test_custom_shape_with_usage_omits_the_nag(self):
        resp = self._store({"shape": "internal-vault-cli", "usage": "vaulttool --cred-file {secret_path} run"})
        assert resp.status_code == 201
        warnings = resp.json()["metadata_warnings"]
        assert len(warnings) == 1
        assert "Add 'usage'" not in warnings[0]

    def test_value_placeholder_rejected_400_with_actionable_detail(self):
        for bad in ("{value}", "{secret_value}", "{plaintext}", "{password}", "{token}", "{credential}"):
            resp = self._store({"shape": "ssh-password", "usage": f"tool --pass {bad} run"})
            assert resp.status_code == 400, bad
            detail = resp.json()["detail"]
            assert "{secret_path}" in detail  # names the right way
            assert "UNMASKED" in detail  # names the WHY

    def test_unknown_placeholder_warns_not_fails(self):
        resp = self._store({"shape": "ssh-password", "usage": "tool -f {secret_path} --port {port}"})
        assert resp.status_code == 201
        assert any("{port}" in w for w in resp.json()["metadata_warnings"])

    def test_non_string_shape_rejected_400(self):
        resp = self._store({"shape": 42})
        assert resp.status_code == 400
        assert "non-empty string" in resp.json()["detail"]

    def test_no_shape_keys_unchanged_behavior(self):
        resp = self._store({"executor": "web-server-3"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["metadata"] == {"executor": "web-server-3"}
        assert data["metadata_warnings"] == []

    def test_patch_value_placeholder_rejected_before_mutation(self):
        client, mock_secret, mock_session = self._patch_client()
        resp = client.patch(
            "/api/v1/secrets/db-password/metadata",
            json={"metadata": {"usage": "tool --pass {value} run"}},
        )
        assert resp.status_code == 400
        assert "{secret_path}" in resp.json()["detail"]
        # enforce-before-mutate: the row is untouched and nothing committed
        assert mock_secret.meta == {"executor": "web-server-3"}
        mock_session.commit.assert_not_called()

    def test_patch_custom_shape_warns_and_merges(self):
        client, *_ = self._patch_client()
        resp = client.patch(
            "/api/v1/secrets/db-password/metadata",
            json={"metadata": {"shape": "internal-vault-cli", "usage": "vaulttool -f {secret_path}"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["shape"] == "internal-vault-cli"
        assert data["metadata"]["executor"] == "web-server-3"  # merge preserved
        assert len(data["metadata_warnings"]) == 1
        assert "CUSTOM shape" in data["metadata_warnings"][0]
