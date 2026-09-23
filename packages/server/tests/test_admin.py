# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for admin operation endpoints."""

from datetime import UTC
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from starlette.testclient import TestClient


def _create_test_app(backend=None, auth_user=None):
    """Create a minimal test app with admin routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.include_router(admin_routes.router, prefix="/api/v1")

    # Override auth deps so require_admin/require_role bypass real auth
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


def _make_mock_db(queries=None, errors=None):
    """Create a mock DB session with configurable queries."""
    db = MagicMock()
    query_mock = MagicMock()
    db.query.return_value = query_mock
    if queries:
        query_mock.first.return_value = queries.get("first")
        query_mock.all.return_value = queries.get("all", [])
        query_mock.count.return_value = queries.get("count", 0)
    if errors:
        db.add.side_effect = errors.get("add")
        db.delete.side_effect = errors.get("delete")
    return db


class TestAdminEnroll:
    """Tests for admin enrollment endpoint."""

    def test_enroll_success(self):
        """POST /admin/enroll should create enrollment token."""
        mock_token = SimpleNamespace(id=1)
        mock_em = MagicMock()
        mock_em.create_enrollment_token.return_value = (mock_token, "enc-token-123")

        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None

        db = MagicMock()
        db.query.return_value = mock_query
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/admin/enroll",
                json={"user_id": "newuser", "auth_mode": "security-key"},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["enrolled"] is True
            assert data["user_id"] == "newuser"
            assert data["enrollment_token"] == "enc-token-123"

    def test_enroll_too_many_tokens(self):
        """POST /admin/enroll should return 400 if too many tokens."""
        mock_em = MagicMock()
        mock_em.create_enrollment_token.side_effect = Exception("User 'user1' already has 3 active enrollment tokens")
        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/admin/enroll",
                json={"user_id": "user1"},
            )
            assert resp.status_code == 400


class TestAdminRemove:
    """Tests for admin user removal endpoint."""

    def test_remove_success(self):
        """DELETE /admin/users/{id} should remove user with row lock."""
        user = SimpleNamespace(user_id="user1", id=1)

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def with_for_update(self):
                return self

            def first(self):
                return user

            def delete(self):
                return 0

        db = MagicMock()
        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/admin/users/user1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["removed"] is True
        assert data["user_id"] == "user1"
        db.delete.assert_called_once_with(user)
        db.commit.assert_called_once()

    def test_remove_not_found(self):
        """DELETE /admin/users/{id} should return 404 for missing user."""

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def with_for_update(self):
                return self

            def first(self):
                return None

        db = MagicMock()
        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/admin/users/missing")
        assert resp.status_code == 404

    def test_remove_integrity_error(self):
        """DELETE /admin/users/{id} should return 400 on FK violation."""
        from sqlalchemy import exc as sqlalchemy_exc

        user = SimpleNamespace(user_id="user1", id=1)

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def with_for_update(self):
                return self

            def first(self):
                return user

            def delete(self):
                return 0

        db = MagicMock()
        db.query.return_value = MockQuery()
        db.delete.side_effect = sqlalchemy_exc.IntegrityError(
            "statement", {}, Exception("violates foreign key constraint")
        )
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/admin/users/user1")
        assert resp.status_code == 400
        db.rollback.assert_called_once()


class TestAdminListUsers:
    """Tests for admin user listing endpoint."""

    def test_list_users(self):
        """GET /admin/users should return list of users."""
        user1 = SimpleNamespace(
            user_id="user1",
            display_name=None,
            status="pending_enrollment",
            auth_mode="security-key",
            enrolled_at=None,
            session_timeout=900,
        )
        user2 = SimpleNamespace(
            user_id="user2",
            display_name="User Two",
            status="active",
            auth_mode="platform",
            enrolled_at=None,
            session_timeout=1800,
        )
        db = MagicMock()
        db.query.return_value.order_by.return_value.all.return_value = [user1, user2]
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/users")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["users"]) == 2
        assert data["users"][0]["user_id"] == "user1"
        assert data["users"][1]["user_id"] == "user2"

    def test_list_users_empty(self):
        """GET /admin/users should return empty list when no users."""
        db = MagicMock()
        db.query.return_value.order_by.return_value.all.return_value = []
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/users")
        assert resp.status_code == 200
        assert resp.json()["users"] == []


class TestAdminConfigureUser:
    """Tests for admin user configuration endpoint."""

    def test_configure_success(self):
        """PUT /admin/users/{id} should update user settings."""
        user = SimpleNamespace(
            user_id="user1",
            auth_mode="security-key",
            session_timeout=900,
        )
        db = MagicMock()
        db.query.return_value.first.return_value = user
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.put(
            "/api/v1/admin/users/user1",
            json={"auth_mode": "platform", "session_timeout": 1800},
        )
        assert resp.status_code == 200
        assert resp.json()["configured"] is True

    def test_configure_not_found(self):
        """PUT /admin/users/{id} should return 404 for missing user."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.put(
            "/api/v1/admin/users/missing",
            json={"auth_mode": "platform"},
        )
        assert resp.status_code == 404


class TestAdminKeyVersionList:
    """Tests for admin key version listing endpoint."""

    def test_list_key_versions(self):
        """GET /admin/key-versions should return list of versions."""
        v1 = SimpleNamespace(
            id=1,
            version_label="v1",
            active=True,
            rotation_pending=False,
            created_at=None,
        )
        db = MagicMock()
        db.query.return_value.order_by.return_value.all.return_value = [v1]
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/key-versions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["versions"]) == 1
        assert data["versions"][0]["version_label"] == "v1"
        assert data["versions"][0]["active"] is True


# Key-rotation route tests (rotate + both rollbacks + alias) moved to
# test_key_rotation.py — real-SQLite truth table per the option-2 ruling
# (ticket key-rotation-worker-missing); the mock classes here pinned the
# old 202/pending fiction and could not observe DB state.


class TestAdminSetCommandPolicy:
    """Tests for admin command policy endpoint."""

    def test_set_policy_new(self):
        """POST /admin/command-policy should create new policy."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/command-policy",
            json={"preset": "strict"},
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] is True
        assert resp.json()["preset"] == "strict"

    def test_set_policy_existing(self):
        """POST /admin/command-policy should update existing policy."""
        policy = SimpleNamespace(
            policy_name="default",
            preset="balanced",
            allowed_commands='["/bin/ls"]',
            dangerous_patterns=None,
            updated_at=None,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = policy
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/command-policy",
            json={"preset": "permissive"},
        )
        assert resp.status_code == 200
        assert resp.json()["preset"] == "permissive"


class TestAdminRecoveryRemoved:
    """The /admin/recovery route is deleted — it minted admins with no code validation.

    Recovery authority lives solely in POST /api/v1/recovery (validate + burn).
    These tests assert the dead admin-minting surface stays dead: the path
    404s and is absent from the OpenAPI schema.
    """

    def test_admin_recovery_route_gone(self):
        """POST /api/v1/admin/recovery must 404 (route removed)."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/recovery",
            json={
                "recovery_code": "recovery-123",
                "new_user_id": "newadmin",
                "webauthn_assertion": {"challenge": "abc"},
            },
        )
        assert resp.status_code == 404

    def test_admin_recovery_absent_from_openapi(self):
        """/admin/recovery must not appear in the OpenAPI schema."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app = _create_test_app(backend=backend)

        schema = app.openapi()
        assert "/api/v1/admin/recovery" not in schema["paths"]


class TestAdminAddAllowedCommand:
    """Tests for admin add allowed command endpoint."""

    def test_add_command_new_policy(self):
        """POST /admin/command-policy/allowed should create policy with command."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/command-policy/allowed",
            json={"command_path": "/usr/bin/python"},
        )
        assert resp.status_code == 200
        assert resp.json()["added"] is True
        assert resp.json()["command_path"] == "/usr/bin/python"

    def test_add_command_existing_policy(self):
        """POST /admin/command-policy/allowed should append to existing policy."""
        import json

        policy = SimpleNamespace(
            policy_name="default",
            preset="balanced",
            allowed_commands=json.dumps(["/bin/ls"]),
            dangerous_patterns=None,
            updated_at=None,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = policy
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/command-policy/allowed",
            json={"command_path": "/usr/bin/python"},
        )
        assert resp.status_code == 200
        assert resp.json()["added"] is True

    def test_get_policy_unset_defaults(self):
        """GET /admin/command-policy with no stored row -> built-in defaults, configured=False, never mutates."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/command-policy")
        assert resp.status_code == 200
        body = resp.json()
        assert body["policy_name"] == "default"
        assert body["preset"] == "balanced"
        assert body["allowed_commands"] == []
        assert body["dangerous_patterns"] == []
        assert body["configured"] is False
        assert body["updated_at"] is None
        db.add.assert_not_called()
        db.commit.assert_not_called()

    def test_get_policy_stored_row(self):
        """GET reflects the stored row: preset + parsed JSON lists + configured=True."""
        policy = SimpleNamespace(
            policy_name="default",
            preset="strict",
            allowed_commands='["/bin/ls", "/usr/bin/cat"]',
            dangerous_patterns='["rm -rf"]',
            updated_at=None,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = policy
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/command-policy")
        assert resp.status_code == 200
        body = resp.json()
        assert body["preset"] == "strict"
        assert body["allowed_commands"] == ["/bin/ls", "/usr/bin/cat"]
        assert body["dangerous_patterns"] == ["rm -rf"]
        assert body["configured"] is True

    def test_get_policy_malformed_json_fails_loudly(self):
        """Corrupt stored JSON -> 500 named detail, never a silent empty list."""
        policy = SimpleNamespace(
            policy_name="default",
            preset="strict",
            allowed_commands="{not json",
            dangerous_patterns=None,
            updated_at=None,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = policy
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/command-policy")
        assert resp.status_code == 500
        assert "malformed" in resp.json()["detail"].lower()

    def test_get_policy_rejects_executor_caller(self):
        """Paired negative: executor mTLS caller -> 403 (require_admin denies executors before any role lookup)."""
        app = _create_test_app(auth_user={"caller": "executor", "executor_id": "venya-exec-1"})
        del app.dependency_overrides[require_admin]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/command-policy")
        assert resp.status_code == 403

    def test_get_policy_unauthenticated_401(self):
        """Paired negative: no mTLS identity and no bearer token -> 401."""
        app = _create_test_app()
        del app.dependency_overrides[require_admin]
        del app.dependency_overrides[get_current_user]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/command-policy")
        assert resp.status_code == 401


class TestAdminKeyVersionDeactivate:
    """Tests for admin key version deactivation endpoint."""

    def test_deactivate_success(self):
        """POST /admin/key-versions/{id}/deactivate should deactivate version."""
        version = SimpleNamespace(id=1, version_label="v1", active=True)
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = version
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/1/deactivate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["deactivated"] is True
        assert data["version_label"] == "v1"

    def test_deactivate_not_found(self):
        """POST /admin/key-versions/{id}/deactivate should return 404."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/999/deactivate")
        assert resp.status_code == 404


class TestAdminKeyVersionRevoke:
    """Tests for admin key version revocation endpoint."""

    def test_revoke_success(self):
        """POST /admin/key-versions/{id}/revoke should revoke version."""
        version = SimpleNamespace(id=1, version_label="v1", active=False)
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = version
        db.query.return_value.filter.return_value.count.return_value = 0
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/1/revoke")
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is True
        assert data["version_label"] == "v1"

    def test_revoke_secrets_in_use(self):
        """POST /admin/key-versions/{id}/revoke should return 400 if secrets use it."""
        version = SimpleNamespace(id=1, version_label="v1", active=False)
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = version
        db.query.return_value.filter.return_value.count.return_value = 5
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/1/revoke")
        assert resp.status_code == 400
        assert "still use this version" in resp.json()["detail"]


class TestAdminKeyRotationStatus:
    """Tests for admin key rotation status endpoint."""

    def test_status_success(self):
        """GET /admin/key-rotation/status should return job list."""
        job1 = SimpleNamespace(
            id=1,
            status="running",
            total_secrets=100,
            completed_secrets=50,
            failed_count=0,
            started_at=None,
            completed_at=None,
        )
        db = MagicMock()

        class MockQuery:
            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return [job1]

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/key-rotation/status")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["jobs"]) == 1
        assert data["jobs"][0]["status"] == "running"
        assert data["jobs"][0]["completed_secrets"] == 50


# Key-rotation job rollback tests: see test_key_rotation.py (real SQLite).


class TestAdminRevokeExecutor:
    """Tests for admin executor revocation endpoint."""

    def test_revoke_executor_success(self):
        """POST /admin/executors/{id}/revoke should revoke certificate."""
        cert = SimpleNamespace(serial_number="cert-123")
        db = MagicMock()

        call_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                call_num[0] += 1
                return cert if call_num[0] == 1 else None

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec1/revoke")
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is True
        assert data["executor_id"] == "exec1"

    def test_revoke_executor_not_found(self):
        """POST /admin/executors/{id}/revoke should return 404."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/missing/revoke")
        assert resp.status_code == 404

    def test_revoke_executor_already_revoked(self):
        """POST /admin/executors/{id}/revoke should return revoked=False if already revoked."""
        cert = SimpleNamespace(serial_number="cert-123")
        revocation = SimpleNamespace(serial_number="cert-123")
        # updated: executor-revocation-by-identity — the route now queries
        # ExecutorCert -> Executor -> ExecutorCertRevocation and the identity
        # flag lives on the Executor row; mocks model the schema per-model
        # instead of by call order.
        executor_row = SimpleNamespace(id="exec1", revoked_at=object())
        db = MagicMock()

        class MockQuery:
            def __init__(self, model):
                self.model = model

            def filter(self, *args, **kwargs):
                return self

            def first(self):
                name = getattr(self.model, "__name__", "")
                if name == "ExecutorCert":
                    return cert
                if name == "Executor":
                    return executor_row
                return revocation

        db.query.side_effect = lambda model: MockQuery(model)
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec1/revoke")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is False


# Key-rotation alias test: see test_key_rotation.py (real SQLite).


class TestAdminReEnroll:
    """Tests for POST /admin/users/{user_id}/re-enroll."""

    def test_re_enroll_success(self):
        """Should deactivate credentials, revoke tokens, create new token."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_user = SimpleNamespace(id=1, user_id="user1", status="active")
        mock_token = SimpleNamespace(id=10)

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_user

            def update(self, *args, **kwargs):
                return 0

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        db.get_session.return_value = db

        # Mock on prototype so real instance methods are mocked
        orig_revoke = EnrollmentManager.revoke_all_active_tokens
        orig_create = EnrollmentManager.create_enrollment_token
        try:
            EnrollmentManager.revoke_all_active_tokens = MagicMock(return_value=2)
            EnrollmentManager.create_enrollment_token = MagicMock(return_value=(mock_token, "new-token-xyz"))

            app = _create_test_app(backend=db)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users/user1/re-enroll")
            assert resp.status_code == 200
            data = resp.json()
            assert data["user_id"] == "user1"
            assert data["enrollment_token"] == "new-token-xyz"
            assert data["expires_in_seconds"] == 900
            assert data["credentials_deactivated"] == 0
            assert data["tokens_revoked"] == 2
            assert mock_user.status == "pending_enrollment"
            assert db.commit.called
        finally:
            EnrollmentManager.revoke_all_active_tokens = orig_revoke
            EnrollmentManager.create_enrollment_token = orig_create

    def test_re_enroll_user_not_found(self):
        """Should return 404 if user does not exist."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

            def update(self, *args, **kwargs):
                return 0

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        db.get_session.return_value = db
        app = _create_test_app(backend=db)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/users/nonexistent/re-enroll")
        assert resp.status_code == 404
        assert "User not found: nonexistent" in resp.json()["detail"]

    def test_re_enroll_enrollment_error(self):
        """Should return 400 on enrollment manager error."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_user = SimpleNamespace(id=1, user_id="user1", status="active")
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_user

        db.query.return_value = MockQuery()
        db.get_session.return_value = db

        orig_revoke = EnrollmentManager.revoke_all_active_tokens
        try:
            EnrollmentManager.revoke_all_active_tokens = MagicMock(side_effect=Exception("Too many tokens"))

            app = _create_test_app(backend=db)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users/user1/re-enroll")
            assert resp.status_code == 400
        finally:
            EnrollmentManager.revoke_all_active_tokens = orig_revoke


class TestAdminListUserTokens:
    """Tests for GET /admin/users/{user_id}/enrollment-tokens."""

    def test_list_tokens_success(self):
        """Should return list of enrollment tokens for user."""
        from datetime import datetime

        now = datetime.now(UTC)
        mock_user = SimpleNamespace(id=1, user_id="user1")
        token1 = SimpleNamespace(id=10, state="created", created_at=now, expires_at=now, used_at=None)
        token2 = SimpleNamespace(id=9, state="completed", created_at=now, expires_at=now, used_at=now)

        db = MagicMock()

        query_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                query_num[0] += 1
                if query_num[0] == 1:
                    return mock_user
                return None

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return [token1, token2]

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db
        app = _create_test_app(backend=db)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/users/user1/enrollment-tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tokens"]) == 2
        assert data["tokens"][0]["id"] == 10
        assert data["tokens"][0]["state"] == "created"
        assert data["tokens"][0]["used_at"] is None
        assert data["tokens"][1]["id"] == 9
        assert data["tokens"][1]["state"] == "completed"

    def test_list_tokens_user_not_found(self):
        """Should return 404 if user does not exist."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return []

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db
        app = _create_test_app(backend=db)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/users/nonexistent/enrollment-tokens")
        assert resp.status_code == 404
        assert "User not found: nonexistent" in resp.json()["detail"]


class TestAdminCreateUserToken:
    """Tests for POST /admin/users/{user_id}/enrollment-tokens."""

    def test_create_token_success(self):
        """Should revoke existing tokens and issue new one."""
        from core.iam.enrollment_manager import EnrollmentManager

        mock_user = SimpleNamespace(id=1, user_id="user1")
        mock_token = SimpleNamespace(id=11)

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_user

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db

        orig_revoke = EnrollmentManager.revoke_all_active_tokens
        orig_create = EnrollmentManager.create_enrollment_token
        try:
            EnrollmentManager.revoke_all_active_tokens = MagicMock(return_value=1)
            EnrollmentManager.create_enrollment_token = MagicMock(return_value=(mock_token, "new-token-abc"))

            app = _create_test_app(backend=db)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users/user1/enrollment-tokens")
            assert resp.status_code == 201
            data = resp.json()
            assert data["user_id"] == "user1"
            assert data["enrollment_token"] == "new-token-abc"
            assert data["expires_in_seconds"] == 900
            assert data["previous_tokens_revoked"] == 1
        finally:
            EnrollmentManager.revoke_all_active_tokens = orig_revoke
            EnrollmentManager.create_enrollment_token = orig_create

    def test_create_token_user_not_found(self):
        """Should return 404 if user does not exist."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db
        app = _create_test_app(backend=db)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/users/nonexistent/enrollment-tokens")
        assert resp.status_code == 404
        assert "User not found: nonexistent" in resp.json()["detail"]


class TestAdminRevokeToken:
    """Tests for DELETE /admin/enrollment-tokens/{token_id}."""

    def test_revoke_token_success(self):
        """Should revoke a specific enrollment token."""
        from core.iam.enrollment_manager import EnrollmentManager

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db

        orig_revoke_token = EnrollmentManager.revoke_token
        try:
            EnrollmentManager.revoke_token = MagicMock(return_value=True)

            app = _create_test_app(backend=db)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/admin/enrollment-tokens/5")
            assert resp.status_code == 200
            data = resp.json()
            assert data["revoked"] is True
            assert data["token_id"] == 5
        finally:
            EnrollmentManager.revoke_token = orig_revoke_token

    def test_revoke_token_not_found(self):
        """Should return 400 if token does not exist or cannot be revoked."""
        from core.iam.enrollment_manager import EnrollmentManager

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

            def update(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        db.get_session.return_value = db

        orig_revoke_token = EnrollmentManager.revoke_token
        try:
            EnrollmentManager.revoke_token = MagicMock(return_value=False)

            app = _create_test_app(backend=db)

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/admin/enrollment-tokens/999")
            assert resp.status_code == 200
            data = resp.json()
            assert data["revoked"] is False
            assert data["token_id"] == 999
        finally:
            EnrollmentManager.revoke_token = orig_revoke_token
