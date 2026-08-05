"""Tests for admin operation endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import admin as admin_routes


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
        mock_token = SimpleNamespace(token="enc-token-123")
        mock_em = MagicMock()
        mock_em.create_enrollment_token.return_value = mock_token

        db = MagicMock()
        db.query.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("vault.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
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
        mock_em.create_enrollment_token.side_effect = Exception(
            "User 'user1' already has 3 active enrollment tokens"
        )
        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("vault.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/admin/enroll",
                json={"user_id": "user1"},
            )
            assert resp.status_code == 400


class TestAdminRemove:
    """Tests for admin user removal endpoint."""

    def test_remove_success(self):
        """DELETE /admin/users/{id} should remove user."""
        user = SimpleNamespace(user_id="user1")
        db = MagicMock()
        db.query.return_value.first.return_value = user
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        with patch("vault.iam.models.User", user):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/admin/users/user1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["removed"] is True
            assert data["user_id"] == "user1"

    def test_remove_not_found(self):
        """DELETE /admin/users/{id} should return 404 for missing user."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                return None
            def delete(self, *args, **kwargs):
                return 0

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/admin/users/missing")
        assert resp.status_code == 404


class TestAdminListUsers:
    """Tests for admin user listing endpoint."""

    def test_list_users(self):
        """GET /admin/users should return list of users."""
        user1 = SimpleNamespace(
            user_id="user1", auth_mode="security-key",
            enrolled_at=None, session_timeout=900,
        )
        user2 = SimpleNamespace(
            user_id="user2", auth_mode="platform",
            enrolled_at=None, session_timeout=1800,
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
            user_id="user1", auth_mode="security-key", session_timeout=900,
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
            id=1, version_label="v1", active=True, rotation_pending=False,
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


class TestAdminKeyVersionRotate:
    """Tests for admin key rotation endpoint."""

    def test_rotate_success(self):
        """POST /admin/key-versions/rotate should create rotation job."""
        active_v = SimpleNamespace(id=1, active=True)
        secret = SimpleNamespace(id=1)
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def order_by(self, *args, **kwargs):
                return self
            def first(self):
                return active_v
            def count(self):
                return 5
            def all(self):
                return [secret]

        db.query.return_value = MockQuery()
        db.add.side_effect = lambda x: setattr(x, 'id', 99) if not hasattr(x, 'id') or x.id is None else None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/rotate", json={})
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert data["old_key_version_id"] == 1
        assert data["new_key_version_id"] is not None

    def test_rotate_no_active_version(self):
        """POST /admin/key-versions/rotate should work with no active version."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def order_by(self, *args, **kwargs):
                return self
            def first(self):
                return None
            def count(self):
                return 0
            def all(self):
                return []

        db.query.return_value = MockQuery()
        db.add.side_effect = lambda x: setattr(x, 'id', 99) if not hasattr(x, 'id') or x.id is None else None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/rotate", json={})
        assert resp.status_code == 202
        data = resp.json()
        assert data["old_key_version_id"] is None


class TestAdminKeyVersionRollback:
    """Tests for admin key version rollback endpoint."""

    def test_rollback_success(self):
        """POST /admin/key-versions/rollback should rollback rotation."""
        job = SimpleNamespace(id=1, status="running")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = job
        db.query.return_value.filter.return_value.count.return_value = 3
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/key-versions/rollback",
            json={"job_id": 1},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["rolled_back"] is True
        assert data["job_id"] == 1
        assert data["restored_secrets_count"] == 3

    def test_rollback_not_found(self):
        """POST /admin/key-versions/rollback should return 404 for missing job."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/key-versions/rollback",
            json={"job_id": 999},
        )
        assert resp.status_code == 404


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
            policy_name="default", preset="balanced",
            allowed_commands='["/bin/ls"]', dangerous_patterns=None,
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


class TestAdminRecovery:
    """Tests for admin recovery endpoint."""

    def test_recovery_new_admin(self):
        """POST /admin/recovery should create new admin user."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
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
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["action"] == "new_admin"
        assert data["user_id"] == "newadmin"

    def test_recovery_user_exists(self):
        """POST /admin/recovery should return 400 if user already exists."""
        user = SimpleNamespace(user_id="existing")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/recovery",
            json={
                "recovery_code": "recovery-123",
                "new_user_id": "existing",
                "webauthn_assertion": {"challenge": "abc"},
            },
        )
        assert resp.status_code == 400


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
            policy_name="default", preset="balanced",
            allowed_commands=json.dumps(["/bin/ls"]),
            dangerous_patterns=None, updated_at=None,
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
            id=1, status="running", total_secrets=100,
            completed_secrets=50, failed_count=0,
            started_at=None, completed_at=None,
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


class TestAdminKeyRotationJobRollback:
    """Tests for admin key rotation job rollback endpoint."""

    def test_rollback_job_success(self):
        """POST /admin/key-rotation/{id}/rollback should rollback job."""
        job = SimpleNamespace(id=1, status="failed")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = job
        db.query.return_value.filter.return_value.count.return_value = 10
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-rotation/1/rollback")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rolled_back"] is True
        assert data["restored_secrets_count"] == 10

    def test_rollback_job_not_found(self):
        """POST /admin/key-rotation/{id}/rollback should return 404."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-rotation/999/rollback")
        assert resp.status_code == 404


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
        db = MagicMock()

        call_num = [0]

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def first(self):
                call_num[0] += 1
                return cert if call_num[0] == 1 else revocation

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec1/revoke")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is False


class TestAdminKeyRotationAlias:
    """Tests for admin key rotation alias endpoint."""

    def test_rotation_alias_delegates(self):
        """POST /admin/key-rotation should delegate to rotate endpoint."""
        active_v = SimpleNamespace(id=1, active=True)
        secret = SimpleNamespace(id=1)
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self
            def order_by(self, *args, **kwargs):
                return self
            def first(self):
                return active_v
            def count(self):
                return 5
            def all(self):
                return [secret]

        db.query.return_value = MockQuery()
        db.add.side_effect = lambda x: setattr(x, 'id', 99) if not hasattr(x, 'id') or x.id is None else None
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-rotation", json={})
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
