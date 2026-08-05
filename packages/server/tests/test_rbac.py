"""Tests for RBAC middleware."""

from unittest.mock import MagicMock, patch

from fastapi import FastAPI, APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient
from starlette.requests import Request

from server.middleware.rbac import RBACMiddleware


class AuthUserMiddleware(BaseHTTPMiddleware):
    """Test middleware that sets auth_user on request state."""
    def __init__(self, app, user_info=None):
        super().__init__(app)
        self.user_info = user_info

    async def dispatch(self, request: Request, call_next):
        if self.user_info is not None:
            request.state.auth_user = self.user_info
        return await call_next(request)


def _create_test_app(auth_user=None, backend=None):
    """Create a minimal test app with RBAC + auth middleware."""
    app = FastAPI()
    if backend is None:
        from unittest.mock import MagicMock
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    router = APIRouter()

    @router.get("/api/v1/admin/test")
    def admin_test():
        return {"result": "admin-ok"}

    @router.post("/api/v1/secrets")
    def secret_create():
        return {"result": "secret-created"}

    @router.get("/api/v1/secrets")
    def secret_list():
        return {"result": "secrets-list"}

    @router.post("/api/v1/roles")
    def role_create():
        return {"result": "role-created"}

    @router.delete("/api/v1/secrets/{secret_id}")
    def secret_delete(secret_id: int):
        return {"result": "secret-deleted"}

    @router.put("/api/v1/secrets/{secret_id}")
    def secret_update(secret_id: int):
        return {"result": "secret-updated"}

    app.include_router(router)
    # Starlette runs middleware in reverse order of addition
    # So RBAC must be added first, AuthUser second
    app.add_middleware(RBACMiddleware)
    app.add_middleware(AuthUserMiddleware, user_info=auth_user)
    return app


class TestRBACMiddleware:
    """Tests for role-based access control middleware."""

    def _make_mock(self, user_permissions=None, admin_role=None):
        """Create a mock RoleManager and patcher.

        Returns tuple of (patcher, rm_mock).
        """
        if user_permissions is None:
            user_permissions = {}
        if admin_role is None:
            admin_role = MagicMock(id=42)

        rm_mock = MagicMock()
        rm_mock.get_role_by_name.return_value = admin_role
        rm_mock.get_user_permissions.side_effect = lambda uid: user_permissions.get(uid, {})

        def has_permission_side_effect(uid, role_id, required_perm):
            perms = user_permissions.get(uid, {})
            if role_id == admin_role.id:
                return perms.get(role_id) == "read-write"
            return any(p == "read-write" for p in perms.values())

        rm_mock.has_permission.side_effect = has_permission_side_effect
        patcher = patch("vault.iam.role_manager.RoleManager", return_value=rm_mock)
        return patcher, rm_mock

    def test_write_denied_for_read_only_user(self):
        """POST to /secrets should be denied for read-only user."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/secrets", json={"key": "test"})
            assert resp.status_code == 403
            assert "Write permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_write_allowed_for_read_write_user(self):
        """POST to /secrets should be allowed for read-write user."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read-write"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/secrets", json={"key": "test"})
            assert resp.status_code == 200
            assert resp.json()["result"] == "secret-created"
        finally:
            patcher.stop()

    def test_admin_denied_for_non_admin_user(self):
        """GET /admin should be denied for non-admin user."""
        admin_role = MagicMock(id=42)
        patcher, _ = self._make_mock(
            user_permissions={"user1": {42: "read"}},
            admin_role=admin_role,
        )
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [42]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/admin/test")
            assert resp.status_code == 403
            assert "Admin permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_admin_allowed_for_admin_user(self):
        """GET /admin should be allowed for admin user with read-write."""
        admin_role = MagicMock(id=42)
        patcher, _ = self._make_mock(
            user_permissions={"user1": {42: "read-write"}},
            admin_role=admin_role,
        )
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [42]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/admin/test")
            assert resp.status_code == 200
            assert resp.json()["result"] == "admin-ok"
        finally:
            patcher.stop()

    def test_no_backend_denies_access(self):
        """If no backend, access should be denied."""
        patcher, _ = self._make_mock()
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/secrets", json={"key": "test"})
            assert resp.status_code == 403
        finally:
            patcher.stop()

    def test_no_admin_role_in_db_denies_access(self):
        """If admin role doesn't exist in DB, admin access denied."""
        patcher, rm_mock = self._make_mock(
            user_permissions={"user1": {1: "read-write"}},
            admin_role=None,
        )
        rm_mock.get_role_by_name.return_value = None
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/admin/test")
            assert resp.status_code == 403
            assert "Admin permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_get_secrets_allowed_for_read_only(self):
        """GET /secrets should be allowed for read-only users."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/secrets")
            assert resp.status_code == 200
            assert resp.json()["result"] == "secrets-list"
        finally:
            patcher.stop()

    def test_no_auth_user_passes_through(self):
        """If no auth_user on request, middleware should pass through."""
        app = _create_test_app(auth_user=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test")
        assert resp.status_code == 200

    def test_post_roles_denied_for_read_only(self):
        """POST to /roles should be denied for read-only user."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/roles", json={"name": "test-role"})
            assert resp.status_code == 403
            assert "Write permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_delete_secrets_denied_for_read_only(self):
        """DELETE on /secrets should be denied for read-only user."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/secrets/1")
            assert resp.status_code == 403
            assert "Write permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_put_secrets_denied_for_read_only(self):
        """PUT on /secrets should be denied for read-only user."""
        patcher, _ = self._make_mock(user_permissions={"user1": {1: "read"}})
        patcher.start()
        try:
            app = _create_test_app(auth_user={"user_id": "user1", "roles": [1]})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put("/api/v1/secrets/1", json={"key": "updated"})
            assert resp.status_code == 403
            assert "Write permission required" in resp.json()["detail"]
        finally:
            patcher.stop()

    def test_executor_bypass(self):
        """Executor (mTLS) should bypass all RBAC checks."""
        app = _create_test_app(auth_user={"user_id": "executor1", "caller": "executor", "roles": []})
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/secrets", json={"key": "test"})
        assert resp.status_code == 200
        assert resp.json()["result"] == "secret-created"
