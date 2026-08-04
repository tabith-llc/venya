"""Tests for roles CRUD endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from venya_server.routes import roles as roles_routes


def _create_test_app(backend=None, auth_user=None):
    """Create a minimal test app with roles routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is None:
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    app.include_router(roles_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)

    return app


def _make_mock_role_manager(role=None, roles=None, members=None, error=None):
    """Create a mock RoleManager with realistic behavior."""
    rm = MagicMock()

    def make_role(id_, name, permissions="read", description=None):
        return SimpleNamespace(
            id=id_, name=name, permissions=permissions, description=description
        )

    if error:
        rm.create_role.side_effect = error
        rm.add_member.side_effect = error
    else:
        if role:
            rm.create_role.return_value = role
        else:
            rm.create_role.return_value = make_role(1, "dev", "read", "Developers")

    if roles is not None:
        rm.list_roles.return_value = roles
    else:
        rm.list_roles.return_value = [make_role(1, "dev", "read", "Developers")]

    if members is not None:
        rm.get_role_members.return_value = members
    else:
        rm.get_role_members.return_value = []

    rm.get_role.return_value = make_role(1, "dev", "read", "Developers")
    rm.delete_role.return_value = True
    rm.add_member.return_value = SimpleNamespace(user_id="user1", role_id=1)
    rm.remove_member.return_value = True

    return rm


class TestRolesCreate:
    """Tests for role creation endpoint."""

    def test_create_success(self):
        """POST /roles should create a role via role_manager."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles",
                json={
                    "name": "dev",
                    "permissions": "read-write",
                    "description": "Developers with write access",
                },
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["name"] == "dev"
            assert data["permissions"] == "read"
            assert data["description"] == "Developers"

    def test_create_duplicate(self):
        """POST /roles should return 400 for duplicate role name."""
        rm = _make_mock_role_manager(error=Exception("Role 'dev' already exists"))
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles",
                json={"name": "dev", "permissions": "read"},
            )
            assert resp.status_code == 400
            assert "already exists" in resp.json()["detail"]

    def test_create_invalid_permissions(self):
        """POST /roles should return 400 for invalid permissions."""
        rm = _make_mock_role_manager(error=Exception("Invalid permissions: admin"))
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles",
                json={"name": "admin", "permissions": "admin"},
            )
            assert resp.status_code == 400
            assert "Invalid permissions" in resp.json()["detail"]


class TestRolesList:
    """Tests for roles listing endpoint."""

    def test_list_success(self):
        """GET /roles should return list of roles."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/roles")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["roles"]) == 1
            assert data["roles"][0]["name"] == "dev"


class TestRolesGet:
    """Tests for role retrieval endpoint."""

    def test_get_success(self):
        """GET /roles/{id} should return role details."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/roles/1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["id"] == 1
            assert data["name"] == "dev"
            assert data["permissions"] == "read"

    def test_get_not_found(self):
        """GET /roles/{id} should return 404 for missing role."""
        rm = _make_mock_role_manager()
        rm.get_role.return_value = None
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/roles/999")
            assert resp.status_code == 404
            assert "not found" in resp.json()["detail"]


class TestRolesUpdate:
    """Tests for role update endpoint."""

    def test_update_success(self):
        """PUT /roles/{id} should update role fields."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        updated_role = SimpleNamespace(
            id=1, name="senior-dev", permissions="read-write", description="Senior developers"
        )
        rm.update_role.return_value = updated_role
        rm.get_role_members.return_value = []

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put(
                "/api/v1/roles/1",
                json={
                    "name": "senior-dev",
                    "permissions": "read-write",
                    "description": "Senior developers",
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "senior-dev"
            assert data["permissions"] == "read-write"
            assert data["description"] == "Senior developers"

    def test_update_not_found(self):
        """PUT /roles/{id} should return 404 for missing role."""
        rm = _make_mock_role_manager()
        rm.update_role.side_effect = Exception("Role 999 not found")
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put(
                "/api/v1/roles/999",
                json={"name": "new-name"},
            )
            assert resp.status_code == 400
            assert "not found" in resp.json()["detail"]

    def test_update_duplicate_name(self):
        """PUT /roles/{id} should return 400 if new name already exists."""
        rm = _make_mock_role_manager()
        rm.update_role.side_effect = Exception("Role 'dev' already exists")
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put(
                "/api/v1/roles/1",
                json={"name": "dev"},
            )
            assert resp.status_code == 400
            assert "already exists" in resp.json()["detail"]

    def test_update_invalid_permissions(self):
        """PUT /roles/{id} should return 400 for invalid permissions."""
        rm = _make_mock_role_manager()
        rm.update_role.side_effect = Exception("Invalid permissions: admin")
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put(
                "/api/v1/roles/1",
                json={"permissions": "admin"},
            )
            assert resp.status_code == 400
            assert "Invalid permissions" in resp.json()["detail"]

    def test_update_partial(self):
        """PUT /roles/{id} should allow partial updates."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        updated_role = SimpleNamespace(
            id=1, name="dev", permissions="read", description="Updated description"
        )
        rm.update_role.return_value = updated_role
        rm.get_role_members.return_value = []

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.put(
                "/api/v1/roles/1",
                json={"description": "Updated description"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["description"] == "Updated description"


class TestRolesDelete:
    """Tests for role deletion endpoint."""

    def test_delete_success(self):
        """DELETE /roles/{id} should delete the role."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["deleted"] is True

    def test_delete_not_found(self):
        """DELETE /roles/{id} should return 404 for missing role."""
        rm = _make_mock_role_manager()
        rm.delete_role.return_value = False
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/999")
            assert resp.status_code == 404
            assert "not found" in resp.json()["detail"]


class TestRoleMembersList:
    """Tests for role members listing endpoint."""

    def test_list_members_success(self):
        """GET /roles/{id}/members should return list of members."""
        rm = _make_mock_role_manager()
        member1 = MagicMock(user_id="user1", role_id=1)
        member2 = MagicMock(user_id="user2", role_id=1)
        rm.get_role_members.return_value = [member1, member2]
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/roles/1/members")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["members"]) == 2
            assert data["members"][0]["user_id"] == "user1"
            assert data["members"][1]["user_id"] == "user2"

    def test_list_members_empty(self):
        """GET /roles/{id}/members should return empty list when no members."""
        rm = _make_mock_role_manager()
        rm.get_role_members.return_value = []
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/roles/1/members")
            assert resp.status_code == 200
            assert resp.json()["members"] == []


class TestRoleMemberAdd:
    """Tests for role member addition endpoint."""

    def test_add_member_success(self):
        """POST /roles/{id}/members should add a user to a role."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles/1/members",
                json={"user_id": "user1"},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["added"] is True
            assert data["user_id"] == "user1"
            assert data["role_id"] == 1

    def test_add_member_duplicate(self):
        """POST /roles/{id}/members should return 400 for duplicate membership."""
        rm = _make_mock_role_manager()
        rm.add_member.side_effect = Exception("User 'user1' is already a member of role 1")
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles/1/members",
                json={"user_id": "user1"},
            )
            assert resp.status_code == 400
            assert "already a member" in resp.json()["detail"]

    def test_add_member_user_not_found(self):
        """POST /roles/{id}/members should return 400 if user doesn't exist."""
        rm = _make_mock_role_manager()
        rm.add_member.side_effect = Exception("User 'nonexistent' not found")
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/roles/1/members",
                json={"user_id": "nonexistent"},
            )
            assert resp.status_code == 400
            assert "not found" in resp.json()["detail"]


class TestRoleMemberRemove:
    """Tests for role member removal endpoint."""

    def test_remove_member_success(self):
        """DELETE /roles/{id}/members/{user_id} should remove a user from a role."""
        rm = _make_mock_role_manager()
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/1/members/user1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["removed"] is True
            assert data["user_id"] == "user1"

    def test_remove_member_not_found(self):
        """DELETE /roles/{id}/members/{user_id} should return 404 if not a member."""
        rm = _make_mock_role_manager()
        rm.remove_member.return_value = False
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        app = _create_test_app(backend=backend)

        with patch("venya.iam.role_manager.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/1/members/nonexistent")
            assert resp.status_code == 404
            assert "not found" in resp.json()["detail"]
