"""Tests for require_role dependency factory (C-06)."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

from server.dependencies import get_current_user, require_role


def _make_rm_mock(user_permissions):
    """Create a mock RoleManager.

    Args:
        user_permissions: Dict mapping user_id -> {role_id: permission}.
    """
    rm = MagicMock()
    rm.get_user_permissions.side_effect = (
        lambda uid: user_permissions.get(uid, {})
    )
    return rm


def _create_app(auth_user, permission, with_backend=True):
    """Create a minimal app with one route protected by require_role."""
    app = FastAPI()
    if with_backend:
        app.state.backend = MagicMock()

    @app.get("/protected")
    async def protected(_=Depends(require_role(permission))):
        return {"result": "ok"}

    # Override get_current_user so it doesn't need a Bearer token.
    # The real get_current_user checks for an Authorization: Bearer header
    # first; the override bypasses that check and returns a fixed user dict.
    if auth_user is not None:
        app.dependency_overrides[get_current_user] = lambda: auth_user

    return app


class TestRequireRoleRead:
    """Tests for require_role("read")."""

    def test_passes_with_any_role_membership(self):
        """A user with a read role passes require_role("read")."""
        rm = _make_rm_mock({"user1": {1: "read"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"
        rm.get_user_permissions.assert_called_once_with("user1")

    def test_passes_with_read_write_role(self):
        """A read-write role satisfies the read requirement."""
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200

    def test_denied_for_user_with_no_roles(self):
        """A user with zero role memberships gets 403 on require_role("read")."""
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"


class TestRequireRoleReadWrite:
    """Tests for require_role("read-write")."""

    def test_passes_with_read_write_role(self):
        """A user with a read-write role passes require_role("read-write")."""
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"

    def test_denied_for_read_only_user(self):
        """A read-only user gets 403 on require_role("read-write")."""
        rm = _make_rm_mock({"user1": {1: "read"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"

    def test_denied_for_user_with_no_roles(self):
        """A user with zero roles gets 403 on require_role("read-write")."""
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"

    def test_any_read_write_role_suffices(self):
        """One read-write role among several roles is enough."""
        rm = _make_rm_mock({"user1": {1: "read", 2: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200


class TestRequireRoleExecutorBypass:
    """Executors (mTLS) bypass the role check, consistent with RBACMiddleware."""

    def test_executor_passes_without_role_lookup(self):
        """Executor user_info (no user_id) passes and never hits RoleManager."""
        rm = _make_rm_mock({})
        rm.get_user_permissions.side_effect = AssertionError(
            "role lookup must not run for executors"
        )
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app(
                {"caller": "executor", "executor_id": "exec-1"},
                "read-write",
            )
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        rm.get_user_permissions.assert_not_called()


class TestRequireRoleAuthAndBackend:
    """Authentication and backend prerequisite behavior."""

    def test_unauthenticated_returns_401(self):
        """No auth_user on request state -> 401 from get_current_user."""
        app = _create_app(None, "read")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_backend_not_initialized_returns_503(self):
        """No backend on app state -> 503 from get_backend."""
        app = _create_app({"user_id": "user1"}, "read", with_backend=False)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 503


class TestRequireRoleFactory:
    """Factory-time validation and session lifecycle."""

    def test_invalid_permission_raises_value_error(self):
        """require_role("execute") raises ValueError at factory call time."""
        with pytest.raises(ValueError, match="Must be 'read' or 'read-write'"):
            require_role("execute")

    def test_empty_permission_raises_value_error(self):
        """require_role("") raises ValueError at factory call time."""
        with pytest.raises(ValueError):
            require_role("")

    def test_db_session_closed_after_check(self):
        """The DB session opened for the role lookup is always closed."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        backend.get_session.assert_called_once()
        session.close.assert_called_once()

    def test_db_session_closed_on_denial(self):
        """The DB session is closed even when the check returns 403."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        session.close.assert_called_once()

    def test_db_rollback_on_role_lookup_error(self):
        """A failure in the role lookup rolls the session back before re-raising."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session

        def _boom(uid):
            raise RuntimeError("db down")

        rm = MagicMock()
        rm.get_user_permissions.side_effect = _boom
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 500
        session.rollback.assert_called_once()
        session.close.assert_called_once()
