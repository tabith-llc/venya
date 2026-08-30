"""Tests for executor list and heartbeat endpoints."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Default: every user holds a read-write role."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


def _create_test_app(backend=None):
    """Create a minimal test app with executor routes."""
    app = FastAPI()

    if backend is None:
        backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend

    app.include_router(executors_routes.router, prefix="/api/v1")

    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    return app, backend


class TestListExecutors:
    """Tests for GET /api/v1/executors endpoint."""

    def test_list_executors_read_role(self):
        """GET /executors should work with read role."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-3"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=10)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["executors"]) == 1
        assert data["executors"][0]["id"] == "web-server-3"
        assert data["executors"][0]["online"] is True

    def test_list_executors_no_auth_fails(self):
        """GET /executors should return 401 without auth."""
        app, _ = _create_test_app()
        del app.dependency_overrides[get_current_user]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")
        assert resp.status_code == 401

    def test_list_executors_online_status_derived(self):
        """last_heartbeat < 60s should show online: true."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-1"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"][0]["online"] is True

    def test_list_executors_offline_status_derived(self):
        """last_heartbeat > 60s should show online: false."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-2"
        mock_executor.hostname = "10.27.28.15"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=120)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"][0]["online"] is False

    def test_list_executors_status_revoked(self):
        """revoked_at set should show status: revoked."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "revoked-server"
        mock_executor.hostname = "10.27.28.16"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=10)
        mock_executor.revoked_at = datetime.now(UTC) - timedelta(hours=1)
        mock_executor.status = "active"
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"][0]["status"] == "revoked"

    def test_list_executors_empty_result(self):
        """No executors should return empty list."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_query.all.return_value = []
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"] == []

    def test_list_executors_hostname_in_response(self):
        """hostname field should be present in response."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-3"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = None
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"][0]["hostname"] == "10.27.28.14"


class TestExecutorHeartbeat:
    """Tests for POST /api/v1/executors/{id}/heartbeat endpoint."""

    def test_heartbeat_updates_timestamp(self):
        """POST /executors/{id}/heartbeat should update last_heartbeat."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-3"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(minutes=5)
        mock_executor.status = "pending"
        mock_executor_filter = MagicMock()
        mock_executor_filter.first.return_value = mock_executor
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_executor_filter
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/web-server-3/heartbeat")

        assert resp.status_code == 200
        assert mock_executor.last_heartbeat > datetime.now(UTC) - timedelta(seconds=1)

    def test_heartbeat_sets_status_active(self):
        """POST /executors/{id}/heartbeat should set status to active."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-3"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(minutes=5)
        mock_executor.status = "pending"
        mock_executor_filter = MagicMock()
        mock_executor_filter.first.return_value = mock_executor
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_executor_filter
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/web-server-3/heartbeat")

        assert resp.status_code == 200
        assert mock_executor.status == "active"

    def test_heartbeat_not_found_404(self):
        """POST /executors/{id}/heartbeat should return 404 for unknown executor."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor_filter = MagicMock()
        mock_executor_filter.first.return_value = None
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_executor_filter
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/unknown-server/heartbeat")

        assert resp.status_code == 404
        assert "Executor not found" in resp.json()["detail"]

    def test_heartbeat_temporary_auth_accepted(self):
        """POST /executors/{id}/heartbeat should accept any authenticated user."""
        app, backend = _create_test_app()
        mock_session = MagicMock()
        mock_executor = MagicMock()
        mock_executor.id = "web-server-3"
        mock_executor.hostname = "10.27.28.14"
        mock_executor.last_heartbeat = None
        mock_executor.status = "pending"
        mock_executor_filter = MagicMock()
        mock_executor_filter.first.return_value = mock_executor
        mock_query = MagicMock()
        mock_query.filter.return_value = mock_executor_filter
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/web-server-3/heartbeat")

        assert resp.status_code == 200
