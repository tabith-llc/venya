# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor list endpoints.

(The POST /executors/{id}/heartbeat alpha variant and its four tests were
REMOVED with the route — ticket sec-endpoint-ratelimit-hardening #7: it was
require_role("none") residue with zero production callers; the real heartbeat
is /api/v1/heartbeat, executor-mTLS gated, tested in test_executor_server.py.
Note for the record: test_heartbeat_temporary_auth_accepted pinned the weak
"any authenticated user" gate as DESIRED behavior — tests can institutionalize
a vulnerability as confidently as they can catch one.)
"""

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
        mock_executor.hostname = "192.0.2.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=10)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_executor.version = None  # additive field (feature/version-surfaces)
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
        mock_executor.hostname = "192.0.2.14"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_executor.version = None  # additive field (feature/version-surfaces)
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
        mock_executor.hostname = "192.0.2.15"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=120)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_executor.version = None  # additive field (feature/version-surfaces)
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
        mock_executor.hostname = "192.0.2.16"
        mock_executor.last_heartbeat = datetime.now(UTC) - timedelta(seconds=30)
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=10)
        mock_executor.revoked_at = datetime.now(UTC) - timedelta(hours=1)
        mock_executor.status = "active"
        mock_executor.version = None  # additive field (feature/version-surfaces)
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
        mock_executor.hostname = "192.0.2.14"
        mock_executor.last_heartbeat = None
        mock_executor.enrolled_at = datetime.now(UTC) - timedelta(days=5)
        mock_executor.revoked_at = None
        mock_executor.status = "active"
        mock_executor.version = None  # additive field (feature/version-surfaces)
        mock_query = MagicMock()
        mock_query.all.return_value = [mock_executor]
        mock_session.query.return_value = mock_query
        backend.get_session.return_value = mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")

        assert resp.status_code == 200
        data = resp.json()
        assert data["executors"][0]["hostname"] == "192.0.2.14"

    def test_list_executors_forbidden_without_roles(self):
        """Authenticated user with no roles -> 403 on GET /executors."""
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {}
        with patch("server.dependencies.RoleManager", return_value=rm):
            app, backend = _create_test_app()
            mock_session = MagicMock()
            mock_query = MagicMock()
            mock_query.all.return_value = []
            mock_session.query.return_value = mock_query
            backend.get_session.return_value = mock_session

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/executors")

        assert resp.status_code == 403


class TestExecutorModelContract:
    """Pins the Executor model<->column contract.

    DB-agnostic substitute for the plan's Postgres-only migration tests:
    reflects the table object (no live schema), asserts the column set, the
    non-nullable hostname (S1 contract), and the timezone-aware timestamps.
    """

    def test_columns_hostname_non_null_and_tz_datetimes(self):
        import sqlalchemy as sa
        from core.iam.models import Executor

        cols = {c.name: c for c in Executor.__table__.columns}
        # "version" added by feature/version-surfaces (migration 029, same
        # changeset — model/migration interlock); conscious contract update.
        assert set(cols) == {"id", "hostname", "enrolled_at", "revoked_at", "last_heartbeat", "status", "version"}
        assert cols["version"].nullable is True

        # hostname maps to the exact DB column name the migration writes.
        assert "hostname" in cols
        assert cols["hostname"].nullable is False

        # All three timestamp columns are timezone-aware (timestamptz).
        for name in ("enrolled_at", "revoked_at", "last_heartbeat"):
            assert isinstance(cols[name].type, sa.DateTime)
            assert cols[name].type.timezone is True

        # status is non-nullable with the pending default.
        assert cols["status"].nullable is False
        assert cols["status"].default.arg == "pending"
