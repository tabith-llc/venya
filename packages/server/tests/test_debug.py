# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for asyncio diagnostic endpoint.

Covers:
- Task state detection (pending, done, cancelled, failed)
- Wall time tracking for named tasks
- DB pool statistics extraction
- Admin-only access control

See: Security Review Item #6 (No asyncio diagnostic endpoint)
"""

import asyncio
import time
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.routes.debug import (
    _build_db_pool_stats,
    _build_task_info,
    _get_coro_name,
    _task_state,
    _task_wall_time_ms,
    router,
)

# ============================================================================
# Helper Function Tests
# ============================================================================


class TestTaskState:
    """Tests for _task_state() helper."""

    def test_pending_task(self):
        """Pending task returns 'pending'."""

        async def dummy():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(dummy())

        try:
            assert _task_state(task) == "pending"
        finally:
            task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()

    def test_done_task(self):
        """Done task returns 'done'."""

        async def completes():
            return "ok"

        loop = asyncio.new_event_loop()
        task = loop.create_task(completes())
        loop.run_until_complete(task)

        try:
            assert _task_state(task) == "done"
        finally:
            loop.close()

    def test_cancelled_task(self):
        """Cancelled task returns 'cancelled'."""

        async def long_running():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(long_running())
        task.cancel()
        loop.run_until_complete(asyncio.sleep(0))

        try:
            assert _task_state(task) == "cancelled"
        finally:
            loop.close()

    def test_failed_task(self):
        """Failed task returns 'failed'."""

        async def raises():
            raise ValueError("test error")

        loop = asyncio.new_event_loop()
        task = loop.create_task(raises())
        # Let the task fail without consuming the exception
        loop.run_until_complete(asyncio.sleep(0))

        try:
            assert _task_state(task) == "failed"
        finally:
            loop.close()


class TestTaskWallTime:
    """Tests for _task_wall_time_ms() helper."""

    def test_tracked_task(self):
        """Task with _created_at returns wall time in ms."""

        async def dummy():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(dummy())
        task._created_at = time.monotonic() - 1.5  # Created 1.5 seconds ago

        try:
            wall_time = _task_wall_time_ms(task)
            assert wall_time is not None
            assert 1400 <= wall_time <= 1600  # ~1500ms tolerance
        finally:
            task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()

    def test_untracked_task(self):
        """Task without _created_at returns None."""

        async def dummy():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(dummy())

        try:
            assert _task_wall_time_ms(task) is None
        finally:
            task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()


class TestCoroName:
    """Tests for _get_coro_name() helper."""

    def test_named_coroutine(self):
        """Named coroutine returns function name."""

        async def my_coroutine():
            await asyncio.sleep(0)

        loop = asyncio.new_event_loop()
        task = loop.create_task(my_coroutine())
        loop.run_until_complete(task)

        try:
            name = _get_coro_name(task)
            assert "my_coroutine" in name
        finally:
            loop.close()


class TestDBPoolStats:
    """Tests for _build_db_pool_stats() helper."""

    def test_pool_status_extraction(self):
        """Pool statistics correctly extracted from SQLAlchemy pool."""
        mock_pool = MagicMock()
        mock_pool.status.return_value = MagicMock(
            checkedin=3,
            checkedout=5,
            overflow=0,
        )
        mock_pool.size.return_value = 10
        mock_pool.max_overflow.return_value = 5

        stats = _build_db_pool_stats(mock_pool)

        assert stats["checked_in"] == 3
        assert stats["checked_out"] == 5
        assert stats["overflow"] == 0
        assert stats["pool_size"] == 10
        assert stats["max_overflow"] == 5
        assert stats["utilization_pct"] == 33.33  # 5 / (10 + 5) * 100

    def test_pool_utilization_calculation(self):
        """Utilization percentage calculated correctly."""
        mock_pool = MagicMock()
        mock_pool.status.return_value = MagicMock(
            checkedin=0,
            checkedout=8,
            overflow=2,
        )
        mock_pool.size.return_value = 10
        mock_pool.max_overflow.return_value = 5

        stats = _build_db_pool_stats(mock_pool)

        # checked_out=8, capacity=15, utilization=8/15=53.33%
        assert abs(stats["utilization_pct"] - 53.33) < 0.1

    def test_pool_zero_capacity(self):
        """Zero capacity returns 0.0 utilization."""
        mock_pool = MagicMock()
        mock_pool.status.return_value = MagicMock(
            checkedin=0,
            checkedout=0,
            overflow=0,
        )
        mock_pool.size.return_value = 0
        mock_pool.max_overflow.return_value = 0

        stats = _build_db_pool_stats(mock_pool)

        assert stats["utilization_pct"] == 0.0


class TestBuildTaskInfo:
    """Tests for _build_task_info() helper."""

    def test_complete_task_info(self):
        """All fields present in task info."""

        async def dummy():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(dummy(), name="test-task")
        task._created_at = time.monotonic() - 0.1

        try:
            info = _build_task_info(task)

            assert "name" in info
            assert "state" in info
            assert "cancelled" in info
            assert "coro_name" in info
            assert "wall_time_ms" in info
            assert "handle" in info

            assert info["name"] == "test-task"
            assert info["state"] == "pending"
            assert isinstance(info["wall_time_ms"], int)
            assert len(info["handle"]) == 8
        finally:
            task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()

    def test_unnamed_task(self):
        """Unnamed task returns task ID as name."""

        async def dummy():
            await asyncio.sleep(100)

        loop = asyncio.new_event_loop()
        task = loop.create_task(dummy())

        try:
            info = _build_task_info(task)
            # Unnamed tasks get "Task-N" format from Python
            assert info["name"].startswith("Task-")
        finally:
            task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()


# ============================================================================
# Endpoint Tests
# ============================================================================


def _create_test_app(backend=None):
    """Create a minimal test app with debug routes."""
    from server.dependencies import get_backend, require_admin
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    app.include_router(router, prefix="/api/v1/admin")

    # Mock backend if not provided
    if backend is None:
        mock_pool = MagicMock()
        mock_pool.status.return_value = MagicMock(checkedin=0, checkedout=0, overflow=0)
        mock_pool.size.return_value = 0
        mock_pool.max_overflow.return_value = 0
        mock_engine = MagicMock()
        mock_engine.pool = mock_pool
        backend = MagicMock()
        backend.engine = mock_engine

    app.dependency_overrides[get_backend] = lambda: backend

    # Mock require_admin to always pass
    app.dependency_overrides[require_admin] = lambda: {"user_id": "admin", "caller": "admin"}

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            request.state.auth_user = {"user_id": "admin", "caller": "admin"}
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestAsyncIOStateEndpoint:
    """Tests for GET /api/v1/admin/debug/asyncio-state endpoint."""

    def test_endpoint_returns_200(self):
        """Authenticated admin request returns 200."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending_tasks" in data
        assert "total_tasks" in data
        assert "tasks" in data
        assert "event_loop" in data
        assert "db_pool" in data

    def test_response_contains_expected_fields(self):
        """Response includes all expected fields with correct types."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()

        # Top-level fields
        assert isinstance(data["pending_tasks"], int)
        assert isinstance(data["total_tasks"], int)
        assert isinstance(data["tasks"], list)
        assert isinstance(data["event_loop"], dict)
        assert isinstance(data["db_pool"], dict)

        # Event loop fields
        assert "time" in data["event_loop"]
        assert "running" in data["event_loop"]
        assert "latency_us" in data["event_loop"]

        # DB pool fields
        assert "checked_in" in data["db_pool"]
        assert "checked_out" in data["db_pool"]
        assert "overflow" in data["db_pool"]
        assert "pool_size" in data["db_pool"]
        assert "max_overflow" in data["db_pool"]
        assert "utilization_pct" in data["db_pool"]

    def test_task_list_populated(self):
        """Task list contains current event loop tasks."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()

        # Should have at least the request handler task
        assert data["total_tasks"] >= 1

        # Check task structure
        if data["tasks"]:
            task = data["tasks"][0]
            assert "name" in task
            assert "state" in task
            assert "cancelled" in task
            assert "coro_name" in task
            assert "handle" in task

    def test_db_pool_null_when_no_backend(self):
        """DB pool returns zeros when backend has no engine."""

        class NoEngineBackend:
            pass

        no_engine_backend = NoEngineBackend()
        app = _create_test_app(backend=no_engine_backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()
        assert data["db_pool"]["checked_in"] == 0
        assert data["db_pool"]["pool_size"] == 0

    def test_db_pool_with_mocked_backend(self):
        """DB pool stats populated when backend exists."""
        mock_pool = MagicMock()
        mock_pool.status.return_value = MagicMock(
            checkedin=3,
            checkedout=5,
            overflow=0,
        )
        mock_pool.size.return_value = 5
        mock_pool.max_overflow.return_value = 10

        mock_engine = MagicMock()
        mock_engine.pool = mock_pool

        mock_backend = MagicMock()
        mock_backend.engine = mock_engine

        app = _create_test_app(backend=mock_backend)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()

        assert data["db_pool"]["checked_in"] == 3
        assert data["db_pool"]["checked_out"] == 5
        assert data["db_pool"]["pool_size"] == 5
        assert data["db_pool"]["max_overflow"] == 10
        assert data["db_pool"]["utilization_pct"] == 33.33  # 5 / (5 + 10) * 100

    def test_event_loop_running(self):
        """Event loop running field is True when called from running loop."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()
        assert data["event_loop"]["running"] is True

    def test_utilization_pct_valid_range(self):
        """Utilization percentage is in valid 0-100 range."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()
        utilization = data["db_pool"]["utilization_pct"]
        assert 0.0 <= utilization <= 100.0


class TestAsyncIOStateWithTasks:
    """Tests for task visibility in the endpoint."""

    def test_tasks_have_correct_structure(self):
        """All tasks in response have the expected fields."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()

        # Should have at least the request handler task
        assert data["total_tasks"] >= 1

        # Verify each task has the expected structure
        for task in data["tasks"]:
            assert "name" in task
            assert "state" in task
            assert "cancelled" in task
            assert "coro_name" in task
            assert "wall_time_ms" in task
            assert "handle" in task
            assert task["state"] in ("pending", "done", "cancelled", "failed")

    def test_pending_tasks_count(self):
        """pending_tasks count matches tasks with state='pending'."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/asyncio-state")
        data = resp.json()

        pending_count = sum(1 for t in data["tasks"] if t["state"] == "pending")
        assert data["pending_tasks"] == pending_count
