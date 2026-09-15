# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for audit log endpoints."""

from datetime import UTC
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import audit as audit_routes
from starlette.testclient import TestClient

# Store the original _is_admin so we can restore it after monkeypatch.
_ORIGINAL_IS_ADMIN = audit_routes._is_admin


@pytest.fixture(autouse=True)
def _restore_is_admin():
    """Restore the real _is_admin after each test, so the module-level
    monkeypatch in _create_test_app / _make_app_with_user does not leak
    into TestIsAdminHelper's direct unit tests of the real function."""
    yield
    audit_routes._is_admin = _ORIGINAL_IS_ADMIN


def _create_test_app(
    backend=None,
    override_guard=True,
    user_id="admin",
    is_admin=True,
):
    """Create a minimal test app with audit route.

    Overrides get_current_user (the inner dependency of require_role) so
    the endpoint receives a known auth_user dict.  Monkeypatches _is_admin
    so the caller's visibility is controllable.
    """
    from core.iam.role_manager import RoleManager
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")
    if override_guard:
        app.dependency_overrides[get_current_user] = lambda: {
            "user_id": user_id,
            "roles": [42],
        }
        audit_routes._is_admin = lambda db, uid: is_admin
        # require_role("read") calls RoleManager.get_user_permissions which
        # hits the mock db → empty list → empty dict → 403. Patch it away.
        patch.object(RoleManager, "get_user_permissions", return_value={1: "read"}).start()

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestAuditList:
    """Tests for audit log listing endpoint."""

    def test_list_empty(self):
        """GET /audit should return empty list when no events."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 0

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["events"] == []
        assert data["total"] == 0

    def test_list_with_events(self):
        """GET /audit should return events."""
        import json
        from datetime import datetime

        # Events returned newest-first (timestamp desc)
        event1 = SimpleNamespace(
            id=2,
            event_type="secret.delete",
            user_id="user1",
            fields=None,
            timestamp=datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC),
        )
        event2 = SimpleNamespace(
            id=1,
            event_type="secret.create",
            user_id="user1",
            fields=json.dumps({"key": "mysecret"}),
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
        )

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 2

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return [event1, event2]

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["events"]) == 2
        assert data["events"][0]["event_type"] == "secret.delete"
        assert data["events"][1]["event_type"] == "secret.create"

    def test_list_with_user_filter(self):
        """GET /audit should filter by user."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 1

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"user": "user1"})
        assert resp.status_code == 200

    def test_list_with_date_range(self):
        """GET /audit should filter by date range."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 5

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/audit",
            params={
                "start_date": "2024-01-01T00:00:00Z",
                "end_date": "2024-01-31T23:59:59Z",
            },
        )
        assert resp.status_code == 200

    def test_list_with_days_filter(self):
        """GET /audit should filter by last N days."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 10

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"days": 7})
        assert resp.status_code == 200

    def test_list_with_hours_filter(self):
        """GET /audit should filter by last N hours."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 3

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"hours": 24})
        assert resp.status_code == 200

    def test_list_pagination(self):
        """GET /audit should respect limit and offset."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 50

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, offset_val, **kwargs):
                assert offset_val == 20
                return self

            def limit(self, limit_val, **kwargs):
                assert limit_val == 10
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"limit": 10, "offset": 20})
        assert resp.status_code == 200

    def test_list_no_backend(self):
        """GET /audit should return 503 if backend not initialized."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 503

    def test_list_with_executor_id_filter(self):
        """GET /audit should filter by executor_id in fields JSON."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 1

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"executor_id": "jump-1"})
        assert resp.status_code == 200

    def test_list_executor_id_with_hours(self):
        """GET /audit should combine executor_id and hours filters."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 5

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"executor_id": "jump-1", "hours": 24})
        assert resp.status_code == 200

    def test_list_executor_id_with_limit_offset(self):
        """GET /audit should combine executor_id with pagination."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 50

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, offset_val, **kwargs):
                assert offset_val == 10
                return self

            def limit(self, limit_val, **kwargs):
                assert limit_val == 20
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/audit",
            params={"executor_id": "jump-1", "limit": 20, "offset": 10},
        )
        assert resp.status_code == 200

    def test_list_empty_fields_no_crash(self):
        """GET /audit should handle events with empty fields gracefully."""
        from types import SimpleNamespace

        event = SimpleNamespace(
            id=1,
            event_type="heartbeat",
            user_id=None,
            fields=None,
            timestamp=__import__("datetime").datetime(2024, 1, 1, 12, 0, 0, tzinfo=__import__("datetime").timezone.utc),
        )

        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 1

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return [event]

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"executor_id": "jump-1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    def test_list_invalid_start_date(self):
        """GET /audit should return 400 for invalid start_date."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 0

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"start_date": "not-a-date"})
        assert resp.status_code == 400

    def test_list_invalid_end_date(self):
        """GET /audit should return 400 for invalid end_date."""
        db = MagicMock()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def count(self):
                return 0

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return []

        db.query.return_value = MockQuery()
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"end_date": "garbage"})
        assert resp.status_code == 400


class TestAuditGuard:
    """Guard enforcement on GET /audit (require_role("read"))."""

    def test_no_auth_user_rejected(self):
        """Without auth override (no auth_user set), GET /audit is 401."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        # override_guard=False leaves require_role("read") live; no middleware sets auth_user
        app = _create_test_app(backend=backend, override_guard=False)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 401


class TestAuditNonAdmin:
    """Non-admin self-filtering on GET /audit."""

    def _make_app_with_user(self, user_id: str, is_admin: bool, backend=None):
        """Create test app with a specific user and admin status."""
        from server.dependencies import get_current_user
        from starlette.middleware.base import BaseHTTPMiddleware

        app = FastAPI()
        if backend is not None:
            app.state.backend = backend
        else:
            # Provide a minimal mock backend so get_backend doesn't 503.
            mock_backend = MagicMock()
            mock_backend.get_session.return_value = MagicMock()
            app.state.backend = mock_backend
        app.include_router(audit_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id, "roles": [42]}
        audit_routes._is_admin = lambda db, uid: is_admin

        class AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                return await call_next(request)

        app.add_middleware(AuthMiddleware)
        return app

    def test_non_admin_sees_own_events_only(self):
        """Non-admin user sees only events with their user_id."""
        import json
        from datetime import datetime

        admin_event = SimpleNamespace(
            id=1,
            event_type="command_executed",
            user_id="admin",
            fields=json.dumps({"executor_id": "exec-1"}),
            timestamp=datetime.now(UTC),
        )
        alice_event = SimpleNamespace(
            id=2,
            event_type="command_executed",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-2"}),
            timestamp=datetime.now(UTC),
        )

        class MockQuery:
            def __init__(self, events):
                self._events = events
                self._filters = []

            def filter(self, *args, **kwargs):
                self._filters.append(args)
                return self

            def count(self):
                return len(self.all())

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def first(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id == val]
                return result[0] if result else None

            def all(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id == val]
                return result

        db = MagicMock()
        db.query.return_value = MockQuery([admin_event, alice_event])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("alice", is_admin=False, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["user_id"] == "alice"

    def test_admin_sees_all_events(self):
        """Admin user sees events for all users."""
        import json
        from datetime import datetime

        admin_event = SimpleNamespace(
            id=1,
            event_type="command_executed",
            user_id="admin",
            fields=json.dumps({"executor_id": "exec-1"}),
            timestamp=datetime.now(UTC),
        )
        alice_event = SimpleNamespace(
            id=2,
            event_type="command_executed",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-2"}),
            timestamp=datetime.now(UTC),
        )

        class MockQuery:
            def __init__(self, events):
                self._events = events
                self._filters = []

            def filter(self, *args, **kwargs):
                self._filters.append(args)
                return self

            def count(self):
                return len(self.all())

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def first(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id == val]
                return result[0] if result else None

            def all(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id == val]
                return result

        db = MagicMock()
        db.query.return_value = MockQuery([admin_event, alice_event])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("admin", is_admin=True, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_hours_filter(self):
        """hours param filters events outside the window."""
        import json
        from datetime import datetime, timedelta

        recent = SimpleNamespace(
            id=1,
            event_type="command_executed",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-1"}),
            timestamp=datetime.now(UTC) - timedelta(hours=1),
        )
        old = SimpleNamespace(
            id=2,
            event_type="command_executed",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-2"}),
            timestamp=datetime.now(UTC) - timedelta(hours=48),
        )

        class MockQuery:
            def __init__(self, events):
                self._events = events
                self._filters = []

            def filter(self, *args, **kwargs):
                self._filters.append(args)
                return self

            def count(self):
                return len(self.all())

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "timestamp":
                                result = [e for e in result if e.timestamp >= val]
                return result

        db = MagicMock()
        db.query.return_value = MockQuery([recent, old])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("alice", is_admin=True, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"hours": 24})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["user_id"] == "alice"

    def test_event_type_filter(self):
        """event_type param filters to matching events."""
        import json
        from datetime import datetime

        cmd_event = SimpleNamespace(
            id=1,
            event_type="command_executed",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-1"}),
            timestamp=datetime.now(UTC),
        )
        session_event = SimpleNamespace(
            id=2,
            event_type="execution_session_created",
            user_id="alice",
            fields=json.dumps({"executor_id": "exec-2"}),
            timestamp=datetime.now(UTC),
        )

        class MockQuery:
            def __init__(self, events):
                self._events = events
                self._filters = []

            def filter(self, *args, **kwargs):
                self._filters.append(args)
                return self

            def count(self):
                return len(self.all())

            def order_by(self, *args, **kwargs):
                return self

            def offset(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "event_type":
                                result = [e for e in result if e.event_type == val]
                return result

        db = MagicMock()
        db.query.return_value = MockQuery([cmd_event, session_event])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("alice", is_admin=True, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit", params={"event_type": "command_executed"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["event_type"] == "command_executed"


class TestIsAdminHelper:
    """Direct unit tests for _is_admin helper."""

    def test_admin_member_returns_true(self):
        """User who is a member of the admin role → True."""
        mock_admin_role = SimpleNamespace(id=1)
        mock_member = SimpleNamespace()

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_member

        class RoleQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_admin_role

        db = MagicMock()

        def query_side_effect(model):
            if model.__name__ == "Role":
                return RoleQuery()
            return MockQuery()

        db.query.side_effect = query_side_effect
        assert audit_routes._is_admin(db, "alice") is True

    def test_role_less_user_returns_false(self):
        """User with no role memberships → False."""
        mock_admin_role = SimpleNamespace(id=1)

        class RoleQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return mock_admin_role

        class MemberQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

        db = MagicMock()

        def query_side_effect(model):
            if model.__name__ == "Role":
                return RoleQuery()
            return MemberQuery()

        db.query.side_effect = query_side_effect
        assert audit_routes._is_admin(db, "bob") is False

    def test_missing_admin_role_returns_false(self):
        """No admin role in the system → False."""

        class MockQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return None

        db = MagicMock()
        db.query.return_value = MockQuery()
        assert audit_routes._is_admin(db, "alice") is False
