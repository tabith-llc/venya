# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for audit log endpoints."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import audit as audit_routes
from starlette.testclient import TestClient

# Store the original _is_admin so we can restore it after monkeypatch.
_ORIGINAL_IS_ADMIN = audit_routes._is_admin

# updated (executor-revocation-by-identity session): patchers started by
# _create_test_app were NEVER stopped — patch.object(RoleManager,
# "get_user_permissions").start() leaked a class-level patch for the rest of
# the pytest session, pinning require_role("read-write") to {1: "read"} in
# EVERY later module (caught by the dial-gate truth cells). Track + stop them.
_STARTED_PATCHERS: list = []


@pytest.fixture(autouse=True)
def _restore_is_admin():
    """Restore the real _is_admin after each test, so the module-level
    monkeypatch in _create_test_app / _make_app_with_user does not leak
    into TestIsAdminHelper's direct unit tests of the real function."""
    yield
    audit_routes._is_admin = _ORIGINAL_IS_ADMIN
    while _STARTED_PATCHERS:
        _STARTED_PATCHERS.pop().stop()


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
        # require_role("auditor") calls RoleManager.get_user_permissions which
        # hits the mock db → empty list → empty dict → 403. Patch it away
        # (read-write = the admin-seeded tier; exceeds the auditor gate).
        _p = patch.object(RoleManager, "get_user_permissions", return_value={1: "read-write"})
        _p.start()
        _STARTED_PATCHERS.append(_p)

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


class TestAuditGuardAuditorTier:
    """Route-level truth table for the auditor gate on GET /api/v1/audit
    (ticket auditor-role). The route moved require_role("read") →
    require_role("auditor"): auditor passes, read-only is DENIED (the
    deliberate release-notes behavior change), read-write/admin still pass
    (regression pin — the ticket's own snippet would have locked admins out).

    NOTE: route path is /api/v1/audit — the ticket cites "/audit/events",
    which does not exist (stale cite, live route verified at audit.py:43-44).
    """

    def _app(self, tier):
        """Self-contained app: live require_role, mocked permissions lookup."""
        from core.iam.role_manager import RoleManager
        from starlette.middleware.base import BaseHTTPMiddleware

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

        app = FastAPI()
        app.state.backend = backend
        app.include_router(audit_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "u1", "roles": [42]}
        audit_routes._is_admin = lambda db_, uid: False

        _p = patch.object(RoleManager, "get_user_permissions", return_value={1: tier})
        _p.start()
        _STARTED_PATCHERS.append(_p)  # autouse fixture stops it

        class AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                return await call_next(request)

        app.add_middleware(AuthMiddleware)
        return app

    def _get(self, tier):
        client = TestClient(self._app(tier), raise_server_exceptions=False)
        return client.get("/api/v1/audit")

    def test_auditor_role_gets_audit_log(self):
        """Acceptance: auditor-role user CAN query the audit log."""
        resp = self._get("auditor")
        assert resp.status_code == 200
        assert resp.json()["events"] == []

    def test_read_role_denied_403(self):
        """Acceptance + PAIRED NEGATIVE: read-role user CANNOT (403) — audit
        access is auditor-scoped, not general-read."""
        resp = self._get("read")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Auditor permission required"

    def test_read_write_role_still_gets_audit_log(self):
        """Regression pin: read-write (the admin-seeded tier) exceeds auditor."""
        resp = self._get("read-write")
        assert resp.status_code == 200


class TestAuditNonAdmin:
    """Non-admin self-filtering on GET /audit."""

    def _make_app_with_user(self, user_id: str, is_admin: bool, backend=None, tier="read-write"):
        """Create test app with a specific user and admin status.

        tier: role permission tier the auditor gate resolves for this
        caller (default read-write — the pre-ruling non-admin operator;
        visibility cells pass "auditor" for the auditor-tier ruling).
        """
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
        # updated: this helper previously FREE-RODE the never-stopped
        # RoleManager patch leaked by _create_test_app (order-dependent green).
        # With the leak stopped per-test, patch explicitly via the tracked list.
        from core.iam.role_manager import RoleManager

        # tier defaults to read-write (operator; passes the auditor gate —
        # ticket auditor-role). Visibility cells pass "auditor" for the
        # auditor-tier FULL-visibility ruling (owner 2026-09-30).
        _p = patch.object(RoleManager, "get_user_permissions", return_value={1: tier})
        _p.start()
        _STARTED_PATCHERS.append(_p)

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

    def test_non_admin_cannot_see_null_userid_events(self):
        """Non-admin user cannot see events with user_id IS NULL (Gate 3 audit ticket).

        SQL equality NULL == 'alice' evaluates to UNKNOWN, so these rows
        are excluded. This is the paired negative for test_non_admin_sees_own_events_only.
        """
        import json
        from datetime import datetime

        null_event = SimpleNamespace(
            id=1,
            event_type="executor_registered",
            user_id=None,
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

            def all(self):
                result = self._events
                for args in self._filters:
                    if len(args) >= 1:
                        expr = args[0]
                        if hasattr(expr, "left") and hasattr(expr, "right"):
                            col = expr.left
                            val = expr.right.value if hasattr(expr.right, "value") else expr.right
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id is not None and e.user_id == val]
                return result

        db = MagicMock()
        db.query.return_value = MockQuery([null_event, alice_event])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("alice", is_admin=False, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["user_id"] == "alice"
        assert data["events"][0]["event_type"] == "command_executed"

    def test_admin_sees_null_userid_events(self):
        """Admin user can see events with user_id IS NULL (Gate 3 audit ticket).

        Admin has no filter applied, so NULL rows pass through.
        """
        import json
        from datetime import datetime

        null_event = SimpleNamespace(
            id=1,
            event_type="executor_registered",
            user_id=None,
            fields=json.dumps({"executor_id": "exec-1"}),
            timestamp=datetime.now(UTC),
        )
        admin_event = SimpleNamespace(
            id=2,
            event_type="command_executed",
            user_id="admin",
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
                return self._events

        db = MagicMock()
        db.query.return_value = MockQuery([null_event, admin_event])
        backend = MagicMock()
        backend.get_session.return_value = db
        app = self._make_app_with_user("admin", is_admin=True, backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        event_types = {e["event_type"] for e in data["events"]}
        assert "executor_registered" in event_types
        assert "command_executed" in event_types

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


class TestAuditAuditorTierVisibility:
    """Auditor-tier FULL audit-log visibility (owner ruling 2026-09-30:
    'THAT IS NOT A TRUE AUDITOR!' — the pre-ruling non-admin self-filter
    left an auditor seeing only their OWN events, which is not an auditor.
    Auditor-tier memberships see the full log; every other non-admin tier
    keeps the self-filter (paired negatives below)."""

    def _events(self):
        import json
        from datetime import datetime

        return [
            SimpleNamespace(
                id=1,
                event_type="command_executed",
                user_id="admin",
                fields=json.dumps({"executor_id": "exec-1"}),
                timestamp=datetime.now(UTC),
            ),
            SimpleNamespace(
                id=2,
                event_type="command_executed",
                user_id="alice",
                fields=json.dumps({"executor_id": "exec-2"}),
                timestamp=datetime.now(UTC),
            ),
        ]

    def _query(self, events):
        class MockQuery:
            def __init__(self, evts):
                self._events = evts
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
                            if hasattr(col, "name") and col.name == "user_id":
                                result = [e for e in result if e.user_id is not None and e.user_id == val]
                return result

        return MockQuery(events)

    def test_auditor_tier_non_admin_sees_all_events(self):
        """P: auditor-only membership, NOT an admin-role member -> FULL log
        (other users' events present; the query carries no user_id filter)."""
        db = MagicMock()
        db.query.return_value = self._query(self._events())
        backend = MagicMock()
        backend.get_session.return_value = db
        app = TestAuditNonAdmin()._make_app_with_user("alice", is_admin=False, backend=backend, tier="auditor")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert {e["user_id"] for e in data["events"]} == {"admin", "alice"}

    def test_read_write_non_admin_still_self_filtered(self):
        """N1 paired negative: read-write WITHOUT auditor/admin keeps the
        self-filter — full visibility is admin + auditor-tier, not
        'everyone who can reach the route'."""
        db = MagicMock()
        db.query.return_value = self._query(self._events())
        backend = MagicMock()
        backend.get_session.return_value = db
        app = TestAuditNonAdmin()._make_app_with_user("alice", is_admin=False, backend=backend, tier="read-write")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["user_id"] == "alice"

    def test_missing_role_map_falls_back_to_self_filter(self):
        """H: fail-closed half — with NO gate-attached role map on the
        auth_user dict the handler falls back to the conservative
        SELF-FILTER, never the full log (defensive branch: every route
        call passes the attaching _checker, so this pins the fallback
        directly at the handler)."""
        import asyncio

        events = self._events()
        query = self._query(events)
        db = MagicMock()
        db.query.return_value = query
        audit_routes._is_admin = lambda db_, uid: False

        resp = asyncio.run(
            audit_routes.audit_list(
                user=None,
                key=None,
                start_date=None,
                end_date=None,
                days=None,
                hours=None,
                event_type=None,
                executor_id=None,
                limit=100,
                offset=0,
                auth_user={"user_id": "alice"},
                db=db,
            )
        )
        assert resp.total == 1
        assert resp.events[0].user_id == "alice"


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


# ---------------------------------------------------------------------------
# POST /audit/ingest — executor-mTLS audit forwarder sink (#307)
# ---------------------------------------------------------------------------


from core.iam import models as audit_models

EXEC_CN = "venya-exec-1"
LIVE_SERIAL = "0000000000000001"
PRESENTED_SERIAL = "00000000000000ff"


def _sqlite_ingest_backend(
    revoked: bool = False,
    cert_serial: str | None = None,
    revoked_serial: str | None = None,
):
    """Real in-memory SQLite backend: AuditEvent + revocation tables, so
    ingest rows LAND for real and are readable back (not mock-chain
    theater). revoked=True sets the identity flag (Executor.revoked_at).
    cert_serial seeds the CURRENT ExecutorCert record; revoked_serial seeds
    a serial-only revocation (identity stays live) — the
    audit-ingest-revoked-serial-flag-divergence shape."""
    from datetime import datetime, timedelta

    from core.iam.models import AuditEvent, Executor, ExecutorCert, ExecutorCertRevocation
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    for table in (
        AuditEvent.__table__,
        Executor.__table__,
        ExecutorCert.__table__,
        ExecutorCertRevocation.__table__,
    ):
        table.create(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now(UTC)
    session.add(
        Executor(
            id=EXEC_CN,
            hostname="venya-exec-1",
            revoked_at=now if revoked else None,
        )
    )
    if cert_serial is not None:
        session.add(
            ExecutorCert(
                executor_id=EXEC_CN,
                serial_number=cert_serial,
                not_before=now - timedelta(days=1),
                not_after=now + timedelta(days=365),
                fingerprint="fp-current",
            )
        )
    if revoked_serial is not None:
        session.add(ExecutorCertRevocation(serial_number=revoked_serial, executor_id=EXEC_CN))
    session.commit()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: sessionmaker(bind=engine)()
    return backend, sessionmaker(bind=engine), engine


def _ingest_app(auth_user, backend):
    """Real audit router + middleware that injects the executor auth state
    the SessionMiddleware would set (mirrors test_filter_endpoint's
    injection pattern; the REAL middleware branch is pinned in
    test_session_middleware.py). auth_user=None simulates a request that
    reached the route without executor identity (route-side guard half)."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")

    class _AuthUserMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = dict(auth_user)
            return await call_next(request)

    app.add_middleware(_AuthUserMiddleware)
    return app


def _ndjson_zstd(lines: list[str]) -> bytes:
    from compression import zstd

    return zstd.compress(("\n".join(lines) + "\n").encode(), level=3)


def _in_window_ts(offset_hours: float = -2.0) -> datetime:
    """A client timestamp INSIDE the #461 skew band, derived from the server
    clock at run time (not a pinned calendar date, which ages out of the
    band and silently turns a positive fixture into a clamped one).
    Offset off "now" so a wall-clock fallback can never match by accident.
    """
    from datetime import timedelta

    return datetime.now(UTC) + timedelta(hours=offset_hours)


def _rejection_line(**over) -> str:
    import json

    payload = {
        "event_type": "command_rejected",
        "session_id": "sess-9",
        "timestamp": _in_window_ts().isoformat(),
        "command": "scp secrets.txt host2:/tmp/",
        "reason": "blocked pattern: scp",
    }
    payload.update(over)
    return json.dumps(payload)


def _executor_auth() -> dict:
    return {"caller": "executor", "executor_id": EXEC_CN}


def _post_ingest(app, body: bytes, headers: dict | None = None):
    hdrs = {
        "Content-Type": "application/x-ndjson",
        "Content-Encoding": "zstd",
    }
    if headers is not None:
        hdrs.update(headers)
    return TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/audit/ingest",
        content=body,
        headers=hdrs,
    )


class TestAuditIngest:
    """Truth table for the #307 sink: forwarded executor events land with
    provenance; every refusal is paired with its succeeding twin."""

    def test_P1_valid_batch_lands_and_visible_to_get(self):
        """P: authenticated 2-line batch (incl. command_rejected with command
        text) → 200, rows land with CN + provenance fields; GET with
        event_type filter sees the rejection; fields carry executor_id
        (the GET executor_id filter's key — sqlite cast variant is
        PostgreSQL-only, so the key is asserted directly via the sqlite
        ->> operator; physical halves are cells F1/F3)."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        sent_ts = _in_window_ts()
        line2 = json.dumps(
            {
                "event_type": "command_executed",
                "session_id": "sess-9",
                "timestamp": (sent_ts + timedelta(seconds=5)).isoformat(),
                "command": "ls -la",
                "exit_code": 0,
                "duration_ms": 3.2,
            }
        )
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line(timestamp=sent_ts.isoformat()), line2]))
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 2}

        s = sm()
        rows = {r.event_type: r for r in s.query(audit_models.AuditEvent).all()}
        assert set(rows) == {"command_rejected", "command_executed"}
        rej = rows["command_rejected"]
        assert rej.user_id == EXEC_CN  # migration-022: mTLS CN verbatim
        fields = json.loads(rej.fields)
        assert fields["executor_id"] == EXEC_CN
        assert fields["sender_revoked"] is False
        assert fields["forwarded"] is True
        assert fields["command"] == "scp secrets.txt host2:/tmp/"  # UNMASKED by design
        assert fields["reason"] == "blocked pattern: scp"
        # spool timestamp preserved EXACTLY as supplied — in-window stamps are
        # never rewritten (SQLite drops the offset on read: compare wall
        # value; a wall-clock fallback would not match)
        assert rej.timestamp.replace(tzinfo=UTC) == sent_ts.replace(tzinfo=UTC)
        assert json.loads(rej.fields)["timestamp_skewed"] is False
        # executor_id readable via the JSON operator (GET filter's key)
        from sqlalchemy import text

        got = s.execute(
            text("SELECT fields ->> 'executor_id' FROM audit_events WHERE event_type='command_rejected'")
        ).scalar()
        assert got == EXEC_CN
        s.close()

        # auditor-tier GET visibility (event_type equality filter is real SQL,
        # works on sqlite) — same engine behind the standard GET harness.
        get_backend = MagicMock()
        get_backend.get_session.side_effect = lambda: sm()
        get_app = _create_test_app(backend=get_backend)
        client = TestClient(get_app, raise_server_exceptions=False)
        g = client.get("/api/v1/audit", params={"event_type": "command_rejected"})
        assert g.status_code == 200
        data = g.json()
        assert data["total"] == 1
        assert data["events"][0]["event_type"] == "command_rejected"
        assert data["events"][0]["user_id"] == EXEC_CN

    def test_P2_unknown_but_valid_event_type_lands(self):
        """P (D4 pin): forward-compat — unknown-but-well-formed type lands
        (String(64) no-CHECK is deliberate)."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        line = json.dumps(
            {"event_type": "future_executor_event", "session_id": "s1", "timestamp": _in_window_ts().isoformat()}
        )
        resp = _post_ingest(app, _ndjson_zstd([line]))
        assert resp.status_code == 200
        s = sm()
        assert s.query(audit_models.AuditEvent).filter_by(event_type="future_executor_event").count() == 1
        s.close()

    def test_N1_no_executor_identity_refused_zero_rows(self):
        """N (paired with P1): request without executor auth state → 403,
        nothing written (route-side guard; the middleware 401 half is
        pinned in test_session_middleware.py)."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(None, backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]))
        assert resp.status_code == 403
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()

    def test_N2_revoked_sender_rows_land_flagged(self):
        """N/D2 (paired with P1): REVOKED registered executor's batch LANDS
        with sender_revoked=true — evidence preservation ruling; never a
        403 retry loop, never a silent drop."""
        backend, sm, _engine = _sqlite_ingest_backend(revoked=True)
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]))
        assert resp.status_code == 200
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        assert row.event_type == "command_rejected"
        assert json.loads(row.fields)["sender_revoked"] is True
        s.close()

    def test_P_serial_stash_presented_revoked_lands_flagged(self):
        """P (audit-ingest-revoked-serial-flag-divergence): identity NOT
        flagged, CURRENT cert live, but the PRESENTED serial is in the
        revocation table — admission (reject_revoked=False) stashes that
        verdict and the ingest route must write it. Pre-fix the route
        re-derived WITHOUT the serial → rows landed unflagged. Expected
        RED pre-fix."""
        backend, sm, _engine = _sqlite_ingest_backend(cert_serial=LIVE_SERIAL, revoked_serial=PRESENTED_SERIAL)
        auth = {"caller": "executor", "executor_id": EXEC_CN, "presented_serial": PRESENTED_SERIAL, "revoked": True}
        app = _ingest_app(auth, backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]))
        assert resp.status_code == 200
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        assert json.loads(row.fields)["sender_revoked"] is True
        s.close()

    def test_N_stash_nonrevoked_serial_lands_unflagged(self):
        """N (paired with P-serial): the same request via a NON-revoked
        presented serial → flag false, rows parseable — the stash never
        hard-codes the flag."""
        backend, sm, _engine = _sqlite_ingest_backend(cert_serial=LIVE_SERIAL, revoked_serial=PRESENTED_SERIAL)
        auth = {"caller": "executor", "executor_id": EXEC_CN, "presented_serial": LIVE_SERIAL, "revoked": False}
        app = _ingest_app(auth, backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]))
        assert resp.status_code == 200
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        assert json.loads(row.fields)["sender_revoked"] is False
        s.close()

    def test_N_fallback_absent_stash_recomputes_with_serial(self):
        """Defense-in-depth half: a caller dict WITHOUT the stashed
        "revoked" key must fall back to a fresh derivation that still
        carries the presented serial — never the pre-fix no-serial call
        (which would miss a serial-only revocation of a live identity)."""
        backend, sm, _engine = _sqlite_ingest_backend(cert_serial=LIVE_SERIAL, revoked_serial=PRESENTED_SERIAL)
        auth = {"caller": "executor", "executor_id": EXEC_CN, "presented_serial": PRESENTED_SERIAL}
        app = _ingest_app(auth, backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]))
        assert resp.status_code == 200
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        assert json.loads(row.fields)["sender_revoked"] is True
        s.close()

    def test_N3_malformed_line_rejects_whole_batch_zero_rows(self):
        """N/D4 (twin: the same batch WITHOUT the garbage succeeds):
        a garbage line mid-batch → 400, ZERO rows — no partial write,
        forwarder keeps its lines and the server log names the line."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        # twin half: clean batch first
        good = _ndjson_zstd([_rejection_line(), _rejection_line(session_id="sess-10")])
        assert _post_ingest(app, good).status_code == 200
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 2
        s.close()
        # poison half: same batch + a garbage line
        bad = _ndjson_zstd(
            [_rejection_line(session_id="sess-11"), "NOT-JSON{{{", _rejection_line(session_id="sess-12")]
        )
        resp = _post_ingest(app, bad)
        assert resp.status_code == 400
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 2  # zero NEW rows
        s.close()

    def test_N4_missing_zstd_encoding_refused(self):
        """N (paired with P1): uncompressed upload → 400, nothing written."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(
            app,
            (_rejection_line() + "\n").encode(),
            headers={"Content-Encoding": "identity"},
        )
        assert resp.status_code == 400
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()

    def test_N5_line_count_over_cap_refused(self):
        """N (paired with P1): > INGEST_MAX_LINES lines → 4xx, zero rows
        (server-side second guard, D3)."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        over = audit_routes.INGEST_MAX_LINES + 1
        line = json.dumps({"event_type": "command_executed", "session_id": "s"})
        resp = _post_ingest(app, _ndjson_zstd([line] * over))
        assert 400 <= resp.status_code < 500
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()

    def test_N6_empty_body_refused(self):
        """N (paired with P1): empty body → 400 (forwarder never sends one;
        pins the contract)."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(app, b"")
        assert resp.status_code == 400
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()

    def test_missing_ndjson_content_type_refused(self):
        """N (paired with P1): zstd body but wrong Content-Type → 400."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line()]), headers={"Content-Type": "application/json"})
        assert resp.status_code == 400
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()

    def test_blank_lines_tolerated_line_still_counted(self):
        """Twin guard for N5's boundary: trailing blank lines (the spool's
        newline-terminated shape) never trip the cap or poison the batch."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line(), ""]))
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 1}
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 1
        s.close()

    def test_event_type_over_64_chars_or_empty_rejected(self):
        """N/D4 (twin = P2): structural bounds — empty or >64-char event_type
        is a producer bug → whole-batch 400."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        for bad_type in ("", "x" * 65):
            line = json.dumps({"event_type": bad_type, "session_id": "s"})
            resp = _post_ingest(app, _ndjson_zstd([line]))
            assert resp.status_code == 400
        s = sm()
        assert s.query(audit_models.AuditEvent).count() == 0
        s.close()


# ---------------------------------------------------------------------------
# POST /audit/ingest — client-timestamp bound (#461)
# ---------------------------------------------------------------------------


class TestAuditIngestTimestampBound461:
    """Ticket audit-ingest-accepts-unbound-client-timestamps #461.

    _spool_timestamp trusted ANY tz-aware executor-supplied stamp, while the
    GET windows (days=/hours=) cut on the SERVER clock: a skewed executor
    stamped its rows outside the window and they vanished from the auditor's
    view without a single row being deleted.

    Chosen shape: CLAMP to the edge of the band + structured FLAG. The bound
    is audit_routes.INGEST_MAX_TIMESTAMP_SKEW (24 hours, server clock, both
    directions). Reject was rejected (it drops the batch and hands the
    executor a permanent stall); flag-only was rejected (the row stays
    invisible, which is the very evasion being fixed). An honest in-window
    executor sees ZERO change — the paired positive cells below pin that.
    """

    def _ingest_one(self, timestamp):
        """Ingest a single line carrying ``timestamp``; return the landed row."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(app, _ndjson_zstd([_rejection_line(timestamp=timestamp)]))
        assert resp.status_code == 200, resp.text
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        result = (row, s)
        return result

    # ---- paired positive: the honest executor is untouched ----

    def test_P1_in_window_stamp_stored_exactly(self):
        """P (AC-2): a stamp inside the band is stored EXACTLY as supplied —
        no clamp, no flag, no extra keys in the row."""
        supplied = datetime.now(UTC) - timedelta(hours=6)
        row, s = self._ingest_one(supplied.isoformat())
        assert row.timestamp.replace(tzinfo=UTC) == supplied
        fields = json.loads(row.fields)
        assert fields["timestamp_skewed"] is False
        # the repair fields are ABSENT for an honest row — nothing invented
        assert "client_timestamp" not in fields
        assert "client_skew_seconds" not in fields
        s.close()

    def test_P2_stamp_near_the_band_edge_stored_exactly(self):
        """P (boundary, honest half): just INSIDE the edge is stored exactly.
        (A literal at-the-edge stamp is a race — the server clock moves
        between the test and the ingest — so the cell sits 5 minutes inside.)"""
        supplied = datetime.now(UTC) - audit_routes.INGEST_MAX_TIMESTAMP_SKEW + timedelta(minutes=5)
        row, s = self._ingest_one(supplied.isoformat())
        assert row.timestamp.replace(tzinfo=UTC) == supplied
        assert json.loads(row.fields)["timestamp_skewed"] is False
        s.close()

    # ---- paired negative: out-of-band stamps are repaired, never hidden ----

    def test_N1_far_past_stamp_clamped_flagged_and_visible(self):
        """N (AC-1/AC-3/AC-4): a stamp one year back — outside any days=/
        hours= window an auditor can even ask for — is CLAMPED into the band,
        flagged in the sender_revoked/forwarded field family, and is visible
        to the windowed GET (the row the old code hid from the default view)."""
        supplied = datetime.now(UTC) - timedelta(days=365)
        row, s = self._ingest_one(supplied.isoformat())
        limit = audit_routes.INGEST_MAX_TIMESTAMP_SKEW
        age = datetime.now(UTC) - row.timestamp.replace(tzinfo=UTC)
        assert age <= limit + timedelta(minutes=5), age
        assert age >= limit - timedelta(minutes=5), age  # clamped to the EDGE, not to now

        fields = json.loads(row.fields)
        assert fields["timestamp_skewed"] is True
        assert fields["client_timestamp"] == supplied.isoformat()  # claim preserved verbatim
        assert fields["client_skew_seconds"] < 0
        assert fields["forwarded"] is True and fields["sender_revoked"] is False  # same family

        # visible to a windowed auditor view (the evasion this ticket is about)
        get_backend = MagicMock()
        get_backend.get_session.side_effect = lambda: s
        client = TestClient(_create_test_app(backend=get_backend), raise_server_exceptions=False)
        g = client.get("/api/v1/audit", params={"days": 2})
        assert g.status_code == 200
        assert g.json()["total"] == 1
        s.close()

    def test_N2_far_future_stamp_clamped_flagged(self):
        """N: a stamp a year in the FUTURE (the out-of-order interleaving
        half) is clamped to the upper edge and flagged."""
        supplied = datetime.now(UTC) + timedelta(days=365)
        row, s = self._ingest_one(supplied.isoformat())
        limit = audit_routes.INGEST_MAX_TIMESTAMP_SKEW
        lead = row.timestamp.replace(tzinfo=UTC) - datetime.now(UTC)
        assert lead <= limit + timedelta(minutes=5), lead
        assert lead >= limit - timedelta(minutes=5), lead
        fields = json.loads(row.fields)
        assert fields["timestamp_skewed"] is True
        assert fields["client_timestamp"] == supplied.isoformat()
        assert fields["client_skew_seconds"] > 0
        s.close()

    def test_N3_just_outside_band_is_repaired(self):
        """N (boundary, dishonest half, twin of P2): five minutes past the
        edge is enough — the bound is enforced, not advisory."""
        supplied = datetime.now(UTC) - audit_routes.INGEST_MAX_TIMESTAMP_SKEW - timedelta(minutes=5)
        row, s = self._ingest_one(supplied.isoformat())
        assert json.loads(row.fields)["timestamp_skewed"] is True
        assert row.timestamp.replace(tzinfo=UTC) != supplied
        # and the repair is the EDGE of the band, not the server "now"
        age = datetime.now(UTC) - row.timestamp.replace(tzinfo=UTC)
        assert abs(age - audit_routes.INGEST_MAX_TIMESTAMP_SKEW) < timedelta(minutes=2), age
        s.close()

    def test_N4_mixed_batch_repairs_only_the_skewed_row(self):
        """N+P in one transaction: an honest row and a skewed row in the same
        batch — the honest one keeps its exact stamp and carries no flag;
        only the skewed one is clamped. Per-row, not per-batch."""
        honest = datetime.now(UTC) - timedelta(hours=1)
        skewed = datetime.now(UTC) - timedelta(days=40)
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        resp = _post_ingest(
            app,
            _ndjson_zstd(
                [
                    _rejection_line(session_id="h", timestamp=honest.isoformat()),
                    _rejection_line(session_id="k", timestamp=skewed.isoformat()),
                ]
            ),
        )
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 2}
        s = sm()
        rows = {json.loads(r.fields)["session_id"]: r for r in s.query(audit_models.AuditEvent).all()}
        assert rows["h"].timestamp.replace(tzinfo=UTC) == honest
        assert json.loads(rows["h"].fields)["timestamp_skewed"] is False
        assert json.loads(rows["k"].fields)["timestamp_skewed"] is True
        assert json.loads(rows["k"].fields)["client_timestamp"] == skewed.isoformat()
        s.close()

    # ---- the naive/garbage half keeps its old behavior (unchanged) ----

    def test_P5_naive_stamp_still_falls_back_to_server_clock(self):
        """P (unchanged behavior): a NAIVE stamp is still refused by the
        parse rule and replaced with the server clock — no flag (the fallback
        cannot be skewed), and the row lands at 'now', inside every window."""
        naive = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=200)
        row, s = self._ingest_one(naive.isoformat())
        age = datetime.now(UTC) - row.timestamp.replace(tzinfo=UTC)
        assert age < timedelta(minutes=5), age
        fields = json.loads(row.fields)
        assert fields["timestamp_skewed"] is False
        assert "client_timestamp" not in fields
        s.close()

    def test_P6_garbage_stamp_still_falls_back_to_server_clock(self):
        """P (unchanged behavior): a non-ISO value degrades to now(UTC),
        unflagged — exactly as before the fix."""
        row, s = self._ingest_one("not-a-timestamp")
        age = datetime.now(UTC) - row.timestamp.replace(tzinfo=UTC)
        assert age < timedelta(minutes=5), age
        assert json.loads(row.fields)["timestamp_skewed"] is False
        s.close()

    def test_P7_missing_stamp_falls_back_unflagged(self):
        """P: a line with no timestamp at all → server clock, unflagged."""
        backend, sm, _engine = _sqlite_ingest_backend()
        app = _ingest_app(_executor_auth(), backend)
        line = json.dumps({"event_type": "command_executed", "session_id": "s"})
        resp = _post_ingest(app, _ndjson_zstd([line]))
        assert resp.status_code == 200
        s = sm()
        row = s.query(audit_models.AuditEvent).one()
        assert datetime.now(UTC) - row.timestamp.replace(tzinfo=UTC) < timedelta(minutes=5)
        assert json.loads(row.fields)["timestamp_skewed"] is False
        s.close()

    # ---- the helper itself, without HTTP ----

    def test_U_bound_helper_returns_value_and_fields(self):
        """Unit: in-band → (same value, no fields); out-of-band → (edge,
        flag fields). No schema column is involved — the flag lives in the
        JSON ``fields`` family, which is what AC-4 asks for."""
        now = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)
        inside = now - timedelta(hours=1)
        assert audit_routes.bound_to_server_clock(inside, now=now) == (inside, {})

        past = now - timedelta(days=3)
        clamped, fields = audit_routes.bound_to_server_clock(past, now=now)
        assert clamped == now - audit_routes.INGEST_MAX_TIMESTAMP_SKEW
        assert fields["timestamp_skewed"] is True
        assert fields["client_timestamp"] == past.isoformat()
        assert fields["client_skew_seconds"] == -3 * 86400

        future = now + timedelta(days=3)
        clamped_up, fields_up = audit_routes.bound_to_server_clock(future, now=now)
        assert clamped_up == now + audit_routes.INGEST_MAX_TIMESTAMP_SKEW
        assert fields_up["client_skew_seconds"] == 3 * 86400

    def test_U_spool_timestamp_contract_unchanged_for_non_aware_values(self):
        """Unit: the naive/garbage/missing branches still return a single
        now(UTC) value with no fields — the old behavior, one extra tuple
        slot."""
        for raw in (None, "", 123, "2026-10-01T10:00:00", "garbage"):
            ts, fields = audit_routes._spool_timestamp(raw)
            assert abs((datetime.now(UTC) - ts).total_seconds()) < 60
            assert fields == {}
