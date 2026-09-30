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
