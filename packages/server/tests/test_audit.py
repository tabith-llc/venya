"""Tests for audit log endpoints."""

from datetime import UTC
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.dependencies import require_admin
from server.routes import audit as audit_routes
from starlette.testclient import TestClient


def _create_test_app(backend=None, override_guard=True):
    """Create a minimal test app with audit route."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")
    if override_guard:
        app.dependency_overrides[require_admin] = lambda: {
            "user_id": "admin",
            "roles": [42],
        }

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
    """Guard enforcement on GET /audit (admin only)."""

    def test_no_auth_user_rejected(self):
        """Without require_admin override (no auth_user set), GET /audit is 401."""
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        # override_guard=False leaves require_admin live; no middleware sets auth_user
        app = _create_test_app(backend=backend, override_guard=False)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 401
