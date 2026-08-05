"""Tests for health check endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import health as health_routes


def _create_test_app(backend=None):
    """Create a minimal test app with health routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(health_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_health_ok(self):
        """GET /health should return ok."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestReadinessCheck:
    """Tests for readiness check endpoint."""

    def test_ready_with_backend(self):
        """GET /ready should return ok when DB is connected."""
        db = MagicMock()
        db.execute.return_value = MagicMock()
        db.commit.return_value = None

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["checks"]["database"] == "connected"

    def test_ready_no_backend(self):
        """GET /ready should return degraded when no backend."""
        app = _create_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["checks"]["database"] == "not_configured"

    def test_ready_db_error(self):
        """GET /ready should return degraded when DB is down."""
        db = MagicMock()
        db.execute.side_effect = Exception("Connection refused")

        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(backend=backend)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert "error" in data["checks"]["database"]
