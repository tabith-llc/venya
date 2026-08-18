"""Tests for health check endpoints."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import health as health_routes


def _create_test_app(backend=None, ca_manager=None, admin_ca_manager=None, config=None):
    """Create a minimal test app with health routes."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    health_routes._reset_health_cache()

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    if ca_manager is not None:
        app.state.ca_manager = ca_manager
    if admin_ca_manager is not None:
        app.state.admin_ca_manager = admin_ca_manager
    if config is not None:
        app.state.config = config
    app.include_router(health_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_health_ok(self):
        """GET /health should return ok when CA is healthy."""
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        app = _create_test_app(ca_manager=ca)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["checks"]["ca"] == "ok"

    def test_health_ca_error(self):
        """GET /health should return 503 when CA key is broken."""
        ca = MagicMock()
        ca.load_ca.side_effect = RuntimeError("key decryption failed")
        app = _create_test_app(ca_manager=ca)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "error"
        assert data["checks"]["ca"] == "check_failed"

    def test_health_admin_ca_skipped(self):
        """GET /health should skip admin_ca when mTLS is disabled."""
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        config = SimpleNamespace(
            admin_mtls=SimpleNamespace(enabled=False)
        )
        app = _create_test_app(ca_manager=ca, config=config)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "admin_ca" not in data["checks"]

    def test_health_admin_ca_ok(self):
        """GET /health should include admin_ca=ok when mTLS enabled and CA loads."""
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        admin_ca = MagicMock()
        admin_ca._load_ca_key.return_value = MagicMock()
        config = SimpleNamespace(
            admin_mtls=SimpleNamespace(enabled=True)
        )
        app = _create_test_app(ca_manager=ca, admin_ca_manager=admin_ca, config=config)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["checks"]["admin_ca"] == "ok"

    def test_health_admin_ca_error(self):
        """GET /health should return 200/degraded when admin CA fails (non-critical)."""
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        admin_ca = MagicMock()
        admin_ca._load_ca_key.side_effect = RuntimeError("admin key missing")
        config = SimpleNamespace(
            admin_mtls=SimpleNamespace(enabled=True)
        )
        app = _create_test_app(ca_manager=ca, admin_ca_manager=admin_ca, config=config)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["checks"]["admin_ca"] == "check_failed"


class TestHealthCache:
    """Tests for health check caching behavior."""

    def test_health_cache_avoids_repeated_disk_reads(self):
        """Two rapid calls hit disk once (cache prevents re-check)."""
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        app = _create_test_app(ca_manager=ca)

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/api/v1/health")
        client.get("/api/v1/health")

        # load_ca should only be called once (cached)
        assert ca.load_ca.call_count == 1

    def test_health_returns_503_on_ca_error(self):
        """Broken CA → HTTP 503 so load balancers stop routing."""
        ca = MagicMock()
        ca.load_ca.side_effect = RuntimeError("CA key corrupted")
        app = _create_test_app(ca_manager=ca)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "error"


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
        assert data["checks"]["database"] == "not_ready"
