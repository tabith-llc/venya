"""Tests for CORS configuration."""

from fastapi import FastAPI
from server.middleware.security_headers import SecurityHeadersMiddleware
from starlette.testclient import TestClient


def _create_test_app(cors_origins=None, middleware_kwargs=None):
    """Create a minimal test app with security headers middleware."""
    app = FastAPI()

    @app.get("/api/v1/executors")
    def list_executors():
        return {"executors": []}

    @app.options("/api/v1/executors")
    def options_executors():
        return {}

    if middleware_kwargs is None:
        middleware_kwargs = {"cors_origins": cors_origins}
    app.add_middleware(SecurityHeadersMiddleware, **middleware_kwargs)
    return app


def _create_full_app():
    """Create a full test app with CORS and security headers."""
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI()

    @app.get("/api/v1/executors")
    def list_executors():
        return {"executors": []}

    @app.options("/api/v1/executors")
    def options_executors():
        return {}

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Request-ID", "X-Total-Count"],
        max_age=3600,
    )
    app.add_middleware(SecurityHeadersMiddleware, cors_origins=["http://localhost"])
    return app


class TestCorsHeaders:
    """Tests for CORS header presence and values."""

    def test_cors_headers_on_get(self):
        """GET response should include CORS headers when origin matches."""
        app = _create_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/executors",
            headers={"Origin": "http://localhost"},
        )
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "http://localhost"
        assert resp.headers["access-control-allow-credentials"] == "true"
        assert "x-request-id" in resp.headers["access-control-expose-headers"].lower()
        assert "x-total-count" in resp.headers["access-control-expose-headers"].lower()

    def test_cors_preflight_succeeds(self):
        """OPTIONS preflight should return 200 with all preflight headers."""
        app = _create_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.options(
            "/api/v1/executors",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "http://localhost"
        assert "GET" in resp.headers["access-control-allow-methods"]
        assert "access-control-max-age" in resp.headers
        assert "origin" in resp.headers["vary"].lower()

    def test_cors_reflects_specific_origin_not_wildcard(self):
        """With allow_credentials=True, ACAO must be the specific origin, never '*'."""
        app = _create_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/executors",
            headers={"Origin": "http://localhost"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        assert acao == "http://localhost"
        assert acao != "*"

    def test_cors_disallowed_origin_no_headers(self):
        """Non-matching origin should get no CORS headers."""
        app = _create_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/executors",
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in resp.headers

    def test_cors_vary_origin_present(self):
        """Response should include Vary: Origin for correct caching."""
        app = _create_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.options(
            "/api/v1/executors",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "vary" in {k.lower() for k in resp.headers}
        assert "origin" in resp.headers["vary"].lower()


class TestSecurityHeadersCsp:
    """Tests for CSP connect-src with CORS origin awareness."""

    def test_csp_connect_src_augments_self(self):
        """CSP connect-src should include 'self' + configured origins."""
        app = _create_test_app(cors_origins=["http://localhost", "https://console.example.com"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")
        csp = resp.headers.get("content-security-policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "connect-src 'self' http://localhost https://console.example.com" in csp

    def test_csp_connect_src_self_when_no_origins(self):
        """No CORS origins = connect-src 'self' only."""
        app = _create_test_app(cors_origins=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")
        csp = resp.headers.get("content-security-policy")
        assert csp is not None
        assert "connect-src 'self'" in csp
        # No extra origins appended
        assert csp.strip().endswith("connect-src 'self'")

    def test_csp_connect_src_self_when_none(self):
        """No cors_origins param = connect-src 'self' only."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/executors")
        csp = resp.headers.get("content-security-policy")
        assert csp is not None
        assert "connect-src 'self'" in csp
