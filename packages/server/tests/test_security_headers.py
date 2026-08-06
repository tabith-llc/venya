"""Tests for security headers middleware."""

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.middleware.security_headers import SecurityHeadersMiddleware


def _create_test_app():
    """Create a minimal test app with security headers middleware."""
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    app.add_middleware(SecurityHeadersMiddleware)
    return app


class TestSecurityHeaders:
    """Tests for security header presence and values."""

    def test_csp_header(self):
        """Content-Security-Policy should be set correctly."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "img-src 'self' data:" in csp
        assert "frame-ancestors 'none'" in csp
        assert "connect-src 'self'" in csp

    def test_x_frame_options(self):
        """X-Frame-Options should be DENY."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_x_content_type_options(self):
        """X-Content-Type-Options should be nosniff."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_referrer_policy(self):
        """Referrer-Policy should be strict-origin-when-cross-origin."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_hsts_header(self):
        """Strict-Transport-Security should have correct value."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        hsts = resp.headers.get("strict-transport-security")
        assert hsts is not None
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts
        assert "preload" in hsts

    def test_all_headers_present(self):
        """All 5 security headers should be present on every response."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        required = {
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
        }
        actual = set(h.lower() for h in resp.headers.keys())
        assert required.issubset(actual)

    def test_headers_on_error_responses(self):
        """Security headers should be present on error responses too."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/nonexistent")
        assert resp.status_code == 404
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-content-type-options") == "nosniff"
