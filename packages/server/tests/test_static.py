"""Tests for static file serving routes."""

from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from starlette.testclient import TestClient

from server.routes import static as static_routes


def _create_test_app():
    """Create a minimal test app with static routes."""
    app = FastAPI()
    app.include_router(static_routes.router)
    return app


class TestServeIndex:
    """Tests for the login page endpoint."""

    def test_serves_index_html(self):
        """GET / should serve index.html."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")


class TestServeEnroll:
    """Tests for the enrollment page endpoint."""

    def test_serves_enroll_html(self):
        """GET /enroll should serve enroll.html."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/enroll")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")


class TestServeDashboard:
    """Tests for the dashboard page endpoint."""

    def test_serves_dashboard_html(self):
        """GET /dashboard should serve dashboard.html."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")


class TestServeStatic:
    """Tests for static asset serving."""

    def test_serves_css_file(self):
        """GET /static/css/app.css should serve the CSS file."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/static/css/app.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]

    def test_serves_js_file(self):
        """GET /static/js/app.js should serve the JS file."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/static/js/app.js")
        assert resp.status_code == 200

    def test_missing_static_file_returns_404(self):
        """GET /static/missing.js should return 404."""
        app = _create_test_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/static/missing.js")
        assert resp.status_code == 404


class TestDirectoryTraversal:
    """Security tests for directory traversal prevention."""

    def test_dotdot_in_path_component_blocked(self, tmp_path):
        """A filename containing .. should be rejected by the regex."""
        # Create a file with .. in its name inside STATIC_DIR
        odd_file = static_routes.STATIC_DIR / "bad..file.txt"
        odd_file.write_text("secret")

        try:
            app = _create_test_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/static/bad..file.txt")
            assert resp.status_code == 400
        finally:
            odd_file.unlink(missing_ok=True)

    def test_sanitize_path_valid_file_passes(self, tmp_path):
        """_sanitize_path should accept valid files within STATIC_DIR."""
        from server.routes.static import _sanitize_path

        test_file = tmp_path / "valid.txt"
        test_file.write_text("ok")

        with patch.object(static_routes, "STATIC_DIR", tmp_path):
            result = _sanitize_path("valid.txt")
            assert result == test_file.resolve()

    def test_sanitize_path_rejects_traversal(self):
        """_sanitize_path should reject paths with .."""
        from fastapi import HTTPException
        from server.routes.static import _sanitize_path

        with patch.object(static_routes, "STATIC_DIR", Path("/tmp")):
            try:
                _sanitize_path("../etc/passwd")
                assert False, "Should have raised HTTPException"
            except HTTPException as e:
                assert e.status_code == 400

    def test_sanitize_path_rejects_double_slash(self):
        """_sanitize_path should reject paths with //"""
        from fastapi import HTTPException
        from server.routes.static import _sanitize_path

        with patch.object(static_routes, "STATIC_DIR", Path("/tmp")):
            try:
                _sanitize_path("//etc/passwd")
                assert False, "Should have raised HTTPException"
            except HTTPException as e:
                assert e.status_code == 400
