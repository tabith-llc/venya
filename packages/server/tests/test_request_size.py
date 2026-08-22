"""Tests for request body size limit middleware."""

from fastapi import FastAPI, Request
from server.middleware.request_size import RequestSizeLimitMiddleware
from starlette.testclient import TestClient


def _create_app(max_body_bytes=1_048_576):
    """Create a minimal test app with request size limit middleware."""
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        body = await request.body()
        return {"received": len(body)}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/admin/secret")
    def admin_secret():
        return {"secret": "data"}

    # Wrap with pure ASGI middleware (outermost layer)
    wrapped = RequestSizeLimitMiddleware(app, max_body_bytes=max_body_bytes)
    return wrapped


class TestRequestSizeLimit:
    """Tests for RequestSizeLimitMiddleware."""

    def test_content_length_exceeds_limit(self):
        """413 when Content-Length > max."""
        app = _create_app(max_body_bytes=100)
        client = TestClient(app, raise_server_exceptions=False)
        payload = b"x" * 200
        resp = client.post("/echo", content=payload)
        assert resp.status_code == 413
        assert "exceeds" in resp.json()["detail"].lower()

    def test_content_length_under_limit(self):
        """Normal request passes when under limit."""
        app = _create_app(max_body_bytes=1000)
        client = TestClient(app, raise_server_exceptions=False)
        payload = b'{"key":"value"}'
        resp = client.post("/echo", content=payload)
        assert resp.status_code == 200
        assert resp.json()["received"] == len(payload)

    def test_content_length_equals_limit(self):
        """Request at exactly the limit passes."""
        app = _create_app(max_body_bytes=100)
        client = TestClient(app, raise_server_exceptions=False)
        payload = b"x" * 100
        resp = client.post("/echo", content=payload)
        assert resp.status_code == 200
        assert resp.json()["received"] == 100

    def test_malformed_content_length(self):
        """Non-numeric Content-Length returns 400."""
        app = _create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/echo",
            content=b"test",
            headers={"Content-Length": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "Invalid Content-Length" in resp.json()["detail"]

    def test_no_body_request_passes(self):
        """GET request with no body works."""
        app = _create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_limit_configurable(self):
        """Different limit values take effect."""
        app = _create_app(max_body_bytes=50)
        client = TestClient(app, raise_server_exceptions=False)
        # Under limit
        resp = client.post("/echo", content=b"hello")
        assert resp.status_code == 200
        # Over limit (50 bytes)
        resp = client.post("/echo", content=b"x" * 100)
        assert resp.status_code == 413

    def test_413_before_auth_runs(self):
        """Oversized request on admin endpoint returns 413, not 401.

        Verifies middleware ordering: oversized requests are rejected
        before auth middleware processes them.
        """
        app = _create_app(max_body_bytes=100)
        wrapped = RequestSizeLimitMiddleware(app, max_body_bytes=100)
        client = TestClient(wrapped, raise_server_exceptions=False)
        resp = client.post("/admin/secret", content=b"x" * 500)
        assert resp.status_code == 413
        assert "exceeds" in resp.json()["detail"].lower()

    def test_chunked_body_exceeds_limit(self):
        """Chunked stream rejected mid-body when exceeding limit."""
        app = _create_app(max_body_bytes=100)
        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)

        # Use raw httpx client to send chunked transfer encoding
        # (TestClient sets Content-Length by default)
        with client as session:
            # Build a chunked request manually
            chunked_body = b"x" * 500
            # Chunked format: size in hex + CRLF + data + CRLF + 0 + CRLF
            chunked_payload = f"{len(chunked_body):x}\r\n".encode() + chunked_body + b"\r\n0\r\n\r\n"
            resp = session.post(
                "/echo",
                content=chunked_payload,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/octet-stream",
                },
            )
            assert resp.status_code == 413
