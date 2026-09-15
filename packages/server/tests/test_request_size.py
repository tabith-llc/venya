# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for request body size limit middleware."""

from fastapi import FastAPI, Request
from pydantic import BaseModel
from server.middleware.request_size import RequestSizeLimitMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
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

    def test_chunked_body_under_limit(self):
        """Chunked stream under the limit passes through (paired positive)."""
        app = _create_app(max_body_bytes=1000)
        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)

        with client as session:
            chunked_body = b"x" * 50
            chunked_payload = f"{len(chunked_body):x}\r\n".encode() + chunked_body + b"\r\n0\r\n\r\n"
            resp = session.post(
                "/echo",
                content=chunked_payload,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/octet-stream",
                },
            )
            assert resp.status_code == 200
            # The ASGI test transport delivers the raw framed bytes as the body
            assert resp.json()["received"] == len(chunked_payload)

    def test_chunked_exceeds_with_base_http_middleware_stack(self):
        """Chunked overflow still yields 413 through BaseHTTPMiddleware layers.

        Regression: BaseHTTPMiddleware.receive_or_disconnect runs the wrapped
        receive inside an anyio task group, so RequestTooLargeError reaches the
        size middleware wrapped in (nested) ExceptionGroups. A plain `except
        RequestTooLargeError` missed it and the client got a bare 500 with no
        response on the wire. Physical-only bug: the bare-app tests above never
        had a BaseHTTPMiddleware in the stack.
        """

        class PassthroughMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                return await call_next(request)

        inner = FastAPI()

        @inner.post("/echo")
        async def echo(request: Request):
            body = await request.body()
            return {"received": len(body)}

        inner.add_middleware(PassthroughMiddleware)
        # Mirror production: size middleware outermost, BHM layers inside
        wrapped = RequestSizeLimitMiddleware(inner, max_body_bytes=100)
        client = TestClient(wrapped, raise_server_exceptions=False, follow_redirects=False)

        with client as session:
            chunked_body = b"x" * 500
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
            assert "exceeds" in resp.json()["detail"].lower()

    def test_chunked_exceeds_pydantic_body_model_route(self):
        """Chunked overflow on a pydantic body-model route still yields 413.

        Production shape (e.g. /api/v1/auth/login/start): FastAPI reads the
        body inside routing for model-typed params and converts ANY body-read
        exception into a handled HTTPException(400) ("There was an error
        parsing the body", fastapi/routing.py blanket `except Exception`).
        Nothing propagates to the size middleware; the gate suppresses the
        400; the stack returns with zero sends. Only the middleware's
        `exceeded` flag can signal the 413 — an exception-based catch is
        structurally dead on this path.
        """

        class Body(BaseModel):
            user_id: str

        class PassthroughMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                return await call_next(request)

        inner = FastAPI()

        @inner.post("/model-echo")
        async def model_echo(body: Body):
            return {"user_id": body.user_id}

        inner.add_middleware(PassthroughMiddleware)
        wrapped = RequestSizeLimitMiddleware(inner, max_body_bytes=100)
        client = TestClient(wrapped, raise_server_exceptions=False, follow_redirects=False)

        with client as session:
            chunked_body = b"x" * 500
            chunked_payload = f"{len(chunked_body):x}\r\n".encode() + chunked_body + b"\r\n0\r\n\r\n"
            resp = session.post(
                "/model-echo",
                content=chunked_payload,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code == 413
            assert "exceeds" in resp.json()["detail"].lower()
