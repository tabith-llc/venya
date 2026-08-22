"""Request body size limit middleware — pure ASGI.

Protects against memory exhaustion from oversized request bodies,
especially on unauthenticated endpoints like executor registration.

Uses Content-Length for fast-path rejection (zero memory waste) and
wraps the receive callable for chunked/streaming requests (limits
memory exposure mid-stream).
"""

import logging

logger = logging.getLogger(__name__)


class RequestTooLargeError(Exception):
    """Raised when request body exceeds size limit during streaming."""


class RequestSizeLimitMiddleware:
    """Pure ASGI middleware that enforces request body size limits.

    Works with any ASGI server (Uvicorn, Hypercorn, Daphne, etc.).
    Registered before all other middleware so oversized requests are
    rejected before auth/rate-limit/RBAC processing cost.
    """

    def __init__(self, app, max_body_bytes: int = 1_048_576):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Parse headers from scope
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        content_length = headers.get("content-length")

        if content_length is not None:
            # Fast path: Content-Length present
            try:
                body_size = int(content_length)
            except ValueError:
                # Malformed Content-Length — reject immediately
                await self._send_response(send, 400, b'{"detail":"Invalid Content-Length"}')
                return

            if body_size > self.max_body_bytes:
                await self._send_response(
                    send,
                    413,
                    f'{{"detail":"Request body exceeds {self.max_body_bytes} bytes"}}'.encode(),
                )
                return

            # Under limit — pass through
            await self.app(scope, receive, send)
        else:
            # Slow path: no Content-Length (chunked transfer encoding)
            # Wrap receive to count bytes as they arrive
            received_bytes = 0
            limit = self.max_body_bytes

            exceeded = False

            async def sized_receive():
                nonlocal received_bytes, exceeded
                if exceeded:
                    return {"type": "http.request", "body": b""}
                message = await receive()
                if message["type"] == "http.request":
                    body = message.get("body", b"")
                    received_bytes += len(body)
                    if received_bytes > limit:
                        exceeded = True
                        raise RequestTooLargeError()
                return message

            try:
                await self.app(scope, sized_receive, send)
            except RequestTooLargeError:
                await self._send_response(
                    send,
                    413,
                    b'{"detail":"Request body exceeds size limit"}',
                )

    @staticmethod
    async def _send_response(send, status, body):
        """Send a simple JSON response."""
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
