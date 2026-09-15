# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
            wire_started = False

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

            async def gated_send(message):
                # Once the limit trips, suppress the app's own response (e.g. the
                # 500 an inner error middleware emits while unwinding) so the 413
                # below is the single ASGI response. Sending a second
                # http.response.start is a protocol violation.
                nonlocal wire_started
                if exceeded:
                    return
                if message["type"] == "http.response.start":
                    wire_started = True
                await send(message)

            try:
                await self.app(scope, sized_receive, gated_send)
            # except* (PEP 654): inner BaseHTTPMiddleware layers wrap the
            # raise in anyio TaskGroup ExceptionGroups (nested per layer);
            # plain `except` never matches the wrapped form.
            except* RequestTooLargeError:
                logger.warning(
                    "Request body exceeded %d bytes (propagated to size middleware)",
                    limit,
                )
            # The 413 is emitted from the `exceeded` flag, not the exception:
            # on pydantic body-model routes FastAPI converts any body-read
            # error into a handled HTTPException(400) ("There was an error
            # parsing the body", fastapi/routing.py), so nothing propagates
            # here — the gate suppresses the 400 and the stack returns with
            # zero sends (client saw uvicorn's fallback 500). The flag is
            # invariant under whatever inner layers do to the exception.
            if exceeded:
                if not wire_started:
                    await self._send_response(
                        send,
                        413,
                        b'{"detail":"Request body exceeds size limit"}',
                    )
                else:
                    logger.warning(
                        "Request body exceeded %d bytes after response start; "
                        "cannot substitute 413, stream terminated",
                        limit,
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
