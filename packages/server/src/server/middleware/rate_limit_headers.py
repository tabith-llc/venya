"""Rate limit header middleware.

Attaches X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
headers to all responses. On 429, also adds Retry-After.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("venya.server")


class RateLimitHeaderMiddleware(BaseHTTPMiddleware):
    """Attach rate limit headers to responses based on request.state info."""

    def __init__(self, app: Any) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        rl_info = getattr(request.state, "rate_limit_info", None)
        if rl_info is None:
            return response

        response.headers["X-RateLimit-Limit"] = str(rl_info.get("limit", 0))
        response.headers["X-RateLimit-Remaining"] = str(rl_info.get("remaining", 0))
        response.headers["X-RateLimit-Reset"] = str(rl_info.get("reset", 0))

        # If this is a 429, ensure Retry-After is present
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                response.headers["Retry-After"] = retry_after

        return response
