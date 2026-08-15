"""Security headers middleware.

Adds security-related HTTP headers to all responses.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    def __init__(
        self,
        app: Any = None,
        cors_origins: list[str] | None = None,
    ) -> None:
        """
        Args:
            app: The next ASGI app.
            cors_origins: CORS origins to include in CSP connect-src.
        """
        super().__init__(app)
        self.cors_origins = cors_origins or []

    def _build_csp(self) -> str:
        """Build Content-Security-Policy header value.

        connect-src always includes 'self' and augments with CORS origins
        so browser clients can make API calls to trusted origins.
        """
        connect_src = "'self'"
        if self.cors_origins:
            connect_src += " " + " ".join(self.cors_origins)
        return (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            f"connect-src {connect_src}"
        )

    SECURITY_HEADERS_TEMPLATE = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": (
            "max-age=31536000; includeSubDomains; preload"
        ),
    }

    async def dispatch(
        self, request: Any, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = self._build_csp()
        for header, value in self.SECURITY_HEADERS_TEMPLATE.items():
            response.headers[header] = value
        return response
