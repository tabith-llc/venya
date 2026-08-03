"""Rate limiting middleware.

Per-IP and per-session throttling to prevent brute force attacks.
"""

from __future__ import annotations

import time
import logging
from collections import defaultdict
from typing import Any

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from venya.vault.rate_limiter import RateLimiter as VaultRateLimiter, RateLimitExceededError

logger = logging.getLogger("venya.server")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting middleware.

    Tracks request counts per IP address and enforces limits.
    Works in tandem with the vault's per-account rate limiter.
    """

    def __init__(
        self,
        app: Any,
        config: Any | None = None,
        requests_per_minute: int = 100,
        auth_requests_per_minute: int = 20,
    ) -> None:
        """
        Args:
            app: The next ASGI app.
            config: RateLimitConfig from server config.
            requests_per_minute: Max requests per IP per minute.
            auth_requests_per_minute: Max auth-related requests per IP per minute.
        """
        super().__init__(app)

        if config is not None:
            self.requests_per_minute = config.ip_rate_limit
            self.auth_requests_per_minute = min(
                config.ip_rate_limit // 5,  # 20% of general limit for auth
                20,
            )
        else:
            self.requests_per_minute = requests_per_minute
            self.auth_requests_per_minute = auth_requests_per_minute

        # In-memory rate limit counters: ip -> list of timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._auth_requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = self._get_client_ip(request)

        # Check auth rate limit for auth endpoints
        if self._is_auth_endpoint(request.url.path):
            self._check_rate_limit(ip, self._auth_requests, self.auth_requests_per_minute)
        else:
            self._check_rate_limit(ip, self._requests, self.requests_per_minute)

        response = await call_next(request)

        # Record the request
        now = time.time()
        if self._is_auth_endpoint(request.url.path):
            self._auth_requests[ip].append(now)
        else:
            self._requests[ip].append(now)

        # Clean old entries
        self._cleanup(ip, now)

        return response

    def _check_rate_limit(
        self,
        ip: str,
        requests: dict[str, list[float]],
        limit: int,
    ) -> None:
        """Check if IP has exceeded rate limit.

        Args:
            ip: Client IP address.
            requests: Request timestamp dict.
            limit: Max requests per window.

        Raises:
            RateLimitExceededError: If limit exceeded.
        """
        now = time.time()
        window_start = now - 60  # 1-minute window

        # Count requests in current window
        count = sum(1 for t in requests.get(ip, []) if t > window_start)

        if count >= limit:
            raise RateLimitExceededError(
                f"IP {ip} exceeded {limit} requests per minute"
            )

    def _cleanup(self, ip: str, now: float) -> None:
        """Remove expired request timestamps."""
        window_start = now - 60

        if ip in self._requests:
            self._requests[ip] = [t for t in self._requests[ip] if t > window_start]
        if ip in self._auth_requests:
            self._auth_requests[ip] = [
                t for t in self._auth_requests[ip] if t > window_start
            ]

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, checking X-Forwarded-For first."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        client = request.scope.get("client")
        if client:
            return client[0]
        return "unknown"

    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if path is an auth-related endpoint."""
        auth_prefixes = (
            "/api/v1/auth/",
            "/api/v1/enrollment/",
        )
        return path.startswith(auth_prefixes)
