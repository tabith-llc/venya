# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Rate limiting middleware.

Per-IP and per-session throttling to prevent brute force attacks.
Uses PostgreSQL fixed-window counters for multi-worker safety.
"""

import logging
import time
from datetime import UTC, datetime, timedelta

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from .. import metrics

logger = logging.getLogger("venya.server")

# Fixed-window bucket sizes
_GENERIC_WINDOW = timedelta(minutes=1)
_AUTH_WINDOW = timedelta(minutes=1)
_BREAK_GLASS_WINDOW = timedelta(hours=1)


def _truncate_to_window(dt: datetime, window: timedelta) -> datetime:
    """Truncate datetime to the start of its fixed-window bucket.

    For 1-minute windows: truncates to the minute.
    For 1-hour windows: truncates to the hour.
    """
    if window == _GENERIC_WINDOW:
        return dt.replace(second=0, microsecond=0)
    elif window == _BREAK_GLASS_WINDOW:
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(second=0, microsecond=0)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting middleware backed by PostgreSQL.

    Uses fixed-window counters stored in the rate_limit_failures table.
    Each request does a single UPSERT round-trip to increment the counter.

    Fixed-window trade-off: a burst at window boundary allows up to 2x
    the limit. Acceptable for this use case.
    """

    def __init__(
        self,
        app: RequestResponseEndpoint,
        config=None,
        requests_per_minute: int = 100,
        auth_requests_per_minute: int = 20,
        break_glass_per_hour: int = 5,
    ) -> None:
        super().__init__(app)

        if config is not None:
            self.enforce = config.enforce
            self.requests_per_minute = config.ip_rate_limit
            # Was `config.ip_rate_limit` — the intended 20/min auth tier was
            # silently collapsed into the 1000/min generic limit (ticket
            # sec-endpoint-ratelimit-hardening #8). The dedicated field
            # restores it; env override VENYA_RATE_LIMIT__AUTH_REQUESTS_PER_MINUTE.
            self.auth_requests_per_minute = config.auth_requests_per_minute
            self.break_glass_per_hour = config.break_glass_requests_per_hour
        else:
            self.enforce = True
            self.requests_per_minute = requests_per_minute
            self.auth_requests_per_minute = auth_requests_per_minute
            self.break_glass_per_hour = 5

        # In-memory break-glass failure tracking for exponential backoff.
        # Short-lived (seconds), doesn't need to be shared across workers.
        self._break_glass_failures: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        ip = self._get_client_ip(request)

        # Skip rate limiting if not enforced
        if not self.enforce:
            return await call_next(request)

        # Determine endpoint type and window
        if self._is_break_glass_endpoint(request.url.path):
            endpoint_type = "break_glass"
            limit = self.break_glass_per_hour
            window = _BREAK_GLASS_WINDOW
        elif self._is_auth_endpoint(request.url.path):
            endpoint_type = "auth"
            limit = self.auth_requests_per_minute
            window = _AUTH_WINDOW
        else:
            endpoint_type = "generic"
            limit = self.requests_per_minute
            window = _GENERIC_WINDOW

        # Check break-glass backoff before processing
        if endpoint_type == "break_glass" and self._check_break_glass_backoff(ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Break-glass endpoint rate limited: too many recent failures"},
            )

        # UPSERT: atomic increment, returns new count
        now = datetime.now(UTC)
        window_start = _truncate_to_window(now, window)

        db = None
        try:
            backend = getattr(request.app.state, "backend", None)
            if backend is None:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Backend not initialized"},
                )
            db = backend.get_session()

            count = self._increment_counter(db, ip, endpoint_type, window_start)

            if count > limit:
                metrics.RATE_LIMIT_HIT_TOTAL.labels(limit_type=endpoint_type).inc()
                if endpoint_type == "break_glass":
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Break-glass endpoint rate limited: too many requests per hour"},
                    )
                elif endpoint_type == "auth":
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Auth endpoint rate limited: too many requests per minute"},
                    )
                else:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Rate limited: too many requests per minute"},
                    )
        finally:
            if db is not None:
                db.close()

        # Process the request
        response = await call_next(request)

        # Record failure if break-glass returned 401
        if endpoint_type == "break_glass" and response.status_code == status.HTTP_401_UNAUTHORIZED:
            self._record_break_glass_failure(ip)

        return response

    def _increment_counter(self, db, identifier: str, endpoint_type: str, window_start: datetime) -> int:
        """Atomically increment a rate limit counter via UPSERT.

        Returns the new count after increment.
        """
        from sqlalchemy import text

        result = db.execute(
            text(
                """
                INSERT INTO rate_limit_failures (identifier, endpoint_type, window_start, count)
                VALUES (:identifier, :endpoint_type, :window_start, 1)
                ON CONFLICT (identifier, endpoint_type, window_start)
                DO UPDATE SET count = rate_limit_failures.count + 1
                RETURNING count
            """
            ),
            {
                "identifier": identifier,
                "endpoint_type": endpoint_type,
                "window_start": window_start,
            },
        )
        count = result.scalar()
        # The dispatch `finally: db.close()` rolls back anything uncommitted;
        # without this commit every request saw count=1 and no DB-backed tier
        # ever enforced (ticket ratelimit-counter-upsert-never-commits).
        db.commit()
        return count

    def _check_break_glass_backoff(self, ip: str) -> bool:
        """Check exponential backoff for break-glass failures.

        Returns True if the client should be delayed/blocked.
        Backoff: 1s, 2s, 4s, 8s, 16s (capped at 16s).
        """
        now = time.time()
        failures = self._break_glass_failures.get(ip, [])

        # Only keep failures within the last hour
        failures = [t for t in failures if now - t < 3600]
        if not failures:
            return False

        attempt_count = len(failures)
        backoff_seconds = min(2 ** (attempt_count - 1), 16)

        last_failure = failures[-1]
        elapsed = now - last_failure

        if elapsed < backoff_seconds:
            metrics.RATE_LIMIT_HIT_TOTAL.labels(limit_type="break_glass_backoff").inc()
            return True

        return False

    def _record_break_glass_failure(self, ip: str) -> None:
        """Record a break-glass failure for exponential backoff."""
        now = time.time()
        if ip not in self._break_glass_failures:
            self._break_glass_failures[ip] = []
        self._break_glass_failures[ip].append(now)

    def _get_client_ip(self, request: Request) -> str:
        """Extract the client IP for rate-limit keying.

        Trusts the RIGHTMOST X-Forwarded-For entry — the one appended by our
        own nginx (`$proxy_add_x_forwarded_for` = "<client-sent>, <real
        peer>") — NOT the leftmost, which is attacker-controlled: one spoofed
        header used to bypass every per-IP limit (break-glass 5/hr, auth tier,
        failure backoff). Ticket sec-endpoint-ratelimit-hardening #8.

        INVARIANT (named, shared): rightmost is trustworthy IFF the app is
        reachable through EXACTLY ONE trusted appending proxy hop — the same
        loopback-only-backend deployment invariant the X-Client-* mTLS header
        chain rests on (installer BIND_ADDRESS=127.0.0.1; see the
        _validate_admin_mtls / _validate_executor_mtls docstrings — two
        controls now share this invariant). A client hitting the app port
        directly spoofs rightmost trivially; a SECOND proxy layer silently
        invalidates it. Do not change the topology without changing this
        function.
        """
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[-1].strip()
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

    def _is_break_glass_endpoint(self, path: str) -> bool:
        """Check if path is a break-glass endpoint."""
        return path == "/api/v1/recovery"
