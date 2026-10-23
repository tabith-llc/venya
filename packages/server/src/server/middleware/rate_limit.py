# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Rate limiting middleware.

Per-IP and per-session throttling to prevent brute force attacks.

Counters live in the SHARED ``rate_limit_failures`` table and are incremented
by one atomic UPSERT, so N core replicas over one database add up to ONE
counter. The fixed-window bucket key comes from the DATABASE clock inside that
same statement and never from the wall clock of whichever replica happens to be
handling the request (ticket #460): the key is part of the table's primary key,
so a replica-local key splits one client into a bucket per replica — the
effective limit becomes limit x buckets and ``Retry-After`` varies per replica.
PostgreSQL's UPSERT buys counter agreement; the shared clock buys bucket
agreement, and ``RETURNING`` carries the new count together with the seconds
left in that same DB-clock window so a 429 and its counter share one authority.

Fixed-window trade-off: a burst at a window boundary allows up to 2x the
limit. Acceptable for this use case.
"""

import logging
import math
import time
from datetime import datetime, timedelta

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from .. import metrics

logger = logging.getLogger("venya.server")

# Fixed-window bucket sizes
_GENERIC_WINDOW = timedelta(minutes=1)
_AUTH_WINDOW = timedelta(minutes=1)
_BREAK_GLASS_WINDOW = timedelta(hours=1)
# Credential-mint window (RF-6 §2.7): a mint costs one FIDO2 touch, so the cap
# is hourly and small, never the generic 1-minute tier — and a mint path left
# unclassified does NOT ship unlimited, it ships at the generic per-IP tier
# (config.rate_limit.ip_rate_limit, default 1000/min), which is no cap on a
# credential at all. Classified explicitly below for that reason.
_ISSUANCE_WINDOW = timedelta(hours=1)

# Bucket shape per window: (date_trunc unit, window length in seconds). Every
# window this middleware uses is a whole minute or a whole hour, which is what
# makes the key expressible as a database-side truncation (#460). The fallback
# for an unlisted window mirrors the old replica-side truncation exactly —
# truncate to the minute — so bucketing behaviour cannot shift silently.
# The break-glass and RF-6 mint windows are equal timedeltas (both one hour), so
# they share the single "hour" entry below — same value, same bucket.
_WINDOW_BUCKET_SHAPE: dict[timedelta, tuple[str, int]] = {
    _GENERIC_WINDOW: ("minute", 60),
    _AUTH_WINDOW: ("minute", 60),
    _BREAK_GLASS_WINDOW: ("hour", 3600),
}

# SQLite rendering of the same truncation, per unit. The product deployment is
# PostgreSQL; SQLite is what the unit suite binds, and this is the #366 dialect
# guard pattern already in the tree (routes/init.py, core/iam/role_manager.py):
# PostgreSQL-only functions never go out over a SQLite bind. 'now' in SQLite is
# UTC, and the format carries the "+00:00" offset so the bucket string lands in
# the DateTime(timezone=True) column exactly like a bound aware datetime.
_SQLITE_BUCKET_FORMAT: dict[str, str] = {
    "minute": "%Y-%m-%d %H:%M:00+00:00",
    "hour": "%Y-%m-%d %H:00:00+00:00",
}

# The counter UPSERT with the window key derived by the DATABASE clock
# (ticket #460). One statement, one round trip, one clock authority:
#   * window_start is produced by date_trunc over the server clock — no
#     replica-supplied key travels in the bind params at all;
#   * RETURNING carries the new count AND retry_seconds derived from the same
#     statement's now(), so the counter and its Retry-After cannot disagree.
# `AT TIME ZONE 'UTC'` twice pins the truncation to UTC boundaries whatever the
# session TimeZone is. now() is the transaction timestamp, so the returned
# window and the returned remaining seconds are read off one clock. Every value
# is a bind param — nothing is interpolated into the statement text.
_SHARED_CLOCK_UPSERT_POSTGRESQL = """
                INSERT INTO rate_limit_failures (identifier, endpoint_type, window_start, count)
                VALUES (
                    :identifier,
                    :endpoint_type,
                    date_trunc(CAST(:unit AS text), (now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),
                    1
                )
                ON CONFLICT (identifier, endpoint_type, window_start)
                DO UPDATE SET count = rate_limit_failures.count + 1
                RETURNING count,
                          window_start,
                          CAST(CEIL(EXTRACT(EPOCH FROM (window_start
                              + CAST(:window_seconds AS double precision) * interval '1 second'
                              - now()))) AS integer) AS retry_seconds
"""

# SQLite form of the same contract: strftime truncates the database clock to
# the bucket, and the remaining seconds come from that same stored bucket plus
# the window length against the database clock.
_SHARED_CLOCK_UPSERT_SQLITE = """
                INSERT INTO rate_limit_failures (identifier, endpoint_type, window_start, count)
                VALUES (
                    :identifier,
                    :endpoint_type,
                    strftime(:bucket_format, 'now'),
                    1
                )
                ON CONFLICT (identifier, endpoint_type, window_start)
                DO UPDATE SET count = rate_limit_failures.count + 1
                RETURNING count,
                          window_start,
                          CAST(strftime('%s', window_start, '+' || :window_seconds || ' seconds') AS INTEGER)
                            - CAST(strftime('%s', 'now') AS INTEGER) AS retry_seconds
"""


def _window_bucket_shape(window: timedelta) -> tuple[str, int]:
    """Return ``(date_trunc unit, window seconds)`` for a bucket size.

    Unknown windows fall back to the minute unit, which is exactly what the
    removed replica-side truncation did (ticket #460 keeps that behaviour
    rather than quietly re-bucketing a window this table has never used).

    Note the one dict entry for two hour tiers: ``_BREAK_GLASS_WINDOW`` and the
    RF-6 §2.7 ``_ISSUANCE_WINDOW`` are equal timedelta VALUES, so they share a
    bucket shape — which is what the removed truncation did with its
    `window in (_BREAK_GLASS_WINDOW, _ISSUANCE_WINDOW)` test.
    """
    return _WINDOW_BUCKET_SHAPE.get(window, ("minute", 60))


def _clamp_retry_after(retry_seconds: int | None) -> int:
    """Seconds until the DB-derived window resets (always >= 1).

    Retry-After contract (ticket delta-b-run-low-bundle O2): EVERY 429 this
    middleware emits carries the header — client backoff without it is
    guesswork. Delta-seconds form (RFC 9110 §10.2.3), never HTTP-date. The
    value arrives from the window's own database clock (#460); the clamp only
    keeps the header positive.
    """
    if retry_seconds is None:
        return 1
    return max(1, math.ceil(retry_seconds))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting middleware backed by PostgreSQL.

    Uses fixed-window counters stored in the rate_limit_failures table.
    Each request does a single UPSERT round-trip to increment the counter, and
    that same statement derives the window key from the database clock — the
    counters AND the buckets are shared state, so replicas that disagree about
    the time still count one client in one bucket (#460).

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
        issuance_per_hour: int = 5,
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
            # Credential-mint tier (RF-6 §2.7). getattr because test doubles and
            # older .env files may carry no key — the default is the ruled value,
            # never "unlimited".
            self.issuance_per_hour = getattr(config, "cert_issuance_requests_per_hour", 5)
        else:
            self.enforce = True
            self.requests_per_minute = requests_per_minute
            self.auth_requests_per_minute = auth_requests_per_minute
            self.break_glass_per_hour = 5
            self.issuance_per_hour = issuance_per_hour

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
        elif self._is_cert_issuance_endpoint(request.url.path):
            # Admin-certificate mint tier (RF-6 §2.7). Keyed per ACCOUNT when an
            # identity is attached, so the cap follows the person across cores
            # and survives a restart; IP only as the fallback for a caller with
            # no identity yet. The counter is the same DB-backed UPSERT as every
            # other tier — that is the property §2.7 rules on for a mint cap
            # (the in-memory limiters enforce N× on N workers and forget on
            # restart).
            endpoint_type = "cert_issuance"
            limit = self.issuance_per_hour
            window = _ISSUANCE_WINDOW
        elif self._is_auth_endpoint(request.url.path):
            endpoint_type = "auth"
            limit = self.auth_requests_per_minute
            window = _AUTH_WINDOW
        else:
            endpoint_type = "generic"
            limit = self.requests_per_minute
            window = _GENERIC_WINDOW

        # Check break-glass backoff before processing
        if endpoint_type == "break_glass":
            backoff_remaining = self._check_break_glass_backoff(ip)
            if backoff_remaining > 0:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Break-glass endpoint rate limited: too many recent failures"},
                    headers={"Retry-After": str(backoff_remaining)},
                )

        # UPSERT: atomic increment against the shared clock. No local time is
        # read here — the bucket key and the seconds left in it both come back
        # from the database (ticket #460). The counter KEY is still chosen here:
        # the mint tier follows the account, every other tier the client IP
        # (RF-6 §2.7).
        identifier = ip if endpoint_type != "cert_issuance" else self._issuance_identifier(request, ip)
        db = None
        try:
            backend = getattr(request.app.state, "backend", None)
            if backend is None:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Backend not initialized"},
                )
            db = backend.get_session()

            count, retry_seconds = self._increment_shared_clock_counter(db, identifier, endpoint_type, window)

            if count > limit:
                metrics.RATE_LIMIT_HIT_TOTAL.labels(limit_type=endpoint_type).inc()
                retry_after = {"Retry-After": str(retry_seconds)}
                if endpoint_type == "break_glass":
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Break-glass endpoint rate limited: too many requests per hour"},
                        headers=retry_after,
                    )
                elif endpoint_type == "cert_issuance":
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": (
                                "Admin certificate issuance rate limited: too many mints this hour — "
                                "one mint costs one security-key touch. Repair: wait for the window "
                                "to reset, or reuse the certificate you already hold until it expires."
                            )
                        },
                        headers=retry_after,
                    )
                elif endpoint_type == "auth":
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Auth endpoint rate limited: too many requests per minute"},
                        headers=retry_after,
                    )
                else:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Rate limited: too many requests per minute"},
                        headers=retry_after,
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

    def _increment_shared_clock_counter(
        self, db, identifier: str, endpoint_type: str, window: timedelta
    ) -> tuple[int, int]:
        """Atomically increment the counter for the window the DATABASE opens.

        Returns ``(count, retry_seconds)`` read off one statement: the new count
        after the increment, and the seconds left in the window that count was
        taken from. The window key never comes from this process — that is the
        whole point (ticket #460): N replicas over a shared table must land one
        client in one bucket, and a replica-clock key splits it into one bucket
        per replica, which multiplies the limit and makes Retry-After depend on
        which core answered.

        Dialect guard (#366 shape, see routes/init.py): ``date_trunc``/``now()``
        are PostgreSQL-side, so the production statement goes out on a
        PostgreSQL bind (a session that cannot report its dialect is treated as
        PostgreSQL so the production contract stays pinned) and the SQLite bind
        gets the ``strftime`` form of the same contract.
        """
        from sqlalchemy import text

        unit, window_seconds = _window_bucket_shape(window)
        bind = db.get_bind() if hasattr(db, "get_bind") else None
        if bind is None or bind.dialect.name == "postgresql":
            sql = _SHARED_CLOCK_UPSERT_POSTGRESQL
            params = {
                "identifier": identifier,
                "endpoint_type": endpoint_type,
                "unit": unit,
                "window_seconds": window_seconds,
            }
        else:
            sql = _SHARED_CLOCK_UPSERT_SQLITE
            params = {
                "identifier": identifier,
                "endpoint_type": endpoint_type,
                "bucket_format": _SQLITE_BUCKET_FORMAT[unit],
                "window_seconds": window_seconds,
            }

        row = db.execute(text(sql), params).one()
        # Same commit contract as _increment_counter below: the dispatch
        # `finally: db.close()` rolls back anything uncommitted, and an
        # uncommitted counter never enforces anything (ticket
        # ratelimit-counter-upsert-never-commits).
        db.commit()
        return int(row.count), _clamp_retry_after(row.retry_seconds)

    def _increment_counter(self, db, identifier: str, endpoint_type: str, window_start: datetime) -> int:
        """Atomically increment a rate limit counter via UPSERT for an EXACT,
        caller-supplied window key.

        Returns the new count after increment.

        NOT the dispatch path since #460: a key supplied by a replica is the
        per-replica-bucket defect this ticket fixes. This form stays for callers
        that must pin a bucket precisely (the window-rollover cell) and is the
        retirement candidate for a follow-up once that cell is re-ruled.
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

    def _check_break_glass_backoff(self, ip: str) -> int:
        """Check exponential backoff for break-glass failures.

        Returns the REMAINING backoff seconds (> 0 = blocked, 0 = pass) — the
        caller turns it into the 429's Retry-After header (ticket
        delta-b-run-low-bundle O2). Truthiness-compatible with the old bool
        contract. Backoff: 1s, 2s, 4s, 8s, 16s (capped at 16s).

        #549: the stamps and this reading come from ``time.monotonic()``, not
        the wall clock. The state is per-process memory and every question
        asked of it (``elapsed``, the 1-hour prune) is elapsed REAL time, so a
        wall-clock step must not move the window: a forward step used to age
        the recorded failures out inside their true backoff (and the prune at
        the same ``now`` dropped the history), and a backward step made
        ``elapsed`` negative and inflated the returned Retry-After past the
        cap (measured: a 3600 s step back returned 3601). One clock per
        structure — both this read and ``_record_break_glass_failure``'s stamp
        are monotonic. The returned figure is a DURATION in int seconds, which
        no clock choice changes.
        """
        now = time.monotonic()
        failures = self._break_glass_failures.get(ip, [])

        # Only keep failures within the last hour
        failures = [t for t in failures if now - t < 3600]
        if not failures:
            return 0

        attempt_count = len(failures)
        backoff_seconds = min(2 ** (attempt_count - 1), 16)

        last_failure = failures[-1]
        elapsed = now - last_failure

        if elapsed < backoff_seconds:
            metrics.RATE_LIMIT_HIT_TOTAL.labels(limit_type="break_glass_backoff").inc()
            return max(1, math.ceil(backoff_seconds - elapsed))

        return 0

    def _record_break_glass_failure(self, ip: str) -> None:
        """Record a break-glass failure for exponential backoff.

        #549: monotonic stamp — see ``_check_break_glass_backoff`` for why the
        backoff window is measured on real time, not the wall clock.
        """
        now = time.monotonic()
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
        loopback-only-backend topology the inner mTLS channel seals
        (end-to-end-mtls-header-trust-removal #314: uvicorn now REQUIRES the
        nginx client cert, so a direct app-port connect dies at the TLS
        handshake instead of merely spoofs; the single-append fact this
        function depends on is unchanged). See the _validate_admin_mtls /
        _validate_executor_mtls docstrings — two controls share this
        invariant. A SECOND proxy layer would still silently invalidate it.
        Do not change the topology without changing this function.
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

    def _is_cert_issuance_endpoint(self, path: str) -> bool:
        """Check if path is an admin-certificate mint (RF-6 §2.7).

        Exact-path match, not a prefix: the tier belongs to the one endpoint
        that mints a credential. A mint path that is NOT classified here falls
        through to the generic per-IP tier (ip_rate_limit, default 1000/min),
        which is not a cap on credential issuance at all — so the classification
        is the cap, and its paired test asserts this path is in the set.
        """
        return path.rstrip("/") == "/api/v1/admin/certs/issue"

    def _issuance_identifier(self, request: Request, ip: str) -> str:
        """Per-account mint key when an identity is attached, IP otherwise.

        ``SessionMiddleware`` is registered OUTERMOST of the two (app.py adds
        RateLimit, then Session, and Starlette treats the last-added as the
        outermost), so by the time this middleware runs the auth layer has
        already attached ``request.state.auth_user`` — that ordering is what
        makes a per-account cap possible here, and
        ``test_issuance_tier_keys_by_account_when_identity_is_attached`` pins it
        instead of trusting it.

        The value lands in the counter's ``identifier`` column (String(64),
        documented in core/iam/models.py as "IP address or user_id depending on
        scope"), so the account form is the column's own second documented use
        and needs no schema change. NO prefix is prepended on purpose: a
        ``user:`` tag on a 64-char user_id would exceed the column width, and
        the ``(identifier, endpoint_type, window_start)`` primary key already
        separates this tier's rows from every other tier's.

        Fail-safe: with no identity (401-class callers) the tier degrades to the
        per-IP key, so an unauthenticated flood of mint attempts is still
        counted — never skipped.
        """
        auth_user = getattr(request.state, "auth_user", None)
        if isinstance(auth_user, dict):
            user_id = auth_user.get("user_id")
            if isinstance(user_id, str) and user_id:
                return user_id[:64]
        return ip
