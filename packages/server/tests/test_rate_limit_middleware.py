# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for rate limiting middleware (PostgreSQL-backed)."""

import math
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from server.middleware import rate_limit
from server.middleware.rate_limit import (
    _AUTH_WINDOW,
    _BREAK_GLASS_WINDOW,
    _GENERIC_WINDOW,
    _ISSUANCE_WINDOW,
    RateLimitMiddleware,
)
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

# --- test-side fake DB helpers (ticket #460) --------------------------------
# The mock backend has to decide which bucket a request landed in, and since
# #460 the product does NOT hand it a replica-supplied key any more: the
# statement derives the bucket from the DATABASE clock. These helpers give the
# fake the same authority, so a mock-backed cell can only pass while the
# middleware asks the database for the window instead of computing one from the
# clock of the process that happens to be handling the request. They mirror
# `_SHARED_CLOCK_UPSERT_SQLITE` / `_SHARED_CLOCK_UPSERT_POSTGRESQL`; no
# assertion in this file was written against them.


def _db_bucket(params: dict, db_now: datetime) -> datetime:
    """The window key as the DATABASE would derive it from `db_now`.

    The explicit-key form (`_increment_counter`) still binds its own bucket, so
    it is honoured as given; anything else is truncated here — the database's
    own clock, which no replica clock can move.
    """
    if "window_start" in params:
        return params["window_start"]
    unit = params.get("unit")
    if unit is None:
        # The SQLite form binds the strftime format instead of the unit name.
        unit = "hour" if params["bucket_format"].endswith("%H:00:00+00:00") else "minute"
    if unit == "hour":
        return db_now.replace(minute=0, second=0, microsecond=0)
    return db_now.replace(second=0, microsecond=0)


def _db_retry_seconds(params: dict, bucket: datetime, db_now: datetime) -> int:
    """Seconds left in `bucket`, measured against the DATABASE clock."""
    remaining = int(params.get("window_seconds", 60)) - (db_now - bucket).total_seconds()
    return max(1, math.ceil(remaining))


def _create_test_app(
    requests_per_minute=100,
    auth_requests_per_minute=20,
    break_glass_per_hour=5,
    counter_counts=None,
    db_now=None,
):
    """Create a minimal test app with rate limit middleware.

    Args:
        counter_counts: Optional dict mapping (ip, endpoint_type, bucket) -> count.
            The mock UPSERT returns the count for the given key.
            If None, defaults to returning 1 for all keys (simulates fresh counters).
        db_now: Optional fixed DATABASE clock for the fake backend (#460). The
            bucket key is derived from it, so a cell can straddle two replica
            clocks over one database minute.
    """
    app = FastAPI()

    class MockConfig:
        enforce = True
        ip_rate_limit = requests_per_minute
        break_glass_requests_per_hour = break_glass_per_hour
        clock_skew = MagicMock()
        clock_skew.token_tolerance_seconds = 60

    # Set post-class: `x = x` inside a class body is a NameError (the RHS
    # resolves class-local); the tier param must come from the enclosing
    # function scope (ticket sec-endpoint-ratelimit-hardening #8).
    MockConfig.auth_requests_per_minute = auth_requests_per_minute

    app.state.config = MockConfig()

    # Build a mock backend with a UPSERT that returns pre-configured counts
    backend = MagicMock()
    db = MagicMock()
    # The middleware picks its statement from the bind dialect (the #366 guard),
    # so pin it: a mock-backed cell must not drift onto the PostgreSQL form by
    # accident of an unpinned MagicMock attribute.
    db.get_bind.return_value.dialect.name = "sqlite"
    fake_db_now = db_now if db_now is not None else datetime.now(UTC)

    def mock_execute(sql, params):
        """Simulate the shared-clock UPSERT: the bucket comes from `fake_db_now`."""
        bucket = _db_bucket(params, fake_db_now)
        key = (params["identifier"], params["endpoint_type"], bucket)
        if counter_counts is not None and key in counter_counts:
            count = counter_counts[key]
        else:
            # Default: first call returns 1, subsequent calls increment
            if key not in mock_execute._call_counts:
                mock_execute._call_counts[key] = 1
            else:
                mock_execute._call_counts[key] += 1
            count = mock_execute._call_counts[key]

        retry_seconds = _db_retry_seconds(params, bucket, fake_db_now)
        app.state.rate_limit_rows.append(
            SimpleNamespace(
                identifier=key[0],
                endpoint_type=key[1],
                window_start=bucket,
                count=count,
                retry_seconds=retry_seconds,
                sql=str(sql.text),
                params=dict(params),
            )
        )

        result = MagicMock()
        result.scalar.return_value = count
        result.one.return_value = SimpleNamespace(count=count, window_start=bucket, retry_seconds=retry_seconds)
        result.rowcount = 1
        return result

    mock_execute._call_counts = {}
    app.state.rate_limit_rows = []
    db.execute.side_effect = mock_execute
    backend.get_session.return_value = db
    app.state.backend = backend

    app.add_middleware(
        RateLimitMiddleware,
        config=app.state.config,
        requests_per_minute=requests_per_minute,
        auth_requests_per_minute=auth_requests_per_minute,
        break_glass_per_hour=break_glass_per_hour,
    )

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/v1/auth/login")
    def auth_login():
        return {"status": "login"}

    @app.get("/api/v1/enrollment/start")
    def enrollment_start():
        return {"status": "enroll"}

    @app.post("/api/v1/recovery")
    def recovery():
        return {"status": "recovery"}

    return app


def _create_test_app_with_401(requests_per_minute=100, auth_requests_per_minute=20, break_glass_per_hour=5):
    """Create a test app where recovery returns 401."""
    app = FastAPI()

    class MockConfig:
        enforce = True
        ip_rate_limit = requests_per_minute
        break_glass_requests_per_hour = break_glass_per_hour
        clock_skew = MagicMock()
        clock_skew.token_tolerance_seconds = 60

    # Set post-class: `x = x` inside a class body is a NameError (the RHS
    # resolves class-local); the tier param must come from the enclosing
    # function scope (ticket sec-endpoint-ratelimit-hardening #8).
    MockConfig.auth_requests_per_minute = auth_requests_per_minute

    app.state.config = MockConfig()

    backend = MagicMock()
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "sqlite"
    fake_db_now = datetime.now(UTC)

    def mock_execute(sql, params):
        bucket = _db_bucket(params, fake_db_now)
        key = (params["identifier"], params["endpoint_type"], bucket)
        if key not in mock_execute._call_counts:
            mock_execute._call_counts[key] = 1
        else:
            mock_execute._call_counts[key] += 1
        count = mock_execute._call_counts[key]
        retry_seconds = _db_retry_seconds(params, bucket, fake_db_now)

        result = MagicMock()
        result.scalar.return_value = count
        result.one.return_value = SimpleNamespace(count=count, window_start=bucket, retry_seconds=retry_seconds)
        result.rowcount = 1
        return result

    mock_execute._call_counts = {}
    db.execute.side_effect = mock_execute
    backend.get_session.return_value = db
    app.state.backend = backend

    app.add_middleware(
        RateLimitMiddleware,
        config=app.state.config,
        requests_per_minute=requests_per_minute,
        auth_requests_per_minute=auth_requests_per_minute,
        break_glass_per_hour=break_glass_per_hour,
    )

    @app.post("/api/v1/recovery")
    def recovery_401():
        return JSONResponse(status_code=401, content={"detail": "Invalid recovery code"})

    return app


class TestRateLimitMiddleware:
    """Tests for PostgreSQL-backed rate limit middleware."""

    def test_health_endpoint_under_general_limit(self):
        """Non-auth endpoints use the general rate limit."""
        app = _create_test_app(requests_per_minute=5, auth_requests_per_minute=20)
        client = TestClient(app)

        for _ in range(5):
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200

    def test_bare_health_alias_generic_tier_parity(self):
        """Bare /health classifies into the SAME generic tier as the canonical
        /api/v1/health (ticket health-probe-401-installer-diagnostics scope a):
        neither auth-tier nor break-glass, so both share the one per-IP generic
        bucket and limit — mixed traffic 429s together, no path gets a
        different (or unlimited) tier."""
        app = _create_test_app(requests_per_minute=5, auth_requests_per_minute=20)

        @app.get("/health")
        def bare_health():
            return {"status": "ok"}

        client = TestClient(app)
        for path in ("/api/v1/health", "/health", "/api/v1/health", "/health", "/api/v1/health"):
            assert client.get(path).status_code == 200
        assert client.get("/health").status_code == 429
        assert client.get("/api/v1/health").status_code == 429

    def test_auth_endpoint_under_auth_limit(self):
        """Auth endpoints use the stricter auth rate limit."""
        app = _create_test_app(requests_per_minute=100, auth_requests_per_minute=3)
        client = TestClient(app)

        for _ in range(3):
            resp = client.get("/api/v1/auth/login")
            assert resp.status_code == 200

        # TIER PIN (ticket sec-endpoint-ratelimit-hardening #8): the 4th
        # request in the window 429s. Pre-fix the constructor collapsed the
        # auth tier into ip_rate_limit (1000/min in production config), so
        # the loop above passed while the tier itself was dead.
        resp = client.get("/api/v1/auth/login")
        assert resp.status_code == 429

    def test_recovery_endpoint_under_break_glass_limit(self):
        """Recovery endpoint uses break-glass limit, not auth limit."""
        app = _create_test_app(requests_per_minute=100, auth_requests_per_minute=2, break_glass_per_hour=5)
        client = TestClient(app)

        for _ in range(5):
            resp = client.post("/api/v1/recovery", json={})
            assert resp.status_code == 200

        resp = client.post("/api/v1/recovery", json={})
        assert resp.status_code == 429

    def test_enrollment_endpoint_under_auth_limit(self):
        """Enrollment endpoints use the stricter auth rate limit."""
        app = _create_test_app(requests_per_minute=100, auth_requests_per_minute=3)
        client = TestClient(app)

        for _ in range(3):
            resp = client.get("/api/v1/enrollment/start")
            assert resp.status_code == 200

        resp = client.get("/api/v1/enrollment/start")
        assert resp.status_code == 429  # tier pin (see test_auth_endpoint_under_auth_limit)


class TestBreakGlassRateLimit:
    """Tests for break-glass (recovery) specific rate limiting."""

    def test_recovery_under_break_glass_limit(self):
        """Recovery endpoint enforces break-glass rate limit (5/hour)."""
        app = _create_test_app(break_glass_per_hour=3)
        client = TestClient(app)

        for _ in range(3):
            resp = client.post("/api/v1/recovery", json={})
            assert resp.status_code == 200

        resp = client.post("/api/v1/recovery", json={})
        assert resp.status_code == 429

    def test_recovery_break_glass_separate_from_auth_limit(self):
        """Break-glass limit is separate from auth limit."""
        app = _create_test_app(auth_requests_per_minute=10, break_glass_per_hour=2)
        client = TestClient(app)

        resp1 = client.post("/api/v1/recovery", json={})
        assert resp1.status_code == 200
        resp2 = client.post("/api/v1/recovery", json={})
        assert resp2.status_code == 200
        resp3 = client.post("/api/v1/recovery", json={})
        assert resp3.status_code == 429

    def test_recovery_401_triggers_backoff(self):
        """Recovery 401 responses trigger exponential backoff."""
        app = _create_test_app_with_401(break_glass_per_hour=10)
        client = TestClient(app)

        resp1 = client.post("/api/v1/recovery", json={})
        assert resp1.status_code == 401

        resp2 = client.post("/api/v1/recovery", json={})
        assert resp2.status_code == 429

    def test_non_recovery_not_affected_by_break_glass(self):
        """Non-recovery endpoints are not affected by break-glass limits."""
        app = _create_test_app(break_glass_per_hour=1)
        client = TestClient(app)

        resp = client.post("/api/v1/recovery", json={})
        assert resp.status_code == 200
        resp = client.post("/api/v1/recovery", json={})
        assert resp.status_code == 429

        resp = client.get("/api/v1/auth/login")
        assert resp.status_code == 200


class TestRateLimitMultiWorker:
    """Tests verifying multi-worker safety (DB-backed counters)."""

    def test_different_ips_have_separate_counters(self):
        """Different IPs should have independent rate limits."""
        app = _create_test_app(requests_per_minute=2)
        client = TestClient(app)

        # IP 203.0.113.1 uses its limit
        resp1 = client.get("/api/v1/health", headers={"X-Forwarded-For": "203.0.113.1"})
        assert resp1.status_code == 200
        resp2 = client.get("/api/v1/health", headers={"X-Forwarded-For": "203.0.113.1"})
        assert resp2.status_code == 200
        resp3 = client.get("/api/v1/health", headers={"X-Forwarded-For": "203.0.113.1"})
        assert resp3.status_code == 429

        # IP 203.0.113.2 should still work (separate counter)
        resp = client.get("/api/v1/health", headers={"X-Forwarded-For": "203.0.113.2"})
        assert resp.status_code == 200

    def test_xff_rightmost_entry_keys_the_limit(self):
        """#8 BYPASS PIN (ticket sec-endpoint-ratelimit-hardening): the limit
        keys on the RIGHTMOST XFF entry — the one our nginx appends
        ($proxy_add_x_forwarded_for = "<client-sent>, <real peer>"). The
        leftmost entry is attacker-controlled; pre-fix, rotating a spoofed
        leftmost value gave every request a fresh bucket (break-glass 5/hr,
        auth tier, and backoff all bypassable with one header)."""
        app = _create_test_app(requests_per_minute=2)
        client = TestClient(app)

        # Same real IP behind three different spoofs → ONE bucket: 2 pass, 3rd 429
        r1 = client.get("/api/v1/health", headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.7"})
        r2 = client.get("/api/v1/health", headers={"X-Forwarded-For": "2.2.2.2, 203.0.113.7"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        r3 = client.get("/api/v1/health", headers={"X-Forwarded-For": "3.3.3.3, 203.0.113.7"})
        assert r3.status_code == 429  # spoof rotation does NOT reset the bucket

        # A different REAL (rightmost) IP still has its own bucket
        r4 = client.get("/api/v1/health", headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.8"})
        assert r4.status_code == 200

    def test_backend_unavailable_returns_503(self):
        """Rate limit check returns 503 if backend is not initialized."""
        app = FastAPI()

        class MockConfig:
            enforce = True
            ip_rate_limit = 100
            auth_requests_per_minute = 20
            break_glass_requests_per_hour = 5
            clock_skew = MagicMock()
            clock_skew.token_tolerance_seconds = 60

        app.state.config = MockConfig()
        app.state.backend = None

        app.add_middleware(RateLimitMiddleware, config=app.state.config)

        @app.get("/api/v1/health")
        def health():
            return {"status": "ok"}

        client = TestClient(app)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 503

    def test_rate_limit_disabled(self):
        """When enforce=False, all requests pass through."""
        app = FastAPI()

        class MockConfig:
            enforce = False
            ip_rate_limit = 1
            auth_requests_per_minute = 20
            break_glass_requests_per_hour = 1
            clock_skew = MagicMock()
            clock_skew.token_tolerance_seconds = 60

        app.state.config = MockConfig()

        backend = MagicMock()
        db = MagicMock()
        backend.get_session.return_value = db
        app.state.backend = backend

        app.add_middleware(RateLimitMiddleware, config=app.state.config)

        @app.get("/api/v1/health")
        def health():
            return {"status": "ok"}

        client = TestClient(app)
        # Should pass even though limit is 1
        for _ in range(5):
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200


def _create_real_db_app(
    requests_per_minute=100,
    auth_requests_per_minute=20,
    break_glass_per_hour=5,
):
    """App wired to a REAL SQLite session factory with production lifecycle.

    `backend.get_session()` returns a FRESH Session per call and the
    middleware's `finally: db.close()` rolls back anything uncommitted —
    exactly the deployed shape. The mock-backed cells above stub
    `db.execute().scalar()` and therefore cannot see a missing COMMIT
    (ticket ratelimit-counter-upsert-never-commits: the UPSERT counters
    never persisted, so no DB-backed tier ever 429'd physically while the
    suite stayed green).
    """
    from core.iam.models import RateLimitFailure
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    RateLimitFailure.__table__.create(engine)
    factory = sessionmaker(bind=engine)

    app = FastAPI()

    class MockConfig:
        enforce = True
        ip_rate_limit = requests_per_minute
        break_glass_requests_per_hour = break_glass_per_hour
        clock_skew = MagicMock()
        clock_skew.token_tolerance_seconds = 60

    MockConfig.auth_requests_per_minute = auth_requests_per_minute
    app.state.config = MockConfig()

    backend = MagicMock()
    backend.get_session.side_effect = lambda: factory()
    app.state.backend = backend

    app.add_middleware(RateLimitMiddleware, config=app.state.config)

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/v1/auth/login")
    def auth_login():
        return {"status": "login"}

    @app.post("/api/v1/recovery")
    def recovery():
        return {"status": "recovery"}

    return app, engine


class TestRealSessionCommitLifecycle:
    """Real-lifecycle truth table for the DB-backed rate-limit counters."""

    def test_counter_rows_persist_across_fresh_sessions(self):
        from sqlalchemy import text

        app, engine = _create_real_db_app()
        client = TestClient(app)
        for _ in range(3):
            assert client.get("/api/v1/health").status_code == 200
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT endpoint_type, count FROM rate_limit_failures")).fetchall()
        # Pre-fix: zero rows — every UPSERT was rolled back by db.close().
        assert rows == [("generic", 3)]

    def test_auth_tier_429_with_real_sessions(self):
        app, _ = _create_real_db_app(auth_requests_per_minute=2)
        client = TestClient(app)
        assert client.get("/api/v1/auth/login").status_code == 200
        assert client.get("/api/v1/auth/login").status_code == 200
        r3 = client.get("/api/v1/auth/login")
        # Pre-fix: 200 — count was always 1 in its rolled-back transaction.
        assert r3.status_code == 429
        assert "Auth endpoint rate limited" in r3.json()["detail"]

    def test_break_glass_hourly_429_with_real_sessions(self):
        app, _ = _create_real_db_app(break_glass_per_hour=1)
        client = TestClient(app)
        assert client.post("/api/v1/recovery").status_code == 200
        r2 = client.post("/api/v1/recovery")
        assert r2.status_code == 429
        assert "per hour" in r2.json()["detail"]

    def test_window_rollover_uses_separate_buckets(self):
        from datetime import datetime, timedelta

        from server.middleware.rate_limit import RateLimitMiddleware

        app, _engine = _create_real_db_app()
        mw = RateLimitMiddleware(app=MagicMock(), config=None)
        now = datetime.now(UTC).replace(second=0, microsecond=0)
        factory = app.state.backend.get_session
        s1 = factory()
        assert mw._increment_counter(s1, "1.2.3.4", "auth", now) == 1
        assert mw._increment_counter(s1, "1.2.3.4", "auth", now) == 2
        s1.close()
        s2 = factory()
        # A fresh session must SEE the committed count (pre-fix: rollback → 1).
        assert mw._increment_counter(s2, "1.2.3.4", "auth", now) == 3
        # New window → its own bucket.
        assert mw._increment_counter(s2, "1.2.3.4", "auth", now + timedelta(minutes=1)) == 1
        s2.close()


class TestRetryAfterHeader:
    """Every middleware 429 carries Retry-After (ticket delta-b-run-low-bundle O2).

    Paired cells per the truth-table rule: one positive per 429 path (header
    present, delta-seconds integer, bounded by the path's window/cap) and the
    negative half (non-429 responses never gain the header). Pre-fix, all four
    paths emitted 429 with NO Retry-After (physically observed: header None at
    the auth tier) — client backoff was guesswork.
    """

    def test_auth_tier_429_carries_retry_after(self):
        client = TestClient(_create_test_app(auth_requests_per_minute=2))
        for _ in range(2):
            assert client.get("/api/v1/auth/login").status_code == 200
        resp = client.get("/api/v1/auth/login")
        assert resp.status_code == 429
        retry = resp.headers.get("Retry-After")
        assert retry is not None, "auth-tier 429 must carry Retry-After"
        assert retry.isdigit()
        assert 1 <= int(retry) <= 60  # 1-minute window

    def test_generic_tier_429_carries_retry_after(self):
        client = TestClient(_create_test_app(requests_per_minute=2))
        for _ in range(2):
            assert client.get("/api/v1/health").status_code == 200
        resp = client.get("/api/v1/health")
        assert resp.status_code == 429
        retry = resp.headers.get("Retry-After")
        assert retry is not None, "generic-tier 429 must carry Retry-After"
        assert retry.isdigit()
        assert 1 <= int(retry) <= 60  # 1-minute window

    def test_break_glass_hourly_429_carries_retry_after(self):
        client = TestClient(_create_test_app(break_glass_per_hour=2))
        for _ in range(2):
            assert client.post("/api/v1/recovery").status_code == 200
        resp = client.post("/api/v1/recovery")
        assert resp.status_code == 429
        retry = resp.headers.get("Retry-After")
        assert retry is not None, "break-glass hourly 429 must carry Retry-After"
        assert retry.isdigit()
        assert 1 <= int(retry) <= 3600  # 1-hour window

    def test_backoff_429_carries_retry_after_within_cap(self):
        client = TestClient(_create_test_app_with_401())
        first = client.post("/api/v1/recovery")
        assert first.status_code == 401  # failure recorded → 1s backoff armed
        resp = client.post("/api/v1/recovery")
        assert resp.status_code == 429
        assert "too many recent failures" in resp.json()["detail"]
        retry = resp.headers.get("Retry-After")
        assert retry is not None, "backoff 429 must carry Retry-After"
        assert retry.isdigit()
        assert 1 <= int(retry) <= 16  # backoff cap

    def test_non_429_responses_have_no_retry_after(self):
        client = TestClient(_create_test_app())
        for resp in (
            client.get("/api/v1/health"),
            client.get("/api/v1/auth/login"),
            client.post("/api/v1/recovery"),
        ):
            assert resp.status_code == 200
            assert "Retry-After" not in resp.headers


# --- shared-clock window key (ticket #460) ----------------------------------
# The defect: the fixed-window bucket key is part of the shared table's primary
# key, and it used to be cut from the clock of whichever core replica happened
# to serve the request. Two replicas with any skew put one client in two
# buckets, so the effective limit became limit x buckets and Retry-After
# depended on which replica answered. The fix derives the bucket inside the
# UPSERT from the DATABASE clock.
#
# Replica-side clock is simulated by swapping the `datetime` name inside the
# middleware module for a subclass whose now() answers as that replica's clock.
# Assertions then use wall-clock ISO strings, which a swapped clock cannot
# spoof.


def _replica_clock(when: datetime):
    class _ReplicaClock(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: NPO001 - test double for one replica's clock
            return when

    return _ReplicaClock


def _serve_from_replica(monkeypatch, when: datetime, client, method: str, path: str, ip: str, **kwargs):
    """One request served by a replica whose local clock reads `when`."""
    monkeypatch.setattr(rate_limit, "datetime", _replica_clock(when))
    try:
        return getattr(client, method)(path, headers={"X-Forwarded-For": ip}, **kwargs)
    finally:
        monkeypatch.undo()


def _minute_bucket(when: datetime) -> datetime:
    return when.replace(second=0, microsecond=0)


class TestSharedClockWindowKey:
    """Two replicas, one database clock: the bucket must agree (#460 AC2/AC3)."""

    def test_two_replicas_across_a_minute_boundary_share_one_bucket(self, monkeypatch):
        """AC2, the paired negative: skew across a minute boundary must NOT split.

        The database clock sits at 12:01:10, so the database minute is
        12:01:00. Replica A's local clock reads 12:00:59 (the previous minute),
        replica B's reads 12:01:29. At the unmodified base the two requests cut
        two buckets (12:00:00 and 12:01:00), each stayed at count 1 against a
        limit of 1, and NEITHER request 429'd — the split limit this ticket is
        about. With the key derived from the shared clock both requests land in
        12:01:00, so the second one trips exactly once.
        """
        db_now = datetime(2026, 10, 8, 12, 1, 10, tzinfo=UTC)
        app = _create_test_app(requests_per_minute=1, db_now=db_now)
        client = TestClient(app)
        ip = "203.0.113.50"

        r1 = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 0, 59, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )
        r2 = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 1, 29, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )

        assert r1.status_code == 200
        assert r2.status_code == 429, "skewed replicas must aggregate into one bucket, not two"

        rows = app.state.rate_limit_rows
        assert [row.window_start.isoformat() for row in rows] == [
            _minute_bucket(db_now).isoformat(),
            _minute_bucket(db_now).isoformat(),
        ], "both replicas landed in the window the database opened"
        assert [row.count for row in rows] == [1, 2], "the combined count trips at count > limit exactly once"

    def test_no_replica_supplied_window_key_reaches_the_statement(self, monkeypatch):
        """The negative half of the key site: the bind params carry no bucket.

        A replica-side key is the defect, so the statement must not accept one:
        the window comes from the database clock expression in the statement
        itself. Paired with the skew cell above, which shows what a
        replica-supplied key does to the counters.
        """
        db_now = datetime(2026, 10, 8, 12, 1, 10, tzinfo=UTC)
        app = _create_test_app(requests_per_minute=1, db_now=db_now)
        client = TestClient(app)
        ip = "203.0.113.51"

        _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 0, 59, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )
        _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 1, 29, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )

        rows = app.state.rate_limit_rows
        assert len(rows) == 2
        for row in rows:
            assert "window_start" not in row.params, "the middleware must not bind a window it cut locally"
            assert "strftime(" in row.sql and "'now'" in row.sql, "the bucket comes from the database clock"

    def test_retry_after_is_the_same_value_from_either_replica(self, monkeypatch):
        """AC3: one logical window, one Retry-After, whichever replica answers.

        Database clock 12:01:10 → 50 seconds left in the 12:01:00 window. The
        two 429s are served by replicas whose local clocks read 12:01:29 and
        12:01:59; a replica-derived answer would differ between them (and, at
        the base, would not even be emitted, because the split buckets kept
        both counts at or under the limit).
        """
        db_now = datetime(2026, 10, 8, 12, 1, 10, tzinfo=UTC)
        app = _create_test_app(requests_per_minute=1, db_now=db_now)
        client = TestClient(app)
        ip = "203.0.113.52"

        pass1 = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 0, 59, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )
        r_b = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 1, 29, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )
        r_a = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 1, 59, tzinfo=UTC), client, "get", "/api/v1/health", ip
        )

        assert pass1.status_code == 200
        assert r_b.status_code == 429 and r_a.status_code == 429
        assert r_b.headers.get("Retry-After") == r_a.headers.get("Retry-After"), "same window, same Retry-After"
        assert r_b.headers["Retry-After"] == "50", "the header is the database window's remaining time"

    def test_two_replicas_across_an_hour_boundary_share_one_break_glass_bucket(self, monkeypatch):
        """The same property on the break-glass (hour) bucket — the one key site."""
        db_now = datetime(2026, 10, 8, 13, 0, 30, tzinfo=UTC)
        app = _create_test_app(break_glass_per_hour=1, db_now=db_now)
        client = TestClient(app)
        ip = "203.0.113.53"

        r1 = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 12, 59, 50, tzinfo=UTC), client, "post", "/api/v1/recovery", ip, json={}
        )
        r2 = _serve_from_replica(
            monkeypatch, datetime(2026, 10, 8, 13, 0, 40, tzinfo=UTC), client, "post", "/api/v1/recovery", ip, json={}
        )

        assert r1.status_code == 200
        assert r2.status_code == 429, "the hour bucket must not split on replica clock either"

        rows = app.state.rate_limit_rows
        buckets = {row.window_start.isoformat() for row in rows}
        assert buckets == {db_now.replace(minute=0, second=0, microsecond=0).isoformat()}
        assert [row.count for row in rows] == [1, 2]
        assert [row.retry_seconds for row in rows] == [3570, 3570]

    def test_the_postgresql_statement_derives_the_key_and_returns_both_columns(self):
        """Pin the production statement shape (the PostgreSQL bind).

        No PostgreSQL is reachable from this leg, so the statement that actually
        runs in the field is pinned at construction: the bucket comes from
        date_trunc over now(), no replica-supplied key is bound, and the same
        RETURNING carries the count and the window's remaining seconds. The
        behaviour cells above run the SQLite form of the identical contract
        against a real database engine.
        """
        db = MagicMock()
        db.get_bind.return_value.dialect.name = "postgresql"
        db.execute.return_value.one.return_value = SimpleNamespace(count=7, window_start=None, retry_seconds=13)

        mw = RateLimitMiddleware(app=MagicMock(), config=None)
        count, retry_after = mw._increment_shared_clock_counter(db, "1.2.3.4", "auth", _AUTH_WINDOW)

        assert (count, retry_after) == (7, 13)
        statement = db.execute.call_args.args[0].text
        params = db.execute.call_args.args[1]
        assert "window_start" not in params
        assert params == {"identifier": "1.2.3.4", "endpoint_type": "auth", "unit": "minute", "window_seconds": 60}
        assert "date_trunc(CAST(:unit AS text), (now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')" in statement
        assert "ON CONFLICT (identifier, endpoint_type, window_start)" in statement
        assert "RETURNING count" in statement and "retry_seconds" in statement
        assert ":window_start" not in statement, "no caller-supplied bucket can enter the key"
        db.commit.assert_called_once()

    def test_the_break_glass_window_maps_to_the_hour_unit_in_the_statement(self):
        """AC-adjacent pin: the hour tier asks the database for an hour bucket."""
        db = MagicMock()
        db.get_bind.return_value.dialect.name = "postgresql"
        db.execute.return_value.one.return_value = SimpleNamespace(count=1, window_start=None, retry_seconds=3599)

        mw = RateLimitMiddleware(app=MagicMock(), config=None)
        count, retry_after = mw._increment_shared_clock_counter(db, "1.2.3.4", "break_glass", _BREAK_GLASS_WINDOW)

        assert (count, retry_after) == (1, 3599)
        assert db.execute.call_args.args[1]["unit"] == "hour"
        assert db.execute.call_args.args[1]["window_seconds"] == 3600

    def test_a_real_database_produces_the_bucket_even_with_a_moved_replica_clock(self, monkeypatch):
        """The fake DB is not the only proof: on a real engine the DATABASE
        supplies the key, and a replica clock hours off cannot move it.

        Asserted against the bucket the same engine re-derives from its own
        clock after the increments, so the expectation is not computed in Python.
        The hour (break-glass) window is used on purpose: the cell only means
        something if the database bucket cannot roll between the two
        increments, and an hour boundary is three orders of magnitude rarer
        than a minute one — no sleep, no flaky assertion.
        """
        from core.iam.models import RateLimitFailure
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        RateLimitFailure.__table__.create(engine)
        factory = sessionmaker(bind=engine)

        def db_bucket() -> str:
            with engine.connect() as conn:
                return conn.execute(text("SELECT strftime('%Y-%m-%d %H:00:00+00:00', 'now')")).scalar()

        moved = datetime(2026, 10, 8, 3, 0, 0, tzinfo=UTC)
        before = db_bucket()
        monkeypatch.setattr(rate_limit, "datetime", _replica_clock(moved))
        try:
            session = factory()
            first = RateLimitMiddleware(app=MagicMock(), config=None)._increment_shared_clock_counter(
                session, "1.2.3.4", "break_glass", _BREAK_GLASS_WINDOW
            )
            session.close()
            session = factory()
            second = RateLimitMiddleware(app=MagicMock(), config=None)._increment_shared_clock_counter(
                session, "1.2.3.4", "break_glass", _BREAK_GLASS_WINDOW
            )
            session.close()
        finally:
            monkeypatch.undo()
        after = db_bucket()

        assert before == after, "the database hour must hold still for the cell to mean anything"
        assert first[0] == 1 and second[0] == 2, "one bucket, aggregate count"
        assert 1 <= first[1] <= 3600

        with engine.connect() as conn:
            rows = conn.execute(text("SELECT window_start, count FROM rate_limit_failures")).all()
        assert len(rows) == 1
        assert rows[0] == (after, 2)
        assert moved.strftime("%Y-%m-%d %H:00:00+00:00") != after, "the replica clock is NOT the key"

    def test_the_cert_issuance_tier_shares_one_bucket_across_skewed_replicas(self, monkeypatch):
        """RF-7 chunk 2 landed a fourth tier on THIS key site while this leg ran.

        The mint cap (RF-6 §2.7 — hourly, small, keyed per account) cut its
        window from the same replica clock, so it inherits the same defect and
        the same fix. Six mints served alternately by two replicas whose clocks
        straddle the hour boundary must aggregate into the one 13:00:00 window
        and arm the cap exactly once; on the base shape the six split across two
        buckets and no cap armed at all.
        """
        db_now = datetime(2026, 10, 8, 13, 0, 30, tzinfo=UTC)
        app = _create_test_app(db_now=db_now)

        @app.post("/api/v1/admin/certs/issue")
        def issue():
            return JSONResponse(status_code=201, content={"status": "minted"})

        client = TestClient(app)
        ip = "203.0.113.54"
        codes = []
        for index in range(6):
            when = (
                datetime(2026, 10, 8, 12, 59, 50, tzinfo=UTC)
                if index % 2 == 0
                else datetime(2026, 10, 8, 13, 0, 40, tzinfo=UTC)
            )
            resp = _serve_from_replica(monkeypatch, when, client, "post", "/api/v1/admin/certs/issue", ip, json={})
            codes.append(resp.status_code)

        assert codes == [201, 201, 201, 201, 201, 429], codes
        rows = app.state.rate_limit_rows
        hour_bucket = db_now.replace(minute=0, second=0, microsecond=0)
        assert {row.window_start.isoformat() for row in rows} == {hour_bucket.isoformat()}, "one window, six mints"
        assert [row.count for row in rows] == [1, 2, 3, 4, 5, 6]
        assert [row.endpoint_type for row in rows] == ["cert_issuance"] * 6

    def test_the_cert_issuance_window_asks_the_database_for_an_hour_bucket(self):
        """The mint tier's statement: hour unit, and the ACCOUNT key passthrough.

        Per-account minting (RF-6 §2.7) and the shared clock (#460) meet in the
        same bind params — the identifier follows the person, the window comes
        from the database.
        """
        db = MagicMock()
        db.get_bind.return_value.dialect.name = "postgresql"
        db.execute.return_value.one.return_value = SimpleNamespace(count=6, window_start=None, retry_seconds=3570)

        mw = RateLimitMiddleware(app=MagicMock(), config=None)
        result = mw._increment_shared_clock_counter(db, "admin@core-1", "cert_issuance", _ISSUANCE_WINDOW)

        assert result == (6, 3570)
        assert db.execute.call_args.args[1] == {
            "identifier": "admin@core-1",
            "endpoint_type": "cert_issuance",
            "unit": "hour",
            "window_seconds": 3600,
        }

    def test_module_docstring_states_the_single_clock_authority(self):
        """AC4: the docstring and the behaviour agree (#460)."""
        doc = rate_limit.__doc__ or ""
        assert "multi-worker safety" not in doc, "the old claim is what this ticket corrected"
        assert "DATABASE clock" in doc
        assert "limit x buckets" in doc

    def test_retry_after_is_clamped_to_a_positive_second(self):
        """The header contract survives an odd database answer: always >= 1."""
        assert rate_limit._clamp_retry_after(None) == 1
        assert rate_limit._clamp_retry_after(0) == 1
        assert rate_limit._clamp_retry_after(-7) == 1
        assert rate_limit._clamp_retry_after(41.2) == 42


@pytest.mark.parametrize("window", [_AUTH_WINDOW, _GENERIC_WINDOW, _BREAK_GLASS_WINDOW, _ISSUANCE_WINDOW])
def test_every_configured_window_is_database_truncable(window):
    """No STOP condition needed: every window in play is a whole minute or a
    whole hour, which is what makes the key a date_trunc call rather than an
    invented bucketing scheme (#460 spec 2)."""
    unit, seconds = rate_limit._window_bucket_shape(window)
    assert unit in {"minute", "hour"}
    assert seconds == int(window.total_seconds())
