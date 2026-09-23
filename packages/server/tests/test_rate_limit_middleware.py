# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for rate limiting middleware (PostgreSQL-backed)."""

from datetime import UTC
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.middleware.rate_limit import RateLimitMiddleware
from starlette.responses import JSONResponse
from starlette.testclient import TestClient


def _create_test_app(
    requests_per_minute=100,
    auth_requests_per_minute=20,
    break_glass_per_hour=5,
    counter_counts=None,
):
    """Create a minimal test app with rate limit middleware.

    Args:
        counter_counts: Optional dict mapping (ip, endpoint_type, bucket) -> count.
            The mock UPSERT returns the count for the given key.
            If None, defaults to returning 1 for all keys (simulates fresh counters).
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

    def mock_execute(sql, params):
        """Simulate UPSERT: return the configured count for this (ip, endpoint_type, window_start)."""
        key = (params["identifier"], params["endpoint_type"], params["window_start"])
        if counter_counts is not None and key in counter_counts:
            count = counter_counts[key]
        else:
            # Default: first call returns 1, subsequent calls increment
            if key not in mock_execute._call_counts:
                mock_execute._call_counts[key] = 1
            else:
                mock_execute._call_counts[key] += 1
            count = mock_execute._call_counts[key]

        result = MagicMock()
        result.scalar.return_value = count
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

    def mock_execute(sql, params):
        key = (params["identifier"], params["endpoint_type"], params["window_start"])
        if key not in mock_execute._call_counts:
            mock_execute._call_counts[key] = 1
        else:
            mock_execute._call_counts[key] += 1
        count = mock_execute._call_counts[key]

        result = MagicMock()
        result.scalar.return_value = count
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

        # IP 10.0.0.1 uses its limit
        resp1 = client.get("/api/v1/health", headers={"X-Forwarded-For": "10.0.0.1"})
        assert resp1.status_code == 200
        resp2 = client.get("/api/v1/health", headers={"X-Forwarded-For": "10.0.0.1"})
        assert resp2.status_code == 200
        resp3 = client.get("/api/v1/health", headers={"X-Forwarded-For": "10.0.0.1"})
        assert resp3.status_code == 429

        # IP 10.0.0.2 should still work (separate counter)
        resp = client.get("/api/v1/health", headers={"X-Forwarded-For": "10.0.0.2"})
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
        r1 = client.get("/api/v1/health", headers={"X-Forwarded-For": "1.1.1.1, 10.0.0.7"})
        r2 = client.get("/api/v1/health", headers={"X-Forwarded-For": "2.2.2.2, 10.0.0.7"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        r3 = client.get("/api/v1/health", headers={"X-Forwarded-For": "3.3.3.3, 10.0.0.7"})
        assert r3.status_code == 429  # spoof rotation does NOT reset the bucket

        # A different REAL (rightmost) IP still has its own bucket
        r4 = client.get("/api/v1/health", headers={"X-Forwarded-For": "1.1.1.1, 10.0.0.8"})
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
