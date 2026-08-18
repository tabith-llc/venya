"""Tests for rate limiting middleware (PostgreSQL-backed)."""

from unittest.mock import MagicMock

from fastapi import FastAPI
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from server.middleware.rate_limit import RateLimitMiddleware


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

    def test_auth_endpoint_under_auth_limit(self):
        """Auth endpoints use the stricter auth rate limit."""
        app = _create_test_app(requests_per_minute=100, auth_requests_per_minute=3)
        client = TestClient(app)

        for _ in range(3):
            resp = client.get("/api/v1/auth/login")
            assert resp.status_code == 200

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

    def test_backend_unavailable_returns_503(self):
        """Rate limit check returns 503 if backend is not initialized."""
        app = FastAPI()

        class MockConfig:
            enforce = True
            ip_rate_limit = 100
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
