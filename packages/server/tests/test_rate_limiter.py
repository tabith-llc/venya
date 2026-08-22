"""Tests for the sliding window rate limiter utility."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from server.rate_limit import rate_limit_registration
from server.utils.rate_limiter import SlidingWindowRateLimiter


class TestSlidingWindowRateLimiter:
    """Tests for SlidingWindowRateLimiter."""

    async def test_allows_within_limit(self):
        """Should allow requests within the limit."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        for i in range(5):
            allowed, retry = await limiter.check_and_consume(["test"])
            assert allowed is True
            assert retry == 0

    async def test_rejects_over_limit(self):
        """Should reject requests exceeding the limit."""
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        for i in range(3):
            allowed, _ = await limiter.check_and_consume(["test"])
            assert allowed is True
        allowed, retry = await limiter.check_and_consume(["test"])
        assert allowed is False
        assert retry > 0

    async def test_single_key(self):
        """Test single key check_and_consume."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        allowed, _ = await limiter.check_and_consume(["key1"])
        assert allowed is True
        allowed, _ = await limiter.check_and_consume(["key1"])
        assert allowed is True
        allowed, _ = await limiter.check_and_consume(["key1"])
        assert allowed is False

    async def test_independent_keys(self):
        """Test that different keys are tracked independently."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        await limiter.check_and_consume(["key1"])
        await limiter.check_and_consume(["key1"])
        allowed, _ = await limiter.check_and_consume(["key1"])
        assert allowed is False
        allowed, _ = await limiter.check_and_consume(["key2"])
        assert allowed is True

    async def test_atomic_multi_key_all_pass(self):
        """Test atomic check-and-consume: all keys pass."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        allowed, _ = await limiter.check_and_consume(["ip:1.2.3.4", "exec:foo"])
        assert allowed is True

    async def test_atomic_multi_key_one_fails(self):
        """Test atomic check-and-consume: one key fails, neither consumed."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        await limiter.check_and_consume(["ip:1.2.3.4"])
        await limiter.check_and_consume(["ip:1.2.3.4"])
        # ip:1.2.3.4 is now at limit
        # exec:bar is fresh
        allowed, retry = await limiter.check_and_consume(["ip:1.2.3.4", "exec:bar"])
        assert allowed is False
        assert retry > 0
        # exec:bar should NOT have been consumed (atomic)
        allowed, _ = await limiter.check_and_consume(["exec:bar"])
        assert allowed is True

    async def test_sliding_window_expiration(self):
        """Test that old requests expire after window."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=0.1)
        await limiter.check_and_consume(["test"])
        await limiter.check_and_consume(["test"])
        allowed, _ = await limiter.check_and_consume(["test"])
        assert allowed is False
        await asyncio.sleep(0.15)
        allowed, _ = await limiter.check_and_consume(["test"])
        assert allowed is True

    async def test_get_remaining(self):
        """Test get_remaining returns correct count."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        assert await limiter.get_remaining("test") == 5
        await limiter.check_and_consume(["test"])
        assert await limiter.get_remaining("test") == 4
        await limiter.check_and_consume(["test"])
        await limiter.check_and_consume(["test"])
        assert await limiter.get_remaining("test") == 2

    async def test_get_reset_time(self):
        """Test get_reset_time returns seconds until oldest expires."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        assert await limiter.get_reset_time("test") == 0
        await limiter.check_and_consume(["test"])
        reset = await limiter.get_reset_time("test")
        assert 0 < reset <= 61

    async def test_is_allowed(self):
        """Test convenience is_allowed method."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        allowed, _ = await limiter.is_allowed("test")
        assert allowed is True
        allowed, _ = await limiter.is_allowed("test")
        assert allowed is True
        allowed, _ = await limiter.is_allowed("test")
        assert allowed is False

    async def test_cleanup_expired(self):
        """Test cleanup removes expired entries."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=0.1)
        await limiter.check_and_consume(["key1"])
        await limiter.check_and_consume(["key2"])
        await limiter.check_and_consume(["key3"])
        await asyncio.sleep(0.15)
        removed = await limiter.cleanup_expired()
        assert removed == 3

    async def test_async_concurrency(self):
        """Test that the limiter is concurrency-safe under asyncio."""
        limiter = SlidingWindowRateLimiter(max_requests=100, window_seconds=60)
        results = []

        async def worker():
            for _ in range(10):
                allowed, _ = await limiter.check_and_consume(["shared"])
                results.append(allowed)

        await asyncio.gather(*[worker() for _ in range(10)])
        assert sum(1 for r in results if r) == 100
        assert sum(1 for r in results if not r) == 0

    async def test_retry_after_calculation(self):
        """Test that retry_after is reasonable."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)
        await limiter.check_and_consume(["test"])
        await asyncio.sleep(0.1)
        await limiter.check_and_consume(["test"])
        allowed, retry = await limiter.check_and_consume(["test"])
        assert allowed is False
        assert 0 < retry <= 2

    def test_validation_max_requests(self):
        """Test that max_requests < 1 raises ValueError."""
        with pytest.raises(ValueError):
            SlidingWindowRateLimiter(max_requests=0)

    def test_validation_window_seconds(self):
        """Test that window_seconds < 1 raises ValueError."""
        with pytest.raises(ValueError):
            SlidingWindowRateLimiter(max_requests=5, window_seconds=0)


class TestSlidingWindowRateLimiterIntegration:
    """Integration tests simulating real-world usage."""

    async def test_admin_token_generation_limit(self):
        """Simulate admin token generation rate limiting."""
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
        # Admin generates 10 tokens
        for i in range(10):
            allowed, _ = await limiter.check_and_consume(["admin:admin1"])
            assert allowed is True, f"Token {i+1} should be allowed"
        # 11th should be blocked
        allowed, retry = await limiter.check_and_consume(["admin:admin1"])
        assert allowed is False
        assert retry > 0
        # Different admin should still work
        allowed, _ = await limiter.check_and_consume(["admin:admin2"])
        assert allowed is True

    async def test_registration_dual_key(self):
        """Simulate executor registration with dual-key limiting."""
        ip_limiter = SlidingWindowRateLimiter(max_requests=20, window_seconds=60)
        exec_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)

        # Simulate 5 registrations from same IP for same executor
        for i in range(5):
            ip_ok, _ = await ip_limiter.check_and_consume(["reg_ip:10.0.0.1"])
            exec_ok, _ = await exec_limiter.check_and_consume(["reg_exec:executor1"])
            assert ip_ok is True
            assert exec_ok is True, f"Registration {i+1} should pass"

        # 6th registration for same executor should fail
        ip_ok, _ = await ip_limiter.check_and_consume(["reg_ip:10.0.0.1"])
        exec_ok, _ = await exec_limiter.check_and_consume(["reg_exec:executor1"])
        assert ip_ok is True
        assert exec_ok is False

        # Registration for different executor from same IP should work
        exec_ok, _ = await exec_limiter.check_and_consume(["reg_exec:executor2"])
        assert exec_ok is True

    async def test_first_registration_stricter_limit(self):
        """First registration uses stricter limit."""
        first_limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        SlidingWindowRateLimiter(max_requests=20, window_seconds=60)

        # First registration: stricter limit of 3
        for i in range(3):
            allowed, _ = await first_limiter.check_and_consume(["reg_ip:10.0.0.1"])
            assert allowed is True
        allowed, _ = await first_limiter.check_and_consume(["reg_ip:10.0.0.1"])
        assert allowed is False


class TestRateLimitRegistrationDep:
    """M-61 regression: the registration dependency must enforce the per-executor
    limit on ITS OWN limiter, not the per-IP limiter's cap.

    Before the fix both the reg_ip: and reg_exec: keys were checked against the
    IP limiter, so an executor rotating IPs was never throttled per-executor
    (the registration_attempts_per_minute cap only fed the response headers).
    """

    @pytest.fixture()
    def fresh_limiters(self):
        from server import rate_limit as _rl

        saved = dict(_rl._LIMITERS)
        _rl._LIMITERS.clear()
        yield
        _rl._LIMITERS.clear()
        _rl._LIMITERS.update(saved)

    @staticmethod
    def _config(**overrides) -> SimpleNamespace:
        base = {
            "enabled": True,
            "registration_ip_per_minute": 1000,  # generous: per-IP must not bind
            "registration_attempts_per_minute": 2,  # tight: per-executor must bind
            "token_generation_per_minute": 10,
        }
        base.update(overrides)
        return SimpleNamespace(executor_enrollment=SimpleNamespace(**base))

    @staticmethod
    def _request(executor_id, config, host="10.0.0.1"):
        req = SimpleNamespace()
        # backend=None makes the is_first DB probe raise and fall through
        # (is_first stays False) without needing a real DB app.state.
        req.app = SimpleNamespace(state=SimpleNamespace(config=config, backend=None))
        req.client = SimpleNamespace(host=host)
        req.state = SimpleNamespace()

        async def _json():
            return {"executor_id": executor_id} if executor_id is not None else {}

        req.json = _json
        return req

    async def test_per_executor_cap_is_enforced(self, fresh_limiters):
        cfg = self._config()
        # Two registrations (== the exec cap) pass; the third trips it -> 429.
        await rate_limit_registration(self._request("execA", cfg))
        await rate_limit_registration(self._request("execA", cfg))
        with pytest.raises(HTTPException) as exc:
            await rate_limit_registration(self._request("execA", cfg))
        assert exc.value.status_code == 429

    async def test_per_executor_is_scoped_not_per_ip(self, fresh_limiters):
        cfg = self._config()
        await rate_limit_registration(self._request("execA", cfg))
        await rate_limit_registration(self._request("execA", cfg))
        with pytest.raises(HTTPException):
            await rate_limit_registration(self._request("execA", cfg))
        # Same IP, fresh executor_id: NOT blocked by execA's exhausted cap.
        # (If the throttle were per-IP, this would also 429.)
        await rate_limit_registration(self._request("execB", cfg))
