"""Tests for the sliding window rate limiter utility."""

import time
import threading

import pytest

from server.utils.rate_limiter import SlidingWindowRateLimiter


class TestSlidingWindowRateLimiter:
    """Tests for SlidingWindowRateLimiter."""

    def test_allows_within_limit(self):
        """Should allow requests within the limit."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        for i in range(5):
            allowed, retry = limiter.check_and_consume(["test"])
            assert allowed is True
            assert retry == 0

    def test_rejects_over_limit(self):
        """Should reject requests exceeding the limit."""
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        for i in range(3):
            allowed, _ = limiter.check_and_consume(["test"])
            assert allowed is True
        allowed, retry = limiter.check_and_consume(["test"])
        assert allowed is False
        assert retry > 0

    def test_single_key(self):
        """Test single key check_and_consume."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        allowed, _ = limiter.check_and_consume(["key1"])
        assert allowed is True
        allowed, _ = limiter.check_and_consume(["key1"])
        assert allowed is True
        allowed, _ = limiter.check_and_consume(["key1"])
        assert allowed is False

    def test_independent_keys(self):
        """Test that different keys are tracked independently."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        limiter.check_and_consume(["key1"])
        limiter.check_and_consume(["key1"])
        allowed, _ = limiter.check_and_consume(["key1"])
        assert allowed is False
        allowed, _ = limiter.check_and_consume(["key2"])
        assert allowed is True

    def test_atomic_multi_key_all_pass(self):
        """Test atomic check-and-consume: all keys pass."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        allowed, _ = limiter.check_and_consume(["ip:1.2.3.4", "exec:foo"])
        assert allowed is True

    def test_atomic_multi_key_one_fails(self):
        """Test atomic check-and-consume: one key fails, neither consumed."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        limiter.check_and_consume(["ip:1.2.3.4"])
        limiter.check_and_consume(["ip:1.2.3.4"])
        # ip:1.2.3.4 is now at limit
        # exec:bar is fresh
        allowed, retry = limiter.check_and_consume(["ip:1.2.3.4", "exec:bar"])
        assert allowed is False
        assert retry > 0
        # exec:bar should NOT have been consumed (atomic)
        allowed, _ = limiter.check_and_consume(["exec:bar"])
        assert allowed is True

    def test_sliding_window_expiration(self):
        """Test that old requests expire after window."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=0.1)
        limiter.check_and_consume(["test"])
        limiter.check_and_consume(["test"])
        allowed, _ = limiter.check_and_consume(["test"])
        assert allowed is False
        time.sleep(0.15)
        allowed, _ = limiter.check_and_consume(["test"])
        assert allowed is True

    def test_get_remaining(self):
        """Test get_remaining returns correct count."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        assert limiter.get_remaining("test") == 5
        limiter.check_and_consume(["test"])
        assert limiter.get_remaining("test") == 4
        limiter.check_and_consume(["test"])
        limiter.check_and_consume(["test"])
        assert limiter.get_remaining("test") == 2

    def test_get_reset_time(self):
        """Test get_reset_time returns seconds until oldest expires."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        assert limiter.get_reset_time("test") == 0
        limiter.check_and_consume(["test"])
        reset = limiter.get_reset_time("test")
        assert 0 < reset <= 61

    def test_is_allowed(self):
        """Test convenience is_allowed method."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        allowed, _ = limiter.is_allowed("test")
        assert allowed is True
        allowed, _ = limiter.is_allowed("test")
        assert allowed is True
        allowed, _ = limiter.is_allowed("test")
        assert allowed is False

    def test_cleanup_expired(self):
        """Test cleanup removes expired entries."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=0.1)
        limiter.check_and_consume(["key1"])
        limiter.check_and_consume(["key2"])
        limiter.check_and_consume(["key3"])
        time.sleep(0.15)
        removed = limiter.cleanup_expired()
        assert removed == 3

    def test_thread_safety(self):
        """Test that the limiter is thread-safe."""
        limiter = SlidingWindowRateLimiter(max_requests=100, window_seconds=60)
        results = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            for _ in range(10):
                allowed, _ = limiter.check_and_consume(["shared"])
                results.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r) == 100
        assert sum(1 for r in results if not r) == 0

    def test_retry_after_calculation(self):
        """Test that retry_after is reasonable."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)
        limiter.check_and_consume(["test"])
        time.sleep(0.1)
        limiter.check_and_consume(["test"])
        allowed, retry = limiter.check_and_consume(["test"])
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

    def test_admin_token_generation_limit(self):
        """Simulate admin token generation rate limiting."""
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
        # Admin generates 10 tokens
        for i in range(10):
            allowed, _ = limiter.check_and_consume([f"admin:admin1"])
            assert allowed is True, f"Token {i+1} should be allowed"
        # 11th should be blocked
        allowed, retry = limiter.check_and_consume([f"admin:admin1"])
        assert allowed is False
        assert retry > 0
        # Different admin should still work
        allowed, _ = limiter.check_and_consume([f"admin:admin2"])
        assert allowed is True

    def test_registration_dual_key(self):
        """Simulate executor registration with dual-key limiting."""
        ip_limiter = SlidingWindowRateLimiter(max_requests=20, window_seconds=60)
        exec_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)

        # Simulate 5 registrations from same IP for same executor
        for i in range(5):
            ip_ok, _ = ip_limiter.check_and_consume([f"reg_ip:10.0.0.1"])
            exec_ok, _ = exec_limiter.check_and_consume([f"reg_exec:executor1"])
            assert ip_ok is True
            assert exec_ok is True, f"Registration {i+1} should pass"

        # 6th registration for same executor should fail
        ip_ok, _ = ip_limiter.check_and_consume([f"reg_ip:10.0.0.1"])
        exec_ok, _ = exec_limiter.check_and_consume([f"reg_exec:executor1"])
        assert ip_ok is True
        assert exec_ok is False

        # Registration for different executor from same IP should work
        exec_ok, _ = exec_limiter.check_and_consume([f"reg_exec:executor2"])
        assert exec_ok is True

    def test_first_registration_stricter_limit(self):
        """First registration uses stricter limit."""
        first_limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        normal_limiter = SlidingWindowRateLimiter(max_requests=20, window_seconds=60)

        # First registration: stricter limit of 3
        for i in range(3):
            allowed, _ = first_limiter.check_and_consume([f"reg_ip:10.0.0.1"])
            assert allowed is True
        allowed, _ = first_limiter.check_and_consume([f"reg_ip:10.0.0.1"])
        assert allowed is False
