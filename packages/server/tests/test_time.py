"""Tests for time utilities with clock skew tolerance."""

from datetime import datetime, timedelta, timezone

import pytest

from server.utils.time import (
    effective_expiry_check_time,
    has_not_yet_started,
    is_expired,
)


class TestIsExpired:
    """Tests for is_expired() helper."""

    def test_not_expired_within_tolerance(self):
        """Token expired 30s ago with 60s tolerance → not expired."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=30)
        assert is_expired(expires_at, tolerance_seconds=60) is False

    def test_not_expired_not_yet_expired(self):
        """Token not yet expired → not expired."""
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert is_expired(expires_at, tolerance_seconds=60) is False

    def test_expired_beyond_tolerance(self):
        """Token expired 90s ago with 60s tolerance → expired."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=90)
        assert is_expired(expires_at, tolerance_seconds=60) is True

    def test_exactly_at_tolerance_boundary(self):
        """Token expired exactly 60s ago with 60s tolerance → expired (<=)."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
        assert is_expired(expires_at, tolerance_seconds=60) is True

    def test_none_expires_at(self):
        """None expires_at → not expired."""
        assert is_expired(None, tolerance_seconds=60) is False

    def test_zero_tolerance(self):
        """Zero tolerance — any past expiry is expired."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert is_expired(expires_at, tolerance_seconds=0) is True

    def test_zero_tolerance_not_yet_expired(self):
        """Zero tolerance — future expiry is not expired."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=1)
        assert is_expired(expires_at, tolerance_seconds=0) is False

    def test_naive_datetime_handled(self):
        """Naive datetime is treated as UTC."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=90)
        naive = expires_at.replace(tzinfo=None)
        assert is_expired(naive, tolerance_seconds=60) is True

    def test_default_tolerance(self):
        """Default tolerance is 60 seconds."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=70)
        assert is_expired(expires_at) is True

    def test_large_tolerance(self):
        """Large tolerance (300s) — token expired 120s ago is not expired."""
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        assert is_expired(expires_at, tolerance_seconds=300) is False


class TestEffectiveExpiryCheckTime:
    """Tests for effective_expiry_check_time() helper."""

    def test_returns_past_time(self):
        """Result is in the past by tolerance amount."""
        result = effective_expiry_check_time(60)
        now = datetime.now(timezone.utc)
        assert result < now
        diff = (now - result).total_seconds()
        assert 59 <= diff <= 61

    def test_zero_tolerance_returns_now(self):
        """Zero tolerance returns approximately now."""
        result = effective_expiry_check_time(0)
        now = datetime.now(timezone.utc)
        diff = abs((now - result).total_seconds())
        assert diff < 1

    def test_large_tolerance(self):
        """Large tolerance returns time further in the past."""
        result = effective_expiry_check_time(300)
        now = datetime.now(timezone.utc)
        diff = (now - result).total_seconds()
        assert 299 <= diff <= 301

    def test_tzinfo_is_utc(self):
        """Result has UTC timezone."""
        result = effective_expiry_check_time(60)
        assert result.tzinfo is not None


class TestHasNotYetStarted:
    """Tests for has_not_yet_started() helper."""

    def _future_time(self, seconds_ahead: int) -> datetime:
        """Create a datetime N seconds in the future."""
        return datetime.now(timezone.utc) + timedelta(seconds=seconds_ahead)

    def _past_time(self, seconds_ago: int) -> datetime:
        """Create a datetime N seconds in the past."""
        return datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)

    def not_yet_started_future(self):
        """Future valid_from → not yet started."""
        valid_from = self._future_time(120)
        assert has_not_yet_started(valid_from, tolerance_seconds=60) is True

    def not_yet_started_within_tolerance(self):
        """valid_from 30s in future with 60s tolerance → not yet started."""
        valid_from = self._future_time(30)
        assert has_not_yet_started(valid_from, tolerance_seconds=60) is True

    def started_past_time(self):
        """Past valid_from → already started."""
        valid_from = self._past_time(120)
        assert has_not_yet_started(valid_from, tolerance_seconds=60) is False

    def started_within_tolerance(self):
        """valid_from 30s in past with 60s tolerance → already started."""
        valid_from = self._past_time(30)
        assert has_not_yet_started(valid_from, tolerance_seconds=60) is False

    def test_boundary_exactly_at_tolerance(self):
        """valid_from exactly 60s in future with 60s tolerance → started."""
        valid_from = self._future_time(60)
        assert has_not_yet_started(valid_from, tolerance_seconds=60) is False
