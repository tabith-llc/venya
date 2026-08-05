"""Per-account failure tracking and rate limiting.

Tracks failed attempts, enforces lockout, and persists failures
to the DB for restart recovery.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class FailureRecord:
    """Records a failed attempt for rate limiting."""

    user_id: str
    failed_attempts: int = 0
    window_start: float = field(default_factory=time.time)


class RateLimitExceededError(Exception):
    """Rate limit exceeded — account locked."""


class RateLimiter:
    """In-memory rate limiter with per-account failure tracking.

    Default: 5 failed attempts within 300 seconds (5 minutes).

    Attributes:
        max_attempts: Maximum failed attempts before lockout.
        window_seconds: Time window in seconds for counting failures.
        _failures: In-memory dict of user_id -> FailureRecord.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: float = 300.0,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, FailureRecord] = {}

    def record_failure(self, user_id: str) -> None:
        """Record a failed attempt for a user.

        Args:
            user_id: The user ID that failed.

        Raises:
            RateLimitExceededError: If the user has exceeded the rate limit.
        """
        now = time.time()
        record = self._failures.get(user_id)

        if record is None:
            record = FailureRecord(user_id=user_id)
            self._failures[user_id] = record

        # Reset window if expired
        if now - record.window_start > self.window_seconds:
            record.failed_attempts = 0
            record.window_start = now

        record.failed_attempts += 1

        if record.failed_attempts >= self.max_attempts:
            raise RateLimitExceededError(
                f"User {user_id} has exceeded {self.max_attempts} failed attempts "
                f"within {self.window_seconds:.0f} seconds"
            )

    def check(self, user_id: str) -> None:
        """Check if a user is currently rate-limited.

        Args:
            user_id: The user ID to check.

        Raises:
            RateLimitExceededError: If the user is rate-limited.
        """
        record = self._failures.get(user_id)
        if record is None:
            return

        now = time.time()
        if now - record.window_start > self.window_seconds:
            # Window expired, reset
            del self._failures[user_id]
            return

        if record.failed_attempts >= self.max_attempts:
            raise RateLimitExceededError(
                f"User {user_id} is locked out: {record.failed_attempts} failed attempts "
                f"within {self.window_seconds:.0f} seconds"
            )

    def record_success(self, user_id: str) -> None:
        """Record a successful attempt, clearing the failure count.

        Args:
            user_id: The user ID that succeeded.
        """
        self._failures.pop(user_id, None)

    def get_remaining_attempts(self, user_id: str) -> int:
        """Get the number of remaining attempts for a user.

        Args:
            user_id: The user ID to check.

        Returns:
            Number of remaining attempts before lockout.
        """
        record = self._failures.get(user_id)
        if record is None:
            return self.max_attempts

        now = time.time()
        if now - record.window_start > self.window_seconds:
            return self.max_attempts

        return max(0, self.max_attempts - record.failed_attempts)

    def reset(self, user_id: str) -> None:
        """Reset the failure count for a user.

        Args:
            user_id: The user ID to reset.
        """
        self._failures.pop(user_id, None)

    def cleanup_expired(self) -> int:
        """Remove expired failure records.

        Returns:
            Number of records removed.
        """
        now = time.time()
        expired = [
            uid
            for uid, record in self._failures.items()
            if now - record.window_start > self.window_seconds
        ]
        for uid in expired:
            del self._failures[uid]
        return len(expired)
