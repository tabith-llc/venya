# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Asyncio-safe sliding window rate limiter.

Atomic all-or-nothing multi-key check-and-consume for rate limiting.
Uses asyncio.Lock for compatibility with FastAPI's async context.
"""

import asyncio
import time
from collections import defaultdict


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter with atomic multi-key operations.

    Uses a sliding log algorithm: tracks exact request timestamps per key,
    and only commits timestamps if all requested keys pass their limits.

    Attributes:
        max_requests: Maximum requests allowed per window.
        window_seconds: Window size in seconds.
        _requests: Dict of key -> list of timestamps.
        _lock: Asyncio lock for atomicity.
    """

    def __init__(self, max_requests: int, window_seconds: float = 60) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds < 0.01:
            raise ValueError("window_seconds must be at least 0.01")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check_and_consume(self, keys: list[str]) -> tuple[bool, int]:
        """Atomically check multiple keys and consume slots if all pass.

        All-or-nothing: if any key exceeds its limit, none are consumed.

        Args:
            keys: List of rate limit keys to check (e.g. ["ip:1.2.3.4", "exec:foo"]).

        Returns:
            Tuple of (allowed, retry_after_seconds).
            If allowed is True, retry_after is 0.
            If allowed is False, retry_after is seconds until the oldest
            exceeding key has a slot available.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        async with self._lock:
            # Clean and check all keys
            oldest_exceeding = 0.0
            for key in keys:
                self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]
                if len(self._requests[key]) >= self.max_requests:
                    oldest = min(self._requests[key])
                    oldest_exceeding = max(oldest_exceeding, oldest)

            if oldest_exceeding > 0.0:
                # At least one key exceeded — don't consume any
                retry_after = int(oldest_exceeding + self.window_seconds - now) + 1
                return False, max(1, retry_after)

            # All keys passed — commit all
            for key in keys:
                self._requests[key].append(now)

            return True, 0

    async def is_allowed(self, key: str) -> tuple[bool, int]:
        """Check a single key and consume if allowed.

        Args:
            key: Rate limit key.

        Returns:
            Tuple of (allowed, retry_after_seconds).
        """
        allowed, retry_after = await self.check_and_consume([key])
        return allowed, retry_after

    async def get_remaining(self, key: str) -> int:
        """Get remaining requests for a key without consuming.

        Args:
            key: Rate limit key.

        Returns:
            Number of remaining requests in the current window.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        async with self._lock:
            requests = [ts for ts in self._requests.get(key, []) if ts > cutoff]
            return max(0, self.max_requests - len(requests))

    async def get_reset_time(self, key: str) -> int:
        """Get seconds until the oldest request in the window expires.

        Args:
            key: Rate limit key.

        Returns:
            Seconds until reset (0 if no requests in window).
        """
        now = time.time()
        cutoff = now - self.window_seconds

        async with self._lock:
            requests = [ts for ts in self._requests.get(key, []) if ts > cutoff]
            if not requests:
                return 0
            oldest = min(requests)
            return max(0, int(oldest + self.window_seconds - now) + 1)

    async def cleanup_expired(self) -> int:
        """Remove expired request timestamps.

        Returns:
            Number of entries removed.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        removed = 0

        async with self._lock:
            keys_to_delete = []
            for key in list(self._requests.keys()):
                before = len(self._requests[key])
                self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]
                removed += before - len(self._requests[key])
                if not self._requests[key]:
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self._requests[key]

        return removed
