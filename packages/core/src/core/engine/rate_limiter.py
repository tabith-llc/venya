# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Per-account failure tracking and rate limiting.

Tracks failed attempts and enforces the lockout window. The counters are
per-process memory — see the ``RateLimiter`` SCOPE note below; nothing here is
written to the database, so a restart clears them.

#549: every stamp in here (``FailureRecord.window_start``, ``locked_at``) and
every ``now`` that ages them comes from ``time.monotonic()`` — elapsed REAL
time, the clock #464 ruled for per-process state. A wall-clock step (NTP
correction, snapshot restore) must not move the failure/lockout windows: a
forward step used to read as "window expired" and reset a live counter (and
delete a live lockout in ``check``/``cleanup_expired``), and a backward step
held records past their true length. One clock per structure — the record is
the structure, and the four methods that read it (``record_failure``,
``check``, ``get_remaining_attempts``, ``cleanup_expired``) all age it against
the same monotonic ``now``; a mixed pair (wall ``now`` against monotonic
stamps) would differ by the whole epoch and make ``cleanup_expired`` sweep
every live record. Figures reported OUT of this class (``retry_after_seconds``)
are durations — clock-independent.
"""

import threading
import time
from dataclasses import dataclass, field


@dataclass
class FailureRecord:
    """Records a failed attempt for rate limiting."""

    user_id: str
    failed_attempts: int = 0
    # #549: monotonic stamp (per-process state; see the module docstring).
    # NOTE for tests: ``default_factory`` binds the REAL ``time.monotonic`` at
    # class-creation time, so a fake patched onto the module's ``time`` name
    # does not reach it — ``record_failure`` stamps ``window_start=now``
    # explicitly for records it creates.
    window_start: float = field(default_factory=time.monotonic)
    locked_at: float = 0.0


class RateLimitExceededError(Exception):
    """Rate limit exceeded — account locked.

    Carries ``retry_after_seconds`` — seconds until unlock (ticket #421) —
    so the server can emit an HTTP Retry-After header without re-deriving
    the limiter's state.
    """

    def __init__(self, message: str, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class RateLimiter:
    """In-memory rate limiter with per-account failure tracking.

    Default: 5 failed attempts within 300 seconds (5 minutes),
    then locked out for 15 minutes (lockout_reinstate_minutes).

    Threading (ticket rate-limiter-unsynchronized-state #516): every read and
    write of ``_failures`` happens under ``self._lock``, so concurrent
    ``record_failure`` calls cannot lose an increment and a traversal cannot
    trip over a concurrent insert.

    SCOPE — this state is PER-PROCESS MEMORY and is NOT SHARED between
    processes. The counter lives in one RateLimiter instance, and one instance
    is built per core process (``Backend.get_core()`` /
    ``CoreFactory.build()``). A deployment running N core processes behind a
    load balancer therefore enforces ``max_attempts`` PER PROCESS: a caller who
    spreads failed attempts across the N workers gets up to N x max_attempts
    before any one worker arms the lockout, and a restart clears the state
    entirely. A lock bounds the lost-update class inside a worker; it does not
    and cannot bound that N x gap. Closing it needs the counters moved to
    shared storage (the ``rate_limit_failures`` fixed-window table plus the
    atomic UPSERT that ``server/middleware/rate_limit.py`` already uses is the
    shape). That gap is recorded here on purpose rather than left implied.

    Attributes:
        max_attempts: Maximum failed attempts before lockout.
        window_seconds: Time window in seconds for counting failures.
        lockout_reinstate_minutes: Minutes before a locked-out user can try again.
        _failures: In-memory dict of user_id -> FailureRecord.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_reinstate_minutes: int = 15,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_reinstate_minutes = lockout_reinstate_minutes
        self._failures: dict[str, FailureRecord] = {}
        # One lock guards the whole dict (#516). Reentrant so a guarded method
        # may call another guarded method without self-deadlocking.
        self._lock = threading.RLock()

    def record_failure(self, user_id: str) -> None:
        """Record a failed attempt for a user.

        Args:
            user_id: The user ID that failed.

        Raises:
            RateLimitExceededError: If the user has exceeded the rate limit.
        """
        now = time.monotonic()  # #549: see the module docstring
        with self._lock:
            record = self._failures.get(user_id)

            if record is None:
                record = FailureRecord(user_id=user_id, window_start=now)
                self._failures[user_id] = record

            # Reset window if expired
            if now - record.window_start > self.window_seconds:
                record.failed_attempts = 0
                record.window_start = now

            record.failed_attempts += 1
            armed = record.failed_attempts >= self.max_attempts
            if armed:
                record.locked_at = now

        if armed:
            raise RateLimitExceededError(
                f"User {user_id} has exceeded {self.max_attempts} failed attempts "
                f"within {self.window_seconds} seconds. Locked out for {self.lockout_reinstate_minutes} minutes.",
                retry_after_seconds=self.lockout_reinstate_minutes * 60,
            )

    def check(self, user_id: str) -> None:
        """Check if a user is currently rate-limited.

        If the user is locked out and the lockout period has elapsed,
        reset their failure count and allow retries.

        Args:
            user_id: The user ID to check.

        Raises:
            RateLimitExceededError: If the user is rate-limited.
        """
        with self._lock:
            record = self._failures.get(user_id)
            if record is None:
                return

            now = time.monotonic()  # #549: see the module docstring

            # If window has expired, clear the record entirely
            if now - record.window_start > self.window_seconds:
                del self._failures[user_id]
                return

            # If locked out, check if lockout period has elapsed
            if record.failed_attempts >= self.max_attempts and record.locked_at > 0:
                lockout_seconds = self.lockout_reinstate_minutes * 60
                # #464: the lockout age is clamped at zero. A BACKWARD clock step
                # (NTP correction, snapshot restore) makes ``now - locked_at``
                # negative, which read as "the window has been over for 400
                # seconds", and the figure we hand back inflates by the whole
                # skew (measured: a 60 s window reported 460 s). Clamping keeps
                # Retry-After inside the configured window and never releases
                # early — a negative age must not be treated as elapsed time.
                # What the clamp does NOT do is shorten the wall-clock wait: the
                # record still releases when the wall clock returns to
                # ``locked_at + lockout_seconds``, i.e. after lockout + skew. That
                # remainder is availability-only (fail-closed) and is stated in
                # the #464 report rather than papered over.
                # #549 update: the stamps and this ``now`` are monotonic now, so
                # a wall-clock step does not move this window at all — the
                # fail-closed remainder above no longer arises from wall skew;
                # the clamp stays as the guard for any negative age.
                lockout_elapsed = max(0.0, now - record.locked_at)
                if lockout_elapsed >= lockout_seconds:
                    # Lockout period elapsed — reset and allow retries
                    record.failed_attempts = 0
                    record.locked_at = 0.0
                    record.window_start = now
                    return
                else:
                    # Still locked out
                    remaining = int(lockout_seconds - lockout_elapsed)
                    raise RateLimitExceededError(
                        f"User {user_id} is locked out. Unlock in {remaining} seconds.",
                        retry_after_seconds=remaining,
                    )

            if record.failed_attempts >= self.max_attempts:
                raise RateLimitExceededError(
                    f"User {user_id} has exceeded {self.max_attempts} failed attempts "
                    f"within {self.window_seconds} seconds.",
                    retry_after_seconds=self.lockout_reinstate_minutes * 60,
                )

    def record_success(self, user_id: str) -> None:
        """Record a successful attempt, clearing the failure count.

        Args:
            user_id: The user ID that succeeded.
        """
        with self._lock:
            self._failures.pop(user_id, None)

    def get_remaining_attempts(self, user_id: str) -> int:
        """Get the number of remaining attempts for a user.

        Args:
            user_id: The user ID to check.

        Returns:
            Number of remaining attempts before lockout.
        """
        with self._lock:
            record = self._failures.get(user_id)
            if record is None:
                return self.max_attempts

            now = time.monotonic()  # #549: see the module docstring
            if now - record.window_start > self.window_seconds:
                return self.max_attempts

            # If locked out and lockout period has elapsed, reset
            if record.failed_attempts >= self.max_attempts and record.locked_at > 0:
                lockout_seconds = self.lockout_reinstate_minutes * 60
                # #464: same clamp as check() — a negative age is not elapsed time.
                if max(0.0, now - record.locked_at) >= lockout_seconds:
                    record.failed_attempts = 0
                    record.locked_at = 0.0
                    record.window_start = now
                    return self.max_attempts

            return max(0, self.max_attempts - record.failed_attempts)

    def reset(self, user_id: str) -> None:
        """Reset the failure count for a user.

        Args:
            user_id: The user ID to reset.
        """
        with self._lock:
            self._failures.pop(user_id, None)

    def cleanup_expired(self) -> int:
        """Remove expired failure records.

        Returns:
            Number of records removed.
        """
        # #549: same monotonic clock as the stamps this sweep ages — a wall
        # ``now`` against monotonic stamps differs by the whole epoch and would
        # read every record as expired.
        now = time.monotonic()
        with self._lock:
            expired = []
            for uid, record in self._failures.items():
                # Window expired
                if now - record.window_start > self.window_seconds or (
                    record.failed_attempts >= self.max_attempts
                    and record.locked_at > 0
                    # #464: clamp, so a backward step cannot read as "elapsed" here either.
                    and max(0.0, now - record.locked_at) >= self.lockout_reinstate_minutes * 60
                ):
                    expired.append(uid)
            for uid in expired:
                del self._failures[uid]
            return len(expired)
