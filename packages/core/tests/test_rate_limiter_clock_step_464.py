# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#464 site 3 — the account lockout ages are clamped, never read backwards.

``core/engine/rate_limiter.py`` compares ``now - record.locked_at`` against the
configured lockout window and derives ``Retry-After`` from the same subtraction.
A BACKWARD clock step (NTP correction, snapshot restore) makes that difference
negative, so the limiter believed the window had been over for the whole skew
before it had begun: the figure we hand back inflated accordingly — measured at
the tip, a 60 s window reported ``Unlock in 460 seconds.`` after a 400 s step.

The ruled mechanism here is the CLAMP (``max(0.0, …)``), not a clock switch:
the lockout state is per-process memory, but the guard asks about a wall-stamped
record and the fix stays minimal. What the clamp guarantees: ``Retry-After`` and
``remaining`` never exceed the configured window, and a negative age is never
counted as elapsed time (no early release). What it deliberately does NOT
guarantee — stated rather than hidden — is that the record releases before the
wall clock returns to ``locked_at + window``; that remainder is fail-closed
(availability only), and closing it needs a high-water-mark anchor, which #464
did not rule.

Clock control: the module's own ``time`` name is replaced with a single-dial
fake, so only ``core.engine.rate_limiter`` sees the moved clock — the stdlib
module is untouched and no other code in the process is affected. Patched symbol
per cell: ``time.time`` (the clock the clamped site uses).

Paired negatives are the ordinary paths: a forward-running clock still releases
exactly at the window, and the shrink-to-zero countdown is unchanged. The
existing #385 wiring cells (``test_ratelimiter_wire.py``) pass unedited beside
these — including the Retry-After bounds cells, which are the pre-fix behaviour
pinned from the other side.
"""

import pytest
from core.engine import rate_limiter as rl_mod
from core.engine.rate_limiter import RateLimiter, RateLimitExceededError

MAX_ATTEMPTS = 3
WINDOW_SECONDS = 300
LOCKOUT_MINUTES = 1
LOCKOUT_SECONDS = LOCKOUT_MINUTES * 60


class _FakeTime:
    """Stand-in for the ``time`` module inside ``core/engine/rate_limiter.py``."""

    def __init__(self, wall: float = 10_000.0) -> None:
        self.wall = wall

    def time(self) -> float:
        return self.wall


def _locked_out(clock: _FakeTime) -> RateLimiter:
    """Arm the lockout at the fake clock's current reading."""
    limiter = RateLimiter(
        max_attempts=MAX_ATTEMPTS,
        window_seconds=WINDOW_SECONDS,
        lockout_reinstate_minutes=LOCKOUT_MINUTES,
    )
    for _ in range(MAX_ATTEMPTS - 1):
        limiter.record_failure("u1")
    with pytest.raises(RateLimitExceededError) as arm:
        limiter.record_failure("u1")
    assert arm.value.retry_after_seconds == LOCKOUT_SECONDS, "arming must report the full window"
    # ``FailureRecord.window_start`` uses ``field(default_factory=time.time)``, which
    # is bound to the REAL clock at class-creation time and so ignores the fake.
    # Normalise it onto the fake clock: these cells are about the lockout age, and
    # a mixed-clock record would make the window-expiry branch do bookkeeping we
    # are not testing.
    limiter._failures["u1"].window_start = clock.wall
    return limiter


class TestLockoutAgeClamped:
    def test_backward_step_does_not_inflate_retry_after(self, monkeypatch):
        """AC2 backward half: a 400 s backward step must not report a Retry-After
        beyond the configured 60 s window (pre-fix it reported 460 s)."""
        clock = _FakeTime()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _locked_out(clock)

        clock.wall -= 400.0  # the step: now sits 400 s BEFORE locked_at
        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")

        assert (
            blocked.value.retry_after_seconds == LOCKOUT_SECONDS
        ), f"Retry-After escaped the configured window: {blocked.value.retry_after_seconds}"
        assert f"{LOCKOUT_SECONDS} seconds" in str(blocked.value), str(blocked.value)

    def test_backward_step_does_not_release_early(self, monkeypatch):
        """AC2 backward half, other side: the clamp must not turn the skewed age
        into elapsed time — the user stays locked, not freed."""
        clock = _FakeTime()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _locked_out(clock)

        clock.wall -= 400.0
        with pytest.raises(RateLimitExceededError):
            limiter.check("u1")
        assert limiter._failures["u1"].locked_at > 0, "lockout must not clear on a negative age"
        assert limiter.get_remaining_attempts("u1") == 0

    def test_forward_running_clock_still_releases_at_the_window(self, monkeypatch):
        """Paired negative: normal behaviour is unchanged — still locked just
        inside the window, released once the window has really elapsed."""
        clock = _FakeTime()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _locked_out(clock)

        clock.wall += LOCKOUT_SECONDS - 1  # one second short: still locked
        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")
        assert blocked.value.retry_after_seconds == 1

        clock.wall += 1.0  # the window has elapsed
        limiter.check("u1")  # must not raise
        assert limiter.get_remaining_attempts("u1") == MAX_ATTEMPTS

    def test_forward_jump_after_a_step_never_goes_negative(self, monkeypatch):
        """A step back and then a jump forward across the window: the reported
        figure stays inside [1, window] on the locked side and the record
        releases normally once the wall clock passes locked_at + window."""
        clock = _FakeTime()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _locked_out(clock)
        locked_at = limiter._failures["u1"].locked_at

        clock.wall -= 400.0
        with pytest.raises(RateLimitExceededError) as first:
            limiter.check("u1")
        clock.wall += 300.0
        with pytest.raises(RateLimitExceededError) as second:
            limiter.check("u1")

        for fig in (first.value.retry_after_seconds, second.value.retry_after_seconds):
            assert 0 < fig <= LOCKOUT_SECONDS, f"reported figure outside the window: {fig}"

        clock.wall = locked_at + LOCKOUT_SECONDS  # exactly the window, real or skewed
        limiter.check("u1")  # releases; must not raise
