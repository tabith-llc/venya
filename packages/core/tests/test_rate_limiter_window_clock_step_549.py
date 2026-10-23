# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#549 site 3 — the failure window ages on a monotonic clock.

``core/engine/rate_limiter.py`` stamped ``FailureRecord.window_start`` (and
``locked_at``) with ``time.time()`` and compared them against the same wall
clock in ``record_failure``, ``check``, ``get_remaining_attempts`` and
``cleanup_expired``. A wall-clock step therefore MOVED the window: measured at
the parent, a forward step of an hour past a two-strike counter read as an
expired window — the counter reset early and a fresh strike no longer armed the
lockout — and the same step made a live lockout release instantly (the record
was even deleted by ``check``). ``cleanup_expired`` swept live records away on
the fake step too. The backward direction held records past their true length
(the #464 clamp keeps the reported figure honest, but the release waits for the
wall clock to crawl back). The record is per-process memory and every age it
answers about is elapsed real time, so per the #464 ruling the clock is
monotonic here: stamps and reads move to ``time.monotonic()`` together.

Structures normalized to ONE clock (never a mix): ``FailureRecord.window_start``,
``FailureRecord.locked_at``, and the ``now`` every method compares them
against — including ``cleanup_expired``, which reads the same two fields:
leaving it on the wall clock would compare wall-now against monotonic stamps
and sweep every live record on any epoch-sized gap. The #464 clamp
(``max(0.0, now - locked_at)``) stays in place untouched — under a monotonic
source a wall step no longer moves the window at all, and the clamp remains as
the guard for any negative age. Durations reported out of this class
(``retry_after_seconds``, ``int``) are clock-independent and unchanged.

Clock control mirrors ``test_rate_limiter_clock_step_464.py``, with a second
dial: the module's own ``time`` name is replaced by a fake exposing BOTH
``time()`` and ``monotonic()``. The fake starts with the dials EQUAL so the
cells read the same numbers on either code shape, and each helper normalizes
``window_start`` onto the fake (the same stand-in quirk the 464 file documents:
``field(default_factory=...)`` binds the real clock at class-creation time, so
a fresh record under the PARENT code would otherwise carry a real epoch stamp).
Step cells move ONE dial; the paired negatives move BOTH together, which is
what ``test_ratelimiter_wire.py`` and ``test_rate_limiter_threading_516.py``
already pin with real clocks — those files' cells pass with zero assertion
edits.
"""

import pytest
from core.engine import rate_limiter as rl_mod
from core.engine.rate_limiter import RateLimiter, RateLimitExceededError

MAX_ATTEMPTS = 3
WINDOW_SECONDS = 300
LOCKOUT_MINUTES = 1
LOCKOUT_SECONDS = LOCKOUT_MINUTES * 60


class _FakeClock:
    """Two-dial stand-in for the ``time`` module in ``core/engine/rate_limiter.py``."""

    def __init__(self, mono: float = 10_000.0, wall: float = 10_000.0) -> None:
        self.mono = mono
        self.wall = wall

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall


def _limiter() -> RateLimiter:
    return RateLimiter(
        max_attempts=MAX_ATTEMPTS,
        window_seconds=WINDOW_SECONDS,
        lockout_reinstate_minutes=LOCKOUT_MINUTES,
    )


def _strike(limiter: RateLimiter, user_id: str = "u1") -> None:
    """One failed attempt that must NOT arm the lockout."""
    limiter.record_failure(user_id)


def _arm(limiter: RateLimiter, clock: _FakeClock, user_id: str = "u1") -> None:
    """Fill the counter to the lockout threshold on the fake clock.

    The last strike raises; the record is then normalized onto the fake clock
    (equal dials at start, so the normalization is the same number either way).
    Under the parent code this replaces the real-epoch ``window_start`` the
    ``default_factory`` left behind — see the module docstring; under the fix it
    is a no-op because the stamps already come from the fake.
    """
    for _ in range(MAX_ATTEMPTS - 1):
        _strike(limiter, user_id)
    with pytest.raises(RateLimitExceededError) as arm:
        limiter.record_failure(user_id)
    assert arm.value.retry_after_seconds == LOCKOUT_SECONDS, "arming must report the full window"
    limiter._failures[user_id].window_start = clock.wall


class TestFailureWindowIgnoresWallSteps:
    def test_forward_step_does_not_reset_the_window_early(self, monkeypatch):
        """The security half: two strikes inside the window, then the wall
        clock jumps an hour ahead while real time stands still. The window has
        NOT elapsed — the counter must still read one remaining and the next
        strike must still arm the lockout. Pre-fix the step read as expiry: the
        counter reset (remaining went to max_attempts) and the third strike
        passed without raising."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _strike(limiter)
        _strike(limiter)
        limiter._failures["u1"].window_start = clock.wall  # see _arm

        clock.wall += 3600.0  # forward step; monotonic stands still

        assert limiter.get_remaining_attempts("u1") == 1, "window silently reset by a wall step"
        with pytest.raises(RateLimitExceededError):
            limiter.record_failure("u1")

    def test_forward_step_does_not_release_a_lockout_early(self, monkeypatch):
        """Same step against an armed lockout: 700 s of wall jump with no real
        time passing must not free the user — ``check()`` must still raise and
        the figure must stay inside the window. Pre-fix the step aged the
        WINDOW out, so check() deleted the record and returned without raising;
        the lockout released instantly."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _arm(limiter, clock)

        clock.wall += 700.0

        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")
        assert 1 <= blocked.value.retry_after_seconds <= LOCKOUT_SECONDS
        assert limiter.get_remaining_attempts("u1") == 0

    def test_backward_step_does_not_expire_the_lockout_early(self, monkeypatch):
        """Backward half, control side: a 400 s step back keeps the user locked
        (negative age is not elapsed time) and the counter stays at zero
        remaining. Then 61 s of REAL time passes while the wall clock stays
        behind the stamps: the true window has elapsed, so the record must
        release. Pre-fix the release waited on the wall clock crawling 400 s
        back — here the step itself no longer moves the window."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _arm(limiter, clock)

        clock.wall -= 400.0
        with pytest.raises(RateLimitExceededError):
            limiter.check("u1")
        assert limiter.get_remaining_attempts("u1") == 0, "lockout released on a negative age"

        clock.mono += 61.0  # real time past the 60 s lockout; wall still behind
        limiter.check("u1")  # must NOT raise — the true window elapsed
        assert limiter.get_remaining_attempts("u1") == MAX_ATTEMPTS

    def test_cleanup_expired_uses_the_same_clock(self, monkeypatch):
        """``cleanup_expired`` reads the same stamps: a forward wall step must
        not sweep live records (pre-fix it deleted the whole dict — the mixed
        pair would re-open the defect through the maintenance path), and after
        the REAL window it still cleans up."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _strike(limiter)
        limiter._failures["u1"].window_start = clock.wall

        clock.wall += 3600.0
        assert limiter.cleanup_expired() == 0, "forward jump swept a live record"
        assert "u1" in limiter._failures

        clock.mono += WINDOW_SECONDS + 1.0  # the window has really elapsed
        assert limiter.cleanup_expired() == 1, "real expiry did not clean up"

    def test_paired_negative_running_clock_releases_at_the_true_window(self, monkeypatch):
        """Paired negative: with BOTH dials running together the ordinary
        failure -> lockout -> expiry sequence is unchanged — still locked one
        second short, released exactly at the window."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _arm(limiter, clock)

        clock.mono += LOCKOUT_SECONDS - 1
        clock.wall += LOCKOUT_SECONDS - 1
        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")
        assert blocked.value.retry_after_seconds == 1

        clock.mono += 1.0
        clock.wall += 1.0
        limiter.check("u1")  # releases; must not raise
        assert limiter.get_remaining_attempts("u1") == MAX_ATTEMPTS

    def test_no_step_control_arms_and_holds(self, monkeypatch):
        """No-step control: with one clock and no step, arming and the locked
        read behave as pinned everywhere else — proves the step cells, not the
        harness, carry the fix."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = _limiter()
        _arm(limiter, clock)

        assert limiter.get_remaining_attempts("u1") == 0
        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")
        assert blocked.value.retry_after_seconds == LOCKOUT_SECONDS
