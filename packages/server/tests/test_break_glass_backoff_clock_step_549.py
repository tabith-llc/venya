# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#549 site 1 — the break-glass backoff ages on a monotonic clock.

``server/middleware/rate_limit.py`` stamped break-glass failures with
``time.time()`` and derived both the 1-hour history prune and the remaining
backoff from that wall clock. A FORWARD clock step therefore aged the recorded
failures out inside their true window — the block evaporated and the whole
history was discarded, silently shortening a security window (the half that
matters). The opposite direction was its own availability hit: a BACKWARD step
made the age of the last failure negative, and ``backoff - elapsed`` inflated
the returned Retry-After far beyond the 16 s cap (measured at the parent: a
3600 s step back reported 3601).

The state is per-process memory (``self._break_glass_failures``), so per the
#464 ruling the clock is switched to ``time.monotonic()`` at BOTH the stamp and
the read — one clock per structure, never a mix. The return contract (int
seconds, 0 = pass, feeding the 429 ``Retry-After``) is unchanged; a duration is
clock-independent.

Clock control mirrors the #464 files: the module's own ``time`` name is replaced
by a two-dial fake, so one cell can move the wall clock while real time stands
still (and vice versa). The paired negatives move both dials together — an
ordinary running clock must behave exactly as before, which is also what the
untouched 429 ``Retry-After`` cells in ``test_rate_limit_middleware.py`` pin
from the integration side.
"""

from server.middleware import rate_limit as rl_mod
from server.middleware.rate_limit import RateLimitMiddleware

HOUR = 3600.0
BACKOFF_CAP = 16


class _FakeClock:
    """Stand-in for the ``time`` module inside ``middleware.rate_limit`` only."""

    def __init__(self, mono: float = 10_000.0, wall: float = 10_000.0) -> None:
        self.mono = mono
        self.wall = wall

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall


async def _dummy_app(scope, receive, send) -> None:  # pragma: no cover - never called
    pass


def _mw() -> RateLimitMiddleware:
    return RateLimitMiddleware(app=_dummy_app)


IP = "203.0.113.7"


class TestBreakGlassBackoffIgnoresWallSteps:
    def test_backward_step_does_not_extend_the_block_past_the_cap(self, monkeypatch):
        """Backward half: one failure arms a 1 s backoff; the wall clock then
        steps an hour BEHIND the stamp while real time has moved half a second.
        The returned figure must stay a real backoff value — inside [1, cap] —
        and the caller must still be blocked (fail-closed, but bounded).
        Pre-fix the subtraction went negative and the reply was 3601."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        mw = _mw()
        mw._record_break_glass_failure(IP)

        clock.mono += 0.5  # half a second of REAL time; still inside the 1 s backoff
        clock.wall -= HOUR  # the step: stamps read an hour in the future

        remaining = mw._check_break_glass_backoff(IP)
        assert remaining > 0, "the caller must stay blocked inside the true backoff"
        assert remaining <= BACKOFF_CAP, (
            f"a wall step extended the block past the {BACKOFF_CAP} s cap: {remaining}"
        )

    def test_forward_step_does_not_forget_failures_inside_their_true_window(
        self, monkeypatch
    ):
        """Forward half — the security side. Five failures arm the capped 16 s
        backoff; one second of real time passes; the wall clock then jumps an
        hour ahead. The recorded failures must NOT be forgotten (and the 1-hour
        history prune must NOT fire on the fake step): the block still holds,
        with about 15 s of the TRUE window remaining. Pre-fix the prune dropped
        the whole history and the call returned 0 — the failure was silently
        evaporated."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        mw = _mw()
        for _ in range(5):
            mw._record_break_glass_failure(IP)

        clock.mono += 1.0  # one real second inside the 16 s backoff
        clock.wall += HOUR + 1.0  # forward jump past the prune horizon

        remaining = mw._check_break_glass_backoff(IP)
        assert remaining > 0, "forward wall step silently dropped the recorded failures"
        assert remaining <= BACKOFF_CAP, f"figure left the configured cap: {remaining}"
        assert remaining == 15, (
            f"history not retained or prune fired on the fake step: expected 15, got {remaining}"
        )

    def test_real_hour_still_prunes_the_history(self, monkeypatch):
        """Paired negative: an hour of REAL time (both dials together) prunes
        the history exactly as before — the window is monotonic, not frozen."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        mw = _mw()
        for _ in range(5):
            mw._record_break_glass_failure(IP)

        clock.mono += HOUR + 1.0
        clock.wall += HOUR + 1.0
        assert mw._check_break_glass_backoff(IP) == 0, "real expiry must clear the block"

    def test_no_failures_returns_zero(self):
        """Paired negative: the untrodden path is unchanged — no recorded
        failure means no block (truthiness contract: 0 = pass)."""
        assert _mw()._check_break_glass_backoff(IP) == 0

    def test_no_step_control_block_holds_then_releases(self, monkeypatch):
        """No-step control: with one clock running normally the backoff arms
        and releases on schedule — the fix is load-bearing only under a step."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        mw = _mw()
        mw._record_break_glass_failure(IP)

        assert mw._check_break_glass_backoff(IP) == 1, "1 s backoff must hold at t=0"

        clock.mono += 2.0
        clock.wall += 2.0
        assert mw._check_break_glass_backoff(IP) == 0, "2 s of real time clears a 1 s backoff"
