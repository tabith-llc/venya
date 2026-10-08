# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#464 site 4 — the sliding-window limiter runs on a monotonic clock.

The limiter stamped requests with ``time.time()`` and pruned with
``cutoff = now - window_seconds``. A FORWARD clock jump therefore pushed the
cutoff past every stored stamp and silently reset the counter to zero — the
deployment then allowed more traffic than the operator configured. The opposite
direction was just as wrong: after a BACKWARD step the stamps sit in the
"future", their age is negative, and they never prune, so a key stays blocked
until the wall clock crawls back.

Both are elapsed-real-time questions and the store is per-process memory, so the
timestamps now come from ``time.monotonic()`` (see the module docstring for the
cross-process check that made this safe).

Clock control: the module's own ``time`` name is replaced by a two-dial fake, so
one cell can move the wall clock while real time stands still. Existing cells in
``test_rate_limiter.py`` are untouched and pass unedited — including the
sleep-based window-expiry one, which a monotonic clock satisfies.
"""

import asyncio

from server.utils import rate_limiter as rl_mod
from server.utils.rate_limiter import SlidingWindowRateLimiter


class _FakeClock:
    """Stand-in for the ``time`` module inside ``utils.rate_limiter`` only."""

    def __init__(self, mono: float = 1_000.0, wall: float = 10_000.0) -> None:
        self.mono = mono
        self.wall = wall

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall


def _fill(limiter: SlidingWindowRateLimiter, key: str = "k") -> None:
    for _ in range(limiter.max_requests):
        allowed, _ = asyncio.run(limiter.is_allowed(key))
        assert allowed, "filling the window should stay allowed"


class TestSlidingWindowIgnoresWallSteps:
    def test_forward_jump_does_not_reset_the_counter(self, monkeypatch):
        """AC2 forward half — the symptom the ticket filed for this site.

        Five of five consumed, then the wall clock jumps 500 s ahead while no
        real time passes. The window has NOT elapsed, so the counter must stay
        full and the next request must still be refused.
        """
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        _fill(limiter)

        clock.wall += 500.0  # forward jump; monotonic does not move

        assert asyncio.run(limiter.get_remaining("k")) == 0, "counter silently reset"
        allowed, retry_after = asyncio.run(limiter.is_allowed("k"))
        assert allowed is False
        # The class rounds its figure up by one second (int(...) + 1), so the
        # ceiling for a window just filled is window+1 — the same bound
        # test_rate_limiter.py pins for get_reset_time.
        assert 1 <= retry_after <= 61, f"retry_after left the configured window: {retry_after}"

    def test_backward_step_does_not_keep_entries_forever(self, monkeypatch):
        """AC2 backward half.

        Five of five consumed; the wall clock then steps 3000 s BEHIND the
        stamps (they read as future). Once 61 s of real time has passed the
        window must expire normally and free the slot — under the wall clock the
        negative age meant "never prune, never release".
        """
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        _fill(limiter)

        clock.wall -= 3000.0
        assert asyncio.run(limiter.get_remaining("k")) == 0  # still full: correct
        assert asyncio.run(limiter.is_allowed("k"))[0] is False

        clock.mono += 61.0  # real time passes; the wall clock stays behind
        assert asyncio.run(limiter.get_remaining("k")) == 5, "window never released after the step"
        assert asyncio.run(limiter.is_allowed("k"))[0] is True

    def test_real_elapsed_time_still_prunes(self, monkeypatch):
        """Paired negative: with both clocks moving together, ordinary window
        expiry is unchanged — prune, release, and consume again."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)

        assert asyncio.run(limiter.is_allowed("k"))[0] is True
        assert asyncio.run(limiter.is_allowed("k"))[0] is True
        assert asyncio.run(limiter.is_allowed("k"))[0] is False

        clock.mono += 59.0
        clock.wall += 59.0
        assert asyncio.run(limiter.is_allowed("k"))[0] is False, "59 s is inside a 60 s window"

        clock.mono += 2.0
        clock.wall += 2.0
        assert asyncio.run(limiter.is_allowed("k"))[0] is True, "61 s of elapsed time must free a slot"

    def test_cleanup_and_reset_time_use_the_same_clock(self, monkeypatch):
        """Every read in the class is monotonic: the stamps it wrote, the cutoff
        it prunes with, and the reset figure it reports all come from one clock
        (a mixed pair would re-open the same defect on the header values)."""
        clock = _FakeClock()
        monkeypatch.setattr(rl_mod, "time", clock)
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        _fill(limiter, key="a")
        _fill(limiter, key="b")

        clock.wall += 500.0  # wall jumps; real time stands still
        reset = asyncio.run(limiter.get_reset_time("a"))
        assert 1 <= reset <= 61, f"reset figure left the configured window: {reset}"
        assert asyncio.run(limiter.cleanup_expired()) == 0, "forward jump discarded live entries"

        clock.mono += 61.0
        assert asyncio.run(limiter.cleanup_expired()) == 6, "real expiry did not clean up"
