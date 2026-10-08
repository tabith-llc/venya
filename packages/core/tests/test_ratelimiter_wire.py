# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Rate-limiter wiring tests (ticket ratelimiter-lockout-inert, refs #385).

Truth table for record_failure() wired into the secret-retrieval failure
paths of Core.get() and Core.get_for_injection(): failures count, the Nth
trips the lockout, a successful retrieval clears the counter, and the
user_id=None guard stays uncounted.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.engine.backend import Backend
from core.engine.core import Core, CoreAccessError
from core.engine.encryption import DecryptionError, encrypt_secret
from core.engine.rate_limiter import RateLimiter, RateLimitExceededError
from core.engine.secure_memory import KekCache

KEK = b"\x11" * 32
MAX_ATTEMPTS = 5


def _secret(value: bytes = b"hunter2", corrupt: bool = False) -> SimpleNamespace:
    """Build a Secret-shaped row whose decrypt_secret() succeeds (or fails)."""
    wrapped_dek, nonce, ciphertext = encrypt_secret(KEK, value)
    if corrupt:
        ciphertext = bytes(b ^ 0xFF for b in ciphertext)
    return SimpleNamespace(
        id=7,
        wrapped_dek=wrapped_dek,
        nonce=nonce,
        encrypted_value=ciphertext,
        meta={},
    )


def _core(resolve_result: object) -> Core:
    core = Core(backend=MagicMock(spec=Backend), kek=KekCache.from_bytes(KEK, mlock=False))
    core._resolve_secret_in = MagicMock(return_value=resolve_result)  # type: ignore[method-assign]
    return core


def _fail_gets(core: Core, count: int, user_id: str = "u1") -> None:
    for _ in range(count):
        with pytest.raises(CoreAccessError):
            core.get("missing", user_id=user_id)


class TestRateLimiterWire:
    def setup_method(self) -> None:
        self.core = _core(None)  # every lookup resolves to not-found

    def test_failures_count_and_nth_trips_lockout(self) -> None:
        """POSITIVE: N-1 failures pass through, the Nth raises RateLimitExceededError."""
        _fail_gets(self.core, MAX_ATTEMPTS - 1)
        assert self.core.rate_limiter.get_remaining_attempts("u1") == 1
        with pytest.raises(RateLimitExceededError):
            self.core.get("missing", user_id="u1")

    def test_lockout_blocks_even_a_successful_lookup(self) -> None:
        """POSITIVE (armed by failures): check() blocks the next get even if the
        secret now resolves — the lockout is real."""
        _fail_gets(self.core, MAX_ATTEMPTS - 1)
        with pytest.raises(RateLimitExceededError):
            self.core.get("missing", user_id="u1")  # arms at the Nth

        armed = _core(_secret())  # same limiter config, secret now visible
        armed.rate_limiter = self.core.rate_limiter
        with pytest.raises(RateLimitExceededError):
            armed.get("present", user_id="u1")

    def test_decrypt_failure_counts(self) -> None:
        """Failure site named in the ticket: decrypt failure increments too."""
        core = _core(_secret(corrupt=True))
        for _ in range(MAX_ATTEMPTS - 1):
            with pytest.raises(DecryptionError):
                core.get("bad", user_id="u1", caller="executor")
        assert core.rate_limiter.get_remaining_attempts("u1") == 1
        with pytest.raises(RateLimitExceededError):
            core.get("bad", user_id="u1", caller="executor")

    def test_success_clears_the_failure_counter(self) -> None:
        """NEGATIVE pair (truth table): a successful retrieval AFTER failures
        resets the counter — N more failures are needed again."""
        _fail_gets(self.core, MAX_ATTEMPTS - 2)
        assert self.core.rate_limiter.get_remaining_attempts("u1") == 2

        good = _core(_secret())
        good.rate_limiter = self.core.rate_limiter
        assert good.get("present", user_id="u1", caller="executor") == "hunter2"
        assert good.rate_limiter.get_remaining_attempts("u1") == MAX_ATTEMPTS

        # Back to the not-found core (shared limiter): a full MAX_ATTEMPTS-1
        # more failures still must NOT trip — only the Nth after the clears:
        _fail_gets(self.core, MAX_ATTEMPTS - 1)
        with pytest.raises(RateLimitExceededError):
            self.core.get("missing", user_id="u1")

    def test_missing_secret_lookup_for_unknown_user_increments(self) -> None:
        """NEGATIVE pair: a lookup that does not resolve (e.g. unknown user)
        increments that user's counter."""
        _fail_gets(self.core, 1, user_id="ghost")
        assert self.core.rate_limiter.get_remaining_attempts("ghost") == MAX_ATTEMPTS - 1

    def test_none_user_guard_does_not_count(self) -> None:
        """NEGATIVE pair: the user_id=None guard raises BEFORE check() and
        records nothing — it is not a user failure."""
        with pytest.raises(CoreAccessError):
            self.core.get("missing", user_id=None)
        assert self.core.rate_limiter._failures == {}


class TestRateLimiterWireInjectionTwin:
    """get_for_injection() is the same not-found/decrypt failure surface
    (§4 twin), wired the same way."""

    def test_injection_not_found_trips_lockout(self) -> None:
        core = _core(None)
        for _ in range(MAX_ATTEMPTS - 1):
            with pytest.raises(CoreAccessError):
                core.get_for_injection("missing", user_id="u1")
        with pytest.raises(RateLimitExceededError):
            core.get_for_injection("missing", user_id="u1")

    def test_injection_decrypt_failure_counts(self) -> None:
        core = _core(_secret(corrupt=True))
        for _ in range(MAX_ATTEMPTS - 1):
            with pytest.raises(DecryptionError):
                core.get_for_injection("bad", user_id="u1")
        assert core.rate_limiter.get_remaining_attempts("u1") == 1

    def test_injection_success_clears(self) -> None:
        failing = _core(None)
        _fail_gets(failing, MAX_ATTEMPTS - 2)
        assert failing.rate_limiter.get_remaining_attempts("u1") == 2

        good = _core(_secret())
        good.rate_limiter = failing.rate_limiter
        secret_id, plaintext, _meta = good.get_for_injection("present", user_id="u1")
        assert (secret_id, plaintext) == (7, "hunter2")
        assert good.rate_limiter.get_remaining_attempts("u1") == MAX_ATTEMPTS

    def test_injection_none_user_guard_does_not_count(self) -> None:
        core = _core(None)
        with pytest.raises(CoreAccessError):
            core.get_for_injection("missing", user_id=None)
        assert core.rate_limiter._failures == {}

    def test_limiter_defaults_unchanged(self) -> None:
        """The wiring ships on the ruled 5/300s/15min defaults."""
        limiter = RateLimiter()
        assert (limiter.max_attempts, limiter.window_seconds) == (5, 300)


class TestLockoutGateAndNeutrality:
    """#421: entrance-B check() gate, counter-neutral masked reads, Retry-After."""

    def test_injection_gated_by_check_before_resolve(self) -> None:
        """B: locked-out user's get_for_injection raises via check() BEFORE
        resolve. RED-before: it resolved."""
        core = _core(None)
        _fail_gets(core, MAX_ATTEMPTS - 1)
        with pytest.raises(RateLimitExceededError):
            core.get("missing", user_id="u1")  # arms at the Nth
        core._resolve_secret_in.reset_mock()
        with pytest.raises(RateLimitExceededError):
            core.get_for_injection("present", user_id="u1")
        assert not core._resolve_secret_in.called

    def test_fresh_user_injection_not_gated(self) -> None:
        """B paired negative: a fresh user's injection retrieval proceeds."""
        good = _core(_secret())
        secret_id, plaintext, _meta = good.get_for_injection("present", user_id="fresh")
        assert (secret_id, plaintext) == (7, "hunter2")

    def test_masked_read_is_counter_neutral(self) -> None:
        """C: 4 strikes, then a masked read — counter UNCHANGED at 4.
        RED-before: the masked read cleared it to 5. (The positive half —
        a real successful retrieval still clears — is pinned by
        test_success_clears_the_failure_counter above.)"""
        core = _core(None)
        _fail_gets(core, MAX_ATTEMPTS - 1)
        assert core.rate_limiter.get_remaining_attempts("u1") == 1
        core._resolve_secret_in.return_value = _secret()  # now visible
        assert core.get("present", user_id="u1") == "\u2022" * 8
        assert core.rate_limiter.get_remaining_attempts("u1") == 1

    def test_retry_after_full_window_at_arming(self) -> None:
        """A: the arming raise carries the FULL lockout window."""
        limiter = RateLimiter()
        for _ in range(MAX_ATTEMPTS - 1):
            limiter.record_failure("u1")
        with pytest.raises(RateLimitExceededError) as arm:
            limiter.record_failure("u1")
        assert arm.value.retry_after_seconds == 15 * 60

    def test_retry_after_shrinks_monotonically_while_locked(self) -> None:
        """A: check()-time Retry-After = locked_at + window - now — bounded by
        the window and shrinking as time passes (no fake-clock idiom in this
        file — grepped first — so wall-clock bounds + rewind, per spec §4)."""
        limiter = RateLimiter()
        for _ in range(MAX_ATTEMPTS - 1):
            limiter.record_failure("u1")
        with pytest.raises(RateLimitExceededError):
            limiter.record_failure("u1")
        with pytest.raises(RateLimitExceededError) as blocked:
            limiter.check("u1")
        first = blocked.value.retry_after_seconds
        assert 0 < first <= 15 * 60
        limiter._failures["u1"].locked_at -= 120
        with pytest.raises(RateLimitExceededError) as later:
            limiter.check("u1")
        assert later.value.retry_after_seconds < first
        assert later.value.retry_after_seconds >= 15 * 60 - 120 - 1
