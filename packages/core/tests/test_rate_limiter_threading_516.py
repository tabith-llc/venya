# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#516 — the account lockout limiter is synchronized state.

Every cell here drives REAL threads and is DETERMINISTIC, in both directions.
The harness idea is a rendezvous inside the record the limiter reads: an
instrumented attribute whose getter blocks until the peer thread signals that
it has done the conflicting mutation (or until a short bound expires).

* Unlocked (HEAD before this leg's fix): the two threads are guaranteed to
  overlap, so the defect reproduces on every run — no sleep-based gambling.
* Locked (after the fix): the peer cannot act while the first operation holds
  the lock, its rendezvous expires at ``RENDEZVOUS_TIMEOUT``, and the same cell
  passes on every run. The bound caps the fixed case's runtime, not its
  correctness.

Deployment shape (measured for this ticket's "answer before coding" ask; full
evidence in the leg report): the limiter is ONE instance per core process —
``Backend.get_core()`` constructs ``Core(rate_limiter=RateLimiter())`` once per
boot — and every production call site sits in an ``async def`` handler, i.e. on
one event-loop thread, with ``uvicorn.run`` called with no ``workers=`` and a
single systemd unit. So inside one worker the unlocked read-modify-write is
LATENT today, and the LIVE half of the defect is the deployment: the counter is
per-process memory and is never shared, so an attacker who spreads attempts
across the three core VMs gets 3x the budget no matter what any lock does.

Both halves are treated honestly here. The lock is what a public core class
owes every caller — ``CoreFactory.with_rate_limiter`` and ``Backend.get_core``
hand the object out to embedding code, and one sync-def handler or threadpool
hop makes the lost-increment class live with no deploy change. The N* gap is
NOT closed by a lock and is not claimed to be: it is documented on the class,
pinned by the last cell in this file.
"""

import threading
import time

import pytest
from core.engine.rate_limiter import RateLimiter, RateLimitExceededError

#: Bound for the rendezvous waits. Long enough that two unlocked threads always
#: find each other (their handshakes land microseconds apart), short enough that
#: a serialized cell costs a fraction of a second.
RENDEZVOUS_TIMEOUT = 0.5


class _RendezvousRecord:
    """FailureRecord stand-in whose ``failed_attempts`` READ is a rendezvous.

    Exactly the first ``readers`` reads park together and are released as a
    group, so all of them observe the same pre-write value. Later reads (the
    limiter re-reads the counter for its threshold test) return immediately.
    """

    def __init__(self, user_id: str, readers: int) -> None:
        self.user_id = user_id
        self.window_start = time.time()  # never expires inside the test window
        self.locked_at = 0.0
        self._readers = readers
        self._seen = 0
        self._release = threading.Event()
        self._guard = threading.Lock()
        self._n = 0

    @property
    def failed_attempts(self) -> int:
        # Snapshot BEFORE arriving at the rendezvous: every racing reader thus
        # captures a value taken before any of them is released to write, which
        # is what makes the lost increment deterministic rather than a coin
        # flip. Reads past the expected pair return the live value.
        snapshot = self._n
        with self._guard:
            self._seen += 1
            count = self._seen
            trip = count == self._readers
        if count <= self._readers:
            if trip:
                self._release.set()
            else:
                self._release.wait(RENDEZVOUS_TIMEOUT)
            return snapshot
        return self._n

    @failed_attempts.setter
    def failed_attempts(self, value: int) -> None:
        self._n = value


class _MidReadRecord:
    """FailureRecord stand-in whose ``window_start`` READ is a handoff.

    The getter signals the peer that the limiter is parked between its read and
    its mutation, then waits for the peer to finish that mutation (or for the
    bound to expire). A fixed ``window_start`` of ``0.0`` makes every limiter
    expiry branch take the conflicting write path.
    """

    def __init__(self, user_id: str, signal: threading.Event, resume: threading.Event) -> None:
        self.user_id = user_id
        self.failed_attempts = 0
        self.locked_at = 0.0

        self._signal = signal
        self._resume = resume

    @property
    def window_start(self) -> float:
        self._signal.set()
        self._resume.wait(RENDEZVOUS_TIMEOUT)
        return 0.0

    @window_start.setter
    def window_start(self, value: float) -> None:
        pass  # a reset writes through; the hook owns the read


def test_concurrent_record_failure_loses_no_attempts():
    """AC-1. RED at HEAD: three record_failure() calls for one user with
    max_attempts=3, the first two concurrent, must count three attempts and arm
    the lockout on the third.

    Unlocked, the two racing readers snapshot the same pre-write value and one
    increment is destroyed: the counter ends short and the threshold is never
    reached — a user who genuinely failed enough times is never locked out.
    """
    limiter = RateLimiter(max_attempts=3, window_seconds=300, lockout_reinstate_minutes=15)
    record = _RendezvousRecord("alice", readers=2)
    limiter._failures["alice"] = record

    premature: list[RateLimitExceededError] = []
    armed_lock = threading.Lock()

    def _one_failure() -> None:
        try:
            limiter.record_failure("alice")
        except RateLimitExceededError as exc:
            with armed_lock:
                premature.append(exc)

    start = threading.Barrier(2)

    def _thread() -> None:
        start.wait(RENDEZVOUS_TIMEOUT)
        _one_failure()

    threads = [threading.Thread(target=_thread) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3 * RENDEZVOUS_TIMEOUT + 5)
        assert not thread.is_alive(), "rendezvous never resolved — harness bug"

    assert not premature, f"two attempts must not arm a 3-attempt lockout: {premature[0]!r}"

    # The third, un-contended attempt is the one that must arm the lockout.
    with pytest.raises(RateLimitExceededError) as arm:
        limiter.record_failure("alice")

    assert record._n == 3, f"lost increment: counter is {record._n}, expected 3"
    # AC-5: Retry-After semantics ride along with the raise.
    assert arm.value.retry_after_seconds == 15 * 60


def test_check_survives_a_concurrent_success_clearing_the_same_key():
    """AC-2. RED at HEAD: check() reads a record, then takes its expiry branch
    and DELETES the key. A record_success() that pops the same key in between
    makes check() delete a key that is already gone — KeyError out of the
    limiter, on the request path that is supposed to answer "locked out?".

    Locked, check() and record_success() cannot interleave: either check()
    deletes first and the pop is a no-op, or the pop lands first and check()
    returns on its own ``record is None`` guard.
    """
    limiter = RateLimiter(max_attempts=5, window_seconds=300)
    errors: list[BaseException] = []
    signal = threading.Event()
    resume = threading.Event()
    limiter._failures["bob"] = _MidReadRecord("bob", signal, resume)

    def _check_thread() -> None:
        try:
            limiter.check("bob")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=_check_thread)
    thread.start()
    assert signal.wait(RENDEZVOUS_TIMEOUT), "check() never reached its read"
    limiter.record_success("bob")  # pops the key while check() is parked
    resume.set()
    thread.join(2 * RENDEZVOUS_TIMEOUT + 5)
    assert not thread.is_alive(), "check() never finished — harness bug"

    assert not errors, f"check() escaped with {errors[0]!r}"
    assert "bob" not in limiter._failures


def test_cleanup_expired_survives_a_concurrent_insert():
    """AC-2 second half. RED at HEAD: cleanup_expired() traverses
    ``self._failures`` while a record_failure() for a NEW user inserts into it —
    "dictionary changed size during iteration", raised out of a maintenance
    sweep.

    Locked, the insert waits for the sweep, and both operations complete.
    """
    limiter = RateLimiter(max_attempts=5, window_seconds=300)
    signal = threading.Event()
    resume = threading.Event()
    limiter._failures["carol"] = _MidReadRecord("carol", signal, resume)
    limiter._failures["dave"] = _MidReadRecord("dave", signal, resume)

    errors: list[BaseException] = []

    def _sweep() -> None:
        try:
            limiter.cleanup_expired()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=_sweep)
    thread.start()
    assert signal.wait(RENDEZVOUS_TIMEOUT), "cleanup_expired() never traversed"
    limiter.record_failure("erin")  # inserts mid-traversal
    resume.set()
    thread.join(3 * RENDEZVOUS_TIMEOUT + 5)
    assert not thread.is_alive(), "sweep never finished — harness bug"

    assert not errors, f"cleanup_expired() escaped with {errors[0]!r}"
    assert "erin" in limiter._failures, "the concurrent insert must still land"


def test_paired_positives_survive_the_lock():
    """AC-4: the lock changes nothing a legitimate caller relies on.

    * a successful authentication still clears the failure state;
    * window expiry still resets the counter;
    * the ``lockout_reinstate_minutes`` path still lets a locked-out user retry.
    """
    limiter = RateLimiter(max_attempts=3, window_seconds=300, lockout_reinstate_minutes=15)
    for _ in range(2):
        limiter.record_failure("frank")
    assert limiter.get_remaining_attempts("frank") == 1
    limiter.record_success("frank")
    assert limiter._failures == {}, "a successful auth must clear the failure state"

    limiter.record_failure("frank")
    limiter._failures["frank"].window_start -= 10_000  # window long expired
    limiter.record_failure("frank")
    assert limiter.get_remaining_attempts("frank") == 2, "an expired window must reset, not add"

    for _ in range(2):
        limiter.record_failure("gina")
    with pytest.raises(RateLimitExceededError):
        limiter.record_failure("gina")
    limiter._failures["gina"].locked_at -= 15 * 60 + 5  # reinstate period elapsed
    limiter.check("gina")  # must NOT raise
    assert limiter.get_remaining_attempts("gina") == 3


def test_class_documents_the_per_process_scope():
    """AC-3: the cross-worker N* gap is stated on the class, not silently left.

    A per-process lock is only honest if the class says the counter is
    per-process memory. This cell fails if that statement is dropped or softened
    into a claim of shared enforcement.
    """
    doc = (RateLimiter.__doc__ or "").lower()
    assert "per-process" in doc, "the class must state that lockout is per-process"
    assert "not shared" in doc, "the class must state that the counter is not shared"
