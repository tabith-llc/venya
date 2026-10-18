# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#603 AC5 clause 3 — the truth table as EXECUTING cells, with paired negatives.

The ruling is ``wave30-specs-20261017/wren-603-threshold-ruling-s132.md`` (lead, s132). Its clause 1
re-affirms the counter and the stop; its clause 2 narrows the *class*: a threshold stop is an
``OPERATIONAL FAULT — no revocation answer received``, never a server-side revocation assertion; its
clause 3 says the proof owes **cells, not comments**, and that **"no silent fourth row" is the
load-bearing phrase**. This file is that proof. It changes no behavior — every assertion is against
the shipped shape at the tip it was written on.

Why these cells are not already covered by ``test_relay_revocation_gate_586.py``: that file reaches
the threshold by feeding the loop ANSWERED ``RevocationStatus.UNREACHABLE`` values (the ``:2125``
arm). The ruling's row 3 is about a **no-answer load**, and the load class that #603 is actually
about — the daemon's own two-worker pool starving — reaches the counter through a DIFFERENT arm,
``except TimeoutError`` at ``daemon.py:2135-2137``, where the check never runs at all. Cell (a) below
drives THAT arm by occupying both workers with blocked tasks, and proves the count came from the
timeout by asserting the check was never called.

Mechanism fact, measured at this base rather than assumed (the arm only fires if the pool timeout is
the exception the loop catches)::

    py 3.14.8
    concurrent.futures.TimeoutError is builtin TimeoutError: True
    raised: (TimeoutError, OSError, Exception, BaseException)

Cell inventory, each with its negative:

* **(a)** — pure capacity/no-answer load, no revocation anywhere: the ``TimeoutError`` arm counts, the
  loop stops on the threshold, the accept point serves ``REFUSE_NO_ANSWER``, and the whole journal
  capture carries NO ``REFUSE_REVOKED`` string. Negative: the same harness with a live, answered
  list never stops and never sets a fault reason.
* **(b)** — a genuine server-side revocation still stops exactly as #442/#586 designed, at the same
  accept point, with the 403 class. This is the leg's revert guard.
* **(b2)** — the two arms are DISTINGUISHABLE at one seam seen twice, which is what makes (a)'s
  absence-assertion meaningful instead of vacuous.
* **row 4** — an answered capacity refusal (the 503 class the bounded read mints) counts as a fault
  and is never converted to ``REVOKED``.
* **(d)** — the fourth-row guard: every class the accept point can emit is enumerated and must be one
  of the ruled three, with a ruled status prefix; a new class, or a reworded one that loses its
  class prefix, reddens this cell.

Deliberately NOT asserted here (fences on the leg): no counter/metrics arithmetic (the refusals
counter is another lane's live surface), no floor or ceiling on ``max_revocation_failures`` (that is
#660, staffed in parallel), no last-known-state field, and no rewording of the shipped strings.
"""

import logging
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest

# Shape A's own capacity-refusal detail, imported BY REFERENCE from its one owner rather than
# copied, so this file cannot drift into testing a string the server no longer sends (the same
# discipline and the same cross-package test precedent as test_revocation_snapshot_caller_603.py,
# which cites server/routes/executors.py:687 for the identical reason).
from server.routes.executors import _STALE_LIST_DETAIL as CAPACITY_503_DETAIL

from executor.config import CertificateRotationConfig, ExecutorConfig, NetworkConfig
from executor.daemon import CertificateManager, ExecutorDaemon, RevocationStatus
from executor.relay_listener import (
    REFUSE_NO_ANSWER,
    REFUSE_NOT_WIRED,
    REFUSE_PEER_REVOKED,
    REFUSE_REVOKED,
    peer_revocation_refusal,
    revocation_accept_reason,
)

DAEMON_LOGGER = "venya.executor.daemon"
THRESHOLD = 3
TICK_TIMEOUT = 1  # NetworkConfig floor is ge=1; 3 ticks x 1 s keeps the leg at seconds

# The three classes the accept point is allowed to emit, straight off the ruling's table. A fourth
# entry here is a product decision the ruling has not made, which is exactly what cell (d) catches.
# Named by the product's own constant names so a parametrisation can report WHICH class moved.
RULED_CLASSES_BY_NAME = {
    "REFUSE_REVOKED": REFUSE_REVOKED,
    "REFUSE_PEER_REVOKED": REFUSE_PEER_REVOKED,
    "REFUSE_NO_ANSWER": REFUSE_NO_ANSWER,
    "REFUSE_NOT_WIRED": REFUSE_NOT_WIRED,
}
RULED_CLASSES = set(RULED_CLASSES_BY_NAME.values())
RULED_CLASS_PREFIXES = ("403 REVOKED", "503 OPERATIONAL FAULT")
#: #597 added a SECOND revocation-claiming class, about a different subject: REFUSE_REVOKED
#: is "THIS executor's credential is dead" and REFUSE_PEER_REVOKED is "the CORE's relay
#: credential that walked in is dead". Both assert a revocation that really happened; a
#: single-claimer rule would have had to word the peer one as a fault to pass, which is
#: the laundering this file's whole vocabulary exists to prevent. Kept as an explicit set
#: so a THIRD claimer still has to be chosen on purpose rather than absorbed silently.
REVOCATION_CLAIMING_CLASSES = {"REFUSE_REVOKED", "REFUSE_PEER_REVOKED"}


def _config(threshold: int = THRESHOLD) -> ExecutorConfig:
    """A config with the shipped threshold and the shortest legal per-tick wait."""
    return ExecutorConfig(
        server_url="https://core.test",
        executor_id="tt-603",
        network=NetworkConfig(request_timeout_seconds=TICK_TIMEOUT),
        cert_rotation=CertificateRotationConfig(rotate_before_days=1, max_revocation_failures=threshold),
    )


def _daemon(config: ExecutorConfig | None = None) -> ExecutorDaemon:
    daemon = ExecutorDaemon(config or _config())
    daemon.client = MagicMock()
    daemon.state.running = True
    return daemon


def _block_both_workers(executor: object) -> list:
    """Occupy every worker in the daemon's HTTP pool so a NEW submission cannot start.

    This is the load, not a stand-in for it: ``_main_loop`` submits the revocation check to this
    same pool (``daemon.py:2112``) and waits on it with ``request_timeout_seconds`` (``:2119``).
    With all workers held, the submission queues, the wait gives up, and the loop takes its
    ``except TimeoutError`` arm — the path #603 says is indistinguishable, at the client, from the
    core being down. The pool holds 2 workers (``daemon.py:1692``).
    """
    blockers = []
    for _ in range(2):
        blocker = threading.Event()
        blockers.append(blocker)
        executor.submit(blocker.wait)  # type: ignore[attr-defined]
    return blockers


def _run_to_completion(daemon: ExecutorDaemon, check) -> int:
    """Run one ``_main_loop`` with rotation and the heartbeat cadence taken out of the way.

    Returns how many ticks the loop completed. ``_shutdown_event.wait``'s return value is NOT a
    stop condition — the shipped loop reads only ``state.running`` in its ``while`` (``:2066``),
    which is what ``stop()`` clears — so a bounded run has to clear that flag itself. A harness
    that returned ``True`` from ``wait`` and expected the loop to end would spin forever, and that
    is exactly how this leg's first run hung instead of failing.
    """
    ticks = 0
    # Budget is deliberately generous against the threshold (x3): a NEGATIVE cell must not pass by
    # being cut off before the thing it rules out could have happened.
    max_ticks = daemon.config.cert_rotation.max_revocation_failures * 3

    def _wait(_timeout: float) -> bool:
        nonlocal ticks
        ticks += 1
        if ticks >= max_ticks:
            daemon.state.running = False
        return False

    with (
        patch.object(daemon.cert_manager, "needs_rotation", return_value=False),
        patch.object(daemon, "_submit_heartbeat"),
        patch.object(daemon._shutdown_event, "wait", side_effect=_wait),
        patch.object(daemon.cert_manager, "check_revocation", check),
    ):
        daemon._main_loop()
    return ticks


def _journal(caplog) -> str:
    """Every line the DAEMON logged during the cell, as one block of text."""
    return "\n".join(r.getMessage() for r in caplog.records if r.name == DAEMON_LOGGER)


def _revocation_lines(caplog) -> list[str]:
    """Journal lines that assert a revocation, by CLASS STRING, not by substring.

    Written deliberately this way: the shipped threshold warning at ``daemon.py:2149-2155``
    legitimately contains the words "neither confirmed nor revoked", so a substring test on
    "revoked" would be red for a correct build. The ruling's requirement is about the *class*
    the refusal belongs to, so this greps the exact ``REFUSE_REVOKED`` journal string.
    """
    text = _journal(caplog) + "\n" + "\n".join(r.getMessage() for r in caplog.records)
    return [line for line in text.splitlines() if REFUSE_REVOKED in line]


class TestCellA_CapacityLoadStopsAsAFaultNotARevocation:
    """Ruling row 3: no answer, threshold reached → stop loudly, in the FAULT class."""

    def test_the_timeout_arm_counts_and_the_stop_carries_no_revocation_claim(self, caplog):
        """(a) positive — pool saturation drives the threshold; the journal never claims a revocation.

        Falsifiers built in: the check must NEVER RUN (so the count can only have come from the
        ``TimeoutError`` arm, not from an answered ``UNREACHABLE``), the loop must stop on its own
        ``break``, the fault reason must be the shipped 503 string, and no line anywhere in the
        capture may carry the 403 revocation class.
        """
        daemon = _daemon()
        blockers = _block_both_workers(daemon._http_executor)  # type: ignore[attr-defined]
        caplog.set_level(logging.DEBUG, logger=DAEMON_LOGGER)
        # Hold the substitute itself: `patch.object` restores the method when the context ends, so
        # reading `daemon.cert_manager.check_revocation.call_count` AFTER the run reads a plain
        # function and raises AttributeError (this leg's first red, and a real trap).
        check = MagicMock(return_value=RevocationStatus.NOT_REVOKED)

        try:
            _run_to_completion(daemon, check)
            # Read the call count BEFORE releasing the queue: the blocked submissions land in the
            # pool afterwards, and a post-release count would describe the drain, not the leg.
            never_ran = check.call_count == 0
        finally:
            for blocker in blockers:
                blocker.set()

        assert never_ran, "the check ran, so this exercised the answered-UNREACHABLE arm, not the timeout arm"
        assert daemon.state.revoked is False, "a no-answer load is not a server-side revocation"
        assert daemon.state.revocation_fault_reason is REFUSE_NO_ANSWER
        assert daemon.state.revocation_answered is False, "no tick was ever answered"
        assert "reached the fault threshold" in _journal(caplog), "the stop was silent"
        assert _revocation_lines(caplog) == [], _revocation_lines(caplog)
        # The accept point, consulted with the state this load produced.
        assert revocation_accept_reason(daemon.state) is REFUSE_NO_ANSWER

    def test_paired_negative_an_answered_live_list_never_stops_and_never_faults(self):
        """(a) negative — the same harness with ANSWERS must serve, not stop.

        Without this half, a build that stops on every tick (answered or not) would pass the
        positive cell and read as fail-closed-but-correct. The loop here has no threshold to hit,
        so it is run a bounded number of ticks and asserted to still be running.
        """
        daemon = _daemon()
        ticks = _run_to_completion(daemon, MagicMock(return_value=RevocationStatus.NOT_REVOKED))

        assert daemon.state.revoked is False
        assert daemon.state.revocation_fault_reason is None, "an answered boot must not carry a fault reason"
        assert daemon.state.revocation_answered is True
        assert ticks > THRESHOLD, f"the loop ran only {ticks} ticks — answers were never accepted"
        # Admits: the gate sees an answered, live credential.
        assert revocation_accept_reason(daemon.state) is None


class TestCellB_GenuineRevocationStillStops:
    """Ruling row 1 / the leg's revert guard: a real 403 half survives."""

    def test_an_answered_revocation_sets_the_bool_and_serves_the_403_class(self, caplog):
        """(b) positive — the server NAMED this credential: stop, loudly, as REVOKED.

        #603 narrowed the class of a NO-ANSWER stop. If that narrowing ever swallowed the answered
        path, this cell reddens and the row becomes a fail-open instead of a fix.
        """
        daemon = _daemon()
        caplog.set_level(logging.DEBUG, logger=DAEMON_LOGGER)

        _run_to_completion(daemon, MagicMock(return_value=RevocationStatus.REVOKED))

        assert daemon.state.revoked is True
        assert daemon.state.revocation_fault_reason is None, "a revocation answer is not a fault"
        assert revocation_accept_reason(daemon.state) is REFUSE_REVOKED
        assert "revoked" in _journal(caplog).lower()

    def test_paired_negative_an_answered_revocation_is_not_relabelled_as_a_fault(self):
        """(b) negative — the fault arm must not absorb the revoked arm.

        The two arms differ in BOTH fields the gate reads (``revoked`` and
        ``revocation_fault_reason``), which is what lets a reader tell "killed" from "cannot tell".
        Asserting the fields are not interchangeable is the paired half of the positive cell above.
        """
        revoked_state = SimpleNamespace(revoked=True, revocation_answered=True, executor_id="tt-603")
        fault_state = SimpleNamespace(
            revoked=False,
            revocation_answered=True,
            revocation_fault_reason=REFUSE_NO_ANSWER,
            executor_id="tt-603",
        )
        assert revocation_accept_reason(revoked_state) is REFUSE_REVOKED
        assert revocation_accept_reason(fault_state) is REFUSE_NO_ANSWER
        assert revoked_state.revoked is not fault_state.revoked
        assert REFUSE_REVOKED != REFUSE_NO_ANSWER


class TestCellB2_TheTwoArmsRemainDistinguishableAtOneSeam:
    """(b2) — the ruling's own sentence: (a)'s negative half and (b)'s positive half are one seam seen twice.

    Both arms are driven through the SAME loop, the SAME accept function, the SAME state object
    shape, and the two outcomes must still differ. If a future change collapses them, the absence
    assertion in cell (a) stops meaning anything, and this cell is the one that says so.
    """

    def test_load_stop_and_answered_revocation_produce_different_classes_at_the_gate(self, caplog):
        daemon_load = _daemon()
        blockers = _block_both_workers(daemon_load._http_executor)  # type: ignore[attr-defined]
        caplog.set_level(logging.DEBUG, logger=DAEMON_LOGGER)
        try:
            _run_to_completion(daemon_load, MagicMock(return_value=RevocationStatus.NOT_REVOKED))
        finally:
            for blocker in blockers:
                blocker.set()

        daemon_revoked = _daemon()
        _run_to_completion(daemon_revoked, MagicMock(return_value=RevocationStatus.REVOKED))

        load_class = revocation_accept_reason(daemon_load.state)
        revoked_class = revocation_accept_reason(daemon_revoked.state)

        assert load_class is REFUSE_NO_ANSWER
        assert revoked_class is REFUSE_REVOKED
        assert load_class != revoked_class, "the two arms collapsed into one class — cell (a) is now vacuous"
        assert daemon_load.state.revoked is False and daemon_revoked.state.revoked is True

    def test_paired_negative_a_stopped_for_answer_boot_still_admits(self):
        """A boot that was answered and never faulted must admit at the same seam.

        Both refusals above are correct only because an answered-live daemon is NOT refused; without
        this row the gate could refuse everything and every other cell here would still be green.
        """
        answered_live = SimpleNamespace(revoked=False, revocation_answered=True, executor_id="tt-603")
        assert revocation_accept_reason(answered_live) is None


class TestRow4_CapacityRefusalIsNeverARevocation:
    """Ruling row 4: an answered capacity refusal counts as a fault and never converts to REVOKED.

    Clause 3(c) rules the ATTRIBUTION question (a distinct reason label) into ``features/`` and out
    of this leg, so nothing here asserts a new label. What is asserted is the shipped classification:
    a 503 from the bounded read arrives at the client as no-answer, feeds the same counter, and
    leaves the credential un-revoked.
    """

    def test_an_answered_503_capacity_refusal_is_no_answer_not_a_revocation(self):
        manager = CertificateManager(_config())
        manager.client = MagicMock(spec=httpx2.Client)
        manager.serial = "0000000000000001"
        request = httpx2.Request("GET", "https://core.test/api/v1/executors/certs/revocation-list")
        manager.client.get.return_value = httpx2.Response(  # type: ignore[union-attr]
            status_code=503, request=request, json={"detail": CAPACITY_503_DETAIL}
        )

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE

    def test_paired_negative_a_capacity_refusal_never_reaches_the_revoked_bool(self, caplog):
        """The refusal is counted, and the class it produces is the fault class.

        This is the same 503 driven through the loop rather than through the poll alone, so the
        claim "never converted to REVOKED" is proved on the path that can actually convert it.
        """
        daemon = _daemon()
        caplog.set_level(logging.DEBUG, logger=DAEMON_LOGGER)

        _run_to_completion(daemon, MagicMock(return_value=RevocationStatus.UNREACHABLE))
        assert daemon.state.revoked is False
        assert daemon.state.revocation_fault_reason is REFUSE_NO_ANSWER
        assert revocation_accept_reason(daemon.state) is REFUSE_NO_ANSWER
        assert _revocation_lines(caplog) == [], _revocation_lines(caplog)

    def test_the_capacity_detail_this_cell_uses_is_the_owners_live_string(self):
        """A guard on this file's own import: if the server rewords the refusal, this cell says so.

        The refusal body is imported by reference, so a rename lands here as a content change
        against the shipped constant rather than as a quietly stale copied literal.
        """
        assert CAPACITY_503_DETAIL
        assert isinstance(CAPACITY_503_DETAIL, str)
        assert (
            "revoked" not in CAPACITY_503_DETAIL.lower()
        ), "the server's capacity refusal now names a revocation — the class boundary moved upstream"


class TestCellD_FourthRowGuard:
    """(d) — no silent fourth row: enumerate every class the accept point can emit."""

    def _emitted_classes(self) -> set:
        """Drive the gate across the whole state space it reads and collect what it emits.

        #597 widened this to BOTH halves of the accept point: ``revocation_accept_reason``
        (is THIS executor's credential dead / can it even tell) and
        ``peer_revocation_refusal`` (is the CORE that walked in dead). A class emitted only
        by the peer half would otherwise be unreachable to this guard, and the paired
        negative below is precisely what catches a class that stops being reachable.
        """
        emitted: set = set()
        for state in (
            None,
            SimpleNamespace(revoked=False, revocation_answered=False),
            SimpleNamespace(revoked=False, revocation_answered=True),
            SimpleNamespace(revoked=True, revocation_answered=True),
            SimpleNamespace(revoked=True, revocation_answered=False),
            SimpleNamespace(revoked=False, revocation_answered=True, revocation_fault_reason=REFUSE_NO_ANSWER),
            SimpleNamespace(revoked=True, revocation_answered=True, revocation_fault_reason=REFUSE_NO_ANSWER),
        ):
            reason = revocation_accept_reason(state)
            if reason is not None:
                emitted.add(reason)

        # The peer half: a live registry naming one revoked relay serial, driven against
        # a matching and a non-matching presented serial (the negative pair).
        peer_states = (
            SimpleNamespace(revoked_relay_serials=frozenset({"000000000000abcd"})),
            SimpleNamespace(revoked_relay_serials=frozenset()),
            None,
        )
        for state in peer_states:
            # ABCD is what a certificate presents, 000000000000abcd is what the row
            # stores — that pair IS the #481 property at this door. AABBCC is the
            # non-matching negative.
            for presented in ("ABCD", "000000000000abcd", "AABBCC", None):
                reason = peer_revocation_refusal(state, presented)
                if reason is not None:
                    emitted.add(reason)
        return emitted

    def test_every_emitted_class_is_one_of_the_ruled_classes(self):
        emitted = self._emitted_classes()
        assert emitted, "the gate emitted nothing at all — this cell would pass vacuously"
        extra = emitted - RULED_CLASSES
        assert not extra, f"an unruled refusal class appeared at the accept point: {extra}"

    def test_paired_negative_every_ruled_class_is_still_reachable(self):
        """The guard bites in both directions: a ruled class that VANISHES is also a change.

        Without this half, deleting a class (say the not-wired refusal) would shrink the emitted set
        and still clear the subset test above.
        """
        emitted = self._emitted_classes()
        missing = RULED_CLASSES - emitted
        assert not missing, f"a ruled refusal class is no longer reachable at the gate: {missing}"

    @pytest.mark.parametrize(
        "name,text",
        sorted(RULED_CLASSES_BY_NAME.items()),
        ids=sorted(RULED_CLASSES_BY_NAME),
    )
    def test_each_class_carries_a_ruled_status_prefix_and_revocation_is_claimed_by_one(self, name, text):
        """The status vocabulary is the class, per the in-code comment at ``relay_listener.py:296-300``.

        A reworded string that loses its prefix would let a fault read as a revocation (or the
        reverse) while the object identity tests above stayed green, so the prefix is asserted here
        as its own guard.
        """
        assert text.startswith(RULED_CLASS_PREFIXES), f"{name}: {text!r} lost its class prefix"
        claims_revocation = "REVOKED" in text.split("—")[0]
        if name in REVOCATION_CLAIMING_CLASSES:
            assert claims_revocation, f"{name} must still assert a revocation"
        else:
            assert not claims_revocation, f"{name} asserts a revocation it has no answer for"

    def test_the_module_exposes_exactly_the_ruled_refusal_constants(self):
        """A new ``REFUSE_*`` class in the module is a fourth row, even if nothing emits it yet.

        Enumeration is by the module's own namespace, so the cell does not depend on this file's
        import list staying in step with the product.
        """
        import executor.relay_listener as relay_module

        refusal_names = {
            name for name, value in vars(relay_module).items() if name.startswith("REFUSE_") and isinstance(value, str)
        }
        assert refusal_names == {
            "REFUSE_REVOKED",
            "REFUSE_PEER_REVOKED",  # #597: the revoked CORE relay peer at :8443
            "REFUSE_NO_ANSWER",
            "REFUSE_NOT_WIRED",
        }, refusal_names
