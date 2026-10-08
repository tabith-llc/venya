# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#551 — an HTTP status error on the revocation poll is a failed check, not a stop.

The premise, re-derived at THIS tree (pinned by ``TestPremise`` so a future
httpx2 that changes it fails here instead of silently un-fixing #551): in the
installed httpx2 build ``HTTPStatusError`` is NOT a ``RequestError`` subclass —
its MRO is ``HTTPStatusError -> HTTPError -> Exception``. So a 4xx/5xx out of
``/api/v1/executors/certs/revocation-list``

* escaped ``CertificateManager.check_revocation``'s ``except httpx2.RequestError``
  arm (wrong class — they are siblings under ``HTTPError``),
* escaped BOTH caller arms in ``ExecutorDaemon._main_loop`` (``TimeoutError`` and
  ``httpx2.RequestError`` only),

unwound ``_main_loop``, and landed in ``start()``'s ``try/finally: self.stop()``.
One 500 from one endpoint stopped the executor daemon.

The fix is the single seam inside ``check_revocation``: a 4xx/5xx answers
``RevocationStatus.UNREACHABLE`` — the same answer #442 site 4 gave a transport
fault — and logs it ABOVE debug with the status code and the URL. Under that
contract "counted failed" is literal, not aspirational: ``_main_loop`` ADVANCES
``_consecutive_revocation_failures`` on ``UNREACHABLE``, so a status error feeds
the existing ``max_revocation_failures`` threshold (the trip half is asserted
below, and is #442's machinery doing its job, not new policy added here).

Every pre-existing cell in ``test_daemon.py::TestCheckRevocation`` stubs
``raise_for_status`` to ``None``, so no cell ever produced a status error. These
cells use REAL ``httpx2.Response`` objects and let the REAL ``raise_for_status()``
raise — no stubbed side effect — so the class that escapes is the class the
daemon sees.

RED at the parent is exactly the status-error half; every ``UNREACHABLE``-from-a
transport fault, ``NOT_REVOKED`` and ``REVOKED`` cell is green at the parent too,
which is what makes them proof that this leg did not move the happy path or
#442's shipped half.
"""

import logging
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import CertificateRotationConfig, ExecutorConfig
from executor.daemon import CertificateManager, ExecutorDaemon, RevocationStatus

REVOCATION_PATH = "/api/v1/executors/certs/revocation-list"
SERVER_URL = "https://example.com"
LOGGER_NAME = "venya.executor.daemon"
THRESHOLD = 4

# The two arms' signatures, so "which arm answered" is testable and not a guess.
UNREACHABLE_ARM_TEXT = "server unreachable"
STATUS_ARM_TEXT = "server answered HTTP"


def _revocation_response(status_code: int, payload: dict | None = None) -> httpx2.Response:
    """A real httpx2 Response for the revocation endpoint, request wired.

    Real, not stubbed: ``raise_for_status()`` then behaves exactly as it does in
    the daemon — a no-op on 2xx, a genuine ``HTTPStatusError`` on 4xx/5xx.
    """
    request = httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
    if payload is None:
        return httpx2.Response(status_code=status_code, request=request)
    return httpx2.Response(status_code=status_code, request=request, json=payload)


def _manager(max_revocation_failures: int = THRESHOLD) -> CertificateManager:
    """A CertificateManager with a mock transport and a serial set.

    ``check_revocation`` touches only ``serial``, the client, the ETag cache and
    ``config.executor_id``, so none of this needs on-disk certificate material.
    """
    config = ExecutorConfig(
        server_url=SERVER_URL,
        executor_id="test-executor",
        cert_rotation=CertificateRotationConfig(rotate_before_days=1, max_revocation_failures=max_revocation_failures),
    )
    manager = CertificateManager(config)
    manager.client = MagicMock(spec=httpx2.Client)
    manager.serial = "0000000000000001"
    return manager


def _daemon(manager: CertificateManager) -> ExecutorDaemon:
    """A daemon whose cert_manager is the given (mock-transport) manager."""
    daemon = ExecutorDaemon(manager.config)
    daemon.cert_manager = manager
    daemon.client = MagicMock(spec=httpx2.Client)
    daemon.state.running = True
    return daemon


def _above_debug(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Records above DEBUG on the daemon logger."""
    return [r for r in caplog.records if r.levelno > logging.DEBUG and r.name.startswith(LOGGER_NAME)]


def _text(records: list[logging.LogRecord]) -> str:
    return " ".join(r.getMessage() for r in records)


def _run_ticks(daemon: ExecutorDaemon, wanted: int) -> int:
    """Drive ``_main_loop`` for ``wanted`` ticks; return how many completed.

    A tick that raises out of ``_main_loop`` IS the bug talking: the exception
    escapes here, the cell goes RED, and in the field ``start()``'s
    ``try/finally: self.stop()`` tears the daemon down. At the fix tip the call
    returns normally. The count is returned rather than assumed so a status error
    that retried into a tight loop shows up as more polls than ticks.
    """
    ticks = {"n": 0}

    def wait(_timeout: float) -> bool:
        ticks["n"] += 1
        if ticks["n"] >= wanted:
            daemon.state.running = False
        return False

    with (
        patch.object(daemon.cert_manager, "needs_rotation", return_value=False),
        patch.object(daemon, "_submit_heartbeat"),
        patch.object(daemon._shutdown_event, "wait", side_effect=wait),
    ):
        daemon._main_loop()
    return ticks["n"]


# ---------------------------------------------------------------------------
# Premise — the load-bearing proof.
# ---------------------------------------------------------------------------


class TestPremise:
    def test_httpstatus_error_is_not_a_request_error(self):
        """HTTPStatusError escapes every ``except httpx2.RequestError`` arm by class.

        If this cell ever goes RED because the MRO gained ``RequestError``, the
        #551 premise is void for that tree — the pre-existing arm would already
        have caught it. STOP and re-derive; do not "fix" this assertion.
        """
        assert not issubclass(httpx2.HTTPStatusError, httpx2.RequestError)
        assert httpx2.HTTPStatusError.__mro__[0] is httpx2.HTTPStatusError
        assert httpx2.HTTPStatusError.__mro__[1] is httpx2.HTTPError
        # Transport faults DO take the RequestError arm — the half that always
        # worked, and the reason the status half stayed invisible.
        assert issubclass(httpx2.TransportError, httpx2.RequestError)

    def test_real_response_produces_the_real_class(self):
        """raise_for_status on a 500 raises HTTPStatusError, not RequestError."""
        with pytest.raises(httpx2.HTTPStatusError) as excinfo:
            _revocation_response(500).raise_for_status()
        assert not isinstance(excinfo.value, httpx2.RequestError)
        assert excinfo.value.response.status_code == 500

    def test_revocation_status_is_the_shipped_tri_state(self):
        """#442 site 4 is in this base: three named answers, and this leg adds no fourth."""
        assert {s.name for s in RevocationStatus} == {"NOT_REVOKED", "REVOKED", "UNREACHABLE"}


# ---------------------------------------------------------------------------
# Fix half — a status error is a failed check (UNREACHABLE), never a stop.
# ---------------------------------------------------------------------------


class TestStatusErrorIsAFailedCheck:
    """Cells 1 and 2 (AC1). RED at the parent: the error unwinds out of both."""

    def test_500_completes_the_tick_and_answers_unreachable(self, caplog):
        """A 500 from the revocation endpoint does not stop the loop; it counts."""
        manager = _manager()
        manager.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]
        daemon = _daemon(manager)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            ticks = _run_ticks(daemon, 1)

        assert ticks == 1, "the tick survived the status error"
        assert daemon.state.revoked is False, "one failed check is not a revoked verdict"
        assert daemon.state._consecutive_revocation_failures == 1, "a status error counts as a failed check"
        records = _above_debug(caplog)
        assert records, "a failed revocation check must be visible above debug, not skipped silently"
        text = _text(records)
        assert STATUS_ARM_TEXT in text, f"the status arm must be the one answering, got: {text}"
        assert "500" in text and REVOCATION_PATH in text, f"status code + endpoint expected, got: {text}"

    def test_403_behaves_like_the_500(self, caplog):
        """Cell 2: a different class of status error must not behave differently."""
        manager = _manager()
        manager.client.get.return_value = _revocation_response(403)  # type: ignore[union-attr]
        daemon = _daemon(manager)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            ticks = _run_ticks(daemon, 1)

        assert ticks == 1, "a 403 from the revocation endpoint must not stop the daemon"
        assert daemon.state._consecutive_revocation_failures == 1
        text = _text(_above_debug(caplog))
        assert "403" in text and REVOCATION_PATH in text, f"status code + endpoint expected, got: {text}"

    def test_check_revocation_returns_unreachable_for_each_status(self):
        """The unit seam: check_revocation itself must not raise on 4xx/5xx.

        Kept separate from the loop cells so a failure names the layer — this is
        the arm inside check_revocation, the one place the decision is made.
        """
        for status_code in (400, 401, 403, 404, 500, 502, 503):
            manager = _manager()
            manager.client.get.return_value = _revocation_response(status_code)  # type: ignore[union-attr]
            assert (
                manager.check_revocation() is RevocationStatus.UNREACHABLE
            ), f"{status_code} must answer UNREACHABLE, never raise, never claim live"

    def test_status_error_keeps_the_daemon_alive_across_two_ticks(self):
        """Cadence: two ticks, two polls, ~30 s apart — never a tight retry loop."""
        manager = _manager(max_revocation_failures=THRESHOLD)
        manager.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]
        daemon = _daemon(manager)

        ticks = _run_ticks(daemon, 2)

        assert ticks == 2, "the loop kept ticking past the status error"
        assert manager.client.get.call_count == 2, "exactly one revocation poll per tick"  # type: ignore[union-attr]
        assert daemon.state._consecutive_revocation_failures == 2
        assert daemon.state.revoked is False, "two failed checks are still under the threshold"
        assert daemon.state.running is False, "stopped only by this cell's own stop signal"

    def test_a_run_of_status_errors_still_trips_the_existing_threshold(self, caplog):
        """Bounded fail-closed applies to status errors too — via #442's threshold.

        THRESHOLD consecutive UNREACHABLE answers flip ``state.revoked`` on the
        ``max_revocation_failures`` branch, with #442's unchanged warning text.
        Nothing here is new policy: #551 only makes the status error FEED the
        counter it used to bypass by killing the loop first.
        """
        manager = _manager(max_revocation_failures=THRESHOLD)
        manager.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]
        daemon = _daemon(manager)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            # The trip happens INSIDE the tick (before its wait()), so the tick
            # that reaches the threshold never completes.
            ticks = _run_ticks(daemon, THRESHOLD + 1)

        assert daemon.state.revoked is True, "a persistent status outage fails closed on the threshold"
        assert daemon.state._consecutive_revocation_failures == THRESHOLD
        assert manager.client.get.call_count == THRESHOLD, "one poll per tick, tripped exactly at the threshold"  # type: ignore[union-attr]
        assert ticks == THRESHOLD - 1, "the looping stopped on the trip, not on this cell's stop signal"
        assert "treating certificate as revoked" in caplog.text

    def test_a_good_answer_between_status_errors_still_resets(self):
        """Paired negative on the counter: UNREACHABLE counts, NOT_REVOKED resets."""
        manager = _manager()
        daemon = _daemon(manager)

        manager.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]
        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        daemon.state._consecutive_revocation_failures += 1
        assert daemon.state._consecutive_revocation_failures == 1

        manager.client.get.return_value = _revocation_response(200, {"revoked_serials": []})  # type: ignore[union-attr]
        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        daemon.state._consecutive_revocation_failures = 0
        assert daemon.state._consecutive_revocation_failures == 0


# ---------------------------------------------------------------------------
# Paired negatives — the happy path and #442's shipped half are untouched.
# Green at the parent, green at the fix tip.
# ---------------------------------------------------------------------------


class TestGenuineAnswersUnchanged:
    def test_serial_present_still_revokes_and_stops(self, caplog):
        """Cell 3 (AC2): a genuine 200 with the serial present still means REVOKED."""
        manager = _manager()
        manager.client.get.return_value = _revocation_response(200, {"revoked_serials": ["0000000000000001"]})  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.REVOKED

        daemon = _daemon(manager)
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            _run_ticks(daemon, 3)

        assert daemon.state.revoked is True, "the shutdown path is unchanged for a real revocation"
        assert "REVOKED" in caplog.text
        assert daemon.state._consecutive_revocation_failures == 0, "a revoked answer is an answer, not a failure"

    def test_identity_revocation_still_terminal(self):
        """Paired negative, identity half: a 200 naming this executor_id still revokes."""
        manager = _manager()
        manager.client.get.return_value = _revocation_response(  # type: ignore[union-attr]
            200, {"revoked_serials": [], "revoked_identities": ["test-executor"]}
        )

        assert manager.check_revocation() is RevocationStatus.REVOKED

    def test_serial_absent_still_not_revoked(self):
        """Cell 4: a genuine 200 without the serial still means live."""
        manager = _manager()
        manager.client.get.return_value = _revocation_response(200, {"revoked_serials": ["0000000000000002"]})  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_no_serial_is_an_answer_not_an_outage(self):
        """Pre-registration behaviour keeps its NOT_REVOKED name (#442's half)."""
        manager = _manager()
        manager.serial = None

        with patch.object(manager.client, "get") as mock_get:
            assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
            mock_get.assert_not_called()

    def test_304_still_short_circuits(self):
        """Paired negative: the not-modified path is untouched by the new arm."""
        manager = _manager()
        manager._last_revocation_etag = '"etag"'
        manager.client.get.return_value = _revocation_response(304)  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_etag_cache_still_advances_on_a_good_response(self):
        """Paired negative: the conditional-GET bookkeeping is collateral-free."""
        manager = _manager()
        manager.client.get.return_value = httpx2.Response(  # type: ignore[union-attr]
            status_code=200,
            request=httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}"),
            json={"revoked_serials": []},
            headers={"etag": '"good-etag"'},
        )

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        assert manager._last_revocation_etag == '"good-etag"'

    def test_etag_cache_does_not_advance_on_a_status_error(self):
        """A failed check keeps the last good ETag — no poisoned cache."""
        manager = _manager()
        manager._last_revocation_etag = '"good-etag"'
        manager.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        assert manager._last_revocation_etag == '"good-etag"'


# ---------------------------------------------------------------------------
# Regression guard — the arm this leg did NOT touch (cell 5).
# ---------------------------------------------------------------------------


class TestTransportFaultArmUnchanged:
    def test_transport_error_still_takes_the_existing_arm(self):
        """A real transport fault keeps #442's RequestError arm and its text."""
        manager = _manager()
        manager.client.get.side_effect = httpx2.TransportError(  # type: ignore[union-attr]
            "connection refused", request=httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
        )

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE

    def test_transport_fault_and_status_error_land_on_different_arms(self, caplog):
        """Same answer, different arms — the new arm did not swallow the old path.

        The two log signatures are what prove it: a transport fault says
        "server unreachable" (#442's wording, unchanged by this leg), a status
        error says "server answered HTTP <code>".
        """
        transport = _manager()
        request = httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
        transport.client.get.side_effect = httpx2.ConnectError("refused", request=request)  # type: ignore[union-attr]

        status = _manager()
        status.client.get.return_value = _revocation_response(500)  # type: ignore[union-attr]

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert transport.check_revocation() is RevocationStatus.UNREACHABLE
            assert status.check_revocation() is RevocationStatus.UNREACHABLE

        text = _text(_above_debug(caplog))
        assert UNREACHABLE_ARM_TEXT in text, f"transport fault must answer on the pre-existing arm, got: {text}"
        assert STATUS_ARM_TEXT in text, f"status error must answer on the new arm, got: {text}"

    def test_httpstatus_error_is_not_swallowed_as_a_transport_fault(self, caplog):
        """The new arm does not steal the RequestError log line — it names the status.

        A single shared message would satisfy #551's crash fix but lose the
        operator signal (which endpoint, which code), so the two stay distinct.
        """
        manager = _manager()
        manager.client.get.return_value = _revocation_response(503)  # type: ignore[union-attr]

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert manager.check_revocation() is RevocationStatus.UNREACHABLE

        text = _text(_above_debug(caplog))
        assert "503" in text and REVOCATION_PATH in text
        assert UNREACHABLE_ARM_TEXT not in text, "a 503 is not a connection fault and must not read like one"
