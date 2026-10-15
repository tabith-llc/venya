# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#603 AC2 TT8 (caller side) — a SERVER_ERROR must not advance the ETag cache clock.

The rule, from the drafter's truth-table additions and adopted by the lead at review
item 3: caching an ETag the check never READ is the laundering move — the next tick
sends ``If-None-Match``, gets a bodyless 304, and ``check_revocation`` answers
``NOT_REVOKED`` about a response nobody parsed. On the revocation plane that answer is
an all-clear, so the clock may advance only on a tick that actually read a payload.

#551 already shipped the plain-500 half of this
(``test_revocation_httpstatus_551.py:346``
``TestGenuineAnswersUnchanged.test_etag_cache_does_not_advance_on_a_status_error``),
and its response carries NO ``etag`` header at all — so that cell cannot see an
implementation that cached a header before raising. What these cells add is the shape
step 2 actually puts on the wire:

* a server error that DOES carry an ETag, still not cached (the ordering guard,
  demonstrated rather than inherited — ``raise_for_status`` before the cache write);
* step 2's own refusal class — the 503 stale snapshot answer — lands as
  ``UNREACHABLE``, counts toward the shipped threshold, and leaves the clock where the
  last good answer set it, so the next poll re-asks for the WHOLE list; and
* the paired positive: an answered tick still advances, so "never cache" has not
  quietly become "never serve a 304".

Real ``httpx2.Response`` objects throughout (the #551 precedent): ``raise_for_status()``
has to raise for real, or the arm under test is a stub rather than the daemon's.
"""

import logging
from unittest.mock import MagicMock, patch

import httpx2

from executor.config import CertificateRotationConfig, ExecutorConfig
from executor.daemon import CertificateManager, ExecutorDaemon, RevocationStatus
from executor.relay_listener import REFUSE_NO_ANSWER

REVOCATION_PATH = "/api/v1/executors/certs/revocation-list"
SERVER_URL = "https://example.com"
LOGGER_NAME = "venya.executor.daemon"
THRESHOLD = 3

# The server-side stale-class detail, at this base routes/executors.py:687. Copied as a
# LITERAL here because the executor package must not import the server package; the
# cell that owns the constant's bytes is the server-side suite.
STALE_LIST_DETAIL = "Revocation list stale or unavailable — dial refused (no revocation asserted)"

GOOD_ETAG = '"good-etag"'


def _response(status_code: int, payload: dict | None = None, headers: dict | None = None) -> httpx2.Response:
    """A real Response for the revocation endpoint, request and headers wired."""
    request = httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
    kwargs = {"status_code": status_code, "request": request, "headers": headers or {}}
    if payload is not None:
        kwargs["json"] = payload
    return httpx2.Response(**kwargs)  # type: ignore[arg-type]


def _manager(max_revocation_failures: int = THRESHOLD) -> CertificateManager:
    """A CertificateManager with a mock transport and a serial set (the #551 shape)."""
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
    daemon = ExecutorDaemon(manager.config)
    daemon.cert_manager = manager
    daemon.client = MagicMock(spec=httpx2.Client)
    daemon.state.running = True
    return daemon


def _sent_etag_headers(manager: CertificateManager) -> list[str | None]:
    """The ``If-None-Match`` values actually put on the wire, in call order."""
    return [
        (call.kwargs.get("headers") or {}).get("If-None-Match")
        for call in manager.client.get.call_args_list  # type: ignore[union-attr]
    ]


class TestTT8ServerErrorDoesNotAdvanceTheCacheClock:
    def test_a_server_error_carrying_an_etag_still_does_not_advance_the_cache(self):
        """The ordering guard, demonstrated not inherited: an error's header is not an answer.

        This is the half #551's cell cannot see — its 500 carries no ``etag`` header, so
        a build that cached the header before calling ``raise_for_status()`` would still
        pass it. Here the error DOES carry one, and the cached value must stay at the
        last GOOD etag.
        """
        manager = _manager()
        manager._last_revocation_etag = GOOD_ETAG
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            500, payload={"detail": "Internal Server Error"}, headers={"etag": '"server-error-etag"'}
        )

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        assert manager._last_revocation_etag == GOOD_ETAG, "a server error moved the cache clock"

    def test_the_step2_stale_refusal_is_a_failed_check_not_an_answer(self):
        """Step 2's own answer class, read by the caller: 503 stale = UNREACHABLE.

        The stale snapshot refusal is a NEW shape on this wire (the poll used to have
        only 200/304/5xx-collision answers). The caller's reading of it is what keeps
        the ceiling honest: it must count as "no answer" and never as "nothing revoked".
        """
        manager = _manager()
        manager._last_revocation_etag = GOOD_ETAG
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            503, payload={"detail": STALE_LIST_DETAIL}, headers={"etag": '"stale-refusal-etag"'}
        )

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        assert manager._last_revocation_etag == GOOD_ETAG

    def test_the_next_poll_still_offers_the_last_good_etag(self):
        """The clock law as a WIRE fact: after a refused tick, the old tag goes out.

        Asserting the cached value alone would pass a build that cleared the cache (which
        re-fetches the whole list forever); asserting the header the next poll SENDS is
        what proves the retained tag is still the one in use.
        """
        manager = _manager()
        manager._last_revocation_etag = GOOD_ETAG
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            503, payload={"detail": STALE_LIST_DETAIL}, headers={"etag": '"stale-refusal-etag"'}
        )
        assert manager.check_revocation() is RevocationStatus.UNREACHABLE

        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            200, payload={"revoked_serials": [], "revoked_identities": []}, headers={"etag": '"next-good-etag"'}
        )
        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        # Both polls went out with the tag the clock held at call time — the refused tick
        # did not clear it, and a refused tick cannot install its own either.
        assert _sent_etag_headers(manager) == [GOOD_ETAG, GOOD_ETAG]
        # The answered tick is what finally moves the clock.
        assert manager._last_revocation_etag == '"next-good-etag"'

    def test_a_stale_refusal_counts_toward_the_threshold_and_stops_with_the_fault_reason(self, caplog):
        """Bounded fail-closed unchanged: the ceiling converts to strikes, then to a fault.

        The threshold math is #442's machinery, and #603 made the trip a FAULT rather
        than a revocation claim. This cell pins that step 2's 503 feeds that same path:
        ``revoked`` stays False, ``revocation_fault_reason`` is the shipped 503
        OPERATIONAL FAULT string, and the daemon stops rather than polling forever.
        """
        manager = _manager(max_revocation_failures=THRESHOLD)
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            503, payload={"detail": STALE_LIST_DETAIL}
        )
        daemon = _daemon(manager)

        def _wait(_timeout: float) -> bool:
            return False

        with (
            caplog.at_level(logging.DEBUG, logger=LOGGER_NAME),
            patch.object(daemon.cert_manager, "needs_rotation", return_value=False),
            patch.object(daemon, "_submit_heartbeat"),
            patch.object(daemon._shutdown_event, "wait", side_effect=_wait),
        ):
            daemon._main_loop()

        assert daemon.state.revoked is False, "a stale snapshot is never a revocation assertion"
        assert daemon.state.revocation_fault_reason is REFUSE_NO_ANSWER
        assert manager.client.get.call_count == THRESHOLD  # type: ignore[union-attr]
        assert "reached the fault threshold" in caplog.text

    def test_paired_positive_an_answered_tick_still_advances_the_clock(self):
        """Without this half, "never cache on error" could hide "never cache at all"."""
        manager = _manager()
        manager._last_revocation_etag = None
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            200, payload={"revoked_serials": []}, headers={"etag": GOOD_ETAG}
        )

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        assert manager._last_revocation_etag == GOOD_ETAG
