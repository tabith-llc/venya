# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Licensing terms in the
# LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#552 — a 200 whose revocation body will not parse is a failed check, not a stop.

The premise, pinned by ``TestPremise`` so a future tree that changes it fails here
instead of silently un-fixing #552. ``CertificateManager.check_revocation`` parsed the
revocation-list response inline:

* ``data = response.json()`` raised ``json.decoder.JSONDecodeError`` on a body that
  is not JSON, and ``UnicodeDecodeError`` on a body that is not text at all (a
  truncated gzip frame, a proxy's binary error page) — both classes measured live at
  this base against a real ``httpx2.Response`` 200;
* a body that decoded to a non-mapping (a JSON list, string, number, or ``null``)
  raised ``AttributeError`` out of the ``data.get(...)`` calls.

None of those four classes is an ``httpx2.RequestError``, so each one left
``check_revocation`` (whose only handlers were ``RequestError`` and, since #551,
``HTTPStatusError``), left BOTH arms in ``ExecutorDaemon._main_loop`` (``TimeoutError``
and ``RequestError``), and unwound ``start()``'s ``try/finally: self.stop()``. One
mis-shaped 200 from one endpoint stopped the executor daemon.

The fix is a NAMED payload-shape guard at the parse site —
``executor.daemon.parse_revocation_payload`` raising ``executor.daemon.RevocationPayloadError``
— and NO blanket ``except Exception`` anywhere on the path: the guard catches exactly
the two decode classes, and checks the decoded shape before anything reads a field.
The bad body answers ``RevocationStatus.UNREACHABLE``, the UNKNOWN the #442 tri-state
already defines (no fourth member), so ``_main_loop`` ADVANCES
``_consecutive_revocation_failures`` and the existing ``max_revocation_failures``
threshold behaves the way it does for a transport fault. Answering ``NOT_REVOKED``
here would be the laundering version of the same defect: a body that said nothing
would be read as "the server says your certificate is live".

One ordering point the guard carries with it (#551's cache rule applied to the new
class): the ETag cache advances only for a body this check actually read. Caching the
ETag of an unreadable payload would let the next tick take a 304 — which is an ANSWER,
``NOT_REVOKED`` — about a body nobody parsed, resetting the very counter that bounds
the outage.

Every cell here uses the REAL ``httpx2.Response(200, request=..., content=... / json=...)``
shape (AC6): no stubbed ``.json()``, so the class that escapes is the class the daemon
sees. The pre-existing ``test_daemon.py::TestCheckRevocation`` cells all stub
``raise_for_status`` and hand back a ``MagicMock`` body, which is why nothing in the
suite ever produced this shape.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import CertificateRotationConfig, ExecutorConfig
from executor.daemon import CertificateManager, ExecutorDaemon, RevocationStatus

# The #552 guard symbols are imported INSIDE the cells that name them, so this module
# still COLLECTS at the parent: the fix-half cells then go RED with the class the
# daemon actually raised (JSONDecodeError / UnicodeDecodeError / AttributeError), the
# guard-shape cells go RED with an ImportError that says the guard did not exist, and
# the paired-negative cells stay green at both tips. A module-level import would have
# turned the whole file into one collection error and lost that per-cell evidence.

REVOCATION_PATH = "/api/v1/executors/certs/revocation-list"
SERVER_URL = "https://example.com"
LOGGER_NAME = "venya.executor.daemon"
THRESHOLD = 4
OWN_SERIAL = "0000000000000001"

# The three arms' signatures, so "which arm answered" is testable and not a guess.
UNREACHABLE_ARM_TEXT = "server unreachable"  # #442's transport arm
STATUS_ARM_TEXT = "server answered HTTP"  # #551's status arm
PAYLOAD_ARM_TEXT = "payload this check cannot read"  # #552's shape guard

# Bodies that are not a revocation list. Each entry names the class the OLD inline
# parse raised with it, so the pairing body -> escape class stays in the record.
MALFORMED_BODY_CASES = [
    (b"not-json", "JSONDecodeError"),
    (b"502 Bad Gateway", "JSONDecodeError"),
    (b"<html>nope</html>", "JSONDecodeError"),
    (b"", "JSONDecodeError"),
    (b'{"revoked_serials": ["0000"', "JSONDecodeError"),
    (b"\x1f\x8b\x08\x00binary", "UnicodeDecodeError"),
]
MALFORMED_BODIES = [
    pytest.param(c, e, id=n)
    for (c, e), n in zip(
        MALFORMED_BODY_CASES,
        [
            "plain-text-not-json",
            "proxy-text-error-page",
            "html-body",
            "empty-body",
            "truncated-json",
            "gzip-frame",
        ],
        strict=True,
    )
]

NON_MAPPING_CASES = [
    (b'["a"]', "list", "AttributeError: 'list' object has no attribute 'get'"),
    (b'"hello"', "string", "AttributeError: 'str' object has no attribute 'get'"),
    (b"42", "number", "AttributeError: 'int' object has no attribute 'get'"),
    (b"null", "null", "AttributeError: 'NoneType' object has no attribute 'get'"),
]
BODIES_THAT_PARSE_BUT_ARE_NOT_A_REVOCATION_LIST = [
    pytest.param(c, n, id=f"json-{n}" + ("-AC2" if n == "list" else "")) for c, n, _ in NON_MAPPING_CASES
]

# Recorded because it is easy to get wrong in a cell: ``httpx2.Response(json=None)``
# builds an EMPTY body (``b""``), which is a JSONDecodeError shape, NOT the ``null``
# shape. Every body above is given as BYTES so the shape a cell names is the shape the
# daemon parses (AC6).


def _guard():
    """The #552 parse-site guard, imported per cell (see the note above the constants).

    Returns:
        ``(RevocationPayloadError, parse_revocation_payload)`` from the live module.
    """
    from executor.daemon import RevocationPayloadError, parse_revocation_payload

    return RevocationPayloadError, parse_revocation_payload


def _response(
    *, content: bytes | None = None, json_body: object = None, headers: dict | None = None
) -> httpx2.Response:
    """A real httpx2 200 from the revocation endpoint, request wired.

    Real, not stubbed: ``.json()`` behaves exactly as it does in the daemon, so the
    class a bad body produces here is the class it produces in the field.
    """
    request = httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
    kwargs: dict = {"status_code": 200, "request": request, "headers": headers or {}}
    if content is not None:
        kwargs["content"] = content
    else:
        kwargs["json"] = json_body
    return httpx2.Response(**kwargs)


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
    manager.serial = OWN_SERIAL
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
    returns normally.
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
    def test_the_four_escape_classes_are_not_request_errors(self):
        """Every class a bad 200 body produced escapes any ``except httpx2.RequestError``.

        If a future tree makes one of these a ``RequestError`` subclass, the #552
        premise is void for that tree — STOP and re-derive, do not delete this cell.
        """
        RevocationPayloadError, _ = _guard()
        for cls in (httpx2.RequestError, httpx2.HTTPError):
            assert not issubclass(RevocationPayloadError, cls)

        assert issubclass(json.JSONDecodeError, ValueError)
        assert not issubclass(json.JSONDecodeError, httpx2.RequestError)
        assert not issubclass(UnicodeDecodeError, httpx2.RequestError)
        assert not issubclass(AttributeError, httpx2.RequestError)
        # Transport faults DO take the RequestError arm — the half that always worked.
        assert issubclass(httpx2.TransportError, httpx2.RequestError)

    @pytest.mark.parametrize(
        "label, body, expected",
        [
            ("plain text", b"not-json", json.JSONDecodeError),
            ("gzip frame", b"\x1f\x8b\x08\x00binary", UnicodeDecodeError),
            ("empty body", b"", json.JSONDecodeError),
        ],
    )
    def test_real_response_bodies_raise_these_classes(self, label, body, expected):
        """The class a bad body raises here is the class the daemon saw inline.

        This is the seam the guard closes; it is asserted on a REAL response object,
        never on a stub (AC6).
        """
        with pytest.raises(expected):
            _response(content=body).json()

    @pytest.mark.parametrize("content, name", BODIES_THAT_PARSE_BUT_ARE_NOT_A_REVOCATION_LIST)
    def test_decoded_non_mapping_has_no_get(self, content, name):
        """AC2's mechanism: a decoded non-mapping raised AttributeError at the `.get` calls."""
        decoded = _response(content=content).json()
        assert not isinstance(decoded, dict), f"{name} must not decode to a mapping"
        with pytest.raises(AttributeError):
            decoded.get("revoked_serials", [])  # type: ignore[union-attr]

    def test_guard_answers_named_errors_for_each_bad_shape(self):
        """parse_revocation_payload names the defect instead of raising the raw class."""
        RevocationPayloadError, parse_revocation_payload = _guard()
        for content, _escaped in MALFORMED_BODY_CASES:
            with pytest.raises(RevocationPayloadError):
                parse_revocation_payload(_response(content=content))
        for content, _name, _escape in NON_MAPPING_CASES:
            with pytest.raises(RevocationPayloadError):
                parse_revocation_payload(_response(content=content))

    def test_guard_passes_the_shapes_that_are_answers(self):
        """Paired negative on the guard: a real answer is an answer, not a defect.

        ``{}`` is the server's empty list (both fields default to ``[]`` in
        ``RevocationListResponse``), so it is VALID — that is the ruling this leg
        recorded: ``{}`` = no revocations, ``null`` = malformed (it has no ``.get``).
        """
        _, parse_revocation_payload = _guard()
        assert parse_revocation_payload(_response(content=b"{}")) == {}
        assert parse_revocation_payload(_response(json_body={"revoked_serials": [OWN_SERIAL]})) == {
            "revoked_serials": [OWN_SERIAL]
        }

    @pytest.mark.parametrize("field", ["revoked_serials", "revoked_identities"])
    def test_guard_rejects_a_field_that_is_not_a_list(self, field):
        """The fields are read as collections, so a non-list value is not an answer.

        ``set(data.get(...))`` / ``{serial_match_key(s) for s in ...}`` raised
        ``TypeError`` on these at the parent — the same crash class one level in.
        """
        RevocationPayloadError, parse_revocation_payload = _guard()
        with pytest.raises(RevocationPayloadError):
            parse_revocation_payload(_response(json_body={field: "not-a-list"}))
        with pytest.raises(RevocationPayloadError):
            parse_revocation_payload(_response(json_body={field: None}))

    def test_guard_does_not_catch_a_non_payload_error(self):
        """AC4 fidelity, negative half: the narrowness is real, not decorative.

        A ``ValueError`` that is not one of the two named decode classes still
        escapes. A blanket ``except Exception`` would swallow it into an UNREACHABLE
        answer and hide a genuine bug — which is the fail-open family (#442, #551)
        this leg refuses to re-open.
        """
        manager = _manager()

        class UnrelatedBug(ValueError):
            """Not a decode class: something in the daemon itself is wrong."""

        manager.client.get.side_effect = UnrelatedBug("programmer error")  # type: ignore[union-attr]
        with pytest.raises(UnrelatedBug):
            manager.check_revocation()

    def test_revocation_status_is_the_shipped_tri_state(self):
        """#442 site 4's three answers are what this feeds; no fourth member is minted."""
        assert {s.name for s in RevocationStatus} == {"NOT_REVOKED", "REVOKED", "UNREACHABLE"}


# ---------------------------------------------------------------------------
# Fix half — a bad-payload 200 is a failed check (UNREACHABLE), never a stop.
# ---------------------------------------------------------------------------


class TestMalformedPayloadIsAFailedCheck:
    """Cells 1 and 2 (AC1/AC2). RED at the parent: the class unwinds out of both layers."""

    @pytest.mark.parametrize("content, escaped", MALFORMED_BODIES)
    def test_unparseable_200_answers_unreachable_without_raising(self, content, escaped, caplog):
        """AC1: a genuine 200 whose body is not JSON does not stop the check."""
        manager = _manager()
        manager.client.get.return_value = _response(content=content)  # type: ignore[union-attr]

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            answer = manager.check_revocation()

        assert answer is RevocationStatus.UNREACHABLE, f"{escaped} body must answer UNKNOWN, never raise"
        records = _above_debug(caplog)
        assert records, "a failed revocation check must be visible above debug, not skipped silently"
        text = _text(records)
        assert PAYLOAD_ARM_TEXT in text, f"the shape guard must be the one answering, got: {text}"
        assert "test-executor" in text, f"the warning must name the executor, got: {text}"
        assert REVOCATION_PATH in text, f"the warning must name the endpoint, got: {text}"

    @pytest.mark.parametrize("content, name", BODIES_THAT_PARSE_BUT_ARE_NOT_A_REVOCATION_LIST)
    def test_non_mapping_200_answers_unreachable_without_raising(self, content, name, caplog):
        """AC2: a body that parses to a list/string/number/null behaves like AC1."""
        manager = _manager()
        manager.client.get.return_value = _response(content=content)  # type: ignore[union-attr]

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            answer = manager.check_revocation()

        assert answer is RevocationStatus.UNREACHABLE, f"a {name} body must answer UNKNOWN, never raise"
        text = _text(_above_debug(caplog))
        assert PAYLOAD_ARM_TEXT in text

    def test_the_answer_is_never_not_revoked(self, caplog):
        """AC5, stated as its own negative: a body that said nothing is not 'live'."""
        for bad in (b"not-json", b"\x1f\x8b\x08\x00binary"):
            manager = _manager()
            manager.client.get.return_value = _response(content=bad)  # type: ignore[union-attr]
            assert manager.check_revocation() is not RevocationStatus.NOT_REVOKED

    def test_a_bad_body_does_not_poison_the_etag_cache(self):
        """The guard runs BEFORE the ETag advances — #551's cache rule, new class.

        Caching an unreadable body's ETag would make the next tick a 304, and a 304
        is an ANSWER (NOT_REVOKED): one bad 200 would erase its own failure count.
        """
        manager = _manager()
        manager._last_revocation_etag = '"good-etag"'
        manager.client.get.return_value = _response(content=b"not-json", headers={"etag": '"bad-body"'})  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        assert manager._last_revocation_etag == '"good-etag"', "the last GOOD etag must survive"

    def test_the_good_etag_still_wins_after_a_bad_tick(self):
        """Paired positive: the retained etag goes out on the next poll as If-None-Match."""
        manager = _manager()
        manager._last_revocation_etag = '"good-etag"'
        manager.client.get.return_value = _response(content=b"not-json")  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.UNREACHABLE

        manager.client.get.return_value = _response(json_body={"revoked_serials": []})  # type: ignore[union-attr]
        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        sent_headers = manager.client.get.call_args.kwargs["headers"]  # type: ignore[union-attr]
        assert sent_headers == {"If-None-Match": '"good-etag"'}

    def test_bad_payload_advances_the_counter_and_keeps_the_loop_running(self, caplog):
        """Loop-level cell (the one this leg RAN): no exception reaches the loop, the tick
        completes, and the consecutive-failure counter ADVANCES on the bad-payload tick."""
        manager = _manager()
        manager.client.get.return_value = _response(content=b"not-json")  # type: ignore[union-attr]
        daemon = _daemon(manager)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            ticks = _run_ticks(daemon, 1)

        assert ticks == 1, "the tick survived the mis-shaped 200"
        assert daemon.state.revoked is False, "one unreadable body is not a revoked verdict"
        assert daemon.state._consecutive_revocation_failures == 1, "a bad payload counts as a failed check"
        assert PAYLOAD_ARM_TEXT in _text(_above_debug(caplog))

    def test_a_run_of_bad_bodies_still_trips_the_existing_threshold(self):
        """Bounded fail-closed covers this class too — via #442's threshold, no new policy."""
        manager = _manager(max_revocation_failures=THRESHOLD)
        manager.client.get.return_value = _response(content=b"not-json")  # type: ignore[union-attr]
        daemon = _daemon(manager)

        _run_ticks(daemon, THRESHOLD + 1)

        assert daemon.state.revoked is True, "a persistently mis-shaped endpoint fails closed"
        assert daemon.state._consecutive_revocation_failures == THRESHOLD
        assert manager.client.get.call_count == THRESHOLD  # type: ignore[union-attr]

    def test_cadence_is_one_poll_per_tick(self):
        """No retry storm inside the check: two ticks, two polls."""
        manager = _manager()
        manager.client.get.return_value = _response(json_body=["a"])  # type: ignore[union-attr]
        daemon = _daemon(manager)

        ticks = _run_ticks(daemon, 2)

        assert ticks == 2
        assert manager.client.get.call_count == 2  # type: ignore[union-attr]
        assert daemon.state._consecutive_revocation_failures == 2


# ---------------------------------------------------------------------------
# Paired negatives — every path that already worked keeps working, on its own arm.
# Green at the parent, green at the fix tip.
# ---------------------------------------------------------------------------


class TestGenuineAnswersUnchanged:
    def test_serial_present_still_revokes(self):
        """AC3 positive half, unit seam."""
        manager = _manager()
        manager.client.get.return_value = _response(json_body={"revoked_serials": [OWN_SERIAL]})  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.REVOKED

    def test_serial_present_still_takes_the_shutdown_branch(self):
        """AC3 positive half, loop seam: the same branch fires, unchanged."""
        manager = _manager()
        manager.client.get.return_value = _response(json_body={"revoked_serials": [OWN_SERIAL]})  # type: ignore[union-attr]
        daemon = _daemon(manager)

        _run_ticks(daemon, 3)

        assert daemon.state.revoked is True, "the shutdown path is unchanged for a real revocation"
        assert daemon.state._consecutive_revocation_failures == 0, "an answer is not a failure"

    def test_identity_revocation_still_terminal(self):
        """Paired negative, identity half: a 200 naming this executor_id still revokes."""
        manager = _manager()
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            json_body={"revoked_serials": [], "revoked_identities": ["test-executor"]}
        )

        assert manager.check_revocation() is RevocationStatus.REVOKED

    def test_not_revoked_answer_is_unchanged_in_value_log_level_and_etag(self, caplog):
        """AC3 negative half, all three clauses: same value, same (debug-only) level,
        and the ETag still advances for a body that was actually read."""
        manager = _manager()
        manager.client.get.return_value = _response(  # type: ignore[union-attr]
            json_body={"revoked_serials": ["0000000000000002"]}, headers={"etag": '"good-etag"'}
        )

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            answer = manager.check_revocation()

        assert answer is RevocationStatus.NOT_REVOKED
        assert manager._last_revocation_etag == '"good-etag"', "a real answer still advances the cache"
        assert not _above_debug(caplog), "the live answer stays at debug — no new noise"

    def test_empty_object_is_a_valid_answer(self):
        """The ``{}`` half of the ruling: no revocations is an answer, not a defect."""
        manager = _manager()
        manager.client.get.return_value = _response(content=b"{}")  # type: ignore[union-attr]

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_304_still_short_circuits(self):
        """Paired negative: the not-modified path is untouched by the guard."""
        manager = _manager()
        manager._last_revocation_etag = '"etag"'
        manager.client.get.return_value = httpx2.Response(  # type: ignore[union-attr]
            status_code=304, request=httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
        )

        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_no_serial_is_an_answer_not_an_outage(self):
        """Pre-registration behaviour keeps its NOT_REVOKED name (#442's half)."""
        manager = _manager()
        manager.serial = None

        with patch.object(manager.client, "get") as mock_get:
            assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
            mock_get.assert_not_called()

    def test_transport_fault_still_takes_the_request_error_arm(self, caplog):
        """The extra paired negative (truth-table law): the new guard cannot eat a
        transport fault. It answers on #442's arm with #442's wording."""
        manager = _manager()
        manager.client.get.side_effect = httpx2.ConnectError(  # type: ignore[union-attr]
            "refused", request=httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
        )

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert manager.check_revocation() is RevocationStatus.UNREACHABLE

        text = _text(_above_debug(caplog))
        assert UNREACHABLE_ARM_TEXT in text, f"a transport fault stays on the RequestError arm, got: {text}"
        assert PAYLOAD_ARM_TEXT not in text, "a connection that was never made is not a payload defect"

    def test_status_error_still_takes_the_httpstatus_error_arm(self, caplog):
        """#551's arm is untouched: a 500 still reads as an HTTP status, not a body."""
        manager = _manager()
        manager.client.get.return_value = httpx2.Response(  # type: ignore[union-attr]
            status_code=500, request=httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")
        )

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert manager.check_revocation() is RevocationStatus.UNREACHABLE

        text = _text(_above_debug(caplog))
        assert STATUS_ARM_TEXT in text, f"#551's arm must still answer for a 500, got: {text}"
        assert PAYLOAD_ARM_TEXT not in text

    def test_three_arms_three_signatures(self, caplog):
        """The three failure classes land on three named arms — none absorbed."""
        request = httpx2.Request("GET", f"{SERVER_URL}{REVOCATION_PATH}")

        transport = _manager()
        transport.client.get.side_effect = httpx2.TransportError("refused", request=request)  # type: ignore[union-attr]

        status = _manager()
        status.client.get.return_value = httpx2.Response(status_code=503, request=request)  # type: ignore[union-attr]

        payload = _manager()
        payload.client.get.return_value = _response(content=b"not-json")  # type: ignore[union-attr]

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert transport.check_revocation() is RevocationStatus.UNREACHABLE
            assert status.check_revocation() is RevocationStatus.UNREACHABLE
            assert payload.check_revocation() is RevocationStatus.UNREACHABLE

        text = _text(_above_debug(caplog))
        assert UNREACHABLE_ARM_TEXT in text
        assert STATUS_ARM_TEXT in text
        assert PAYLOAD_ARM_TEXT in text

    def test_a_good_answer_between_bad_ones_still_resets(self):
        """Counter law, both halves: UNREACHABLE counts, a real answer resets."""
        manager = _manager()
        daemon = _daemon(manager)

        manager.client.get.return_value = _response(content=b"not-json")  # type: ignore[union-attr]
        assert manager.check_revocation() is RevocationStatus.UNREACHABLE
        daemon.state._consecutive_revocation_failures += 1
        assert daemon.state._consecutive_revocation_failures == 1

        manager.client.get.return_value = _response(json_body={"revoked_serials": []})  # type: ignore[union-attr]
        assert manager.check_revocation() is RevocationStatus.NOT_REVOKED
        daemon.state._consecutive_revocation_failures = 0
        assert daemon.state._consecutive_revocation_failures == 0
