# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#697 EMITTER HALF — the operational-fault refusal becomes bytes on the wire.

Leg 404 built the receiving door: the core forwards a relay 503 whose detail opens with
``"503 OPERATIONAL FAULT — "``. This leg is the emitting half, and the measurement that made it
necessary was blunt — at the base, the literal was true, it was journalled, it was audited, and it
never reached anyone. A door with nothing to forward is not a fix.

The design tension this file exists to keep honest: the refusal happens **before a single request byte
is read**, deliberately, because a refused connection must never hand an unauthenticated peer a parser.
So the notice must be written without reading, must not slow the single-threaded accept loop, and must
not turn a refusal into an admission. Every cell below defends one of those clauses.

What is asserted, in order:

1. **AC1 positive** — an unanswered daemon, and an unwired listener, each answer HTTP 503 carrying
   their own literal, over real mTLS on loopback.
2. **THE NOTICE NEEDS NO REQUEST** — a peer that completes the handshake and sends ZERO bytes still
   gets the notice. This is the load-bearing one: it is the difference between "we proved the notice
   without reading a request" and "we proved it with a request in front of it".
3. **AC2 paired negatives** — the 403 revocation class and BOTH peer classes keep the silent close,
   byte-identically to shipped behavior. A revocation is an assertion about a credential, not a fault
   the operator can act on, and it is not broadcast here.
4. **The refusal is still a refusal** — no handler thread, no engine call, no session, and an unwired
   listener still never serves.
5. **The accept loop survives a peer that will not read** — the notice is bounded, and the next
   connection still gets an answer.
6. **The existing records are undisturbed** — the journal line and ``refusal_recorder`` payload keep
   their shipped shape for the classes that did not change.

LOOPBACK, NOT FLEET: every cell here drives a real ``RelayListener`` on 127.0.0.1 with the test PKI.
That is a real TCP+TLS stack and a real httpx2 client, but it is NOT a fleet guest, and it does not
prove the core->operator path on a real network. The report labels the physical fleet observation
NOT RUN.
"""

import logging
import socket
import ssl
from types import SimpleNamespace

import httpx2
import pytest

from executor.relay_listener import (
    REFUSE_NO_ANSWER,
    REFUSE_NOT_WIRED,
    REFUSE_PEER_EXECUTOR_REVOKED,
    REFUSE_PEER_REVOKED,
    REFUSE_REVOKED,
    RelayListener,
    is_operational_fault_refusal,
    send_refusal_notice,
)

# House pattern (this file's own neighbour, test_relay_revocation_gate_586.py, does the same):
# import the plain PKI/build helpers, define the fixtures locally. No fixture is imported.
from tests.test_relay_listener import (
    ALLOWED,
    SERVER_CN,
    _ca,
    _client,
    _factory,
    _FakeExec,
    _leaf,
    _ok_result,
    _start,
    _url,
    _write_cert_only,
    _write_dir,
)

RELAY_LOGGER = "venya.executor.relay"


def _state(*, revoked: bool = False, answered: bool = True, **kw) -> SimpleNamespace:
    defaults: dict = {
        "revoked": revoked,
        "revocation_answered": answered,
        "revocation_fault_reason": None,
        "revoked_relay_serials": set(),
        "revoked_executor_serials": set(),
        "executor_id": "emit-test",
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _payload(session_id: str = "s1") -> dict:
    return {"session_id": session_id, "command": ["echo", "hi"], "secrets": []}


def _relay_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == RELAY_LOGGER]


@pytest.fixture()
def emit_pk(tmp_path) -> SimpleNamespace:
    """A real three-tier PKI: CA, a server-auth relay leaf, and an allowed client leaf."""
    ca_key, ca_cert = _ca()
    srv_cert, srv_key = _leaf(ca_key, ca_cert, SERVER_CN, server_auth=True)
    c_cert, c_key = _leaf(ca_key, ca_cert, ALLOWED)
    from executor.config import ExecutorConfig, MtlsConfig

    ca_p = _write_cert_only(ca_cert, tmp_path, "ca")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    cli = _write_dir(c_cert, c_key, tmp_path, "cli")
    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="emit-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_p, cert=srv[0], key=srv[1]),
    )
    # The serial the gate will actually read off the established connection
    # (`getpeercert()["serialNumber"]`, uppercase hex, leading zeros per OpenSSL), plus its unpadded
    # form — the peer arm matches on the canonical serial, so both shapes are offered rather than
    # guessed at.
    padded = f"{c_cert.serial_number:016X}"
    return SimpleNamespace(
        ca=ca_p,
        srv=srv,
        client=cli,
        config=config,
        client_serials={padded, padded.lstrip("0") or "0", f"{c_cert.serial_number:X}"},
    )


def _start_with(emit_pk, state, factory=None):
    fake = _FakeExec(result=_ok_result())
    sessions: list = []
    listener = _start(emit_pk.config, factory or _factory(fake, sessions), [ALLOWED], state=state)
    return listener, fake, sessions


def _raw_handshake(emit_pk, port, send_bytes: bytes = b"", read_until: float = 3.0) -> bytes:
    """Complete a real TLS handshake as an allowed client, optionally send NOTHING, and read.

    Returns every byte the listener chose to write. This is how the "no request byte is read"
    clause is measured rather than claimed: with ``send_bytes=b""`` the peer never transmits an
    HTTP request, so any response bytes can only have come from a write that did not read.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(emit_pk.ca)
    ctx.load_cert_chain(emit_pk.client[0], emit_pk.client[1])
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname="relay")
    collected = b""
    try:
        if send_bytes:
            tls.sendall(send_bytes)
        tls.settimeout(read_until)
        while True:
            try:
                chunk = tls.recv(4096)
            except (ssl.SSLError, OSError):
                # A refusal closes the socket mid-read; the bytes collected so far ARE the answer.
                break
            if not chunk:
                break
            collected += chunk
    finally:
        try:
            tls.close()
        except OSError:
            pass
    return collected


# -----------------------------------------------------------------------------------------
# 1. AC1 positive — the fault class answers on the wire, over real mTLS
# -----------------------------------------------------------------------------------------


class TestFaultClassAnswersOnTheWire:
    def test_unanswered_boot_answers_503_with_the_literal(self, emit_pk):
        """The core has not answered this boot: the refusal now carries REFUSE_NO_ANSWER as a detail."""
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert resp.status_code == 503, resp.text
        assert resp.json()["detail"] == REFUSE_NO_ANSWER, resp.json()
        assert resp.json()["detail"].startswith("503 OPERATIONAL FAULT — "), "the class name is the contract"

    def test_unwired_state_answers_503_with_the_other_literal(self, emit_pk):
        """A listener with nothing wired answers its OWN sentence — not the unanswered boot's."""
        bare = RelayListener(emit_pk.config, lambda _sid: None, [ALLOWED], host="127.0.0.1", port=0)
        bare.start()
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(bare), json=_payload())
        finally:
            bare.stop()
        assert resp.status_code == 503, resp.text
        assert resp.json()["detail"] == REFUSE_NOT_WIRED, resp.json()

    def test_the_notice_is_valid_http_a_strict_client_accepts_it(self, emit_pk):
        """Status line, Content-Type, Content-Length, and a body that parses.

        A malformed notice is worse than none: the core's arm would fall to a transport class and the
        operator would get a vaguer sentence than before. So the SHAPE is asserted, not just the text.
        """
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert resp.headers.get("content-type") == "application/json", resp.headers
        assert resp.headers.get("connection", "").lower() == "close", resp.headers
        body = resp.content
        assert int(resp.headers["content-length"]) == len(body), (resp.headers["content-length"], len(body))
        assert set(resp.json()) == {"detail"}, resp.json()

    def test_the_admitted_path_is_untouched(self, emit_pk):
        """Paired positive for the whole row: an answered, live credential still runs the command."""
        listener, _fake, sessions = _start_with(emit_pk, _state(answered=True))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert resp.status_code == 200, resp.text
        assert sessions == ["s1"], sessions


# -----------------------------------------------------------------------------------------
# 2. THE NOTICE NEEDS NO REQUEST — the clause the design tension turns on
# -----------------------------------------------------------------------------------------


class TestNoticeIsWrittenWithoutReading:
    def test_a_peer_that_sends_zero_request_bytes_still_gets_the_notice(self, emit_pk):
        """The refusal still happens before any request byte is read — measured, not asserted in prose.

        Handshake only. The peer transmits NOTHING past the TLS ClientHello/Finished. If the notice
        depended on reading a request, this would collect zero bytes; it collects the whole 503. That
        is the difference between keeping #586's ruled window and quietly moving it.
        """
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        port = listener.port
        try:
            collected = _raw_handshake(emit_pk, port, send_bytes=b"")
        finally:
            listener.stop()
        text = collected.decode("utf-8", "replace")
        assert text.startswith("HTTP/1.1 503"), repr(text[:80])
        assert REFUSE_NO_ANSWER in text, repr(text[:200])

    def test_the_notice_never_echoes_anything_the_peer_sent(self, emit_pk):
        """A canary in the request body must not appear in the refusal.

        The body is built from a module constant, so this cannot fail by construction — which is
        exactly why it is worth a cell: the #410 control on the core side exists because the 400 lane
        DOES echo, and a refusal notice that echoed would put request content on a screen that was
        never authorised to see it.
        """
        canary = "CANARY-do-not-echo-9f3c"
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json={"session_id": canary, "command": [canary], "secrets": []})
        finally:
            listener.stop()
        assert canary not in resp.text, resp.text
        assert resp.json()["detail"] == REFUSE_NO_ANSWER


# -----------------------------------------------------------------------------------------
# 3. AC2 — the OTHER classes still behave exactly as shipped (the negative half)
# -----------------------------------------------------------------------------------------


class TestRevocationClassStaysSilent:
    def test_revoked_credential_gets_no_http_response_at_all(self, emit_pk):
        """The 403 class is an ASSERTION about a credential, and it is not broadcast.

        Shipped behavior, kept byte-for-byte: the connection closes with no response, so a peer cannot
        use the wire to enumerate which credentials a registry has killed.
        """
        listener, _fake, _sessions = _start_with(emit_pk, _state(revoked=True))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                with pytest.raises(httpx2.RequestError) as excinfo:
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert getattr(excinfo.value, "response", None) is None, "the revoked class answered HTTP — that is a leak"

    def test_revoked_credential_gets_no_notice_bytes_on_a_handshake_only_peer(self, emit_pk):
        """The same clause through the raw door: zero response bytes, not an error-shaped response."""
        listener, _fake, _sessions = _start_with(emit_pk, _state(revoked=True))
        port = listener.port
        try:
            collected = _raw_handshake(emit_pk, port, send_bytes=b"")
        finally:
            listener.stop()
        assert collected == b"", repr(collected[:120])

    def test_peer_classes_are_out_of_scope_and_stay_silent(self, emit_pk):
        """REFUSE_PEER_* are named in the spec as out of scope; this pins that they did not move.

        A peer-serial refusal is decided AFTER the state gate admits, so the state here is
        answered-and-live (the fault class cannot fire) with the peer's OWN serial on the revoked list
        — the only shape that reaches the peer arm over a real handshake.
        """
        listener = _start(
            emit_pk.config,
            _factory(_FakeExec(result=_ok_result()), []),
            [ALLOWED],
            state=_state(revoked_relay_serials=emit_pk.client_serials),
        )
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                with pytest.raises(httpx2.RequestError) as excinfo:
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert getattr(excinfo.value, "response", None) is None

    def test_the_class_predicate_names_only_the_two_faults(self):
        """One predicate decides which class speaks, so it is asserted against all five literals.

        The peer classes and the revocation class must be False: an identity test that drifted to a
        prefix would let ``403 REVOKED`` through the same door.
        """
        assert is_operational_fault_refusal(REFUSE_NO_ANSWER) is True
        assert is_operational_fault_refusal(REFUSE_NOT_WIRED) is True
        for other in (REFUSE_REVOKED, REFUSE_PEER_REVOKED, REFUSE_PEER_EXECUTOR_REVOKED):
            assert is_operational_fault_refusal(other) is False, other
        # And the near-miss shapes that a prefix test would have accepted:
        assert is_operational_fault_refusal("503 OPERATIONAL FAULT — a different sentence") is False
        assert is_operational_fault_refusal(None) is False

    def test_the_writer_refuses_to_send_for_a_non_fault_reason(self):
        """The gate is INSIDE the writer too, not only at the call site — belt and braces.

        A future arm that calls this with a revocation string must not become a broadcast path.
        """
        sink = _RecordingConn()
        assert send_refusal_notice(sink, REFUSE_REVOKED) is False
        assert sink.writes == [], "a non-fault class wrote bytes"
        assert send_refusal_notice(_BrokenConn(), REFUSE_NO_ANSWER) is False, "a failed write must not raise"


class _RecordingConn:
    """A connection double: records what was written, never moves bytes."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.writes.append(data)


class _BrokenConn:
    def settimeout(self, _t: float) -> None:
        raise OSError("closed")

    def sendall(self, _data: bytes) -> None:
        raise OSError("closed")


# -----------------------------------------------------------------------------------------
# 4. A refusal is still a refusal
# -----------------------------------------------------------------------------------------


class TestNoticeIsNotAnAdmission:
    def test_the_engine_is_never_reached_for_the_fault_class(self, emit_pk):
        """The notice carries a reason AND still runs nothing."""

        def _never(_sid):  # pragma: no cover - must not run
            raise AssertionError("the notice let a refused connection through to the engine")

        listener = _start(emit_pk.config, _never, [ALLOWED], state=_state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert resp.status_code == 503, resp.text
        assert "exit_code" not in resp.text

    def test_the_gate_still_closes_the_connection(self, emit_pk):
        """After the notice the socket is finished: a second request on the same connection fails."""
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        port = listener.port
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(emit_pk.ca)
        ctx.load_cert_chain(emit_pk.client[0], emit_pk.client[1])
        req = b"POST /execute HTTP/1.1\r\nhost: relay\r\ncontent-length: 0\r\n\r\n"
        try:
            tls = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname="relay")
            try:
                tls.sendall(req)
                first = tls.recv(4096)
                assert first.startswith(b"HTTP/1.1 503"), repr(first[:60])
                tls.settimeout(3)
                # A refusal closes the socket, so the next read returns nothing or reports the reset;
                # both mean "this connection is finished", which is the clause. A keep-alive that
                # admitted a second request would answer with another response instead.
                try:
                    second = tls.recv(4096)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    second = b""
            finally:
                tls.close()
        finally:
            listener.stop()
        assert second == b"", "the connection stayed open after the notice — that is keep-alive on a refusal"

    # -----------------------------------------------------------------------------------------
    # 5. The accept loop survives a peer that will not read
    # -----------------------------------------------------------------------------------------

    def test_the_real_door_bytes_satisfy_the_receiving_door(self, emit_pk):
        """THE SEAM CELL — the bytes this door wrote, read by the code that decides what to forward.

        No synthetic response is built here: a real mTLS client dials a real listener in the fault
        state, and the resulting **real** ``httpx2.Response`` is handed to the core's own forwarding
        helpers (``_relay_refusal_detail`` + ``OPERATIONAL_FAULT_DETAIL_PREFIX``, imported from
        ``server.routes.executors`` — a test reading product code, the precedent being
        ``packages/executor/tests/test_integration.py`` importing ``server``).

        This is the link that makes the two halves one row rather than two near-misses: leg 404 proves
        the route forwards a literal it is handed; this proves the door HANDS it, byte for byte.
        """
        from server.routes.executors import (
            GENERIC_RELAY_ERROR_DETAIL,
            OPERATIONAL_FAULT_DETAIL_PREFIX,
            _relay_refusal_detail,
        )

        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
            # Reproduce the core arm's own read of a real response: raise_for_status ->
            # HTTPStatusError -> e.response. Same object, no re-typed body.
            with pytest.raises(httpx2.HTTPStatusError) as excinfo:
                resp.raise_for_status()
            relayed = excinfo.value.response
        finally:
            listener.stop()

        assert relayed.status_code == 503
        detail = _relay_refusal_detail(relayed)
        assert detail == REFUSE_NO_ANSWER, detail
        # The receiving door's actual predicate, applied to the real bytes:
        assert detail.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX), "the two halves do NOT meet"
        assert detail != GENERIC_RELAY_ERROR_DETAIL

    def test_the_unwired_door_bytes_satisfy_the_receiving_door_too(self, emit_pk):
        """The second literal, same seam — a listener with no state wired is the rarer half."""
        from server.routes.executors import OPERATIONAL_FAULT_DETAIL_PREFIX, _relay_refusal_detail

        bare = RelayListener(emit_pk.config, lambda _sid: None, [ALLOWED], host="127.0.0.1", port=0)
        bare.start()
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(bare), json=_payload())
        finally:
            bare.stop()
        detail = _relay_refusal_detail(resp)
        assert detail == REFUSE_NOT_WIRED, detail
        assert detail.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX)


class TestAcceptLoopSurvivesASilentPeer:
    def test_an_unread_notice_does_not_stall_the_next_connection(self, emit_pk):
        """The single-threaded accept path must not be hostage to a peer that never reads.

        A raw peer handshakes, reads NOTHING back, and is left to the bounded notice timeout. The very
        next real dial must still be refused properly — proving the notice is bounded, not blocking.
        """
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        port = listener.port
        stranded = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(emit_pk.ca)
            ctx.load_cert_chain(emit_pk.client[0], emit_pk.client[1])
            stranded = ctx.wrap_socket(
                socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname="relay"
            )
            # The notice is written to us and we deliberately never read it.
            assert stranded is not None
            with _client(emit_pk.ca, emit_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
            assert resp.status_code == 503, resp.text
            assert resp.json()["detail"] == REFUSE_NO_ANSWER
        finally:
            if stranded is not None:
                try:
                    stranded.close()
                except OSError:
                    pass
            listener.stop()


# -----------------------------------------------------------------------------------------
# 6. The shipped records are undisturbed
# -----------------------------------------------------------------------------------------


class TestJournalAndAuditStillFire:
    def test_the_fault_journal_line_is_unchanged_apart_from_the_delivery_note(self, emit_pk, caplog):
        """The grep-able string a 3 a.m. reader uses still starts the same way.

        #586's ruled vocabulary is a journal contract; this row may ADD a delivery note, it may not
        re-flow the sentence. Asserted on the prefix the runbook table tells people to search for.
        """
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        lines = _relay_lines(caplog)
        assert len(lines) == 1, lines
        assert lines[0].startswith("Relay :8443 refused a new connection from "), lines[0]
        assert REFUSE_NO_ANSWER in lines[0], lines[0]

    def test_the_revoked_journal_line_is_byte_identical_to_shipped(self, emit_pk, caplog):
        """Nothing about the 403 class's record moved — no delivery note, no new wording."""
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        listener, _fake, _sessions = _start_with(emit_pk, _state(revoked=True))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        lines = _relay_lines(caplog)
        assert len(lines) == 1, lines
        assert "notice" not in lines[0].lower(), lines[0]
        assert REFUSE_REVOKED in lines[0], lines[0]

    def test_the_refusal_recorder_still_receives_the_reason(self, emit_pk):
        """The audit spool copy is unchanged: same callable, same three arguments, same reason."""
        recorded: list = []
        listener = _start(
            emit_pk.config, _factory(_FakeExec(result=_ok_result()), []), [ALLOWED], state=_state(answered=False)
        )
        listener._server.refusal_recorder = lambda reason, host, port: recorded.append((reason, host, port))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert len(recorded) == 1, recorded
        assert recorded[0][0] == REFUSE_NO_ANSWER, recorded

    def test_a_failed_notice_write_never_breaks_the_refusal_or_the_record(self, emit_pk, caplog, monkeypatch):
        """The notice is a courtesy, never a dependency: if it cannot be written, the row still holds.

        Forced by patching the writer to fail, so the shipped path (close + journal + audit +
        ConnectionRefusedError) is exercised with the notice absent. Asserted on all three:
        the peer still gets no response, the journal still names the class, and it says the notice
        did not go out.
        """
        import executor.relay_listener as rl

        monkeypatch.setattr(rl, "send_refusal_notice", lambda _conn, _reason: False)
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        listener, _fake, _sessions = _start_with(emit_pk, _state(answered=False))
        try:
            with _client(emit_pk.ca, emit_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        lines = _relay_lines(caplog)
        assert len(lines) == 1, lines
        assert REFUSE_NO_ANSWER in lines[0], lines[0]
        assert "notice not delivered" in lines[0], lines[0]
