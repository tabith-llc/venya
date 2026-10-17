# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor-side mTLS relay listener (B0.1 / B0.2 / B0.3).

Receives ``POST /execute`` on :8443 from the core server over mTLS and runs the
command via the existing :class:`~executor.executor.Executor.execute()` engine.

This is the receiver half of the execution relay. The core is the TLS *client*;
it presents a client certificate and verifies this executor's leaf certificate.
The executor requires a client certificate (``CERT_REQUIRED``) and, after the
handshake, rejects any peer whose CN is not an explicitly configured relay
client (``relay_client_ids``).

Transport is stdlib (``http.server`` + ``ssl.SSLContext``). The wire shape comes
from ``venya_contract`` (pydantic) — the frozen relay contract shared with the
server, so a one-sided field change is an import/type error, not a runtime drift.

RF-3 (2026-10-11): the listener threads. Admission is a
``threading.Semaphore`` in the handler, sized by
``VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS`` / ``[executor]
max_concurrent_commands``; the shipped default is 1.
"""

import json
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pydantic import ValidationError
from venya_contract import RelayRequest, RelayResponse

from .executor import CommandRejected
from .key_passphrase import ssl_password_callback

logger = logging.getLogger("venya.executor.relay")

RELAY_PORT = 8443

# Request-body cap. Derivation (ticket relay-listener-body-cap-and-timeout):
# the wire protocol has NO hard maximum — core bounds its own ingress with
# max_request_body_bytes (default 1 MiB, operator-raisable to 100 MB) and a
# session's secret_keys list is unbounded (each wrapped_value ≈ value×4/3).
# 16 MiB covers a default-cap command plus ~11 max-size wrapped secrets with
# margin; it bounds a misbehaving authenticated peer's nominal allocation
# (multi-GB Content-Length) without tightening the legitimate contract. If an
# operator raises core's max_request_body_bytes past ~12 MiB, this constant
# needs a matching knob (refactor-1 config-consolidation territory).
MAX_RELAY_BODY_BYTES = 16 * 1024 * 1024

# Per-socket-operation INACTIVITY timeout (not a total-duration ceiling):
# socketserver applies it via connection.settimeout, so a slow-but-steady
# transfer of any size never trips it, while a silent peer releases its handler
# thread well below SBX_TIMEOUT (1h) and inside one heartbeat interval.
# HTTP/1.0 (BaseHTTPRequestHandler default) closes the connection after every
# response, so no keep-alive idle clock exists. Residual: a byte-trickle peer
# can still hold its handler — bounded in practice by core's own httpx2 client
# timeout (300s), after which the socket EOFs. Threat model is a misbehaving
# AUTHENTICATED peer (mTLS + CN allowlist), not an adversarial one.
RELAY_READ_TIMEOUT_SECONDS = 30.0

# #477 (relay-stop-unbounded-skips-cleanup-under-systemd): the bound stop()
# waits for in-flight command(s) to finish and their teardown to run. RF-3 made
# this "command(s)": the listener threads, so shutdown() no longer implies the
# engine is done — stop() now bounds the wait by taking every admission permit
# (see RelayListener.stop). The bound itself is unchanged: an unwaited shutdown
# was unbounded (a command may run to SBX_TIMEOUT = 1h) — and systemd's default
# stop deadline then SIGKILLed the process, skipping the sandbox-removal
# finally and the temp cleanup. 30 s keeps a normal restart prompt; the unit
# declares TimeoutStopSec=45s so systemd's kill lands only AFTER this bound +
# margin for the remaining teardown steps (a static interlock guards the two
# values — see tests/test_relay_stop_477.py). A command outliving the bound is
# logged and left to the boot-reaper pairing row; overflow can never again be
# a silent skip without a journal trace.
RELAY_STOP_DEADLINE_SECONDS = 30.0


class ExecuteHandler(BaseHTTPRequestHandler):
    """Handle ``POST /execute`` with mTLS mutual authentication.

    Identity (B0.3) is the *parsed* CN of the peer certificate, compared by
    exact match — case- and whitespace-sensitive, no normalization. A CN bound
    for ``TLS`` peer verification; the same CN is what the operator allowlists.

    Bodies are fixed-length only: ``BaseHTTPRequestHandler`` never decodes
    ``Transfer-Encoding: chunked``, and a chunked request (no Content-Length)
    reads zero bytes and is rejected 400 as malformed — a documented protocol
    assumption, matching the core client (``httpx2.post(json=...)`` always
    sends Content-Length).
    """

    # Inactivity ceiling for every blocking socket op on this connection
    # (header read, body read, response write); see RELAY_READ_TIMEOUT_SECONDS.
    timeout = RELAY_READ_TIMEOUT_SECONDS

    # Silence default per-request stderr logging.
    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/execute":
            self._reply(404, {"detail": "not found"})
            return

        # B0.3: the presented cert must map to an allowed relay client identity.
        # Exact, case-sensitive match against the configured allow-list.
        peer_cn = self._peer_common_name()
        if peer_cn is None or peer_cn not in self.server.allowed_client_ids:  # type: ignore[attr-defined]
            logger.warning("Relay /execute rejected: peer CN %r not allowed", peer_cn)
            self._reply(403, {"detail": "unknown client identity"})
            return

        # #477: no NEW commands once draining. The flag is set before the
        # serve_forever shutdown is requested, so a peer racing the teardown
        # gets the flat 503 lane (same no-retry treatment as an execution
        # failure) instead of queueing behind a shutdown in progress.
        draining = getattr(self.server, "draining", None)
        if draining is not None and draining.is_set():
            logger.warning("Relay /execute rejected: executor is draining (shutdown in progress)")
            self._reply(503, {"detail": "executor is draining (shutdown in progress)"})
            return

        # Body-size guard BEFORE any read/allocation: reject absurd or
        # negative Content-Length without touching the socket payload.
        # (Negative would otherwise mean read-until-EOF — an unbounded hang.)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError as exc:
            self._reply(400, {"detail": f"malformed Content-Length: {exc}"})
            return
        if length < 0:
            self._reply(400, {"detail": "invalid Content-Length"})
            return
        if length > MAX_RELAY_BODY_BYTES:
            logger.warning(
                "Relay /execute rejected: Content-Length %d exceeds cap %d (peer CN %r)",
                length,
                MAX_RELAY_BODY_BYTES,
                peer_cn,
            )
            self._reply(413, {"detail": "request body exceeds relay cap"})
            return

        # Parse + normalize the payload via the frozen relay contract
        # (venya_contract). ``wrapped_value`` arrives as a JSON string; the executor
        # engine's ``strip_sentinel()`` requires bytes, so the str->bytes mapping
        # happens here — an executor-internal concern, not part of the wire shape.
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            req = RelayRequest(**body)
        except (ValueError, ValidationError, UnicodeDecodeError) as exc:
            self._reply(400, {"detail": f"malformed request: {exc}"})
            return
        session_id = req.session_id
        # argv list, verbatim from the frozen contract (ticket
        # execution-command-wire-unstructured-string #322, ruling Q1=A1):
        # boundaries are preserved into the engine, which runs them DIRECT
        # in the sandbox; the sh -c form is kept only for the ruled
        # session-bound `<` case (ruling Q3=C3, leg B landed).
        command = req.command
        secrets = [
            {
                "secret_id": s.secret_id,
                "wrapped_value": s.wrapped_value.encode("utf-8"),
            }
            for s in req.secrets
        ]

        # B0.2: wire to the existing engine. The factory is wired to
        # ExecutorDaemon.create_executor in production; tests inject a stub.
        #
        # RF-3 admission point. The permit is taken HERE — after identity, drain
        # and body-cap gates have all been answered, and around the execution
        # section only — so the work that parallelises is the engine call, not
        # the parse. Consequences a reader should not have to rediscover:
        #   * a peer over cap WAITS (RF-2 ruling: queue inside the core's 300 s
        #     relay budget — deliberately not a 503 and not a Retry-After); the
        #     block is ``acquire()`` with no timeout, so the wait is ended by the
        #     peer giving up or by a slot freeing, never by a synthesized error;
        #   * waiting costs a thread + an fd + a COMPLETED mTLS handshake. The
        #     single-threaded listener refused that peer in the kernel accept
        #     backlog before it ever handshook. Admission outcome at cap=1 is
        #     unchanged (one command at a time); the handshake/queue timing is not
        #     identical, and this code does not claim that it is — see
        #     RelayListener's docstring and tests/test_relay_threading_rf3.py.
        #   * the server-side SSL context is SHARED by concurrent handshakes,
        #     but it is no longer mutated in place: a rotation publishes a whole
        #     new context and each accepted connection is wrapped with whatever
        #     is current at accept time (``_RelayHTTPServer``, GitLab #579). An
        #     in-flight handshake finishes on the context it started with.
        slots = getattr(self.server, "command_slots", None)  # type: ignore[attr-defined]
        if slots is not None:
            slots.acquire()
        try:
            # #477 again, AFTER admission: a peer that queued while a command ran
            # must not start a new command once the drain has begun. One check
            # before the read cannot say that, because the queue itself is new.
            draining = getattr(self.server, "draining", None)
            if draining is not None and draining.is_set():
                logger.warning("Relay /execute rejected at admission: executor is draining (shutdown in progress)")
                self._reply(503, {"detail": "executor is draining (shutdown in progress)"})
                return

            # Per the plan's failure-mode table, any execution failure is a flat 503
            # (no retry), which also covers sandbox/subprocess timeouts surfacing as
            # exceptions from the engine. ONE carve-out (ticket policy-reject-flat-503
            # #410): a CommandRejected from the pre-run gates is not an execution
            # failure — nothing ran — and takes a 422-with-reason lane.
            # env/askpass specs (ticket secret-shape-env-injection) pass through
            # as plain dicts; secret_id -> plaintext resolution happens inside
            # execute() where the unwrapped bundles live — the listener never
            # touches plaintext.
            env_vars = [e.model_dump() for e in req.env] if req.env else None
            executor: Any = None
            try:
                # The factory call stays INSIDE the try: before this change a raising
                # factory was covered by the flat 503 lane, and that has to keep
                # holding. ``executor`` is initialised to None so the finally below
                # still runs when the factory itself raises.
                executor = self.server.executor_factory(session_id)  # type: ignore[attr-defined]
                result = executor.execute(command, secrets, env_vars=env_vars, askpass_helper=req.askpass_helper)
            except CommandRejected as exc:
                # The reason describes the CALLER's own command (both gates run
                # before injection, so secret material is structurally absent) —
                # safe to surface. 422 is the deliberately-distinct code: the
                # listener's 400 lane echoes request-body fragments in its
                # details, so the server forwards ONLY this status's detail
                # onward (routes/executors.py, #410 hop).
                logger.warning("Relay /execute policy rejection for session %s: %s", session_id, exc)
                self._reply(422, {"detail": str(exc)})
                return
            except Exception:
                logger.exception("Relay /execute failed for session %s", session_id)
                self._reply(503, {"detail": "execution failed"})
                return
            finally:
                # #467: this is the code that ends the session, so this is where the
                # session's AuditLogger forwarder is stopped. It runs on every lane,
                # including a raising engine, so a session cannot leak its 1 s-poll
                # thread. The hasattr guard keeps the injected stubs in
                # test_relay_listener / test_relay_stop_477 — which model the engine,
                # not a closable session — exactly as they are.
                close = getattr(executor, "close", None)
                if callable(close):
                    close()

            self._reply(
                200,
                RelayResponse(
                    exit_code=result.exit_code,
                    stdout=result.stdout.decode("utf-8", "replace"),
                    stderr=result.stderr.decode("utf-8", "replace"),
                    masked_count=len(result.masked_secret_ids),
                ).model_dump(),
            )
        finally:
            # RF-3: the permit is returned only after the response is written and
            # the engine teardown (the inner finally above) has run, so a slot is
            # never handed to the next peer while this command is still alive.
            # Every lane above releases: success, 422, 503 and the early drain
            # return all leave through this finally.
            if slots is not None:
                slots.release()

    def _peer_common_name(self) -> str | None:
        """Return the parsed CN from the peer (client) certificate, or None.

        ``getpeercert()`` is populated only after a client certificate was
        presented and validated. With ``CERT_REQUIRED`` a successful handshake
        guarantees a peer cert; this returns None only for an absent CN attr.
        """
        cert = self.connection.getpeercert() or {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return None

    def _reply(self, status_code: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# --- #586 accept gate: the two refusal classes, named ------------------------------
# A refused connection never receives an HTTP response (the refusal happens before
# a single request byte is read), so the owner's ruled status split lives in these
# STRINGS: 403 = revoked, 503 = operational fault. A 3 a.m. reader must be able to
# tell "this credential was killed" from "this daemon cannot tell either way".
REFUSE_REVOKED = "403 REVOKED — this executor's credential is revoked server-side"
REFUSE_NO_ANSWER = (
    "503 OPERATIONAL FAULT — no revocation answer received this boot "
    "(the core has neither confirmed nor revoked this credential; check core reachability)"
)
REFUSE_NOT_WIRED = (
    "503 OPERATIONAL FAULT — the relay listener holds no daemon state, so revocation " "cannot be consulted at all"
)
# #597: the peer class this door can now actually name. Distinct from REFUSE_REVOKED,
# which is about THIS executor's own credential — a message that said "your credential
# is revoked" to a CORE whose relay cert was revoked would describe an event that did
# not happen to it.
REFUSE_PEER_REVOKED = "403 REVOKED — the peer's core relay credential is revoked (registry membership, #597)"


def revocation_accept_reason(state: Any) -> str | None:
    """Accept-gate verdict for one NEW :8443 connection; None admits.

    SINGLE RULEBOOK, AS A CACHE (#586 STEP 0). This reads the ONE already-computed
    answer on this side — ``DaemonState.revoked`` — plus a boot-scope flag that says
    whether the core has ANSWERED the revocation question at all this boot. It holds
    no copy of the revocation list and implements no serial or identity matching:
    ``server/revocation.py`` (module contract comment) names a second implementation
    as the rotation/revocation split-brain, and at :8443 the peer is the CORE's
    relay-client credential, which the EXECUTOR-serial list never describes — a
    peer-serial test here would be a second rulebook AND one that cannot match.

    Fail-closed on "cannot consult" (DoD point 3, #586 acceptance 6): no state wired,
    and no answer yet this boot, both refuse. Once answered the flag stays answered —
    a later outage is already bounded by ``cert_rotation.max_revocation_failures``,
    which carries a #603 fault reason (``state.revocation_fault_reason``) and takes the
    listener down with the daemon; it does NOT set ``state.revoked``, because no answer
    is a server-side revocation claim.
    """
    if state is None:
        return REFUSE_NOT_WIRED
    if getattr(state, "revoked", False):
        return REFUSE_REVOKED
    if getattr(state, "revocation_fault_reason", None) is not None:
        # #603: the threshold tripped with no answer ever arriving — same 503 class as
        # a boot that was never answered, never the 403 revocation claim.
        return REFUSE_NO_ANSWER
    if not getattr(state, "revocation_answered", False):
        return REFUSE_NO_ANSWER
    return None


def peer_revocation_refusal(state: Any, peer_serial: str | None) -> str | None:
    """#597: refuse a NEW :8443 connection whose PEER credential is revoked; None admits.

    Keyed on REGISTRY MEMBERSHIP and nothing else. There is deliberately no staleness
    arm here: the list this matches against is refreshed by the same ~30 s poll that
    answers the executor's own revocation question, and adding an age-based stop to a
    door whose revocation source is a 1-hour-stamped artifact is the fleet-wide outage
    #586 measured and the owner has not agreed to. Refusing an unknown peer would be the
    other failure: the CN allowlist, not this set, decides who may connect at all.

    ``peer_serial`` is the presented client certificate's serial in ANY spelling; both
    sides go through ``serial_match_key`` (#481), so a padded row and an unpadded
    certificate still meet.

    None state, no population yet, and no peer serial each ADMIT — this function only
    ever removes a connection the registry has named dead. It cannot be the reason a
    healthy core is refused, which is the exact property that made #586 option 3
    unacceptable.
    """
    if state is None or peer_serial is None:
        return None
    revoked = getattr(state, "revoked_relay_serials", None)
    if not revoked:
        return None
    from core.utils.cert_serial import serial_match_key

    if serial_match_key(peer_serial) in {serial_match_key(s) for s in revoked}:
        return REFUSE_PEER_REVOKED
    return None


class _RelayHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server that TLS-wraps each ACCEPTED connection.

    The listening socket is deliberately left plain and the wrap happens in
    ``get_request``, after the accept. GitLab #579: wrapping the listening
    socket welds ONE ``SSLContext`` to the port for the life of the process, so
    a certificate rotation that rewrites the files on disk is never presented
    on :8443 until the daemon restarts.

    With the wrap moved to accept time, ``RelayListener`` can publish a freshly
    built context and every NEW connection is served the new leaf, while a
    handshake already in flight finishes on the context it started with. The
    live ``SSLContext`` is never mutated, which is what keeps this safe under
    RF-3's concurrent handshakes: swapping a reference is atomic under the GIL,
    mutating a shared OpenSSL CTX under a concurrent handshake is not.

    #586 builds the revocation gate BESIDE that path, not inside it: after the
    handshake completes and before the socket reaches a handler, the published
    state is consulted and a refused connection is closed. No request byte is
    read, no handler thread starts, and the refusal is journalled — the listener
    asserts the refusal itself, so the control is not the daemon's cooperative
    stop wearing a different hat.

    The ``relay_ssl_context`` attribute is set by ``RelayListener.start()``, and so
    is ``revocation_state``; an absent state is "cannot consult", which refuses.
    """

    relay_ssl_context: ssl.SSLContext
    revocation_state: Any = None
    # Optional callable ``(reason, host, port)`` — the durable record of one refusal.
    # None is not a failure: the journal line always fires, and the spool copy exists
    # only where the daemon has an audit sink wired.
    refusal_recorder: Callable[[str, str, int], None] | None = None

    def get_request(self):
        conn, addr = self.socket.accept()
        try:
            tls_conn = self.relay_ssl_context.wrap_socket(conn, server_side=True)
        except OSError:
            # A refused handshake (no client cert / foreign CA) must not leak the
            # accepted fd, and must stay the OSError the serve loop already
            # swallows — the shape the wrapped-listener accept path had.
            conn.close()
            raise
        reason = revocation_accept_reason(self.revocation_state)
        if reason is None:
            # #597: the door may also refuse because the PEER is dead, not because this
            # daemon cannot tell. Read off the established connection's client
            # certificate, so it is the credential that was actually presented — never a
            # header and never a name lookup. Placed after the state gate so an
            # unanswered daemon refuses first: that answer is about this executor, and
            # claiming to know about the peer while not knowing about ourselves would be
            # the louder lie of the two.
            peer_serial = None
            try:
                peer_serial = tls_conn.getpeercert().get("serialNumber")
            except (OSError, ValueError):
                # No readable peer serial admits (see peer_revocation_refusal): this
                # function's only power is to refuse a serial the registry named.
                peer_serial = None
            reason = peer_revocation_refusal(self.revocation_state, peer_serial)
        if reason is None:
            return tls_conn, addr
        # Post-handshake refusal — the owner's option 3, and its named window: the
        # credential was admitted by the handshake and is refused here, before any
        # request bytes. ConnectionRefusedError is an OSError, which is the shape
        # ``socketserver._handle_request_noblock`` already swallows from this hook.
        try:
            tls_conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        tls_conn.close()
        host, port = (addr, 0) if isinstance(addr, str) else (addr[0], addr[1])
        logger.warning("Relay :8443 refused a new connection from %s:%s — %s", host, port, reason)
        recorder = self.refusal_recorder
        if recorder is not None:
            try:
                recorder(reason, host, port)
            except Exception:
                # A failed audit write must never turn a refusal into an accept-loop
                # crash, and never silently: name it in the journal.
                logger.exception("Relay refusal audit write failed (peer %s:%s)", host, port)
        raise ConnectionRefusedError(reason)


class RelayListener:
    """Run the mTLS relay listener in a background thread.

    ``ThreadingHTTPServer`` + a ``threading.Semaphore(cap)`` admission permit,
    taken in the handler around the execution section (RF-3). ``cap`` comes from
    the one knob, pinned by the owner 2026-10-11 as both
    ``VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS`` (env) and
    ``[executor] max_concurrent_commands`` (TOML); the shipped default is **1**.
    The listener still runs in its own daemon thread so it never contends with
    the reaper, heartbeat, or revocation loops.

    WHAT DEFAULT 1 DOES AND DOES NOT REPRODUCE — stated honestly, because the
    carrier's old "byte-identical" wording described a property this design does
    not have. At cap=1 the ADMISSION OUTCOME is the same as the single-threaded
    listener: one command runs at a time, and a second arrival never reaches the
    engine while the first holds the permit. The HANDSHAKE TIMING is not the
    same. Today an over-cap arrival is refused in the kernel accept backlog
    (``socketserver.TCPServer.request_queue_size``, 5 on the shipped
    interpreter) and never completes a TLS handshake; with admission in the
    handler it is accepted, handshakes against the shared server context, and
    holds a thread plus an fd while it waits. Pinned by
    ``tests/test_relay_threading_rf3.py``.

    OPEN DECISION THAT GATES ANY DEFAULT ABOVE 1 (owner's call, recorded here so
    the next reader does not re-derive it): WHERE the queue should live.
      (i)  backlog admission — a connection-level limit keeps refused-before-
           handshake at cap=1, but past ``request_queue_size`` it is a kernel
           refusal, not a queue, which is the accident RF-2's ruling says must
           not be inherited as a spec;
      (ii) handler admission — what this code implements: a real queue that
           waits inside the core's 300 s relay budget (not a 503, not a
           Retry-After), at the cost of a thread + fd + completed handshake per
           waiting peer.
    cap=1 is safe under either shape, so this half ships at (ii) with the
    default still 1. Raising the default above 1 is gated on that ruling AND on
    the two bench cells RF-2 makes mandatory (cross-command leak, pool-before-
    listener); neither has run, and the isolation property that serialization
    used to give for free is now an ACCEPTANCE-CHECKED property, not an assumed
    one. The cap's ceiling is RAM-derived from the measured per-sandbox
    footprint — this file deliberately holds no fixed maximum.

    Anti-confusion: ``daemon.py``'s ``ThreadPoolExecutor(max_workers=2)`` is the
    HTTP/heartbeat pool, NOT command execution.
    """

    def __init__(
        self,
        config: Any,
        executor_factory: Callable[[str], Any],
        allowed_client_ids: list[str],
        host: str = "0.0.0.0",  # nosec B104 — private relay net; mTLS CERT_REQUIRED + CN allowlist is the access control
        port: int = RELAY_PORT,
        state: Any = None,
    ) -> None:
        self._config = config
        self._executor_factory = executor_factory
        self.allowed_client_ids = frozenset(allowed_client_ids)
        self._host = host
        self._port = port
        # #586: the ONE revocation answer this side holds, published by the daemon's
        # main loop (``DaemonState.revoked`` + ``revocation_answered``). Held by
        # reference and read per accept, so a revocation that lands mid-life reaches
        # the gate without a restart. None = nothing wired = refuse.
        self.revocation_state = state
        # #586: the durable audit sink for refusals. The daemon assigns this after
        # its boot spool forwarder exists (that forwarder is built later, in
        # ``start()``), so it is a public attribute read per refusal rather than a
        # constructor argument. None = journal only (see ``_record_refusal``'s
        # shortcut note).
        self.refusal_sink: Any = None
        self._server: _RelayHTTPServer | None = None
        self._thread: threading.Thread | None = None
        # RF-3 admission permits. Created in start() from the knob (never here:
        # a listener that never started must not carry a cap nobody read).
        self._slots: threading.Semaphore | None = None
        self._cap = 1
        # #477: set by stop() BEFORE the shutdown is requested. While set, the
        # handler refuses every NEW /execute with a flat 503 — the "no new
        # commands" flag of cooperative drain.
        self._draining = threading.Event()

    @property
    def active(self) -> bool:
        """True once the listener is bound and serving."""
        return self._server is not None

    @property
    def port(self) -> int:
        """Bound port. Reflects the OS-assigned port for an ephemeral bind."""
        if self._server is not None:
            return self._server.server_address[1]
        return self._port

    def _build_ssl_context(self) -> ssl.SSLContext:
        # The executor presents its own leaf cert and trusts the CA that signed
        # the core's relaying client cert. ``CERT_REQUIRED`` enforces the client
        # half of the handshake.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # GitLab #323: floor the relay at TLSv1.2 (reject TLSv1.0/1.1 pre-handshake).
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # #565: the relay serves on the executor's own leaf key, which is now an
        # encrypted envelope at rest. The callback is consulted only for an
        # encrypted file, so a legacy plaintext key binds exactly as before; an
        # envelope this host cannot open raises the named refusal instead of a bare
        # ``PEM lib`` error from the listener thread. The trust posture is
        # untouched: CERT_REQUIRED and the CN allowlist below stay as ruled.
        context.load_cert_chain(self._config.mtls.cert, self._config.mtls.key, password=ssl_password_callback())
        context.load_verify_locations(self._config.mtls.ca_cert)
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def start(self) -> None:
        if not self.allowed_client_ids:
            logger.error(
                "relay_client_ids is empty — executor relay listener NOT started "
                "(fail-closed; :8443 will not bind). Set relay_client_ids to the "
                "core's relaying client certificate CN."
            )
            return

        try:
            context = self._build_ssl_context()
            # RF-3: threaded listener; concurrency is limited by the admission
            # permit below, not by the accept loop. Handler threads are daemon
            # (http.server.ThreadingHTTPServer sets daemon_threads), which is
            # also why server_close() does not join a live command — stop()
            # bounds that wait itself, see below.
            server = _RelayHTTPServer((self._host, self._port), ExecuteHandler)
        except Exception:
            logger.exception("Failed to start executor relay listener — relay disabled")
            return

        # The cap is read ONCE here, so a hot config change cannot strand a
        # permit count that differs from the one stop() waits on.
        self._cap = self._read_cap()
        self._slots = threading.Semaphore(self._cap)

        server.executor_factory = self._executor_factory  # type: ignore[attr-defined]
        server.allowed_client_ids = self.allowed_client_ids  # type: ignore[attr-defined]
        # RF-3: the permits the handler acquires around the execution section.
        server.command_slots = self._slots  # type: ignore[attr-defined]
        # #477: the no-new-commands flag the handler consults before executing.
        server.draining = self._draining  # type: ignore[attr-defined]
        # #579: the context is PUBLISHED to the accept path, not wrapped onto
        # the listening socket, so a rotation can swap it (``reload_ssl_context``).
        server.relay_ssl_context = context
        # #586: the accept gate reads the daemon's revocation answer per connection.
        server.revocation_state = self.revocation_state  # type: ignore[attr-defined]
        server.refusal_recorder = self._record_refusal  # type: ignore[attr-defined]
        if self.revocation_state is None:
            logger.error(
                "Relay listener started with NO revocation state wired — every new "
                "connection to :%d will be refused (%s). This is the fail-closed "
                "shape; wire the daemon state.",
                self._port,
                REFUSE_NOT_WIRED,
            )

        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="venya-relay", daemon=True)
        self._thread.start()
        logger.info(
            "Executor relay listener started on %s:%d (mTLS CERT_REQUIRED, %d allowed client CN(s), "
            "max_concurrent_commands=%d)",
            self._host,
            self.port,
            len(self.allowed_client_ids),
            self._cap,
        )

    def reload_ssl_context(self) -> bool:
        """Rebuild the published mTLS context from the on-disk material (#579).

        Called by the daemon's rotation arm right after ``CertificateManager.rotate()``
        replaces key, cert and CA at the SAME paths. The old context object is left
        untouched — connections that already handshook keep presenting what they
        started with, and the next accept is wrapped with the fresh leaf. Never
        rebuilds the trust set by ADDING to the live one: a whole new context is
        built by ``_build_ssl_context``, so an anchor that rotate() rewrote is
        REPLACED, not accumulated (the reason this is not an in-place
        ``load_cert_chain``).

        Returns True when the new context is published. A rebuild failure keeps
        the previous context serving — with a loud error line naming the
        consequence — because rotation already succeeded on disk and taking the
        relay down here would trade a stale leaf for an executor that cannot be
        reached at all. The TLS floors are not touched either way: the rebuild is
        the same ``_build_ssl_context`` the boot path uses.
        """
        if self._server is None:
            logger.error("Relay TLS reload skipped — the listener is not running, so there is no port to publish to")
            return False
        try:
            context = self._build_ssl_context()
        except Exception:
            logger.exception(
                "Relay TLS context rebuild FAILED after rotation — :8443 keeps presenting the "
                "pre-rotation certificate until a reload succeeds or the daemon restarts"
            )
            return False
        self._server.relay_ssl_context = context
        logger.info(
            "Executor relay listener TLS context rebuilt from the on-disk material — "
            "new :8443 connections present the post-rotation certificate"
        )
        return True

    def _record_refusal(self, reason: str, host: str, port: int) -> None:
        """Durable record of one accept-gate refusal, on the EXISTING audit spool.

        No new mechanism (DoD point 5): this reuses ``AuditLogger.emit`` — the local
        disk append every executor audit event already takes, which the boot
        forwarder carries to the core sink when ``[audit] remote_url`` is set.

        shortcut: a refusal reaches the spool only where the daemon wired an audit
        sink (``audit_boot_forwarder``); with none configured the journal line in
        ``_RelayHTTPServer.get_request`` is the only record. Upgrade when the
        listener is given an unconditional session-less AuditLogger.
        """
        sink = self.refusal_sink
        if sink is None:
            return
        sink.emit(
            "relay_refused",
            reason=reason,
            peer_host=host,
            peer_port=port,
            executor_id=getattr(self.revocation_state, "executor_id", None),
        )

    def _read_cap(self) -> int:
        """Admission cap from the knob, fail-closed to 1 (today's behaviour).

        A config object that does not carry the field (an older fixture, a stub)
        must not widen concurrency by accident, and an unparseable value must not
        either — the default is the safe one, so anything unexpected lands there
        with a warning rather than raising at start.
        """
        executor_cfg = getattr(self._config, "executor", None)
        raw = getattr(executor_cfg, "max_concurrent_commands", None)
        if raw is None:
            return 1
        try:
            cap = int(raw)
        except (TypeError, ValueError):
            logger.warning("executor.max_concurrent_commands=%r is not an integer — admitting 1 command at a time", raw)
            return 1
        if cap < 1:
            logger.warning("executor.max_concurrent_commands=%d would admit nothing — using 1", cap)
            return 1
        return cap

    def _wait_for_idle(self, timeout: float) -> bool:
        """Take every admission permit within ``timeout``, then hand them back.

        True = idle was reached (nothing is in flight and, with ``_draining``
        set, nothing new can start). False = the budget ran out while a command
        still held a permit. Permits are released in the finally so a
        never-admitted waiter is not starved by a stop that is giving up.
        """
        slots = self._slots
        if slots is None:
            return True
        held = 0
        deadline = time.monotonic() + max(timeout, 0.0)
        try:
            for _ in range(self._cap):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not slots.acquire(timeout=remaining):
                    return False
                held += 1
            return True
        finally:
            for _ in range(held):
                slots.release()

    def stop(self, deadline_seconds: float = RELAY_STOP_DEADLINE_SECONDS) -> None:
        """Cooperative, BOUNDED shutdown (#477).

        Order:
        1. set the draining flag — the handler refuses every NEW /execute
           with a flat 503 ("no new commands", acceptance 1), both before
           admission and again at the admission point (RF-3: a peer that queued
           while a command ran must not start one once the drain has begun);
        2. request the ``serve_forever`` shutdown and wait for it BOUNDED, then
           spend what is left of the SAME budget taking every admission permit.
           Holding all of them is the proof that nothing is in flight: a permit
           is only returned after the engine's teardown ``finally``
           (sandbox teardown, executor.py) and the response write. This is the
           threaded form of the guarantee that, on the old single-threaded
           server, ``shutdown()`` gave for free — the common case still returns
           with the teardown done, the first arm of acceptance 2;
        3. if an in-flight command outlives the bound, return anyway with a
           named ERROR line. The unit's TimeoutStopSec (45 s > this 30 s
           bound) is what would otherwise follow with a SIGKILL — the exact
           skip-the-teardown class this ticket kills. Overflow residue is
           covered by the boot-reaper pairing row; the journal states
           verbatim what could not be finished here.

        NOT redesigned by this leg: what a *queued* (never-admitted) peer costs a
        shutdown — it is a daemon thread holding an open socket, released when
        the process exits. That analysis, and the order drain and admission
        should take above cap=1, stay open with the owner's queue-location
        ruling.
        """
        self._draining.set()
        overflow = False
        if self._server is not None:
            budget = time.monotonic() + max(deadline_seconds, 0.0)
            waiter = threading.Thread(target=self._server.shutdown, name="venya-relay-shutdown", daemon=True)
            waiter.start()
            waiter.join(timeout=max(budget - time.monotonic(), 0.0))
            # RF-3: shutdown() alone no longer means the command is done — the
            # handler runs in its own thread now, so the bound is spent on the
            # permits, not on the accept loop.
            if not self._wait_for_idle(timeout=max(budget - time.monotonic(), 0.0)):
                overflow = True
            if overflow:
                logger.error(
                    "Relay stop deadline (%.0fs) reached with a command still in flight — "
                    "no longer waiting; that command's sandbox teardown will not complete "
                    "in this process (boot reaper pairing ticket covers the residue)",
                    deadline_seconds,
                )
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            # On the overflow path a handler thread is still running the command
            # (RF-3: it is no longer the serve thread that executes). Joining
            # handler threads here would spend a second deadline and make the
            # "bounded" stop unbounded again, so this stays a serve-thread join.
            # It is a daemon thread: the shutdown request is already set, so it
            # exits on its own once the poll loop ends; a non-overflow stop
            # joins normally.
            self._thread.join(timeout=0.0 if overflow else 5.0)
            self._thread = None
        logger.info("Executor relay listener stopped")
