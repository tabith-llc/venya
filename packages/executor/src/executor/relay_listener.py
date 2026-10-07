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
"""

import json
import logging
import ssl
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from pydantic import ValidationError
from venya_contract import RelayRequest, RelayResponse

from .executor import CommandRejected

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
# transfer of any size never trips it, while a silent peer releases the single
# handler thread well below SBX_TIMEOUT (1h) and inside one heartbeat interval.
# HTTP/1.0 (BaseHTTPRequestHandler default) closes the connection after every
# response, so no keep-alive idle clock exists. Residual: a byte-trickle peer
# can still hold the handler — bounded in practice by core's own httpx2 client
# timeout (300s), after which the socket EOFs. Threat model is a misbehaving
# AUTHENTICATED peer (mTLS + CN allowlist), not an adversarial one.
RELAY_READ_TIMEOUT_SECONDS = 30.0

# #477 (relay-stop-unbounded-skips-cleanup-under-systemd): the bound stop()
# waits for the in-flight command to finish and its teardown to run. The
# server is single-threaded and executes INLINE, so an unwaited shutdown was
# unbounded (a command may run to SBX_TIMEOUT = 1h) — and systemd's default
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


class RelayListener:
    """Run the mTLS relay listener in a background thread.

    Single-threaded ``HTTPServer`` => one command at a time (sequential
    execution, per the plan). The listener runs in its own daemon thread so it
    never contends with the reaper, heartbeat, or revocation loops.

    DOCUMENTED TRADEOFF (ticket relay-listener-body-cap-and-timeout, part 2 —
    deliberate, not an omission): sequential execution keeps per-command
    secrets, filter state, and bundles isolated from interleaving. Consequence,
    accepted: a legitimately slow command (up to SBX_TIMEOUT) delays every
    other authorized peer's request behind it — one busy slot starves the
    daemon's responsiveness. The body cap + inactivity timeout bound the
    *allocation* and *silence* failure modes, not execution parallelism. Do
    not "fix" the queueing without re-weighing the isolation argument.
    """

    def __init__(
        self,
        config: Any,
        executor_factory: Callable[[str], Any],
        allowed_client_ids: list[str],
        host: str = "0.0.0.0",  # nosec B104 — private relay net; mTLS CERT_REQUIRED + CN allowlist is the access control
        port: int = RELAY_PORT,
    ) -> None:
        self._config = config
        self._executor_factory = executor_factory
        self.allowed_client_ids = frozenset(allowed_client_ids)
        self._host = host
        self._port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
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
        context.load_cert_chain(self._config.mtls.cert, self._config.mtls.key)
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
            server = HTTPServer((self._host, self._port), ExecuteHandler)
        except Exception:
            logger.exception("Failed to start executor relay listener — relay disabled")
            return

        server.executor_factory = self._executor_factory  # type: ignore[attr-defined]
        server.allowed_client_ids = self.allowed_client_ids  # type: ignore[attr-defined]
        # #477: the no-new-commands flag the handler consults before executing.
        server.draining = self._draining  # type: ignore[attr-defined]
        server.socket = context.wrap_socket(server.socket, server_side=True)

        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="venya-relay", daemon=True)
        self._thread.start()
        logger.info(
            "Executor relay listener started on %s:%d (mTLS CERT_REQUIRED, %d allowed client CN(s))",
            self._host,
            self.port,
            len(self.allowed_client_ids),
        )

    def stop(self, deadline_seconds: float = RELAY_STOP_DEADLINE_SECONDS) -> None:
        """Cooperative, BOUNDED shutdown (#477).

        Order:
        1. set the draining flag — the handler refuses every NEW /execute
           with a flat 503 ("no new commands", acceptance 1);
        2. request the ``serve_forever`` shutdown and wait for it BOUNDED. On
           the single-threaded server the request completes only once the
           in-flight command finishes and its ``finally`` (sandbox teardown,
           executor.py) has run — the common case returns with the teardown
           done, the first arm of acceptance 2;
        3. if the in-flight command outlives the bound, return anyway with a
           named ERROR line. The unit's TimeoutStopSec (45 s > this 30 s
           bound) is what would otherwise follow with a SIGKILL — the exact
           skip-the-teardown class this ticket kills. Overflow residue is
           covered by the boot-reaper pairing row; the journal states
           verbatim what could not be finished here.
        """
        self._draining.set()
        overflow = False
        if self._server is not None:
            waiter = threading.Thread(target=self._server.shutdown, name="venya-relay-shutdown", daemon=True)
            waiter.start()
            waiter.join(timeout=deadline_seconds)
            overflow = waiter.is_alive()
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
            # On the overflow path the serve thread is the one still running
            # the command — joining it here would spend a second deadline and
            # make the "bounded" stop unbounded again. It is a daemon thread:
            # the shutdown request is already set, so it exits on its own once
            # the command returns; a non-overflow stop joins normally.
            self._thread.join(timeout=0.0 if overflow else 5.0)
            self._thread = None
        logger.info("Executor relay listener stopped")
