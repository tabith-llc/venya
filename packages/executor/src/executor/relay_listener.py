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

Stdlib only (``http.server`` + ``ssl.SSLContext``) — no new dependencies.
"""

import json
import logging
import ssl
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger("venya.executor.relay")

RELAY_PORT = 8443


class ExecuteHandler(BaseHTTPRequestHandler):
    """Handle ``POST /execute`` with mTLS mutual authentication.

    Identity (B0.3) is the *parsed* CN of the peer certificate, compared by
    exact match — case- and whitespace-sensitive, no normalization. A CN bound
    for ``TLS`` peer verification; the same CN is what the operator allowlists.
    """

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

        # Parse + normalize the payload. ``wrapped_value`` arrives as a JSON
        # string; the executor engine's ``strip_sentinel()`` requires bytes.
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            session_id = body["session_id"]
            command = body["command"]
            secrets = [
                {
                    "secret_id": secret["secret_id"],
                    "wrapped_value": str(secret["wrapped_value"]).encode("utf-8"),
                }
                for secret in body.get("secrets", [])
            ]
        except (ValueError, KeyError, UnicodeDecodeError) as exc:
            self._reply(400, {"detail": f"malformed request: {exc}"})
            return

        # B0.2: wire to the existing engine. The factory is wired to
        # ExecutorDaemon.create_executor in production; tests inject a stub.
        # Per the plan's failure-mode table, any execution failure is a flat 503
        # (no retry), which also covers sandbox/subprocess timeouts surfacing as
        # exceptions from the engine.
        try:
            result = self.server.executor_factory(session_id).execute(command, secrets)  # type: ignore[attr-defined]
        except Exception:
            logger.exception("Relay /execute failed for session %s", session_id)
            self._reply(503, {"detail": "execution failed"})
            return

        self._reply(
            200,
            {
                "exit_code": result.exit_code,
                "stdout": result.stdout.decode("utf-8", "replace"),
                "stderr": result.stderr.decode("utf-8", "replace"),
                "masked_count": len(result.masked_secret_ids),
            },
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

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Executor relay listener stopped")
