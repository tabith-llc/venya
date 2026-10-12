# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""GitLab #579 — the relay listener's mTLS context must follow a rotation.

The defect: ``RelayListener.start()`` built the server ``SSLContext`` ONCE and
wrapped the LISTENING socket with it, so after ``CertificateManager.rotate()``
rewrote the cert/key/CA files, :8443 kept presenting the pre-rotation leaf —
a serial the server has already auto-revoked — until the daemon restarted.

The fix shape under test: the listening socket stays plain and each ACCEPTED
connection is wrapped with whatever context the listener publishes
(``_RelayHTTPServer``); the daemon's rotation arm calls
``RelayListener.reload_ssl_context()``, which builds a WHOLE NEW context with
the same ``_build_ssl_context`` floors and swaps the reference. No poller, no
listener restart, and no live ``SSLContext`` mutated under RF-3's concurrent
handshakes — swapping a reference is atomic, mutating a shared CTX is not.

Truth-table pairing (every gate gets its negative half):
  rotation + reload   -> presented leaf serial CHANGES            (positive)
  rotation, no reload -> serial UNCHANGED *and* still serving     (no dead-listener green)
  reload              -> CERT_REQUIRED still refuses a certless peer
  reload              -> TLSv1.2 floor + CERT_REQUIRED still on the published context
  rebuild failure     -> incumbent keeps serving, named ERROR, returns False
  never started       -> reload refused, returns False, no raise
  CA rotation         -> the anchor set is REPLACED: an old-CA client cert is
                        refused (an in-place load_verify_locations ADD fails this)
  main loop           -> a successful rotation calls the reload; a failed one does not
"""

import logging
import socket
import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509

from executor.config import ExecutorConfig, MtlsConfig, ReaperConfig
from executor.daemon import ExecutorDaemon, RevocationStatus
from executor.relay_listener import RelayListener

logger = logging.getLogger("venya.executor.relay.test")

# Reuse the real-PKI builders from the relay suite (house pattern: import plain
# helpers, define fixtures locally) — tests.test_relay_stop_477.py does the same.
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


@pytest.fixture()
def rot_pk(tmp_path) -> SimpleNamespace:
    """Real PKI on disk, in three layers.

    CA A + leaf 1 (incumbent) + allowed client. Leaf 2 / client 2 are signed by
    the SAME CA A — that is the realistic leaf-only rotation a 30-day renewal
    performs, so an existing peer still trusts the new leaf. CA B + leaf 3 /
    client 3 exist for the anchor-replacement cell, where the CA file itself is
    rewritten. The names are the config's own paths, so a cell "rotates" by
    overwriting the files the config points at.
    """
    a_key, a_cert = _ca()
    b_key, b_cert = _ca()

    srv_cert, srv_key = _leaf(a_key, a_cert, SERVER_CN, server_auth=True)
    c_ok_cert, c_ok_key = _leaf(a_key, a_cert, ALLOWED)
    srv2_cert, srv2_key = _leaf(a_key, a_cert, SERVER_CN, server_auth=True)
    srv3_cert, srv3_key = _leaf(b_key, b_cert, SERVER_CN, server_auth=True)
    c3_cert, c3_key = _leaf(b_key, b_cert, ALLOWED)

    ca_a_crt = _write_cert_only(a_cert, tmp_path, "ca-a")
    ca_b_crt = _write_cert_only(b_cert, tmp_path, "ca-b")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    c_ok = _write_dir(c_ok_cert, c_ok_key, tmp_path, "c-ok")
    srv2 = _write_dir(srv2_cert, srv2_key, tmp_path, "srv2")
    srv3 = _write_dir(srv3_cert, srv3_key, tmp_path, "srv3")
    c3 = _write_dir(c3_cert, c3_key, tmp_path, "c3")

    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="relay-rotation-test",
        relay_client_ids=[ALLOWED],
        # The listener reads these two paths; a rotation overwrites them in place.
        mtls=MtlsConfig(ca_cert=ca_a_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(
        config=config,
        ca_a=ca_a_crt,
        ca_b=ca_b_crt,
        srv=srv,
        c_ok=c_ok,
        srv2=srv2,
        srv3=srv3,
        c3=c3,
        serial_1=srv_cert.serial_number,
        serial_2=srv2_cert.serial_number,
        serial_3=srv3_cert.serial_number,
    )


def _started(rot_pk):
    """A running listener with a stub engine and the allowed client ready."""
    fake = _FakeExec(result=_ok_result(stdout=b"hello", masked=["a"]))
    return _start(rot_pk.config, _factory(fake, []), [ALLOWED]), fake


def _install(rot_pk, pair, ca_file: str | None = None) -> int:
    """The disk half of ``rotate()``: new key, then new cert, then new CA, all
    at the paths the config already points at (``pair`` is a (cert, key) tuple
    from another leaf). Returns the new leaf serial."""
    cert_path, key_path = pair
    Path(rot_pk.config.mtls.key).write_bytes(Path(key_path).read_bytes())
    Path(rot_pk.config.mtls.cert).write_bytes(Path(cert_path).read_bytes())
    if ca_file:
        Path(rot_pk.config.mtls.ca_cert).write_bytes(Path(ca_file).read_bytes())
    return x509.load_pem_x509_certificate(Path(cert_path).read_bytes()).serial_number


def _presented_serial(listener: RelayListener, ca_file: str, client_cert: tuple[str, str] | None) -> int:
    """Handshake with the real listener and return the serial of the leaf it presented.

    ``ca_file`` is what this peer trusts; ``client_cert`` is what it presents
    (None = no client certificate at all, the CERT_REQUIRED negative).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_file)
    if client_cert:
        ctx.load_cert_chain(client_cert[0], client_cert[1])
    raw = socket.create_connection(("127.0.0.1", listener.port), timeout=10.0)
    conn = ctx.wrap_socket(raw, server_hostname=SERVER_CN)
    try:
        der = conn.getpeercert(binary_form=True)
    finally:
        conn.close()
    assert der is not None, "handshake completed without a peer certificate"
    return x509.load_der_x509_certificate(der).serial_number


def _client_ctx(ca_file: str, client_cert: tuple[str, str] | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_file)
    if client_cert:
        ctx.load_cert_chain(client_cert[0], client_cert[1])
    return ctx


def _presented_serial(listener: RelayListener, ca_file: str, client_cert: tuple[str, str] | None) -> int:
    """Handshake with the real listener and return the serial of the leaf it presented.

    ``ca_file`` is what this peer trusts; ``client_cert`` is what it presents.
    Only valid for a peer the listener ACCEPTS — use ``_rejects_peer`` for the
    negative half, because under TLS 1.3 the client's own handshake finishes
    before the server's fatal alert arrives.
    """
    ctx = _client_ctx(ca_file, client_cert)
    raw = socket.create_connection(("127.0.0.1", listener.port), timeout=10.0)
    conn = ctx.wrap_socket(raw, server_hostname=SERVER_CN)
    try:
        der = conn.getpeercert(binary_form=True)
    finally:
        conn.close()
    assert der is not None, "handshake completed without a peer certificate"
    return x509.load_der_x509_certificate(der).serial_number


def _rejects_peer(listener: RelayListener, ca_file: str, client_cert: tuple[str, str] | None) -> bool:
    """True only when this peer gets NO service at all: the handshake is refused
    and not one byte of HTTP comes back.

    The rejection is asserted at the application layer on purpose. ``CERT_REQUIRED``
    is enforced by the server, and under TLS 1.3 a client-side ``wrap_socket()``
    can return before the server's fatal alert is read — an exception from the
    wrap would be a flaky proxy for "refused". A stall is NOT a refusal either:
    ``socket.timeout`` is deliberately not caught below, so it fails the run
    loudly instead of counting as a rejection.
    """
    ctx = _client_ctx(ca_file, client_cert)
    raw = socket.create_connection(("127.0.0.1", listener.port), timeout=10.0)
    try:
        conn = ctx.wrap_socket(raw, server_hostname=SERVER_CN)
    except ssl.SSLError:
        return True
    try:
        conn.sendall(b"POST /execute HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
        data = conn.recv(1)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, ssl.SSLCertVerificationError) as exc:
        # The server alerted or hung up. A socket.timeout is deliberately NOT in
        # this tuple: a stall is not a refusal, and it must fail the run loudly.
        logger.debug("rejected peer closed the dial: %r", exc)
        return True
    finally:
        conn.close()
    # b"" = the server closed the connection without serving a single byte.
    return data == b""


def _post_on(conn, body: bytes) -> int:
    """Send one /execute over an ALREADY-OPEN TLS connection, return the status."""
    conn.sendall(
        b"POST /execute HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    chunks: list[bytes] = []
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    response = b"".join(chunks)
    assert response.startswith(b"HTTP/1."), f"no HTTP response on a live connection: {response!r}"
    return int(response.split(b" ", 2)[1])


def _serves(listener: RelayListener, rot_pk) -> bool:
    """One real /execute round trip — the alive proof that keeps a 'nothing
    changed' assertion from passing on a dead listener."""
    payload = {"session_id": "s-579", "command": ["echo", "hi"], "secrets": []}
    with _client(rot_pk.ca_a, rot_pk.c_ok) as client:
        return client.post(_url(listener), json=payload).status_code == 200


class TestRotationRebuildsThePresentedContext:
    def test_reload_presents_the_new_leaf(self, rot_pk):
        """POSITIVE: the disk half plus reload_ssl_context() makes :8443 answer
        with the post-rotation serial. Before this leg the old serial — already
        revoked server-side — was presented until a daemon restart."""
        listener, _fake = _started(rot_pk)
        try:
            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c_ok) == rot_pk.serial_1
            new_serial = _install(rot_pk, rot_pk.srv2)
            assert new_serial == rot_pk.serial_2 and new_serial != rot_pk.serial_1

            assert listener.reload_ssl_context() is True

            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c_ok) == rot_pk.serial_2
        finally:
            listener.stop()

    def test_no_reload_leaves_the_incumbent_leaf_and_keeps_serving(self, rot_pk):
        """NEGATIVE half, and the anti-false-green: the files alone must NOT move
        the presented serial (there is no poller — the reload is the trigger),
        and the listener must be provably alive while it says nothing changed."""
        listener, _fake = _started(rot_pk)
        try:
            _install(rot_pk, rot_pk.srv2)

            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c_ok) == rot_pk.serial_1
            assert _serves(listener, rot_pk) is True, "listener must be live for this to mean anything"
        finally:
            listener.stop()

    def test_serving_continues_on_the_same_port_after_the_swap(self, rot_pk):
        """The swap is not a re-bind: the ephemeral port is unchanged and a
        request still round-trips on the newly published context."""
        listener, fake = _started(rot_pk)
        try:
            port_before = listener.port
            _install(rot_pk, rot_pk.srv2)
            assert listener.reload_ssl_context() is True

            assert listener.port == port_before, "reload must not re-bind the listening socket"
            assert _serves(listener, rot_pk) is True
            assert fake.command == ["echo", "hi"]
        finally:
            listener.stop()

    def test_in_flight_connection_finishes_on_the_context_it_started_with(self, rot_pk):
        """The RF-3 half: the listener threads, so a rotation can land while a
        handshake is in progress. This is why the fix swaps a REFERENCE instead
        of calling ``load_cert_chain`` on the live context — an accepted
        connection keeps the SSL object (and the leaf) it negotiated, and the
        next connection gets the new one. Nothing is mutated under a peer.
        """
        listener, _fake = _started(rot_pk)
        conn = _client_ctx(rot_pk.ca_a, rot_pk.c_ok).wrap_socket(
            socket.create_connection(("127.0.0.1", listener.port), timeout=10.0),
            server_hostname=SERVER_CN,
        )
        try:
            der = conn.getpeercert(binary_form=True)
            assert x509.load_der_x509_certificate(der).serial_number == rot_pk.serial_1

            _install(rot_pk, rot_pk.srv2)
            assert listener.reload_ssl_context() is True

            # the pre-rotation connection still completes its request on the
            # context it started with (it was never yanked out from under it)
            assert _post_on(conn, b'{"session_id":"s-579","command":["echo","hi"],"secrets":[]}') == 200
            # ...and a NEW connection is served the post-rotation leaf
            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c_ok) == rot_pk.serial_2
        finally:
            conn.close()
            listener.stop()


class TestFloorsSurviveTheRebuild:
    def test_cert_required_still_refuses_a_certless_peer(self, rot_pk):
        """NEGATIVE half of the identity gate: a rebuilt context must not grow
        permissive. CERT_REQUIRED bites at the handshake, so a peer with no
        client certificate never reaches the handler."""
        listener, _fake = _started(rot_pk)
        try:
            _install(rot_pk, rot_pk.srv2)
            assert listener.reload_ssl_context() is True

            assert _rejects_peer(listener, rot_pk.ca_a, None), "a certless peer was served"
            # paired positive: the same dial WITH the allowed client succeeds,
            # so the refusal above is the gate, not a broken listener.
            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c_ok) == rot_pk.serial_2
        finally:
            listener.stop()

    def test_tls_floor_and_verify_mode_hold_on_the_published_context(self, rot_pk):
        """#323's floor and the mTLS posture are asserted on the context that is
        ACTUALLY PUBLISHED after a reload, not merely on a fresh build — the
        reload must not relax either."""
        listener, _fake = _started(rot_pk)
        try:
            _install(rot_pk, rot_pk.srv2)
            assert listener.reload_ssl_context() is True

            published = listener._server.relay_ssl_context
            assert published.minimum_version == ssl.TLSVersion.TLSv1_2
            assert published.verify_mode == ssl.CERT_REQUIRED
        finally:
            listener.stop()


class TestCARotationReplacesTheAnchorSet:
    def test_old_ca_client_cert_is_refused_once_the_anchor_rotates(self, rot_pk):
        """Why this is a REBUILD and not an in-place ``load_cert_chain``:
        ``load_verify_locations`` ADDs to a live store, so a rotated-away CA
        would stay trusted forever. A fresh context replaces the set — the
        old-CA client cert is refused on the wire, the new-CA one is accepted.

        Both peers trust the NEW anchor file, so a failure on the old-CA dial
        can only be the server rejecting a certificate it no longer trusts.
        """
        listener, _fake = _started(rot_pk)
        try:
            new_serial = _install(rot_pk, rot_pk.srv3, ca_file=rot_pk.ca_b)
            assert new_serial == rot_pk.serial_3
            assert listener.reload_ssl_context() is True

            # positive: new-CA client, new-CA leaf, new anchor — serves.
            assert _presented_serial(listener, rot_pk.ca_a, rot_pk.c3) == rot_pk.serial_3

            # negative: a client cert signed by the RETIRED CA is refused at the
            # handshake (it trusts the same new anchor, so this is the server's
            # store that moved, not the client's).
            assert _rejects_peer(listener, rot_pk.ca_a, rot_pk.c_ok), "a rotated-away client cert was served"
        finally:
            listener.stop()


class TestRebuildFailureIsLoudAndKeepsService:
    def test_unreadable_material_keeps_the_incumbent_and_says_so(self, rot_pk, caplog):
        """NEGATIVE half of the reload: a rebuild that raises must not take the
        relay down and must not pass silently. The disk half already landed, so
        the incumbent context keeps serving behind a named ERROR line."""
        listener, _fake = _started(rot_pk)
        try:
            Path(rot_pk.config.mtls.cert).write_text("-----BEGIN CERTIFICATE-----\nnot a cert\n")

            with caplog.at_level(logging.ERROR, logger="venya.executor.relay"):
                assert listener.reload_ssl_context() is False

            assert "rebuild FAILED" in caplog.text
            assert _serves(listener, rot_pk) is True
        finally:
            listener.stop()

    def test_reload_before_start_is_refused_without_raising(self, rot_pk):
        """The other half of "no port to publish to": a listener that never
        started returns False and raises nothing (the fail-closed
        empty-relay_client_ids shape must not gain a new crash path)."""
        listener = RelayListener(rot_pk.config, lambda _sid: None, [ALLOWED])
        assert listener.active is False
        assert listener.reload_ssl_context() is False


class TestDaemonRotationArmWiresTheListener:
    """The daemon half: a rotation that succeeds must reach the listener, and
    one that fails must not."""

    @pytest.fixture()
    def daemon_config(self) -> ExecutorConfig:
        return ExecutorConfig(
            server_url="https://core.test",
            executor_id="loop-test",
            reaper=ReaperConfig(check_interval=0.1, secret_ttl_seconds=1),
        )

    def _run_one_rotation(self, daemon, new_client, rotate_exc=None):
        """Drive _main_loop() through exactly one rotation, then shutdown
        (the shape of tests/test_daemon_loop.py's _run_one_rotation)."""

        def do_rotate():
            daemon.state.running = False
            if rotate_exc is not None:
                raise rotate_exc

        relay = MagicMock()
        daemon.relay = relay
        with (
            patch.object(daemon.cert_manager, "needs_rotation", return_value=True),
            patch.object(daemon.cert_manager, "rotate", side_effect=do_rotate),
            patch.object(daemon, "_create_mtls_client", return_value=new_client),
            patch.object(daemon.cert_manager, "check_revocation", return_value=RevocationStatus.NOT_REVOKED),
            patch.object(daemon, "_send_heartbeat"),
            patch.object(daemon._shutdown_event, "wait", return_value=False),
        ):
            daemon._main_loop()
        return relay

    def test_successful_rotation_reloads_the_relay_context(self, daemon_config):
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock()
        daemon.state.running = True

        relay = self._run_one_rotation(daemon, MagicMock())

        relay.reload_ssl_context.assert_called_once_with()

    def test_failed_rotation_does_not_reload_the_relay_context(self, daemon_config):
        """NEGATIVE half: the reload lives inside the rotation arm, so a rotate()
        that raised — nothing new on disk — must not publish a context minted
        from the unchanged files, and the loop still swallows the error."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock()
        daemon.state.running = True

        relay = self._run_one_rotation(daemon, MagicMock(), rotate_exc=RuntimeError("boom"))

        relay.reload_ssl_context.assert_not_called()


def test_fixture_mints_distinct_material(rot_pk):
    """Guard on the fixture: if the leaves shared a serial, or srv2/srv3 were
    byte-identical to the incumbent, every "the serial changed" assert above
    would be vacuous."""
    assert len({rot_pk.serial_1, rot_pk.serial_2, rot_pk.serial_3}) == 3
    incumbent = Path(rot_pk.srv[0]).read_bytes()
    assert Path(rot_pk.srv2[0]).read_bytes() != incumbent
    assert Path(rot_pk.srv3[0]).read_bytes() != incumbent
    assert Path(rot_pk.ca_b).read_bytes() != Path(rot_pk.ca_a).read_bytes()
