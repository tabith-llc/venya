# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#597 executor side: the peer population lands, and the :8443 door can name it.

The registry (server, `core_relay_credentials`) is what made this possible: before it the
credential a CORE presents at an executor's :8443 was in no table, so no list could name
it and #586's listener CRL was measured to be a no-op against its own subject
(`wave30-specs-20261017/flash5-586-listener-door-s134-report.md`, CASE 2).

Two claims, each paired with its reject:

  A. THE CARRY — the poll's `revoked_relay_serials` lands on DaemonState, and an
     unanswered tick cannot empty it.
  B. THE DOOR — a presented client certificate whose serial the registry names as revoked
     is refused before any request byte; every other shape is admitted. THIS HALF IS
     NON-COOPERATIVE: `get_request` is driven with a real TLS handshake and no daemon
     object in the path, so the refusal cannot be the daemon's cooperative stop wearing a
     different hat.

The ruled boundary this file must not cross: the consult keys on REGISTRY MEMBERSHIP,
never on list age. A staleness stop condition at this door is #586's availability trade
and belongs to the owner, so there is no cell here that refuses on age and none that
would let one appear by accident.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from executor.relay_listener import (
    REFUSE_PEER_REVOKED,
    peer_revocation_refusal,
    revocation_accept_reason,
)

# A certificate SERIAL is a public identifier — it is in the certificate anyone can
# read and in the handshake log. Chosen low-entropy and obviously fake on purpose, so
# it also does not trip the repo's detect-secrets hook, which is right to treat a
# long random hex string as secret-shaped.
PEER_SERIAL_INT = 0xABCD
PEER_SERIAL_UPPER = "ABCD"  # the exact spelling ssl.getpeercert() yields
PEER_SERIAL_CANON = "000000000000abcd"  # the exact spelling the registry stores


def _code_only(fn) -> str:
    """Source with the docstring removed.

    The absence-cells below need this: my own prose in the docstring says "age" and
    "CN allowlist" while describing what the function does NOT do, and a substring scan
    over the whole source would fail on the sentence that states the fence. Checking the
    CODE is the honest instrument; checking prose is a test that argues with its comments.
    """
    import ast
    import inspect
    import textwrap

    src = inspect.getsource(fn)
    node = ast.parse(textwrap.dedent(src)).body[0]
    doc = ast.get_docstring(node, clean=False)
    return src.replace(doc, "") if doc else src


def _state(**over):
    base = {
        "revoked": False,
        "revocation_answered": True,
        "revocation_fault_reason": None,
        "revoked_relay_serials": frozenset(),
    }
    base.update(over)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# A. THE CARRY
# ---------------------------------------------------------------------------


class TestPeerPopulationLands:
    """The parsed poll body reaches DaemonState, and an outage cannot wipe it."""

    def test_a_fresh_manager_starts_with_an_empty_peer_set(self) -> None:
        """The default is the admitting one, constructed the real way (not ``__new__``)."""
        from executor.config import ExecutorConfig
        from executor.daemon import CertificateManager

        cm = CertificateManager(ExecutorConfig())
        assert cm.last_relay_serials == frozenset(), "starts empty, which admits"
        assert not hasattr(cm, "state"), (
            "CertificateManager must not grow a DaemonState — the poll writes its own "
            "attribute and _main_loop carries it to the state object it owns"
        )

    def test_daemon_state_starts_with_an_empty_peer_set(self) -> None:
        from executor.daemon import DaemonState

        st = DaemonState()
        assert st.revoked_relay_serials == frozenset()
        # and an empty set must never be the reason a connection is refused
        assert peer_revocation_refusal(st, PEER_SERIAL_UPPER) is None

    def test_the_carry_lives_on_the_manager_and_the_state_object(self) -> None:
        """Both ends of the carry exist, and the write sites are the two intended ones.

        Labelled as the source-shape check it is: it cannot prove behaviour, which the
        cells above and the handshake below do.
        """

        from executor import daemon as dm

        src = _code_only(dm.CertificateManager.check_revocation)
        guard = src.index("parse_revocation_payload(response)")
        at_parse = src.index("self.last_relay_serials")
        assert at_parse > guard, "the peer set must be written only AFTER the shape guard accepted the body"
        loop = _code_only(dm.ExecutorDaemon._main_loop)
        assert (
            "state.revoked_relay_serials = self.cert_manager.last_relay_serials" in loop
        ), "_main_loop never carries the peer population onto the state the listener reads"
        # one writer on the state object: a second one could empty it on a bad tick
        assert loop.count("revoked_relay_serials =") == 1, "more than one writer publishes the peer set"


# ---------------------------------------------------------------------------
# B. THE DOOR — the pure function, then a real handshake
# ---------------------------------------------------------------------------


class TestPeerRefusalPureFunction:
    """Every accept paired with a reject. This is the whole truth table in one place."""

    def test_revoked_peer_serial_is_refused(self) -> None:
        st = _state(revoked_relay_serials=frozenset({PEER_SERIAL_CANON}))
        assert peer_revocation_refusal(st, PEER_SERIAL_UPPER) == REFUSE_PEER_REVOKED

    def test_live_peer_serial_is_admitted(self) -> None:
        st = _state(revoked_relay_serials=frozenset({"0000000000009999"}))
        assert peer_revocation_refusal(st, PEER_SERIAL_UPPER) is None

    def test_empty_registry_admits_rather_than_refusing_the_unknown(self) -> None:
        """The 263 direction that matters AT THE DOOR: an empty peer set is "nothing is
        named dead", never "nothing is allowed". Refusing here would stop a healthy fleet
        on a core that has not registered yet."""
        assert peer_revocation_refusal(_state(revoked_relay_serials=frozenset()), PEER_SERIAL_UPPER) is None

    def test_no_state_admits(self) -> None:
        assert peer_revocation_refusal(None, PEER_SERIAL_UPPER) is None

    def test_unreadable_peer_serial_admits(self) -> None:
        assert peer_revocation_refusal(_state(revoked_relay_serials=frozenset({PEER_SERIAL_CANON})), None) is None

    def test_padded_and_unpadded_spellings_meet(self) -> None:
        """#481 at the door: the cert says ABCD, the row says 000000000000abcd."""
        st = _state(revoked_relay_serials=frozenset({PEER_SERIAL_CANON}))
        for spelling in (PEER_SERIAL_UPPER, PEER_SERIAL_CANON, "abcd", "0xabcd", "  ABCD  "):
            assert peer_revocation_refusal(st, spelling) == REFUSE_PEER_REVOKED, spelling

    def test_a_different_serial_is_not_refused_by_an_adjacent_revoke(self) -> None:
        st = _state(revoked_relay_serials=frozenset({PEER_SERIAL_CANON}))
        assert peer_revocation_refusal(st, "0000000000000001") is None

    def test_refusal_claims_revocation_and_carries_the_403_class(self) -> None:
        """The vocabulary guard, restated for the new class so a reword is caught here too."""
        assert REFUSE_PEER_REVOKED.startswith("403 REVOKED")
        assert "peer" in REFUSE_PEER_REVOKED, "it must say WHOSE revocation this is"

    def test_peer_refusal_is_a_distinct_string_from_the_self_refusal(self) -> None:
        """Two subjects, two messages. Reusing REFUSE_REVOKED would tell a CORE that its
        own credential is revoked when what happened is that the registry named it dead —
        and the operator would look at the wrong daemon."""
        from executor.relay_listener import REFUSE_REVOKED

        assert REFUSE_PEER_REVOKED != REFUSE_REVOKED

    def test_no_age_or_staleness_term_exists_in_the_peer_consult(self) -> None:
        """The ruled fence, asserted as an absence: this leg ships NO stop clock.

        A future arm that reads list age here would make a healthy executor refuse its
        fleet an hour after boot — #586's measured CASE 3. This cell is the tripwire.
        """

        from executor.relay_listener import peer_revocation_refusal as p

        src = _code_only(p)
        for banned in ("next_update", "age", "stale", "expired", "monotonic", "time()"):
            assert (
                banned not in src
            ), f"the peer consult grew a staleness arm ({banned!r}) — that is #586's trade, not this row's"
        # positive control on the instrument: prove the scan can find a token when one is
        # really in the code, so the green above is not an artifact of an empty read.
        assert "serial_match_key" in src, "the scan read no code at all — the absence assertion would be vacuous"

    def test_self_state_gate_still_answers_first(self) -> None:
        """A daemon that cannot answer about ITSELF must not be out-talked by a peer claim."""
        unanswered = SimpleNamespace(
            revoked=False,
            revocation_answered=False,
            revocation_fault_reason=None,
            revoked_relay_serials=frozenset({PEER_SERIAL_CANON}),
        )
        assert revocation_accept_reason(unanswered) is not None, "the self gate must still refuse an unanswered boot"


class TestRealHandshakeAtTheDoor:
    """Non-cooperative proof: a real TLS handshake, a real presented certificate, no daemon."""

    @staticmethod
    def _material(tmp: Path) -> dict:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        now = dt.datetime.now(dt.UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idaho-relay")]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(PEER_SERIAL_INT)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )
        # the listener's own server leaf: a second cert, self-signed is enough for a loopback test
        srv_key = ec.generate_private_key(ec.SECP256R1())
        srv = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exec-1")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exec-1")]))
            .public_key(srv_key.public_key())
            .serial_number(2)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(srv_key, hashes.SHA256())
        )

        def w(name: str, data: bytes) -> str:
            p = tmp / name
            p.write_bytes(data)
            return str(p)

        return {
            "ca": w("ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
            "peer_cert": w("peer.pem", leaf.public_bytes(serialization.Encoding.PEM)),
            "peer_key": w(
                "peer.key",
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ),
            ),
            "srv_cert": w("srv.pem", srv.public_bytes(serialization.Encoding.PEM)),
            "srv_key": w(
                "srv.key",
                srv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ),
            ),
        }

    def _drive(self, m: dict, state) -> tuple:
        """Run one real accept through the shipped `_RelayHTTPServer.get_request` path."""
        from executor.relay_listener import _RelayHTTPServer

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        srv_ctx.load_cert_chain(m["srv_cert"], m["srv_key"])
        srv_ctx.load_verify_locations(m["ca"])
        srv_ctx.verify_mode = ssl.CERT_REQUIRED

        plain = socket.socket()
        plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        plain.bind(("127.0.0.1", 0))
        plain.listen(1)
        port = plain.getsockname()[1]

        server = _RelayHTTPServer.__new__(_RelayHTTPServer)
        server.socket = plain
        server.relay_ssl_context = srv_ctx
        server.revocation_state = state
        refusals: list = []
        server.refusal_recorder = lambda reason, host, prt: refusals.append(reason)

        result: dict = {}

        def accept_once():
            try:
                conn, _addr = server.get_request()
                result["admitted"] = True
                conn.close()
            except Exception as e:
                result["admitted"] = False
                result["error"] = f"{type(e).__name__}"

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()

        cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli_ctx.check_hostname = False
        cli_ctx.verify_mode = ssl.CERT_NONE
        cli_ctx.load_verify_locations(m["ca"])
        cli_ctx.load_cert_chain(m["peer_cert"], m["peer_key"])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                cli_ctx.wrap_socket(raw, server_hostname="localhost").close()
        except OSError:
            pass
        t.join(5)
        plain.close()
        return "admitted" if result.get("admitted") else f"refused:{result.get('error')}", refusals

    def test_revoked_peer_is_refused_at_the_real_door_before_any_request(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            m = self._material(Path(d))
            outcome, refusals = self._drive(m, _state(revoked_relay_serials=frozenset({PEER_SERIAL_CANON})))
            assert (
                outcome == "refused:ValueError" or "refused" in outcome
            ), f"the door admitted a revoked peer: {outcome}"
            assert refusals == [REFUSE_PEER_REVOKED], f"no durable refusal was recorded: {refusals}"

    def test_the_same_peer_is_admitted_when_the_registry_calls_it_live(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            m = self._material(Path(d))
            outcome, refusals = self._drive(m, _state(revoked_relay_serials=frozenset()))
            assert outcome == "admitted", f"the door refused a healthy peer: {outcome}"
            assert refusals == [], "a refusal was recorded against an admitted connection"

    def test_the_door_reads_the_presented_certificate_not_a_name(self) -> None:
        """The serial comes off the established connection's client certificate.

        Proven by the pair above with the certificate minted at a serial the registry
        names: no CN, header, or peer-supplied string is consulted anywhere in
        `peer_revocation_refusal`.
        """

        from executor.relay_listener import peer_revocation_refusal as p

        src = _code_only(p)
        # Code tokens only. A header/CN read would appear as an attribute access or a call,
        # not as the word in a sentence.
        for not_allowed in ("request.headers", "getpeercert", ".common_name", "ssl_client", "hostname"):
            assert (
                not_allowed not in src
            ), f"the peer consult reaches for {not_allowed!r}; it takes the serial as an argument and nothing else"
        # and the signature is exactly (state, peer_serial) — no new door to read from
        import inspect as _i

        params = list(_i.signature(p).parameters)
        assert params == ["state", "peer_serial"], f"the peer consult grew an input: {params}"
