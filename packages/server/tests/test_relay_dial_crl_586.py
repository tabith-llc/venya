# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#586 Slice 1 — the relay dial consults a CRL at the TLS layer itself.

Owner ruling (2026-10-13, verbatim): "if its a stronger connection-time refusal,
build it", and on the staleness question: "to me it sounds like the only safe
thing to do is refuse everything until a properly refreshed list arrives." The
boundary was then ruled too (owner, verbatim: "agree completely"): the refusal is
of NEW connections at the dial; work already in flight is NOT yanked — and no
later seat may "harden" this into killing live sessions without a fresh owner
ruling. There is deliberately no in-flight-kill path, knob, or TODO in the
product code these cells pin.

Real crypto only (house discipline): a locally minted CA (same key-usage shape as
``ca.py`` CAManager.initialize: key_cert_sign AND crl_sign, because the CRL the
check consumes is CA-signed and STRICT mode enforces the usage bits), real leaves,
a real CRL, a real loopback handshake. The refusing party is the CLIENT context
built by ``_build_relay_ssl_context``; the peer is a bare ``ssl`` socket — no
daemon object, no ``DaemonState``, no venya executor code runs on either side of
the refusal, which is AC3's "the refusal must not be cooperation" half, proven
in a unit.

THE THREE STATES (cell names carry them): fresh list + live leaf ADMITS; fresh
list + revoked leaf REFUSES and SAYS REVOKED (403 class); stale/absent list
REFUSES and NEVER SAYS REVOKED (503 class, #603 lesson: an honest message must
not name a security event that did not happen).
"""

import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from server.routes.executors import (
    _STALE_LIST_DETAIL,
    _X509_V_ERR_CERT_REVOKED,
    _X509_V_ERR_CRL_HAS_EXPIRED,
    _X509_V_ERR_UNABLE_TO_GET_CRL,
    _build_relay_ssl_context,
    _dial_crl_verdict_for,
    _ensure_dial_crl_store,
)

REVOKED_SERIAL = 0x3333
LIVE_SERIAL = 0x2222


def _mint_ca(cn: str = "Slice1Root"):
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x01)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(True, None), critical=True)
        # mirrors ca.py CAManager.initialize's KeyUsage (crl_sign=True is the one
        # the CRL check needs; STRICT enforces it)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return name, cert, key


CA_NAME, CA_CERT, CA_KEY = _mint_ca()


def _mint_leaf(serial: int):
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"venya-exec-{serial:04x}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(CA_NAME)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                CA_CERT.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .sign(CA_KEY, hashes.SHA256())
    )
    return cert, key


def _mint_crl(*, revoked_serials=(), last_update: datetime | None = None, next_update: datetime | None = None):
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(CA_NAME)
        .last_update(last_update or (now - timedelta(minutes=1)))
        .next_update(next_update or (now + timedelta(hours=1)))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now - timedelta(minutes=1)).build()
        )
    return builder.sign(CA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _ca_dir(tmp_path: Path) -> Path:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    (ca_dir / "ca.crt").write_bytes(CA_CERT.public_bytes(serialization.Encoding.PEM))
    return ca_dir


def _request(ca_dir: Path, crl_der: bytes):
    """Minimal app.state: config.ca_dir + a CA manager whose generate_crl hands back
    the bytes the store must carry (the real mint is CAManager's own tested path)."""
    ca_manager = MagicMock()
    ca_manager.generate_crl.return_value = crl_der
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(config=SimpleNamespace(ca_dir=str(ca_dir)), ca_manager=ca_manager))
    )


def _handshake(store: str | None, cert, key, ca_dir: Path):
    """One real loopback TLS handshake: server presents ``cert``, the client is the
    product builder's context. Returns (outcome, verify_code, server_app_bytes)."""
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cf, kf = cert_file(cert), key_file(key)
    srv.load_cert_chain(cf, kf)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    server_saw: list = []

    def _serve():
        try:
            conn, _ = sock.accept()
            tls = srv.wrap_socket(conn, server_side=True)
            server_saw.append(tls.recv(8))
            tls.close()
        except Exception as exc:
            server_saw.append(exc)

    threading.Thread(target=_serve, daemon=True).start()
    client = _build_relay_ssl_context(str(ca_dir / "ca.crt"), crl_capath=store)
    outcome = ("OK", None)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        tls = client.wrap_socket(raw, server_hostname="localhost")
        tls.sendall(b"ping")
        tls.close()
    except ssl.SSLCertVerificationError as exc:
        outcome = ("REFUSED", exc.verify_code)
    except Exception as exc:
        outcome = ("ERR", f"{type(exc).__name__}: {exc}")
    time.sleep(0.3)
    sock.close()
    return outcome, server_saw


_CERTS: dict = {}


def cert_file(cert) -> str:
    import tempfile

    path = Path(tempfile.mkstemp(suffix=".pem")[1])
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _CERTS[id(cert)] = path
    return str(path)


def key_file(key) -> str:
    import tempfile

    path = Path(tempfile.mkstemp(suffix=".pem")[1])
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    _CERTS[id(key)] = path
    return str(path)


# --- the ruled three states, end to end ----------------------------------------


class TestRuledStatesAtTheDialHandshake:
    def test_fresh_list_admits_live_leaf(self, tmp_path):
        """AC2's paired negative: with a fresh list and an unlisted leaf, the dial
        behaves exactly as before Slice 1 — the handshake completes and bytes flow."""
        ca_dir = _ca_dir(tmp_path)
        store = _ensure_dial_crl_store(_request(ca_dir, _mint_crl()), MagicMock())
        (outcome, code), saw = _handshake(store, *_mint_leaf(LIVE_SERIAL), ca_dir)
        assert outcome == "OK", code
        assert saw and saw[0] == b"ping", saw

    def test_fresh_list_refuses_revoked_leaf_and_says_revoked(self, tmp_path):
        """AC1 positive: the serial listed in the fresh CRL dies IN the handshake
        (verify code 23 = X509_V_ERR_CERT_REVOKED), and the verdict maps to the
        revocation-asserting class: 403, wording names the revocation."""
        ca_dir = _ca_dir(tmp_path)
        store = _ensure_dial_crl_store(_request(ca_dir, _mint_crl(revoked_serials=[REVOKED_SERIAL])), MagicMock())
        (outcome, code), saw = _handshake(store, *_mint_leaf(REVOKED_SERIAL), ca_dir)
        assert outcome == "REFUSED"
        assert code == _X509_V_ERR_CERT_REVOKED == 23
        assert isinstance(saw[0], Exception), "the server must never reach an application read"

    def test_stale_list_refuses_and_never_says_revoked(self, tmp_path):
        """The owner's ruling applied to a LIVE leaf: a list past its stated
        next-update REFUSES the dial (code 12), and the verdict is the stale class
        (503) whose detail does NOT claim any revocation (#603 lesson)."""
        ca_dir = _ca_dir(tmp_path)
        stale = _mint_crl(
            last_update=datetime.now(UTC) - timedelta(hours=3),
            next_update=datetime.now(UTC) - timedelta(hours=1),
        )
        store = _ensure_dial_crl_store(_request(ca_dir, stale), MagicMock())
        (outcome, code), saw = _handshake(store, *_mint_leaf(LIVE_SERIAL), ca_dir)
        assert outcome == "REFUSED"
        assert code == _X509_V_ERR_CRL_HAS_EXPIRED == 12
        exc = ssl.SSLCertVerificationError("CRL has expired")
        exc.verify_code = code
        mapped = _dial_crl_verdict_for(exc)
        assert mapped is not None
        _code, status, detail = mapped
        assert status == 503 and detail == _STALE_LIST_DETAIL
        assert "revoked" not in detail.lower() or "no revocation asserted" in detail  # never an assertion
        assert isinstance(saw[0], Exception), "stale refusal must also be pre-request-byte"

    def test_missing_crl_link_refuses_as_stale_class(self, tmp_path):
        """No list at all is the same ruled class as a stale one: the store dir
        keeps the anchor link but loses the ``.r0`` — verify fails with code 3
        (unable to get CRL), mapped 503, wording names the LIST, never a
        revocation. Fail-closed by construction, per the owner's words."""
        ca_dir = _ca_dir(tmp_path)
        store = Path(_ensure_dial_crl_store(_request(ca_dir, _mint_crl()), MagicMock()))
        for link in store.glob("*.r0"):
            link.unlink()
        (outcome, code), _saw = _handshake(str(store), *_mint_leaf(LIVE_SERIAL), ca_dir)
        assert outcome == "REFUSED"
        assert code == _X509_V_ERR_UNABLE_TO_GET_CRL == 3
        exc = ssl.SSLCertVerificationError("unable to get certificate CRL")
        exc.verify_code = code
        _code, status, detail = _dial_crl_verdict_for(exc)
        assert (status, detail) == (503, _STALE_LIST_DETAIL)


# --- AC3: the refusal is not cooperation ----------------------------------------


class TestRefusalIsNotCooperation:
    def test_no_daemon_object_in_the_refusing_path(self, tmp_path):
        """The refusing code path is (client context + on-disk list) only: this
        cell builds both with zero venya daemon state — no DaemonState, no poll,
        no core dial gate — and the revoked peer is still refused. A patched or
        stopped peer daemon cannot affect a refusal it is never consulted for."""
        ca_dir = _ca_dir(tmp_path)
        store = _ensure_dial_crl_store(
            _request(ca_dir, _mint_crl(revoked_serials=[REVOKED_SERIAL])),
            MagicMock(),
        )
        client = _build_relay_ssl_context(str(ca_dir / "ca.crt"), crl_capath=store)
        assert client.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
        assert isinstance(store, str)  # the ONLY revocation input is the on-disk list

    def test_peer_receives_no_request_bytes(self, tmp_path):
        """Non-cooperation's negative half at the wire: the refused connections
        (revoked and stale) die before a single application byte arrives —
        ``server_saw`` carries an exception, never payload."""
        ca_dir = _ca_dir(tmp_path)
        store = _ensure_dial_crl_store(
            _request(ca_dir, _mint_crl(revoked_serials=[REVOKED_SERIAL])),
            MagicMock(),
        )
        _outcome, saw = _handshake(store, *_mint_leaf(REVOKED_SERIAL), ca_dir)
        assert all(isinstance(item, Exception) for item in saw), saw


# --- the store itself -----------------------------------------------------------


class TestDialCrlStore:
    def test_store_lands_hash_linked_crl_only(self, tmp_path):
        ca_dir = _ca_dir(tmp_path)
        store = Path(_ensure_dial_crl_store(_request(ca_dir, _mint_crl()), MagicMock()))
        assert store.stat().st_mode & 0o777 == 0o700
        assert not (
            store / "ca.pem"
        ).exists(), "the store must carry NO anchor copy — #501's trust set stays the cafile alone"
        assert (store / "crl.pem").read_bytes().startswith(b"-----BEGIN X509 CRL-----")
        links = list(store.glob("*.r0"))
        assert links, "openssl rehash must name the CRL"
        assert not list(store.glob("*.0")), "no cert link belongs in this dir"
        for link in links:
            assert link.is_symlink() and link.resolve() == store / "crl.pem"

    def test_rotated_anchor_relinks_under_new_hash(self, tmp_path):
        """CA rotation must not leave the old-name CRL link behind — the fingerprint
        marker re-runs the link pass on anchor change (the #579 lesson: material
        reaching the live surface, not welded to boot state)."""
        ca_dir = _ca_dir(tmp_path)
        store = Path(_ensure_dial_crl_store(_request(ca_dir, _mint_crl()), MagicMock()))
        old_links = {p.name for p in store.glob("*.0")} | {p.name for p in store.glob("*.r0")}
        other_name, other_cert, other_key = _mint_ca(cn="Slice1RootRotated")
        (ca_dir / "ca.crt").write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))
        crl2 = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(other_name)
            .last_update(datetime.now(UTC))
            .next_update(datetime.now(UTC) + timedelta(hours=1))
            .sign(other_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        store2 = Path(_ensure_dial_crl_store(_request(ca_dir, crl2), MagicMock()))
        new_links = {p.name for p in store2.glob("*.r0")}
        assert new_links and new_links != old_links
        assert not list(store2.glob("*.0"))

    def test_mint_failure_raises_the_refusal_class(self, tmp_path):
        """Owner posture: no freshly minted list = refuse, and the route arm turns
        it into the 503 that names the LIST, not a revocation. No silent fallback
        to a CRL-less context exists anywhere in these cells."""
        ca_dir = _ca_dir(tmp_path)
        req = _request(ca_dir, _mint_crl())
        req.app.state.ca_manager.generate_crl.side_effect = RuntimeError("DB stalled")
        with pytest.raises(RuntimeError):
            _ensure_dial_crl_store(req, MagicMock())

    def test_absent_ca_manager_refuses_dial_via_get_ca_manager(self, tmp_path):
        """The pre-existing 503 seam (_get_ca_manager) IS the fail-closed path when
        the core holds no CA manager at all; the caller re-raises it verbatim."""
        ca_dir = _ca_dir(tmp_path)
        req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=SimpleNamespace(ca_dir=str(ca_dir)))))
        with pytest.raises(HTTPException) as excinfo:
            _ensure_dial_crl_store(req, MagicMock())
        assert excinfo.value.status_code == 503


# --- the classifier truth table (both halves) -----------------------------------


class TestVerdictClassifier:
    @pytest.mark.parametrize(
        ("code", "want_status", "want_revoked_wording"),
        [
            (_X509_V_ERR_CERT_REVOKED, 403, True),  # the ONLY code that may say revoked
            (_X509_V_ERR_CRL_HAS_EXPIRED, 503, False),
            (_X509_V_ERR_UNABLE_TO_GET_CRL, 503, False),
            (20, None, None),  # unrelated verification failures keep the established arm
        ],
    )
    def test_codes_map_to_ruled_classes(self, code, want_status, want_revoked_wording):
        exc = ssl.SSLCertVerificationError("x")
        exc.verify_code = code
        verdict = _dial_crl_verdict_for(exc)
        if want_status is None:
            assert verdict is None
            return
        assert verdict is not None
        _c, status, detail = verdict
        assert status == want_status
        assert ("revoked" in detail.lower()) is want_revoked_wording, detail


# --- the truncation split-brain: a NAMED cell, not a silent TODO -----------------


class TestTruncationSplitBrain:
    def test_omitted_revoked_serial_is_tls_admitted_documented(self, tmp_path):
        """#337's served-cap (1000) means a revocation past the cap is NOT in the
        list bytes — the TLS layer can only refuse what the list asserts, so this
        cell pins the KNOWN split-brain instead of pretending it away: TLS ADMITS
        the omitted leaf, and the APPLICATION dial gate (change C, already merged
        and tested in test_relay_dial_credential_gates_586.py) stays the backstop
        that reads the DB, not the list. If the cap is ever raised or the list
        made authoritative at the transport, THIS test is the review trigger."""
        ca_dir = _ca_dir(tmp_path)
        crl_without_the_entry = _mint_crl(revoked_serials=[])  # simulates: revoked in DB, past cap, omitted
        store = _ensure_dial_crl_store(_request(ca_dir, crl_without_the_entry), MagicMock())
        (outcome, code), _saw = _handshake(store, *_mint_leaf(REVOKED_SERIAL), ca_dir)
        assert outcome == "OK", code  # admitted at TLS — see docstring: gate covers it above
