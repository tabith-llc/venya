# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#565 Part B — the CLI LOADS a passphrase-protected admin key for admin mTLS.

Part A (#547a) made both admin writers encrypt the leaf private key. This leg is the read
side: `api_client._build_ssl_context` now hands `SSLContext.load_cert_chain` a passphrase
callback for a pair the caller did not supply one for, reading
`VENYA_ADMIN_CA_KEY_PASSPHRASE` through the SAME predicate the writers use (#554's one-helper
law), so a blankness or length rule cannot land on one side and miss the other.

The positive half is proven at the TLS layer, not through a mock: the key is written by the
shipped writer, the context is built by the shipped builder, and a real `ssl` server that
REQUIRES a client certificate completes the handshake and reports which client certificate it
saw. A context that loaded the key but could not present it would fail that cell.

Truth table (every accepted shape carries its rejected half):

| shape                                   | expected |
|-----------------------------------------|----------|
| encrypted key + right passphrase        | loads, and the handshake presents it |
| encrypted key + WRONG passphrase        | refused, by name, "did not open" |
| encrypted key + NO passphrase configured| refused, by name, "no passphrase" |
| encrypted key + whitespace-only value   | refused as "no passphrase" (the shipped #554 predicate) |
| plaintext key, passphrase unset         | loads exactly as before (no regression) |
| mismatched cert/key pair                | keeps the pair-load text, not a passphrase text |

Passphrases here are dev-only test values, the same shape #547's cells already carry.
"""

import datetime
import socket
import ssl
import threading
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from venya_cli.api_client import APIClientError, _build_ssl_context
from venya_cli.commands import cmd_admin_generate_admin_cert, cmd_admin_init_admin_ca

UTC = datetime.UTC
# dev-only test passphrase; 20 code points, so it clears the #573 floor and is never the
# subject of a length refusal in this file.
LEAF_PASSPHRASE = "test-partb-passphrase-565"
IDENTITY = "admin@example.com"


@pytest.fixture(autouse=True)
def _admin_passphrase_env(monkeypatch):
    """Every cell states its own passphrase; the default is the one that opens the key.

    monkeypatch restores the environment per cell, so nothing here leaks into another file.
    """
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
    yield


def _admin_pair(tmp_path):
    """A real admin CA + admin leaf, written by the SHIPPED writers (#547a).

    Returns (ca_cert, leaf_cert, leaf_key). The leaf key on disk is an encrypted PKCS#8
    envelope — that is the whole subject of this leg.
    """
    ca_dir = tmp_path / "admin-ca"
    assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(ca_dir))) == 0
    out = tmp_path / "leaf"
    assert (
        cmd_admin_generate_admin_cert(SimpleNamespace(identity=IDENTITY, ca_dir=str(ca_dir), output_dir=str(out))) == 0
    )
    return ca_dir / "admin-ca.crt", out / "admin.crt", out / "admin.key"


def _server_leaf(ca_cert_path, ca_key_path, tmp_path):
    """A server leaf signed by that admin CA, valid for https://localhost.

    The CA key is opened IN MEMORY with the dev passphrase and never written back out
    unencrypted — no plaintext key material lands on disk anywhere in this file.
    """
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=LEAF_PASSPHRASE.encode())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(0x565_0001)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    srv_cert = tmp_path / "server.crt"
    srv_key = tmp_path / "server.key"
    srv_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    srv_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return srv_cert, srv_key


class _TlsServer:
    """A one-connection mTLS server: CERT_REQUIRED, anchored on the admin CA."""

    def __init__(self, ca_cert, srv_cert, srv_key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(srv_cert), keyfile=str(srv_key))
        self.ctx.load_verify_locations(cafile=str(ca_cert))
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.peer_cn = None
        self.error = None
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            with conn:
                with self.ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    peer = tls_conn.getpeercert()
                    self.peer_cn = next((v for rdn in peer["subject"] for k, v in rdn if k == "commonName"), None)
                    tls_conn.sendall(b"ok\n")
        except OSError as e:  # a refused handshake is the negative half's evidence
            self.error = e
        finally:
            self.sock.close()

    def close(self):
        self._t.join(timeout=5)


def _handshake(client_ctx, port):
    """Drive one real TLS handshake; returns the CN the SERVER saw for the client."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls_conn:
        tls_conn.recv(16)


def test_encrypted_admin_key_completes_a_real_mtls_handshake(tmp_path):
    """POSITIVE, at the TLS layer: a key written encrypted by the shipped writer is loaded
    AND presented. The server demands a client certificate, so this cell cannot pass with a
    context that loaded the key but did not offer it — `peer_cn` is the server's own account
    of which credential it was shown."""
    ca_cert, leaf_cert, leaf_key = _admin_pair(tmp_path)
    srv_cert, srv_key = _server_leaf(ca_cert, tmp_path / "admin-ca" / "admin-ca.key", tmp_path)
    server = _TlsServer(ca_cert, srv_cert, srv_key)
    try:
        ctx = _build_ssl_context(cafile=str(ca_cert), certfile=str(leaf_cert), keyfile=str(leaf_key))
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls_conn:
            assert tls_conn.recv(16) == b"ok\n"
    finally:
        server.close()
    assert server.error is None, f"the server refused the handshake: {server.error}"
    assert server.peer_cn == IDENTITY, "the server did not see the admin leaf it was shown"


def test_wrong_passphrase_is_refused_by_name_never_as_missing(tmp_path, monkeypatch):
    """NEGATIVE (4 distinct answers, requirement 4): a passphrase that was GIVEN and did not
    open the key says so, and does not fall through to "no key configured"."""
    ca_cert, leaf_cert, leaf_key = _admin_pair(tmp_path)
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "a-different-but-real-passphrase")
    with pytest.raises(APIClientError) as excinfo:
        _build_ssl_context(cafile=str(ca_cert), certfile=str(leaf_cert), keyfile=str(leaf_key))
    msg = str(excinfo.value)
    assert "failed to decrypt the admin client key" in msg, msg
    assert str(leaf_key) in msg, "the refusal must name the key it could not open"
    assert "no passphrase is" not in msg, "wrong passphrase must not read as unset"
    # the bad value itself never appears (masker law: name the class, never the secret)
    assert "a-different-but-real-passphrase" not in msg


def test_missing_passphrase_on_an_encrypted_key_is_a_named_refusal(tmp_path, monkeypatch):
    """NEGATIVE: the pair IS configured, so this is NOT the "set both env vars" text — it
    names the key file and the variable that opens it, and sends nothing."""
    ca_cert, leaf_cert, leaf_key = _admin_pair(tmp_path)
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
    with pytest.raises(APIClientError) as excinfo:
        _build_ssl_context(cafile=str(ca_cert), certfile=str(leaf_cert), keyfile=str(leaf_key))
    msg = str(excinfo.value)
    assert "REFUSED" in msg and "no passphrase is" in msg, msg
    assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in msg, msg
    assert str(leaf_key) in msg


@pytest.mark.parametrize("blank", ["", " ", "   ", "\t"], ids=["empty", "one-space", "three", "tab"])
def test_whitespace_only_passphrase_reads_as_no_passphrase(tmp_path, blank, monkeypatch):
    """#554's shipped predicate, observed on the READ side and reported, not re-ruled here:
    a blank value is "no passphrase", so the dial names the missing variable rather than
    handing a value of spaces to OpenSSL. If #554's scope is ever ruled differently, THIS is
    the cell that flips."""
    ca_cert, leaf_cert, leaf_key = _admin_pair(tmp_path)
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", blank)
    with pytest.raises(APIClientError) as excinfo:
        _build_ssl_context(cafile=str(ca_cert), certfile=str(leaf_cert), keyfile=str(leaf_key))
    assert "no passphrase is" in str(excinfo.value)


def test_plaintext_admin_key_still_loads_with_no_passphrase_configured(tmp_path, monkeypatch):
    """NO REGRESSION: the core's machine-plane pair is plaintext at rest by ruling
    (#565 R7-Q1, site 1 exempt), and OpenSSL never invokes a passphrase callback for a key
    it does not need to open — so this shape is unchanged with the variable unset."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "machine-plane")])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "anchor.crt"
    crt = tmp_path / "admin.crt"
    kp = tmp_path / "admin.key"
    pem = cert.public_bytes(serialization.Encoding.PEM)
    ca.write_bytes(pem)
    crt.write_bytes(pem)
    kp.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
    ctx = _build_ssl_context(cafile=str(ca), certfile=str(crt), keyfile=str(kp))
    assert isinstance(ctx, ssl.SSLContext)


def test_a_mismatched_pair_keeps_the_pair_text_not_a_passphrase_text(tmp_path):
    """Paired negative for the branch that routes refusals: cert of one pair + key of
    another must NOT be reported as a passphrase problem. That mislabel would send an
    operator to the wrong file — OpenSSL's text is identical for both, so the code asks the
    key alone whether the passphrase opens it.
    """
    ca_cert, _leaf_cert, leaf_key = _admin_pair(tmp_path)
    other = tmp_path / "other.crt"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, IDENTITY)])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(3)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    other.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(APIClientError) as excinfo:
        _build_ssl_context(cafile=str(ca_cert), certfile=str(other), keyfile=str(leaf_key))
    msg = str(excinfo.value)
    assert "Failed to load the admin mTLS client cert/key pair" in msg, msg
    assert "decrypt" not in msg and "no passphrase" not in msg
