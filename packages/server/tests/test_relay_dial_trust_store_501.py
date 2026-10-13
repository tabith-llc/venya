# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#501 relay-dial-system-trust-store — the relay dial anchors on the Venya CA ONLY.

`ssl.create_default_context()` calls `load_default_certs()`, and
`load_verify_locations()` ADDS to the trust set instead of replacing it, so at HEAD
the core->executor relay accepted any leaf issued by any CA the host happens to
trust for the executor hostname. This suite pins the trust SET by mechanism: it
runs the real route, captures the context production hands to
`httpx2.AsyncClient(verify=...)`, and drives an in-process TLS handshake (MemoryBIO
— no sockets, no fleet, no network) against a leaf signed by each CA.

The host trust store is stood in for by `SSL_CERT_FILE`, which
`set_default_verify_paths()` (and therefore `load_default_certs()`) honors — the
very path `create_default_context()` used to pull public CAs in.
"""

import ast
import datetime
import ssl
from datetime import UTC, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from server.ca import CAManager
from starlette.testclient import TestClient

from tests.test_execution_relay import _create_test_app

EXECUTOR_HOST = "venya-exec-1"
VALIDITY = datetime.timedelta(days=365)
SERVER_SRC = Path(__file__).resolve().parents[1] / "src" / "server"


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Same read-write grant the relay suite installs (it is module-scoped there)."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


# ---------------------------------------------------------------------------
# Certificate material — the product CA for the Venya side, a mirror-image CA
# for the "present in the host store, but not the Venya CA" side.
# ---------------------------------------------------------------------------


def _venya_ca(tmp_path, monkeypatch) -> CAManager:
    """A CA dir carrying the installer's root shape, usable by the product signer.

    ``install-venya-core.sh`` mints the shipped root WITH a SubjectKeyIdentifier
    (and an AKI built from it); ``CAManager.initialize()`` omits the SKI, which
    matters here because ``VERIFY_X509_STRICT`` — set at HEAD by
    ``create_default_context()`` and preserved by this fix — rejects a chain whose
    CA carries no SKI when the leaf asserts an AKI key identifier. The fixture
    therefore mirrors the SHIPPED root, and the leaf is still signed by the real
    ``CAManager.sign_csr`` so the leaf extension set is production's.
    """
    monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
    ca_dir = tmp_path / "venya-ca"
    cert, key = _mint_root("Venya Root CA", ca_dir)
    _write_pair(ca_dir, cert, key)
    return CAManager(str(ca_dir))


def _mint_root(common_name: str, ca_dir: Path | None = None, organization: str = "Venya"):
    """Self-signed root in the shipped shape: BC + KeyUsage + SKI + AKI."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(UTC)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**_CA_KEY_USAGE), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _write_pair(ca_dir: Path, cert, key) -> None:
    """Land a root as ca.crt/ca.key (unencrypted key — unit fixture only)."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ca_dir / "ca.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _sign_venya_leaf(manager: CAManager, executor_id: str = EXECUTOR_HOST):
    """A leaf minted the product way: P-256 CSR -> CAManager.sign_csr."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, executor_id)]))
        .sign(key, hashes.SHA256())
    )
    return manager.sign_csr(csr, executor_id), key


_CA_KEY_USAGE = {
    "digital_signature": False,
    "key_encipherment": False,
    "content_commitment": False,
    "data_encipherment": False,
    "key_agreement": False,
    "key_cert_sign": True,
    "crl_sign": True,
    "encipher_only": False,
    "decipher_only": False,
}


def _foreign_ca():
    """ "Public" CA: the shipped root's shape, a different subject and key.

    Not the Venya CA; the tests place it in the host trust store via
    SSL_CERT_FILE. KeyUsage and SKI are present so a rejection can never be
    blamed on extension strictness instead of the anchor set.
    """
    return _mint_root("Example Public Root CA", None, organization="Example Public")


def _foreign_leaf(ca_cert, ca_key, hostname: str = EXECUTOR_HOST):
    """A leaf for the executor hostname signed by the foreign (host-store) CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _write_material(tmp_path, name: str, cert, key) -> tuple[str, str]:
    """PEM a cert/key pair to disk; returns (cert_path, key_path)."""
    cert_path = tmp_path / f"{name}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / f"{name}.key"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


# ---------------------------------------------------------------------------
# Relay harness: the session/executor DB mocks from the relay suite, with REAL
# TLS material on disk (nothing about the context build is mocked).
# ---------------------------------------------------------------------------


def _relay_app(ca_dir: str, mtls: tuple[str, str] | None = None):
    """App wired for one relay call; returns (app, backend)."""
    app, backend = _create_test_app()
    app.state.config.ca_dir = ca_dir
    app.state.config.mtls_cert, app.state.config.mtls_key = mtls if mtls else (None, None)

    db = MagicMock()
    session = MagicMock()
    session.id = "sess-1"
    session.user_id = "test-user"
    session.expires_at = datetime.datetime.now(UTC) + timedelta(minutes=5)
    session.executor_id = "exec-1"
    session.command = ""
    session.completed_at = None
    session.exit_code = None
    session.stdout = None
    session.stderr = None

    executor = MagicMock()
    executor.id = "exec-1"
    executor.hostname = EXECUTOR_HOST
    executor.revoked_at = None
    executor.serial_number = None
    executor.version = None

    def query_side_effect(model):
        if model.__name__ == "ExecutionSession":
            return session_query
        if model.__name__ == "Executor":
            return executor_query
        if model.__name__ == "SessionSecret":
            return secrets_query
        if model.__name__ == "ExecutorCert":
            # #586: the relay dial refuses an executor with no registered, current
            # certificate (503), so a cell that wants the dial to RUN must model one.
            # The revocation row query below still returns None → the record reads LIVE.
            cert_q = MagicMock()
            cert_q.filter.return_value.first.return_value = SimpleNamespace(
                serial_number="0000000000001000",
                not_after=datetime.datetime.now(datetime.UTC) + timedelta(days=30),
            )
            return cert_q
        if model.__name__ == "ExecutorCertRevocation":
            none_q = MagicMock()
            none_q.filter.return_value.first.return_value = None
            return none_q
        return session_query

    session_query = MagicMock()
    session_query.filter.return_value.first.return_value = session
    executor_query = MagicMock()
    executor_query.filter.return_value.first.return_value = executor
    secrets_query = MagicMock()
    secrets_query.all.return_value = []

    db.query.side_effect = query_side_effect
    db.add = MagicMock()
    db.commit = MagicMock()
    backend.get_session.return_value = db
    return app, backend


def _relay_dial_context(app, monkeypatch) -> ssl.SSLContext | None:
    """POST one command through the real route; return the verify= context.

    httpx2.AsyncClient is stubbed at the CONSTRUCTOR, so the dial never leaves
    the process and the captured `verify=` is the production-built context.
    A None return means the route refused before dialing (status != 200).
    """
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    captured: dict = {}

    def _capture_client(*args, **kwargs):
        captured["verify"] = kwargs.get("verify")
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"exit_code": 0, "stdout": "", "stderr": "", "masked_count": 0}
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        client.post = AsyncMock(return_value=response)
        return client

    with patch("server.routes.executors.httpx2.AsyncClient", side_effect=_capture_client):
        test_client = TestClient(app, raise_server_exceptions=False)
        resp = test_client.post(
            "/api/v1/executors/exec-1/execute",
            json={"session_id": "sess-1", "command": ["echo", "hello"]},
        )
    assert resp.status_code == 200, f"relay refused before dialing: {resp.status_code} {resp.text}"
    ctx = captured.get("verify")
    assert isinstance(ctx, ssl.SSLContext), f"relay handed httpx2 a non-context: {ctx!r}"
    return ctx


def _anchor_subjects(ctx: ssl.SSLContext) -> list[str]:
    """CommonName of every CA cert actually loaded in this context's trust store.

    ``get_ca_certs()`` returns OpenSSL ASN.1 tuples: subject is a sequence of
    RDNs, each a sequence of ``(label, value)`` pairs where the label is
    ``'commonName'`` (dotted-string form also accepted for portability).
    """
    cn_labels = {"commonName", NameOID.COMMON_NAME.dotted_string}
    subjects = []
    for cert in ctx.get_ca_certs():
        cn = next(
            (str(attr[1]) for rdn in cert["subject"] for attr in rdn if str(attr[0]) in cn_labels),
            "?",
        )
        subjects.append(cn)
    return subjects


def _server_context(cert_path: str, key_path: str, client_ca: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    if client_ca:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=client_ca)
    return ctx


def _client_handshake(client_ctx, server_ctx, hostname=EXECUTOR_HOST) -> bool:
    """Drive one in-process handshake; True = the client accepted the server leaf.

    Raises ssl.SSLCertVerificationError when the client refuses the chain — the
    rejection the paired-negative cell asserts on.
    """
    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    client_done = server_done = False
    for _ in range(64):
        to_server, to_client = c_out.read(), s_out.read()
        if to_server:
            s_in.write(to_server)
        if to_client:
            c_in.write(to_client)
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        if client_done and server_done:
            return True
    raise AssertionError("TLS handshake reached no conclusion")


# ---------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------


class TestRelayDialTrustStore:
    def test_relay_anchors_only_the_venya_ca(self, tmp_path, monkeypatch):
        """Trust set == the Venya CA, even with a public CA in the host store.

        RED at HEAD: create_default_context() loaded the host store first and
        load_verify_locations() only ADDED the Venya root, so the anchor list
        came back as ['Example Public Root CA', 'Venya Root CA'].
        """
        venya = _venya_ca(tmp_path, monkeypatch)
        foreign_cert, foreign_key = _foreign_ca()
        foreign_ca_path, _ = _write_material(tmp_path, "public-ca", foreign_cert, foreign_key)
        monkeypatch.setenv("SSL_CERT_FILE", foreign_ca_path)

        app, _backend = _relay_app(str(venya.ca_dir))
        ctx = _relay_dial_context(app, monkeypatch)

        assert _anchor_subjects(ctx) == ["Venya Root CA"]

    def test_relay_accepts_a_venya_ca_signed_leaf(self, tmp_path, monkeypatch):
        """GREEN preserved: the dial still verifies a real CAManager-signed leaf."""
        venya = _venya_ca(tmp_path, monkeypatch)
        leaf, leaf_key = _sign_venya_leaf(venya)
        cert_path, key_path = _write_material(tmp_path, "venya-leaf", leaf, leaf_key)
        foreign_cert, foreign_key = _foreign_ca()
        foreign_ca_path, _ = _write_material(tmp_path, "public-ca-accept", foreign_cert, foreign_key)
        monkeypatch.setenv("SSL_CERT_FILE", foreign_ca_path)

        app, _backend = _relay_app(str(venya.ca_dir))
        ctx = _relay_dial_context(app, monkeypatch)

        assert _client_handshake(ctx, _server_context(cert_path, key_path)) is True

    def test_relay_rejects_a_host_store_signed_leaf(self, tmp_path, monkeypatch):
        """Paired negative: a leaf for the SAME hostname signed by a host-store CA
        is refused. RED at HEAD — that chain validated, because the private
        control plane shared its trust set with the public PKI.
        """
        venya = _venya_ca(tmp_path, monkeypatch)
        foreign_cert, foreign_key = _foreign_ca()
        foreign_ca_path, _ = _write_material(tmp_path, "public-ca-neg", foreign_cert, foreign_key)
        leaf, leaf_key = _foreign_leaf(foreign_cert, foreign_key)
        cert_path, key_path = _write_material(tmp_path, "public-leaf", leaf, leaf_key)
        monkeypatch.setenv("SSL_CERT_FILE", foreign_ca_path)

        app, _backend = _relay_app(str(venya.ca_dir))
        ctx = _relay_dial_context(app, monkeypatch)

        with pytest.raises(ssl.SSLCertVerificationError) as excinfo:
            _client_handshake(ctx, _server_context(cert_path, key_path))
        # the failure is the anchor set, not a hostname or extension quibble
        assert "unable to get local issuer certificate" in str(excinfo.value)

    def test_relay_still_carries_the_mtls_client_chain(self, tmp_path, monkeypatch):
        """The client half of the dial survives the anchor fix (mTLS both ways)."""
        venya = _venya_ca(tmp_path, monkeypatch)
        leaf, leaf_key = _sign_venya_leaf(venya)
        leaf_cert_path, leaf_key_path = _write_material(tmp_path, "venya-leaf-mtls", leaf, leaf_key)

        app, _backend = _relay_app(str(venya.ca_dir), mtls=(leaf_cert_path, leaf_key_path))
        ctx = _relay_dial_context(app, monkeypatch)

        server_ctx = _server_context(leaf_cert_path, leaf_key_path, client_ca=str(venya.ca_cert_path))
        assert _client_handshake(ctx, server_ctx) is True
        assert _anchor_subjects(ctx) == ["Venya Root CA"]

    def test_relay_keeps_the_verification_flags_the_old_line_set(self, tmp_path, monkeypatch):
        """No silent relaxation: CERT_REQUIRED + hostname check + both strict flags.

        Guards the bare-context trap: PROTOCOL_TLS_CLIENT alone does NOT carry
        VERIFY_X509_STRICT / VERIFY_X509_PARTIAL_CHAIN, which create_default_context()
        applied at HEAD, and it pins TLS 1.2 as the floor.
        """
        venya = _venya_ca(tmp_path, monkeypatch)
        app, _backend = _relay_app(str(venya.ca_dir))
        ctx = _relay_dial_context(app, monkeypatch)

        assert ctx.verify_mode is ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert ctx.verify_flags & ssl.VERIFY_X509_STRICT
        assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_relay_without_an_anchor_is_503_not_the_system_store(self, tmp_path, monkeypatch):
        """Fail-closed posture kept: an anchor-less core answers 503 rather than
        dialing on the host store — the CLI/executor `else: load_default_certs()`
        branch is deliberately NOT copied to the secret-carrying relay."""
        _venya_ca(tmp_path, monkeypatch)
        empty = tmp_path / "no-anchor"
        empty.mkdir()
        foreign_cert, foreign_key = _foreign_ca()
        foreign_ca_path, _ = _write_material(tmp_path, "public-ca-failclosed", foreign_cert, foreign_key)
        monkeypatch.setenv("SSL_CERT_FILE", foreign_ca_path)

        app, _backend = _relay_app(str(empty))
        test_client = TestClient(app, raise_server_exceptions=False)
        with patch("server.routes.executors.httpx2.AsyncClient") as client_cls:
            resp = test_client.post(
                "/api/v1/executors/exec-1/execute",
                json={"session_id": "sess-1", "command": ["echo", "hello"]},
            )
        assert resp.status_code == 503
        assert "TLS misconfiguration" in resp.json()["detail"]
        client_cls.assert_not_called()  # nothing was dialed on host trust


class TestRelayDefaultContextSweep:
    """Criterion 4 witness (AST, not text): the relay module makes no
    `ssl.create_default_context()` call. The full site list across packages —
    including the ones #501 does NOT touch — is carried in the report.
    """

    @staticmethod
    def _call_sites(py_file: Path) -> list[int]:
        tree = ast.parse(py_file.read_text(), filename=str(py_file))
        lines = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name == "create_default_context":
                    lines.append(node.lineno)
        return lines

    def test_server_source_has_no_default_context_call_left(self):
        offenders = {}
        for py_file in sorted(SERVER_SRC.rglob("*.py")):
            lines = self._call_sites(py_file)
            if lines:
                offenders[str(py_file.relative_to(SERVER_SRC))] = lines
        assert offenders == {}, f"unrelated default-trust dials reappeared: {offenders}"
