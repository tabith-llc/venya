# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Startup identity probe must trust the configured Venya CA (#502).

``CertificateManager._verify_cert_recognized`` used to hand httpx2 a bare
``verify=True``, which means "the host trust store" — the CA the core's
certificate is actually signed by never entered the picture, so a correctly
enrolled executor could abort its own boot with the ghost-identity message.

Cells here:
  1. AC1  real TLS handshake against a server whose certificate comes from a
          private CA given as ``ca_bundle`` -> probe succeeds (RED at HEAD).
  2. AC2  paired negative: server certificate from an UNtrusted CA, the local
          anchor configured -> still the ruled ghost abort, not a downgrade.
  3. AC1b the same anchor taken from ``mtls.ca_cert`` (the file registration and
          rotation write), ``ca_bundle`` unset -> probe succeeds.
  4. AC4  sanctioned ``VENYA_TLS_VERIFY=false`` knob still turns verification off
          at this site, byte-identically.
  5. AC3  register() and the probe share one context construction (drift pin).
"""

import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.config import ExecutorConfig
from executor.daemon import CertificateManager

# --- PKI helpers (self-contained; full control over the issuing CA) ---

NOT_BEFORE = datetime.now(UTC) - timedelta(days=1)
NOT_AFTER = datetime.now(UTC) + timedelta(days=30)


def _ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A fresh ECDSA P-256 CA (self-signed, CA:true, key_cert_sign)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    *,
    dns_names: tuple[str, ...] = (),
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A CA-signed leaf (client or server) with optional DNS SANs."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
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
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        # OpenSSL 3 chain building wants the identifiers present, exactly as the
        # product CA puts them on a real executor/core leaf.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    if dns_names:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), False)
    return key, builder.sign(ca_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


# --- Real TLS server (handshake is not mocked — AC1/AC2 need the genuine path) ---


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        body = b'{"executor_id": "test-executor", "revoked": false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # silence the test server
        return


class _TlsServer:
    """Threaded HTTPS server on 127.0.0.1:0 with one server material set (files on disk)."""

    def __init__(self, cert_file, key_file) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_file), str(key_file))
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self._thread.start()
        return f"https://localhost:{self._httpd.server_address[1]}"

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def pki(tmp_path):
    """venya CA + an untrusted CA, and the on-disk client material."""
    venya_key, venya_cert = _ca("Venya Test CA")
    rogue_key, rogue_cert = _ca("Rogue CA")
    srv_key, srv_venya = _leaf(venya_key, venya_cert, "core.test", dns_names=("localhost",))
    rogue_srv_key, srv_rogue = _leaf(rogue_key, rogue_cert, "core.test", dns_names=("localhost",))
    cli_key, cli_cert = _leaf(venya_key, venya_cert, "test-executor")

    files = {
        "venya_ca": tmp_path / "venya-ca.crt",
        "rogue_ca": tmp_path / "rogue-ca.crt",
        "srv_venya": tmp_path / "srv-venya.crt",
        "srv_venya_key": tmp_path / "srv-venya.key",
        "srv_rogue": tmp_path / "srv-rogue.crt",
        "srv_rogue_key": tmp_path / "srv-rogue.key",
        "client": tmp_path / "executor.crt",
        "client_key": tmp_path / "executor.key",
    }
    files["venya_ca"].write_bytes(_pem(venya_cert))
    files["rogue_ca"].write_bytes(_pem(rogue_cert))
    files["srv_venya"].write_bytes(_pem(srv_venya))
    files["srv_venya_key"].write_bytes(_key_pem(srv_key))
    files["srv_rogue"].write_bytes(_pem(srv_rogue))
    files["srv_rogue_key"].write_bytes(_key_pem(rogue_srv_key))
    files["client"].write_bytes(_pem(cli_cert))
    files["client_key"].write_bytes(_key_pem(cli_key))
    return SimpleNamespace(**files)


def _manager(tmp_path, *, ca_bundle: str | None = None, mtls_ca: str | None = None) -> CertificateManager:
    """CertificateManager wired to the on-disk client pair; server_url set by callers."""
    return CertificateManager(
        ExecutorConfig.model_validate(
            {
                "server_url": "https://localhost:1",
                "executor_id": "test-executor",
                "ca_bundle": ca_bundle,
                "mtls": {
                    "cert": str(tmp_path / "executor.crt"),
                    "key": str(tmp_path / "executor.key"),
                    "ca_cert": mtls_ca or str(tmp_path / "missing-ca.crt"),
                },
            }
        )
    )


def _manager_at(tmp_path, url: str, *, ca_bundle: str | None, mtls_ca: str | None) -> CertificateManager:
    """Same wiring as _manager(), pointed at a live server URL."""
    return CertificateManager(
        ExecutorConfig.model_validate(
            {
                "server_url": url,
                "executor_id": "test-executor",
                "ca_bundle": ca_bundle,
                "mtls": {
                    "cert": str(tmp_path / "executor.crt"),
                    "key": str(tmp_path / "executor.key"),
                    "ca_cert": mtls_ca or str(tmp_path / "missing-ca.crt"),
                },
            }
        )
    )


# --- 1. AC1: configured ca_bundle is the trust anchor (real handshake) ---


class TestProbeTrustsConfiguredCa:
    def test_probe_succeeds_against_private_ca_server(self, tmp_path, pki):
        """RED at HEAD: the handshake was verified against the host store, the
        private CA in ca_bundle was never loaded, and the probe raised the ghost
        abort for a legitimately enrolled executor."""
        with _TlsServer(pki.srv_venya, pki.srv_venya_key) as url:
            cm = _manager_at(tmp_path, url, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
            cm._verify_cert_recognized("test-executor")  # must not raise

    def test_probe_succeeds_with_anchor_from_mtls_ca_cert(self, tmp_path, pki):
        """AC1b: the registration/rotation file (mtls.ca_cert) alone is an anchor —
        the daemon's heartbeat client already uses it (``_create_mtls_client``), so a
        deployment that sets only that path must not fail its own boot probe."""
        with _TlsServer(pki.srv_venya, pki.srv_venya_key) as url:
            cm = _manager_at(tmp_path, url, ca_bundle=None, mtls_ca=str(pki.venya_ca))
            cm._verify_cert_recognized("test-executor")  # must not raise


# --- 2. AC2: paired negative — an untrusted CA is still rejected, still ghost ---


class TestProbeRejectsUntrustedCa:
    def test_untrusted_ca_still_ghost_aborts(self, tmp_path, pki, caplog):
        """Server certificate signed by a CA nobody configured: the handshake must
        still fail, and the failure must still be CLASSIFIED as the ruled ghost
                abort. Verification was not downgraded to make cell 1 pass."""
        with _TlsServer(pki.srv_rogue, pki.srv_rogue_key) as url:
            cm = _manager_at(tmp_path, url, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
            with pytest.raises(RuntimeError, match="ghost identity") as ei:
                cm._verify_cert_recognized("test-executor")
        assert "Refusing to run as a ghost identity" in str(ei.value)

    def test_wrong_ca_uses_the_tls_handshake_class_not_a_new_one(self, tmp_path, pki):
        """The reject travels through ``_is_tls_handshake_failure`` (shape 3 in the
        docstring) — a fix that swallowed SSL errors into the INCONCLUSIVE path
        would pass cell 1 by weakening the verdict; this pins it does not."""
        with _TlsServer(pki.srv_rogue, pki.srv_rogue_key) as url:
            cm = _manager_at(tmp_path, url, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
            with pytest.raises(httpx2.TransportError) as ei:
                with httpx2.Client(
                    cert=(str(pki.client), str(pki.client_key)),
                    verify=cm._server_ssl_context(),
                    timeout=10.0,
                ) as client:
                    client.post(f"{url}/api/v1/heartbeat", json={"executor_id": "test-executor"})
            from executor.daemon import _is_tls_handshake_failure

            assert _is_tls_handshake_failure(ei.value) is True


# --- 3. AC4: the sanctioned dev knob still turns verification off at this site ---


class TestProbeKnobStaysByteIdentical:
    def test_false_knob_passes_verify_false(self, tmp_path, pki, monkeypatch, caplog):
        """``VENYA_TLS_VERIFY=false`` -> verify=False, no anchor context built, same
        warning line. Ruled-by-design dev behaviour (sec-sweep-low-informational)."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        ok = MagicMock(spec=httpx2.Response)
        ok.status_code = 200
        cm = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
        with caplog.at_level("WARNING"):
            with patch("executor.daemon.httpx2.Client") as MockClient:
                MockClient.return_value.__enter__.return_value = MockClient.return_value
                MockClient.return_value.post.return_value = ok
                cm._verify_cert_recognized("test-executor")
        assert MockClient.call_args[1]["verify"] is False
        assert MockClient.call_args[1]["cert"] == (str(pki.client), str(pki.client_key))
        assert "identity probe skips TLS verification" in caplog.text

    def test_unset_knob_passes_an_ssl_context_not_true(self, tmp_path, pki, monkeypatch):
        """The defect's shape: bare ``verify=True`` means the system store. With the
        knob unset the site must hand over a context, never the boolean."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        ok = MagicMock(spec=httpx2.Response)
        ok.status_code = 200
        cm = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = ok
            cm._verify_cert_recognized("test-executor")
        verify = MockClient.call_args[1]["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert verify.verify_mode is ssl.CERT_REQUIRED
        assert verify.check_hostname is True


# --- 4. AC3: one construction, both paths (drift pin) ---


class TestSharedContextConstruction:
    def test_both_sites_call_the_one_builder(self, tmp_path, pki, monkeypatch):
        """register() and the identity probe build their verify parameter through
        ``_server_ssl_context`` — a future edit at one site cannot silently skip the
        anchors again, because both paths now go through one symbol."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        calls: list[str] = []

        def _spy(_self: CertificateManager) -> ssl.SSLContext:
            calls.append("built")
            return ctx

        ok = MagicMock(spec=httpx2.Response)
        ok.status_code = 200
        cm = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
        with patch.object(CertificateManager, "_server_ssl_context", _spy):
            with patch("executor.daemon.httpx2.Client") as MockClient:
                MockClient.return_value.__enter__.return_value = MockClient.return_value
                MockClient.return_value.post.return_value = ok
                cm._verify_cert_recognized("test-executor")
        assert MockClient.call_args[1]["verify"] is ctx
        assert calls == ["built"]

    def test_builder_loads_both_anchors_when_present(self, tmp_path, pki):
        """The builder adds ca_bundle AND the registration-written CA file, and
        tolerates an absent path (a fresh install has no CA file yet)."""
        bare = ssl.create_default_context()
        base = bare.cert_store_stats()["x509_ca"]
        cm = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
        ctx = cm._server_ssl_context()
        assert ctx.cert_store_stats()["x509_ca"] >= base + 1
        subjects = repr(ctx.get_ca_certs())
        assert "Venya Test CA" in subjects
        # A bundle-only manager still gets its anchor.
        bundle_only = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=None)
        assert "Venya Test CA" in repr(bundle_only._server_ssl_context().get_ca_certs())

    def test_builder_tolerates_missing_anchor_files(self, tmp_path, pki):
        cm = _manager(tmp_path, ca_bundle=str(tmp_path / "nope-bundle.crt"), mtls_ca=str(tmp_path / "nope.crt"))
        ctx = cm._server_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)
        # No anchor loaded from the two absent paths — the context is still a
        # verifying one (CERT_REQUIRED), so a missing file never means "trust all".
        assert ctx.verify_mode is ssl.CERT_REQUIRED
        assert ctx.check_hostname is True


class TestGhostMessageUnchanged:
    def test_probe_still_raises_ruled_message_on_403(self, tmp_path, pki, monkeypatch):
        """App-level reject keeps the ruled re-enroll text (nothing here moved)."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        deny = MagicMock(spec=httpx2.Response)
        deny.status_code = 403
        cm = _manager(tmp_path, ca_bundle=str(pki.venya_ca), mtls_ca=str(pki.venya_ca))
        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = deny
            with pytest.raises(RuntimeError, match="ghost identity") as ei:
                cm._verify_cert_recognized("test-executor")
        assert "venya admin executor-enroll" in str(ei.value)
