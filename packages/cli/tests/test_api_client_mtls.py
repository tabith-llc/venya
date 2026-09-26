# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth-table tests for APIClient admin mTLS client-cert support.

Ticket cli-admin-mtls-verify-cert-conflict (option (a) ruling): the client
cert rides an ssl.SSLContext passed as `verify=` — NEVER the httpx2 `cert=`
kwarg (httpx2 >= 2.12 rejects cert= combined with a string verify, which
TypeErrored EVERY admin-mTLS command in the natural flow: config CA + cert
env + no SSL_CERT_FILE). The real-construction class below reproduces that
field bug without mocking httpx2.Client — the mocked truth table above it
kept passing for months precisely because construction was never live.
"""

import datetime
import ssl
from pathlib import Path
from unittest.mock import patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError, _build_ssl_context


def _make_cert_key(tmp_path: Path, name: str) -> tuple[Path, Path]:
    """Generate a real self-signed Ed25519 cert+key pair (PEM, unencrypted).

    Self-signed is sufficient: these tests exercise TLS context construction
    (load_verify_locations / load_cert_chain), never a handshake.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    cert_p = tmp_path / f"{name}.crt"
    key_p = tmp_path / f"{name}.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_p, key_p


def _ctx_cn(ctx: ssl.SSLContext) -> set[str]:
    """Common names among the trust anchors loaded into ctx."""
    names = set()
    for cert in ctx.get_ca_certs():
        for rdn in cert["subject"]:
            for attr, value in rdn:
                if attr == "commonName":
                    names.add(value)
    return names


class TestBuildSslContext:
    """Helper-level truth table for the unified context (ticket option (a))."""

    def test_ca_only_context_carries_the_ca(self, tmp_path: Path):
        ca, _ = _make_cert_key(tmp_path, "test-ca")
        ctx = _build_ssl_context(cafile=str(ca), certfile=None, keyfile=None)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert "test-ca" in _ctx_cn(ctx)

    def test_cert_chain_loads_alongside_ca(self, tmp_path: Path):
        ca, _ = _make_cert_key(tmp_path, "test-ca")
        cert, key = _make_cert_key(tmp_path, "admin")
        ctx = _build_ssl_context(cafile=str(ca), certfile=str(cert), keyfile=str(key))
        assert "test-ca" in _ctx_cn(ctx)
        # load_cert_chain succeeding IS the assertion (a bad pair raises).

    def test_mismatched_cert_key_raises_apiclienterror_not_sslerror(self, tmp_path: Path):
        """Paired negative: cert of one pair + key of another → loud
        APIClientError naming the mTLS pair, never a raw ssl traceback."""
        ca, _ = _make_cert_key(tmp_path, "test-ca")
        cert, _ = _make_cert_key(tmp_path, "admin-a")
        _, key = _make_cert_key(tmp_path, "admin-b")
        with pytest.raises(APIClientError, match="mTLS"):
            _build_ssl_context(cafile=str(ca), certfile=str(cert), keyfile=str(key))

    def test_no_cafile_falls_back_to_system_trust(self):
        ctx = _build_ssl_context(cafile=None, certfile=None, keyfile=None)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        # NOTE: get_ca_certs() stays empty here BY DESIGN — load_default_certs()
        # routes through OpenSSL's default-path lookup (set_default_verify_paths),
        # which does not populate the introspectable store. Construction success
        # + strict verify flags are the observable contract.


class TestRealConstructionNoMock:
    """REAL httpx2.Client construction — the cells the mocked table cannot see."""

    def test_natural_flow_mtls_plus_config_ca_constructs(self, tmp_path: Path, monkeypatch):
        """The field-bug repro: config CA (venya setup) + admin mTLS env +
        NO SSL_CERT_FILE. Pre-fix this raised TypeError inside httpx2
        (cert= + verify=<str> forbidden); it is the natural documented flow."""
        ca, _ = _make_cert_key(tmp_path, "setup-ca")
        (tmp_path / "ca.crt").write_bytes(ca.read_bytes())  # Config.ca_path location
        cert, key = _make_cert_key(tmp_path, "admin")
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        client = APIClient(config_file=tmp_path / "config.json")
        try:
            assert isinstance(client._http, httpx2.Client)
            assert client.has_admin_mtls is True
        finally:
            client.close()

    def test_ssl_cert_file_env_wins_over_config_ca(self, tmp_path: Path, monkeypatch):
        """SSL_CERT_FILE precedence unchanged by the context unification."""
        env_ca, _ = _make_cert_key(tmp_path, "env-ca")
        cfg_ca, _ = _make_cert_key(tmp_path, "cfg-ca")
        (tmp_path / "ca.crt").write_bytes(cfg_ca.read_bytes())
        monkeypatch.setenv("SSL_CERT_FILE", str(env_ca))
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        captured: dict = {}
        import venya_cli.api_client as mod

        real = mod._build_ssl_context

        def spy(cafile, certfile, keyfile):
            captured["cafile"] = cafile
            return real(cafile, certfile, keyfile)

        monkeypatch.setattr(mod, "_build_ssl_context", spy)
        client = APIClient(config_file=tmp_path / "config.json")
        try:
            assert captured["cafile"] == str(env_ca)
        finally:
            client.close()

    def test_config_ca_used_when_no_env(self, tmp_path: Path, monkeypatch):
        """Precedence path 2: no SSL_CERT_FILE → the setup-installed CA."""
        cfg_ca, _ = _make_cert_key(tmp_path, "cfg-ca")
        (tmp_path / "ca.crt").write_bytes(cfg_ca.read_bytes())
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        captured: dict = {}
        import venya_cli.api_client as mod

        real = mod._build_ssl_context

        def spy(cafile, certfile, keyfile):
            captured["cafile"] = cafile
            return real(cafile, certfile, keyfile)

        monkeypatch.setattr(mod, "_build_ssl_context", spy)
        client = APIClient(config_file=tmp_path / "config.json")
        try:
            assert captured["cafile"] == str(tmp_path / "ca.crt")
        finally:
            client.close()


class TestAdminMtlsClientCert:
    """VENYA_ADMIN_CERT / VENYA_ADMIN_KEY env var handling in APIClient.__init__."""

    @patch("venya_cli.api_client.httpx2.Client")
    def test_both_set_constructs_with_ssl_context(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both env vars set → client constructed with verify=<SSLContext>
        carrying the client cert — NEVER the httpx2 cert= kwarg (ticket
        cli-admin-mtls-verify-cert-conflict: cert= + string verify TypeErrors
        on httpx2 >= 2.12, breaking every admin-mTLS command)."""
        cert, key = _make_cert_key(tmp_path, "admin")
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))

        APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        assert "cert" not in kwargs
        assert isinstance(kwargs["verify"], ssl.SSLContext)

    @patch("venya_cli.api_client.httpx2.Client")
    def test_neither_set_no_cert_param(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Neither env var set → no cert key in Client kwargs."""
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        assert "cert" not in kwargs

    @patch("venya_cli.api_client.httpx2.Client")
    def test_only_cert_set_raises_naming_key(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Only VENYA_ADMIN_CERT set → loud error naming the missing var."""
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "admin.crt"))
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        with pytest.raises(APIClientError, match="VENYA_ADMIN_KEY"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_only_key_set_raises_naming_cert(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Only VENYA_ADMIN_KEY set → loud error naming the missing var."""
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "admin.key"))

        with pytest.raises(APIClientError, match="VENYA_ADMIN_CERT"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_cert_path_does_not_exist_raises(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both set but cert file missing → actionable error."""
        key = tmp_path / "admin.key"
        key.write_text("dummy key")

        monkeypatch.setenv("VENYA_ADMIN_CERT", str(tmp_path / "nonexistent.crt"))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))

        with pytest.raises(APIClientError, match="does not exist"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_key_path_does_not_exist_raises(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both set but key file missing → actionable error."""
        cert = tmp_path / "admin.crt"
        cert.write_text("dummy cert")

        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "nonexistent.key"))

        with pytest.raises(APIClientError, match="does not exist"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()

    @patch("venya_cli.api_client.httpx2.Client")
    def test_has_admin_mtls_true_when_cert_configured(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Both env vars set (valid files) -> has_admin_mtls flag is True.

        run_command's headless gate reads this to exempt `admin` from FIDO2.
        """
        cert, key = _make_cert_key(tmp_path, "admin")
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))

        client = APIClient(config_file=tmp_path / "config.json")

        assert client.has_admin_mtls is True

    @patch("venya_cli.api_client.httpx2.Client")
    def test_has_admin_mtls_false_when_no_cert(self, mock_client_cls, tmp_path: Path, monkeypatch):
        """Neither env var set -> has_admin_mtls is False (gate fires normally)."""
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)

        client = APIClient(config_file=tmp_path / "config.json")

        assert client.has_admin_mtls is False
