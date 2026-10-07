# Copyright (c) 2026 Tabith LLC.
# Use of this source code is available under the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under the MIT License.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for login-path CA diagnostics (ticket cli-login-ca-error-message / 439).

The login trust failure must name the trust FILE and the REPAIR command
(`venya setup <core>`), and must tell an ABSENT ca.crt apart from a PRESENT-BUT-
NOT-A-CERTIFICATE one. Today the operator gets raw OpenSSL text naming neither
path nor remedy — RED baselines for T1/T2 below are that defect.

Truth-table pair per the standing rule: T3 guards the good path (valid CA still
builds a verifying context — no unverified fallback introduced).

No network: T2 drives Fido2Auth._get with a patched transport that raises the
exact ConnectError class a real TLS verification failure surfaces as.
"""

from __future__ import annotations

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
from venya_cli.api_client import APIClientError, _build_ssl_context
from venya_cli.fido2_client import Fido2Auth, Fido2ClientError


def _make_ca(tmp_path: Path) -> Path:
    """Self-signed CA-shaped PEM — construction exercises loading, not handshakes."""
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t439-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    ca = tmp_path / "ca.crt"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca


def _connect_error_with_ssl_cause(url: str) -> httpx2.ConnectError:
    """The exception shape httpx raises when OpenSSL refuses the handshake
    because the peer cert chains to no loaded anchor (the system-trust case)."""
    inner = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "unable to get local issuer certificate (_ssl.c:1016)"
    )
    err = httpx2.ConnectError(str(inner), request=httpx2.Request("GET", url))
    err.__cause__ = inner
    return err


class TestLoginCaDiagnostics439:
    def test_T1_invalid_ca_names_path_and_setup(self, tmp_path: Path):
        """T1: ca.crt holding non-certificate bytes must fail with a message
        naming the resolved path AND `venya setup` — never raw OpenSSL alone.

        RED at tip 439-base: load_verify_locations raises ssl.SSLError whose
        text ("[X509: NO_CERTIFICATE_OR_CRL_FOUND] ... (_ssl.c:4416)") carries
        neither the path nor the repair.
        """
        bad = tmp_path / "ca.crt"
        bad.write_bytes(b"this is not a certificate - staging script wrote text here\n")
        with pytest.raises(APIClientError) as excinfo:
            _build_ssl_context(cafile=str(bad), certfile=None, keyfile=None)
        msg = str(excinfo.value)
        assert str(bad) in msg, f"resolved CA path missing from: {msg}"
        assert "venya setup" in msg, f"repair command missing from: {msg}"

    def test_T2_stale_ca_names_file_and_differs_from_invalid(self, tmp_path: Path, monkeypatch):
        """T2: with a config-dir CA INSTALLED and the server failing to verify
        against it (the ordinary shape after a core reinstall), the ceremony error
        must name the trusted FILE and the REPAIR, and read differently from the
        invalid-file message.

        #533 changed what "no CA" means here: an ABSENT anchor is now a refusal
        before the dial (test_cli_fido2_ceremony_anchor_533.py), so this cell
        covers the case the hint still owns — an anchor that exists and did not
        verify. RED at the pre-439 tip: the ceremony error was
        'Connection failed: <raw ssl text>' — no path, no repair.
        """
        ca = _make_ca(tmp_path)
        url = "https://core.example.invalid/api/v1/auth/options"
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        auth = Fido2Auth("https://core.example.invalid", ca_path=ca)
        assert auth._anchor == str(ca)  # anchored — the case the hint owns

        with patch("venya_cli.fido2_client.httpx2.Client") as client_cls:
            client_cls.return_value.__enter__.return_value.get.side_effect = _connect_error_with_ssl_cause(url)
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._get("/api/v1/auth/options")
        msg = str(excinfo.value)
        assert str(ca) in msg, f"trusted CA path missing from: {msg}"
        assert "did not verify" in msg.lower(), f"verification statement missing from: {msg}"
        assert "venya setup" in msg, f"repair command missing from: {msg}"
        # #533: the wording no longer claims a system-store fallback happened.
        assert "system trust store" not in msg and "system store" not in msg

        # The two failure classes must be distinguishable from each other.
        bad = tmp_path / "bad-ca" / "ca.crt"
        bad.parent.mkdir()
        bad.write_bytes(b"not a certificate\n")
        with pytest.raises(APIClientError) as invalid_exc:
            _build_ssl_context(cafile=str(bad), certfile=None, keyfile=None)
        assert str(excinfo.value) != str(invalid_exc.value)

    def test_T3_valid_ca_still_builds_verifying_context(self, tmp_path: Path):
        """T3 (regression guard, GREEN before and after): a valid CA yields a
        verifying context — CERT_REQUIRED + hostname check; no unverified path.
        """
        ca = _make_ca(tmp_path)
        ctx = _build_ssl_context(cafile=str(ca), certfile=None, keyfile=None)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
