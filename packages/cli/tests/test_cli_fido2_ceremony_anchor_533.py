# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Trust-anchor tests for the CLI FIDO2 ceremony dial (ticket cli-fido2-ceremony-dial-falls-back-to-host-store #533).

The defect: ``Fido2Auth.__init__`` ended in ``self._verify: str | bool = True``,
and both dials handed that straight to ``httpx2.Client(verify=...)``. With
``verify=True`` httpx asks OpenSSL for the WORKSTATION OS trust store, so the
WebAuthn ceremony — the credential that gates every admin action — was verified
against the host store whenever the config-dir ``ca.crt`` was absent (the
documented state on any host that never ran ``venya setup <core>``, and after
every core reinstall). A publicly-issued leaf for that hostname passed silently;
the old ``_tls_absent_hint`` only decorated a verification FAILURE, and a
publicly-trusted certificate never fails.

This is the workstation-ceremony half of #530 (bearer dial) and #501 (server
relay). The shape is inherited, not re-litigated:

  * the refusal lands at the DIAL, not at construction — ``venya setup <core>``
    is the repair the refusal names, and it must stay reachable (AC4).
  * ``SSL_CERT_FILE`` stays the explicit public-CA opt-in: the operator NAMES a
    bundle and that bundle becomes the anchor (AC2).
  * the anchored context is built by the same house builder,
    ``api_client._build_ssl_context``, so it loads ONLY the Venya anchor with
    ``CERT_REQUIRED`` + ``check_hostname`` on.

Truth table per the standing rule (the negative half is what shipped broken):
  * no anchor -> REFUSE, proved by PROHIBITION SHAPE: ``httpx2.Client`` is never
    constructed, and ``ssl.SSLContext.load_default_certs`` is rigged to explode
    and is never reached. An anchor-COUNT assertion would be a lying cell on
    this build — ``ssl.create_default_context()`` reports ``get_ca_certs() == 0``
    while the store is live (lead-verified hazard, AC5, do not re-derive).
  * anchor configured -> the ceremony proceeds, anchored, and the transport
    receives an ``ssl.SSLContext`` (never a bare ``True``).
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
from venya_cli.api_client import _anchor_refusal_text
from venya_cli.fido2_client import Fido2Auth, Fido2ClientError

TICKET_ID = "cli-fido2-ceremony-dial-falls-back-to-host-store"


def _make_ca(tmp_path: Path, name: str) -> Path:
    """Self-signed CA-shaped PEM — these cells exercise anchor loading, not handshakes."""
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
    path = tmp_path / f"{name}.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _anchor_cns(ctx: ssl.SSLContext) -> set[str]:
    """Common names of the anchors actually loaded into ctx."""
    names: set[str] = set()
    for cert in ctx.get_ca_certs():
        for rdn in cert["subject"]:
            for attr, value in rdn:
                if attr == "commonName":
                    names.add(value)
    return names


def _no_host_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prohibition shape: make ANY host-store load explode."""

    def _boom(*_a, **_k):
        raise AssertionError("load_default_certs() was reached — the ceremony dial fell back to the host store (#533)")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _boom)


def _connect_error_with_ssl_cause(url: str) -> httpx2.ConnectError:
    """The exception shape httpx raises when OpenSSL refuses the handshake."""
    inner = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "unable to get local issuer certificate (_ssl.c:1016)"
    )
    err = httpx2.ConnectError(str(inner), request=httpx2.Request("GET", url))
    err.__cause__ = inner
    return err


class TestNoAnchorRefuses:
    """AC1 + AC3 (negative half) — no anchor resolvable: refuse, dial nothing."""

    def test_absent_config_ca_refuses_at_the_dial_and_constructs_no_transport(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """RED at base: with the config-dir CA absent this transport dialed the host store."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = tmp_path / "ca.crt"  # deliberately NOT created
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            with pytest.raises(Fido2ClientError, match="no Venya TLS trust anchor"):
                auth._get("/api/v1/auth/login/start")
            # The 'nothing dialed' proof is on the transport, not a log string.
            mock_client_cls.assert_not_called()

    def test_absent_config_ca_refuses_on_the_post_side_too(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Both dial sites are covered — the assertion POST carries the credential."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = tmp_path / "ca.crt"
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            with pytest.raises(Fido2ClientError, match="no Venya TLS trust anchor"):
                auth._post("/api/v1/auth/login/complete", {"challenge_id": "c", "response": {}})
            mock_client_cls.assert_not_called()

    def test_no_ca_path_argument_refuses_as_loudly_as_an_absent_file(self, monkeypatch: pytest.MonkeyPatch):
        """The bare ``Fido2Auth(url)`` construction (ca_path never handed) is the
        same refusal, not a silent host-store dial."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        auth = Fido2Auth("https://venya-core-1")
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            with pytest.raises(Fido2ClientError, match="no Venya TLS trust anchor"):
                auth._get("/x")
            mock_client_cls.assert_not_called()

    def test_refusal_names_the_missing_material_the_prohibition_and_the_repair(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """AC1's three named parts (the #439 precedent: name the FILE, not just 'TLS failed')."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = tmp_path / "ca.crt"
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        with patch("venya_cli.fido2_client.httpx2.Client"):
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._get("/x")
        msg = str(excinfo.value)
        assert str(ca) in msg, f"the searched CA path is missing from: {msg}"
        assert "system trust store" in msg, f"the host-store prohibition is missing from: {msg}"
        assert "venya setup <core>" in msg, f"the repair command is missing from: {msg}"
        assert "SSL_CERT_FILE" in msg, f"the explicit opt-in route is missing from: {msg}"

    def test_construction_without_anchor_is_allowed_because_setup_is_the_repair(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """AC4: the refusal must land at the DIAL.

        ``venya setup <core>`` is the repair this refusal names, and the
        ceremony object is built before dispatch too — a construction-time raise
        would brick the repair on exactly the anchor-less host that needs it
        (the same tension #530 resolved on the bearer path; inherited).
        """
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        auth = Fido2Auth("https://venya-core-1", ca_path=tmp_path / "ca.crt")
        assert auth.server_url == "https://venya-core-1"

    def test_venya_tls_verify_knob_supplies_no_anchor(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """``VENYA_TLS_VERIFY=false`` distrusts a certificate over https; it is never
        an anchor override and never re-opens the host-store path (the #530 ruling)."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        auth = Fido2Auth("https://venya-core-1", ca_path=tmp_path / "ca.crt")
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            with pytest.raises(Fido2ClientError, match="no Venya TLS trust anchor"):
                auth._get("/x")
            mock_client_cls.assert_not_called()


class TestAnchorConfiguredAccepts:
    """AC3 (positive half) — an anchor configured: the ceremony proceeds, anchored."""

    def test_setup_installed_ca_reaches_the_dial_as_a_context(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = _make_ca(tmp_path, "venya-ceremony-root-533")
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            auth._get("/api/v1/auth/login/start")
        mock_client_cls.assert_called_once()
        verify = mock_client_cls.call_args.kwargs["verify"]
        # Never a bare True (that is httpx asking the host store).
        assert isinstance(verify, ssl.SSLContext)
        assert verify.verify_mode == ssl.CERT_REQUIRED
        assert verify.check_hostname is True

    def test_anchored_context_carries_only_the_venya_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """The anchor is the ONLY trust material in the context (#530 shape)."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = _make_ca(tmp_path, "venya-root-unique-533")
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        ctx = auth._dial_verify()
        assert _anchor_cns(ctx) == {"venya-root-unique-533"}

    def test_ssl_cert_file_opt_in_still_reaches_the_dial(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """AC2: a public-CA-served core stays reachable — by the operator NAMING a bundle.

        The env value is not a hint that the host store may be used; it becomes
        the anchor handed to the transport.
        """
        _no_host_store(monkeypatch)
        bundle = _make_ca(tmp_path, "public-bundle-533")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        # No config-dir CA at all: the opt-in alone must carry the dial.
        auth = Fido2Auth("https://venya-core-1", ca_path=tmp_path / "absent-ca.crt")
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            auth._post("/api/v1/auth/login/complete", {})
        mock_client_cls.assert_called_once()
        verify = mock_client_cls.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert _anchor_cns(verify) == {"public-bundle-533"}

    def test_env_opt_in_wins_over_the_config_ca(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Precedence half of AC2: SSL_CERT_FILE first, then the setup CA."""
        _no_host_store(monkeypatch)
        env_bundle = _make_ca(tmp_path, "env-bundle")
        config_ca = _make_ca(tmp_path, "config-ca")
        monkeypatch.setenv("SSL_CERT_FILE", str(env_bundle))
        auth = Fido2Auth("https://venya-core-1", ca_path=config_ca)
        assert auth._anchor == str(env_bundle)
        assert _anchor_cns(auth._dial_verify()) == {"env-bundle"}

    def test_corrupt_anchor_still_lands_the_439_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Present-but-not-a-certificate reads differently from absent, and stays a
        Fido2ClientError so every ceremony caller's handler still catches it."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        bad = tmp_path / "bad-ca.crt"
        bad.write_text("not a certificate\n")
        auth = Fido2Auth("https://venya-core-1", ca_path=bad)
        with pytest.raises(Fido2ClientError, match="could not be loaded as a certificate"):
            auth._dial_verify()


class TestSharedWordingWithTheBearerDial:
    """The ceremony reuses the landed refusal wording — it does not invent a second one."""

    def test_ceremony_refusal_is_the_bearer_refusal_with_its_own_transport_noun(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = tmp_path / "ca.crt"
        auth = Fido2Auth("https://venya-core-1", ca_path=ca)
        with patch("venya_cli.fido2_client.httpx2.Client"):
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._get("/x")
        expected = _anchor_refusal_text(auth._anchor_searched, transport="WebAuthn ceremony call")
        assert str(excinfo.value) == expected
        assert "WebAuthn ceremony call" in str(excinfo.value)

    def test_fido2_module_reuses_the_shared_refusal_builder(self):
        """AC1: the shape is inherited from ``api_client`` (static pin)."""
        import inspect

        from venya_cli import fido2_client as mod

        src = Path(inspect.getfile(mod)).read_text()
        assert "_anchor_refusal_text" in src
        assert "_build_ssl_context" in src


class TestHostStoreSymbolGone:
    """Static pins: the fallback is removed from this transport, not merely bypassed in tests."""

    def test_fido2_module_has_no_load_default_certs_call_site(self):
        import re

        from venya_cli import fido2_client as mod

        src = Path(mod.__file__).read_text()
        assert not re.search(r"\.load_default_certs\(", src), "a load_default_certs() call site survived (#533)"

    def test_no_dial_passes_a_bare_verify_bool(self):
        """Both ``httpx2.Client(...)`` dials hand an anchor, never ``verify=True``."""
        from venya_cli import fido2_client as mod

        src = Path(mod.__file__).read_text()
        assert "verify=self._dial_verify()" in src
        assert "verify=True" not in src
        assert "verify=False" not in src
