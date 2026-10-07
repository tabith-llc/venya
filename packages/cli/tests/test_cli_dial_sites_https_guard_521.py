# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Scheme-guard tests for the remaining CLI dial sites (ticket cli-dial-sites-missing-https-guard #521).

The guard itself already landed (#497/#506/#508) as the shared
``_require_https_server_url``; this suite puts that ONE helper on the dial sites
that were still accepting any scheme, and never invents a second check:

  * site 2 — the post-register revocation-list read (``_verify_register_auth``),
    which sends an ``Authorization: Bearer`` header.
  * site 3 — ``Fido2Auth`` (the ceremony transport: WebAuthn challenge +
    assertion), guarded once at its ``__init__`` so every construction site is
    covered rather than re-copied at each of the five call sites.

Truth table per the standing rule: every refusal cell is paired with the accept
half (https, and the bare-hostname form that normalizes to https), plus the
sanctioned ``VENYA_TLS_VERIFY=false``-over-https case, which stays a
distrust-the-certificate escape and never a no-TLS escape.

The #521 chokepoint cell (``APIClient`` base_url) is NOT here: AC2 requires the
design call to be proposed and ruled before that site is coded. See the leg
report.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli import commands as commands_mod
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.commands import _https_refusal, _require_https_server_url
from venya_cli.fido2_client import Fido2Auth, Fido2ClientError

TICKET = "cli-dial-sites-missing-https-guard"


def _ca(tmp_path: Path) -> Path:
    """A real self-signed CA PEM.

    #530 made the bearer path LOAD the resolved anchor before any dial, so a
    PEM-shaped placeholder no longer survives the context build. These cells
    still observe the scheme, never a handshake.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t521-ca")])
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


class TestSharedGuardUnchanged:
    """The refactor that let a raising site reuse the print-and-return-False helper's
    wording must not change what the landed sites print (#506/#508 regression)."""

    def test_refusal_string_is_the_landed_wording(self):
        text = _https_refusal("http://x", site="the test site", ticket="t-1", detail="d")
        assert text.startswith("Error: server URL must be https:// — got 'http://x'.")
        assert "the test site" in text
        assert "d" in text
        assert "(ticket t-1)" in text

    def test_helper_prints_that_same_string_and_still_returns_false(self, capsys):
        assert _require_https_server_url("http://x", site="s", ticket="t") is False
        assert capsys.readouterr().err.strip() == _https_refusal("http://x", site="s", ticket="t").strip()

    def test_helper_accepts_https(self, capsys):
        assert _require_https_server_url("https://x", site="s", ticket="t") is True
        assert capsys.readouterr().err == ""


class TestSite2RevocationRead:
    """Site 2 — ``_verify_register_auth`` GET /executors/certs/revocation-list."""

    def _client(self, tmp_path: Path) -> APIClient:
        _ca(tmp_path)
        client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
        client.config.access_token = "bearer-token-under-test"
        return client

    def test_http_url_refuses_and_sends_nothing(self, tmp_path: Path):
        """RED at base: the read carried the bearer token over http://."""
        client = self._client(tmp_path)
        try:
            with patch("venya_cli.commands.httpx2.Client") as mock_client_cls:
                with pytest.raises(APIClientError, match="must be https://"):
                    commands_mod._verify_register_auth(client, "http://venya-core-1", None)
                mock_client_cls.assert_not_called()
        finally:
            client.close()

    def test_refusal_text_carries_the_ticket_and_the_token_reason(self, tmp_path: Path):
        client = self._client(tmp_path)
        try:
            with patch("venya_cli.commands.httpx2.Client"):
                with pytest.raises(APIClientError) as excinfo:
                    commands_mod._verify_register_auth(client, "http://venya-core-1", None)
            assert TICKET in str(excinfo.value)
            assert "bearer token" in str(excinfo.value)
        finally:
            client.close()

    def test_https_url_still_reads(self, tmp_path: Path):
        """Accept half: the read still happens, still bearer-bearing."""
        client = self._client(tmp_path)
        try:
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            with patch("venya_cli.commands.httpx2.Client") as mock_client_cls:
                mock_client_cls.return_value.__enter__.return_value.get.return_value = resp
                commands_mod._verify_register_auth(client, "https://venya-core-1", None)
            url = mock_client_cls.return_value.__enter__.return_value.get.call_args.args[0]
            assert url == "https://venya-core-1/api/v1/executors/certs/revocation-list"
            hdrs = mock_client_cls.return_value.__enter__.return_value.get.call_args.kwargs["headers"]
            assert hdrs["Authorization"] == "Bearer bearer-token-under-test"
        finally:
            client.close()

    def test_venya_tls_verify_false_does_not_re_open_plaintext(self, tmp_path: Path, monkeypatch):
        """AC4 paired negative: the sanctioned knob is a distrust-cert escape, not
        a no-TLS escape — over http:// it still refuses at this site."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        client = self._client(tmp_path)
        try:
            with patch("venya_cli.commands.httpx2.Client") as mock_client_cls:
                with pytest.raises(APIClientError, match="must be https://"):
                    commands_mod._verify_register_auth(client, "http://venya-core-1", None)
                mock_client_cls.assert_not_called()
        finally:
            client.close()

    def test_caller_passes_the_already_guarded_url(self):
        """Wiring half: the one caller resolves+guards BEFORE the CSR, and hands
        that same resolved value down — so the register flow cannot reach this
        read with a scheme it did not already refuse (#508 landed guard)."""
        import inspect

        body = inspect.getsource(commands_mod.executor_register)
        assert "_require_https_server_url(" in body
        assert "_verify_register_auth(client, server_url, ca_bundle)" in body


class TestSite3Fido2CeremonyTransport:
    """Site 3 — Fido2Auth, the ceremony transport, guarded at its ONE seam."""

    def test_http_url_refuses_at_construction(self):
        with pytest.raises(Fido2ClientError, match="must be https://"):
            Fido2Auth("http://venya-core-1")

    def test_refusal_names_the_ticket_and_the_ceremony(self):
        with pytest.raises(Fido2ClientError) as excinfo:
            Fido2Auth("http://venya-core-1")
        assert TICKET in str(excinfo.value)
        assert "FIDO2 ceremony transport" in str(excinfo.value)

    def test_no_transport_and_no_request_on_refusal(self):
        """'nothing dialed' proof: httpx2.Client is never constructed."""
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
            with pytest.raises(Fido2ClientError):
                Fido2Auth("http://venya-core-1")
            mock_client_cls.assert_not_called()

    def test_https_url_accepted(self):
        auth = Fido2Auth("https://venya-core-1")
        assert auth.server_url == "https://venya-core-1"

    def test_bare_hostname_normalizes_to_https(self):
        """AC3 paired positive: the form the operator is told to type still works,
        and is never rewritten to plaintext."""
        auth = Fido2Auth("venya-core-1")
        assert auth.server_url == "https://venya-core-1"

    def test_explicit_scheme_is_never_rewritten_up_or_down(self):
        """The guard reads an explicit scheme as written: no silent https upgrade
        of a config value, and no downgrade ever."""
        with pytest.raises(Fido2ClientError):
            Fido2Auth("http://venya-core-1:8000")
        assert Fido2Auth("https://venya-core-1:8443").server_url == "https://venya-core-1:8443"

    def test_trailing_slash_still_refused_when_plaintext(self):
        with pytest.raises(Fido2ClientError, match="must be https://"):
            Fido2Auth("http://venya-core-1/")

    def test_venya_tls_verify_false_does_not_re_open_plaintext(self, monkeypatch):
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        with pytest.raises(Fido2ClientError, match="must be https://"):
            Fido2Auth("http://venya-core-1")

    def test_https_with_knob_still_constructs(self, monkeypatch):
        """AC4: the knob over https keeps its ruled meaning at this site too."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        assert Fido2Auth("https://venya-core-1").server_url == "https://venya-core-1"

    @pytest.mark.parametrize(
        "fn_name",
        ["cmd_init", "cmd_enroll", "cmd_credential_add", "_elevate"],
    )
    def test_every_ceremony_call_site_goes_through_the_guarded_seam(self, fn_name):
        """Structural pin for 'one seam, five callers': each ceremony command
        constructs Fido2Auth, so the __init__ guard covers all of them without a
        hand-copied check at each site (AC1: no new check)."""
        import inspect

        body = inspect.getsource(getattr(commands_mod, fn_name))
        assert "Fido2Auth(" in body

    def test_plaintext_config_reaches_a_ceremony_as_a_clean_refusal(self, tmp_path, monkeypatch):
        """End-to-end shape at the command boundary: an operator whose config.json
        holds a plaintext URL gets a non-zero refusal and no ceremony HTTP at all
        (run_command's dispatcher catches Fido2ClientError as Execution failed)."""
        cfg = tmp_path / "config.json"
        cfg.write_text('{"server_url": "http://venya-core-1", "access_token": "tok"}')
        client = APIClient(config_file=cfg)
        try:
            with patch("venya_cli.fido2_client.httpx2.Client") as mock_client_cls:
                with pytest.raises(Fido2ClientError, match="must be https://"):
                    Fido2Auth(client.config.server_url, ca_path=client.config.ca_path)
                mock_client_cls.assert_not_called()
        finally:
            client.close()


class TestNoSecondGuardInvented:
    """AC1: these sites reuse the ONE landed helper's check/wording."""

    def test_fido2_module_reuses_the_shared_refusal_builder(self):
        src = Path(__import__("venya_cli.fido2_client", fromlist=["x"]).__file__).read_text()
        assert "_https_refusal" in src
        # No hand-copied variant of the sentence itself.
        assert "Plaintext http is " not in src

    def test_the_wording_exists_once_in_the_whole_cli_package(self):
        """The refusal sentence lives in exactly one place across the package, so
        no site is maintaining a hand-copied variant of it.

        Matched on the stable fragments because the landed builder composes the
        sentence across two f-string lines.
        """
        pkg = Path(commands_mod.__file__).parent
        needles = ("Plaintext http is ", "not supported for {site}")
        hits = sorted(f.name for f in pkg.glob("*.py") if all(n in f.read_text() for n in needles))
        assert hits == ["commands.py"]
        src = (pkg / "commands.py").read_text()
        # The refusal SENTENCE is built once; "Plaintext http is REJECTED" also
        # appears in prose (the guard's own docstring), so the pin keys on the
        # composable error prefix instead.
        assert src.count('f"Error: server URL must be https://') == 1
