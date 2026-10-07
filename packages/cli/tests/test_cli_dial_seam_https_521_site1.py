# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Site 1 of ticket cli-dial-sites-missing-https-guard #521 — the dial seam.

Owner-ruled shape (issue note 3971354985, 2026-10-07): **option C**. The scheme
guard lives INSIDE the lazy transport builder ``APIClient._http`` (cli
``api_client.py``), next to the landed #530 anchor refusal, so it fires at the
moment a request is about to leave — and ``venya setup`` still constructs.

Why not construction time (the alternative that was rejected): ``run_command()``
builds an ``APIClient`` for EVERY command before it dispatches, so an eager raise
in ``__init__`` bricks ``venya setup`` — the repair the refusal itself names — on
exactly the host that needs it. ``TestSetupStillConstructs`` below is the
anti-regression pair: every cell in it FAILS if the guard moves to construction.

One seam covers BOTH dial paths that use the shared transport — ``_request`` (GET
/ POST / PUT / PATCH / DELETE) and ``_post_raw`` (auth refresh) — so there is no
per-command copy of the check. The refusal text is the ONE landed wording class
(``commands._https_refusal``, shared with sites 2/3); this module imports it
lazily because commands.py imports api_client at its top.

Out of scope by ruling (criterion 5, report-only): ``register_executor`` builds
its own ``httpx2.Client`` and is NOT covered by this seam; its sibling ticket is
``cli-register-executor-dial-falls-back-to-host-store``.
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
from venya_cli.api_client import APIClient, APIClientAuthenticationError, APIClientError

TICKET = "cli-dial-sites-missing-https-guard"
PLAINTEXT = "http://core.invalid"
SECURE = "https://core.invalid"


def _ca(tmp_path: Path) -> Path:
    """A real self-signed CA PEM, planted as SSL_CERT_FILE.

    The scheme guard runs AFTER the #530 anchor check, so a cell that wants to
    observe the scheme needs an anchor to exist — otherwise what it sees is the
    anchor refusal, which is a different rule (and a different ticket).
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t521-site1-ca")])
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
    ca = tmp_path / "anchor-ca.crt"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca


def _client(tmp_path: Path, monkeypatch, server_url: str) -> APIClient:
    """A client with a REAL anchor and the URL under test.

    Patch.dict(clear) keeps an ambient SSL_CERT_FILE off the hermetic path.
    """
    monkeypatch.setenv("SSL_CERT_FILE", str(_ca(tmp_path)))
    monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
    return APIClient(server_url=server_url, config_file=tmp_path / "config.json")


def _no_build_transport():
    """A transport factory that explodes if ANY client is constructed.

    The honest shape for 'nothing left the machine': the guard must raise before
    httpx2.Client exists, so a construction attempt is itself the failure.
    """
    return MagicMock(side_effect=AssertionError("httpx2.Client was constructed — the scheme guard must land first"))


class TestSchemeRefusedAtTheSeam:
    """RED at base: a plaintext config meant every generic API call went in the clear."""

    def test_http_base_url_refuses_at_first_dial(self, tmp_path, monkeypatch):
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            factory = _no_build_transport()
            with patch("venya_cli.api_client.httpx2.Client", factory):
                with pytest.raises(APIClientError, match="must be https://"):
                    _ = client._http
            assert factory.call_count == 0  # no HTTP client ever existed
        finally:
            client.close()

    def test_request_path_refuses_and_is_not_reworded(self, tmp_path, monkeypatch):
        """The `_request` half: the refusal is resolved OUTSIDE the try (#530 shape),
        so it never gets swallowed into 'Connection failed:' by the httpx handlers."""
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://") as excinfo:
                    client.get("/api/v1/secrets")
            assert "Connection failed" not in str(excinfo.value)
        finally:
            client.close()

    def test_post_raw_path_refuses_same_seam(self, tmp_path, monkeypatch):
        """The `_post_raw` half (auth endpoints, no auto-refresh): same refusal."""
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://"):
                    client._post_raw("/api/v1/auth/logout", {})
        finally:
            client.close()

    def test_refresh_path_carries_the_refusal_text(self, tmp_path, monkeypatch):
        """`refresh_token` wraps APIClientError into an auth error by design; the
        scheme text still rides along, so the operator reads the real reason."""
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        client.config.access_token = "tok"
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientAuthenticationError, match="must be https://"):
                    client.refresh_token()
        finally:
            client.close()

    def test_refusal_names_the_ticket_and_the_reason(self, tmp_path, monkeypatch):
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError) as excinfo:
                    _ = client._http
            assert TICKET in str(excinfo.value)
            assert "bearer token" in str(excinfo.value)
            assert PLAINTEXT in str(excinfo.value)
        finally:
            client.close()

    def test_anchorless_plaintext_host_gets_the_anchor_refusal_first(self, tmp_path, monkeypatch):
        """Ordering pin: with NO anchor and a plaintext URL, the #530 refusal wins.

        That refusal is the one that names `venya setup`, and the ordering keeps
        the repair hint on screen for the host that has not been set up at all.
        """
        monkeypatch.setattr(Path, "exists", lambda self: False)  # no config-dir CA either
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        client = APIClient(server_url=PLAINTEXT, config_file=tmp_path / "config.json")
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                    _ = client._http
        finally:
            client.close()


class TestPlaintextIsNeverReopened:
    """The sanctioned dev knob is a distrust-the-certificate escape, not a no-TLS escape."""

    def test_tls_verify_false_does_not_re_open_plaintext(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://"):
                    _ = client._http
        finally:
            client.close()

    def test_no_scheme_url_is_refused_not_assumed(self, tmp_path, monkeypatch):
        """A URL with no scheme at all never reaches httpx as an implicit guess."""
        client = _client(tmp_path, monkeypatch, "core.invalid")
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://"):
                    _ = client._http
        finally:
            client.close()

    def test_cli_default_localhost_is_refused_at_the_dial(self, tmp_path, monkeypatch):
        """The no-config default (`http://localhost:8000`) is plaintext, so it is
        refused at the dial too — this is the fixture class that had to name an
        https URL in test_api_client_mtls.py / test_cli_setup.py."""
        cfg = tmp_path / "config.json"
        cfg.write_text("{}")
        monkeypatch.setenv("SSL_CERT_FILE", str(_ca(tmp_path)))
        client = APIClient(config_file=cfg)
        assert client.config.server_url == "http://localhost:8000"
        try:
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://"):
                    _ = client._http
        finally:
            client.close()


class TestHttpsStillDials:
    """GREEN halves — the guard must not become a blanket refusal."""

    def test_https_base_url_builds_the_transport(self, tmp_path, monkeypatch):
        client = _client(tmp_path, monkeypatch, SECURE)
        mock_client = MagicMock()
        try:
            with patch("venya_cli.api_client.httpx2.Client", return_value=mock_client) as factory:
                assert client._http is mock_client
            assert factory.call_count == 1
            assert factory.call_args.kwargs["base_url"] == SECURE
        finally:
            client.close()

    def test_https_request_sends_on_the_built_transport(self, tmp_path, monkeypatch):
        client = _client(tmp_path, monkeypatch, SECURE)
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b'{"ok": true}'
        resp.json.return_value = {"ok": True}
        stub = MagicMock()
        stub.request.return_value = resp
        try:
            with patch("venya_cli.api_client.httpx2.Client", return_value=stub) as factory:
                assert client.get("/api/v1/secrets") == {"ok": True}
            assert factory.call_count == 1
        finally:
            client.close()


class TestSetupStillConstructs:
    """Anti-regression pair for option C — every cell here FAILS if the guard moves
    to construction time (``__init__``), which is exactly what bricks `venya setup`."""

    def test_plaintext_config_does_not_raise_at_construction(self, tmp_path, monkeypatch):
        """run_command() constructs before dispatching; a raise here would make the
        refusal unreachable for the command that fixes it."""
        monkeypatch.setenv("SSL_CERT_FILE", str(_ca(tmp_path)))
        client = APIClient(server_url=PLAINTEXT, config_file=tmp_path / "config.json")
        # Nothing raised: the client object exists, no transport built yet.
        assert client._anchor
        assert client._APIClient__http is None
        client.close()

    def test_setup_still_installs_the_ca_on_a_bare_hostname(self, tmp_path, monkeypatch):
        """`venya setup <core>` end-to-end: bare hostname normalizes to https, the CA
        is fetched over that https URL and written, and the flow never trips the seam."""
        from venya_cli import commands as commands_mod

        cfg = tmp_path / "config.json"
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        client = APIClient(config_file=cfg)  # plaintext default, no anchor — the pre-setup host
        pem = _self_signed_pem_bytes()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = pem
        try:
            with patch("venya_cli.commands.httpx2.get", return_value=resp) as mock_get:
                rc = commands_mod.cmd_setup(client, _setup_args("venya-core-1"))
            assert rc == 0
            assert mock_get.call_args.args[0] == "https://venya-core-1/.well-known/venya-ca.crt"
            assert (cfg.parent / "ca.crt").exists()
        finally:
            client.close()

    def test_setup_refuses_an_explicit_plaintext_core_before_writing(self, tmp_path, monkeypatch, capsys):
        """Paired negative at the command boundary: `venya setup http://core` is
        refused by the setup guard, nothing is fetched, nothing is written."""
        from venya_cli import commands as commands_mod

        cfg = tmp_path / "config.json"
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        client = APIClient(config_file=cfg)
        try:
            with patch("venya_cli.commands.httpx2.get", side_effect=AssertionError("CA fetched")):
                rc = commands_mod.cmd_setup(client, _setup_args("http://core.invalid"))
            assert rc == 1
            assert "must be https://" in capsys.readouterr().err
            assert not (cfg.parent / "ca.crt").exists()
        finally:
            client.close()


class TestStubSeamStillUsable:
    """The setter branch: ~40 sibling cells inject a stub transport. The guard lives
    in the BUILD branch, so an injected stub for a plaintext config must not raise."""

    def test_injected_stub_for_plaintext_config_does_not_raise(self, tmp_path, monkeypatch):
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        stub = MagicMock()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b"{}"
        resp.json.return_value = {}
        stub.request.return_value = resp
        try:
            client._http = stub  # the test seam — no build, so no scheme check
            assert client.get("/api/v1/secrets") == {}
        finally:
            client.close()

    def test_forcing_a_rebuild_with_none_does_raise_for_plaintext(self, tmp_path, monkeypatch):
        """The other half of the setter seam: `_http = None` forces the REAL build,
        and the real build is guarded."""
        client = _client(tmp_path, monkeypatch, PLAINTEXT)
        try:
            client._http = MagicMock()
            client._http = None
            with patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("transport built")):
                with pytest.raises(APIClientError, match="must be https://"):
                    _ = client._http
        finally:
            client.close()


class TestNoSecondGuardInvented:
    """AC1: this site reuses the ONE refusal wording class — no fifth copy."""

    def test_api_client_reuses_the_shared_refusal_builder(self):
        import venya_cli.api_client as api_client_mod

        src = Path(api_client_mod.__file__).read_text()
        assert "_https_refusal" in src
        assert "Plaintext http is " not in src  # no hand-copied variant of the sentence

    def test_the_guard_is_at_the_seam_not_at_construction(self):
        """Structural pin for the ruled shape: the check is inside the `_http`
        property body, not in `__init__`."""
        import inspect

        import venya_cli.api_client as api_client_mod

        prop = inspect.getsource(api_client_mod.APIClient._http.fget)
        assert "_https_refusal" in prop
        init = inspect.getsource(api_client_mod.APIClient.__init__)
        assert "_https_refusal" not in init


def _setup_args(corename: str):
    from types import SimpleNamespace

    return SimpleNamespace(corename=corename, ca_sha256=None)


def _self_signed_pem_bytes() -> bytes:
    """A valid CA PEM for the setup fetch cell (content parsed by cmd_setup)."""
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "venya-core-1")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
    )
