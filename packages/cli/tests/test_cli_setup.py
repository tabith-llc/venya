# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for `venya setup` (feature/cli-setup-command) and the CA
verify precedence it installs.

setup = save server URL + fetch/install the core CA cert. Every gate gets a
paired negative: garbage body, 404 (not-a-venya-core), unreachable host, pin
mismatch. The precedence cells pin the load-bearing negative both ways:
SSL_CERT_FILE env set + ca.crt on disk -> env still wins (keeps the
full-lifecycle-test.md and cert-rotation-runbook flows working); no env +
ca.crt present -> the setup-installed CA is used.
"""

import datetime
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from venya_cli import commands as commands_mod
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.fido2_client import Fido2Auth


def _self_signed_pem(cn: str = "venya-core-1") -> bytes:
    """A valid self-signed CA cert PEM, generated in-test."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def ca_pem() -> bytes:
    return _self_signed_pem()


def _fingerprint(pem: bytes) -> str:
    return x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()


def _resp(status_code: int, content: bytes = b"") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.content = content
    return r


def _args(corename: str, pin: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(corename=corename, ca_sha256=pin)


class TestSetupCommand:
    def test_success_installs_ca_and_saves_url(self, tmp_path: Path, capsys: pytest.CaptureFixture, ca_pem: bytes):
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
        assert rc == 0
        # bare hostname normalized to https; scoped unverified GET, 5s timeout
        mock_get.assert_called_once_with("https://venya-core-1/.well-known/venya-ca.crt", verify=False, timeout=5.0)
        assert client.config.server_url == "https://venya-core-1"
        ca = client.config.ca_path
        assert ca.exists()
        assert stat.S_IMODE(os.stat(ca).st_mode) == 0o600
        assert ca.read_bytes() == ca_pem
        out = capsys.readouterr().out
        assert "https://venya-core-1" in out
        assert _fingerprint(ca_pem) in out
        assert "venya init" in out

    def test_prefixed_url_unchanged(self, tmp_path: Path, ca_pem: bytes):
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("https://core.example.com"))
        assert rc == 0
        assert client.config.server_url == "https://core.example.com"
        mock_get.assert_called_once()
        assert mock_get.call_args.args[0] == "https://core.example.com/.well-known/venya-ca.crt"

    def test_garbage_response_fails_loudly(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        """NEGATIVE: body that is not PEM -> rc=1, no ca.crt, URL still saved."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, b"this is not a certificate")):
            rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
        assert rc == 1
        assert not client.config.ca_path.exists()
        assert client.config.server_url == "https://venya-core-1"
        assert (tmp_path / "config.json").exists()
        assert "setup incomplete" in capsys.readouterr().err

    def test_unreachable_host(self, tmp_path: Path):
        """NEGATIVE: ConnectError -> rc=1, nothing written."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", side_effect=httpx2.ConnectError("no route to host")):
            rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
        assert rc == 1
        assert not client.config.ca_path.exists()

    def test_404_is_not_a_venya_core(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        """NEGATIVE: 404 = not a venya core -> rc=1, loud."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(404)):
            rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
        assert rc == 1
        assert not client.config.ca_path.exists()
        err = capsys.readouterr().err
        assert "setup incomplete" in err
        assert "venya core" in err

    def test_pin_mismatch_no_write(self, tmp_path: Path, capsys: pytest.CaptureFixture, ca_pem: bytes):
        """NEGATIVE: --ca-sha256 mismatch -> rc=1, nothing written."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)):
            rc = commands_mod.cmd_setup(client, _args("venya-core-1", pin="0" * 64))
        assert rc == 1
        assert not client.config.ca_path.exists()
        assert "mismatch" in capsys.readouterr().err

    def test_pin_normalized_match(self, tmp_path: Path, ca_pem: bytes):
        """Colons/spaces/case in the pin are normalized before comparison."""
        client = APIClient(config_file=tmp_path / "config.json")
        fp = _fingerprint(ca_pem)
        pin = ":".join(fp[i : i + 2].upper() for i in range(0, 64, 2)) + "  "
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)):
            rc = commands_mod.cmd_setup(client, _args("venya-core-1", pin=pin))
        assert rc == 0
        assert client.config.ca_path.exists()


class TestSetupHttpsRequired:
    """#497 pin (ticket cli-setup-ca-fetch-plaintext-http): `venya setup` is the one
    remaining place a plaintext transport could install a trust anchor. The fetched
    bytes become the anchor every later call verifies against, so an on-path
    adversary that answers the GET picks the CA. Plaintext is REFUSED, not
    downgraded — same ruling class as sec-sweep-low-informational #17 at the
    heartbeat site (user ruling 2026-09-21). VENYA_TLS_VERIFY=false is not in play
    here: it means "distrust this certificate over https", never "no TLS"."""

    def test_http_scheme_refused_before_any_fetch_or_write(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
        ca_pem: bytes,
    ):
        """RED at HEAD: an explicit http:// corename -> rc=1, no GET, no server_url
        write, no ca.crt."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("http://venya-core-1"))
        assert rc == 1
        mock_get.assert_not_called()
        assert not client.config.ca_path.exists()
        assert not (tmp_path / "config.json").exists()
        assert client.config.server_url == "http://localhost:8000"  # untouched default
        err = capsys.readouterr().err
        assert "https://" in err
        assert "cli-setup-ca-fetch-plaintext-http" in err

    def test_http_scheme_refused_even_with_correct_pin(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
        ca_pem: bytes,
    ):
        """NEGATIVE pairing: a --ca-sha256 pin that WOULD match does not unlock
        plaintext — the scheme check runs first, before any fetch."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("http://venya-core-1", pin=_fingerprint(ca_pem)))
        assert rc == 1
        mock_get.assert_not_called()
        assert not client.config.ca_path.exists()
        assert not (tmp_path / "config.json").exists()
        assert "https://" in capsys.readouterr().err

    def test_bare_hostname_still_normalizes_to_https(self, tmp_path: Path, ca_pem: bytes):
        """Paired positive: the refusal is scheme-specific, not a lockdown — the
        documented bare-hostname form keeps working exactly as before."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
        assert rc == 0
        assert mock_get.call_args.args[0] == "https://venya-core-1/.well-known/venya-ca.crt"
        assert client.config.server_url == "https://venya-core-1"
        assert client.config.ca_path.read_bytes() == ca_pem

    def test_https_scheme_still_fetches(self, tmp_path: Path, ca_pem: bytes):
        """Paired positive: explicit https:// proceeds to the fetch unchanged."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)) as mock_get:
            rc = commands_mod.cmd_setup(client, _args("https://core.example.com"))
        assert rc == 0
        mock_get.assert_called_once()
        assert client.config.ca_path.read_bytes() == ca_pem

    def test_pin_mismatch_writes_nothing(self, tmp_path: Path, capsys: pytest.CaptureFixture, ca_pem: bytes):
        """Criterion 3 unchanged: an https fetch whose pin mismatches writes nothing
        (the optional-pin path the refusal must not disturb)."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)):
            rc = commands_mod.cmd_setup(client, _args("https://core.example.com", pin="1" * 64))
        assert rc == 1
        assert not client.config.ca_path.exists()
        assert client.config.server_url == "https://core.example.com"
        assert "mismatch" in capsys.readouterr().err


class TestCaVerifyPrecedence:
    """APIClient anchor precedence: SSL_CERT_FILE env > setup ca.crt > REFUSAL.

    Since ticket cli-admin-mtls-verify-cert-conflict (option (a)) the chosen
    anchor is loaded into ONE ssl.SSLContext passed as verify= (string verify
    and the cert= kwarg are gone — httpx2 >= 2.12 rejects the combination).
    #530 replaced the old third branch ("then system trust") with a loud
    refusal, and moved the context/transport build to the first DIAL — so
    these cells touch client._http to reach the seam. Context behavior itself
    is tested with real certs in test_api_client_mtls.py::TestBuildSslContext.

    #521 (the dial seam) also refuses a non-https base_url at this seam, so the
    two cells that reach the build name an https server_url — they are anchor
    PRECEDENCE cells, not scheme cells. The no-anchor cell keeps the plaintext
    default on purpose: the anchor refusal is checked FIRST and wins, which is
    the ordering the #530 wording depends on.
    """

    def test_ca_used_when_present_no_env(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")  # content irrelevant — the spy observes the PATH
        sentinel = object()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("venya_cli.api_client._build_ssl_context", return_value=sentinel) as spy,
            patch("venya_cli.api_client.httpx2.Client") as mock_client,
        ):
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            _ = client._http  # #530 dial seam — the transport is built here, not at construction
        assert spy.call_args.kwargs["cafile"] == str(ca)
        assert mock_client.call_args.kwargs.get("verify") is sentinel
        assert "cert" not in mock_client.call_args.kwargs

    def test_env_wins_over_ca(self, tmp_path: Path):
        """LOAD-BEARING NEGATIVE: env set + ca.crt present -> env still wins."""
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        sentinel = object()
        with (
            patch.dict(os.environ, {"SSL_CERT_FILE": "/tmp/venya-ca.crt"}, clear=True),
            patch("venya_cli.api_client._build_ssl_context", return_value=sentinel) as spy,
            patch("venya_cli.api_client.httpx2.Client"),
        ):
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            _ = client._http  # #530 dial seam — the transport is built here, not at construction
        assert spy.call_args.kwargs["cafile"] == "/tmp/venya-ca.crt"

    def test_no_anchor_refuses_never_system_trust(self, tmp_path: Path):
        """#530: no SSL_CERT_FILE and no setup CA -> the dial REFUSES.

        Paired negative for the branch that used to be 'then system trust'. The
        builder is rigged to record any call: the refusal must land before it,
        so a token-bearing request can never be satisfied by a publicly-issued
        certificate for the hostname.
        """
        sentinel = object()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("venya_cli.api_client._build_ssl_context", return_value=sentinel) as spy,
            patch("venya_cli.api_client.httpx2.Client") as mock_client,
        ):
            client = APIClient(config_file=tmp_path / "config.json")
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                _ = client._http
            # And the refusal is at the dial, not the request: no transport ever existed.
            spy.assert_not_called()
            mock_client.assert_not_called()
        # Constructing the client with no anchor is still allowed — `venya setup`
        # is the repair, and run_command() builds the client before it dispatches.


class TestFido2CaPrecedence:
    """Fido2Auth (the init/login ceremony) uses the same precedence."""

    def test_ca_used_when_no_env(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with patch.dict(os.environ, {}, clear=True):
            auth = Fido2Auth("https://core", ca_path=ca)
        assert auth._anchor == str(ca)

    def test_env_wins_over_ca(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with patch.dict(os.environ, {"SSL_CERT_FILE": "/tmp/venya-ca.crt"}, clear=True):
            auth = Fido2Auth("https://core", ca_path=ca)
        # #533: the named bundle IS the anchor — the transport never falls back to
        # `verify=True` (which is httpx asking the host store).
        assert auth._anchor == "/tmp/venya-ca.crt"


class TestSetupCaDirPermission376:
    """#376 D-3: the setup CA-dir site (commands.py, `ca_path.parent.mkdir`)
    was the one CLI secret-dir site missing both mode=0o700 and the
    ensure_secret_dir pinned idiom every sibling site uses."""

    def test_setup_tightens_preexisting_loose_ca_dir(self, tmp_path: Path, ca_pem: bytes):
        """RED half: a pre-existing loose config dir (upgrade-install shape)
        must land 0700 — bare exist_ok mkdir never re-pins an existing dir;
        content unchanged (CA still 0600, byte-exact)."""
        cfg_dir = tmp_path / "loose"
        cfg_dir.mkdir()
        cfg_dir.chmod(0o755)
        client = APIClient(config_file=cfg_dir / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)):
            old = os.umask(0o022)
            try:
                rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
            finally:
                os.umask(old)
        assert rc == 0
        assert stat.S_IMODE(cfg_dir.stat().st_mode) == 0o700
        ca = client.config.ca_path
        assert stat.S_IMODE(os.stat(ca).st_mode) == 0o600
        assert ca.read_bytes() == ca_pem
        assert not list(cfg_dir.glob(".venya-ca-*"))

    def test_setup_fresh_dir_modes_under_umask077(self, tmp_path: Path, ca_pem: bytes):
        """Paired control: fresh dir under a restrictive umask — dir 0700,
        ca.crt 0600 byte-exact; the pin must not LOOSEN anything."""
        cfg_dir = tmp_path / "fresh"
        client = APIClient(config_file=cfg_dir / "config.json")
        with patch("venya_cli.commands.httpx2.get", return_value=_resp(200, ca_pem)):
            old = os.umask(0o077)
            try:
                rc = commands_mod.cmd_setup(client, _args("venya-core-1"))
            finally:
                os.umask(old)
        assert rc == 0
        assert stat.S_IMODE(cfg_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(os.stat(client.config.ca_path).st_mode) == 0o600
        assert client.config.ca_path.read_bytes() == ca_pem
