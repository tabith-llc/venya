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
from venya_cli.api_client import APIClient
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


class TestCaVerifyPrecedence:
    """APIClient.__init__: SSL_CERT_FILE env > setup ca.crt > system trust."""

    def test_ca_used_when_present_no_env(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("venya_cli.api_client.httpx2.Client") as mock_client,
        ):
            APIClient(config_file=tmp_path / "config.json")
        assert mock_client.call_args.kwargs.get("verify") == str(ca)

    def test_env_wins_over_ca(self, tmp_path: Path):
        """LOAD-BEARING NEGATIVE: env set + ca.crt present -> env still wins."""
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with (
            patch.dict(os.environ, {"SSL_CERT_FILE": "/tmp/venya-ca.crt"}, clear=True),
            patch("venya_cli.api_client.httpx2.Client") as mock_client,
        ):
            APIClient(config_file=tmp_path / "config.json")
        assert "verify" not in mock_client.call_args.kwargs

    def test_system_trust_when_neither(self, tmp_path: Path):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("venya_cli.api_client.httpx2.Client") as mock_client,
        ):
            APIClient(config_file=tmp_path / "config.json")
        assert "verify" not in mock_client.call_args.kwargs


class TestFido2CaPrecedence:
    """Fido2Auth (the init/login ceremony) uses the same precedence."""

    def test_ca_used_when_no_env(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with patch.dict(os.environ, {}, clear=True):
            auth = Fido2Auth("https://core", ca_path=ca)
        assert auth._verify == str(ca)

    def test_env_wins_over_ca(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_bytes(b"pem")
        with patch.dict(os.environ, {"SSL_CERT_FILE": "/tmp/venya-ca.crt"}, clear=True):
            auth = Fido2Auth("https://core", ca_path=ca)
        assert auth._verify is True
