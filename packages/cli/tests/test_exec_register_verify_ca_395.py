# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the exec-register post-verify trust propagation (#395).

The verify client used to be the plain session ``client``, whose TLS trust is
the config-dir CA only — on a config-less host the CSR POST (which honors
``--ca-bundle``) succeeded while the very next verify call could only ever
die with CERTIFICATE_VERIFY_FAILED, and that loud TLS failure shipped with
rc=0 + "registered successfully". Lead ruling (2026-10-03): (i) trust order
config-dir CA if present, else explicit --ca-bundle, else LOUD failure —
never an insecure or skipped-verify path; (ii) verification failure exits
rc!=0 with the cert KEPT and the wording "registered, auth NOT verified".

Each positive half carries its paired negative (truth-table rule): the
config-dir CA path stays the first word, and no trust material means a hard
stop, not a silent system-store fallthrough.
"""

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClientError
from venya_cli.commands import executor_register


def _write_bundle(path: Path) -> Path:
    """A real self-signed PEM — load_verify_locations must accept it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-venya-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _register_args(tmp_path, ca_bundle=None):
    return SimpleNamespace(
        executor_id="test-exec",
        core_url="https://core.example.com",
        output_dir=str(tmp_path / "certs"),
        enrollment_token=None,
        ca_bundle=ca_bundle,
    )


def _mock_register_client(config_ca_exists=False):
    """MagicMock APIClient whose register_executor returns a real cert PEM."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "returned-exec"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    client = MagicMock()
    client.config.server_url = "https://core.example.com"
    client.config.access_token = None
    ca = MagicMock()
    ca.__str__ = lambda self: "/fake/config/ca.crt"
    ca.exists.return_value = config_ca_exists
    client.config.ca_path = ca
    client.register_executor.return_value = {
        "cert_pem": cert_pem,
        "ca_cert_pem": cert_pem,
        "serial_number": "01:23:45",
        "not_after": "2026-09-13T00:00:00+00:00",
    }
    return client


def _ok_response():
    response = MagicMock()
    response.raise_for_status.return_value = None
    return response


class TestTrustResolution:
    """Trust build order, at the resolver itself (ruling (i))."""

    def test_config_dir_ca_wins_over_bundle(self, tmp_path):
        """Paired negative for (a): when the config-dir CA is present it stays
        the trust source — --ca-bundle must not displace it (the incumbent
        client trust path is unchanged)."""
        from venya_cli.commands import _resolve_register_verify_cafile

        bundle = _write_bundle(tmp_path / "ca.crt")
        client = _mock_register_client(config_ca_exists=True)
        assert _resolve_register_verify_cafile(client, str(bundle)) == "/fake/config/ca.crt"

    def test_bundle_used_when_config_ca_absent(self, tmp_path):
        """(a) resolver half: config-less host honors the resolved --ca-bundle."""
        from venya_cli.commands import _resolve_register_verify_cafile

        bundle = _write_bundle(tmp_path / "ca.crt")
        client = _mock_register_client(config_ca_exists=False)
        assert _resolve_register_verify_cafile(client, str(bundle)) == str(bundle)

    def test_no_trust_material_fails_loud(self):
        """(b) resolver half: no config-dir CA and no bundle → loud error, no
        system-store or no-verify fallback (production mandate)."""
        from venya_cli.commands import _resolve_register_verify_cafile

        client = _mock_register_client(config_ca_exists=False)
        with pytest.raises(APIClientError) as excinfo:
            _resolve_register_verify_cafile(client, None)
        message = str(excinfo.value)
        assert "--ca-bundle" in message
        assert "ca.crt" in message

    def test_verify_request_targets_resolved_url_and_bundle(self, tmp_path):
        """(a) full half: the verify GET goes to the RESOLVED core URL (#387
        preserved) over an ssl context carrying the bundle trust."""
        from venya_cli.commands import _verify_register_auth

        bundle = _write_bundle(tmp_path / "ca.crt")
        client = _mock_register_client(config_ca_exists=False)
        with patch("venya_cli.commands.httpx2.Client") as MockHttp:
            MockHttp.return_value.__enter__.return_value = MockHttp.return_value
            MockHttp.return_value.get.return_value = _ok_response()
            _verify_register_auth(client, "https://core.example.com", str(bundle))
        verify_arg = MockHttp.call_args.kwargs["verify"]
        assert type(verify_arg).__name__ == "SSLContext"
        assert MockHttp.return_value.get.call_args.args[0] == (
            "https://core.example.com/api/v1/executors/certs/revocation-list"
        )


class TestRegisterPostVerifyFlow:
    """rc/wording posture pinned both halves (ruling (ii), AC-2)."""

    def test_config_less_bundle_success_path(self, tmp_path, capsys):
        """(a): config-less host + --ca-bundle → verify passes, rc=0,
        'Authentication verified.' and 'registered successfully'."""
        bundle = _write_bundle(tmp_path / "ca.crt")
        client = _mock_register_client(config_ca_exists=False)
        with (
            patch("venya_cli.api_client.httpx2.Client") as MockPost,
            patch("venya_cli.commands.httpx2.Client") as MockVerify,
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
        ):
            MockPost.return_value.__enter__.return_value = MockPost.return_value
            MockPost.return_value.post.return_value = _ok_response()
            MockVerify.return_value.__enter__.return_value = MockVerify.return_value
            MockVerify.return_value.get.return_value = _ok_response()
            rc = executor_register(client, _register_args(tmp_path, ca_bundle=str(bundle)))
        assert rc == 0
        out = capsys.readouterr().out
        assert "Authentication verified." in out
        assert "registered successfully" in out

    def test_no_trust_loud_and_unverified(self, tmp_path, capsys):
        """(b): config-less host, no bundle → loud failure naming --ca-bundle,
        rc=1, the 'registered successfully' line NEVER prints, cert files stay
        on disk (ruling (ii): kept)."""
        client = _mock_register_client(config_ca_exists=False)
        with (
            patch("venya_cli.api_client.httpx2.Client") as MockPost,
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
        ):
            MockPost.return_value.__enter__.return_value = MockPost.return_value
            MockPost.return_value.post.return_value = _ok_response()
            rc = executor_register(client, _register_args(tmp_path))
        assert rc == 1
        captured = capsys.readouterr()
        assert "--ca-bundle" in captured.err
        assert "auth NOT verified" in captured.err
        assert "registered successfully" not in captured.out
        out_dir = tmp_path / "certs"
        assert (out_dir / "executor.crt").exists()
        assert stat.S_IMODE((out_dir / "executor.key").stat().st_mode) == 0o600

    def test_verify_failure_rc1_cert_kept(self, tmp_path, capsys):
        """(c): verify request fails (TLS/HTTP) → rc=1 + 'registered, auth NOT
        verified' + cert kept; success wording absent."""
        bundle = _write_bundle(tmp_path / "ca.crt")
        client = _mock_register_client(config_ca_exists=False)
        with (
            patch("venya_cli.api_client.httpx2.Client") as MockPost,
            patch("venya_cli.commands.httpx2.Client") as MockVerify,
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
        ):
            MockPost.return_value.__enter__.return_value = MockPost.return_value
            MockPost.return_value.post.return_value = _ok_response()
            MockVerify.return_value.__enter__.return_value = MockVerify.return_value
            MockVerify.return_value.get.side_effect = httpx2.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
            rc = executor_register(client, _register_args(tmp_path, ca_bundle=str(bundle)))
        assert rc == 1
        captured = capsys.readouterr()
        assert "registered, auth NOT verified" in captured.err
        assert "registered successfully" not in captured.out
        assert (tmp_path / "certs" / "executor.crt").exists()

    def test_config_dir_ca_path_unchanged(self, tmp_path, capsys):
        """(d) paired negative: a config-bearing host verifies through the
        config-dir CA — --ca-bundle absent, zero new failure modes."""
        ca_dir = tmp_path / "config"
        ca_dir.mkdir()
        _write_bundle(ca_dir / "ca.crt")
        client = _mock_register_client(config_ca_exists=True)
        client.config.ca_path = ca_dir / "ca.crt"
        with (
            patch("venya_cli.api_client.httpx2.Client") as MockPost,
            patch("venya_cli.commands.httpx2.Client") as MockVerify,
            patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(tmp_path / "absent.toml")),
        ):
            MockPost.return_value.__enter__.return_value = MockPost.return_value
            MockPost.return_value.post.return_value = _ok_response()
            MockVerify.return_value.__enter__.return_value = MockVerify.return_value
            MockVerify.return_value.get.return_value = _ok_response()
            rc = executor_register(client, _register_args(tmp_path))
        assert rc == 0
        out = capsys.readouterr().out
        assert "Authentication verified." in out
        assert "registered successfully" in out
