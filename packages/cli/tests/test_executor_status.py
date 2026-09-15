"""Tests for executor_status CLI command.

Tests cover:
- _parse_executor_cert() shared helper
- _get_server_url() config fallback chain
- executor_status() with various states
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _generate_test_keypair():
    """Generate an ECDSA P-256 keypair for testing."""
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, executor_id="venya-exec", validity_days=30):
    """Generate a self-signed certificate for testing."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(private_key, hashes.SHA256())
    )
    return cert


# ---------------------------------------------------------------------------
# _parse_executor_cert() tests
# ---------------------------------------------------------------------------


class TestParseExecutorCert:
    """Tests for the shared _parse_executor_cert() helper."""

    def test_parse_returns_none_for_missing_file(self):
        """Returns None when cert file doesn't exist."""
        from venya_cli.commands import _parse_executor_cert

        result = _parse_executor_cert("/nonexistent/path/cert.pem")
        assert result is None

    def test_parse_returns_none_for_invalid_file(self, tmp_path):
        """Returns None when cert file is not a valid certificate."""
        from venya_cli.commands import _parse_executor_cert

        cert_path = tmp_path / "not-a-cert.pem"
        cert_path.write_text("this is not a certificate")

        result = _parse_executor_cert(str(cert_path))
        assert result is None

    def test_parse_returns_metadata_for_valid_cert(self, tmp_path):
        """Returns dict with metadata for a valid certificate."""
        from venya_cli.commands import _parse_executor_cert

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "parse-test", validity_days=30)
        cert_path = tmp_path / "valid.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        result = _parse_executor_cert(str(cert_path))
        assert result is not None
        assert result["executor_id"] == "parse-test"
        assert (
            "SERIAL" in result["serial"]
            or result["serial"]
            .replace("A", "")
            .replace("B", "")
            .replace("C", "")
            .replace("D", "")
            .replace("E", "")
            .replace("F", "")
            != ""
        )
        assert "parse-test" in result["subject"]
        assert result["days_remaining"] > 0
        assert result["days_remaining"] <= 30

    def test_parse_returns_negative_days_for_expired_cert(self, tmp_path):
        """Returns negative days_remaining for an expired certificate."""
        from venya_cli.commands import _parse_executor_cert

        private_key = _generate_test_keypair()
        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.COMMON_NAME, "expired-test"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now - timedelta(days=5))
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "expired.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        result = _parse_executor_cert(str(cert_path))
        assert result is not None
        assert result["days_remaining"] < 0


# ---------------------------------------------------------------------------
# _get_server_url() tests
# ---------------------------------------------------------------------------


class TestGetServerUrl:
    """Tests for the _get_server_url() config fallback chain."""

    def test_core_url_arg_takes_precedence(self):
        """--core-url arg is returned immediately."""
        from venya_cli.commands import _get_server_url

        args = MagicMock()
        args.core_url = "https://my-core.example.com"
        args.config_path = "/nonexistent/executor.toml"

        result = _get_server_url(args)
        assert result == "https://my-core.example.com"

    def test_config_json_used_when_non_default(self, tmp_path):
        """Config.json server_url is used when not localhost:8000."""
        from venya_cli.commands import _get_server_url

        args = MagicMock()
        args.core_url = None
        args.config_path = "/nonexistent/executor.toml"

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "https://from-config.example.com"
            MockConfig.return_value = mock_config

            result = _get_server_url(args)
            assert result == "https://from-config.example.com"

    def test_config_json_skipped_when_localhost(self, tmp_path):
        """Config.json with localhost:8000 is skipped, falls through to executor.toml."""
        from venya_cli.commands import _get_server_url

        args = MagicMock()
        args.core_url = None
        args.config_path = "/nonexistent/executor.toml"

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = _get_server_url(args)
            assert result == "unknown"

    def test_executor_toml_used_as_fallback(self, tmp_path):
        """Executor TOML is used when Config.json has localhost."""
        from venya_cli.commands import _get_server_url

        toml_path = tmp_path / "executor.toml"
        toml_path.write_text('server_url = "https://from-toml.example.com"')

        args = MagicMock()
        args.core_url = None
        args.config_path = str(toml_path)

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = _get_server_url(args)
            assert result == "https://from-toml.example.com"

    def test_returns_unknown_when_no_config(self):
        """Returns 'unknown' when no config sources available."""
        from venya_cli.commands import _get_server_url

        args = MagicMock()
        args.core_url = None
        args.config_path = "/nonexistent/executor.toml"

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = _get_server_url(args)
            assert result == "unknown"


# ---------------------------------------------------------------------------
# executor_status() tests
# ---------------------------------------------------------------------------


class TestExecutorStatus:
    """Tests for the executor_status() function."""

    def test_status_ok(self, tmp_path, capsys):
        """Status returns 0 when cert is valid with >7 days remaining."""
        from venya_cli.commands import executor_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "status-ok", validity_days=30)
        cert_path = tmp_path / "ok.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.core_url = None
        args.config_path = None

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 0

        captured = capsys.readouterr()
        assert "Executor Status" in captured.out
        assert "Registered:     Yes" in captured.out
        assert "status-ok" in captured.out
        assert "Serial:" in captured.out
        assert "Status:         OK" in captured.out

    def test_status_warning(self, tmp_path, capsys):
        """Status returns 0 (not 1) when cert expires in <7 days."""
        from venya_cli.commands import executor_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "status-warn", validity_days=3)
        cert_path = tmp_path / "warn.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.core_url = None
        args.config_path = None

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 0

        captured = capsys.readouterr()
        assert "Status:         WARNING" in captured.out
        assert "WARNING: Certificate expires in less than 7 days!" in captured.err

    def test_status_expired(self, tmp_path, capsys):
        """Status returns 1 when cert is expired."""
        from venya_cli.commands import executor_status

        private_key = _generate_test_keypair()
        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.COMMON_NAME, "status-expired"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now - timedelta(days=5))
            .sign(private_key, hashes.SHA256())
        )
        cert_path = tmp_path / "expired.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.core_url = None
        args.config_path = None

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 1

        captured = capsys.readouterr()
        assert "Status:         EXPIRED" in captured.out

    def test_status_not_registered(self, tmp_path, capsys):
        """Status returns 1 when cert file doesn't exist."""
        from venya_cli.commands import executor_status

        args = MagicMock()
        args.cert_path = str(tmp_path / "nonexistent.pem")
        args.core_url = None
        args.config_path = None

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 1

        captured = capsys.readouterr()
        assert "Registered:     No" in captured.out
        assert "Status:         NOT REGISTERED" in captured.out

    def test_status_includes_serial(self, tmp_path, capsys):
        """Status prints the certificate serial number."""
        from venya_cli.commands import executor_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "serial-test", validity_days=30)
        cert_path = tmp_path / "serial.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.core_url = None
        args.config_path = None

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 0

        captured = capsys.readouterr()
        assert "Serial:" in captured.out
        # Serial should be a hex string (non-empty)
        for line in captured.out.split("\n"):
            if line.strip().startswith("Serial:"):
                serial_value = line.split(":", 1)[1].strip()
                assert len(serial_value) > 0

    def test_status_uses_core_url_arg(self, tmp_path, capsys):
        """Status uses --core-url arg for server URL display."""
        from venya_cli.commands import executor_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "url-test", validity_days=30)
        cert_path = tmp_path / "url.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.core_url = "https://my-core.example.com"
        args.config_path = None

        result = executor_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "https://my-core.example.com" in captured.out
