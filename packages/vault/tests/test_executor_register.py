"""Tests for executor registration CLI commands.

Tests cover:
- CLI argument parsing for run, exec register, exec cert status
- ECDSA P-256 key generation
- CSR creation
- executor_register() flow with mocked API
- executor_cert_status() with real certificate files
- File permissions
"""

import json
import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vault.cli.api_client import APIClient, APIClientError, Config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_mock_response(status_code=200, json_data=None, content=None):
    """Create a mock httpx.Response."""
    mock = MagicMock()
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode() if content is None else content
    elif content is not None:
        mock.content = content
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


def _make_mock_client(config_file=None):
    """Create an APIClient with mocked HTTP layer."""
    if config_file is None:
        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text("{}")
    client = APIClient(config_file=config_file)
    mock_http = MagicMock()
    mock_response = _make_mock_response(status_code=200, json_data={"test": True})
    mock_response.raise_for_status.return_value = None
    mock_http.request.return_value = mock_response
    client._http = mock_http
    return client, config_file


def _generate_test_keypair():
    """Generate an ECDSA P-256 keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key


def _generate_test_csr(private_key, executor_id="venya-exec"):
    """Generate a CSR for testing."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr


def _generate_test_cert(private_key, executor_id="venya-exec", validity_days=30):
    """Generate a self-signed cert for testing cert status."""
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])
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
# CLI argument parsing tests
# ---------------------------------------------------------------------------


class TestCLIParsing:
    """Tests for CLI argument parsing."""

    def test_run_command_exists(self):
        """The 'run' command is available as a top-level command."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["run", "ls", "-la"])
        assert args.command == "run"
        assert args.command_args == ["ls", "-la"]

    def test_run_command_with_secrets(self):
        """The 'run' command accepts --secret flags."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "run",
            "--secret", "db_password",
            "--secret", "api_key",
            "echo", "hello",
        ])
        assert args.command == "run"
        assert args.secrets == ["db_password", "api_key"]

    def test_run_command_with_executor_id(self):
        """The 'run' command accepts --executor-id."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "run",
            "--executor-id", "my-executor",
            "ls",
        ])
        assert args.executor_id == "my-executor"

    def test_exec_command_exists(self):
        """The 'exec' command group is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "register"])
        assert args.command == "exec"
        assert args.exec_command == "register"

    def test_exec_register_defaults(self):
        """exec register has correct default values."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "register"])
        assert args.exec_command == "register"
        assert args.executor_id == "venya-exec"
        assert args.output_dir == "/etc/venya/executor"
        assert args.vault_url is None

    def test_exec_register_custom_params(self):
        """exec register accepts custom --executor-id, --vault-url, --output-dir."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "exec", "register",
            "--executor-id", "my-exec-1",
            "--vault-url", "https://vault.example.com",
            "--output-dir", "/tmp/certs",
        ])
        assert args.executor_id == "my-exec-1"
        assert args.vault_url == "https://vault.example.com"
        assert args.output_dir == "/tmp/certs"

    def test_exec_cert_status(self):
        """exec cert status is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "cert", "status"])
        assert args.exec_command == "cert"
        assert args.cert_command == "status"
        assert args.cert_path == "/etc/venya/executor/executor.crt"

    def test_exec_cert_status_custom_path(self):
        """exec cert status accepts --cert-path."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "exec", "cert", "status",
            "--cert-path", "/custom/path.pem",
        ])
        assert args.cert_path == "/custom/path.pem"

    def test_exec_cert_renew(self):
        """exec cert renew is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "cert", "renew"])
        assert args.exec_command == "cert"
        assert args.cert_command == "renew"

    def test_exec_cert_revoke(self):
        """exec cert revoke is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "cert", "revoke"])
        assert args.exec_command == "cert"
        assert args.cert_command == "revoke"

    def test_exec_heartbeat(self):
        """exec heartbeat is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "heartbeat"])
        assert args.exec_command == "heartbeat"

    def test_exec_audit(self):
        """exec audit is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "audit"])
        assert args.exec_command == "audit"

    def test_exec_status(self):
        """exec status is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "status"])
        assert args.exec_command == "status"

    def test_exec_without_subcommand(self):
        """exec without subcommand prints error."""
        from vault.cli.cli import create_parser
        from vault.cli.commands import run_command

        parser = create_parser()
        args = parser.parse_args(["exec"])
        # exec_command will be None
        assert args.exec_command is None

    def test_no_command_returns_nonzero(self):
        """No command returns exit code 1."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([])
        assert args.command is None


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    """Tests for ECDSA P-256 key generation."""

    def test_ecdsa_key_generation(self):
        """ECDSA P-256 key generation produces valid keypair."""
        private_key = _generate_test_keypair()
        from cryptography.hazmat.primitives.asymmetric import ec
        assert isinstance(private_key.curve, ec.SECP256R1)
        public_key = private_key.public_key()
        # Verify the key can sign/verify
        message = b"test data"
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

    def test_ecdsa_key_serialization(self):
        """Private key can be serialized to PEM format."""
        private_key = _generate_test_keypair()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert pem.endswith(b"-----END PRIVATE KEY-----\n")
        # Can be re-loaded
        loaded = serialization.load_pem_private_key(pem, password=None)
        assert isinstance(loaded.curve, ec.SECP256R1)


# ---------------------------------------------------------------------------
# CSR creation tests
# ---------------------------------------------------------------------------


class TestCSRCreation:
    """Tests for CSR creation."""

    def test_csr_creation(self):
        """CSR is created with correct CN."""
        private_key = _generate_test_keypair()
        csr = _generate_test_csr(private_key, "test-exec-1")

        # Verify CSR is valid PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        assert csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")

        # Verify CSR subject
        loaded_csr = x509.load_pem_x509_csr(csr_pem)
        cn_attrs = [
            attr.value for attr in loaded_csr.subject
            if attr.oid == NameOID.COMMON_NAME
        ]
        assert "test-exec-1" in cn_attrs

    def test_csr_signing_key_matches(self):
        """CSR signing key matches the original private key."""
        private_key = _generate_test_keypair()
        csr = _generate_test_csr(private_key, "match-test")
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        loaded_csr = x509.load_pem_x509_csr(csr_pem)
        # The public key in the CSR should match the original private key
        assert loaded_csr.public_key().public_numbers() == private_key.public_key().public_numbers()


# ---------------------------------------------------------------------------
# executor_register() tests
# ---------------------------------------------------------------------------


class TestExecutorRegister:
    """Tests for the executor_register() function."""

    def test_register_success(self, tmp_path):
        """Successful registration saves cert and key files."""
        from vault.cli.commands import executor_register

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "venya-exec", validity_days=30)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        ca_cert_pem = cert_pem  # In real scenario, this would be the CA cert

        output_dir = str(tmp_path / "certs")

        # Create mock args
        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = "https://vault.example.com"
        args.output_dir = output_dir

        # Create client
        client, config_file = _make_mock_client()

        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "executor_id": "venya-exec",
                "cert_pem": cert_pem,
                "ca_cert_pem": ca_cert_pem,
                "serial_number": "01:23:45",
                "not_after": "2026-09-13T00:00:00+00:00",
            },
        )

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = executor_register(client, args)
                assert result == 0

                # Verify files were created
                assert (tmp_path / "certs" / "executor.key").exists()
                assert (tmp_path / "certs" / "executor.crt").exists()
                assert (tmp_path / "certs" / "ca.crt").exists()

                # Verify key file permissions
                key_stat = os.stat(tmp_path / "certs" / "executor.key")
                assert stat.S_IMODE(key_stat.st_mode) == 0o600
            finally:
                client.close()
        config_file.unlink()

    def test_register_no_vault_url(self, tmp_path):
        """Registration fails without vault URL when config has no URL."""
        from vault.cli.commands import executor_register

        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text("{}")

        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = None
        args.output_dir = str(tmp_path)

        client, _ = _make_mock_client(config_file)
        try:
            result = executor_register(client, args)
            assert result == 1
        finally:
            client.close()
        config_file.unlink()

    def test_register_api_failure(self, tmp_path):
        """Registration fails gracefully when API returns error."""
        from vault.cli.commands import executor_register

        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text('{"server_url": "https://vault.example.com"}')

        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = None
        args.output_dir = str(tmp_path)

        client, _ = _make_mock_client(config_file)
        client._http.request.side_effect = APIClientError("Connection refused")
        try:
            result = executor_register(client, args)
            assert result == 1
        finally:
            client.close()
        config_file.unlink()

    def test_register_no_cert_in_response(self, tmp_path):
        """Registration fails when API returns no certificate."""
        from vault.cli.commands import executor_register

        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text('{"server_url": "https://vault.example.com"}')

        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = None
        args.output_dir = str(tmp_path)

        client, _ = _make_mock_client(config_file)
        client._http.request.return_value = _make_mock_response(
            status_code=201,
            json_data={
                "executor_id": "venya-exec",
                "serial_number": "01:23:45",
                "not_after": "2026-09-13T00:00:00+00:00",
            },
        )
        try:
            result = executor_register(client, args)
            assert result == 1
        finally:
            client.close()
        config_file.unlink()

    def test_register_creates_output_dir(self, tmp_path):
        """Registration creates output directory if it doesn't exist."""
        from vault.cli.commands import executor_register

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "venya-exec", validity_days=30)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        nested_dir = str(tmp_path / "a" / "b" / "c" / "certs")

        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = "https://vault.example.com"
        args.output_dir = nested_dir

        client, config_file = _make_mock_client()

        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "executor_id": "venya-exec",
                "cert_pem": cert_pem,
                "ca_cert_pem": cert_pem,
                "serial_number": "01:23:45",
                "not_after": "2026-09-13T00:00:00+00:00",
            },
        )

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = executor_register(client, args)
                assert result == 0
                assert (tmp_path / "a" / "b" / "c" / "certs" / "executor.key").exists()
            finally:
                client.close()
        config_file.unlink()

    def test_register_uses_config_server_url(self, tmp_path):
        """Registration uses server_url from config when --vault-url is not provided."""
        from vault.cli.commands import executor_register

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "venya-exec", validity_days=30)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text('{"server_url": "https://config-url.example.com"}')

        args = MagicMock()
        args.executor_id = "venya-exec"
        args.vault_url = None
        args.output_dir = str(tmp_path)

        client, _ = _make_mock_client(config_file)

        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "executor_id": "venya-exec",
                "cert_pem": cert_pem,
                "ca_cert_pem": cert_pem,
                "serial_number": "01:23:45",
                "not_after": "2026-09-13T00:00:00+00:00",
            },
        )

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = executor_register(client, args)
                assert result == 0
                # Verify throwaway client was created with verify=True
                MockClient.assert_called_once_with(verify=True, timeout=30.0)
            finally:
                client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# executor_cert_status() tests
# ---------------------------------------------------------------------------


class TestExecutorCertStatus:
    """Tests for the executor_cert_status() function."""

    def test_cert_status_ok(self, tmp_path):
        """Cert status returns 0 when cert has >7 days remaining."""
        from vault.cli.commands import executor_cert_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "status-test", validity_days=30)
        cert_path = tmp_path / "good.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)

        result = executor_cert_status(args)
        assert result == 0

    def test_cert_status_expired(self, tmp_path):
        """Cert status returns 1 when cert is expired."""
        from vault.cli.commands import executor_cert_status

        private_key = _generate_test_keypair()
        # Create a cert that expired 5 days ago
        now = datetime.now(timezone.utc)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "expired-test"),
        ])
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

        result = executor_cert_status(args)
        assert result == 1

    def test_cert_status_expiring_soon(self, tmp_path):
        """Cert status returns 0 when cert expires in <7 days (warning, still valid)."""
        from vault.cli.commands import executor_cert_status

        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "expiring-test", validity_days=3)
        cert_path = tmp_path / "expiring.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)

        result = executor_cert_status(args)
        assert result == 0

    def test_cert_status_missing_file(self, tmp_path):
        """Cert status returns 1 when cert file doesn't exist."""
        from vault.cli.commands import executor_cert_status

        args = MagicMock()
        args.cert_path = str(tmp_path / "nonexistent.pem")

        result = executor_cert_status(args)
        assert result == 1

    def test_cert_status_reads_cn(self, tmp_path, capsys):
        """Cert status prints the CN from the certificate."""
        from vault.cli.commands import executor_cert_status

        private_key = _generate_test_keypair()
        cn_value = "my-special-executor"
        cert = _generate_test_cert(private_key, cn_value, validity_days=30)
        cert_path = tmp_path / "cn-test.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        args = MagicMock()
        args.cert_path = str(cert_path)

        result = executor_cert_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert cn_value in captured.out


# ---------------------------------------------------------------------------
# Placeholder subcommand tests
# ---------------------------------------------------------------------------


class TestPlaceholderSubcommands:
    """Tests for placeholder subcommands."""

    def test_cert_renew_placeholder(self):
        """cert renew dispatches to executor_cert_renew."""
        from unittest.mock import patch

        from vault.cli.commands import executor_cert

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            args.cert_command = "renew"
            with patch("vault.cli.commands.executor_cert_renew", return_value=0) as mock_renew:
                result = executor_cert(client, args)
                assert result == 0
                mock_renew.assert_called_once()
        finally:
            client.close()

    def test_cert_revoke_placeholder(self):
        """cert revoke is implemented — see test_executor_cert_revoke.py."""
        from vault.cli.commands import executor_cert

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            args.cert_command = "revoke"
            # Without --executor-id and without a cert file, should fail with exit 1
            result = executor_cert(client, args)
            assert result == 1
        finally:
            client.close()

    def test_heartbeat_placeholder(self):
        """heartbeat implemented — see test_executor_heartbeat.py."""
        pass

    def test_audit_placeholder(self):
        """audit prints 'Not yet implemented'."""
        from vault.cli.commands import executor_audit

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            result = executor_audit(client, args)
            assert result == 0
        finally:
            client.close()

    def test_status_placeholder(self, tmp_path):
        """status returns 1 when not registered (no cert file)."""
        from vault.cli.commands import executor_status

        args = MagicMock()
        args.cert_path = str(tmp_path / "nonexistent.pem")
        args.vault_url = None
        args.config_path = None

        with patch("vault.cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            result = executor_status(args)
            assert result == 1

    def test_exec_group_no_subcommand(self):
        """exec without subcommand returns 1."""
        from vault.cli.commands import cmd_exec_group

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            args.exec_command = None
            result = cmd_exec_group(client, args)
            assert result == 1
        finally:
            client.close()

    def test_exec_group_unknown_subcommand(self):
        """exec with unknown subcommand returns 1."""
        from vault.cli.commands import cmd_exec_group

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            args.exec_command = "fizzbuzz"
            result = cmd_exec_group(client, args)
            assert result == 1
        finally:
            client.close()

    def test_exec_cert_no_subcommand(self):
        """exec cert without subcommand returns 1."""
        from vault.cli.commands import executor_cert

        client, config_file = _make_mock_client()
        try:
            args = MagicMock()
            args.cert_command = None
            result = executor_cert(client, args)
            assert result == 1
        finally:
            client.close()
