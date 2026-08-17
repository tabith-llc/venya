"""Tests for executor_cert_revoke CLI command.

Tests cover:
- Success with explicit --executor-id
- Success with cert-file fallback (reads CN from local cert)
- Not admin / authentication failure (APIClientAuthenticationError)
- Executor not found (404)
- Network error (APIClientError)
- Invalid/missing cert file for fallback mode
- cmd_admin_revoke_executor delegates to executor_cert_revoke
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
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
    from datetime import datetime, timedelta, timezone

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


def _setup_cert_files(tmp_path, executor_id="test-exec", validity_days=30):
    """Generate and write cert+key files, return (cert_path, key_path, private_key)."""
    private_key = _generate_test_keypair()
    cert = _generate_test_cert(private_key, executor_id, validity_days)

    cert_path = tmp_path / "executor.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    key_path = tmp_path / "executor.key"
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    return cert_path, key_path, private_key


# ---------------------------------------------------------------------------
# executor_cert_revoke tests
# ---------------------------------------------------------------------------


class TestExecutorCertRevoke:
    """Tests for executor_cert_revoke function."""

    def test_revoke_with_explicit_executor_id(self, tmp_path, capsys):
        """Revoke succeeds with explicit --executor-id argument."""
        mock_client = MagicMock()
        mock_client.post.return_value = {"revoked": True, "executor_id": "jump-1"}

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=mock_client)

        assert result == 0
        mock_client.post.assert_called_once_with("/api/v1/admin/executors/jump-1/revoke")

        captured = capsys.readouterr()
        assert "Certificate revoked." in captured.out
        assert "jump-1" in captured.out
        assert "Revoked:      Yes" in captured.out

    def test_revoke_with_cert_fallback(self, tmp_path, capsys):
        """Revoke without --executor-id reads CN from local cert file."""
        cert_path, _, _ = _setup_cert_files(tmp_path, executor_id="local-exec", validity_days=30)

        mock_client = MagicMock()
        mock_client.post.return_value = {"revoked": True, "executor_id": "local-exec"}

        args = MagicMock()
        args.executor_id = None
        args.cert_path = str(cert_path)

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=mock_client)

        assert result == 0
        mock_client.post.assert_called_once_with("/api/v1/admin/executors/local-exec/revoke")

        captured = capsys.readouterr()
        assert "Certificate revoked." in captured.out
        assert "local-exec" in captured.out

    def test_revoke_auth_failure(self, tmp_path, capsys):
        """Authentication failure returns exit 1 with helpful message."""
        from vault.cli.api_client import APIClientAuthenticationError

        mock_client = MagicMock()
        mock_client.post.side_effect = APIClientAuthenticationError("Invalid token")

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=mock_client)

        assert result == 1

        captured = capsys.readouterr()
        assert "Authentication failed" in captured.err
        assert "admin credentials" in captured.err

    def test_revoke_not_found(self, tmp_path, capsys):
        """Executor not found (404) returns exit 1."""
        from vault.cli.api_client import APIClientError

        mock_client = MagicMock()
        mock_client.post.side_effect = APIClientError("Executor not found: unknown-exec")

        args = MagicMock()
        args.executor_id = "unknown-exec"
        args.cert_path = str(tmp_path / "executor.crt")

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=mock_client)

        assert result == 1

        captured = capsys.readouterr()
        assert "Revoke failed" in captured.err
        assert "unknown-exec" in captured.err

    def test_revoke_network_error(self, tmp_path, capsys):
        """Network error returns exit 1."""
        from vault.cli.api_client import APIClientError

        mock_client = MagicMock()
        mock_client.post.side_effect = APIClientError("Connection refused")

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=mock_client)

        assert result == 1

        captured = capsys.readouterr()
        assert "Revoke failed" in captured.err

    def test_revoke_cert_fallback_missing_file(self, tmp_path, capsys):
        """Missing cert file for fallback mode returns exit 1."""
        args = MagicMock()
        args.executor_id = None
        args.cert_path = str(tmp_path / "nonexistent.pem")

        from vault.cli.commands import executor_cert_revoke

        result = executor_cert_revoke(args, client=None)

        assert result == 1

        captured = capsys.readouterr()
        assert "certificate not found" in captured.err
        assert "nonexistent.pem" in captured.err

    def test_revoke_creates_client_when_none(self, tmp_path, capsys):
        """When client=None, creates APIClient from config."""
        cert_path, _, _ = _setup_cert_files(tmp_path, executor_id="auto-exec", validity_days=30)

        args = MagicMock()
        args.executor_id = None
        args.cert_path = str(cert_path)

        with patch("vault.cli.commands.APIClient") as MockAPIClient:
            mock_instance = MagicMock()
            mock_instance.post.return_value = {"revoked": True, "executor_id": "auto-exec"}
            MockAPIClient.return_value = mock_instance

            from vault.cli.commands import executor_cert_revoke

            result = executor_cert_revoke(args, client=None)

            assert result == 0
            MockAPIClient.assert_called_once()
            mock_instance.post.assert_called_once_with("/api/v1/admin/executors/auto-exec/revoke")


# ---------------------------------------------------------------------------
# cmd_admin_revoke_executor delegation tests
# ---------------------------------------------------------------------------


class TestAdminRevokeExecutorDelegation:
    """Tests that cmd_admin_revoke_executor delegates to executor_cert_revoke."""

    def test_admin_revoke_delegates(self, capsys):
        """cmd_admin_revoke_executor passes executor_id and client to executor_cert_revoke."""
        mock_client = MagicMock()
        mock_client.post.return_value = {"revoked": True, "executor_id": "admin-exec"}

        args = MagicMock()
        args.executor_id = "admin-exec"

        with patch("vault.cli.commands.executor_cert_revoke") as mock_revoke:
            mock_revoke.return_value = 0
            from vault.cli.commands import cmd_admin_revoke_executor

            result = cmd_admin_revoke_executor(mock_client, args)

            assert result == 0
            mock_revoke.assert_called_once()
            call_args = mock_revoke.call_args
            # First arg should have executor_id
            assert call_args[0][0].executor_id == "admin-exec"
            # Second arg should be client=mock_client
            assert call_args[1]["client"] is mock_client

    def test_admin_revoke_returns_error_code(self, capsys):
        """cmd_admin_revoke_executor returns error code from executor_cert_revoke."""
        mock_client = MagicMock()

        args = MagicMock()
        args.executor_id = "bad-exec"

        with patch("vault.cli.commands.executor_cert_revoke") as mock_revoke:
            mock_revoke.return_value = 1
            from vault.cli.commands import cmd_admin_revoke_executor

            result = cmd_admin_revoke_executor(mock_client, args)

            assert result == 1
