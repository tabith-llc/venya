"""Tests for executor_audit CLI command.

Tests cover:
- Success with table output
- Success with --json output
- No events found
- Not admin/auditor (authentication failure)
- Network error
- Missing cert file for fallback mode
- executor_id extracted from fields JSON
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
# executor_audit tests
# ---------------------------------------------------------------------------


class TestExecutorAudit:
    """Tests for executor_audit function."""

    def test_audit_table_output(self, tmp_path, capsys):
        """Audit succeeds with table output format."""
        mock_client = MagicMock()
        mock_client.get.return_value = {
            "events": [
                {
                    "id": 142,
                    "event_type": "executor_registered",
                    "user_id": "admin-1",
                    "fields": {"executor_id": "jump-1", "serial_number": "ABCD"},
                    "timestamp": "2026-08-13T10:00:00Z",
                },
                {
                    "id": 143,
                    "event_type": "heartbeat",
                    "user_id": None,
                    "fields": {"executor_id": "jump-1"},
                    "timestamp": "2026-08-13T10:00:30Z",
                },
            ],
            "total": 2,
            "limit": 100,
            "offset": 0,
        }

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 0
        mock_client.get.assert_called_once_with(
            "/api/v1/audit",
            params={"executor_id": "jump-1", "limit": 100, "offset": 0},
        )

        captured = capsys.readouterr()
        assert "Audit Events for jump-1" in captured.out
        assert "executor_registered" in captured.out
        assert "jump-1" in captured.out
        assert "2026-08-13T10:00:00Z" in captured.out

    def test_audit_json_output(self, tmp_path, capsys):
        """Audit with --json prints raw response."""
        mock_client = MagicMock()
        expected_response = {
            "events": [
                {
                    "id": 142,
                    "event_type": "heartbeat",
                    "user_id": None,
                    "fields": {"executor_id": "jump-1"},
                    "timestamp": "2026-08-13T10:00:00Z",
                },
            ],
            "total": 1,
            "limit": 100,
            "offset": 0,
        }
        mock_client.get.return_value = expected_response

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = True

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 0
        captured = capsys.readouterr()
        assert '"events"' in captured.out
        assert '"jump-1"' in captured.out

    def test_audit_no_events(self, tmp_path, capsys):
        """No events returns clean message."""
        mock_client = MagicMock()
        mock_client.get.return_value = {"events": [], "total": 0, "limit": 100, "offset": 0}

        args = MagicMock()
        args.executor_id = "unknown-exec"
        args.cert_path = str(tmp_path / "executor.crt")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 0

        captured = capsys.readouterr()
        assert "No audit events found" in captured.out
        assert "unknown-exec" in captured.out

    def test_audit_auth_failure(self, tmp_path, capsys):
        """Authentication failure returns exit 1 with helpful message."""
        from vault.cli.api_client import APIClientAuthenticationError

        mock_client = MagicMock()
        mock_client.get.side_effect = APIClientAuthenticationError("Invalid token")

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Authentication failed" in captured.err
        assert "admin or auditor" in captured.err

    def test_audit_network_error(self, tmp_path, capsys):
        """Network error returns exit 1."""
        from vault.cli.api_client import APIClientError

        mock_client = MagicMock()
        mock_client.get.side_effect = APIClientError("Connection refused")

        args = MagicMock()
        args.executor_id = "jump-1"
        args.cert_path = str(tmp_path / "executor.crt")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Audit query failed" in captured.err

    def test_audit_cert_fallback(self, tmp_path, capsys):
        """Without --executor-id, reads CN from local cert file."""
        cert_path, _, _ = _setup_cert_files(tmp_path, executor_id="local-exec", validity_days=30)

        mock_client = MagicMock()
        mock_client.get.return_value = {
            "events": [
                {
                    "id": 1,
                    "event_type": "heartbeat",
                    "user_id": None,
                    "fields": {"executor_id": "local-exec"},
                    "timestamp": "2026-08-13T10:00:00Z",
                },
            ],
            "total": 1,
            "limit": 100,
            "offset": 0,
        }

        args = MagicMock()
        args.executor_id = None
        args.cert_path = str(cert_path)
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(mock_client, args)

        assert result == 0
        mock_client.get.assert_called_once_with(
            "/api/v1/audit",
            params={"executor_id": "local-exec", "limit": 100, "offset": 0},
        )

        captured = capsys.readouterr()
        assert "Audit Events for local-exec" in captured.out

    def test_audit_cert_fallback_missing_file(self, tmp_path, capsys):
        """Missing cert file for fallback mode returns exit 1."""
        args = MagicMock()
        args.executor_id = None
        args.cert_path = str(tmp_path / "nonexistent.pem")
        args.hours = None
        args.days = None
        args.limit = 100
        args.offset = 0
        args.json = False

        from vault.cli.commands import executor_audit

        result = executor_audit(None, args)

        assert result == 1

        captured = capsys.readouterr()
        assert "certificate not found" in captured.err
        assert "nonexistent.pem" in captured.err
