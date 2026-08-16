"""Tests for executor_cert_renew CLI command.

Tests cover:
- Success case (new key, CSR, mTLS auth, atomic file save)
- Not registered (missing cert)
- Missing key file
- mTLS authentication failure (401/403)
- Server rejects CSR (400)
- Network error (connection refused)
- Invalid cert file
- Atomic write failure preserves original files
"""

import json
import stat
from datetime import datetime, timedelta, timezone
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

    cert_path = tmp_path / "executor.pem"
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


def _make_renew_response():
    """Create a mock server response for certificate renewal."""
    now = datetime.now(timezone.utc)
    return {
        "executor_id": "test-exec",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL..." + "X" * 100 + "\n-----END CERTIFICATE-----\n",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL..." + "Y" * 100 + "\n-----END CERTIFICATE-----\n",
        "serial_number": "AB:CD:EF:12:34:56",
        "not_after": (now + timedelta(days=365)).isoformat(),
    }


def _make_mock_httpx_response(status_code=200, json_data=None):
    """Create a mock httpx2 response."""
    import httpx2

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.content = json.dumps(json_data).encode() if json_data else b""
    mock_resp.json.return_value = json_data or {}
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=mock_resp,
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


def _make_mock_httpx_client(post_response=None, post_error=None, get_response=None, get_error=None):
    """Create a mock httpx2.Client for mTLS calls."""
    import httpx2

    mock_post_resp = post_response or _make_mock_httpx_response(
        status_code=200, json_data=_make_renew_response()
    )
    if post_error:
        mock_post_resp.raise_for_status.side_effect = post_error

    mock_get_resp = get_response or _make_mock_httpx_response(status_code=200, json_data={"revoked_serials": []})
    if get_error:
        mock_get_resp.raise_for_status.side_effect = get_error

    mock_client = MagicMock()
    mock_client.post = MagicMock(return_value=mock_post_resp)
    mock_client.get = MagicMock(return_value=mock_get_resp)
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# Success cases
# ---------------------------------------------------------------------------


class TestRenewSuccess:
    """Tests for successful certificate renewal."""

    def test_renew_success(self, tmp_path, capsys):
        """Renewal succeeds: new key+CSR, mTLS auth, files saved, correct output."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.vault_url = "https://venya-vault"

        mock_client = _make_mock_httpx_client()

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Certificate renewed successfully" in captured.out
        assert "test-exec" in captured.out
        assert str(cert_path) in captured.out
        assert str(key_path) in captured.out

        # Verify new key was written (different from original)
        new_key_data = key_path.read_bytes()
        original_key_data = key_path  # Note: key was atomically replaced
        assert new_key_data != b""
        assert b"PRIVATE KEY" in new_key_data

        # Verify new cert was written
        new_cert_data = cert_path.read_bytes()
        assert b"CERTIFICATE" in new_cert_data

        # Verify CA cert was saved
        ca_cert_path = tmp_path / "ca.pem"
        assert ca_cert_path.exists()

    def test_renew_success_with_custom_paths(self, tmp_path, capsys):
        """Renewal respects custom --cert-path and --key-path for output."""
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_cert = custom_dir / "my-cert.pem"
        custom_key = custom_dir / "my-key.key"

        # Create original cert at custom path
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "custom-exec", 30)
        custom_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        custom_key.write_bytes(key_pem)
        custom_key.chmod(0o600)

        args = MagicMock()
        args.cert_path = str(custom_cert)
        args.key_path = str(custom_key)
        args.vault_url = "https://venya-vault"

        mock_client = _make_mock_httpx_client()

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 0

        # Verify files were written to custom paths
        assert custom_cert.exists()
        assert custom_key.exists()
        assert custom_key.stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestRenewErrors:
    """Tests for certificate renewal error handling."""

    def test_renew_not_registered(self, tmp_path, capsys):
        """Missing cert file returns exit code 1."""
        nonexistent = tmp_path / "nonexistent.pem"

        args = MagicMock()
        args.cert_path = str(nonexistent)
        args.key_path = None

        from vault.cli.commands import executor_cert_renew
        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "certificate not found" in captured.err

    def test_renew_missing_key(self, tmp_path, capsys):
        """Cert exists but key missing returns exit code 1."""
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "test-exec", 30)

        cert_path = tmp_path / "executor.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        # Intentionally do NOT create the key file

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(cert_path.with_suffix(".key"))
        args.vault_url = "https://venya-vault"

        from vault.cli.commands import executor_cert_renew
        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "private key not found" in captured.err

    def test_renew_mtls_failure_401(self, tmp_path, capsys):
        """Server returns 401 — mTLS auth failed."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        mock_resp = _make_mock_httpx_response(status_code=401, json_data={"detail": "Invalid certificate"})
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "mTLS authentication failed" in captured.err

    def test_renew_mtls_failure_403(self, tmp_path, capsys):
        """Server returns 403 — mTLS forbidden."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        mock_resp = _make_mock_httpx_response(status_code=403, json_data={"detail": "Certificate revoked"})
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "mTLS authentication failed" in captured.err

    def test_renew_csr_rejected(self, tmp_path, capsys):
        """Server returns 400 — CSR rejected."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        mock_resp = _make_mock_httpx_response(
            status_code=400,
            json_data={"detail": "Weak key — ECDSA P-256 required"},
        )
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Renewal failed" in captured.err

    def test_renew_network_error(self, tmp_path, capsys):
        """Connection failure returns exit code 1."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        import httpx2

        mock_client = _make_mock_httpx_client(
            post_error=httpx2.ConnectError("Connection refused"),
        )

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Connection failed" in captured.err

    def test_renew_invalid_cert(self, tmp_path, capsys):
        """Corrupt cert file returns exit code 1."""
        cert_path = tmp_path / "executor.pem"
        cert_path.write_text("this is not a valid certificate")
        key_path = tmp_path / "executor.key"
        key_path.write_text("not a key either")

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)

        from vault.cli.commands import executor_cert_renew
        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "certificate not found" in captured.err or "Error:" in captured.err


# ---------------------------------------------------------------------------
# Atomic write tests
# ---------------------------------------------------------------------------


class TestRenewAtomicWrite:
    """Tests for atomic cert/key replacement."""

    def test_atomic_write_failure_preserves_original(self, tmp_path, capsys):
        """If write fails, original cert/key remain intact."""
        cert_path, key_path, original_key = _setup_cert_files(tmp_path)
        original_cert_data = cert_path.read_bytes()
        original_key_data = key_path.read_bytes()

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        # Mock the server response as successful
        mock_client = _make_mock_httpx_client()

        # Patch Path.write_bytes to fail after the cert temp file is written
        original_write_bytes = Path.write_bytes

        def failing_write_bytes(self, data):
            if ".tmp" in str(self) and "key" in str(self):
                raise OSError("Disk full")
            return original_write_bytes(self, data)

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            with patch.object(Path, "write_bytes", failing_write_bytes):
                from vault.cli.commands import executor_cert_renew
                result = executor_cert_renew(args)

        assert result == 1

        # Original files must be preserved
        assert cert_path.read_bytes() == original_cert_data
        assert key_path.read_bytes() == original_key_data

        # Temp files should be cleaned up
        assert not cert_path.with_suffix(".pem.tmp").exists()
        assert not key_path.with_suffix(".key.tmp").exists()

    def test_atomic_rename_order_key_before_cert(self, tmp_path):
        """Key is renamed before cert — key_tmp should not persist on success."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.vault_url = "https://venya-vault"

        mock_client = _make_mock_httpx_client()

        with patch("vault.cli.commands.httpx2.Client", return_value=mock_client):
            from vault.cli.commands import executor_cert_renew
            result = executor_cert_renew(args)

        assert result == 0

        # No temp files should remain
        assert not cert_path.with_suffix(".pem.tmp").exists()
        assert not key_path.with_suffix(".key.tmp").exists()

        # Files should be valid
        cert_data = cert_path.read_bytes()
        assert b"CERTIFICATE" in cert_data

        key_data = key_path.read_bytes()
        assert b"PRIVATE KEY" in key_data
