"""Tests for executor_heartbeat CLI command.

Tests cover:
- Success cases (not revoked, new cert required)
- Revoked certificate
- Missing cert/key files
- Network errors (connection refused, timeout, server error)
- Invalid cert file
- Unknown server URL
- Fingerprint included in payload
- mTLS client instantiation
- Key path derivation and override
- Custom cert path
- Output format verification
"""

import json
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
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])
    now = datetime.now(timezone.utc)
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
    """Generate and write cert+key files, return (cert_path, key_path)."""
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

    return cert_path, key_path, private_key


def _make_mock_response(status_code=200, json_data=None):
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


def _make_mock_client(response_data=None, post_error=None, status_code=200):
    """Create a mock httpx2.Client that returns a mock response from .post()."""
    mock_resp = _make_mock_response(
        status_code=status_code,
        json_data=response_data or {"revoked": False, "new_cert_required": False},
    )
    mock_post = MagicMock(return_value=mock_resp)
    if post_error:
        mock_post.side_effect = post_error

    mock_client = MagicMock()
    mock_client.post = mock_post
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# Success cases
# ---------------------------------------------------------------------------


class TestHeartbeatSuccess:
    """Tests for successful heartbeat responses."""

    def test_heartbeat_success_not_revoked(self, tmp_path, capsys):
        """Heartbeat succeeds when not revoked and no cert rotation needed."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Heartbeat Response" in captured.out
        assert "Revoked:         No" in captured.out
        assert "Cert Rotation:   Not Required" in captured.out

    def test_heartbeat_success_new_cert_required(self, tmp_path, capsys):
        """Heartbeat succeeds when new cert is required (not revoked)."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": True},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Cert Rotation:   Required" in captured.out
        assert "Revoked:         No" in captured.out

    def test_heartbeat_includes_fingerprint_in_payload(self, tmp_path):
        """SHA-256 hex fingerprint is sent in the POST body."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client) as MockClient:
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0

        # Verify the POST call included the fingerprint
        call_args = mock_client.post.call_args
        json_payload = call_args.kwargs["json"] if call_args.kwargs else call_args[1]["json"]
        assert "executor_id" in json_payload
        assert "cert_fingerprint" in json_payload
        assert isinstance(json_payload["cert_fingerprint"], str)
        assert len(json_payload["cert_fingerprint"]) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# Revoked certificate
# ---------------------------------------------------------------------------


class TestHeartbeatRevoked:
    """Tests for revoked certificate handling."""

    def test_heartbeat_revoked(self, tmp_path, capsys):
        """Heartbeat exits 1 and prints WARNING when revoked."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": True, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Revoked:         YES" in captured.out
        assert "WARNING: This executor's certificate has been revoked." in captured.err

    def test_heartbeat_revoked_with_cert_rotation(self, tmp_path, capsys):
        """Heartbeat exits 1 when both revoked and cert rotation needed."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": True, "new_cert_required": True},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Revoked:         YES" in captured.out
        assert "Cert Rotation:   Required" in captured.out


# ---------------------------------------------------------------------------
# Missing cert/key files
# ---------------------------------------------------------------------------


class TestHeartbeatMissingFiles:
    """Tests for missing certificate or key files."""

    def test_heartbeat_missing_cert(self, tmp_path, capsys):
        """Heartbeat exits 1 when cert file doesn't exist."""
        from core.cli.commands import executor_heartbeat

        args = MagicMock()
        args.cert_path = str(tmp_path / "nonexistent.pem")
        args.key_path = None
        args.core_url = "https://venya-core"

        result = executor_heartbeat(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "certificate not found" in captured.err
        assert "Run 'venya exec register'" in captured.err

    def test_heartbeat_missing_key(self, tmp_path, capsys):
        """Heartbeat exits 1 when key file doesn't exist but cert does."""
        cert_path, _, _ = _setup_cert_files(tmp_path)

        # Deliberately do NOT create the key file
        key_path = tmp_path / "executor.key"
        key_path.unlink()  # Remove it

        from core.cli.commands import executor_heartbeat

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        result = executor_heartbeat(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "private key not found" in captured.err


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------


class TestHeartbeatNetworkErrors:
    """Tests for network error handling."""

    def test_heartbeat_connection_refused(self, tmp_path, capsys):
        """Heartbeat exits 1 on connection error."""
        import httpx2

        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            post_error=httpx2.ConnectError("Connection refused"),
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Connection failed" in captured.err

    def test_heartbeat_timeout(self, tmp_path, capsys):
        """Heartbeat exits 1 on timeout."""
        import httpx2

        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            post_error=httpx2.TimeoutException("Request timed out"),
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "timed out" in captured.err

    def test_heartbeat_server_error_500(self, tmp_path, capsys):
        """Heartbeat exits 1 on 500 server error."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            status_code=500,
            response_data={"detail": "Internal server error"},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Heartbeat failed" in captured.err


# ---------------------------------------------------------------------------
# Invalid cert
# ---------------------------------------------------------------------------


class TestHeartbeatInvalidCert:
    """Tests for invalid certificate handling."""

    def test_heartbeat_invalid_cert_file(self, tmp_path, capsys):
        """Heartbeat exits 1 when cert file is not a valid certificate."""
        from core.cli.commands import executor_heartbeat

        # Write invalid PEM content
        cert_path = tmp_path / "executor.crt"
        cert_path.write_text("this is not a certificate")

        # Also write a valid key (so we get past the key check)
        key_path = tmp_path / "executor.key"
        key_path.write_text("fake key")

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        result = executor_heartbeat(args)
        assert result == 1

        captured = capsys.readouterr()
        # _parse_executor_cert returns None for invalid cert
        assert "certificate not found" in captured.err


# ---------------------------------------------------------------------------
# Server URL resolution
# ---------------------------------------------------------------------------


class TestHeartbeatServerUrl:
    """Tests for server URL resolution."""

    def test_heartbeat_unknown_server_url(self, tmp_path, capsys):
        """Heartbeat exits 1 when server URL is unknown."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        from core.cli.commands import executor_heartbeat

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = None

        with patch("core.cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            # tomllib is imported locally inside _get_server_url
            with patch.dict("sys.modules", {"tomllib": None}):
                result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "server URL not configured" in captured.err


# ---------------------------------------------------------------------------
# mTLS client
# ---------------------------------------------------------------------------


class TestHeartbeatMtls:
    """Tests for mTLS client usage."""

    def test_heartbeat_mtls_client_used(self, tmp_path):
        """httpx2.Client is instantiated with cert=(cert_path, key_path)."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client) as MockClient:
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0
        MockClient.assert_called_once()
        call_kwargs = MockClient.call_args.kwargs if MockClient.call_args.kwargs else MockClient.call_args[1]
        assert call_kwargs["cert"] == (str(cert_path), str(key_path))
        assert call_kwargs["verify"] is True
        assert call_kwargs["timeout"] == 10.0


# ---------------------------------------------------------------------------
# Key path derivation
# ---------------------------------------------------------------------------


class TestHeartbeatKeyPath:
    """Tests for key path derivation and override."""

    def test_heartbeat_key_derived_from_cert(self, tmp_path):
        """Key path is derived from cert path when --key-path not provided."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client) as MockClient:
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0
        call_kwargs = MockClient.call_args.kwargs if MockClient.call_args.kwargs else MockClient.call_args[1]
        # key_path was derived: executor.crt -> executor.key
        assert call_kwargs["cert"] == (str(cert_path), str(key_path))

    def test_heartbeat_custom_key_path(self, tmp_path):
        """--key-path overrides the derived key path."""
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "test-exec", validity_days=30)

        cert_path = tmp_path / "executor.crt"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        # Custom key path
        custom_key_path = tmp_path / "custom.key"
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        custom_key_path.write_bytes(key_pem)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(custom_key_path)
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client) as MockClient:
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0
        call_kwargs = MockClient.call_args.kwargs if MockClient.call_args.kwargs else MockClient.call_args[1]
        assert call_kwargs["cert"] == (str(cert_path), str(custom_key_path))


# ---------------------------------------------------------------------------
# Custom cert path
# ---------------------------------------------------------------------------


class TestHeartbeatCustomCertPath:
    """Tests for custom --cert-path."""

    def test_heartbeat_custom_cert_path(self, tmp_path):
        """--cert-path overrides the default cert path."""
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "test-exec", validity_days=30)

        custom_cert_path = tmp_path / "custom.pem"
        custom_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        custom_key_path = tmp_path / "custom.key"
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        custom_key_path.write_bytes(key_pem)

        args = MagicMock()
        args.cert_path = str(custom_cert_path)
        args.key_path = str(custom_key_path)
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client) as MockClient:
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0
        call_kwargs = MockClient.call_args.kwargs if MockClient.call_args.kwargs else MockClient.call_args[1]
        assert call_kwargs["cert"][0] == str(custom_cert_path)


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------


class TestHeartbeatOutput:
    """Tests for output format verification."""

    def test_heartbeat_output_includes_fingerprint(self, tmp_path, capsys):
        """Fingerprint appears in stdout output."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Fingerprint:" in captured.out
        # Fingerprint should be a 64-char hex string
        for line in captured.out.split("\n"):
            if line.strip().startswith("Fingerprint:"):
                fp = line.split(":", 1)[1].strip()
                assert len(fp) == 64
                int(fp, 16)  # Should be valid hex

    def test_heartbeat_output_revoked_format(self, tmp_path, capsys):
        """Revoked field shows 'YES' (not 'No') when revoked."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": True, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Revoked:         YES" in captured.out
        assert "Revoked:         No" not in captured.out

    def test_heartbeat_output_executor_id(self, tmp_path, capsys):
        """Executor ID from cert CN appears in output."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path, "my-executor")

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_client(
            response_data={"revoked": False, "new_cert_required": False},
        )

        with patch("core.cli.commands.httpx2.Client", return_value=mock_client):
            from core.cli.commands import executor_heartbeat
            result = executor_heartbeat(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Executor ID:     my-executor" in captured.out
        assert "Heartbeat Response" in captured.out
