"""Tests for executor enrollment token infrastructure.

Tests cover:
- CLI parsing for admin executor-enroll
- _is_tls_error() helper
- APIClient.register_executor() with TLS fallback
- Token format validation
"""

import ssl
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from vault.cli.api_client import APIClient, APIClientError, _is_tls_error
from unittest.mock import call


class TestIsTLSError:
    """Tests for the _is_tls_error() helper."""

    def test_ssl_cert_verification_error(self):
        """ssl.SSLCertVerificationError is detected as TLS error."""
        exc = httpx2.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
        exc.__cause__ = ssl.SSLCertVerificationError("cert failed")
        assert _is_tls_error(exc) is True

    def test_ssl_error(self):
        """ssl.SSLError is detected as TLS error."""
        exc = httpx2.ConnectError("SSL handshake failed")
        exc.__cause__ = ssl.SSLError("handshake error")
        assert _is_tls_error(exc) is True

    def test_connection_refused(self):
        """Connection refused is NOT a TLS error."""
        exc = httpx2.ConnectError("Connection refused")
        assert _is_tls_error(exc) is False

    def test_timeout(self):
        """ConnectTimeout is NOT a TLS error."""
        exc = httpx2.ConnectTimeout("Connection timed out")
        assert _is_tls_error(exc) is False

    def test_deep_cause_chain(self):
        """TLS error deep in cause chain is detected."""
        inner = ssl.SSLCertVerificationError("deep cert error")
        middle = RuntimeError("middle wrapper")
        middle.__cause__ = inner
        outer = httpx2.ConnectError("outer")
        outer.__cause__ = middle
        assert _is_tls_error(outer) is True

    def test_no_cause(self):
        """Exception with no cause chain returns False."""
        exc = RuntimeError("plain error")
        assert _is_tls_error(exc) is False


class TestAPIClientRegisterExecutor:
    """Tests for APIClient.register_executor() with throwaway clients."""

    def _make_client(self):
        """Create an APIClient with a temp config file."""
        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text('{"server_url": "https://vault.example.com"}')
        return APIClient(config_file=config_file), config_file

    def test_register_success(self):
        """Successful registration returns cert data via throwaway client."""
        client, config_file = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-1",
            "cert_pem": "-----BEGIN CERTIFICATE-----",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----",
            "serial_number": "01:23",
            "not_after": "2026-09-01T00:00:00+00:00",
        }
        mock_response.content = b'{"test": true}'
        mock_response.raise_for_status.return_value = None

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = client.register_executor("test-1", "CSR_PEM")
                assert result["executor_id"] == "test-1"
                MockClient.assert_called_once_with(verify=True, timeout=30.0)
            finally:
                client.close()
        config_file.unlink()

    def test_register_with_enrollment_token(self):
        """Registration includes enrollment_token in payload."""
        client, config_file = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-1", "cert_pem": "CERT",
            "ca_cert_pem": "CA", "serial_number": "01",
            "not_after": "2026-09-01",
        }
        mock_response.content = b'{}'
        mock_response.raise_for_status.return_value = None

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                client.register_executor("test-1", "CSR_PEM", enrollment_token="enrl_exec_abc123")
                call_args = MockClient.return_value.post.call_args
                assert call_args[1]["json"]["enrollment_token"] == "enrl_exec_abc123"
            finally:
                client.close()
        config_file.unlink()

    def test_register_without_enrollment_token_excludes_it(self):
        """Registration without token does not include it in payload."""
        client, config_file = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-1", "cert_pem": "CERT",
            "ca_cert_pem": "CA", "serial_number": "01",
            "not_after": "2026-09-01",
        }
        mock_response.content = b'{}'
        mock_response.raise_for_status.return_value = None

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                client.register_executor("test-1", "CSR_PEM")
                call_args = MockClient.return_value.post.call_args
                assert "enrollment_token" not in call_args[1]["json"]
            finally:
                client.close()
        config_file.unlink()

    def test_register_tls_fallback(self):
        """On TLS error, falls back to verify=False throwaway client."""
        client, config_file = self._make_client()

        tls_error = httpx2.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
        tls_error.__cause__ = ssl.SSLCertVerificationError("cert failed")

        fallback_response = MagicMock()
        fallback_response.status_code = 201
        fallback_response.json.return_value = {
            "executor_id": "test-1", "cert_pem": "CERT",
            "ca_cert_pem": "CA", "serial_number": "01",
            "not_after": "2026-09-01",
        }
        fallback_response.content = b'{}'
        fallback_response.raise_for_status.return_value = None

        call_count = [0]

        def post_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise tls_error
            return fallback_response

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = post_side_effect

            try:
                result = client.register_executor("test-1", "CSR_PEM")
                assert result["executor_id"] == "test-1"
                assert MockClient.call_count == 2
                assert MockClient.call_args_list[0] == call(verify=True, timeout=30.0)
                assert MockClient.call_args_list[1] == call(verify=False, timeout=30.0)
            finally:
                client.close()
        config_file.unlink()

    def test_register_network_error_re_raises(self):
        """On network error (not TLS), re-raises as APIClientError without fallback."""
        client, config_file = self._make_client()

        network_error = httpx2.ConnectError("Connection refused")

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = network_error

            try:
                with pytest.raises(APIClientError, match="Connection failed"):
                    client.register_executor("test-1", "CSR_PEM")
                MockClient.assert_called_once_with(verify=True, timeout=30.0)
            finally:
                client.close()
        config_file.unlink()

    def test_register_http_status_error(self):
        """HTTP error responses are wrapped in APIClientError."""
        client, config_file = self._make_client()

        error_response = MagicMock()
        error_response.status_code = 400
        error_response.json.return_value = {"detail": "Invalid CSR"}
        error_response.content = b'{"detail": "Invalid CSR"}'
        error_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "Bad Request", request=MagicMock(), response=error_response
        )

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = error_response

            try:
                with pytest.raises(APIClientError, match="Invalid CSR"):
                    client.register_executor("test-1", "CSR_PEM")
            finally:
                client.close()
        config_file.unlink()

    def test_register_empty_response(self):
        """Empty response returns empty dict."""
        client, config_file = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.content = b""
        mock_response.raise_for_status.return_value = None

        with patch("vault.cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = client.register_executor("test-1", "CSR_PEM")
                assert result == {}
            finally:
                client.close()
        config_file.unlink()


class TestCLIParsing:
    """Tests for CLI argument parsing."""

    def test_admin_executor_enroll(self):
        """admin executor-enroll subcommand is available."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["admin", "executor-enroll", "jump-1"])
        assert args.admin_command == "executor-enroll"
        assert args.executor_id == "jump-1"

    def test_exec_register_with_enrollment_token(self):
        """exec register accepts --enrollment-token argument."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "exec", "register",
            "--enrollment-token", "enrl_exec_abc123",
            "--executor-id", "my-exec",
        ])
        assert args.exec_command == "register"
        assert args.enrollment_token == "enrl_exec_abc123"
        assert args.executor_id == "my-exec"

    def test_exec_register_without_enrollment_token(self):
        """exec register works without --enrollment-token."""
        from vault.cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "register"])
        assert args.exec_command == "register"
        assert args.enrollment_token is None
