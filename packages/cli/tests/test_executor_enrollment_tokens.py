# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor enrollment token infrastructure.

Tests cover:
- CLI parsing for admin executor-enroll
- APIClient.register_executor() success/error paths
- Token format validation
"""

import ssl
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from venya_cli.api_client import APIClient, APIClientError

# #536: the registration dial now anchors OR refuses, so every cell in this file
# needs a Venya trust anchor present to let the POST go out at all. The anchor
# comes from ``conftest.venya_tls_anchor_536`` (``monkeypatch.setenv``, scoped per
# cell, OVERWRITING any ambient ``SSL_CERT_FILE``) — never from this machine's
# shell or its ``/tmp``. Fixture-only: no assertion here changed to get it; the
# two #536 re-pins below change the SHAPE they assert and keep their own subject.
pytestmark = pytest.mark.usefixtures("venya_tls_anchor_536")


class TestAPIClientRegisterExecutor:
    """Tests for APIClient.register_executor() with throwaway clients."""

    def _make_client(self):
        """Create an APIClient with a temp config file."""
        config_file = Path(tempfile.mktemp(suffix=".json"))
        config_file.write_text('{"server_url": "https://core.example.com"}')
        return APIClient(config_file=config_file), config_file

    def test_register_success(self, venya_tls_anchor_536):
        """Successful registration returns cert data via throwaway client.

        #536 re-pin: this cell asserted ``verify=True``, which is httpx asking
        OpenSSL for the HOST system store — the behavior the owner ruled away
        (pinned-CA-only, no exceptions). It now pins the anchored contract in BOTH
        directions, so a reintroduced host-store path turns it red: the transport
        gets an ``ssl.SSLContext`` carrying ONLY the Venya anchor, and the same
        call on a host with no anchor at all refuses before any client exists.
        """
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

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                result = client.register_executor("test-1", "CSR_PEM")
                assert result["executor_id"] == "test-1"
                MockClient.assert_called_once()
                verify = MockClient.call_args.kwargs["verify"]
                assert isinstance(verify, ssl.SSLContext), "a bare bool verify= is the host store (#536)"
                assert verify.verify_mode == ssl.CERT_REQUIRED
                assert verify.check_hostname is True
                # ONLY the Venya anchor is trusted on this POST — a host-store
                # load would put the OS bundle's names in this set.
                assert venya_tls_anchor_536.cns(verify) == {venya_tls_anchor_536.cn}
                assert MockClient.call_args.kwargs["timeout"] == 30.0
            finally:
                client.close()
        config_file.unlink()

        refused = venya_tls_anchor_536.without_anchor()
        with patch("venya_cli.api_client.httpx2.Client") as NoClient:
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                refused.register_executor("test-1", "CSR_PEM")
            NoClient.assert_not_called()

    def test_register_with_enrollment_token(self):
        """Registration includes enrollment_token in payload."""
        client, config_file = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-1",
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        mock_response.content = b"{}"
        mock_response.raise_for_status.return_value = None

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
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
            "executor_id": "test-1",
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        mock_response.content = b"{}"
        mock_response.raise_for_status.return_value = None

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            try:
                client.register_executor("test-1", "CSR_PEM")
                call_args = MockClient.return_value.post.call_args
                assert "enrollment_token" not in call_args[1]["json"]
            finally:
                client.close()
        config_file.unlink()

    def test_register_network_error_re_raises(self, venya_tls_anchor_536):
        """On network error, re-raises as APIClientError without fallback.

        #536 re-pin: the ``verify=True`` assert here pinned the host-store dial.
        The wrap-the-error subject is unchanged; the trust shape is now the
        anchored context, plus the paired refusal on an anchor-less host.
        """
        client, config_file = self._make_client()

        network_error = httpx2.ConnectError("Connection refused")

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = network_error

            try:
                with pytest.raises(APIClientError, match="Connection failed"):
                    client.register_executor("test-1", "CSR_PEM")
                MockClient.assert_called_once()
                verify = MockClient.call_args.kwargs["verify"]
                assert isinstance(verify, ssl.SSLContext), "a bare bool verify= is the host store (#536)"
                assert venya_tls_anchor_536.cns(verify) == {venya_tls_anchor_536.cn}
            finally:
                client.close()
        config_file.unlink()

        refused = venya_tls_anchor_536.without_anchor()
        with patch("venya_cli.api_client.httpx2.Client") as NoClient:
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                refused.register_executor("test-1", "CSR_PEM")
            NoClient.assert_not_called()

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

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
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

        with patch("venya_cli.api_client.httpx2.Client") as MockClient:
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
        from venya_cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["admin", "executor-enroll", "jump-1"])
        assert args.admin_command == "executor-enroll"
        assert args.executor_id == "jump-1"

    def test_exec_register_with_enrollment_token(self):
        """exec register accepts --enrollment-token argument."""
        from venya_cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(
            [
                "exec",
                "register",
                "--enrollment-token",
                "enrl_exec_abc123",
                "--executor-id",
                "my-exec",
            ]
        )
        assert args.exec_command == "register"
        assert args.enrollment_token == "enrl_exec_abc123"
        assert args.executor_id == "my-exec"

    def test_exec_register_without_enrollment_token(self):
        """exec register works without --enrollment-token."""
        from venya_cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["exec", "register"])
        assert args.exec_command == "register"
        assert args.enrollment_token is None
