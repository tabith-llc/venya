# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for CLI enroll single-command and login commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
from venya_cli.api_client import APIClient
from venya_cli.fido2_client import Fido2ClientError


def _make_mock_response(status_code=200, json_data=None):
    """Create a mock httpx.Response."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode()
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


def _make_client(mock_http=None):
    """Create an APIClient with a mocked HTTP client."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)

    client = APIClient(config_file=config_file)
    if mock_http:
        client._http = mock_http
    return client, config_file


# ---------------------------------------------------------------------------
# cmd_enroll single-command tests
# ---------------------------------------------------------------------------


class TestEnrollSingleCommand:
    """Tests for venya enroll <token> single-command."""

    def test_enroll_success(self):
        """Enroll drives start→FIDO2→complete, stores session_token."""
        client, config_file = _make_client()
        mock_http = MagicMock()

        start_resp = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "enroll_chal_123",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        start_resp.raise_for_status.return_value = None

        complete_resp = _make_mock_response(
            status_code=200,
            json_data={
                "status": "ok",
                "user_id": "jsmith",
                "session_token": "sess-token-xyz",
            },
        )
        complete_resp.raise_for_status.return_value = None

        mock_http.request.side_effect = [start_resp, complete_resp]
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_abc"
        args.label = "YubiKey"
        args.json = False
        client.config.server_url = "https://venya-core-1"

        with patch("venya_cli.fido2_client.Fido2Auth") as mock_fido2_cls:
            mock_fido2 = MagicMock()
            mock_fido2_cls.return_value = mock_fido2
            mock_fido2._build_registration_options.return_value = "REQ_OPTIONS"
            mock_fido2._get_credential.return_value = "CRED"
            mock_fido2._format_credential_response.return_value = {
                "id": "dGVzdA==",
                "rawId": "dGVzdA==",
                "response": {"clientDataJSON": "Y2xpZW50IGRhdGE=", "attestationObject": "YXR0ZXN0YXRpb24="},
                "type": "public-key",
            }

            result = __import__("venya_cli.commands", fromlist=["cmd_enroll"]).cmd_enroll(client, args)

        assert result == 0
        assert client.config.access_token == "sess-token-xyz"

        # Verify two POSTs hit correct endpoints
        calls = mock_http.request.call_args_list
        assert calls[0][0][0] == "POST"
        assert "/api/v1/enroll/browser/start" in calls[0][0][1]
        assert calls[1][0][0] == "POST"
        assert "/api/v1/enroll/browser/complete" in calls[1][0][1]

        client.close()
        config_file.unlink()

    def test_enroll_no_session_token_returns_1(self):
        """Server returns no session_token → exit 1, token not stored."""
        client, config_file = _make_client()
        mock_http = MagicMock()

        start_resp = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "enroll_chal_123",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        start_resp.raise_for_status.return_value = None

        complete_resp = _make_mock_response(
            status_code=200,
            json_data={"status": "ok", "user_id": "jsmith"},
        )
        complete_resp.raise_for_status.return_value = None

        mock_http.request.side_effect = [start_resp, complete_resp]
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll"
        args.label = None
        args.json = False
        client.config.server_url = "https://venya-core-1"

        with patch("venya_cli.fido2_client.Fido2Auth") as mock_fido2_cls:
            mock_fido2 = MagicMock()
            mock_fido2_cls.return_value = mock_fido2
            mock_fido2._build_registration_options.return_value = "REQ_OPTIONS"
            mock_fido2._get_credential.return_value = "CRED"
            mock_fido2._format_credential_response.return_value = {"id": "dGVzdA==", "response": {}}

            result = __import__("venya_cli.commands", fromlist=["cmd_enroll"]).cmd_enroll(client, args)

        assert result == 1
        assert client.config.access_token is None

        client.close()
        config_file.unlink()

    def test_enroll_fido2_error_returns_1(self):
        """FIDO2 key error → exit 1."""
        client, config_file = _make_client()
        args = MagicMock()
        args.token = "tok_enroll"
        args.label = None
        args.json = False
        client.config.server_url = "https://venya-core-1"

        with patch("venya_cli.fido2_client.Fido2Auth") as mock_fido2_cls:
            mock_fido2 = MagicMock()
            mock_fido2_cls.return_value = mock_fido2
            mock_fido2._build_registration_options.side_effect = Fido2ClientError("key error")

            result = __import__("venya_cli.commands", fromlist=["cmd_enroll"]).cmd_enroll(client, args)

        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_network_error_returns_1(self):
        """Network error on start → exit 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll"
        args.label = None
        args.json = False

        result = __import__("venya_cli.commands", fromlist=["cmd_enroll"]).cmd_enroll(client, args)

        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_login tests
# ---------------------------------------------------------------------------


class TestLoginSingleCommand:
    """Tests for venya login <user_id> single-command."""

    def test_login_success(self):
        """Login calls client.authenticate, token stored, returns 0."""
        from venya_cli.fido2_client import Fido2Auth

        client, config_file = _make_client()
        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False
        client.config.server_url = "https://venya-core-1"

        with patch.object(Fido2Auth, "authenticate") as mock_auth:
            mock_auth.return_value = {
                "user_id": "jsmith",
                "session_token": "sess-token-abc",
                "credential_id": "cred-123",
            }

            result = __import__("venya_cli.commands", fromlist=["cmd_login"]).cmd_login(client, args)

        assert result == 0
        assert client.config.access_token == "sess-token-abc"
        mock_auth.assert_called_once_with(user_id="jsmith", timeout=60.0)

        client.close()
        config_file.unlink()

    def test_login_auth_failure_returns_1(self):
        """FIDO2 auth failure → exit 1."""
        from venya_cli.api_client import APIClientAuthenticationError
        from venya_cli.fido2_client import Fido2Auth

        client, config_file = _make_client()
        args = MagicMock()
        args.user_id = "baduser"
        args.json = False

        with patch.object(Fido2Auth, "authenticate") as mock_auth:
            mock_auth.side_effect = APIClientAuthenticationError("key not found")

            result = __import__("venya_cli.commands", fromlist=["cmd_login"]).cmd_login(client, args)

        assert result == 1

        client.close()
        config_file.unlink()
