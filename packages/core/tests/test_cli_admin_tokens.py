"""Tests for CLI admin list-tokens, issue-token, and revoke-token commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest

from core.cli.api_client import APIClient, APIClientError
from core.cli.commands import cmd_admin_list_tokens, cmd_admin_issue_token, cmd_admin_revoke_token


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
# cmd_admin_list_tokens tests
# ---------------------------------------------------------------------------


class TestAdminListTokens:
    """Tests for venya admin list-tokens command."""

    def test_list_tokens_success(self):
        """List tokens shows table with all columns."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "tokens": [
                    {
                        "id": "tok_001",
                        "state": "active",
                        "created_at": "2025-01-01T00:00:00",
                        "expires_at": "2025-01-01T01:00:00",
                        "used_at": None,
                    },
                    {
                        "id": "tok_002",
                        "state": "used",
                        "created_at": "2025-01-02T00:00:00",
                        "expires_at": "2025-01-02T01:00:00",
                        "used_at": "2025-01-02T00:30:00",
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_list_tokens(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "/api/v1/admin/users/jsmith/enrollment-tokens"
        client.close()
        config_file.unlink()

    def test_list_tokens_json_output(self):
        """List tokens with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "tokens": [
                    {
                        "id": "tok_001",
                        "state": "active",
                        "created_at": "2025-01-01T00:00:00",
                        "expires_at": "2025-01-01T01:00:00",
                        "used_at": None,
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_admin_list_tokens(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert "tokens" in parsed
        assert len(parsed["tokens"]) == 1
        assert parsed["tokens"][0]["id"] == "tok_001"
        client.close()
        config_file.unlink()

    def test_list_tokens_empty(self):
        """List tokens with no tokens prints message."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"tokens": []},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_list_tokens(client, args)
        assert result == 0
        client.close()
        config_file.unlink()

    def test_list_tokens_404_user_not_found(self):
        """List tokens for non-existent user returns 404."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=404,
            json_data={"detail": "User not found"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "not found", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "nonexistent"
        args.json = False

        result = cmd_admin_list_tokens(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_list_tokens_network_error(self):
        """List tokens with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_list_tokens(client, args)
        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_admin_issue_token tests
# ---------------------------------------------------------------------------


class TestAdminIssueToken:
    """Tests for venya admin issue-token command."""

    def test_issue_token_success(self):
        """Issue token succeeds and prints token, revoked count, expiry."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "enrollment_token": "tok_new_abc123",
                "previous_tokens_revoked": 2,
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_issue_token(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/v1/admin/users/jsmith/enrollment-tokens"
        client.close()
        config_file.unlink()

    def test_issue_token_json_output(self):
        """Issue token with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "enrollment_token": "tok_new_xyz",
                "previous_tokens_revoked": 1,
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_admin_issue_token(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["enrollment_token"] == "tok_new_xyz"
        assert parsed["previous_tokens_revoked"] == 1
        client.close()
        config_file.unlink()

    def test_issue_token_404_user_not_found(self):
        """Issue token for non-existent user returns 404."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=404,
            json_data={"detail": "User not found"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "not found", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "nonexistent"
        args.json = False

        result = cmd_admin_issue_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_issue_token_400_token_already_revoked(self):
        """Issue token with 400 error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Cannot issue token for this user"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_issue_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_issue_token_network_error(self):
        """Issue token with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_issue_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_admin_revoke_token tests
# ---------------------------------------------------------------------------


class TestAdminRevokeToken:
    """Tests for venya admin revoke-token command."""

    def test_revoke_token_success(self):
        """Revoke token succeeds and prints confirmation."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"deleted": True},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "tok_001"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "DELETE"
        assert call_args[0][1] == "/api/v1/admin/enrollment-tokens/tok_001"
        client.close()
        config_file.unlink()

    def test_revoke_token_404_not_found(self):
        """Revoke non-existent token returns 404."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=404,
            json_data={"detail": "Token not found"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "not found", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "tok_nonexistent"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_revoke_token_400_already_revoked(self):
        """Revoke already-revoked token returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Token is already revoked"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "tok_old"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_revoke_token_network_error(self):
        """Revoke token with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.token_id = "tok_001"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1
        client.close()
        config_file.unlink()
