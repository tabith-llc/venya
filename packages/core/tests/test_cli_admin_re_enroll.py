"""Tests for CLI admin re-enroll command."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest

from core.cli.api_client import APIClient, APIClientError
from core.cli.commands import cmd_admin_re_enroll


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
# cmd_admin_re_enroll tests
# ---------------------------------------------------------------------------


class TestAdminReEnroll:
    """Tests for venya admin re-enroll command."""

    def test_re_enroll_success(self):
        """Re-enroll succeeds and prints user_id, status, token, credentials_deactivated, tokens_revoked."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_reenroll_xyz",
                "credentials_deactivated": True,
                "tokens_revoked": 2,
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_re_enroll(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/v1/admin/users/jsmith/re-enroll"
        client.close()
        config_file.unlink()

    def test_re_enroll_json_output(self):
        """Re-enroll with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_reenroll_json",
                "credentials_deactivated": True,
                "tokens_revoked": 1,
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
            result = cmd_admin_re_enroll(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["user_id"] == "jsmith"
        assert parsed["status"] == "pending_enrollment"
        assert parsed["credentials_deactivated"] is True
        assert parsed["tokens_revoked"] == 1
        client.close()
        config_file.unlink()

    def test_re_enroll_404_user_not_found(self):
        """Re-enroll for non-existent user returns 404."""
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

        result = cmd_admin_re_enroll(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_re_enroll_400_enrollment_error(self):
        """Re-enroll with 400 error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Cannot re-enroll user in current state"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_re_enroll(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_re_enroll_network_error(self):
        """Re-enroll with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.user_id = "jsmith"
        args.json = False

        result = cmd_admin_re_enroll(client, args)
        assert result == 1
        client.close()
        config_file.unlink()
