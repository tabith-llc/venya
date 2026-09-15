"""Tests for CLI admin create-user and enhanced admin list commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_create_user, cmd_admin_list


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
# cmd_admin_create_user tests
# ---------------------------------------------------------------------------


class TestAdminCreateUser:
    """Tests for venya admin create-user command."""

    def test_create_user_success(self):
        """Basic create user succeeds and prints user_id, status, token."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_abc123",
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = None
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[1]["json"] == {"username": "jsmith"}
        client.close()
        config_file.unlink()

    def test_create_user_with_display_name(self):
        """Create user with display_name includes it in payload."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_xyz",
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = "John Smith"
        args.roles = None
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[1]["json"]["display_name"] == "John Smith"
        client.close()
        config_file.unlink()

    def test_create_user_with_roles(self):
        """Create user with comma-separated roles parses them correctly."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_roles",
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = "admin,operator"
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[1]["json"]["roles"] == ["admin", "operator"]
        client.close()
        config_file.unlink()

    def test_create_user_json_output(self):
        """Create user with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=201,
            json_data={
                "user_id": "jsmith",
                "status": "pending_enrollment",
                "enrollment_token": "tok_json",
                "expires_in_seconds": 900,
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = None
        args.json = True

        result = cmd_admin_create_user(client, args)
        assert result == 0

        # Capture stdout
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            cmd_admin_create_user(client, args)
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["user_id"] == "jsmith"
        assert parsed["status"] == "pending_enrollment"
        client.close()
        config_file.unlink()

    def test_create_user_400_duplicate_username(self):
        """Create user with existing username returns 400 error."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "User 'jsmith' already exists"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = None
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_create_user_400_invalid_role(self):
        """Create user with invalid role returns 400 error."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Role 'nonexistent' not found"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = "nonexistent"
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_create_user_network_error(self):
        """Create user with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")

        client._http = mock_http

        args = MagicMock()
        args.username = "jsmith"
        args.display_name = None
        args.roles = None
        args.json = False

        result = cmd_admin_create_user(client, args)
        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_admin_list tests
# ---------------------------------------------------------------------------


class TestAdminList:
    """Tests for venya admin list command."""

    def test_list_users_success(self):
        """List users shows table with all columns."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "users": [
                    {
                        "user_id": "admin",
                        "display_name": "Admin User",
                        "status": "active",
                        "auth_mode": "security-key",
                        "enrolled_at": "2025-01-01T00:00:00",
                        "session_timeout": 900,
                    },
                    {
                        "user_id": "jsmith",
                        "display_name": None,
                        "status": "pending_enrollment",
                        "auth_mode": "platform",
                        "enrolled_at": None,
                        "session_timeout": 1800,
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = False

        result = cmd_admin_list(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "/api/v1/admin/users"
        client.close()
        config_file.unlink()

    def test_list_users_json_output(self):
        """List users with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "users": [
                    {
                        "user_id": "admin",
                        "display_name": "Admin User",
                        "status": "active",
                        "auth_mode": "security-key",
                        "enrolled_at": "2025-01-01T00:00:00",
                        "session_timeout": 900,
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_admin_list(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert "users" in parsed
        assert len(parsed["users"]) == 1
        assert parsed["users"][0]["display_name"] == "Admin User"
        assert parsed["users"][0]["status"] == "active"
        client.close()
        config_file.unlink()

    def test_list_users_empty(self):
        """List users with no users prints message."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"users": []},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = False

        result = cmd_admin_list(client, args)
        assert result == 0
        client.close()
        config_file.unlink()

    def test_list_users_network_error(self):
        """List users with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.json = False

        result = cmd_admin_list(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_list_users_display_name_null_shows_dash(self):
        """Null display_name shows '-' in table output."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "users": [
                    {
                        "user_id": "jsmith",
                        "display_name": None,
                        "status": "pending_enrollment",
                        "auth_mode": "security-key",
                        "enrolled_at": None,
                        "session_timeout": 900,
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = False

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_admin_list(client, args)

        assert result == 0
        output = f.getvalue()
        assert "-" in output
        client.close()
        config_file.unlink()
