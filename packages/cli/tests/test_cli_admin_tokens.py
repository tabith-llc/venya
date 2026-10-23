# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for CLI admin list-tokens, issue-token, and revoke-token commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_issue_token, cmd_admin_list_tokens, cmd_admin_revoke_token


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
    """Tests for venya admin revoke-token command (#666).

    Every response body here is the shape the route ACTUALLY returns, captured against
    the shipped bytes: ``AdminTokenRevokeResponse`` is ``{"token_id": int, "revoked": bool}``
    (`packages/server/src/server/routes/admin.py`, `admin_revoke_token`), and a id the route
    did not touch answers **200 with ``revoked: false``**, not 404 and not 400. The two older
    cells in this class mocked ``{"deleted": True}`` and a 400-on-already-revoked, and neither
    shape exists in the server — which is why the false success shipped green: a test that
    pins a fiction can never catch the fiction.
    """

    def test_revoke_token_success(self, capsys):
        """Confirmed revocation exits 0 and names the user plane."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"revoked": True, "token_id": 1},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "1"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "DELETE"
        assert call_args[0][1] == "/api/v1/admin/enrollment-tokens/1"
        # The confirmation names WHICH plane it acted on: user and executor enrollment
        # tokens are separate tables sharing one integer id space (#666 ACT 1, case f).
        out = capsys.readouterr().out
        assert "User enrollment token '1' revoked." in out
        client.close()
        config_file.unlink()

    def test_revoke_token_200_not_revoked_is_a_refusal(self, capsys):
        """#666 the bug: 200 + revoked:false is a NO-OP, so the CLI must not report success.

        This is the shape the server returns for an id it did not touch. Transport success
        is not semantic success — the body decides.
        """
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"revoked": False, "token_id": 999999},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "999999"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Nothing was revoked" in captured.err
        assert "999999" in captured.err
        assert "revoked." not in captured.out
        client.close()
        config_file.unlink()

    def test_revoke_token_executor_plane_id_is_a_refusal(self, capsys):
        """An executor-class id answers revoked:false on this user-scoped route — refused, and
        the repair text says the true thing (no executor revoke verb exists; TTL expires it)."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"revoked": False, "token_id": 1},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "1"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Nothing was revoked" in captured.err
        assert "Executor enrollment tokens have no revoke command" in captured.err
        assert "revoked." not in captured.out
        client.close()
        config_file.unlink()

    def test_revoke_token_200_already_revoked_is_a_refusal(self, capsys):
        """Already-revoked (the captured real shape: 200 + revoked:false) exits 1.

        Corrected from a cell that mocked 400 "Token is already revoked" — the shipped route
        never emits that (#666 ACT 1 case d).
        """
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"revoked": False, "token_id": 2},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "2"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1
        assert "Nothing was revoked" in capsys.readouterr().err
        client.close()
        config_file.unlink()

    def test_revoke_token_200_without_the_flag_is_a_refusal(self, capsys):
        """A 200 whose body carries no confirmation at all (empty or shape-drifted) is a failure.

        The guard is on the VALUE being exactly True, so an absent key cannot read as success.
        """
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(status_code=200, json_data={})
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "7"
        args.json = False

        result = cmd_admin_revoke_token(client, args)
        assert result == 1
        assert "Nothing was revoked" in capsys.readouterr().err
        client.close()
        config_file.unlink()

    def test_revoke_token_404_not_found(self):
        """Non-2xx is a transport failure and exits 1.

        NOTE: the shipped route does not answer 404 for an absent id (it answers 200 +
        revoked:false — see the cell above). This cell holds the CLI's error path for a
        non-2xx answer from ANY front of house (proxy, authz rejection, future change),
        which is a real thing a CLI must handle; it is no longer a claim about what
        admin_revoke_token returns for a miss.
        """
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

    def test_revoke_token_422_non_numeric_id(self, capsys):
        """A non-numeric token id is refused by FastAPI (422) and exits 1 — measured face,
        the only pre-existing path that already reported honestly (#666 ACT 1 case e)."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=422,
            json_data={"detail": [{"type": "int_parsing", "loc": ["path", "token_id"]}]},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "unprocessable", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token_id = "not-an-int"
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
