"""Leg 814 / #729 — the CLI prints the HTTP status (R-2701 second half).

The role writers now live under /api/v1/admin/, so a version-skewed CLI that
still posts the old literals gets 405/404 (proven server-side in
test_roles_writer_admin_prefix_729.py). These cells prove the OTHER half: the
operator SEES the number. Proof layers, named per the leg-813 fixture law:

- TestRequestLayer  — ``APIClient._request`` rendering (the one site the role
  verbs traverse: get/post/put/delete/patch all call _request).
- TestOperatorText  — the ``role delete`` command's stderr line, i.e. what the
  human actually reads.

No identity is involved in these cells; no fixture supplies one.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.commands import cmd_role_delete


def _client_with_config():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)
    return APIClient(config_file=config_file), config_file


def _failing_response(status_code, detail):
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    mock.json.return_value = {"detail": detail}
    mock.content = json.dumps({"detail": detail}).encode()
    return mock


class TestRequestLayer:
    """Layer: APIClient._request error rendering."""

    def test_stale_writer_405_number_visible(self):
        client, config_file = _client_with_config()
        try:
            mock_http = MagicMock()
            resp = _failing_response(405, "Method Not Allowed")
            resp.raise_for_status.side_effect = httpx2.HTTPStatusError("405", request=MagicMock(), response=resp)
            mock_http.request.return_value = resp
            client._http = mock_http  # sanctioned test seam (test_cli.py, *_rf8* files)
            with pytest.raises(APIClientError) as excinfo:
                client.post("/api/v1/roles", json={"name": "ops"})
            msg = str(excinfo.value)
            assert "HTTP 405" in msg, msg
            assert "Method Not Allowed" in msg, msg
        finally:
            client.close()
            config_file.unlink()

    def test_stale_member_remove_404_number_visible(self):
        client, config_file = _client_with_config()
        try:
            mock_http = MagicMock()
            resp = _failing_response(404, "Not Found")
            resp.raise_for_status.side_effect = httpx2.HTTPStatusError("404", request=MagicMock(), response=resp)
            mock_http.request.return_value = resp
            client._http = mock_http
            with pytest.raises(APIClientError) as excinfo:
                client.delete("/api/v1/roles/5/members/carol")
            msg = str(excinfo.value)
            assert "HTTP 404" in msg, msg
        finally:
            client.close()
            config_file.unlink()


class TestOperatorText:
    """Layer: the operator-visible stderr line of a role verb."""

    def test_role_delete_stderr_carries_the_status_number(self, capsys):
        client = MagicMock()
        # int-shaped role refs short-circuit _resolve_role_id (commands.py),
        # so the only dial this cell makes is the writer call itself.
        client.delete.side_effect = APIClientError("HTTP 405: Method Not Allowed")
        args = MagicMock()
        args.role_id = "7"
        rc = cmd_role_delete(client, args)
        err = capsys.readouterr().err
        assert rc == 1
        assert "Failed to delete role: HTTP 405" in err, err
