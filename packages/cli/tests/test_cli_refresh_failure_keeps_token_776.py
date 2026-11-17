"""#776 — a failed transparent refresh must not clear the stored token, and must name the way back.

Cells per leg 1556 spec §1.2:
  (a) a refused refresh leaves config.json byte-identical (RED before the fix: the clear
      went through the saving setter and rewrote the file within the same second);
  (b) a SUCCESSFUL refresh still rotates the token, in memory and on disk — the fix
      narrows a clear, it does not disable a refresh;
  (c) the error text names `venya login` and is asserted, not eyeballed.
Plus the issue's own arms: unit halves of AC2/AC3 (config show) and AC5 (a transient
5xx/timeout also keeps the token), and the transport-level check that the remedy
reaches the caller instead of being discarded on the bare 401.
"""

import json
from unittest.mock import MagicMock, patch

import httpx2
from venya_cli.api_client import APIClient, APIClientAuthenticationError, APIClientError
from venya_cli.commands import cmd_config_show


def _client_with_token(tmp_path, token="stored-token"):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://core.test", "access_token": token}))
    return APIClient(config_file=config_file)


def _on_disk_token(client):
    return json.loads(client.config.config_file.read_text()).get("access_token")


def test_failed_refresh_never_clears_the_stored_token(tmp_path):
    """Cell (a) + issue AC5: a refused refresh and a transient one both leave the token on disk."""
    refusals = [
        APIClientAuthenticationError("Invalid or expired token"),  # server refuses the refresh
        APIClientError("HTTP 503: Service Unavailable"),  # transient — body §4.5: not proof of death
    ]
    for refusal in refusals:
        client = _client_with_token(tmp_path)
        before = client.config.config_file.read_bytes()
        with patch.object(client, "_post_raw", side_effect=refusal):
            try:
                client.refresh_token()
                raise AssertionError("refresh_token must still raise on failure")
            except APIClientAuthenticationError:
                pass
        # No config write at all — the file is byte-identical, not merely equivalent.
        assert client.config.config_file.read_bytes() == before
        assert _on_disk_token(client) == "stored-token"
        client.close()


def test_successful_refresh_still_rotates_the_token(tmp_path):
    """Cell (b) paired negative: rotation and persistence are unchanged by the fix."""
    client = _client_with_token(tmp_path)
    with patch.object(client, "_post_raw", return_value={"access_token": "rotated-token"}):
        assert client.refresh_token() == "rotated-token"
    assert client.config.access_token == "rotated-token"
    assert _on_disk_token(client) == "rotated-token"
    client.close()


def test_refresh_failure_text_names_login_verb(tmp_path):
    """Cell (c): the raised sentence names the mint verb and states the token state."""
    client = _client_with_token(tmp_path)
    with patch.object(client, "_post_raw", side_effect=APIClientAuthenticationError("Invalid or expired token")):
        try:
            client.refresh_token()
            raise AssertionError("refresh_token must raise")
        except APIClientAuthenticationError as e:
            assert "venya login" in str(e)
            assert "left in place" in str(e)
    client.close()


def test_request_401_with_refused_refresh_reaches_caller_with_remedy(tmp_path):
    """Issue §4.1: the remedy survives to the print — the 401 path used to discard it (`pass`)."""
    client = _client_with_token(tmp_path)
    mock_http = MagicMock()
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.json.return_value = {"detail": "Invalid or expired token"}
    mock_http.request.side_effect = httpx2.HTTPStatusError("401", request=MagicMock(), response=resp_401)
    client._http = mock_http
    with patch.object(client, "_post_raw", side_effect=APIClientAuthenticationError("Invalid or expired token")):
        try:
            client._request("GET", "/api/v1/secrets")
            raise AssertionError("_request must raise on 401 after a refused refresh")
        except APIClientAuthenticationError as e:
            msg = str(e)
    assert "HTTP 401" in msg  # the original status still travels (R-2701)
    assert "venya login" in msg  # and the way back travels with it
    assert _on_disk_token(client) == "stored-token"  # and the credential was not consumed
    client.close()


def test_config_show_drops_the_wrong_verb(tmp_path, capsys):
    """Issue AC2 (tree-provable half): the [set] line no longer names 'venya run'."""
    client = _client_with_token(tmp_path)
    assert cmd_config_show(client) == 0
    out = capsys.readouterr().out
    assert "venya run" not in out
    assert "refreshed automatically" in out
    client.close()


def test_config_show_not_set_names_the_mint_verb(tmp_path, capsys):
    """Issue AC3: a machine that has never logged in is told the verb that mints a token."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://core.test"}))
    client = APIClient(config_file=config_file)
    assert cmd_config_show(client) == 0
    out = capsys.readouterr().out
    assert "Access Token: [not set]" in out
    assert "venya login" in out
    client.close()
