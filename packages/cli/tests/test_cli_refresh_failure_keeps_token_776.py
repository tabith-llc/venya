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


# ---------------------------------------------------------------------------
# Leg 1560 revision — #776 AC5 clause two and finding 2, driven through the
# REAL _post_raw wrapping (only the transport is mocked, exactly as a live 503):
# transient arms say RETRY PENDING with no ceremony word; the refused arm keeps
# the 1556 sentence; never-held stays a third state with a third text (#706).
# ---------------------------------------------------------------------------

# The shipped 1556 remedy clause, pinned by value so a swing cannot pass it by
# rewording — the refused arm must carry these bytes.
_CEREMONY_SENTENCE = (
    "the stored token was left in place; " "run `venya login <user-id>` to mint a new one (security-key ceremony)"
)


def _drive_status_through_post_raw(client, status_code, detail):
    """Transport answers `status_code` on the refresh POST; nothing else is mocked."""
    mock_http = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"detail": detail}
    resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
        f"HTTP {status_code}", request=MagicMock(), response=resp
    )
    mock_http.request.return_value = resp
    client._http = mock_http


def _refresh_message(client):
    try:
        client.refresh_token()
    except APIClientAuthenticationError as e:
        return str(e)
    raise AssertionError("refresh_token must raise")


def test_transient_503_says_pending_not_ceremony(tmp_path):
    """AC5 clause two, RED at the 1556 tip: a 503 must name pending and no ceremony."""
    client = _client_with_token(tmp_path)
    before = client.config.config_file.read_bytes()
    _drive_status_through_post_raw(client, 503, "core busy")
    msg = _refresh_message(client)
    assert "ceremony" not in msg
    assert "venya login" not in msg
    assert "pending" in msg and "retry" in msg
    assert "503" in msg  # the cause is named on the fact, not on the server's prose
    assert client.config.config_file.read_bytes() == before  # clause one still holds
    client.close()


def test_refresh_timeout_says_pending_at_the_same_seam(tmp_path):
    """Finding 2, RED at the 1556 tip (the class escaped unwrapped): timeout is transient."""
    client = _client_with_token(tmp_path)
    before = client.config.config_file.read_bytes()
    mock_http = MagicMock()
    mock_http.request.side_effect = httpx2.TimeoutException("read timed out")
    client._http = mock_http
    msg = _refresh_message(client)
    assert "ceremony" not in msg
    assert "pending" in msg
    assert "timed out" in msg  # the cause is named
    assert client.config.config_file.read_bytes() == before
    client.close()


def test_refused_401_keeps_the_1556_ceremony_sentence(tmp_path):
    """Paired negative against the swing: the refused arm carries the pinned bytes.

    Green at the 1556 tip by design — it pins what 1556 shipped; its bite is the
    byte-pinned clause plus the pending-word-absent discriminator below, which any
    over-swing to a unified pending sentence trips.
    """
    client = _client_with_token(tmp_path)
    before = client.config.config_file.read_bytes()
    _drive_status_through_post_raw(client, 401, "Invalid or expired token")
    msg = _refresh_message(client)
    assert _CEREMONY_SENTENCE in msg
    assert "pending" not in msg
    assert client.config.config_file.read_bytes() == before
    client.close()


def test_never_held_state_keeps_its_own_text(tmp_path):
    """#706 discipline: never-held is neither refused nor transient — a third text."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://core.test"}))
    client = APIClient(config_file=config_file)
    msg = _refresh_message(client)
    assert "No token to refresh" in msg
    assert "ceremony" not in msg
    assert "pending" not in msg
    client.close()
