"""#808 — a rate limit tells the operator to wait, not to touch the key.

The shipped arm keyed "refused" on the whole 4xx band (`400 <= status < 500`), so HTTP 429 — and
400, 404, 409 — answered with the security-key ceremony sentence. A rate limit means the request
was never evaluated: it says something about volume, nothing about the credential. Only 401 and 403
are the core's verdict ON the token, and those two keep the ruled 1556 sentence byte-for-byte.

Cells per leg 1573 spec §3.1: everything is driven through the REAL `refresh_token()` -> `_post_raw()`
path with only the transport mocked (the same shape as the #776 revision cells it sits beside), at the
eight statuses of the drive table plus the two paired negatives. The paired negative is the load-bearing
half: narrowing the band must not send a genuine 401/403 to the pending arm.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from venya_cli.api_client import APIClient, APIClientAuthenticationError, APIClientError

# The shipped 1556 remedy clause, pinned BY VALUE: a genuine refusal must still carry
# these exact bytes, so a swing that rewords it cannot pass this cell.
_CEREMONY_SENTENCE = (
    "the stored token was left in place; " "run `venya login <user-id>` to mint a new one (security-key ceremony)"
)

# The ruled pending clause, likewise pinned: the no-verdict class keeps the sentence #776 shipped.
_PENDING_CLAUSE = "the stored token was left in place; the retry is pending, the next call refreshes automatically"


def _client_with_token(tmp_path: Path, token: str = "stored-token") -> APIClient:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://core.test", "access_token": token}))
    return APIClient(config_file=config_file)


def _on_disk_token(client: APIClient):
    return json.loads(client.config.config_file.read_text()).get("access_token")


def _drive_status(client: APIClient, status_code: int, detail: str) -> None:
    """The transport answers `status_code` on the refresh POST; nothing else is mocked."""
    mock_http = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"detail": detail}
    resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
        f"HTTP {status_code}", request=MagicMock(), response=resp
    )
    mock_http.request.return_value = resp
    client._http = mock_http


def _refresh_message(client: APIClient) -> str:
    try:
        client.refresh_token()
    except APIClientAuthenticationError as e:
        return str(e)
    raise AssertionError("refresh_token must raise")


# ---------------------------------------------------------------------------
# RED at the base tip (eb1c227f): the no-verdict statuses answer with a ceremony.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status_code", [400, 404, 409, 429])
def test_no_verdict_status_says_pending_not_ceremony(tmp_path, status_code):
    """§1 decision 1: a status that says nothing about the credential is no-verdict.

    429 is the ticket's own complaint; 400/404/409 are the rest of the band the shipped
    comparison swept in. None of them is the core judging this token.
    """
    client = _client_with_token(tmp_path)
    before = client.config.config_file.read_bytes()
    _drive_status(client, status_code, "core said no")
    msg = _refresh_message(client)
    assert "ceremony" not in msg, f"HTTP {status_code} asked for a key touch: {msg}"
    assert "venya login" not in msg
    assert _PENDING_CLAUSE in msg
    # AC3 from the sibling row: the sentence names the status it actually observed.
    assert f"HTTP {status_code}" in msg
    assert _on_disk_token(client) == "stored-token"
    assert client.config.config_file.read_bytes() == before  # #776 clause one still holds
    client.close()


def test_429_is_not_reworded_into_a_wait_timer(tmp_path):
    """§1 decision 2/3: 429 rides the existing pending arm — no new sentence, no invented wait.

    `Retry-After` is not read on this path (grep at the base tip: 0 hits), so nothing here may
    name a duration. The remedy is that no ceremony is asked for, not a timer the code cannot keep.
    """
    client = _client_with_token(tmp_path)
    _drive_status(client, 429, "Too Many Requests")
    msg = _refresh_message(client)
    assert "ceremony" not in msg
    assert "seconds" not in msg and "retry in" not in msg
    client.close()


# ---------------------------------------------------------------------------
# The two classes that did not move — driven so a swing is caught, not assumed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status_code", [500, 502])
def test_transient_5xx_still_says_pending(tmp_path, status_code):
    """#776 AC5 unchanged: a 5xx was already pending and stays pending."""
    client = _client_with_token(tmp_path)
    _drive_status(client, status_code, "core busy")
    msg = _refresh_message(client)
    assert "ceremony" not in msg and "venya login" not in msg
    assert _PENDING_CLAUSE in msg
    assert f"HTTP {status_code}" in msg
    assert _on_disk_token(client) == "stored-token"
    client.close()


def test_timeout_and_status_none_stay_pending(tmp_path):
    """`status is None` is no-verdict by definition — the transport never answered."""
    client = _client_with_token(tmp_path)
    mock_http = MagicMock()
    mock_http.request.side_effect = httpx2.TimeoutException("read timed out")
    client._http = mock_http
    msg = _refresh_message(client)
    assert "ceremony" not in msg and "venya login" not in msg
    assert _PENDING_CLAUSE in msg
    assert "timed out" in msg
    assert _on_disk_token(client) == "stored-token"
    client.close()


# ---------------------------------------------------------------------------
# Paired negatives (root AGENTS §2): the narrowing must not swallow a real refusal.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status_code", [401, 403])
def test_genuine_refusal_keeps_the_ceremony_sentence_byte_for_byte(tmp_path, status_code):
    """401/403 are the two codes that speak ABOUT this credential; they keep the ruled text.

    401 arrives as `APIClientAuthenticationError` from the raise site; 403 arrives as a bare
    `APIClientError` carrying the status, so this cell proves the code test — not the class —
    is what refuses it, and it would go RED on any fix that keyed on the class alone.
    """
    client = _client_with_token(tmp_path)
    before = client.config.config_file.read_bytes()
    _drive_status(client, status_code, "Invalid or expired token")
    msg = _refresh_message(client)
    assert _CEREMONY_SENTENCE in msg, f"HTTP {status_code} lost the ruled remedy: {msg}"
    assert "pending" not in msg
    assert _on_disk_token(client) == "stored-token"
    assert client.config.config_file.read_bytes() == before
    client.close()


def test_authentication_class_without_a_status_is_still_refused(tmp_path):
    """A raise site that names the auth class IS the credential fact — status or no status."""
    client = _client_with_token(tmp_path)
    with patch.object(client, "_post_raw", side_effect=APIClientAuthenticationError("Invalid or expired token")):
        msg = _refresh_message(client)
    assert _CEREMONY_SENTENCE in msg
    assert _on_disk_token(client) == "stored-token"
    client.close()


def test_bare_client_error_without_a_status_is_pending(tmp_path):
    """Paired against the cell above: the same missing status, the other class -> no verdict."""
    client = _client_with_token(tmp_path)
    with patch.object(client, "_post_raw", side_effect=APIClientError("no status seen")):
        msg = _refresh_message(client)
    assert "ceremony" not in msg
    assert _PENDING_CLAUSE in msg
    client.close()
