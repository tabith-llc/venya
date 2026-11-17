# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 1563 / iid 707 — one refresh per burst, and a token write that keeps other writers' keys.

Two faults, both in ``packages/mcp/src/venya_mcp``:

1. **No single-flight.** Every tool call dials through the server's one shared ``VenyaClient``,
   so a burst of expired-token 401s launched one ``POST /auth/refresh`` each, and a call whose own
   refresh came back non-200 was reported as an expired session while a sibling refresh in the
   same burst had succeeded. Cells: ``..._share_one_refresh_post``, ``..._refused..._once``,
   and the cause-splitting cells that follow it.
2. **The lost update.** ``update_token`` wrote this process's whole startup snapshot back over a
   file the CLI also owns, so a key the CLI changed after the MCP started was silently reverted —
   ``server_url`` among them, which selects the core the client dials. Cells:
   ``test_key_added_by_another_writer_survives_the_refresh`` and its pair.

Every cell here is written RED at ``dev`` ``db53cda8`` (see the report): the base source posts per
call and republishes the snapshot, so the counts and the key below both fail there.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_mcp.client import SessionExpiredError, VenyaAPIError, VenyaClient
from venya_mcp.config import MCPConfig

#: Long enough that every gathered caller reaches the refresh seam while the first one is still
#: in flight. A mock that returns without suspending would let the burst serialize and the
#: single-flight would never be exercised.
_BURST_SECONDS = 0.05

# The two session sentences this package ships, as literals: these cells guard the WORDS an
# operator reads, and a constant imported from the source under test would pass by construction.
_EXPIRED_SENTENCE = (
    "Venya session expired and could not be renewed. "
    "Run `venya login <USER_ID>` and approve your security key, "
    "then restart the MCP server."
)


def _config(tmp_path: Path, token: str | None, **keys: Any) -> MCPConfig:
    """A fixture-planted session file — never a real user config."""
    body: dict[str, Any] = {"server_url": "https://venya-core-1"}
    if token is not None:
        body["access_token"] = token
    body.update(keys)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body))
    return MCPConfig(path)


def _response(status_code: int, body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {}
    resp.text = ""
    resp.headers = {}
    return resp


def _client(config: MCPConfig) -> VenyaClient:
    return VenyaClient(config, verify=False)


# --- 1. single-flight: one refresh POST per burst --------------------------------------------


async def test_concurrent_401s_share_one_refresh_post(tmp_path: Path) -> None:
    """AC1 — three calls forced into a 401 produce ONE refresh POST and zero expirals.

    RED at base: ``_refresh`` POSTs per caller, so the count below is 3.
    """
    config = _config(tmp_path, "old-token")
    posts: list[str] = []

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        # The core accepts only the renewed token, so a caller that retried is visible here.
        if kw["headers"]["Authorization"].endswith("renewed-token"):
            return _response(200, {"ok": True})
        await asyncio.sleep(0)
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        posts.append(url)
        await asyncio.sleep(_BURST_SECONDS)
        return _response(200, {"access_token": "renewed-token"})

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    results = await asyncio.gather(*(client._request("GET", "/api/v1/secrets") for _ in range(3)))

    assert posts == [
        f"{config.server_url}/api/v1/auth/refresh"
    ], f"expected one refresh POST for the burst, saw {len(posts)}"
    assert all(r == {"ok": True} for r in results), "a coalesced caller must still get its answer"
    assert json.loads(config.path.read_text())["access_token"] == "renewed-token"


async def test_refresh_refused_by_the_core_posts_once_and_says_expired(tmp_path: Path) -> None:
    """AC2 + AC4 — a refused refresh is a real answer: shared once, still the session sentence.

    The negative of the cell above: single-flight must not invent success. Every caller gets the
    ruled expired/remedy/restart wording, and the core is asked once, not three times.
    """
    config = _config(tmp_path, "old-token")
    posts: list[str] = []

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        await asyncio.sleep(0)
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        posts.append(url)
        await asyncio.sleep(_BURST_SECONDS)
        return _response(401)

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    errors = await asyncio.gather(
        *(client._request("GET", "/api/v1/secrets") for _ in range(3)), return_exceptions=True
    )

    assert len(posts) == 1, f"expected one refresh POST for the burst, saw {len(posts)}"
    assert all(
        isinstance(e, SessionExpiredError) for e in errors
    ), f"a refused refresh must still reach the operator as an expired session: {errors}"
    assert all(str(e) == _EXPIRED_SENTENCE for e in errors), "and in the ruled words, not a new voice"


# --- 2. one message per cause: only a refusal may be called expired ---------------------------


async def test_refresh_5xx_is_not_reported_as_an_expired_session(tmp_path: Path) -> None:
    """AC3 — a 503 from the core is an unreachable-core answer, carrying the status it showed."""
    config = _config(tmp_path, "old-token")

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        return _response(503)

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    with pytest.raises(VenyaAPIError) as exc_info:
        await client._request("GET", "/api/v1/secrets")

    assert exc_info.value.status_code == 503
    assert "503" in str(exc_info.value), "the status the core answered is named"
    assert "expired" not in str(exc_info.value) and "security key" not in str(
        exc_info.value
    ), "no ceremony wording for a fault that was not a refusal"


async def test_refresh_timeout_reports_no_status_it_never_observed(tmp_path: Path) -> None:
    """AC3 — a timeout is not a 401, and the sentence may not assert a number."""
    config = _config(tmp_path, "old-token")

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> Any:
        raise httpx2.ConnectTimeout("read timed out")

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    with pytest.raises(VenyaAPIError) as exc_info:
        await client._request("GET", "/api/v1/secrets")

    assert exc_info.value.status_code is None
    assert "with no response" in str(exc_info.value)
    assert "expired" not in str(exc_info.value) and "security key" not in str(exc_info.value)


async def test_refresh_unreachable_core_reports_no_status_it_never_observed(
    tmp_path: Path,
) -> None:
    """AC3 — same fault through the transport door instead of the timer door."""
    config = _config(tmp_path, "old-token")

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> Any:
        raise httpx2.ConnectError("name does not resolve")

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    with pytest.raises(VenyaAPIError) as exc_info:
        await client._request("GET", "/api/v1/secrets")

    assert exc_info.value.status_code is None
    assert "expired" not in str(exc_info.value) and "security key" not in str(exc_info.value)


async def test_refused_refresh_leaves_the_stored_token_intact(tmp_path: Path) -> None:
    """(c) — no regression of the token-intact behavior #776 landed: a refusal writes nothing.

    The stored session is the operator's credential; a refresh the core refused must clear
    neither the file nor the client's own copy.
    """
    config = _config(tmp_path, "old-token")
    before = config.path.read_text()

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        return _response(403)

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    with pytest.raises(SessionExpiredError):
        await client._request("GET", "/api/v1/secrets")

    assert config.path.read_text() == before, "the session file is byte-unchanged"
    assert client._access_token == "old-token", "and the client still holds it"


# --- 3. the lost update: a refresh must not revert another writer's keys ----------------------


def test_key_added_by_another_writer_survives_the_refresh(tmp_path: Path) -> None:
    """(b) — a key the CLI changed after startup SURVIVES this writer, core address included.

    RED at base: ``update_token`` republished the startup snapshot, so the file came back holding
    the core this process started on. That is the dangerous half of iid 707 — an operator's
    traffic silently re-pointed at a different core.
    """
    config = _config(tmp_path, "old-token")
    path = config.path
    # The CLI rewrites the file after the MCP server started: a new core, and a key that did not
    # exist when this process took its snapshot.
    path.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-2",
                "access_token": "cli-token",
                "user_id": "u-42",
            }
        )
    )

    config.update_token("renewed-token")

    data = json.loads(path.read_text())
    assert data["server_url"] == "https://venya-core-2", "the core the client dials is not this writer's to revert"
    assert data["user_id"] == "u-42", "an unknown key is preserved, not resurrected over"
    assert data["access_token"] == "renewed-token", "and the refresh itself still lands"
    # Deliberate half: only the file follows the other writer. This process keeps dialing the
    # core its session started on — a token write must not move a bearer token mid-session.
    assert config.server_url == "https://venya-core-1"


def test_unreadable_session_file_still_receives_the_new_token(tmp_path: Path) -> None:
    """The pair: a file this writer cannot read is no reason to lose the refresh.

    A corrupt or vanished session file must not raise out of a successful refresh, and must not
    publish another writer's half-written content as if it were readable — this process's own keys
    are written instead.
    """
    config = _config(tmp_path, "old-token", server_url="https://venya-core-1")
    config.path.write_text("{ not json")

    config.update_token("renewed-token")

    data = json.loads(config.path.read_text())
    assert data["access_token"] == "renewed-token"
    assert data["server_url"] == "https://venya-core-1"
    assert config.path.stat().st_mode & 0o777 == 0o600, "and the write is still 0600"


def test_vanished_session_file_still_receives_the_new_token(tmp_path: Path) -> None:
    """Same fault through the other door: the file is gone rather than unparseable."""
    config = _config(tmp_path, "old-token")
    config.path.unlink()

    config.update_token("renewed-token")

    assert json.loads(config.path.read_text())["access_token"] == "renewed-token"


# --- 4. the two planes keep dialing the same way after the fix --------------------------------


async def test_single_success_path_still_persists_and_retries(tmp_path: Path) -> None:
    """(c) — no regression of the token-intact path #776 shipped: one call, one refresh, retried.

    The shape the guard test in ``test_client.py`` covers, re-asserted through the single-flight
    door so this leg cannot pass by breaking the ordinary case.
    """
    config = _config(tmp_path, "old-token")

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        if kw["headers"]["Authorization"].endswith("renewed-token"):
            return _response(200, {"data": "ok"})
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        return _response(200, {"access_token": "renewed-token"})

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    assert await client._request("GET", "/api/v1/secrets") == {"data": "ok"}
    assert client._access_token == "renewed-token"
    assert json.loads(config.path.read_text())["access_token"] == "renewed-token"


async def test_a_second_burst_refreshes_again(tmp_path: Path) -> None:
    """Single-flight is per burst, not once per process: a later expiry still refreshes.

    The negative of the coalescing cell — a fix that cached the first refresh forever would leave
    the second core verdict unsought and this cell red.
    """
    config = _config(tmp_path, "old-token")
    posts: list[str] = []
    tokens = iter(["burst-one", "burst-two"])

    async def fake_request(method: str, url: str, **kw: Any) -> MagicMock:
        # The core honors only a token it minted itself; "old-token" and "expired-again" are not.
        if kw["headers"]["Authorization"].removeprefix("Bearer ").startswith("burst"):
            return _response(200, {"ok": True})
        await asyncio.sleep(0)
        return _response(401)

    async def fake_post(url: str, **kw: Any) -> MagicMock:
        posts.append(url)
        await asyncio.sleep(_BURST_SECONDS)
        return _response(200, {"access_token": next(tokens)})

    client = _client(config)
    client._http = MagicMock(request=fake_request, post=fake_post)

    await asyncio.gather(*(client._request("GET", "/api/v1/a") for _ in range(2)))
    first_burst_posts = len(posts)
    # Expire the token the client now holds, the way a core would.
    client._access_token = "expired-again"
    await asyncio.gather(*(client._request("GET", "/api/v1/b") for _ in range(2)))

    assert first_burst_posts == 1
    assert len(posts) == 2, "one refresh per burst, and a new burst is a new refresh"
