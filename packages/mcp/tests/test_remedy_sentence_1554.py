# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 1554 — the session remedy names the verb that renews, not one that can clear the token.

`iid 776` (and `iid 705` behind it) is the reason: a read verb dialed with a dead token gets a 401,
the transparent refresh is refused, and the CLI then clears the stored access token. The shipped
sentence sent the operator to `venya list`, so following it destroyed the credential it was trying
to restore. Both `SessionExpiredError` sites now name `venya login <USER_ID>`, the verb the product
documents (`docs/cli-reference.md`, `venya login <USER_ID> [OPTIONS]`).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from venya_mcp.client import SessionExpiredError, VenyaClient
from venya_mcp.config import MCPConfig

#: Verbs this message must never name. `venya list` reaches the #776 clearing path; `venya run`
#: boots a sandbox, and with no token left it fails at the auth gate too.
BANNED_VERBS = ("venya list", "venya run")


def _config(tmp_path: Path, token: str | None) -> MCPConfig:
    """A fixture-planted session file — never a real user config."""
    path = tmp_path / "config.json"
    body: dict[str, str] = {"server_url": "https://venya-core-1"}
    if token is not None:
        body["access_token"] = token
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


def _assert_remedy(message: str) -> None:
    assert "venya login" in message, f"the renewing verb is not named: {message!r}"
    assert "<USER_ID>" in message, "and it is named in the documented call shape"
    for verb in BANNED_VERBS:
        assert verb not in message, f"the remedy still sends the operator to `{verb}`"
    # A reconnect step is still true at this face — the running server holds the token it read
    # at startup (iid 705). Leg 1555 changes that behavior; its wording, not this assert.
    assert "MCP server" in message


async def _empty_token_message(tmp_path: Path) -> str:
    """Site 1: no token in memory — `_headers()` refuses before any dial."""
    client = _client(_config(tmp_path, token=None))
    with pytest.raises(SessionExpiredError) as excinfo:
        client._headers()
    return str(excinfo.value)


async def _refresh_refused_message(tmp_path: Path) -> str:
    """Site 2: a 401 the refresh could not answer — `_request()` refuses after the retry."""
    client = _client(_config(tmp_path, token="dead-token"))
    client._http = MagicMock()
    client._http.request = AsyncMock(return_value=_response(401))
    client._http.post = AsyncMock(return_value=_response(401))
    with pytest.raises(SessionExpiredError) as excinfo:
        await client._request("GET", "/api/v1/secrets")
    return str(excinfo.value)


async def test_empty_token_remedy_names_login(tmp_path: Path) -> None:
    _assert_remedy(await _empty_token_message(tmp_path))


async def test_refresh_refused_remedy_names_login(tmp_path: Path) -> None:
    _assert_remedy(await _refresh_refused_message(tmp_path))


async def test_both_sites_answer_with_one_sentence(tmp_path: Path) -> None:
    """The paired negative: one operator-facing remedy, so either site reverting goes RED here."""
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    first = await _empty_token_message(tmp_path / "a")
    second = await _refresh_refused_message(tmp_path / "b")
    assert first == second, "the two sites drifted apart"
    _assert_remedy(first)
