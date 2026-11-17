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

The last cell reaches the third site too, `MCPConfig._load`, which is the startup precondition a
new server answers with, so every message that offers this remedy is covered by this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from venya_mcp.client import SessionExpiredError, VenyaClient
from venya_mcp.config import RENEW_CLAUSE, MCPConfig

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


async def test_one_renewing_clause_at_every_site(tmp_path: Path) -> None:
    """The paired negative: one renewing clause, composed at every site that offers a remedy.

    This replaces a cell that asked the two client refusals to answer with one whole sentence.
    #706 AC1 rules that the fault is named too — a session this process never held is not called
    an expired one, and a refusal the core did answer is — so those messages are meant to differ,
    while the remedy a reader acts on is not. `RENEW_CLAUSE` is one constant, and what keeps a
    site from drifting back to a verb that can clear the token is that each site composes it.

    Instrument record, measured at this venue by mutating the source and reverting it: dropping
    `RENEW_CLAUSE` from the shared client tail fires nine cells across the two remedy files, this
    one among them. Dropping it from the startup site fires this cell and the two startup pins in
    `test_client_session_reread_705.py` and nothing else here — the cell this one replaces drove
    only the two client helpers, so the startup site was outside its range.
    """
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    never_held = await _empty_token_message(tmp_path / "a")
    refused = await _refresh_refused_message(tmp_path / "b")
    with pytest.raises(FileNotFoundError) as excinfo:
        MCPConfig(tmp_path / "absent.json")  # third site: the server never started
    startup = str(excinfo.value)

    for message in (never_held, refused, startup):
        assert RENEW_CLAUSE in message, f"the shared clause is not composed here: {message!r}"
        _assert_remedy(message)
    assert never_held != refused, "#706: the two client faults stay distinguishable"
