# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#697 AC1 (render side) — the honest 503 reaches the operator, not just the route.

The other half of this row lives in
``packages/server/tests/test_relay_503_relay_697.py`` and holds the ROUTE: a relay 503 whose detail
opens with the operational-fault prefix is forwarded verbatim. This file holds what the owner
actually asked for — that the sentence the executor chose is what the MCP caller READS — so it
drives the real client error path and the real tool wrapper, and asserts the literal survives both.

The seam between the two files is asserted, not assumed: the body handed to the client here is the
JSON the route emits for that status, read from the server module's OWN named constant, so a change
to the forwarded class moves this cell too instead of letting it keep passing on an old sentence.

Not claimed, and said plainly because the row's AC4 says to say it: which words each MCP TOOL prints
from ``VenyaAPIError`` was NOT traced across the whole client surface. Only ``run_command`` is driven
below. The untraced remainder is disclosed in ``docs/beta-known-limitations.md``.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# The forwarded class, imported from the server module rather than re-typed here. This is a TEST
# reading a constant across packages (the precedent is packages/cli/tests importing server routes);
# the product's packages/server still imports nothing from packages/executor.
from server.routes.executors import GENERIC_RELAY_ERROR_DETAIL, OPERATIONAL_FAULT_DETAIL_PREFIX
from venya_mcp.client import VenyaAPIError, VenyaClient
from venya_mcp.config import MCPConfig
from venya_mcp.server import call_tool

#: One literal of the forwarded class, built from the server's own prefix. The tail is the
#: daemon's wording; the class NAME is what the door keys on, so the tail can be re-worded without
#: changing what these cells prove.
FORWARDED_DETAIL = OPERATIONAL_FAULT_DETAIL_PREFIX + "no revocation answer received this boot"
UNFORWARDED_DETAIL = "execution failed"


def _config(tmp_path: Path) -> MCPConfig:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://venya-core-1", "access_token": "tok"}))
    return MCPConfig(config_file)


def _core_response(status: int, detail: str) -> MagicMock:
    """A stand-in for the response the CORE sends after its relay arm has decided.

    Exactly the shape ``server`` produces for an ``HTTPException(status_code, detail)``: JSON with a
    ``detail`` key and an ``application/json`` content type — the two things the client's error lift
    reads. Status is carried through unchanged, as the route does.
    """
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"detail": detail}
    resp.text = json.dumps({"detail": detail})
    resp.headers = {"content-type": "application/json"}
    return resp


def _client(tmp_path: Path, status: int, detail: str) -> VenyaClient:
    client = VenyaClient(_config(tmp_path), verify=False)
    http = MagicMock()
    http.request = AsyncMock(return_value=_core_response(status, detail))
    client._http = http
    return client


async def test_honest_503_literal_reaches_the_api_error(tmp_path: Path):
    """AC1 (client half): the lifted error carries the executor's sentence, not a substitute."""
    client = _client(tmp_path, 503, FORWARDED_DETAIL)
    with pytest.raises(VenyaAPIError) as excinfo:
        await client._request("POST", "/api/v1/executors/exec-1/execute")
    text = str(excinfo.value)
    assert excinfo.value.status_code == 503
    assert excinfo.value.detail == FORWARDED_DETAIL
    assert "503 OPERATIONAL FAULT" in text, text
    assert text.count("Venya API error") == 1, text


async def test_honest_503_literal_reaches_the_tool_surface(tmp_path: Path):
    """AC1 end-to-end to the operator-visible line: the tool propagates it, still prefixed once.

    ``call_tool`` deliberately re-raises ``VenyaAPIError`` rather than returning error text (so a
    failure cannot read as success), which makes the exception's own render the operator's line.
    """
    client = _client(tmp_path, 503, FORWARDED_DETAIL)
    with patch("venya_mcp.server.get_client", return_value=client):
        with pytest.raises(VenyaAPIError) as excinfo:
            await call_tool("run_command", {"executor_id": "exec-1", "command": "ls", "secret_keys": []})
    text = str(excinfo.value)
    assert text.count("Venya API error") == 1, text
    assert "503 OPERATIONAL FAULT" in text, text
    assert "check core reachability" in text or "no revocation answer" in text, text


async def test_paired_negative_substituted_detail_still_renders_substituted(tmp_path: Path):
    """The #410 control, seen from the client: an unrecognised detail renders the generic string.

    Shown to have teeth by the same mutation as the server-side AC2 cell (widening the prefix gate
    makes the FORWARDING stop substituting; this cell is the render-side witness that the
    substitution is what the operator sees when the door does not open).
    """
    client = _client(tmp_path, 503, UNFORWARDED_DETAIL)
    with pytest.raises(VenyaAPIError) as excinfo:
        await client._request("POST", "/api/v1/executors/exec-1/execute")
    assert excinfo.value.detail == UNFORWARDED_DETAIL
    # The route would NOT have forwarded that body; what reaches the client on the generic path is
    # the substituted sentence, asserted here by name so the constant cannot silently change.
    generic = _client(tmp_path, 503, GENERIC_RELAY_ERROR_DETAIL)
    with pytest.raises(VenyaAPIError) as gen_exc:
        await generic._request("POST", "/api/v1/executors/exec-1/execute")
    assert gen_exc.value.detail == GENERIC_RELAY_ERROR_DETAIL
    assert GENERIC_RELAY_ERROR_DETAIL in str(gen_exc.value)
