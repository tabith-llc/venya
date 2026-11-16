# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""MCP face of leg 1424 (iid #798): an agent's answer must not read as a delivery.

`run_command` is the channel an LLM operator reads, and it said "Command exited with code
0." for a run whose egress the sandbox proxy refused — the proxy answers a denial as a
completed HTTP 403, so the exit code is the caller's own client grading that answer. The
pair of cells below is the truth table: the denial is said, and a delivered run is left
exactly as it was.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from venya_mcp.server import _AUDIT_DETAIL_KEYS, call_tool


def _client(answer):
    """A workstation-side stand-in for the relay answer, with the denial fields optional —
    an executor that predates them simply omits the keys."""
    client = MagicMock()
    client.run_command = AsyncMock(return_value=answer)
    client.get_audit = AsyncMock(return_value=[])
    return client


_ANSWER = {"executor_id": "web-3", "command": "curl -sS http://example.com/", "secret_keys": []}


async def test_a_refused_egress_is_said_before_the_exit_code():
    client = _client(
        {
            "exit_code": 0,
            "stdout": "Approval required for example.com:80.",
            "stderr": "venya: the sandbox proxy refused this run's egress to example.com:80",
            "masked_count": 0,
            "egress_denied": True,
            "egress_denied_host": "example.com:80",
        }
    )
    with patch("venya_mcp.server.get_client", return_value=client):
        result = await call_tool("run_command", _ANSWER)

    lines = result[0].text.splitlines()
    assert "Egress to example.com:80 was refused by the sandbox policy" in lines[1]
    assert "Command exited with code 0" in lines[0], "the caller's own code is not rewritten"
    assert "not a delivered request" in lines[1]


async def test_a_delivered_answer_keeps_the_shape_it_had():
    """★ Paired negative: nothing is said about egress when nothing was refused, and an
    answer from an executor that has no such field reads as it did before this change."""
    for answer in (
        {"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0},
        {"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0, "egress_denied": False},
    ):
        with patch("venya_mcp.server.get_client", return_value=_client(answer)):
            result = await call_tool("run_command", _ANSWER)
        text = result[0].text
        assert "refused" not in text.lower(), text
        assert text.splitlines()[0] == "Command exited with code 0. (executor=web-3)"


def test_the_audit_renderer_can_show_the_refused_destination():
    """`get_audit` prints only keys on its list, and drops the rest without a word: a row
    whose destination is not in `_AUDIT_DETAIL_KEYS` is a trail that names no host."""
    assert "egress_host" in _AUDIT_DETAIL_KEYS
