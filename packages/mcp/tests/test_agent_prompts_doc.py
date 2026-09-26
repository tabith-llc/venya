# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the paste-ready agent prompt stays true to the tool surface.

Ticket mcp-agents-md-prompt-guidance (vehicle ruling (b)+(d), owner
2026-09-25): docs/agent-prompts.md is the customer-facing operating
contract pasted into agent instruction files. Its load-bearing claims are
pinned here to the live MCP tool surface so the doc cannot silently rot —
the same drift class as the list_secrets description (e8a08eb promised what
the rendering never delivered), in documentation form.
"""

import asyncio
import re
from pathlib import Path

from venya_mcp.server import list_tools

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "agent-prompts.md"


def _block() -> str:
    text = DOC.read_text()
    m = re.search(r"<!-- snippet-start -->(.*)<!-- snippet-end -->", text, re.DOTALL)
    assert m, (
        "paste-block markers (<!-- snippet-start/end -->) missing from "
        "docs/agent-prompts.md — the doc was restructured without updating "
        "the interlock"
    )
    block = m.group(1)
    # Paired negative: the guard must not pass because the block shrank to nothing.
    assert len(block.strip()) > 400, f"paste-block shrank to {len(block.strip())} chars — content drift?"
    return block


class TestAgentPromptsDocPinned:
    def test_every_mcp_tool_is_named_in_the_block(self):
        tools = asyncio.run(list_tools())
        assert tools, "list_tools() returned nothing — tool surface collapsed?"
        block = _block()
        missing = [t.name for t in tools if t.name not in block]
        assert not missing, (
            f"snippet omits tool(s) {missing} — either the tool surface grew "
            "(update the snippet + this interlock deliberately) or a tool was "
            "renamed (the snippet is now teaching a dead name)"
        )

    def test_block_carries_the_contract_claims(self):
        block = _block()
        for needle in (
            "[REDACTED:",  # marker format (filter.rs contract)
            "/run/secrets/venya",  # injection path contract (a2 resolved-usage)
            "usage",  # the ready-to-run template flow
            "503",  # builtins/sandbox-failure behavior
            "401",  # human re-authentication rule
        ):
            assert needle in block, f"snippet lost the '{needle}' contract claim"

    def test_block_never_directs_a_web_fetch(self):
        block = _block()
        assert "http" not in block, (
            "paste-block contains a URL — the block is self-contained by design; "
            "agents must never need a web fetch to operate (owner ruling "
            "2026-09-25, live-cell evidence: the brief-fetch line cost a webfetch "
            "of GitHub navigation chrome)"
        )

    def test_doc_points_at_the_full_brief(self):
        text = DOC.read_text()
        assert "agents.md" in text, "doc no longer links the full operating brief"
