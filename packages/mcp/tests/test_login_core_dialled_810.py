# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#810 read side: a session file that names its core is dialled, not defaulted away.

The writer half lives in `packages/cli` (`cmd_login` → `Config.merge_transient_core_for_login`,
`packages/cli/tests/test_login_persists_dialled_core_810.py`), and capability isolation bars a
cross-package drive from here — so the document below is the VERBATIM content that cell produces
(the dict equality is pinned there; the two literals are pasted side by side in the leg report).
What this file pins is the read: a fresh MCP start over a file that names a core takes that core
as its dial target, which is exactly what the token-only file — the shape #810's login left on
disk — could not do, and why the writer had to change.

Cell honesty: both cells here are GREEN at base as well as tip — the reader already honours a
`server_url` that exists; the defect was that no login ever wrote one beside the token. They are
kept because they pin the far half of the chain this leg closes, and because the paired control
proves the allowed `https://localhost` default (#768 AC5 shape, landed cell
`test_server_url_default_localhost_allowed`) is NOT narrowed by anything in this change set. The
landed adoption/never-held sentences are untouched bytes here; their suite colors ride the gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from venya_mcp.client import VenyaClient
from venya_mcp.config import MCPConfig

CORE = "https://core.example"
TOKEN = "tok-810"
LOGIN_WRITES = {"server_url": CORE, "access_token": TOKEN}
TOKEN_ONLY = {"access_token": TOKEN}


def _config_file(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "config.json"
    p.write_text(json.dumps(payload))
    return p


class TestFreshStartDialsPersistedCore:
    def test_named_core_is_the_dial_target_not_the_default(self, tmp_path):
        cfg = MCPConfig(_config_file(tmp_path, LOGIN_WRITES))
        assert cfg.server_url == CORE
        assert cfg.disk_server_url == CORE
        client = VenyaClient(cfg, verify=False)
        assert client._access_token == TOKEN  # the construction read holds the login's bearer
        assert client.config.server_url == CORE  # and it rides to the named core, not the default

    def test_control_token_only_file_still_yields_the_allowed_default(self, tmp_path):
        """The shape #810 produced: no key, no core, and the shipped default stands — pinned
        as allowed, never narrowed by this leg."""
        cfg = MCPConfig(_config_file(tmp_path, TOKEN_ONLY))
        assert cfg.server_url == "https://localhost"
        assert cfg.disk_server_url is None
