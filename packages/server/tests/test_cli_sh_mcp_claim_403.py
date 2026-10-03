# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static honesty cells for the bash cli installer's venya-mcp claim (#403).

Bash twin of the ps1 cells in test_ps1_mcp_claim_401.py (same idiom: regex
branch extraction against the installer text, re-anchor by symbol). The old
shape was `[ -x "$MCP_PY" ] && ! import` — an absent interpreter
short-circuited the check and "venya-mcp installed" printed unconditionally.
#396 contract: claims gate on verification. Truth table: positive = the
installed claim is unreachable when the interpreter is absent (it lives only
in the verified branch, after the import check); negative = the skip branch
carries the SKIPPED/UNVERIFIED disclosure. Also pins that the old
short-circuit test is gone.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "install-venya-cli.sh").read_text(encoding="utf-8")


def _mcp_branches() -> tuple[str, str]:
    m = re.search(
        r'if \[ -x "\$MCP_PY" \]; then\n(?P<yes>.*?)\n    else\n(?P<no>.*?)\n    fi',
        SRC,
        re.DOTALL,
    )
    assert m, "mcp import-check branch not found — re-anchor by symbol"
    return m.group("yes"), m.group("no")


def test_installed_claim_lives_only_in_the_verified_branch() -> None:
    yes, no = _mcp_branches()
    assert "import venya_mcp.server" in yes
    # pin the claim PRINT itself, not the substring inside the error text
    assert 'info "venya-mcp installed' in yes
    assert yes.index("import venya_mcp.server") < yes.index('info "venya-mcp installed')
    assert "venya-mcp installed" not in no


def test_skip_branch_discloses_degraded_state() -> None:
    _, no = _mcp_branches()
    assert "SKIPPED" in no
    assert "UNVERIFIED" in no
    assert "$MCP_PY" in no


def test_short_circuit_claim_shape_is_gone() -> None:
    assert '[ -x "$MCP_PY" ] &&' not in SRC
