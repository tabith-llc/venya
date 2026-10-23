# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static honesty cells for the ps1 venya-mcp install claim (ticket #401).

No pwsh runner on the Linux dev box — execution UNVERIFIED, riding the #328 win11
window; static review cells per the #396 precedent (see
test_installer_origin_pin_posture.py for the idiom). The old shape printed
"venya-mcp installed" even when the import check was skipped because the venv
interpreter was absent. #396 contract: claims gate on verification. Truth
table: positive = verified branch carries the installed claim; negative = the
skip branch carries the SKIPPED disclosure and NO installed claim. Also pins
the ruled TEMP-sweep disclosure (P5 hunk).
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "install-venya-cli.ps1").read_text(encoding="utf-8")


def _mcp_branches() -> tuple[str, str]:
    # The #628 sweep made this site literal, so the anchor names the literal
    # form: a revert to the positional -Path fails here as well as in
    # test_ps1_testpath_literal_628.py.
    m = re.search(
        r"if \(Test-Path -LiteralPath \$mcpPython\) \{\n(?P<yes>.*?)\n        \} else \{\n(?P<no>.*?)\n        \}",
        SRC,
        re.DOTALL,
    )
    assert m, "mcp import-check branch not found — re-anchor by symbol"
    return m.group("yes"), m.group("no")


def test_installed_claim_lives_only_in_the_verified_branch() -> None:
    yes, no = _mcp_branches()
    assert "import venya_mcp.server" in yes
    assert "venya-mcp installed" in yes
    assert yes.index("import venya_mcp.server") < yes.index("venya-mcp installed")
    assert "venya-mcp installed" not in no


def test_skip_branch_discloses_degraded_state() -> None:
    _, no = _mcp_branches()
    assert "SKIPPED" in no
    assert "UNVERIFIED" in no
    assert "$mcpPython" in no


def test_temp_sweep_discloses_instead_of_blinding() -> None:
    m = re.search(r"\n\} finally \{.*?\n\}", SRC, re.DOTALL)
    assert m, "finally block not found — re-anchor by symbol"
    block = m.group(0)
    # the ruled hunk: collected errors and a leftover disclosure, not a bare
    # -EA SilentlyContinue swallow of the scratch-dir sweep
    assert "-ErrorVariable sweepErr" in block
    assert "Could not fully remove scratch dir" in block
    assert re.search(r"-LiteralPath \$workDir -Recurse -Force -ErrorAction SilentlyContinue \}", block) is None
