# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static honesty cells for the ps1 uninstaller verify-absent loop (#402).

No pwsh runner on montana — execution UNVERIFIED, riding the #328 win11
window (repo idiom for ps1: static review cells only; no PSParser/tokenize
harness exists — this file states so per #402 AC-3). The old shape printed
"Removed $Base" unverified and checked only the two shims; the #396 bash
contract requires every declared removal site re-tested after removal, with
the success claim gated on the loop. AC-1 parity grep-diff: the verify site
set must equal the installer's writer sites.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UNINSTALL = (REPO_ROOT / "uninstall-venya-cli.ps1").read_text(encoding="utf-8")
INSTALL = (REPO_ROOT / "install-venya-cli.ps1").read_text(encoding="utf-8")


def _verify_sites() -> set[str]:
    m = re.search(r"foreach \(\$p in @\((?P<sites>.*?)\)\) \{", UNINSTALL, re.DOTALL)
    assert m, "verify-absent loop not found — re-anchor by symbol"
    return {s.strip() for s in m.group("sites").split(",")}


def test_verify_sites_match_installer_writer_sites() -> None:
    # AC-1 grep-diff: the installer writes the tool venvs under
    # $ToolDir = Base\uv-tools and the shims under $BinDir = Base\bin...
    assert re.search(r"\$ToolDir\s*=\s*Join-Path \$Base 'uv-tools'", INSTALL)
    assert re.search(r"\$BinDir\s*=\s*Join-Path \$Base 'bin'", INSTALL)
    # ...as the two uv tools named here (verified install targets)...
    assert "'uv tool install venya-cli'" in INSTALL
    assert "'uv tool install venya-mcp'" in INSTALL
    # ...with the shims the installer itself verifies by name:
    assert "Join-Path $BinDir 'venya.exe'" in INSTALL
    assert "Join-Path $BinDir 'venya-mcp.exe'" in INSTALL
    # the uninstaller defines the same roots:
    assert re.search(r"\$ToolDir\s*=\s*Join-Path \$Base 'uv-tools'", UNINSTALL)
    # and the verify loop covers exactly the declared removal sites:
    assert _verify_sites() == {
        "$Base",
        "(Join-Path $ToolDir 'venya-cli')",
        "(Join-Path $ToolDir 'venya-mcp')",
        "(Join-Path $BinDir 'venya.exe')",
        "(Join-Path $BinDir 'venya-mcp.exe')",
    }


def test_success_claim_is_gated_on_the_loop() -> None:
    sites = UNINSTALL.index("foreach ($p in @(")
    claim = UNINSTALL.index("Venya CLI uninstalled machine-wide.")
    assert sites < claim, "success claim must sit after the verify-absent loop"
    # every survivor fails loud with its path (Fail exits 1 per its definition)
    loop = re.search(r"foreach \(\$p in @\(.*?\n\}", UNINSTALL, re.DOTALL).group(0)
    assert "Fail " in loop and "Still present after removal:" in loop


def test_no_premature_unverified_removed_claim_for_root() -> None:
    # paired negative: the bare "Removed $Base" claim from before #402 stays gone
    assert 'Info "Removed $Base"' not in UNINSTALL
    # the PATH-resolution sweep (second verification layer) is kept:
    assert "still resolves at" in UNINSTALL
