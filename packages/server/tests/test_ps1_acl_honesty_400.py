# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static honesty cells for the ps1 protected-DACL gate (ticket #400).

No pwsh runner on the Linux dev box — execution UNVERIFIED, riding the #328 win11
window; static review cells mirror the ps1 idiom in
test_installer_origin_pin_posture.py. The gate counts files under the install
root for protected DACLs; it must never print a bare PASS over a
SilentlyContinue-blinded (unverified) count. The pass claim is reachable only
on the zero-not-checked branch; the disclosure branch names the not-checked
count. Truth table: positive = clean full-coverage tree passes; negative =
unreadable items force the INCOMPLETE disclosure, never a bare "passed".
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "install-venya-cli.ps1").read_text(encoding="utf-8")


def _acl_block() -> str:
    m = re.search(
        r"Verifying no file was left with a protected DACL.*?(?=\n\s*# --- Machine PATH)",
        SRC,
        re.DOTALL,
    )
    assert m, "ACL gate block not found — re-anchor by symbol before editing"
    return m.group(0)


def test_pass_claim_gated_on_full_coverage() -> None:
    block = _acl_block()
    # the not-checked disclosure is tested BEFORE the pass claim prints
    assert "$notChecked -gt 0" in block
    assert block.index("$notChecked -gt 0") < block.index("ACL check passed")
    # the disclosure names what was NOT checked and what was verified
    assert "NOT checked" in block
    assert "$verified" in block
    # errors are collected, not swallowed: enumeration via -ErrorVariable,
    # ACL reads via per-item try/catch under -ErrorAction Stop
    assert "-ErrorVariable enumErr" in block
    assert "Get-Acl -LiteralPath $_.FullName -ErrorAction Stop" in block
    assert re.search(r"\} catch \{\s*\$notChecked\+\+", block), "catch must count"
    # the Fail path for real protected hits stays intact
    assert "carry a protected DACL" in block


def test_no_silentlycontinue_blinding_in_gate() -> None:
    # paired negative: the blinded pattern that motivated #400 must not return
    assert "Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue" not in SRC
