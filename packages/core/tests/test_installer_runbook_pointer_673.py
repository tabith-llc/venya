# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#673 AC4 — pin the admin-CA passphrase recovery banner, both halves, in the
cheap string form the ticket explicitly permits ("a hand-typed string test is
acceptable here precisely because the artifact is a printed string").

The mechanism, named so a re-anchor from an older ref cannot silently restore the
false claim: the banner at the end of ``install-venya-core.sh`` used to print
``Until that lands, ...`` — a sentence asserting the renewed-pair path did not
exist, written before #565 Part B shipped it. That false half was removed at
``cbf5398e``; what this cell adds is the pin that did not exist then, plus the
pointer re-aim of this leg: the line aimed at runbook ``§0`` (an index), and it
now aims directly at ``§5`` (the break-glass procedure) while keeping ``§7 step
0`` — the one place the runbook shows reading the stored passphrase back — in the
same sentence. A future edit that truncates the path back to a single hop trips
the negative half.

Truth table (the repo's paired-negative law):
  accepted — the real shipped script: pointer names the runbook AND §5, the
             read-back hop §7 step 0 is present, the true #565 sentences at
             :1291-1298 survive, and ``Until that lands`` is absent;
  rejected — a synthetic banner carrying the false ``Until that lands`` claim;
  rejected — a synthetic banner that names §5 but drops the §7-step-0 hop
             (the truncation this leg's shape rule forbids).

The reject path is exercised against the synthetic text in
``test_helper_fires_on_false_banner`` so this cell has been SEEN RED by
construction — a pin nobody watched fail is decoration.
"""

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_INSTALLER = _ROOT / "install-venya-core.sh"

# The exact pointer line as shipped by #673 (this leg). Substrings, not full-line
# equality: the line lives inside an `echo "..."` and quoting style is not the
# contract — the destinations are.
_POINTER_NEEDS = ("cert-rotation-runbook.md", "§5", "§7 step 0")
# The true sentences #565 Part B put in the same banner block; the earlier fix's
# own lines, re-derived at this pen from the shipped file.
_TRUE_NEEDS = (
    "VENYA_ADMIN_CA_KEY_PASSPHRASE (#565 Part B)",
    "machine-plane pair above needs no passphrase",
)
# The false claim, byte-exact from the pre-cbf5398e banner (`2b702101`, line 1188).
_FALSE_CLAIM = "Until that lands"


def _banner_problems(text: str) -> list[str]:
    """Every way the recovery banner fails its contract, as printed reasons.

    Pure over the text so the negative halves can be run against synthetic
    inputs without touching the shipped file.
    """
    problems: list[str] = []
    if _FALSE_CLAIM in text:
        problems.append(f"false claim present: {_FALSE_CLAIM!r}")
    pointer = [ln for ln in text.splitlines() if "cert-rotation-runbook.md §" in ln]
    if not pointer:
        problems.append("no runbook section pointer in the banner at all")
    else:
        joined = "\n".join(pointer)
        for need in _POINTER_NEEDS:
            if need not in joined:
                problems.append(f"pointer line omits {need!r}")
    for need in _TRUE_NEEDS:
        if need not in text:
            problems.append(f"#565 true sentence missing: {need!r}")
    return problems


def test_shipped_banner_is_clean() -> None:
    """Positive half: the real install-venya-core.sh passes every check."""
    text = _INSTALLER.read_text(encoding="utf-8")
    assert _banner_problems(text) == [], "admin-CA passphrase recovery banner drifted from the #673 contract"


def test_helper_fires_on_false_banner() -> None:
    """Negative half + prove-it-can-fail: the same helper MUST reject a banner
    that restores the false claim, and one that truncates the pointer path."""
    shipped = _INSTALLER.read_text(encoding="utf-8")
    false_synthetic = shipped.replace(
        "  machine-plane pair above needs no passphrase and remains the headless",
        "  B). Until that lands, the headless admin pattern on this core is the",
    )
    assert false_synthetic != shipped, "synthetic replacement did not fire — instrument dead"
    problems = _banner_problems(false_synthetic)
    assert problems and _FALSE_CLAIM in problems[0], problems

    truncated = shipped.replace(
        "cert-rotation-runbook.md §5 (read-back: §7 step 0; §0 is the index).",
        "cert-rotation-runbook.md §5.",
    )
    assert truncated != shipped, "truncation synthetic did not fire — instrument dead"
    problems = _banner_problems(truncated)
    assert any("§7 step 0" in p for p in problems), problems


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
