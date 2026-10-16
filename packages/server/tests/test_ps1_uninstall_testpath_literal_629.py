# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#629 static cells: every ``Test-Path`` in the Windows UNINSTALLER binds ``-LiteralPath``.

No pwsh runner on this box — the ps1 is never executed here, so these are static
review cells in the #400/#401 idiom (read the script text with ``re``), mirroring
the shape #628 shipped for the installer.

The defect: ``Test-Path`` takes its first argument as ``-Path``, and ``-Path``
resolves wildcards — ``[`` and ``]`` are a character class matching one of the
characters inside them. So an install root by the literal spelling
``C:\\Program Files [venya]`` matches nothing, and the uninstaller reports
``Install root ... not present - nothing to remove there.`` for a directory that
is on disk, skips the ``Remove-Item``, and then the ALREADY-LITERAL verify-absent
loop downstream says ``Still present after removal``. Two contradictory lines
from one run, which is why the symptom reads as a verify bug and is not one.
#628 measured the same engine physically on the ``win11`` guest with
``VENYA_INSTALL_DIR=C:\\temp[gate]``; ``-LiteralPath`` does not resolve wildcards.

This file is the uninstaller half of the same sweep. The three probes at the
install root, the ``%APPDATA%\\venya`` config directory and the legacy
``.config\\venya`` directory bind ``-Path``; the verify-absent probe that CATCHES
the bug already binds ``-LiteralPath`` and this leg leaves it byte-untouched.
The acceptance half is the sweep, not any one site: a partial fix re-opens the
sibling-site defect that produced both rows.

Truth table — positive: each named site is tested through ``-LiteralPath``;
negative: zero ``Test-Path`` calls in the file bind a wildcard, and the detector
is shown non-vacuous by a mutation cell that feeds a reverted line to the very
same function and requires it to catch it, plus a paired cell proving the literal
form is not simply over-reported.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "uninstall-venya-cli.ps1").read_text(encoding="utf-8")

#: One ``Test-Path`` call. Group ``args`` is populated ONLY when the next token
#: is not ``-LiteralPath`` — a positional (or explicit ``-Path``) argument, which
#: is the wildcard-binding form #629 removes from this file.
CALL = re.compile(r"Test-Path(?P<args>\s+(?!-LiteralPath)\S[^\n]*)?")

#: Sites the ticket names, each in the form the fix ships. Asserted one by one so
#: a single revert fails at its own site instead of hiding in a count.
LITERAL_SITES = (
    r"if \(Test-Path -LiteralPath \$Base\) \{",  # install-root probe
    r"Test-Path -LiteralPath \$cfgDir",  # the %APPDATA%\venya purge probe
    r"Test-Path -LiteralPath \$legacy",  # the pre-%APPDATA% config probe
    r"Test-Path -LiteralPath \$p\b",  # #402 verify-absent loop (not this leg's to edit)
)

#: Floor on call sites (the three probes above plus #402's verify-absent probe).
#: A check that silently disappears lowers the count and is a change of behaviour,
#: not a cleanup.
MIN_CALL_SITES = 4


def _call_lines(text: str) -> list[tuple[int, str]]:
    """``Test-Path`` call sites as ``(lineno, text)``, comment lines excluded.

    Whole-line comments carry the #402/#628 explanation and may name both
    parameters; they are prose, not calls, so they are skipped here (the skip
    itself is exercised by ``test_comment_prose_is_not_a_call_site``).
    """
    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        if "Test-Path" in line:
            out.append((lineno, line.strip()))
    return out


def _offenders(text: str) -> list[str]:
    """Every ``Test-Path`` call in ``text`` that binds a wildcard, with its line."""
    hits = []
    for lineno, line in _call_lines(text):
        if any(m.group("args") is not None for m in CALL.finditer(line)):
            hits.append(f":{lineno} {line}")
    return hits


class TestPs1UninstallTestpathLiteral629:
    """#629 — the uninstaller must not read a bracketed install root as missing."""

    def test_no_wildcard_binding_test_path_sites(self) -> None:
        """The sweep: zero positional ``Test-Path`` calls remain."""
        offenders = _offenders(SRC)
        assert not offenders, "Test-Path binds -Path (wildcards) again — #629: " + "; ".join(offenders)

    def test_every_named_site_is_literal(self) -> None:
        """Positive half of the truth table: each site ships in literal form."""
        for pattern in LITERAL_SITES:
            assert re.search(pattern, SRC), f"site no longer literal: {pattern}"

    def test_call_site_floor_matches_the_sweep(self) -> None:
        """No check was deleted to make the sweep green.

        Counts call sites, not offenders — pairs with the cell above: zero
        offenders over a SHRUNKEN site count is not the fix this ticket ruled.
        """
        sites = _call_lines(SRC)
        assert (
            len(sites) >= MIN_CALL_SITES
        ), f"expected at least {MIN_CALL_SITES} Test-Path call sites, found {len(sites)}: {sites}"

    def test_detector_catches_a_reverted_site(self) -> None:
        """Mutation check: the sweep cell is not vacuous.

        A hand-written negative fixture — the install-root probe back in the
        shipped-buggy positional form — goes through the same detector and must be
        reported. Without this, ``test_no_wildcard_binding_test_path_sites`` would
        also pass if the detector quietly stopped matching anything.
        """
        fixture = "if (Test-Path $Base) { Remove-Item -LiteralPath $Base -Recurse -Force }\n"
        hits = _offenders(fixture)
        assert len(hits) == 1, f"detector missed the reverted site (fixture {fixture!r} -> {hits})"
        # the same line in the fixed form reads clean, so the detector is not
        # simply reporting every Test-Path it sees
        fixed = fixture.replace("Test-Path $Base", "Test-Path -LiteralPath $Base")
        assert _offenders(fixed) == [], f"detector over-reports the literal form: {fixed!r}"

    def test_comment_prose_is_not_a_call_site(self) -> None:
        """The skip rule, exercised on a paired fixture.

        Explanation lines naming ``Test-Path`` are prose, not calls; the second
        line of the same fixture is a real call and must still be caught, so the
        skip cannot pass by swallowing every line. (``install-venya-cli.ps1``
        carries such a comment in-file and pins that half there; this file does
        not carry one today, so the rule is exercised on the fixture here.)
        """
        fixture = (
            "    # Test-Path takes -Path positionally; use -LiteralPath (#629)\n"
            "    if (Test-Path $legacy) { Remove-Item -LiteralPath $legacy -Recurse -Force }\n"
        )
        hits = _offenders(fixture)
        assert len(hits) == 1, f"comment prose counted as a call site, or the real call was missed: {hits}"
        assert ":2" in hits[0], f"the surviving offender should be the real call at :2, got {hits}"

    def test_source_pin_verify_absent_loop_still_reads_literal(self) -> None:
        """Trip-wire for #402's own bytes (this leg touches that check not at all).

        The verify-absent loop is the check that catches a partial removal; if it
        ever moves back to a positional ``Test-Path`` it reports a bracketed root
        as absent-after-removal-proof, and #402 re-opens while #629 stays green.
        """
        assert re.search(r"foreach \(\$p in @\(\$Base,", SRC)
        assert re.search(r"if \(Test-Path -LiteralPath \$p\) \{ Fail \"Still present after removal", SRC)
