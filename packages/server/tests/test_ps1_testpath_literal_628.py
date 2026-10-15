# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#628 static cells: every ps1 ``Test-Path`` binds ``-LiteralPath``.

No pwsh runner on this box — the ps1 is never executed here, so these are static
review cells in the #400/#401 idiom (read the script text with ``re``).

The defect, found physically on the ``win11`` guest: with ``VENYA_INSTALL_DIR``
set to ``C:\\temp[gate]`` the shipped installer aborted with ``uv.exe missing
after extraction`` while the file was on disk. ``Test-Path`` takes its first
argument as ``-Path``, and ``-Path`` resolves wildcards — ``[gate]`` is a
character class matching one of ``g``, ``a``, ``t``, ``e`` — so a literal
directory name by that spelling matches nothing and an existing file reads as
missing. ``-LiteralPath`` does not resolve wildcards.

#493 fixed the ``Get-ChildItem``/``Get-Acl`` enumeration inside the ACL gate and
the zero-enumeration guard at the foot of that block. Every ``Test-Path`` UPSTREAM
of the gate stayed positional, so an install with a bracketed root never reached
#493's fix. The acceptance half here is the sweep, not any one site: a partial fix
re-opens the sibling-site defect that produced this row.

Truth table — positive: each named site is tested through ``-LiteralPath``;
negative: zero ``Test-Path`` calls in the file bind a wildcard, and the detector
is shown non-vacuous by a mutation cell that feeds a reverted line to the very
same function and requires it to catch it.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "install-venya-cli.ps1").read_text(encoding="utf-8")

#: One ``Test-Path`` call. Group ``args`` is populated ONLY when the next token
#: is not ``-LiteralPath`` — a positional (or explicit ``-Path``) argument, which
#: is the wildcard-binding form #628 removes from this file.
CALL = re.compile(r"Test-Path(?P<args>\s+(?!-LiteralPath)\S[^\n]*)?")

#: Sites the ticket names, each in the form the fix ships. Asserted one by one so
#: a single revert fails at its own site instead of hiding in a count.
LITERAL_SITES = (
    r"Test-Path -LiteralPath \$p\b",  # Get-SystemTool: the System32 probe
    r"Test-Path -LiteralPath \$UvExe",  # uv present check + post-extraction probe
    r"Test-Path -LiteralPath \(Join-Path \$extractDir 'packages\\cli\\pyproject\.toml'\)",
    r"Test-Path -LiteralPath \(Join-Path \$extractDir 'packages\\mcp\\pyproject\.toml'\)",
    r"Test-Path -LiteralPath \$Base\b",  # #493's zero-enumeration guard
    r"Test-Path -LiteralPath \$venyaExe",
    r"Test-Path -LiteralPath \$mcpExe",
    r"Test-Path -LiteralPath \$mcpPython",
    r"Test-Path -LiteralPath \$workDir",
)

#: Floor on call sites (the nine above plus #493's guard). A check that silently
#: disappears lowers the count and is a change of behaviour, not a cleanup.
MIN_CALL_SITES = 10


def _call_lines(text: str) -> list[tuple[int, str]]:
    """``Test-Path`` call sites as ``(lineno, text)``, comment lines excluded.

    Whole-line comments carry the #493/#628 explanation and name both parameters;
    they are prose, not calls, so they are skipped here (the skip itself is
    exercised by ``test_comment_prose_is_not_a_call_site``).
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


class TestPs1TestPathLiteral628:
    """#628 — the installer must not read a bracketed path as missing."""

    def test_no_wildcard_binding_test_path_sites(self) -> None:
        """The sweep: zero positional ``Test-Path`` calls remain."""
        offenders = _offenders(SRC)
        assert not offenders, "Test-Path binds -Path (wildcards) again — #628: " + "; ".join(offenders)

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

        A hand-written negative fixture — one site back in the shipped-buggy
        positional form — goes through the same detector and must be reported.
        Without this, ``test_no_wildcard_binding_test_path_sites`` would also
        pass if the detector quietly stopped matching anything.
        """
        fixture = "    if (-not (Test-Path $UvExe)) { Fail 'uv.exe missing' }\n"
        hits = _offenders(fixture)
        assert len(hits) == 1, f"detector missed the reverted site (fixture {fixture!r} -> {hits})"
        # the same line in the fixed form reads clean, so the detector is not
        # simply reporting every Test-Path it sees
        fixed = fixture.replace("Test-Path $UvExe", "Test-Path -LiteralPath $UvExe")
        assert _offenders(fixed) == [], f"detector over-reports the literal form: {fixed!r}"

    def test_comment_prose_is_not_a_call_site(self) -> None:
        """The skip rule, exercised directly: explanation lines naming
        ``Test-Path`` are prose, not calls — and the file does carry them, so the
        rule is not vacuous either."""
        prose = "    # Test-Path takes -Path positionally; use -LiteralPath (#628)\n"
        assert "Test-Path" in prose
        assert _offenders(prose) == [], "comment prose counted as a call site"
        assert any(
            "Test-Path" in ln for ln in SRC.splitlines() if ln.strip().startswith("#")
        ), "the file no longer carries a Test-Path comment — skip rule untested here"

    def test_source_pin_the_acl_gate_still_reads_literal(self) -> None:
        """Trip-wire for #493's own bytes (this leg touches no gate code).

        If ``Get-ChildItem``/``Get-Acl`` ever move back to ``-Path``, the ACL gate
        counts zero files under a bracketed root and #493 re-opens; caught here as
        well as in ``test_ps1_acl_honesty_400.py``.
        """
        assert re.search(r"Get-ChildItem -LiteralPath \$Base", SRC)
        assert re.search(r"Get-Acl -LiteralPath \$_.FullName", SRC)
