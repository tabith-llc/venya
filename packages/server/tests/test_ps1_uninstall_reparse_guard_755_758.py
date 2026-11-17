# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Static review cells for the Windows uninstaller's two #755/#758 guards.

``uninstall-venya-cli.sh`` refuses a symlinked config dir (#758) and
``uninstall-venya-core.sh`` refuses a symlinked state path (#755); the Windows arm of the
same uninstaller read zero of those words. ``Remove-Item -Recurse -Force`` on a junction
deletes the LINK NAME and succeeds, so a machine-wide install root that is a link produced
a run that claimed an uninstall while the tree the link pointed at stayed on the disk.
That half is what the guard block covers, and its load-bearing property is ORDER: a test
that sits after the first destructive call cannot prevent anything.

The second half is the residual-``PATH`` sweep. The verify-absent loop under #402 is what
establishes that this run's removal happened; the sweep only answers which ``venya`` is
answering. When any hit failed the run, an operator with two install roots who removed
one of them was told the command had failed and given "inspect manually" instead of the
name of the root still answering. So the sweep classifies: a hit under the root just
removed still fails loud, a hit under a different root is named and the run exits 0.
Neither arm loosens the verify-absent loop, and a cell here pins that too.

Every cell reads a function over arbitrary text rather than the shipped module constant
directly, so its own paired negative can feed that same function a reverted file: a
detector that only ever sees the text it likes is not a detector.

No pwsh runner is asserted here. Repo-side this plane stays static review, the idiom #402,
#629 and #642 keep; the executable arms ran on the Windows guest (report for leg 755).
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = (REPO_ROOT / "uninstall-venya-cli.ps1").read_text(encoding="utf-8")

#: The guard block, anchored on its own first line rather than on a line number.
GUARD_BLOCK = re.compile(r"\$guardRoots = @\(\$Base\).*?\n\}", re.DOTALL)

#: The residual-PATH sweep, anchored on the prefix it computes.
SWEEP_BLOCK = re.compile(r"\$removedPrefix = \$Base\.TrimEnd.*?\n\}", re.DOTALL)

#: The arm that owns a hit inside the root this run just removed.
UNDER_ROOT_ARM = re.compile(
    r"if \(\$c\.Source\.StartsWith\(\$removedPrefix, \[StringComparison\]::OrdinalIgnoreCase\)\) \{.*?\n    \}",
    re.DOTALL,
)

#: The first destructive call in the file: removal of the install root itself.
FIRST_REMOVAL = "Remove-Item -LiteralPath $Base -Recurse -Force"

#: The other machine state a run writes, which a late refusal cannot un-write.
PATH_WRITE = "[Environment]::SetEnvironmentVariable('Path'"


def _block(pattern: re.Pattern[str], text: str, label: str) -> str:
    """One named block out of ``text``, or a refusal naming what went missing."""
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"{label} not found in uninstall-venya-cli.ps1 — it was removed, not renamed")
    return match.group(0)


def _guard(text: str) -> str:
    return _block(GUARD_BLOCK, text, "reparse guard block")


def _sweep(text: str) -> str:
    return _block(SWEEP_BLOCK, text, "residual-PATH sweep")


def _under_root_arm(text: str) -> str:
    sweep = _sweep(text)
    match = UNDER_ROOT_ARM.search(sweep)
    if match is None:
        raise AssertionError("the under-the-removed-root arm is not the shape this row pins")
    return match.group(0)


def _guard_ends_before_the_first_removal(text: str) -> bool:
    end_of_guard = text.index(_guard(text)) + len(_guard(text))
    return end_of_guard < text.index(FIRST_REMOVAL) < text.index(PATH_WRITE)


# ------------------------------------------------------------------ D-1, the guard
def test_guard_probes_with_an_lstat_not_a_presence_test() -> None:
    """``Get-Item -Force`` is the lstat side: a link whose target is already gone still reads
    here as an item, where a presence test reads "missing" and walks past it (#755/#758)."""
    guard = _guard(SRC)
    assert "Get-Item -LiteralPath $root -Force" in guard
    assert "[IO.FileAttributes]::ReparsePoint" in guard
    # literal binding, the #628/#629 door: an operator root with brackets is one name, not a pattern
    assert "Get-Item $root" not in guard


def test_guard_runs_before_anything_is_touched() -> None:
    """The load-bearing half. A refusal after ``Remove-Item`` reports on damage already done."""
    assert _guard_ends_before_the_first_removal(SRC), "guard must sit above the install-root removal"
    guard = _guard(SRC)
    assert SRC.index(guard) < SRC.index(PATH_WRITE)


def test_guard_refusal_names_the_link_and_says_nothing_was_removed() -> None:
    guard = _guard(SRC)
    assert "Fail " in guard, "the refusal goes through Fail, which is the nonzero exit in this file"
    assert re.search(r"function Fail\(.*exit 1", SRC), "Fail must still exit nonzero"
    assert "Nothing was removed" in guard
    # where it points, when the shell can say so: LinkType and Target are read as capabilities, and
    # the tested 5.1.26100 guest answers LinkType=Junction, so this is not a version gate.
    assert "LinkType" in guard and "Target" in guard


def test_guard_covers_the_config_roots_only_when_the_purge_is_in_scope() -> None:
    """A linked ``%APPDATA%\\venya`` is refused when this run is about to remove it, and left
    alone when it is not — the same scope #758 gives the bash arm."""
    assert re.search(
        r"\$guardRoots = @\(\$Base\)\s*\nif \(\$purge -eq 'yes'\) \{ \$guardRoots \+= \$cfgDir, \$legacy \}",
        _guard(SRC),
    ), "the guard's root list must be install root first, config roots only on the purge arm"


# ------------------------------------------------------------------ D-2, the classification
def test_hit_under_the_removed_root_still_fails_loud() -> None:
    """The relaxation this fix must NOT be: arm (a) keeps exiting 1."""
    assert "Fail " in _under_root_arm(SRC)


def test_hit_under_another_root_is_named_and_does_not_fail_the_run() -> None:
    named = re.search(
        r'Warn "\$s still resolves at \$\(\$c\.Source\)[^\n]*different install root[^\n]*completed[^\n]*"',
        _sweep(SRC),
    )
    assert named, "a second install must be named as itself, not reported as a failed removal"
    assert "Fail" not in named.group(0)


def test_an_unattributable_hit_is_not_read_as_a_clean_machine() -> None:
    """``Get-Command`` can answer with no Source at all (an alias or function face). "It
    resolves somewhere this run cannot name" is not evidence about which root, so the run
    does not claim success either."""
    assert re.search(r"if \(-not \$c\.Source\) \{ Fail ", _sweep(SRC))


def test_verify_absent_loop_is_untouched_by_this_fix() -> None:
    """#402's loop is what makes the success claim reachable; loosening it is prohibited."""
    sites = re.search(r"foreach \(\$p in @\((?P<sites>.*?)\)\) \{", SRC, re.DOTALL)
    assert sites, "verify-absent loop not found — re-anchor by symbol"
    assert {s.strip() for s in sites.group("sites").split(",")} == {
        "$Base",
        "(Join-Path $ToolDir 'venya-cli')",
        "(Join-Path $ToolDir 'venya-mcp')",
        "(Join-Path $BinDir 'venya.exe')",
        "(Join-Path $BinDir 'venya-mcp.exe')",
    }
    assert "if (Test-Path -LiteralPath $p) { Fail " in SRC, "the survivor probe must still Fail"


# ------------------------------------------------------------------ non-vacuity
def test_detectors_redden_on_a_reverted_file() -> None:
    """Each detector, fed the shipped text with its own subject cut out, must refuse."""
    without_guard = SRC.replace(_guard(SRC), "# guard deleted", 1)
    without_sweep = SRC.replace(_sweep(SRC), "# sweep deleted", 1)
    with pytest.raises(AssertionError, match="guard block"):
        _guard(without_guard)
    with pytest.raises(AssertionError, match="sweep"):
        _sweep(without_sweep)


def test_ordering_detector_rejects_a_guard_moved_below_the_removal() -> None:
    """The pairing that matters most: the guard still exists, in the wrong place."""
    moved = SRC.replace(_guard(SRC), "", 1).replace(FIRST_REMOVAL, FIRST_REMOVAL + "\n" + _guard(SRC), 1)
    _guard(moved)  # the block is still findable — so only the order cell can catch this
    assert not _guard_ends_before_the_first_removal(moved)


def test_classification_detector_rejects_a_relaxation() -> None:
    """Turning arm (a) from a refusal into a warning must redden the cell that pins it."""
    sweep = _sweep(SRC)
    relaxed = sweep.replace(
        'Fail "$s still resolves at $($c.Source) - inside the removed root',
        'Warn "$s still resolves at $($c.Source) - inside the removed root',
        1,
    )
    assert relaxed != sweep, "the fixture line to relax was not found — this cell is vacuous"
    with pytest.raises(AssertionError, match="Fail"):
        assert "Fail " in _under_root_arm(SRC.replace(sweep, relaxed, 1))
