"""#675 AC5 — the passphrase length declarations must not drift, and the census that
guards them must be able to SEE all of them.

The floor is declared six times across two planes (five Python, one shell) and the
ceiling five times in Python. A refactoring into a single shared import was NOT taken
here: `core/engine/backend.py` carries the DB-KEK enforcement path the owner holds
frozen, and four packages cannot share one import without reaching through it. So AC5's
second option governs — a paired-negative drift cell, built from DECLARATION FORMS
rather than a filename list.

The cell carries its own negative on purpose. This row's own census moved four -> five
-> six under better patterns: a bare `= 15` grep misses the annotated
`MIN_PASSPHRASE_CODE_POINTS: Final[int] = 15` in `backend.py`, and a `*.py` pathspec
cannot see `DB_PASSPHRASE_FLOOR=15` in `install-venya-core.sh` at all. A drift test whose
instrument cannot see two of its six targets would pass while the declarations disagreed,
so `_extract` is exercised against a value it must reject before any real file is trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# Declaration forms, not filenames: the optional `: Final[int]`-style annotation is what
# catches the core's annotated pair, and the value is captured so a disagreement reads.
_PY_DECL = re.compile(r"\b((?:MIN|MAX)_PASSPHRASE_CODE_POINTS)(\s*:[^=\n]+)?\s*=\s*(\d+)")
_SHELL_FLOOR = re.compile(r"^\s*DB_PASSPHRASE_FLOOR\s*=\s*(\d+)", re.MULTILINE)


def _extract(source: str) -> dict[str, int]:
    """Every MIN/MAX passphrase declaration in one Python source, name -> value."""
    found: dict[str, int] = {}
    for name, _annotation, value in _PY_DECL.findall(source):
        found[name] = int(value)
    return found


def _python_declarations() -> dict[Path, dict[str, int]]:
    sites: dict[Path, dict[str, int]] = {}
    for path in sorted((REPO / "packages").glob("*/src/**/*.py")):
        found = _extract(path.read_text(encoding="utf-8"))
        if found:
            sites[path] = found
    return sites


def _shell_floor() -> int:
    source = (REPO / "install-venya-core.sh").read_text(encoding="utf-8")
    hits = _SHELL_FLOOR.findall(source)
    assert len(hits) == 1, f"expected exactly one DB_PASSPHRASE_FLOOR declaration, saw {hits}"
    return int(hits[0])


def test_the_instrument_sees_the_annotated_form_and_rejects_a_drift():
    """Negative half FIRST: prove the pattern can fail, or the rest is a habit.

    The annotated line is the declaration form a bare `= 15` grep loses, and the second
    block is what a drifted value looks like. If either assertion here ever stops
    holding, the drift cell below has stopped meaning anything.
    """
    annotated = _extract("MIN_PASSPHRASE_CODE_POINTS: Final[int] = 15\n")
    assert annotated == {"MIN_PASSPHRASE_CODE_POINTS": 15}, "annotated form is invisible"

    drifted = _extract("MIN_PASSPHRASE_CODE_POINTS = 16\nMAX_PASSPHRASE_CODE_POINTS = 64\n")
    assert drifted["MIN_PASSPHRASE_CODE_POINTS"] == 16, "a drifted value is not read"

    plain = _extract("MIN_PASSPHRASE_CODE_POINTS = 15  # inclusive\n")
    assert plain == {"MIN_PASSPHRASE_CODE_POINTS": 15}, "the unannotated form is invisible"


def test_the_census_finds_every_known_declaration_site():
    """A census that silently sees fewer sites than exist is the defect #675 item 5
    demonstrates, so the count itself is asserted, per file, not inferred."""
    sites = _python_declarations()
    rel = {p.relative_to(REPO).as_posix() for p in sites}
    expected = {
        "packages/cli/src/venya_cli/commands.py",
        "packages/cli/src/venya_cli/executor_key.py",
        "packages/core/src/core/engine/backend.py",
        "packages/executor/src/executor/key_passphrase.py",
        "packages/server/src/server/ca.py",
    }
    missing = expected - rel
    assert not missing, f"the declaration pattern missed: {sorted(missing)}"
    assert _shell_floor() == 15, "the shell floor declaration is not readable by this cell"


def test_all_floor_declarations_agree_across_both_planes():
    floors: dict[str, int] = {}
    for path, found in _python_declarations().items():
        if "MIN_PASSPHRASE_CODE_POINTS" in found:
            floors[path.relative_to(REPO).as_posix()] = found["MIN_PASSPHRASE_CODE_POINTS"]
    floors["install-venya-core.sh:DB_PASSPHRASE_FLOOR"] = _shell_floor()

    distinct = set(floors.values())
    assert len(floors) >= 6, f"only {len(floors)} floor sites found: {sorted(floors)}"
    assert distinct == {15}, (
        "the passphrase floor has drifted; operator prompts and refusals interpolate it, "
        f"so these numbers are what an operator is told: {floors}"
    )


def test_all_ceiling_declarations_agree_and_stay_a_stated_permit():
    """The ceiling is a documented PERMIT (owner OPTION 1, research clause C2), so this
    cell guards only that the five sites agree. It deliberately does NOT assert any
    refusal above the value — enforcing 64 would retire a ruling."""
    ceilings: dict[str, int] = {}
    for path, found in _python_declarations().items():
        if "MAX_PASSPHRASE_CODE_POINTS" in found:
            ceilings[path.relative_to(REPO).as_posix()] = found["MAX_PASSPHRASE_CODE_POINTS"]
    assert len(ceilings) >= 5, f"only {len(ceilings)} ceiling sites found: {sorted(ceilings)}"
    assert set(ceilings.values()) == {64}, f"the stated ceiling has drifted: {ceilings}"
