# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#447 guard — the shipped httpx2 cap is the ruled range, in EVERY member that declares it.

``install-venya-cli.sh`` runs ``uv tool install .../packages/cli``, which re-resolves ``httpx2``
from the DECLARED range: ``uv.lock`` does not travel to the customer. An unbounded ``>=0.27.0``
lets an install pick a version no gated suite ever ran (today's BETA DAY step 3 resolved 2.13.1).

This cell is the TREE door of a two-door rule (refs #447, owner's "(b): all three files, atomic,
ok scoped to LANDING not EVIDENCING"). The hook door — the ``httpx2-bound-census`` entry in
``.pre-commit-config.yaml`` — fires at commit time but is bypassed by ``--no-verify`` and absent
from a fresh clone (measured: 0 non-sample hooks). This file loads the ONE shared implementation at
``scripts/check_httpx2_bound_census.py`` — the same ``importlib`` idiom as
``packages/core/tests/test_detect_secrets_baseline.py`` for its guard scripts, and deliberately NOT
a second copy of the rule — and asserts the census over the shipped tree, then proves the census
can bite with three mutations on scratch trees.

What each original assertion became, and why none was dropped (the check-weakening class, same
shape as #442 R3): the old cell read only ``packages/cli/pyproject.toml`` and asserted (1) an
upper bound is present, (2) the declaration equals the ruled range, (3) the range admits the
tested line 2.12.0, (4) it refuses 2.13.0. Assertion (1) is now carried by (2) plus the census —
both are strictly stronger forms of "a dropped cap fails here" — and (2)(3)(4) survive verbatim on
the cli manifest. The delta: coverage moved from 1 member to all 5 declaring members.
"""

import importlib.util
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
_CENSUS_SCRIPT = REPO_ROOT / "scripts" / "check_httpx2_bound_census.py"

_CLI_PKG = Path(__file__).resolve().parents[1]
_PYPROJECT = _CLI_PKG / "pyproject.toml"

HTTPX2_NAME = "httpx2"
TESTED_LINE = "2.12.0"
UNTESTED_NEXT = "2.13.0"
RULED_RANGE = ">=0.27.0,<2.13.0"

# Tree door: load the shared census. A missing or renamed script is a loud ERROR here, never a
# skip — a skip would reopen the exact hole this file exists to close.
_spec = importlib.util.spec_from_file_location("httpx2_bound_census", _CENSUS_SCRIPT)
assert _spec is not None and _spec.loader is not None, f"the shared census must live at {_CENSUS_SCRIPT} (refs #447)"
census = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(census)


def _dependencies() -> list[str]:
    with _PYPROJECT.open("rb") as handle:
        return list(tomllib.load(handle)["project"]["dependencies"])


def _httpx2_declaration() -> str:
    matches = [d for d in _dependencies() if d.startswith(HTTPX2_NAME)]
    assert matches, f"{HTTPX2_NAME} must stay declared in {_PYPROJECT.name}"
    return matches[0]


def _specifier(declaration: str) -> str:
    return declaration[len(HTTPX2_NAME) :]


def _bounds(specifier: str) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
    """(floor, cap) — cap is None when the declaration carries no upper bound."""
    lower, _, upper = specifier.partition(",")
    floor = _version(lower.strip().removeprefix(">=").removeprefix(">"))
    cap_text = upper.strip().removeprefix("<=").removeprefix("<")
    return floor, _version(cap_text) if cap_text else None


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def _scratch_tree(tmp_path: Path, member_dirs: dict[str, str | None]) -> Path:
    """A throwaway workspace: root glob `packages/*`, one member per entry (None = no manifest)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\n', encoding="utf-8")
    for name, deps_toml in member_dirs.items():
        member = tmp_path / "packages" / name
        member.mkdir(parents=True)
        if deps_toml is not None:
            (member / "pyproject.toml").write_text(deps_toml, encoding="utf-8")
    return tmp_path


def test_httpx2_declaration_is_the_ruled_range() -> None:
    """(2) verbatim: the cli declaration is the ruled range exactly — and so, by its own text,
    carries an upper bound: assertion (1) needs no separate helper."""
    assert _httpx2_declaration() == f"{HTTPX2_NAME}{RULED_RANGE}"


def test_range_admits_the_tested_line() -> None:
    """(3) verbatim."""
    floor, cap = _bounds(_specifier(_httpx2_declaration()))
    assert cap is not None, "httpx2 range must be capped (refs #447)"
    assert floor <= _version(TESTED_LINE) < cap


def test_range_refuses_the_untested_line_above() -> None:
    """(4) verbatim."""
    _floor, cap = _bounds(_specifier(_httpx2_declaration()))
    assert cap is not None, "httpx2 range must be capped (refs #447)"
    assert not _version(UNTESTED_NEXT) < cap


def test_census_passes_on_the_shipped_tree() -> None:
    """The workspace-wide face the single-manifest cell could not see: every member that declares
    httpx2 carries the ruled range, and the census is not blind while doing it."""
    assert census.main([_CENSUS_SCRIPT.name, str(REPO_ROOT)]) == 0
    manifests = census.member_manifests(REPO_ROOT)
    assert manifests, "the member glob must resolve to at least one manifest — an empty census is blindness, not green"
    declaring = [m for m in manifests if census.httpx2_declaration(m) is not None]
    assert len(declaring) >= 2, f"a census over 1 manifest is the old blind cell; found {len(declaring)}"


@pytest.mark.parametrize(
    "member",
    [
        # Mutation A — a REVERTED PIN: the capped declaration loses its upper bound.
        "badcap",
        # Mutation B — a DRIFTED RANGE: capped, but not at the ruled cap.
        "drifted",
    ],
)
def test_census_bites_a_mutated_declaration(tmp_path: Path, member: str, capsys) -> None:
    """The hook is defeatable; this assertion is not. Self-sanity first (the planted-negative
    idiom): the identical tree minus the bad member must be GREEN, so the failure below is the
    declaration's doing and not a fixture artifact."""
    good = {"cliish": '[project]\nname = "cliish"\ndependencies = ["httpx2' + RULED_RANGE + '"]\n'}
    clean = _scratch_tree(tmp_path / "clean", good)
    assert census.main(["census", str(clean)]) == 0, "the control tree must pass before the plant means anything"
    planted = {
        "badcap": '[project]\nname = "badcap"\ndependencies = ["httpx2>=0.27.0"]\n',
        "drifted": '[project]\nname = "drifted"\ndependencies = ["httpx2>=0.27.0,<3.0.0"]\n',
    }[member]
    bad = _scratch_tree(tmp_path / "bad", {**good, member: planted})
    rc = census.main(["census", str(bad)])
    captured = capsys.readouterr()
    assert rc == 1, f"the census must refuse {member}: {captured.out!r}"
    assert member in captured.err and HTTPX2_NAME in captured.err


def test_census_fails_loud_when_blind(tmp_path: Path, capsys) -> None:
    """Mutation C — an entry deleted from the census list: a glob that resolves to NO members
    raises SystemExit rather than reporting green over an empty set."""
    empty = _scratch_tree(tmp_path, {"ghost": None})
    with pytest.raises(SystemExit) as raised:
        census.main(["census", str(empty)])
    assert "NO manifests" in str(raised.value)


def test_census_reports_a_removed_declaration_as_skipped(tmp_path: Path, capsys) -> None:
    """The deletion class the old file could not see: a member that drops the dependency is
    SKIPPED BY NAME — visibly, so a cap cannot be laundered by removing and re-adding it later
    in a different member. This is the census being honest about its own scope, not a pass."""
    tree = _scratch_tree(
        tmp_path,
        {
            "kept": '[project]\nname = "kept"\ndependencies = ["httpx2' + RULED_RANGE + '"]\n',
            "gone": ' [project]\nname = "gone"\ndependencies = []\n'.lstrip(),
        },
    )
    assert census.main(["census", str(tree)]) == 0
    skip_list = capsys.readouterr().out.split("without the dep:")[-1]
    assert (
        "gone" in skip_list and "kept" not in skip_list
    ), "the skip list must name the member WITHOUT the dep, not the covered one"
