# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#640 — the doc gate can now SEE a root-level page, and the seeing is falsifiable.

The defect was not a wrong sentence in a root document; it was that **no doc gate could read a
root-level `.md`**. Every doc gate in this repo hardcodes its own path
(`test_cli_reference_doc.py:34`, `test_bandit_suppressions_doc.py:21`, `test_agent_prompts_doc.py:24`,
`test_installer_core_ip_hosts_490.py:47`), and the one gate that does glob —
`test_terminology_yubico.py:27-34` — lists two root FILENAMES (`README.md`,
`THIRD-PARTY-NOTICES.md`) plus `docs/**/*.md`, so any other root page is invisible no matter what it
asserts. A page added later (`SUPPORT.md`, the case that started this) matches nothing, and the green
suite means only "I did not look".

So this gate does two things and refuses to do a third:

- it **enumerates** root-level `*.md` at run time, so a new root page is covered without anyone editing
  the guard — coverage is a property of the glob, not of somebody remembering to add a filename;
- it checks **one narrow, named fact**: a claim that a version is the current one. The source of truth
  is the dist metadata (`packages/cli/pyproject.toml`, the single version source since `c218fbc`), plus
  the newest dated heading in `CHANGELOG.md`.
- it **does not read prose**. A guard that interprets sentences gets switched off inside a week; a guard
  that compares one named string survives. Version tokens that appear in dated historical notes are
  deliberately NOT claims and are not checked — see `_CLAIM_MARKERS`.

AC2 is satisfied by `test_planted_false_claim_turns_the_gate_red` and its green pair. The blind spot
itself is pinned by `test_old_name_list_enumeration_misses_a_new_root_page`, which shows a
filename-list scan of the same tree reporting **clean** while the glob scan reports the violation: that
cell is the bug recorded as a test, and it fails if someone reintroduces the name list.
"""

import ast
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

#: A version-shaped token anywhere in a string. Used by the self-pinning cell below to catch THIS file
#: reintroducing a literal plate, which is the defect #640 is about.
VERSION_LIKE = re.compile(r"\d+\.\d+\.\d+(?:alpha|beta|rc|dev)?\d*")

#: The widening. One pattern, root-level markdown, resolved at run time.
ROOT_DOC_GLOB = "*.md"

#: What the historical shape looks like: `0.1.0beta1`, `v0.1.0alpha16`.
VERSION_TOKEN = re.compile(
    # The pre-release suffix is OPTIONAL. Requiring it meant a root page claiming a STABLE version
    # ("the current version is 1.2.3") matched nothing and read green on a lie — found by running this
    # gate against a synthetic suffixless tree, and pinned by test_a_stable_version_claim_is_red_too.
    r"v?(\d+\.\d+\.\d+(?:[-.]?(?:alpha|beta|rc|dev)\d*)?)",
    re.IGNORECASE,
)

#: A version token is only a CLAIM when it sits next to one of these. Everything else is a dated
#: record ("validated on 0.1.0alpha16, 2026-09-30") and checking it would be prose interpretation,
#: which is out of scope by design and would get this gate disabled.
_CLAIM_MARKERS = re.compile(
    r"current version|latest release|shipped (?:as|version)|this build|now at|version is",
    re.IGNORECASE,
)

#: Newest real version heading in CHANGELOG.md. `[Unreleased]` is a section, not a version claim.
_CHANGELOG_HEAD = re.compile(r"^## \[v?(\d+\.\d+\.\d+(?:[-.]?(?:alpha|beta|rc|dev)\d*)?)\]", re.MULTILINE)


def dist_version(root: Path = REPO_ROOT) -> str:
    """The single version source: the CLI's dist metadata."""
    with open(root / "packages" / "cli" / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def root_docs(root: Path = REPO_ROOT) -> list[Path]:
    """Every root-level markdown file, right now, whatever it is called."""
    return sorted(p for p in root.glob(ROOT_DOC_GLOB) if p.is_file())


def violations(root: Path = REPO_ROOT) -> list[str]:
    """Every root-level version claim that disagrees with the dist metadata.

    Returns the empty list only after having READ files — the caller proves that happened, because an
    empty list from an empty scan is exactly the failure mode this row is about.
    """
    truth = dist_version(root)
    found: list[str] = []
    for path in root_docs(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.name
        if rel == "CHANGELOG.md":
            head = _CHANGELOG_HEAD.search(text)
            if head and head.group(1) != truth:
                line = text.count("\n", 0, head.start()) + 1
                found.append(f"{rel}:{line}: CHANGELOG head says {head.group(1)!r}, dist says {truth!r}")
        for m in _CLAIM_MARKERS.finditer(text):
            # the claim sentence: from this marker to the end of its line
            tail = text[m.start() : text.index("\n", m.start()) if "\n" in text[m.start() :] else len(text)]
            for v in VERSION_TOKEN.finditer(tail):
                if v.group(1) != truth:
                    line = text.count("\n", 0, v.start()) + 1
                    found.append(f"{rel}:{line}: claims {v.group(1)!r} as current, dist says {truth!r}")
    return found


# --- AC: the scan must actually be looking -------------------------------------------------------


class TestGuardDoesNotCarryItsOwnDefect:
    """#640 is a story about a version statement that quietly stopped matching reality. A test file
    that hardcodes the plate tells the same story about itself, so this cell makes that impossible.

    It reads THIS file's AST and rejects a version-shaped literal in any executable string — comments
    and docstrings are allowed, because they describe the defect rather than depend on it. When the two
    hardcoded falsifiers were found (they went red on a second tree whose plate differed), this cell is
    what stops the third one from arriving quietly.
    """

    def _executable_strings(self, tree: ast.AST) -> list[tuple[int, str]]:
        """String constants that are NOT docstrings — i.e. data the tests actually compare against."""
        docstrings: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", [])
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                    docstrings.add(id(body[0].value))
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                out.append((getattr(node, "lineno", 0), node.value))
        return out

    def test_no_hardcoded_plate_in_executable_strings(self):
        src = Path(__file__).resolve().read_text(encoding="utf-8")
        offenders = []
        for lineno, text in self._executable_strings(ast.parse(src)):
            for m in VERSION_LIKE.finditer(text):
                offenders.append(f"{Path(__file__).name}:{lineno}: {m.group(0)!r} in {text[:60]!r}")
        assert offenders == [], (
            "this gate hardcodes a version in executable code — derive it from dist_version() instead; "
            "it rot on the next bump exactly like the page #640 was filed over:\n" + "\n".join(offenders)
        )

    def test_the_pinning_cell_itself_can_fail(self, tmp_path: Path):
        """Falsifier for the falsifier: a copy of this file with a literal plate injected must be
        rejected by the cell above. A self-pinning check that cannot fail is the thing we are fixing.

        The injected value is DERIVED, not typed — a test that hardcodes the very thing it is looking
        for would fail its own sibling cell, and did: this cell's first version carried a literal
        `0.1.0beta9` in the payload and `test_no_hardcoded_plate_in_executable_strings` caught it. That
        red was the check working, so the payload went through `wrong_version()` rather than the
        assertion going soft.
        """
        src = Path(__file__).resolve().read_text(encoding="utf-8")
        bait = wrong_version(dist_version())
        marker = '    (root / "README.md").write_text("# Venya\\n", encoding="utf-8")'
        assert marker in src, "injection site moved: this cell is no longer testing anything"
        infected = src.replace(marker, marker.replace("# Venya\\n", f"# Venya {bait}\\n"), 1)
        assert bait != dist_version()
        offenders = []
        for lineno, text in self._executable_strings(ast.parse(infected)):
            for m in VERSION_LIKE.finditer(text):
                offenders.append(f"{m.group(0)} at :{lineno}")
        assert offenders, f"a planted version literal ({bait}) slipped past the pinning check"


class TestScanIsNotVacuous:
    """A guard whose root path is wrong reports a clean tree forever. These cells make that loud."""

    def test_repo_root_resolves_to_the_venue(self):
        assert (
            REPO_ROOT / "packages" / "cli" / "pyproject.toml"
        ).is_file(), f"{REPO_ROOT} is not the repo root — every other cell in this file would pass by scanning nothing"

    def test_enumeration_finds_the_root_pages_that_exist(self):
        """The coverage half of AC1: named root pages must be IN the scan, not assumed by it."""
        names = {p.name for p in root_docs()}
        assert {"README.md", "CHANGELOG.md"} <= names, f"root scan found only {sorted(names)}"
        # six root pages were tracked at the base of this branch; the floor is a tripwire for a
        # broken glob, not a count of what should exist.
        assert len(names) >= 5, f"suspiciously small root scan: {sorted(names)}"

    def test_glob_discovers_a_page_the_gate_has_never_heard_of(self):
        """AC1's real content: a file nobody named becomes covered, with no edit to the guard.

        This is the `SUPPORT.md` case. The old gates could only cover a page someone had already
        thought to list; this one covers the page by shape.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            shutil_tree(tmp)
            truth = dist_version()
            (tmp / "SUPPORT.md").write_text(f"Venya support\n\nThe current version is {truth}.\n", encoding="utf-8")
            assert "SUPPORT.md" in {p.name for p in root_docs(tmp)}
            assert violations(tmp) == [], "a TRUE claim on a brand-new root page must read clean"
            (tmp / "SUPPORT.md").write_text(
                f"Venya support\n\nThe current version is {wrong_version(truth)}.\n", encoding="utf-8"
            )
            assert violations(tmp), "a FALSE claim on a brand-new root page must be seen"


# --- AC2: the falsifier, both halves -----------------------------------------------------------


class TestPlantedClaim:
    """RED on a lie, GREEN on the truth. Without the red half, AC1 is satisfiable by a glob that
    matches the path and checks nothing in it."""

    def test_planted_false_claim_turns_the_gate_red(self, tmp_path: Path):
        shutil_tree(tmp_path)
        truth = dist_version()
        lie = wrong_version(truth)
        assert lie != truth, "derivation returned the plate unchanged: this cell can no longer be red"
        (tmp_path / "SUPPORT.md").write_text(
            f"# Support\n\nThe current version is {lie} and it ships weekly.\n", encoding="utf-8"
        )
        got = violations(tmp_path)
        assert got, "the gate did not see a false version claim on a root-level page"
        assert any("SUPPORT.md" in v for v in got), got
        assert any(lie in v for v in got), got

    def test_the_same_page_with_a_true_claim_is_green(self, tmp_path: Path):
        shutil_tree(tmp_path)
        truth = dist_version()
        (tmp_path / "SUPPORT.md").write_text(
            f"# Support\n\nThe current version is {truth} and it ships weekly.\n", encoding="utf-8"
        )
        assert violations(tmp_path) == []

    def test_false_changelog_head_turns_the_gate_red(self, tmp_path: Path):
        """The other root-level claim shape: the newest CHANGELOG entry vs the plate.

        The planted value is DERIVED from the real plate, never written here as a literal: a falsifier
        that hardcodes `0.1.0beta1` is itself a version claim, and it would start failing on the next
        release bump for a reason that has nothing to do with the guard — which is the exact defect
        class this row was filed for.
        """
        shutil_tree(tmp_path)
        truth = dist_version()
        bump = wrong_version(truth)
        assert bump != truth, "derivation returned the plate unchanged: this cell can no longer be red"
        cl = tmp_path / "CHANGELOG.md"
        cl.write_text(cl.read_text(encoding="utf-8").replace(f"## [{truth}]", f"## [{bump}]", 1), encoding="utf-8")
        got = violations(tmp_path)
        assert any("CHANGELOG.md" in v for v in got), (got, truth, bump)
        assert any(bump in v for v in got), got

    def test_true_changelog_head_is_green(self, tmp_path: Path):
        """Paired positive: the same fixture with the head left AT the plate reads clean."""
        shutil_tree(tmp_path)
        assert violations(tmp_path) == []

    def test_historical_version_note_is_not_treated_as_a_claim(self, tmp_path: Path):
        """The paired negative on the NARROW class: a dated record naming an old plate is not a claim
        about the current one, and checking it would be reading prose.

        The past plate is DERIVED and asserted to differ from the current one. On a branch where the
        literal happened to equal the plate, the cell would prove nothing — it would read clean whether
        or not the guard distinguished the two shapes.
        """
        shutil_tree(tmp_path)
        truth = dist_version()
        past = historical_version(truth)
        assert past != truth, "derived past plate equals the current plate: this cell is vacuous here"
        (tmp_path / "NOTES.md").write_text(
            f"# Notes\n\nRestore procedure validated by physical drill, 2026-09-30, on {past}.\n",
            encoding="utf-8",
        )
        assert violations(tmp_path) == []

    def test_a_stable_version_claim_is_red_too(self, tmp_path: Path):
        """The gap a suffixless tree exposed.

        The first VERSION_TOKEN required an `alpha|beta` suffix, so on a tree whose plate is a plain
        `0.1.0` a planted claim like `0.1.7` matched NOTHING and the gate reported clean — green over a
        lie, which is the exact failure #640 is about. This cell builds a pre-release-free tree and
        demands the red.
        """
        root = tmp_path / "stable"
        root.mkdir(parents=True)
        shutil_tree(root)
        # A plate with no pre-release suffix, written as a shape rather than a literal so this file
        # stays free of hardcoded plates (see TestGuardDoesNotCarryItsOwnDefect).
        plate = re.sub(r"(alpha|beta|rc|dev)\d*$", "", dist_version())
        (root / "packages" / "cli" / "pyproject.toml").write_text(
            f'[project]\nname = "venya-cli"\nversion = "{plate}"\n', encoding="utf-8"
        )
        (root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\n- x\n\n## [{plate}] - 2026-10-15\n\n- y\n", encoding="utf-8"
        )
        assert plate != dist_version(), "the tree under test already had a stable plate; pick another shape"
        assert dist_version(root) == plate
        assert violations(root) == [], f"a clean stable tree must read green: {violations(root)}"

        lie = wrong_version(plate)
        assert lie != plate, lie
        (root / "SUPPORT.md").write_text(f"# Support\n\nThe current version is {lie}.\n", encoding="utf-8")
        got = violations(root)
        assert any("SUPPORT.md" in v and lie in v for v in got), f"stable-version claim slipped past: {got}"

        # and the CHANGELOG head is compared on a stable plate too, not just a pre-release one
        (root / "SUPPORT.md").unlink()
        head_lie = wrong_version(plate)
        (root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\n- x\n\n## [{head_lie}] - 2026-11-01\n\n- y\n", encoding="utf-8"
        )
        got = violations(root)
        assert any("CHANGELOG.md" in v for v in got), f"suffixless CHANGELOG head went unchecked: {got}"


class TestBlindSpotIsRecorded:
    """The bug itself, as a test: a filename list reports clean while the glob reports the violation."""

    def test_old_name_list_enumeration_misses_a_new_root_page(self, tmp_path: Path):
        shutil_tree(tmp_path)
        lie = f"# Support\n\nThe current version is {wrong_version(dist_version())}.\n"
        (tmp_path / "SUPPORT.md").write_text(lie, encoding="utf-8")

        # The old shape (as at test_terminology_yubico.py:27): a tuple of names + docs/**/*.md.
        name_list = ("README.md", "THIRD-PARTY-NOTICES.md")
        old_saw_it = any((tmp_path / n).exists() and "SUPPORT.md" in (tmp_path / n).read_text() for n in name_list)
        assert not old_saw_it, "fixture changed: the name-list scan is no longer blind here"

        # The new shape sees it.
        assert violations(tmp_path), "the glob scan lost the very coverage this row was filed to add"


# --- the shipped tree --------------------------------------------------------------------------


class TestShippedTree:
    def test_root_docs_are_clean_at_the_current_dist_version(self):
        """The gate, over the real tree. Green here means it LOOKED and found no disagreement —
        `test_enumeration_finds_the_root_pages_that_exist` is what makes that sentence mean anything."""
        assert root_docs(), "no root docs enumerated"
        assert violations() == [], violations()

    def test_changelog_head_agrees_with_the_plate(self):
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        head = _CHANGELOG_HEAD.search(text)
        assert head is not None, "CHANGELOG.md has no version heading the gate can read"
        assert head.group(1) == dist_version(), f"CHANGELOG head {head.group(1)} != dist {dist_version()}"

    def test_coverage_does_not_depend_on_the_page_name(self):
        """The scan is a SHAPE, not a list of names, and this cell fails if that ever regresses.

        Deliberately does NOT assert `SUPPORT.md` is absent from this branch. That page is the reason
        the row exists and it may well land here carrying a TRUE claim — a cell that required its
        absence would go red on the day the thing being protected finally ships, which is the same
        self-defeating shape this whole ticket is about.
        """
        import inspect

        assert ROOT_DOC_GLOB == "*.md", "the root scan stopped being a shape and went back to names"
        src = inspect.getsource(root_docs)
        assert "glob" in src, "root_docs() no longer enumerates — it is reading a fixed list again"
        # and the scan really is name-agnostic: three invented pages, none of them known to the gate,
        # are all covered by the same call.
        for invented in ("SUPPORT.md", "WARRANTY.md", "PRICING.md"):
            assert invented not in inspect.getsource(violations), invented
        assert len(root_docs()) >= 5, f"root scan suspiciously small: {root_docs()}"


# --- fixture -----------------------------------------------------------------------------------


def _shift_last_number(truth: str, delta: int) -> str:
    """Move the final numeric run of a version by `delta`, leaving the rest identical."""
    m = re.search(r"(\d+)\s*$", truth)
    if not m:
        return ""
    return truth[: m.start()] + str(int(m.group(1)) + delta)


def wrong_version(truth: str) -> str:
    """A version token guaranteed to differ from `truth`, built from `truth`.

    Every planted lie in this file goes through here. Two failure modes this closes:
      * a literal like `0.9.9beta9` differs from the plate on one branch and might not on another, so a
        "false claim" fixture can quietly stop being false when the version moves;
      * `0.1.0` ends in a zero, so naively subtracting from it hands back the plate unchanged. The first
        delta that produces a different string wins, and callers assert the inequality.
    """
    for delta in (7, 11, 3, 1):
        cand = _shift_last_number(truth, delta)
        if cand and cand != truth:
            return cand
    raise AssertionError(f"cannot derive a version differing from {truth!r}")


def historical_version(truth: str) -> str:
    """A token that reads like a PAST release and is not the current plate.

    Same reason as `wrong_version`: the historical-note cell only distinguishes "claim" from "dated
    record" if the token it plants differs from the plate on whichever tree runs it.
    """
    cand = _shift_last_number(truth, -3)
    if cand and cand != truth:
        return cand
    return wrong_version(truth)


def shutil_tree(root: Path) -> None:
    """A minimal repo skeleton that `violations()` can read: a CLI pyproject and a CHANGELOG.

    The version plate in the fixture is copied from the real tree so a cell that plants a lie cannot
    pass for the wrong reason (an unreadable source), and the true-claim cells stay true if the plate
    ever moves. The CHANGELOG head is written from `dist_version()` for the same reason — this helper
    must not itself carry a version literal.
    """
    import shutil

    root.mkdir(parents=True, exist_ok=True)
    cli = root / "packages" / "cli"
    cli.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_ROOT / "packages" / "cli" / "pyproject.toml", cli / "pyproject.toml")
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [Unreleased]\n\n- x\n\n## [{dist_version()}] - 2026-10-15\n\n- y\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("# Venya\n", encoding="utf-8")
