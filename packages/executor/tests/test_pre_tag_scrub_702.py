# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#702 — the executable pre-commit/pre-tag scrub guard, tested both ways.

Leg 298 scrubbed the identifiers and widened the pytest interlock. This leg makes the
rule FIRE WITHOUT BEING REMEMBERED: `scripts/pre_tag_scrub.py` is wired into
`.pre-commit-config.yaml`, so every commit is judged, and it runs with `--stage pre-tag
--ref <rev>` against the tag candidate before `git tag`. That is the honest substitute
for the "CI gates the expanded guard" clause in the owner's #689 plan, which describes a
mechanism this repo does not have (measured at `87a743c`: zero CI config files of any
kind; the only automated gate is the pre-commit chain, and a pytest cell is voluntary).

What this file is NOT: a restatement of the pattern table. The vocabulary is imported,
and `test_installer_no_private_literals.py::TestOneVocabularyAndNarrowExclusions` pins
that the two consumers hold the same objects. Cells here judge the SCRIPT — its stages,
its refusals, and its claim to have read something.

Every negative runs through `run()`, the same function the hook entry calls, so a
fixture cannot pass by exercising a friendlier code path than production takes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "pre_tag_scrub.py"

sys.path.insert(0, str(_REPO_ROOT / "scripts"))
import pre_tag_scrub
import private_literals

#: A ref that shipped the identifiers this rule exists to refuse. The pin below is
#: deliberately a REAL commit, not a fixture: "a guard that cannot see the defect it
#: was written for, pointed at the commit that had it, is not a guard." Pinned by
#: `git cat-file -t` so a garbage-collected or rewritten ref fails as a named
#: instrument fault rather than a skipped cell.
PRE_SCRUB_REF = "802bbbd"


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    """A repo-shaped fixture tree: the bundle's top levels + a root doc."""
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for rel in pre_tag_scrub.SHIPPED_SURFACE[0]:
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)
    (tmp_path / "README.md").write_text("nothing private here\n")
    return tmp_path


def _big_clean_tree(tmp_path: Path) -> Path:
    """Clean, and BIG enough to clear the anti-vacuous file floor.

    `MIN_FILES` is a real refusal, so a fixture tree that wants a PASS verdict has to
    be honest about size — building it here rather than lowering the floor is the point:
    the floor is not negotiable per test.
    """
    files = {
        f"{root}/keep_{i}.py": "nothing private here\n" for root in pre_tag_scrub.SHIPPED_SURFACE[0] for i in range(80)
    }
    return _tree(tmp_path, files)


class TestStageRefusals:
    """The empty-surface law: an unread tree is a BROKEN guard, never a green one."""

    def test_empty_tree_refuses_rather_than_passes(self, tmp_path):
        rc, output = pre_tag_scrub.run("scan", tmp_path)
        assert rc == 1, "an empty surface passed — the guard advertises coverage it never read"
        assert "ZERO files" in output

    def test_tiny_tree_refuses_below_the_floor(self, tmp_path):
        """A surface that shrank to a handful of files is path drift, not cleanliness."""
        root = _tree(tmp_path, {"packages/one.py": "nothing private here\n"})
        rc, output = pre_tag_scrub.run("scan", root)
        assert rc == 1
        assert "below the" in output, f"expected the floor refusal, got: {output[:200]}"

    def test_the_floor_has_a_positive_half(self, tmp_path):
        """Paired negative for the floor: ABOVE it, a clean tree PASSES.

        Without this the refusal could be firing on any small tree for a reason that
        has nothing to do with `MIN_FILES`, and the floor would be a claim rather than
        a measured bound. Both halves read the same `surface_files` count the verdict
        branches on, so the number and the decision cannot disagree.
        """
        floor = pre_tag_scrub.MIN_FILES

        # Sub-floor: derived from the count the verdict actually reads, not from a
        # guessed number of files — `_tree` also writes a root README.md, so an
        # earlier draft of this cell built floor-1 files, measured floor, and passed
        # while claiming to prove the refusal.
        under = _tree(tmp_path / "under", {f"packages/p{i}.py": "clean\n" for i in range(floor // 2)})
        read_under = len(pre_tag_scrub.surface_files(under, pre_tag_scrub.SHIPPED_SURFACE))
        assert read_under < floor, f"fixture did not land under the floor: read {read_under}"
        rc, output = pre_tag_scrub.run("scan", under)
        assert rc == 1 and "below the" in output, f"a sub-floor clean tree must trip the floor, got rc={rc}"

        # At/over-floor positive half.
        over = _tree(tmp_path / "over", {f"packages/p{i}.py": "clean\n" for i in range(floor + 1)})
        read_over = len(pre_tag_scrub.surface_files(over, pre_tag_scrub.SHIPPED_SURFACE))
        assert read_over >= floor, f"fixture did not clear the floor: read {read_over}"
        rc, output = pre_tag_scrub.run("scan", over)
        assert rc == 0, f"an at-floor clean tree must pass, got: {output[:200]}"

    def test_pre_tag_without_a_ref_fails_loud(self, tmp_path):
        rc, output = pre_tag_scrub.run("pre-tag", tmp_path, ref=None)
        assert rc == 1 and "--ref" in output, "pre-tag defaulted to the worktree — a dirty tree could flatter a tag"

    def test_unreadable_ref_fails_closed(self, tmp_path):
        root = _big_clean_tree(tmp_path)
        rc, output = pre_tag_scrub.run("pre-tag", root, ref="no-such-ref-xyz")
        assert rc == 1
        assert "cannot read ref" in output

    def test_cli_missing_ref_exits_nonzero(self):
        """The operator-facing shape: the hook must not exit 0 on a bad invocation."""
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--stage", "pre-tag"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1, proc.stdout + proc.stderr


class TestDetectionAndGreenForms:
    """All four classes redden; the sanctioned replacements and lookalikes stay green."""

    @pytest.mark.parametrize("cls", sorted(private_literals.PRIVATE_CLASSES))
    def test_each_class_reds_its_own_fixture(self, tmp_path, cls):
        fixture = private_literals.DETECTION_FIXTURES[cls]
        root = _tree(tmp_path, {"docs/page.md": fixture + "\n"})
        rc, output = pre_tag_scrub.run("scan", root)
        assert rc == 1, f"{cls} fixture went green: {output[:200]!r}"
        assert output.count(cls) >= 1, f"the failure did not name the class that fired: {output[:200]}"

    def test_the_ip_only_pattern_could_never_have_seen_the_hostname(self):
        """The contrast that makes hole 1 a measurement, not a story."""
        line = private_literals.IP_BLIND_FIXTURE
        assert private_literals.RFC1918.search(line) is None, (
            "the IP-only pattern now matches the hostname fixture — the #689 premise "
            "that six files were invisible to it is false, and this cell must be "
            "re-derived rather than deleted"
        )
        assert private_literals.DEV_HOSTNAME.search(line)

    def test_sanctioned_replacements_stay_green(self, tmp_path):
        """The guard must not refuse the forms the scrub tells people to use."""
        root = _big_clean_tree(tmp_path)
        for i, example in enumerate(private_literals.SANCTIONED_EXAMPLES):
            (root / "docs" / f"sanctioned_{i}.md").write_text(example + "\n")
        rc, output = pre_tag_scrub.run("scan", root)
        assert rc == 0, f"a sanctioned form reddened: {output[:400]}"

    def test_lookalikes_stay_green(self, tmp_path):
        """Boundary law: a word that merely CONTAINS a site name is not that name."""
        root = _big_clean_tree(tmp_path)
        for i, lookalike in enumerate(private_literals.LOOKALIKE_EXAMPLES):
            (root / "docs" / f"lookalike_{i}.md").write_text(lookalike + "\n")
        rc, output = pre_tag_scrub.run("scan", root)
        assert rc == 0, f"the boundaries are decoration and ordinary prose burns: {output[:400]}"

    def test_the_shipped_cn_shape_reds_and_the_replacement_greens(self):
        """Both directions of the `(?![\\w])` choice in one cell.

        A site name carrying the shipped `-relay` CN suffix is a disclosure — the
        boundary deliberately does NOT stop at a hyphen, or every real relay CN would
        slip past. The sanctioned `core-1-relay` looks exactly as hyphenated and must
        stay green. The refused spelling is never written here: this leg's own guard
        reddened a docstring that did, which is the rule working on the seat that
        wrote it, and the fix was to name the class rather than add an exclusion.
        """
        assert private_literals.DEV_HOSTNAME.search(private_literals.RELAY_CN_FIXTURE)
        assert not private_literals.DEV_HOSTNAME.search("core-1-relay")


class TestAgainstRealHistory:
    """The bar the spec set: point it at the commit that HAD the defect."""

    def test_pinned_pre_scrub_ref_resolves(self):
        """Instrument fault guard first: a missing ref is not a green run."""
        proc = subprocess.run(
            ["git", "cat-file", "-t", PRE_SCRUB_REF],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"pin {PRE_SCRUB_REF} does not resolve: {proc.stderr.strip()}"
        assert proc.stdout.strip() == "commit"

    def test_reddens_at_the_pre_scrub_face(self):
        """The #689 face must fail, with every class represented.

        Numbers are asserted as `>=` per class rather than exact counts, because an
        exact count re-rots the moment history is rewritten on this repo (it has been,
        once, in October) while the claim that matters is CLASS coverage.
        """
        rc, output = pre_tag_scrub.run("pre-tag", _REPO_ROOT, ref=PRE_SCRUB_REF)
        assert rc == 1, "the guard went GREEN at the commit that shipped the identifiers — it is not a guard"
        for cls in private_literals.PRIVATE_CLASSES:
            assert output.count(cls) >= 1, f"class {cls} fired nothing at the pre-scrub face: {output[:300]}"

    def test_green_at_this_tip(self):
        """The bar for landing: the same code, the same repo, zero hits now.

        This is the pair to the cell above — same `run()`, same tree, two refs, two
        answers. A guard that reddens everything is as useless as one that reddens
        nothing, and this is the half that proves the difference is the code, not the
        tool.
        """
        rc, output = pre_tag_scrub.run("pre-tag", _REPO_ROOT, ref="HEAD")
        assert rc == 0, output


class TestSuppliedFilesAreJudgedToo:
    """The release recipe's guard clause reads "zero operator-private-identifier hits
    (staged scripts **+ notes**)". Release notes are not in the tree when the check
    runs, so `--path` brings them into the SAME vocabulary. Two cells, both directions,
    because a flag that silently skips an unreadable file would pass the very thing the
    clause is about."""

    def test_a_dirty_supplied_file_reds(self, tmp_path):
        # `pre-tag` reads a REF, so the root must be a repo: this is the recipe's real
        # shape (tag candidate + notes file), not a fixture tree. An earlier draft
        # passed a tmp_path here and the stage correctly refused it — the instrument
        # fault was the cell, not the guard.
        notes = tmp_path / "notes.md"
        notes.write_text(private_literals.DETECTION_FIXTURES["dev-hostname"] + "\n")
        rc, output = pre_tag_scrub.run("pre-tag", _REPO_ROOT, ref="HEAD", extra=[str(notes)])
        assert rc == 1, "a private identifier in the release notes went green"
        assert "notes.md" in output and "supplied file" in output, output[:220]

    def test_a_clean_supplied_file_stays_green(self, tmp_path):
        notes = tmp_path / "notes.md"
        notes.write_text("Addresses in these notes use RFC 5737 documentation ranges.\n")
        rc, output = pre_tag_scrub.run("pre-tag", _REPO_ROOT, ref="HEAD", extra=[str(notes)])
        assert rc == 0, f"a clean notes file reddened: {output[:200]}"

    def test_a_missing_supplied_file_refuses_rather_than_skipping(self, tmp_path):
        """The failure mode this exists to prevent: a recipe that names a file nobody
        wrote, and reads green because the tool shrugged and moved on."""
        rc, output = pre_tag_scrub.run("pre-tag", _REPO_ROOT, ref="HEAD", extra=[str(tmp_path / "absent.md")])
        assert rc == 1 and "not a readable file" in output, f"missing --path went quiet: rc={rc} {output[:160]}"


class TestHookIsWiredAndAffordable:
    """A hook nobody installed, or one that costs a minute per commit, is not enforcement."""

    def _hook_entry(self) -> dict[str, str]:
        text = (_REPO_ROOT / ".pre-commit-config.yaml").read_text()
        assert "pre_tag_scrub.py" in text, "the guard is NOT wired into the pre-commit chain"
        block = text[text.index("pre_tag_scrub.py") :]
        entry = {}
        for line in block.splitlines()[:12]:
            stripped = line.strip()
            if ":" in stripped and not stripped.startswith("#"):
                key, _, value = stripped.partition(":")
                entry[key.strip()] = value.strip()
        return entry

    def test_pre_commit_entry_exists_with_the_right_shape(self):
        entry = self._hook_entry()
        assert entry.get("language") == "system", entry
        assert entry.get("pass_filenames") == "false", entry
        assert entry.get("always_run") == "true", entry

    def test_the_wired_command_actually_runs(self):
        """Not a config-file assertion — the real entry, in a subprocess, on this tree."""
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--stage", "pre-commit"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"the hook as configured fails at the tip: {proc.stdout}{proc.stderr}"
        assert "shipped files scanned" in proc.stdout

    def test_run_cost_is_stated_not_assumed(self):
        """Every seat pays this on every commit. Bound it, and print the number."""
        import time

        started = time.monotonic()
        rc, _output = pre_tag_scrub.run("pre-commit", _REPO_ROOT)
        elapsed = time.monotonic() - started
        assert rc == 0
        # 4s ceiling: measured ~1.3s cold on this box. A ceiling that is comfortably
        # above the measurement still catches the regression that matters — a scan that
        # starts walking `.venv` or `target` (thousands of files) and takes minutes.
        assert elapsed < 4.0, f"the pre-commit hook costs {elapsed:.1f}s — every lane feels that"
