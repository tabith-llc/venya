# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: shipped artifacts carry ZERO private-range literals AND zero
private site identities.

Regression guard for ticket installer-default-egress-allowlist-dev-subnet
(owner ruling 2026-09-23, options (a)+(c)): the executor installer once
seeded the DEV-fleet subnet 10.27.28.0/24 into every customer's egress
allowlist, and the literal shipped in every whole-tree tarball plus the
standalone venya-common.sh release asset. The default is now teaching-empty
(fail-closed) with an explicit VENYA_EGRESS_ALLOW seed knob that aborts
loudly on any invalid entry.

This test fails if a private-range default is ever restored anywhere in the
installer surface. Scope note: product defaults + fixtures elsewhere in the
tree belong to ticket private-infra-product-defaults-and-fixtures; when that
sweep lands, extend this guard tree-wide.

**That extension happened, and it needed two more halves (ticket #689, owner
ruling 2026-10-21: "beta release cannot happen with this info present! we will
scrub BEFORE tagging.").** The extension left two structural holes, both found
by reading this file rather than by trusting its name:

1. **IP-literal-only.** An RFC1918 regex cannot see a hostname (`montana`,
   `idaho`), an operator email (`dust@…`) or a workspace path (`/media/dust`).
   The 2026-10 tree sweep therefore cleaned the addresses and shipped the site
   names. `DEV_HOSTNAME`, `OPERATOR_IDENTITY` and `WORKSPACE_PATH` close that.
2. **Scan-root blind spot.** `BUNDLE_SCAN_ROOTS` used to be `("packages",
   "docs")`, while the served bundle ships `packages/ docs/ tests/ scripts/
   systemd/` PLUS root-level `*.md`. So the root `CHANGELOG.md` — the file
   holding the most identifiable values — was never opened by the tree-wide
   cell, and its name in `INTERLOCK_EXCLUDES` was dead weight hiding that fact.
   The scan surface is now derived from what the bundle ships.

Both holes carry paired negatives in `TestGuardCoversItsOwnBlindSpots`: the
same fixture line that the widened classes redden, the old IP-only pattern
leaves green; and a fixture in a ROOT `CHANGELOG.md` is invisible to the old
root pair and caught by the new surface. A guard that only ever passes is not
a guard.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

ARTIFACT_GLOBS = (
    "install-venya-*.sh",
    "uninstall-venya-*.sh",
    "install-venya-cli.ps1",
    "uninstall-venya-cli.ps1",
    "venya-common.sh",
)

# ONE vocabulary, imported from `scripts/private_literals.py` — the same module the
# executable pre-commit/pre-tag guard (`scripts/pre_tag_scrub.py`, #702) loads.
#
# Leg 298 wrote these patterns inline right here. When the second consumer arrived,
# inline became a FORK: two files free to disagree about what counts as private,
# which is exactly the #689 mechanism (a rule written in one place, applied in
# another). `test_the_two_consumers_share_one_vocabulary` pins object identity, so
# re-copying the table into either file goes red rather than drifting quietly.
#
# It also means this file names the refused tokens in order to refuse them, so it
# must be excluded from its own scan — and the exclusion list is the module's, which
# is TWO exact filenames and nothing else. The narrowness is tested, not asserted
# (`test_vocabulary_exclusion_cannot_hide_a_real_file`).
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import private_literals
from private_literals import (
    DETECTION_FIXTURES,
    HISTORICAL_ADDRESS_FIXTURE,
    LOOKALIKE_EXAMPLES,
    RELAY_CN_FIXTURE,
    SANCTIONED_EXAMPLES,
)

# Re-exported under the names the cells below already use: one spelling for readers,
# one definition in the repo.
RFC1918 = private_literals.RFC1918
PRIVATE_CLASSES = private_literals.PRIVATE_CLASSES
BUNDLE_SCAN_ROOTS = private_literals.BUNDLE_SCAN_ROOTS
BUNDLE_SCAN_ROOT_GLOBS = private_literals.BUNDLE_SCAN_ROOT_GLOBS
INTERLOCK_EXCLUDES = private_literals.VOCABULARY_BEARERS
INTERLOCK_EXCLUDE_DIRS = private_literals.EXCLUDED_DIRS
INTERLOCK_EXCLUDE_SUFFIXES = private_literals.EXCLUDED_SUFFIXES

#: The PRE-widening surface, kept as a named constant so the paired negative can
#: prove the old check was blind instead of asserting that in prose. The empty
#: root-glob tuple is not a detail: it is the whole second half of hole 2.
OLD_SURFACE = private_literals.LEGACY_SURFACE
SHIPPED_SURFACE = private_literals.SHIPPED_SURFACE


def _artifacts() -> list[Path]:
    files = sorted({p for g in ARTIFACT_GLOBS for p in REPO_ROOT.glob(g)})
    assert files, f"no installer artifacts matched {ARTIFACT_GLOBS} at {REPO_ROOT} — path drift?"
    return files


def _is_scannable(p: Path) -> bool:
    return (
        p.is_file()
        and not any(d in p.parts for d in INTERLOCK_EXCLUDE_DIRS)
        and p.name not in INTERLOCK_EXCLUDES
        and p.name != Path(__file__).name
        and p.suffix not in INTERLOCK_EXCLUDE_SUFFIXES
    )


#: Every shipped text file under `root`, per a scan surface. `Surface` =
#: (walked sub-trees, root-level globs), so a paired-negative test can run the
#: guard against a synthetic tree under EITHER the widened surface or the
#: pre-#689 one. Without that the blind-spot cells could only assert the guard
#: PASSES — which is exactly the untested half this file has a history of.
Surface = tuple[tuple[str, ...], tuple[str, ...]]


def _tree_files(root: Path = REPO_ROOT, surface: Surface = SHIPPED_SURFACE):
    scan_roots, root_globs = surface
    for scan_root in scan_roots:
        for p in (root / scan_root).rglob("*"):
            if _is_scannable(p):
                yield p
    # Root-level shipped docs (the bundle carries CHANGELOG/README/SECURITY/…
    # at the top level), filtered by the SAME predicate — a file that skips the
    # filter would also skip the exclusion rules, and that asymmetry is how a
    # scan surface quietly grows an exempt class.
    for glob in root_globs:
        for p in sorted(root.glob(glob)):
            if _is_scannable(p):
                yield p


def _offending_lines(text: str) -> list[tuple[str, int, str]]:
    """(class, line-number, line) for every private literal in one file's text."""
    found: list[tuple[str, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for cls, pattern in PRIVATE_CLASSES.items():
            if pattern.search(line):
                found.append((cls, lineno, line.strip()))
    return found


def _scan_tree(root: Path = REPO_ROOT, surface: Surface = SHIPPED_SURFACE) -> tuple[int, list[str]]:
    """(files scanned, offender descriptors) — the tree-wide cell and its
    negatives all read through this one function, so a fixture cannot pass by
    testing a different code path than the real check takes."""
    offenders: list[str] = []
    scanned = 0
    for path in _tree_files(root, surface):
        scanned += 1
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue  # binary/undecodable — not a shipped text literal
        for cls, lineno, _line in _offending_lines(text):
            rel = path.relative_to(root) if path.is_relative_to(root) else path
            offenders.append(f"{cls}: {rel}:{lineno}")
    return scanned, offenders


class TestInstallerNoPrivateLiterals:
    def test_artifact_glob_finds_the_shipped_surface(self):
        """Paired negative for the sweep: the guard must not pass because the
        surface silently shrank or moved (empty-glob = green = worthless)."""
        names = {p.name for p in _artifacts()}
        assert "venya-common.sh" in names
        assert "install-venya-executor.sh" in names
        assert "install-venya-core.sh" in names
        assert "install-venya-cli.sh" in names
        # 3 installers + 3 uninstallers + 2 ps1 + venya-common.sh
        assert len(names) >= 9, f"shipped installer surface shrank: {sorted(names)}"

    def test_zero_private_literals_in_installer_artifacts(self):
        """Widened from IP-only: an installer script naming a dev host or a
        developer workspace path is the same disclosure class as one seeding a
        dev subnet, and #689 found the guard could only see the last one."""
        offenders = []
        for path in _artifacts():
            for cls, lineno, line in _offending_lines(path.read_text()):
                offenders.append(f"{cls}: {path.name}:{lineno}: {line.strip()}")
        assert not offenders, (
            "private-range literals in shipped installer artifacts — the "
            "egress default is teaching-empty by owner ruling "
            "(installer-default-egress-allowlist-dev-subnet):\n" + "\n".join(offenders)
        )

    def test_rfc1918_pattern_catches_the_historical_defect(self):
        """The regex must actually match the literal it exists to prevent."""
        assert RFC1918.search("10.27.28.0/24")
        assert RFC1918.search("DNS to 10.27.28.1")
        assert not RFC1918.search("203.0.113.0/24")  # RFC 5737 examples stay legal
        assert not RFC1918.search("version 1.10.27")

    def test_zero_private_literals_tree_wide(self):
        """The tree-wide cell, widened from IP-only to every private class, and
        from `packages`+`docs` to the surface the bundle actually ships.

        shortcut: matches full dotted quads only — bare class shorthand
        (10/8) and IPv6 ULA (fc00::/7) are NOT caught; CIDRs whose base is
        a full dotted quad DO match (the self-test pins prove it). Hostname,
        identity and path classes match on bounded words, so an unrelated word
        containing one (e.g. `idahox`) does not trip — pinned by
        `test_widened_classes_do_not_eat_lookalikes`.
        """
        scanned, offenders = _scan_tree()
        assert scanned > 50, f"tree scan surface shrank to {scanned} — path drift?"
        assert not offenders, (
            "private literals in the shipped tree. Addresses: use RFC 5737 "
            "(192.0.2/198.51.100/203.0.113). Identities: use admin@example.com. "
            "Hostnames: use a `<core-host>`-shaped example, not a site name. "
            "Paths: use a workspace-relative form.\n" + "\n".join(sorted(offenders))
        )


class TestGuardCoversItsOwnBlindSpots:
    """Paired negatives for the two holes this file shipped with (#689).

    A filter/gate check that is tested only on the side it permits is untested,
    so each cell here runs BOTH halves: the fixture reddens the widened guard,
    and the same fixture is provably invisible to the shape the guard had
    before. That second half is what makes the blind spot a measured fact
    instead of a claim in a docstring.
    """

    # All fixtures are imported from `private_literals`, not written here: the
    # refused tokens live in exactly two files in the repo (this one and the module),
    # and a third copy in a test would need a third exclusion. `DETECTION_FIXTURES`
    # is keyed by class, so a new class with no negative is a KeyError, not a green.
    HOST_FIXTURE = DETECTION_FIXTURES["dev-hostname"] + "\n"
    IDENTITY_FIXTURE = DETECTION_FIXTURES["operator-identity"] + "\n"
    ADDRESS_FIXTURE = DETECTION_FIXTURES["rfc1918-address"] + "\n"
    PATH_FIXTURE = DETECTION_FIXTURES["workspace-path"] + "\n"
    RELAY_CN_LINE = RELAY_CN_FIXTURE + "\n"
    HISTORICAL_ADDRESS = HISTORICAL_ADDRESS_FIXTURE + "\n"
    SANCTIONED_RELAY_CN_LINE = RELAY_CN_FIXTURE.replace("idaho", "core-1") + "\n"
    SANCTIONED_LINES = tuple(f"{example}\n" for example in SANCTIONED_EXAMPLES)
    LOOKALIKE_LINES = tuple(f"{lookalike}\n" for lookalike in LOOKALIKE_EXAMPLES)

    def test_hostname_class_reds_and_the_old_ip_pattern_missed_it(self):
        """THE contrast that proves hole 1 was real, in both directions."""
        classes = [cls for cls, _n, _l in _offending_lines(self.HOST_FIXTURE)]
        assert "dev-hostname" in classes, "a `montana` fixture must redden the widened guard"
        assert RFC1918.search(self.HOST_FIXTURE) is None, (
            "the IP-only pattern caught the hostname fixture — then the #689 "
            "finding that six files were invisible to it is wrong and this cell "
            "is lying about its own premise"
        )

    def test_identity_and_path_classes_red(self):
        assert "operator-identity" in [c for c, _n, _l in _offending_lines(self.IDENTITY_FIXTURE)]
        assert "workspace-path" in [c for c, _n, _l in _offending_lines(self.PATH_FIXTURE)]
        assert "rfc1918-address" in [c for c, _n, _l in _offending_lines(self.ADDRESS_FIXTURE)]

    def test_sanctioned_replacement_forms_stay_green(self):
        """The guard must not eat its own replacements — otherwise the scrub is
        unshippable and the check is a lie about the convention it names."""
        for fixture in self.SANCTIONED_LINES + (self.SANCTIONED_RELAY_CN_LINE,):
            assert _offending_lines(fixture) == [], f"green-by-design fixture reddened: {fixture.strip()!r}"

    def test_widened_classes_do_not_eat_lookalikes(self):
        """Negative half of the boundary: a word that merely CONTAINS a site
        name is not the site name, and a relative path is not a workspace mount."""
        for benign in self.LOOKALIKE_LINES + (self.SANCTIONED_RELAY_CN_LINE,):
            assert _offending_lines(benign) == [], f"lookalike tripped the guard: {benign.strip()!r}"

    def test_root_changelog_reds_now_and_was_invisible_before(self):
        """THE contrast that proves hole 2 was real: same fixture, same
        content, two scan surfaces. The old `packages`+`docs` pair could not
        see a root-level file at all — so widening the regex alone would still
        have shipped the changelog dirty."""
        root = self._scratch_repo(private_in_root_changelog=True)
        widened_count = len(_scan_tree(root)[1])
        old_surface_count = len(_scan_tree(root, OLD_SURFACE)[1])
        assert widened_count > 0, "the widened surface missed a private literal in a root CHANGELOG.md"
        assert old_surface_count == 0, (
            "the pre-#689 root pair CAUGHT the root changelog — so this cell's "
            "premise (that the scan-root hole was real) is false; re-derive it "
            "rather than letting the proof go quietly"
        )

    def test_widened_surface_scans_every_bundle_root(self):
        """Positive half of the scan-root pin: the guard must walk each top
        level the bundle ships, not merely claim to."""
        root = self._scratch_repo(private_in_root_changelog=False)
        for rel_root in BUNDLE_SCAN_ROOTS:
            (root / rel_root).mkdir(parents=True, exist_ok=True)
            (root / rel_root / "probe.txt").write_text(self.HOST_FIXTURE)
        _scanned, offenders = _scan_tree(root)
        assert len(offenders) == len(BUNDLE_SCAN_ROOTS), (
            f"expected one offender per bundle root ({len(BUNDLE_SCAN_ROOTS)}), "
            f"got {offenders} — a root is silently outside the walk"
        )

    def test_generated_output_exclusion_cannot_hide_source(self):
        """The `target`/`build` directory exclusion is for generated output
        only. This pins that a SAME-named file outside those directories is
        still caught, so the exclusion cannot become a general hiding place."""
        root = self._scratch_repo(private_in_root_changelog=False)
        for rel in ("packages/executor/target/root-output", "packages/executor/src/realness.txt"):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.PATH_FIXTURE)
        _scanned, offenders = _scan_tree(root)
        assert len(offenders) == 1, f"expected exactly the non-generated file to red, got {offenders}"
        assert "realness.txt" in offenders[0]

    def test_scan_surface_refuses_to_pass_by_scanning_nothing(self):
        """The empty-surface negative at the real repo: if a path refactor ever
        moves the tree, the check must go red, not green."""
        scanned, _offenders = _scan_tree()
        assert scanned > 500, f"real scan surface is only {scanned} files — path drift or a bad exclusion"

    @staticmethod
    def _scratch_repo(private_in_root_changelog: bool) -> Path:
        """A minimal tree shaped like the repo root: the bundle's top levels +
        a root CHANGELOG.md. Built per call so no fixture can leak state."""
        import tempfile

        root = Path(tempfile.mkdtemp(prefix="private-literal-guard-fixture-"))
        for rel_root in OLD_SURFACE[0]:
            (root / rel_root).mkdir(parents=True, exist_ok=True)
            (root / rel_root / "clean.txt").write_text("nothing private here\n")
        changelog = (
            TestGuardCoversItsOwnBlindSpots.HOST_FIXTURE + TestGuardCoversItsOwnBlindSpots.ADDRESS_FIXTURE
            if private_in_root_changelog
            else "nothing private here\n"
        )
        (root / "CHANGELOG.md").write_text(changelog)
        return root


class TestOneVocabularyAndNarrowExclusions:
    """#702 pins: the interlock and the executable hook cannot disagree about what
    counts as private, and the files exempt from the rule are exempt by exact name.

    Both halves are the failure class this ticket is about. A rule restated is a rule
    that drifts (that is literally how #689 shipped: an IP rule written in one place,
    applied in another), and an exclusion list that grows by directory or prefix stops
    being an exception and becomes a hole.
    """

    def test_the_two_consumers_share_one_vocabulary(self):
        """Object identity, not equal content — a copied table would read identical."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import pre_tag_scrub

        assert pre_tag_scrub.PRIVATE_CLASSES is PRIVATE_CLASSES, (
            "scripts/pre_tag_scrub.py and this interlock hold DIFFERENT pattern tables; "
            "one owner rule now has two vocabularies that can drift, which is the #689 "
            "mechanism reproduced inside the guard written to stop it"
        )
        # And the SCAN, not just the table: `pre_tag_scrub.offending_lines` must be the
        # module's function, not a local re-implementation with the same name.
        assert pre_tag_scrub.offending_lines is private_literals.offending_lines, (
            "the hook re-implements the scan instead of importing it — two code paths "
            "judging one rule, so a fix to one silently leaves the other behind"
        )

    def test_every_class_has_a_negative_that_reds_it(self):
        """A class added without a paired negative is a KeyError here, not a silent
        green in the tree-wide cell — the table cannot grow untested."""
        for cls in PRIVATE_CLASSES:
            assert cls in DETECTION_FIXTURES, f"class {cls!r} ships with no negative fixture"
            assert cls in _class_of(
                DETECTION_FIXTURES[cls]
            ), f"fixture for {cls!r} does not redden its own class: {_class_of(DETECTION_FIXTURES[cls])}"

    def test_vocabulary_exclusion_cannot_hide_a_real_file(self):
        """The exclusion is two EXACT filenames. A same-token file anywhere else,
        including beside the vocabulary, still reddens."""
        root = _scratch_repo()
        planted = root / "scripts" / "not_the_vocabulary.py"
        planted.write_text(DETECTION_FIXTURES["dev-hostname"] + "\n")
        _scanned, offenders = _scan_tree(root)
        assert any("not_the_vocabulary.py" in o for o in offenders), (
            f"the vocabulary exclusion is wider than two filenames — a planted file "
            f"next to the vocabulary went unseen: {offenders}"
        )

    def test_the_vocabulary_bears_itself_and_is_still_excluded(self):
        """Positive half of the same pin: the module DOES carry the tokens (it must,
        to refuse them), and IS exempt — so the exemption is real, not aspirational."""
        vocab = REPO_ROOT / "scripts" / private_literals.PRIVATE_LITERALS_FILENAME
        assert vocab.is_file()
        assert _offending_lines(vocab.read_text()), (
            "the vocabulary module contains no refused token, so it is not the source "
            "of the rule this interlock reads — path drift, and the import is stale"
        )
        assert private_literals.PRIVATE_LITERALS_FILENAME in INTERLOCK_EXCLUDES

    def test_pre_tag_script_names_the_surface_it_scans(self):
        """The hook and this interlock must walk the SAME top levels, or the release
        recipe guards a different tree than the commit does."""
        assert tuple(private_literals.BUNDLE_SCAN_ROOTS) == tuple(BUNDLE_SCAN_ROOTS)


def _class_of(line: str) -> list[str]:
    return [cls for cls, _n, _l in _offending_lines(line)]


def _scratch_repo() -> Path:
    """A clean repo-shaped fixture. No `clean_tree` flag: the one caller that wants a
    dirty tree PLANTS the dirty file itself, which is the point of that cell."""
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="private-literals-vocab-"))
    for rel in BUNDLE_SCAN_ROOTS:
        (root / rel).mkdir(parents=True, exist_ok=True)
        (root / rel / "keep.txt").write_text("nothing private here\n")
    (root / "README.md").write_text("nothing private here\n")
    return root


class TestTeachingDefaultPinned:
    """Positive half: the literal guard must not be passable by deleting the
    feature. Pins the ruled design's load-bearing pieces."""

    def test_allowlist_writer_is_teaching_empty_with_loud_knob(self):
        common = (REPO_ROOT / "venya-common.sh").read_text()
        assert "EMPTY BY DESIGN" in common
        assert "VENYA_EGRESS_ALLOW" in common
        assert "venya_validate_egress_entry" in common
        # abort-before-write contract: invalid knob input never half-applies
        assert "nothing was written" in common
        # operator teaching: file is read at sandbox creation, no restart
        assert "next command run" in common
        # re-run contract preserved
        assert "not overwriting" in common
