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

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

ARTIFACT_GLOBS = (
    "install-venya-*.sh",
    "uninstall-venya-*.sh",
    "install-venya-cli.ps1",
    "uninstall-venya-cli.ps1",
    "venya-common.sh",
)

# Any RFC1918 literal (superset of the dev-topology 10.27.27.x / 10.27.28.x
# ranges). Lookarounds keep version strings and longer numerics out.
RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
)

# The half the IP regex was structurally blind to: development/estate HOSTNAMES.
# Bounded so `core-1-relay`, `idahox` or `montanahauser` cannot match by
# accident, and unanchored to a word-start hyphen so `venya-test-workstation`
# style names still match on their own component.
DEV_HOSTNAME = re.compile(r"(?<![\w-])(?:montana|idaho|wyoming|colorado|utah|texas|venya-test-workstation)(?![\w])")

# An operator identity — the local part of the owner's address, in any domain.
# `admin@example.com` and `admin-bot@workstation` are the sanctioned fixture
# forms already used in this tree; a personal local part is not.
OPERATOR_IDENTITY = re.compile(r"(?<![\w.-])(?:dust|dusty|dustin)@")

# A developer workspace PATH. Scoped to the private mounts, NOT to "any
# absolute path": `/tmp/tabichat/…` is the sanctioned fleet scratch root and
# must keep working, or this guard blocks its own test harness.
WORKSPACE_PATH = re.compile(r"/(?:media/dust|home/dust|home/opencode)\b|dust-ext1")

#: Every class the shipped text must be free of, named so a failure says which
#: hole reopened rather than just printing a line.
PRIVATE_CLASSES: dict[str, re.Pattern[str]] = {
    "rfc1918-address": RFC1918,
    "dev-hostname": DEV_HOSTNAME,
    "operator-identity": OPERATOR_IDENTITY,
    "workspace-path": WORKSPACE_PATH,
}

#: The PRE-widening surface, kept as a named constant so the paired negative can
#: prove the old check was blind instead of asserting that in prose. The empty
#: root-glob tuple is not a detail: it is the whole second half of hole 2.
OLD_SURFACE: Surface = (("packages", "docs"), ())

# Tree-wide guard (ticket private-infra-product-defaults-and-fixtures, Stage 3;
# surface corrected by #689): no private literal in ANY shipped text surface.
# The bundle ships packages/ docs/ tests/ scripts/ systemd/ + root *.md, all
# counted from the live served venya-core-install.tar.gz (610/42/10/7/5 paths +
# the root files), so the scan is derived from what a customer actually fetches.
BUNDLE_SCAN_ROOTS = ("packages", "docs", "tests", "scripts", "systemd")
BUNDLE_SCAN_ROOT_GLOBS = ("*.md",)
# `CHANGELOG.md` USED to sit here under the comment "D3 — historical release
# record". It was never actually read (see hole 2), and a historical record does
# not require the literal: the changelog is scrubbed and scanned like the rest.
INTERLOCK_EXCLUDES = ("test_installer_no_private_literals.py",)  # self (docstring + pattern pins + fixtures)
INTERLOCK_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".mypy_cache",
    ".ruff_cache",
    # Generated BUILD output, never shipped: counted from the live bundles
    # (`tar tzf … | grep -c '/target/|/build/'` -> 0). A lane that builds the
    # Rust extension holds its own absolute workspace path in `target/…`, which
    # is local build state, not a shipped literal — see
    # TestGuardCoversItsOwnBlindSpots.test_generated_output_exclusion_cannot_hide_source.
    "target",
    "build",
}
INTERLOCK_EXCLUDE_SUFFIXES = (".lock",)  # uv.lock — generated


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
SHIPPED_SURFACE: Surface = (BUNDLE_SCAN_ROOTS, BUNDLE_SCAN_ROOT_GLOBS)


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

    HOST_FIXTURE = "read over SSH as win on montana (rc=0)\n"
    IDENTITY_FIXTURE = "identity: dust@montana\n"
    ADDRESS_FIXTURE = "seeded 10.27.28.0/24 in the allowlist\n"
    PATH_FIXTURE = "copies live in /media/dust/dust-ext1/tabith/reference-docs/\n"
    SANCTIONED_DOC_ADDRESS = "use 192.0.2.1 as the resolver\n"
    SANCTIONED_SCRATCH_PATH = "scratch lives in /tmp/tabichat/leg298/\n"
    SANCTIONED_FIXTURE_IDENTITY = "identity: admin@example.com\n"
    SANCTIONED_RELAY_CN = "comment: e.g. 'core-1-relay'\n"

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
        for fixture in (
            self.SANCTIONED_DOC_ADDRESS,
            self.SANCTIONED_SCRATCH_PATH,
            self.SANCTIONED_FIXTURE_IDENTITY,
            self.SANCTIONED_RELAY_CN,
        ):
            assert _offending_lines(fixture) == [], f"green-by-design fixture reddened: {fixture.strip()!r}"

    def test_widened_classes_do_not_eat_lookalikes(self):
        """Negative half of the boundary: a word that merely CONTAINS a site
        name is not the site name, and a relative path is not a workspace mount."""
        for benign in (
            "hostname idahox relay\n",
            "the montanahauser case\n",
            "path /tmp/media/dustings/ is fine\n",
            "austin@example.com\n",
            "core-1-relay is the example CN\n",
        ):
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
