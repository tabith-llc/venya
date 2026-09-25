# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: shipped installer artifacts carry ZERO private-range literals.

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


# Tree-wide guard (ticket private-infra-product-defaults-and-fixtures, Stage 3):
# no RFC1918 literal in any shipped source/test/doc. Exclusions are deliberate.
TREE_SCAN_ROOTS = ("packages", "docs")  # + root-level *.sh/*.ps1 already covered by ARTIFACT_GLOBS
INTERLOCK_EXCLUDES = (
    "test_installer_no_private_literals.py",  # self (docstring + regex self-test pins)
    "CHANGELOG.md",  # D3 — historical release record
)
INTERLOCK_EXCLUDE_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules"}
INTERLOCK_EXCLUDE_SUFFIXES = (".lock",)  # uv.lock — generated


def _artifacts() -> list[Path]:
    files = sorted({p for g in ARTIFACT_GLOBS for p in REPO_ROOT.glob(g)})
    assert files, f"no installer artifacts matched {ARTIFACT_GLOBS} at {REPO_ROOT} — path drift?"
    return files


def _tree_files():
    for root in TREE_SCAN_ROOTS:
        for p in (REPO_ROOT / root).rglob("*"):
            if not p.is_file():
                continue
            if any(d in p.parts for d in INTERLOCK_EXCLUDE_DIRS):
                continue
            if p.name in INTERLOCK_EXCLUDES or p.name == Path(__file__).name:
                continue
            if p.suffix in INTERLOCK_EXCLUDE_SUFFIXES:
                continue
            yield p


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

    def test_zero_rfc1918_literals_in_installer_artifacts(self):
        offenders = []
        for path in _artifacts():
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if RFC1918.search(line):
                    offenders.append(f"{path.name}:{lineno}: {line.strip()}")
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

    def test_zero_rfc1918_literals_tree_wide(self):
        # ponytail: matches full dotted quads only — bare class shorthand
        # (10/8) and IPv6 ULA (fc00::/7) are NOT caught; CIDRs whose base is
        # a full dotted quad DO match (the self-test pins prove it). Widen
        # the regex only on an owner scope decision (Stage-3 ruling: no).
        offenders = []
        scanned = 0
        for path in _tree_files():
            scanned += 1
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue  # binary/undecodable — not a shipped text literal
            for lineno, line in enumerate(text.splitlines(), 1):
                if RFC1918.search(line):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
        assert (
            scanned > 50
        ), f"tree scan surface shrank to {scanned} — path drift?"  # paired negative: guard can't pass by scanning nothing
        assert (
            not offenders
        ), "RFC1918 literals in the public tree (use RFC 5737 192.0.2/198.51.100/203.0.113):\n" + "\n".join(offenders)


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
