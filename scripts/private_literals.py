# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""THE one vocabulary of private identifiers, the surface that carries them, and
the fixtures that prove the vocabulary can fire.

Written once (ticket #689, leg 298) inside
``packages/executor/tests/test_installer_no_private_literals.py`` and pulled out here
by #702 (leg 306) because a SECOND consumer arrived — ``scripts/pre_tag_scrub.py``,
the executable pre-commit/pre-tag guard. Two pattern sets for one owner rule is how
vocabulary drifts, and the drift is not hypothetical: the 2026-10 sweep applied the
IP rule and shipped the site names. Both consumers import THIS module, and each suite
carries a cell asserting they loaded the same objects.

**This file is the only place in the repo that writes the refused tokens, plus the
pytest interlock that already did** — which is why those two names are the whole
exclusion list (``VOCABULARY_BEARERS``, exact filenames, no directory, no glob, no
prefix). The guard's fixtures live HERE rather than in the test files so that adding
negative coverage never grows the exclusion list and never puts another private token
in an ordinary source file.

The owner's standing constraint, verbatim (2026-10-21): *"no subnets, agent names,
personal info in venya code, must be completely site-agnostic."* Four classes answer
it:

* ``rfc1918-address`` — a private-range literal. The original defect: the executor
  installer once seeded the dev-fleet subnet into every customer's egress allowlist.
* ``dev-hostname`` — a development or estate HOST NAME. The IP regex was structurally
  blind to this class, and that blindness is why a sweep "cleaned the guard" while
  shipping the hostnames.
* ``operator-identity`` — a personal local part before ``@``, in any domain. The
  sanctioned fixture forms (``admin@example.com``, ``admin-bot@workstation``) are NOT
  matched, so the guard does not eat its own replacement.
* ``workspace-path`` — a developer workspace mount. Deliberately scoped to three
  private mounts plus the volume label, NOT to "any absolute path":
  ``/tmp/tabichat/…`` is the sanctioned fleet scratch root, and a guard that refused it
  would block its own test harness.

BOUNDARY LAW, because an unbounded word class eats ordinary prose. Each name is
guarded on both sides: ``(?<![\\w-])`` so a longer word does not CONTAIN it, and
``(?![\\w])`` — NOT ``(?![\\w-])`` — so the shipped relay CN shape ``<host>-relay``
still matches. That asymmetry is load-bearing and ``DETECTION_FIXTURES`` pins both
directions: ``core-1-relay`` greens as the sanctioned example, ``idahox`` greens as a
lookalike, and a real ``idaho-relay`` reds.

RESIDUAL, NAMED NOT BURIED (for the owner's eye, not a defect to fix here): this file
names the hostnames it refuses, it is tracked, and tracked files ship in the release
bundle. A guard cannot refuse what it cannot name, so the tokens appear in the
artifact as REFUSED TERMS in a pattern table — a different exposure from #689, where
they identified live infrastructure inside customer-facing docs and product source. If
the owner wants the tokens absent from the bundle as well, the act is to ship the
vocabulary as a build-time-only file, which is a packaging change outside this leg's
bar; the option is recorded in the leg report rather than taken.
"""

from __future__ import annotations

import re
from pathlib import Path

# --------------------------------------------------------------------------
# The classes
# --------------------------------------------------------------------------

#: Any RFC1918 literal (superset of the dev-topology 10.27.27.x / 10.27.28.x
#: ranges). Lookarounds keep version strings and longer numerics out.
RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
)

#: Development / estate host names. See BOUNDARY LAW in the module docstring.
DEV_HOSTNAME = re.compile(r"(?<![\w-])(?:montana|idaho|wyoming|colorado|utah|texas|venya-test-workstation)(?![\w])")

#: A personal local part before ``@``. Domain-agnostic on purpose: the local part IS
#: the identity, and re-homing it to another domain does not un-name it.
OPERATOR_IDENTITY = re.compile(r"(?<![\w.-])(?:dust|dusty|dustin)@")

#: A developer workspace mount. Three mounts + the volume label, not "any absolute
#: path" — see the module docstring.
WORKSPACE_PATH = re.compile(r"/(?:media/dust|home/dust|home/opencode)\b|dust-ext1")

#: Every class shipped text must be free of, NAMED so a failure says WHICH hole
#: reopened rather than just printing a line. This table is the single vocabulary.
PRIVATE_CLASSES: dict[str, re.Pattern[str]] = {
    "rfc1918-address": RFC1918,
    "dev-hostname": DEV_HOSTNAME,
    "operator-identity": OPERATOR_IDENTITY,
    "workspace-path": WORKSPACE_PATH,
}

# --------------------------------------------------------------------------
# Fixtures — the paired negatives, kept with the patterns they exercise
# --------------------------------------------------------------------------

#: One fixture per class that MUST redden it. Keyed by class so a new class without
#: a negative is a KeyError at import time in the test, not a silent green.
DETECTION_FIXTURES: dict[str, str] = {
    "rfc1918-address": "seeded 10.27.28.0/24 in the allowlist",
    "dev-hostname": "read over SSH as win on montana (rc=0)",
    "operator-identity": "identity: dust@montana",
    "workspace-path": "copies live in /media/dust/dust-ext1/tabith/reference-docs/",
}

#: The shipped relay CN shape, and the historical defect string the IP-only guard
#: was written for. Both must redden SOMETHING: one is the class the guard could not
#: see (hostname), the other the class it always could (address).
RELAY_CN_FIXTURE = "comment=\"Subject CN as presented, e.g. 'idaho-relay'\""
HISTORICAL_ADDRESS_FIXTURE = "hardcoded resolver IP (`10.27.28.1` — a development-fleet address)"

#: The blindness proof for class hole 1: this line reddens the hostname class and is
#: INVISIBLE to the pre-#689 IP-only pattern. If that ever stops being true, the
#: premise of the #689 finding is false and the test says so out loud rather than
#: letting the proof go quietly.
IP_BLIND_FIXTURE = DETECTION_FIXTURES["dev-hostname"]

#: Forms the owner's ruling SANCTIONS as replacements. Each must stay green, or the
#: guard is refusing its own fix and the scrub is unshippable.
SANCTIONED_EXAMPLES: tuple[str, ...] = (
    "192.0.2.0/24",
    "192.0.2.1",
    "198.51.100.7",
    "203.0.113.0/24",
    "admin@example.com",
    "admin-bot@workstation",
    "core-1-relay",
    "ssh bot@venya-core-1",
    "/tmp/tabichat/leg306/report.md",
    'dns_resolver = "<your resolver IP>"',
)

#: Lookalikes: a word that merely CONTAINS a name, or a name inside a longer word.
#: These must stay green, or the boundary law is decoration and ordinary prose burns.
LOOKALIKE_EXAMPLES: tuple[str, ...] = (
    "hostname idahox relay",
    "the montanahauser case",
    "/tmp/media/dustings/ is a lane path",
    "austin@example.com",
    "version 1.10.27",
    "wyomingish",
)

# --------------------------------------------------------------------------
# The shipped-text surface
# --------------------------------------------------------------------------

#: Top levels the release bundle carries, counted from the live served
#: ``venya-core-install.tar.gz`` (packages 610 · docs 42 · tests 10 · scripts 7 ·
#: systemd 5 paths) plus the root ``*.md`` files. Deriving the surface from what a
#: customer fetches — not from what a scan happened to walk — is the correction #689
#: forced: ``("packages","docs")`` never opened the root ``CHANGELOG.md``, the file
#: holding the most identifiable values.
BUNDLE_SCAN_ROOTS: tuple[str, ...] = ("packages", "docs", "tests", "scripts", "systemd")

#: Root-level shipped documents, GLOBBED (not enumerated) so a new root page is
#: covered the day it lands rather than needing someone to remember a list.
BUNDLE_SCAN_ROOT_GLOBS: tuple[str, ...] = ("*.md",)

#: Generated build output: gitignored, absent from every bundle
#: (``tar tzf <bundle> | grep -c '/target/|/build/'`` -> 0 across all three), and a
#: lane's own absolute workspace path lands inside it the moment it builds the Rust
#: extension (measured: 596 offender lines across 51 files in one venue). NOT a source
#: class exclusion — the interlock's
#: ``test_generated_output_exclusion_cannot_hide_source`` proves a same-named file
#: elsewhere still reddens.
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        "target",
        "build",
    }
)

#: Lockfiles: generated, machine-written, not a human text surface.
EXCLUDED_SUFFIXES: tuple[str, ...] = (".lock",)

#: The files that must carry the vocabulary in order to refuse it. EXACT FILENAMES —
#: no directory, no glob, no prefix — and the pre-tag script proves the narrowness by
#: planting the same token in an un-named file and demanding it redden.
PRIVATE_LITERALS_FILENAME = "private_literals.py"
INTERLOCK_FILENAME = "test_installer_no_private_literals.py"
VOCABULARY_BEARERS: tuple[str, ...] = (PRIVATE_LITERALS_FILENAME, INTERLOCK_FILENAME)

#: The pre-#689 surface, kept named so the paired negative can PROVE the old scan was
#: blind rather than asserting it in prose: two roots, and no root-level documents.
LEGACY_SURFACE: tuple[tuple[str, ...], tuple[str, ...]] = (("packages", "docs"), ())
SHIPPED_SURFACE: tuple[tuple[str, ...], tuple[str, ...]] = (BUNDLE_SCAN_ROOTS, BUNDLE_SCAN_ROOT_GLOBS)


def is_excluded(path: Path) -> bool:
    """True when ``path`` is not part of the shipped-text surface."""
    if not path.is_file():
        return True
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    return path.name in VOCABULARY_BEARERS


def offending_lines(text: str) -> list[tuple[str, int, str]]:
    """``(class, line-number, stripped-line)`` for every private literal in one file.

    The class name comes first because that is what a report should carry. The line
    text is here for a human staring at a failed commit; a caller that PUBLISHES a
    finding prints the descriptor and not the line — these are the bytes this rule
    exists to keep out of artifacts, and a report that quotes them reopens the ticket.
    """
    found: list[tuple[str, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for cls, pattern in PRIVATE_CLASSES.items():
            if pattern.search(line):
                found.append((cls, lineno, line.strip()))
    return found


def surface_files(root: Path, surface: tuple[tuple[str, ...], tuple[str, ...]] = SHIPPED_SURFACE) -> list[str]:
    """Repo-relative paths of the shipped text surface, sorted.

    Paths as STRINGS, not ``Path`` objects, because the pre-tag stage enumerates the
    same surface from a git REF via ``ls-tree``. Both modes must judge the identical
    file set or one rule quietly reads two trees, so one function returns the list and
    the other two read it.
    """
    scan_roots, root_globs = surface
    names: set[str] = set()
    for scan_root in scan_roots:
        base = root / scan_root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not is_excluded(path):
                names.add(path.relative_to(root).as_posix())
    for glob in root_globs:
        for path in root.glob(glob):
            if not is_excluded(path):
                names.add(path.relative_to(root).as_posix())
    return sorted(names)
