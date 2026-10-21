# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Fail a commit, or a tag, that ships a private identifier (refs #689, #702).

**Why this script exists.** The owner's #689 scrub plan part 3 read: *"Release workflow
hook — scrub step runs before git tag; CI gates the expanded guard."* Measured at
``87a743c``, **there is no CI in this repo** — no ``.github/workflows``, no
``.gitlab-ci.yml``, no Jenkins/Azure/Circle/Travis file of any kind
(``git ls-tree -r --name-only <dev> | grep -icE '\\.github/workflows|gitlab-ci|jenkins|
azure-pipelines|drone|circleci|travis'`` -> **0**). The only automated gate this repo
has is ``.pre-commit-config.yaml``, and the #689 guard was a **pytest cell**, which runs
only when a seat voluntarily runs a suite. Concretely: a commit reintroducing a dev
hostname passed every hook this repo has. That is the #690 failure shape again — the fix
shipped, the enforcement step did not.

**So this is the honest substitute for the CI the plan assumed, and the deviation from
the owner's wording is deliberate and must stay visible**, not smoothed: a pre-commit
hook (every commit, no human remembering) plus an explicit pre-tag invocation of the
SAME code (``--ref``, run against the tag candidate before ``git tag``).

**Why it is not ``detect-secrets``** and cannot be counted as covered by it: that tool
hunts secret-*shaped* strings (high-entropy tokens, key formats). This class is host
names, personal local parts, private subnets and workspace paths — ordinary prose with
zero entropy. Its presence in the chain proves nothing about this rule.

One implementation, three stages (the house shape of
``scripts/detect_secrets_baseline_guard.py``, which this file copies conventions from):

* ``--stage pre-commit`` — the whole shipped-text surface as it stands in the working
  tree. Cheap enough to sit on every commit (measured and printed by ``--timing``;
  stdlib-only, no ``uv``, no network, and it never writes to the tree — the #627 class
  of a hook mutating tracked state mid-commit is the reason).
* ``--stage pre-tag --ref <rev>`` — the surface as it exists AT THAT REF, read through
  ``git ls-tree``/``git show`` so a dirty worktree cannot flatter the thing about to be
  tagged. This is the release-recipe command.
* ``--stage scan [--root DIR]`` — the same walk with no git at all, for a lane test that
  needs to point the rule at a fixture tree.

**The vocabulary lives in ``scripts/private_literals.py`` and nowhere else.** This file
imports the pattern table, the fixtures and the surface definition, because two pattern
sets for one owner rule is how they drift — and because #689 was itself a case of a rule
that existed in one place and was applied in another.

**An empty file list is a FAILURE, never a green.** A guard that passes because it found
nothing to read is worse than no guard: it advertises coverage it does not have. Every
stage routes through ``_verdict``, which enforces ``MIN_FILES`` and reports how many
files it actually read.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from private_literals import (
    INTERLOCK_FILENAME,
    PRIVATE_CLASSES,
    PRIVATE_LITERALS_FILENAME,
    SHIPPED_SURFACE,
    offending_lines,
    surface_files,
)

#: Floor on files read, below which a run cannot be trusted to mean "clean". The real
#: surface measured 645 files at the #689 tip before this leg, and 700+ after; the floor
#: is a path-drift tripwire, not a claim about the current count — print the number
#: beside every verdict so a shrink is visible rather than merely tolerated.
MIN_FILES = 400

STAGES = ("pre-commit", "pre-tag", "scan")


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    # check=False on purpose: callers branch on returncode. An absent ref is a real
    # answer a operator needs named, not a traceback.
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, check=False)


def _git_bytes(args: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    """Byte-capturing git call: a blob is not necessarily UTF-8, and `text=True`
    raises on one instead of answering the question. The ref stage must be able to
    say "this blob is binary" the way the disk walk says it with `read_text()`."""
    return subprocess.run(args, cwd=str(cwd), capture_output=True, check=False)


def repo_root(start: Path | None = None) -> Path:
    """Git's toplevel for ``start`` (defaults to this process' cwd)."""
    out = _git(["git", "rev-parse", "--show-toplevel"], start or Path.cwd())
    if out.returncode != 0:
        raise RuntimeError(f"not inside a git repository: {out.stderr.strip()}")
    return Path(out.stdout.strip())


def _descriptor(rel: str, cls: str, lineno: int) -> str:
    """One offender, WITHOUT the private text.

    The matched line is deliberately not carried: this tool's output lands in commit
    logs, terminal transcripts and lane reports, and printing the identifier it just
    refused is how a scrub gets re-published by its own guard. Class + file + line is
    enough to find and fix it.
    """
    return f"{cls}: {rel}:{lineno}"


def scan_texts(items: list[tuple[str, str]]) -> list[str]:
    """Offenders over (relative-path, text) pairs, using the single vocabulary."""
    offenders: list[str] = []
    for rel, text in items:
        for cls, lineno, _line in offending_lines(text):
            offenders.append(_descriptor(rel, cls, lineno))
    return offenders


def worktree_items(root: Path) -> list[tuple[str, str]]:
    """(rel, text) for the shipped surface as it stands on disk."""
    items: list[tuple[str, str]] = []
    for rel in surface_files(root, SHIPPED_SURFACE):
        path = root / rel
        try:
            items.append((rel, path.read_text()))
        except (UnicodeDecodeError, OSError):
            continue  # binary/undecodable — not a shipped text literal
    return items


def ref_items(root: Path, ref: str) -> list[tuple[str, str]]:
    """(rel, text) for the shipped surface AT ``ref``.

    Enumerated from the ref's own tree, not from the worktree, so an uncommitted fix
    cannot make a tag candidate read clean — which is the exact failure this stage
    exists to close. Paths are filtered by their BASENAME against the same exclusion
    table the disk walk uses (the directory exclusions are for generated output, which
    ``ls-tree`` does not list anyway).
    """
    listing = _git(["git", "ls-tree", "-r", "--name-only", ref], root)
    if listing.returncode != 0:
        raise RuntimeError(f"cannot read ref {ref!r}: {listing.stderr.strip() or 'no such ref'}")
    names = [n for n in listing.stdout.splitlines() if n]
    kept = [n for n in names if _in_surface(n) and Path(n).name not in (PRIVATE_LITERALS_FILENAME, INTERLOCK_FILENAME)]
    items: list[tuple[str, str]] = []
    for rel in kept:
        show = _git_bytes(["git", "show", f"{ref}:{rel}"], root)
        if show.returncode != 0:
            continue  # unreadable blob: the file count below is what catches that
        try:
            text = show.stdout.decode("utf-8")
        except UnicodeDecodeError:
            continue  # binary/undecodable — same rule the disk walk applies
        items.append((rel, text))
    return items


def _in_surface(rel: str) -> bool:
    """Is a repo-relative path part of the shipped text surface?"""
    parts = rel.split("/")
    if any(part in {"target", "build", ".venv", "__pycache__", ".git", "node_modules"} for part in parts):
        return False
    if rel.endswith(".lock"):
        return False
    if len(parts) == 1:
        return parts[0].endswith(".md")
    return parts[0] in SHIPPED_SURFACE[0]


def _verdict(items: list[tuple[str, str]], offenders: list[str], stage: str, target: str) -> tuple[int, str]:
    """The single pass/fail decision, shared by every stage.

    Three ways to fail, and only one way to pass, checked in this order:
    offenders first (a real hit is never reported as a size complaint), then the empty
    list, then the floor. An empty surface is a BROKEN GUARD, not a clean tree, and a
    guard that passes on nothing advertises coverage it never had.
    """
    if offenders:
        # FIRST, before any size question: a detected identifier is reported even if
        # the surface also looks too small to trust. Swallowing a real hit behind a
        # floor message would let a shrink hide the thing the guard exists to catch.
        listed = "\n".join(f"    - {o}" for o in sorted(offenders))
        return 1, (
            f"ERROR: {len(offenders)} private-identifier hit(s) in the shipped text surface at {target} (refs #689).\n\n"
            f"{listed}\n\n"
            "  Classes and what to use instead:\n"
            "    rfc1918-address    -> an RFC 5737 documentation range (192.0.2/198.51.100/203.0.113)\n"
            "    dev-hostname       -> a role word ('the dev box', \"the owner's workstation\") or a\n"
            "                        `<core-host>` placeholder; the shipped relay CN shape is <host>-relay\n"
            "    operator-identity  -> admin@example.com\n"
            "    workspace-path     -> a workspace-relative path ('the reference-docs/ directory')\n\n"
            f"  The vocabulary and its exclusions live in scripts/{PRIVATE_LITERALS_FILENAME}; the\n"
            "  same table is what the pytest interlock reads, so the two cannot disagree.\n"
            "  Do NOT add an exclusion to make this pass, and do not reach for --no-verify:\n"
            f"  the interlock cell in {INTERLOCK_FILENAME} runs the same rule from the suite.\n"
        )
    if not items:
        return 1, (
            f"REFUSED: {stage} read ZERO files from {target}.\n"
            f"  The shipped surface is derived from {list(SHIPPED_SURFACE[0])} + root *.md.\n"
            "  An empty list means the surface moved, the ref is wrong, or this is not a\n"
            "  repo root — it does NOT mean the tree is clean. Never ship a guard that\n"
            "  passes on nothing: it advertises coverage it never had.\n"
        )
    if len(items) < MIN_FILES:
        return 1, (
            f"REFUSED: {stage} read only {len(items)} files from {target} — below the\n"
            f"  {MIN_FILES}-file floor, so the scan surface shrank (path drift or a bad\n"
            "  exclusion) rather than the tree being clean. Re-derive the surface, do not\n"
            "  lower this number to make a run pass.\n"
        )
    return (
        0,
        f"OK: {len(items)} shipped files scanned at {target}; zero private identifiers ({len(PRIVATE_CLASSES)} classes).\n",
    )


def extra_items(root: Path, paths: list[str]) -> list[tuple[str, str]]:
    """(rel, text) for operator-supplied files, judged by the same vocabulary.

    The release recipe's guard clause reads "zero operator-private-identifier hits
    (staged scripts **+ notes**)". The tree scan cannot see a release-notes file that
    has not been written into the repo yet, so the notes arrive here — through this
    script — rather than through a second grep someone retypes, which is how one rule
    grows two vocabularies and drifts (#689, again).

    A missing path is a FAILURE, not a skip: a recipe that quietly ignores an absent
    notes file has stopped checking the notes.
    """
    items: list[tuple[str, str]] = []
    for given in paths:
        path = Path(given)
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            raise RuntimeError(f"--path {given!r} is not a readable file")
        try:
            items.append((path.name, path.read_text()))
        except UnicodeDecodeError:
            raise RuntimeError(f"--path {given!r} is not UTF-8 text") from None
    return items


def run(stage: str, root: Path, ref: str | None = None, extra: list[str] | None = None) -> tuple[int, str]:
    """(rc, output) for one stage. Single code path for all three, so no stage can
    be more permissive than another by accident."""
    if stage == "pre-tag":
        if not ref:
            return 1, "REFUSED: --stage pre-tag needs --ref <rev> — a tag candidate is a REF, not a worktree.\n"
        try:
            items = ref_items(root, ref)
        except RuntimeError as exc:
            # Fail CLOSED here too: `run()` is what both the hook and the tests call,
            # so an unreadable ref must be a verdict, not an exception that escapes
            # one caller and not another.
            return 1, f"REFUSED: cannot read the tag candidate — {exc}\n"
        target = f"ref {ref}"
    else:
        items = worktree_items(root)
        target = f"worktree {root}"
    extras: list[tuple[str, str]] = []
    try:
        extras = extra_items(root, extra or [])
    except RuntimeError as exc:
        return 1, f"REFUSED: {exc}\n"
    if extras:
        items = items + extras
        target = f"{target} + {len(extras)} supplied file(s)"
    return _verdict(items, scan_texts(items), stage, target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse to commit, or to tag, a tree that ships a private identifier (#689/#702)."
    )
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--ref", help="tag candidate rev — required for --stage pre-tag")
    parser.add_argument("--repo", help="repository root (default: git's toplevel for the cwd)")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        metavar="FILE",
        help="extra file to judge with the same vocabulary — repeat once per release-notes file "
        "or staged script outside the tree (the release recipe's '+ notes' half). A named file "
        "that does not exist is a FAILURE, not a skip.",
    )
    parser.add_argument(
        "--timing",
        action="store_true",
        help="print the wall-clock cost to stderr (every seat pays this on each commit)",
    )
    args = parser.parse_args(argv)

    started = time.monotonic()
    try:
        root = Path(args.repo).resolve() if args.repo else repo_root()
        rc, output = run(args.stage, root, args.ref, args.path)
    except (RuntimeError, ValueError) as exc:
        # Fail loud, and fail CLOSED: an undecided run must not read as a pass.
        print(f"pre-tag scrub guard cannot decide: {exc}", file=sys.stderr)
        return 1
    if output:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")
    if args.timing:
        print(f"pre_tag_scrub: {args.stage} took {time.monotonic() - started:.2f}s", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
