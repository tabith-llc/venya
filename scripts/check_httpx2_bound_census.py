#!/usr/bin/env python3
# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at this file's repository root. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1
"""Pre-commit entry: the #447 httpx2 upper bound is a workspace-wide invariant.

One implementation, several doors (the `detect_secrets_baseline_guard.py` shape): the pre-commit
chain calls it as the `httpx2-bound-census` hook, and
`packages/cli/tests/test_httpx2_upper_bound_447.py` loads THIS file — the hook bypasses on
`--no-verify` and a fresh clone has no hooks installed, so the test cell is what closes both.

**Stdlib only, on purpose.** It imports `tomllib` (Python >= 3.11) and `pathlib`, nothing else.
It is therefore safe to run as `language: system` with a bare `python3` entry, because it never
needs the project environment: **no `uv run`, no venv, no resolution — and so no `uv lock` write.**
That is the #627 lesson: a hook that ran bare `uv run` silently rewrote tracked `uv.lock`
mid-commit (16 lines nobody chose) while pip-audit itself reported clean. A hook that cannot open
the lockfile for writing cannot repeat it, which is why this entry is not merely lighter but
structurally safer than the hooks it joins.

**Exit contract.** 0 = every member that declares httpx2 carries the ruled range. 1 = a real
violation (prints the member, the file, and what it declares). Anything else — a glob that
resolves to nothing, a member declaring httpx2 twice, an unreadable manifest — is a LOUD failure,
never a silent pass: an instrument that cannot see must say it is blind.

`pass_filenames: false` + the hook's `files:` pattern is what makes it fire: pre-commit runs this
against the repo root, and the pattern decides whether the hook is invoked at all.
"""

import sys
import tomllib
from pathlib import Path

RULED_RANGE = ">=0.27.0,<2.13.0"
HTTPX2_NAME = "httpx2"


def member_manifests(root: Path) -> list[Path]:
    """Member manifests, derived from the workspace root's OWN glob — never a hardcoded list."""
    with (root / "pyproject.toml").open("rb") as handle:
        patterns = tomllib.load(handle)["tool"]["uv"]["workspace"]["members"]
    found: list[Path] = []
    for pattern in patterns:
        for candidate in sorted(root.glob(pattern)):
            manifest = candidate / "pyproject.toml" if candidate.is_dir() else candidate
            if manifest.is_file() and manifest not in found:
                found.append(manifest)
    if not found:
        # Blind, not green: an empty census makes every comparison trivially true.
        raise SystemExit(f"FAIL: workspace glob {patterns!r} resolved to NO manifests under {root}")
    return found


def httpx2_declaration(manifest: Path) -> str | None:
    with manifest.open("rb") as handle:
        deps = tomllib.load(handle).get("project", {}).get("dependencies", [])
    matches = [d for d in deps if d.split(";")[0].strip().startswith(HTTPX2_NAME)]
    if not matches:
        return None
    if len(matches) > 1:
        raise SystemExit(
            f"FAIL: {manifest} declares {HTTPX2_NAME} {len(matches)} times — no single ruled range to compare"
        )
    return matches[0]


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    want = f"{HTTPX2_NAME}{RULED_RANGE}"
    offenders: list[tuple[str, Path, str]] = []
    skipped: list[str] = []
    covered = 0
    for manifest in member_manifests(root):
        declaration = httpx2_declaration(manifest)
        if declaration is None:
            skipped.append(manifest.parent.name)
            continue
        covered += 1
        if declaration != want:
            offenders.append((manifest.parent.name, manifest, declaration))

    if offenders:
        print(
            f"FAIL: {HTTPX2_NAME} must carry the SAME ruled upper bound ({RULED_RANGE}) in every "
            "workspace member that declares it — refs #447",
            file=sys.stderr,
        )
        for name, path, declaration in offenders:
            print(f"  - {name}: declares {declaration!r} in {path}", file=sys.stderr)
        print(
            "  Why: uv.lock does NOT travel to the customer, so each install resolves the range at "
            "the customer's own moment; an uncapped member can resolve a version no gated suite ran.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: {HTTPX2_NAME} bound census — {covered} members carry {want}; {len(skipped)} without the dep: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
