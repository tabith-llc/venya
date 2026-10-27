#!/usr/bin/env python3
# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at this file's repository root. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1
"""Interlock: every ``subprocess`` child in ``packages/*/src`` carries ``timeout=``.

THE CLASS THIS CLOSES. One untimed ``subprocess.run`` in the egress-policy path was enough to
park the executor's single admission permit forever: a wedged sandboxd meant no later command
ran at all, and nothing was ever broken on its face — the call was simply waiting. No lint, type
check or suite sees that. The fix for the one instance is a bound; the fix for the CLASS is this
file.

SCOPE, and why it is ``packages/*/src`` and not all of ``packages/``. The same walk over the
whole tree at ``5b9a709b`` counted **111** call sites across **43** files, **70** of them with no
``timeout=``; **68** of those 70 are ``tests/`` harness files and one is a repo script
(``packages/core/scripts/gen_bandit_suppressions.py``). A gate over all of ``packages/`` would
red-gate 68 existing test-harness sites on its first run — a wall of exemptions that hides the
real ones, which is not closing a class. Restricted to ``packages/*/src``: **104** files, **24**
call sites, **2** unbounded. One of those 2 is bounded by this row (the egress-policy site in
``strategies/sbx_strategy.py``); the other is the single shipped exemption below.

**Stdlib only, on purpose** — the same reasoning as ``check_httpx2_bound_census.py``: it may run
as a bare ``python3`` pre-commit entry, never through ``uv``, so it cannot rewrite ``uv.lock``
mid-commit (the #627 class).

**Exit contract.** 0 = every site is bounded or explicitly exempted. 1 = a real violation
(printed with file, line, the call name and the keywords it does pass). Anything else — a glob
that resolves to nothing, a file that will not parse, an exemption that no longer matches the
definition it names, an exemption whose site has gone, a scanned file count below
``MIN_SCANNED_FILES``, more exemptions than ``MAX_EXEMPTIONS`` allows — is a LOUD failure, never
a silent pass. An instrument that cannot see must say it is blind: a pattern that quietly stops
matching would report this class as clean forever.

Two doors, one implementation (the #447 shape): the ``subprocess-timeout-census`` pre-commit
entry, and ``packages/executor/tests/test_subprocess_timeout_interlock_598.py``, which loads THIS
file and asserts it over the shipped tree — because a pre-commit hook is bypassed by
``--no-verify`` and is absent from a fresh clone (measured on this venue: the hook door fires, and
the pytest door is what survives both of those).
"""

import argparse
import ast
import sys
from pathlib import Path

#: The call names this census knows. ``check_call`` takes no ``timeout`` of its own — it forwards
#: ``**kwargs`` to ``Popen.communicate``, where ``timeout`` IS honoured — so it is scanned on the
#: same terms as the rest, and an exemption or a bound has to say so.
SUBPROCESS_CALLS = ("run", "check_output", "check_call", "call", "Popen")

#: Floor on scanned files, below which a run cannot be trusted to mean "clean". The real
#: ``packages/*/src`` surface measured **104** files at ``5b9a709b`` (the base of this row); the
#: floor is a path-drift tripwire, not a claim about the current count — the census PRINTS its own
#: number beside every verdict so a shrink is visible rather than merely tolerated. House pattern:
#: ``MIN_FILES = 400`` in ``scripts/pre_tag_scrub.py``, set there from that script's own surface.
MIN_SCANNED_FILES = 100

#: Ceiling on shipped exemptions. Adding an entry is legal only by raising this number in the
#: same change, which turns every new exemption into a visible, reviewable edit instead of a
#: line someone appends to a list and nobody reads. ``MAX_EXEMPTIONS`` pinned at its own value is
#: what the interlock's paired-negative cell proves can fire.
MAX_EXEMPTIONS = 1

#: Exemptions: ``"<relative path>::<enclosing function>" -> reason``. Site-scoped, NOT
#: file-scoped: an unbounded call added anywhere else in an exempted file is still a violation,
#: which is what keeps this from being a hole with a name on it. The key names the code it
#: excuses, so a rename or a deletion fails the census loudly instead of quietly exempting
#: whatever later sits under the same path.
#: A reason is mandatory — an exemption that says nothing excuses nothing.
EXEMPTIONS: dict[str, str] = {
    "packages/executor/src/executor/executor.py::_run_command_direct": (
        "the LEGACY direct path, documented at that function as reached only by direct calls "
        "(tests) — factory.py ships SbxStrategy as the sole product strategy — and it is "
        "self-bounded anyway: `_direct_path_timeout()` (VENYA_DIRECT_PATH_TIMEOUT, default "
        "SBX_TIMEOUT) is applied to the output capture AND to the wait that follows it, so the "
        "child cannot be reaped forever (#470). `Popen` accepts no `timeout=` keyword of its "
        "own; the bound lives in communicate()/wait()."
    ),
}

#: An inline opt-out for a call whose bound is passed through ``**kwargs``, which cannot be
#: judged statically. Deliberately requires a reason in the same line, not just the token.
EXEMPT_COMMENT = "subprocess-timeout: exempt ("


def src_files(root: Path) -> list[Path]:
    """Every ``.py`` under ``packages/*/src``, derived from the tree's own glob.

    Never a hardcoded package list: a new member must be scanned the day it exists.
    """
    found: list[Path] = []
    for member in sorted(root.glob("packages/*/src")):
        found.extend(p for p in sorted(member.rglob("*.py")) if p.is_file())
    if not found:
        raise SystemExit(f"FAIL: packages/*/src resolved to NO files under {root} — the census is blind, not green")
    return found


def call_sites(path: Path) -> list[tuple[int, str, list[str], bool, str]]:
    """``(line, call name, keyword names, treated as bounded, enclosing function)``.

    The enclosing function is what an exemption is scoped to. A module-level call reports
    ``"<module>"``.
    """
    source = path.read_text()
    tree = ast.parse(source)
    lines = source.splitlines()
    # Map every node to its nearest enclosing function, so an exemption names the code it excuses.
    parent: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def enclosing_func(node: ast.AST) -> str:
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
            node = parent.get(node)  # type: ignore[assignment]
        return "<module>"

    sites: list[tuple[int, str, list[str], bool, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in SUBPROCESS_CALLS:
            continue
        base = func.value
        if not (isinstance(base, ast.Name) and base.id == "subprocess"):
            continue
        keywords = sorted(k.arg for k in node.keywords if k.arg)
        has_timeout = "timeout" in keywords
        # A `**kwargs` splat hides the bound from a static read. It counts as bounded only when
        # the inline marker with a reason sits on the call, so an unexplained splat is a violation.
        if not has_timeout and any(k.arg is None for k in node.keywords):
            window = lines[max(0, node.lineno - 4) : node.lineno + 1]
            has_timeout = any(EXEMPT_COMMENT in line for line in window)
        sites.append((node.lineno, func.attr, keywords, has_timeout, enclosing_func(node)))
    return sites


def census(root: Path, exemptions: dict[str, str] | None = None) -> int:
    """Run the census over ``root``. Returns 0 or 1; raises loudly on a broken instrument.

    ``exemptions`` defaults to the shipped table. A caller that drives a fixture tree passes an
    explicit table (usually ``{}``) so the census's verdict is about ITS predicate and not about
    paths that only exist in the real repo — the guarantee inherits nothing from its caller.
    """
    table = EXEMPTIONS if exemptions is None else exemptions
    if len(table) > MAX_EXEMPTIONS:
        raise SystemExit(
            f"FAIL: {len(EXEMPTIONS)} exemption(s) shipped, MAX_EXEMPTIONS is {MAX_EXEMPTIONS} — "
            "raising the ceiling is the act, so do it on purpose and in the same change"
        )
    files = src_files(root)
    if len(files) < MIN_SCANNED_FILES:
        raise SystemExit(
            f"FAIL: only {len(files)} files scanned under packages/*/src, floor is "
            f"{MIN_SCANNED_FILES} — the glob drifted, so a zero here is blindness, not cleanliness"
        )
    violations: list[str] = []
    exempt_hits: set[str] = set()
    for path in files:
        try:
            sites = call_sites(path)
        except SyntaxError as exc:
            raise SystemExit(f"FAIL: {path} does not parse ({exc}) — the census cannot judge a file it cannot read")
        except OSError as exc:
            raise SystemExit(f"FAIL: {path} is unreadable ({exc}) — the census is blind, not green")
        rel = str(path.relative_to(root))
        unbounded = [(line, name, kw, fn) for line, name, kw, bounded, fn in sites if not bounded]
        for line, name, kw, fn in unbounded:
            key = f"{rel}::{fn}"
            reason = table.get(key)
            if reason is None:
                violations.append(f"{key}:{line} subprocess.{name} has NO timeout= (keywords it does pass: {kw})")
                continue
            if not reason.strip():
                raise SystemExit(f"FAIL: exemption for {key} carries no reason — an unexplained exemption is not one")
            exempt_hits.add(key)
            print(f"exempt {key}:{line} subprocess.{name} kwargs={kw} — {reason}")
    stale = sorted(set(table) - exempt_hits)
    if stale:
        # An exemption whose site is gone is a hole waiting to be silently refilled.
        raise SystemExit(
            f"FAIL: stale exemption(s) {stale} — no unbounded site remains there; "
            "the code moved, was bounded, or was deleted. Delete the entry."
        )
    print(
        f"scanned {len(files)} files under packages/*/src ({root}); {len(table)} exemption(s), ceiling {MAX_EXEMPTIONS}"
    )
    if violations:
        for v in violations:
            print(f"VIOLATION: {v}")
        print(f"FAIL: {len(violations)} subprocess call site(s) with no timeout= — bound them")
        return 1
    print("OK: every subprocess call in packages/*/src is bounded or exempted with a reason")
    return 0


def self_test() -> int:
    """Prove the census can return nonzero BEFORE its zero on the shipped tree is believed.

    The guarantee inherits nothing from its caller: it builds its own fixture tree with its own
    EMPTY exemption table, runs the real walk against it, and requires both faces. The shipped
    exemption table is a claim about the shipped tree and must never be allowed to colour this
    control — hence the save/restore below, not a global mutation. The floor tripwire and the
    exemption ceiling are separately pinned by the pytest cell, so this tests the PREDICATE only.
    """
    import shutil
    import tempfile

    shipped = dict(EXEMPTIONS)
    tmp = Path(tempfile.mkdtemp(prefix="timeout-census-selftest-"))
    try:
        src = tmp / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        good = src / "good.py"
        bad = src / "bad.py"
        good.write_text("import subprocess\n\nsubprocess.run(['true'], timeout=5, check=False)\n")
        bad.write_text("import subprocess\n\nsubprocess.run(['true'], check=False)\n")
        if census(tmp, exemptions={}) != 1:
            print("SELF-TEST FAILED: an unbounded site read as clean")
            return 1
        bad.unlink()
        if census(tmp, exemptions={}) != 0:
            print("SELF-TEST FAILED: a fully bounded fixture did not read clean")
            return 1
        assert shipped == EXEMPTIONS, "the self-test must not disturb the shipped table"
        print("SELF-TEST OK: the census fires on an unbounded site and clears a bounded one")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument("--self-test", action="store_true", help="prove the census can fire, then exit")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return census(Path(args.root).resolve())


if __name__ == "__main__":
    sys.exit(main())
