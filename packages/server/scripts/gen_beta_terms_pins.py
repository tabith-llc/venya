# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Generator for the `file:line` pins on docs/beta-known-limitations.md (#Leg 3, owner ruling 2026-10-18).

**Owner's ruling, verbatim:** *"claim-truth now, numbers re-pinned at the cut commit with a checked
assertion."* So this tool is BUILT now and RUN at the cut commit. It is deliberately NOT run today:
`origin/dev` moved twice while the terms page was being corrected, and a number pinned at a tip that
has already moved is how the wrong cites got published in the first place — a hand-applied offset
"verified" at a stale face.

Two jobs, and they are the same job seen from either end of the release:

- ``resolve`` — for every cite the page prints, find the line the NAMED SYMBOL actually sits on.
- ``generate`` — rewrite the page's coordinates to those lines, leaving every word beside them alone.

A cite is ``path:N`` where ``path`` is a tracked source file, and the symbol it names is taken from
the page's own prose: the nearest backticked literal before the cite that exists in that file. That
is the same reading a human auditor uses, and it is why the assertion is checkable at all — a number
without a named symbol cannot be verified by anyone, at any commit.

Nothing here edits prose. Prose correctness (does the entry describe the shipped tree) is the other
half of the ruling and it is a person's job, re-derived per entry against the behaviour, not a
generator's.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# .../packages/server/scripts/x.py -> parents[0]=scripts [1]=server [2]=packages [3]=repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "beta-known-limitations.md"
#: The curated manifest this tool re-keys alongside the page. Same directory as this file.
MANIFEST_PY = Path(__file__).resolve().parent / "beta_terms_cites.py"

#: A `file:line` or `file:line-line` coordinate on a tracked source path.
CITE = re.compile(r"(?P<path>[A-Za-z0-9_.\-/]+\.(?:py|sh|rs|ps1|toml)):(?P<start>\d+)(?:-(?P<end>\d+))?")

#: Backticked literals in prose — candidate symbol names, in the order they appear.
LITERAL = re.compile(r"`([^`\n]{2,120})`")

#: A literal is not a symbol name when it is one of these. Numbers, ports, env spellings,
#: shas, file extensions and prose fragments all fail the shape test rather than being
#: silently matched against some line that happens to contain them.
_NOT_A_SYMBOL = re.compile(
    r"""
      ^[\d.]+$                        # 3650, 0.0, 1033c2d-shaped
    | ^v?\d+\.\d+\.\d+                # version plates
    | ^[0-9a-f]{7,40}$                # commit shas
    | ^:\d+$                          # :8443 — a port, not a symbol
    | ^/                              # an absolute path or a flag
    | \.(py|sh|md|rs|ps1|toml)$       # a filename
    | ^[A-Z][A-Z0-9_]{2,}$            # a bare ENV/CONST name is only a symbol if it also exists; kept, see _pick
    | \s                              # anything with whitespace is prose, not one identifier
    """,
    re.VERBOSE,
)


def _load_manifest():
    """Load beta_terms_cites from THIS file's own directory.

    Importing it by bare module name works when you run the script from scripts/ and explodes with
    ModuleNotFoundError under pytest, where sys.path is the suite's. Found the hard way: the first
    red demonstration failed on the import, not on the planted defect, which would have taught a
    later reader nothing.
    """
    path = Path(__file__).resolve().parent / "beta_terms_cites.py"
    spec = importlib.util.spec_from_file_location("beta_terms_cites", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules.setdefault("beta_terms_cites", mod)
    spec.loader.exec_module(mod)
    return mod


@dataclass(frozen=True)
class Cite:
    """One coordinate on the page, plus the symbol it claims to point at."""

    path: str
    start: int
    end: int
    symbol: str | None
    line: int  # 1-based line of the PAGE, for messages
    occurrence: int = 1
    kind: str = "pin"  # pin | dated | exempt | unmanifested
    printed: str = ""  # the token EXACTLY as the page spells it

    @property
    def token(self) -> str:
        # The page's own spelling, so a rewrite can find it. The manifest normalises paths for
        # RESOLUTION; the page's bytes are what must be matched and replaced.
        return self.printed or (
            f"{self.path}:{self.start}" if self.start == self.end else f"{self.path}:{self.start}-{self.end}"
        )


def _tracked_files() -> dict[str, list[str]]:
    """Every tracked source file, mapped path -> list of lines.

    Uses `git ls-tree` on the working tree's HEAD rather than walking the disk, so a stray
    untracked copy of a same-named file can never be resolved against. Absent files map to [].
    """
    out: dict[str, list[str]] = {}
    listing = _git("ls-tree", "-r", "--name-only", "HEAD")
    for rel in (listing or "").splitlines():
        if rel.endswith((".py", ".sh")):
            p = REPO_ROOT / rel
            if p.is_file():
                out[rel] = p.read_text(encoding="utf-8", errors="replace").split("\n")
    return out


def _git(*args: str) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,  # the returncode test below is the check
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _basename_matches(name: str, files: dict[str, list[str]]) -> list[str]:
    """Full path, or a `.../x.py` / `dir/x.py` suffix, resolved against the tracked listing."""
    if name in files:
        return [name]
    tail = name.removeprefix(".../")
    return [p for p in files if p == tail or p.endswith("/" + tail)]


#: How far back from the cite to look for the symbol it names. A clause, not a paragraph:
#: the page writes "the symbol `foo` (`path:N`)", so the name lives beside the number. Anything
#: further back belongs to a different claim and picking it up would resolve a cite to a line the
#: sentence never pointed at — a NEW wrong coordinate carrying a green check, which is the defect
#: this tool exists to replace.
CLAUSE_WINDOW = 260


def _clause_before(line: str, pos: int, prev: str) -> str:
    """The clause that a coordinate sits at the end of.

    Cut at the last sentence terminator or list bullet before the cite, and at a comma only when
    the tail is short — enough to reach a name written in the same clause, not enough to reach the
    previous sentence's subject.
    """
    head = line[:pos]
    if len(head.strip()) < 12 and prev:
        head = prev + " " + head
    for marker in (". ", ": ", "- ", "; "):
        i = head.rfind(marker)
        if i != -1 and len(head) - i < CLAUSE_WINDOW:
            head = head[i + 1 :]
    return head[-CLAUSE_WINDOW:]


def _pick_symbol(clause: str, lines: list[str]) -> str | None:
    """The nearest backticked literal in the clause that occurs verbatim in the target file.

    Nearest to the number wins. A literal is eligible unless it is a bare number, a sha, a port,
    a version plate, or a path that is itself the cite. Multi-word literals are allowed, because
    the page uses `self.revoked = False` where no single identifier is distinctive.
    """
    for cand in reversed(LITERAL.findall(clause)):
        c = cand.strip()
        if len(c) < 3:
            continue
        if _NOT_A_SYMBOL.match(c):
            continue
        if c.endswith((".py", ".sh", ".md")) or CITE.search(c):
            continue
        if any(c in ln for ln in lines):
            return c
    return None


def parse_cites(text: str, files: dict[str, list[str]] | None = None) -> list[Cite]:
    """Every coordinate on the page, in document order, carrying its CURATED symbol.

    The symbol comes from `beta_terms_cites.MANIFEST`, not from the prose — see that file's
    docstring for why inference measured 10/105 here and why guessing was worse than refusing.
    A token absent from the manifest is returned with ``symbol=None`` and ``kind='unmanifested'``,
    which the guard turns RED: a new cite on a signed page must be a decided cite.
    """
    manifest = _load_manifest()
    DATED_BLOCK_FIRST_PAGE_LINE = manifest.DATED_BLOCK_FIRST_PAGE_LINE
    DATED_OVERRIDES = manifest.DATED_OVERRIDES
    MANIFEST = manifest.MANIFEST

    files = files if files is not None else _tracked_files()
    out: list[Cite] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for m in CITE.finditer(line):
            token = m.group(0)
            path = m.group("path")
            start = int(m.group("start"))
            end = int(m.group("end")) if m.group("end") else start
            matched = _basename_matches(path, files)
            entry = MANIFEST.get(token)
            if entry is not None:
                cpath, symbol, occ, kind = entry
                out.append(Cite(cpath, start, end, symbol, lineno, occ, kind, printed=token))
                continue
            if token in DATED_OVERRIDES:
                out.append(
                    Cite(matched[0] if len(matched) == 1 else path, start, end, None, lineno, 1, "dated", printed=token)
                )
                continue
            dated = lineno >= DATED_BLOCK_FIRST_PAGE_LINE
            out.append(
                Cite(
                    matched[0] if len(matched) == 1 else path,
                    start,
                    end,
                    None,
                    lineno,
                    1,
                    "dated" if dated else "unmanifested",
                    printed=token,
                )
            )
    return out


def resolve(cites: list[Cite], files: dict[str, list[str]] | None = None) -> list[tuple[Cite, int | None]]:
    """Pair each cite with the line its curated symbol occurs on, `occurrence`-th time.

    None means: not pinnable (a dated record, an unmanifested token, a symbol that does not exist,
    or an occurrence count that no longer reaches the one the manifest names). Never a guess.
    """
    files = files if files is not None else _tracked_files()
    out: list[tuple[Cite, int | None]] = []
    for c in cites:
        if c.kind != "pin" or c.symbol is None:
            out.append((c, None))
            continue
        lines = files.get(c.path)
        if lines is None:
            out.append((c, None))
            continue
        hits = [i for i, ln in enumerate(lines, 1) if c.symbol in ln]
        out.append((c, hits[c.occurrence - 1] if 0 < c.occurrence <= len(hits) else None))
    return out


def check_symbols(cites: list[Cite], files: dict[str, list[str]]) -> list[str]:
    """Every pin/dated cite's named symbol must still exist in the named file.

    Dated records are checked this way rather than by line: the number is allowed to be history,
    the symbol is not allowed to be fiction.
    """
    bad: list[str] = []
    for c in cites:
        if c.symbol is None:
            if c.kind == "unmanifested":
                bad.append(f"  page:{c.line} {c.token} is not in the cite manifest")
            continue
        lines = files.get(c.path)
        if lines is None:
            bad.append(f"  page:{c.line} {c.token} cites an untracked path {c.path}")
            continue
        if not any(c.symbol in ln for ln in lines):
            bad.append(f"  page:{c.line} {c.token} symbol {c.symbol!r} is absent from {c.path}")
    return bad


def generate(text: str | None = None) -> str:
    """Rewrite every coordinate to the line its symbol names. Prose is untouched.

    Raises ``ValueError`` when a cite cannot be resolved — a pin is never guessed, and a
    generator that silently leaves a stale number is the defect this replaced.
    """
    files = _tracked_files()
    src = text if text is not None else DOC.read_text(encoding="utf-8")
    unresolvable: list[str] = []
    out_lines = src.split("\n")
    cites = parse_cites(src, files)
    bad_symbol = check_symbols(cites, files)
    if bad_symbol:
        raise ValueError("cite integrity failed:\n" + "\n".join(bad_symbol))
    for c, now in resolve(cites, files):
        if now is None:
            if c.kind != "pin":
                continue  # dated/exempt records keep their digits by design
            unresolvable.append(f"  page:{c.line} {c.token} symbol={c.symbol!r} occ={c.occurrence}")
            continue
        if now == c.start and (c.end == c.start or now == c.end):
            continue
        # Replace the page's own spelling of the token with the resolved full path and the line
        # its symbol names. `c.printed` is the exact text that matched, so it is always found.
        old_token = c.printed
        line = out_lines[c.line - 1]
        if old_token not in line:
            unresolvable.append(f"  page:{c.line} {old_token} (token not found on re-read)")
            continue
        if c.end == c.start:
            replacement = f"{c.path}:{now}"
        else:
            replacement = f"{c.path}:{now}-{now + (c.end - c.start)}"
        out_lines[c.line - 1] = line.replace(old_token, replacement, 1)
    if unresolvable:
        raise ValueError(
            "cannot re-pin these cites from the named symbol — fix the symbol or the path, "
            "never the number by hand:\n" + "\n".join(unresolvable)
        )
    return "\n".join(out_lines)


def _manifest_dict_node(tree: ast.AST):
    """The MANIFEST dict literal, whichever assignment form the file uses (`x = {}` or `x: T = {}`).

    Both forms occur in this file's own history, and an `AnnAssign`-only scan silently returns "no
    manifest" and turns the audit into a pass-by-vacuity — the exact defect this guard is here to
    catch, so it accepts both and the caller raises if neither is found.
    """
    for node in ast.walk(tree):
        target = ""
        if isinstance(node, ast.Assign) and node.targets:
            target = getattr(node.targets[0], "id", "")
        elif isinstance(node, ast.AnnAssign):
            target = getattr(node.target, "id", "")
        if target == "MANIFEST" and isinstance(getattr(node, "value", None), ast.Dict):
            return node.value
    return None


def _value_of(v: ast.expr, mod) -> object:
    """The entry's VALUE as Python sees it (evaluated), not as it is written.

    Comparing source text reports a false conflict: one entry may be written on one line and its twin
    across five, and both mean the same tuple. The whole point of this audit is to distinguish
    "redundant" from "a meaning was lost", so it must compare values the way the interpreter does.
    """
    try:
        return eval(compile(ast.Expression(v), "<manifest-value>", "eval"), vars(mod))
    except Exception:
        return ast.get_source_segment("", v) or "<unparsable>"


def audit_keys(module_src: str, mod=None) -> tuple[int, int, dict[str, list]]:
    """(keys counted in the SOURCE, keys the runtime dict holds, {dup_key: [values…]}).

    **Why the source count is the one that matters.** A repeated dict key is not an error in Python:
    the last entry wins and the earlier one vanishes at import time, with no warning. So `len(MANIFEST)`
    cannot see a clobber — a page can be re-pinned onto a key that already means something else and
    every runtime metric stays green on the wrong meaning. Counting the source keys is the only way to
    see the loss at all.
    """
    mod = mod or _load_manifest()
    tree = ast.parse(module_src)
    node = _manifest_dict_node(tree)
    if node is None:
        raise ValueError("no MANIFEST dict literal found — the key audit would pass by checking nothing")
    keys: list[str] = []
    values: dict[str, list] = {}
    for k, v in zip(node.keys, node.values):
        key = eval(compile(ast.Expression(k), "<manifest-key>", "eval"), vars(mod))
        keys.append(key)
        values.setdefault(key, []).append(_value_of(v, mod))
    counts = Counter(keys)
    dups = {k: vals for k, vals in values.items() if counts[k] > 1}
    return len(keys), len(set(keys)), dups


def manifest_key_problems(module_src: str, mod=None) -> list[str]:
    """Every reason to refuse this manifest, as printable lines. Empty list == the file is sound."""
    n_src, n_run, dups = audit_keys(module_src, mod)
    out: list[str] = []
    for key, vals in sorted(dups.items()):
        if len(set(vals)) > 1:
            out.append(
                f"  {key}: declared {len(vals)}x with DIFFERENT values — one meaning is lost:\n    "
                + "\n    ".join(repr(v) for v in vals)
            )
        else:
            out.append(f"  {key}: declared {len(vals)}x with an identical value — dead entry, no clobber")
    if n_src != n_run:
        out.append(f"  source keys {n_src} != runtime keys {n_run}: {n_src - n_run} lost to duplicate keys")
    return out


def rekey_manifest(newkey: dict[str, str], values: dict[str, tuple]) -> str:
    """Rewrite the manifest's KEYS to the post-pin coordinates, preserving the file's structure.

    Each key node is replaced across its own source span (a key never wraps, even where its value
    does), so an abbreviated spelling like `executors.py:699` becomes the FULL path the re-pinned page
    prints — which is what `parse_cites()` looks the token up by. Splicing only the trailing digits,
    which the first version of this function did, left nine abbreviated keys pointing at tokens the
    page no longer printed: the manifest looked re-keyed and was not.

    Comments and value formatting survive because nothing outside the key span is touched. When two
    keys collapse onto one coordinate, the later entry is deleted only if the values are identical;
    a differing pair is a clobber and the caller refuses before anything is written.
    """
    src = MANIFEST_PY.read_text(encoding="utf-8")
    mod = _load_manifest()
    node = _manifest_dict_node(ast.parse(src))
    if node is None:
        raise ValueError("re-key refused: no MANIFEST literal")
    pairs = list(zip(node.keys, node.values))
    plan = []  # (key_node, value_node, old_key, new_key)
    for k, v in pairs:
        key = eval(compile(ast.Expression(k), "<k>", "eval"), vars(mod))
        plan.append((k, v, key, newkey.get(key, key)))
    # Which new keys are shared, and whether sharing is safe (identical values) or a clobber.
    by_new: dict[str, list] = {}
    for _k, _v, old, new in plan:
        by_new.setdefault(new, []).append(old)
    drop: set[str] = set()
    for new, olds in by_new.items():
        if len(olds) > 1:
            vals = {tuple(values[o]) for o in olds}
            if len(vals) > 1:
                raise ValueError(f"re-key refused: {new} would hold {len(vals)} different meanings {olds}")
            drop.update(olds[1:])  # identical values: keep the first, delete the rest
    lines = src.split("\n")
    # Right-to-left within a line so earlier columns stay valid; whole-entry deletes applied after.
    edits = sorted(
        [
            (k.lineno, k.col_offset, k.end_col_offset, f"{new!r}")
            for k, _v, old, new in plan
            if new != old and old not in drop
        ],
        key=lambda e: (e[0], e[1]),
        reverse=True,
    )
    for lineno, c0, c1, text in edits:
        i = lineno - 1
        lines[i] = lines[i][:c0] + text + lines[i][c1:]
    deleted = 0
    for k, v, old, _new in sorted(plan, key=lambda t: t[0].lineno, reverse=True):
        if old in drop:
            del lines[k.lineno - 1 : v.end_lineno]
            deleted += 1
    print(f"re-key: {len(edits)} manifest keys moved, {deleted} identical-value duplicates dropped")
    return "\n".join(lines)


def write_atomic(path: Path, text: str) -> None:
    """One file, published by rename. Same directory, so no cross-device rename; fsync before it.

    `os.replace` is atomic per file: a reader sees the old bytes or the new ones, never a half-written
    file. Across the PAIR it is not atomic — no filesystem gives that for two paths — so the order is
    chosen to fail LOUD: the manifest is replaced first, which means a crash between the two renames
    leaves the page printing old coordinates that the new manifest no longer declares, and the interlock
    reddens on every one of them. The mirror order would leave new page coordinates undeclared, which
    also reddens; either way a torn write is a red suite, never a silent green.
    """
    tmp = path.with_name(path.name + ".rekey-tmp")
    tmp.write_text(text, encoding="utf-8")
    with tmp.open("r+") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--write",
        action="store_true",
        help="rewrite the page's coordinates (RUN AT THE CUT COMMIT; report the sha you ran it at)",
    )
    ap.add_argument("--check", action="store_true", help="print what would change; exit 1 if anything would")
    args = ap.parse_args(argv)

    src = DOC.read_text(encoding="utf-8")
    try:
        new = generate(src)
    except ValueError as e:
        print(f"UNRESOLVABLE\n{e}", file=sys.stderr)
        return 2
    # The key audit runs on EVERY verb, not just --write: a manifest that lost an entry to a duplicate
    # key is unsafe whether or not anyone is re-pinning right now, and rc 0 must not be reportable on top
    # of one. Conflicting duplicates refuse the run; identical ones are printed as a warning only.
    try:
        problems = manifest_key_problems(MANIFEST_PY.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError) as e:
        print(f"MANIFEST AUDIT FAILED\n{e}", file=sys.stderr)
        return 2
    conflicting = [p for p in problems if "DIFFERENT values" in p]
    for p in problems:
        print(p, file=sys.stderr)
    if conflicting:
        print(f"REFUSED: {len(conflicting)} conflicting duplicate manifest key(s); nothing written", file=sys.stderr)
        return 2
    changed = new != src
    n = len(parse_cites(src))
    if args.write:
        if changed:
            plan = {}
            for c, now in zip(parse_cites(src), [x[1] for x in resolve(parse_cites(src), _tracked_files())]):
                if now is None or c.kind != "pin" or now == c.start:
                    continue
                width = c.end - c.start
                plan[c.printed] = f"{c.path}:{now}" if width == 0 else f"{c.path}:{now}-{now + width}"
            new_manifest = rekey_manifest(plan, dict(_load_manifest().MANIFEST))
            # Prove the pair is consistent BEFORE publishing either file.
            probe = ast.parse(new_manifest)
            pk = _manifest_dict_node(probe)
            if pk is None:
                print(
                    "REFUSED: re-keyed manifest does not parse to a MANIFEST literal; nothing written", file=sys.stderr
                )
                return 2
            pn_src, pn_run, pdups = audit_keys(new_manifest)
            bad = {k: v for k, v in pdups.items() if len(set(v)) > 1}
            if bad or pn_src != pn_run:
                print(
                    f"REFUSED: re-key would leave {len(bad)} conflicting dup(s), src={pn_src} run={pn_run}; "
                    "nothing written",
                    file=sys.stderr,
                )
                return 2
            write_atomic(MANIFEST_PY, new_manifest)
            write_atomic(DOC, new)
            print(
                f"re-pinned {n} cites and re-keyed {len(plan)} manifest keys at "
                f"{(_git('rev-parse','HEAD') or '?').strip()}"
            )
        else:
            print(f"{n} cites already correct at {(_git('rev-parse','HEAD') or '?').strip()}; nothing written")
        return 0
    if args.check:
        print(
            f"{n} cites; would change: {changed}; manifest keys src/run: "
            f"{audit_keys(MANIFEST_PY.read_text(encoding='utf-8'))[:2]}"
        )
        return 1 if changed else 0
    print(f"{n} cites resolved; nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
