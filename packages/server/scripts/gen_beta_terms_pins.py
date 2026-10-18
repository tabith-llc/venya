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
import importlib.util
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# .../packages/server/scripts/x.py -> parents[0]=scripts [1]=server [2]=packages [3]=repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "beta-known-limitations.md"

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
    changed = new != src
    n = len(parse_cites(src))
    if args.write:
        if changed:
            DOC.write_text(new, encoding="utf-8")
        print(f"re-pinned {n} cites at {(_git('rev-parse','HEAD') or '?').strip()}")
        return 0
    if args.check:
        print(f"{n} cites; would change: {changed}")
        return 1 if changed else 0
    print(f"{n} cites resolved; nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
