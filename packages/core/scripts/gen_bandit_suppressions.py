# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Generate docs/bandit-nosec-suppressions.md from the live source tree.

The previous hand-maintained register rotted to 0/49 accurate rows (venya-dev
ticket docs-staleness-sweep-20260919): line numbers drift, sites move, new
suppressions never got added. This generator scans every scanned source line
carrying a `nosec` marker and emits it VERBATIM — rows are keyed on file +
line content, never line numbers, so ordinary edits above a site don't rot
the doc. Adding/removing/editing a suppression changes the doc -> the
interlock test (packages/core/tests/test_bandit_suppressions_doc.py) goes
RED until regenerated:

    uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py

Scope is the bandit hook's own file set: the `-r`/`-x` args are parsed from
.pre-commit-config.yaml, so the register and the hook scan the same files by
construction (one definition, no drift — refs 485). The scan is further
restricted to git-tracked files so the committed doc is deterministic across
clones: local gitignored residue (e.g. packages/executor/build/) would
otherwise make the regenerated doc machine-dependent.
"""

import fnmatch
import re
import subprocess  # nosec B404 — git ls-files provides the tracked set; fixed argv, no shell
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_PATH = REPO_ROOT / "docs" / "bandit-nosec-suppressions.md"
NOSEC_RE = re.compile(r"#\s*nosec")
_PRECOMMIT_CONFIG = ".pre-commit-config.yaml"

# The generated doc's H1, built from fragments so this file — itself inside
# the scanned set — holds no literal marker match of its own and can never
# list its own title as a fake suppression row.
_H1 = "# Bandit " + "`#" + " nosec` Suppressions"

# detect-secrets "Secret Keyword" fires on verbatim-quoted source lines that
# look like assignments of a passphrase-named constant (e.g. the B105-suppressed
# env-var-NAME lines in server ca.py). These rows quote lines ALREADY committed
# in source (they passed the hook there), so an inline pragma here cannot mask
# a new leak — it only stops re-flagging the quotation. Rule is content-keyed,
# so regeneration stays deterministic and the drift interlock stays byte-exact.
_PRAGMA_TRIGGERS = ("password", "passphrase", "secret", "token", "api_key")
_PRAGMA = " <!-- pragma: allowlist secret -->"


def load_bandit_args(root: Path = REPO_ROOT) -> tuple[list[str], list[str]]:
    """(recurse roots, exclusion patterns) from the pre-commit bandit hook.

    The hook's own `-r`/`-x` args in .pre-commit-config.yaml are the single
    definition of "scanned source". Parsing them here — instead of re-globbing
    a narrower set — is what keeps the register from drifting narrower than
    the hook (refs 485).
    """
    cfg = yaml.safe_load((root / _PRECOMMIT_CONFIG).read_text(encoding="utf-8"))
    for repo in cfg.get("repos", []) or []:
        for hook in repo.get("hooks", []) or []:
            if hook.get("id") != "bandit":
                continue
            args: list[str] = hook.get("args", [])
            recurse: list[str] = []
            excludes: list[str] = []
            i = 0
            while i < len(args):
                flag = args[i]
                value = args[i + 1] if i + 1 < len(args) else None
                if flag == "-r" and value is not None:
                    recurse.append(value)
                    i += 2
                elif flag == "-x" and value is not None:
                    excludes.extend(part for part in value.split(",") if part)
                    i += 2
                else:
                    i += 1
            return recurse, excludes
    raise ValueError(f"bandit hook not found in {root / _PRECOMMIT_CONFIG}")


def _excluded(rel: str, excludes: list[str]) -> bool:
    """True if a repo-relative path falls under any hook exclusion.

    Handles both forms the hook uses: directory prefixes (trailing slash —
    matches anything under the dir) and plain glob patterns.
    """
    for pat in excludes:
        if fnmatch.fnmatch(rel, pat):
            return True
        if pat.endswith("/") and rel.startswith(pat):
            return True
    return False


def _tracked_py_files(root: Path) -> set[Path]:
    """Repo-tracked *.py files — the committed tree, not local residue."""
    raw = subprocess.run(  # nosec B603 B607 — git ls-files with fixed argv list, no shell, no external input
        ["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    tracked = {chunk.decode("utf-8") for chunk in raw.split(b"\0") if chunk}
    return {root / name for name in tracked if name.endswith(".py")}


def scanned_files(root: Path = REPO_ROOT) -> list[Path]:
    """Every git-tracked .py file the pre-commit bandit hook scans."""
    recurse, excludes = load_bandit_args(root)
    out: list[Path] = []
    for py in _tracked_py_files(root):
        rel = py.relative_to(root).as_posix()
        if not any(rel.startswith(r.rstrip("/") + "/") for r in recurse):
            continue
        if not _excluded(rel, excludes):
            out.append(py)
    return sorted(out)


def scan(root: Path = REPO_ROOT) -> list[tuple[str, str]]:
    """(repo-relative file, stripped verbatim line) for every nosec marker."""
    rows: list[tuple[str, str]] = []
    for py in scanned_files(root):
        rel = py.relative_to(root).as_posix()
        for line in py.read_text(encoding="utf-8").splitlines():
            if NOSEC_RE.search(line):
                rows.append((rel, line.strip()))
    return rows


def generate() -> str:
    rows = scan()
    out = [
        _H1,
        "",
        "<!-- GENERATED FILE — DO NOT HAND-EDIT.",
        "     Source of truth: every `nosec` marker in the files the pre-commit",
        "     bandit hook scans — all of packages/ minus the hook's own -x exclusions,",
        "     parsed from .pre-commit-config.yaml; git-tracked files only.",
        "     Regenerate: uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py",
        "     Enforced by packages/core/tests/test_bandit_suppressions_doc.py (drift = RED). -->",
        "",
        "Every suppression in the scanned source, verbatim. All entries are intentional —",
        "false positives or deliberate design decisions; the comment on each line carries its",
        "justification. Rows are keyed on file + line content (line numbers drift and are",
        "deliberately not recorded). Scope = the bandit hook's own file set: `packages/` minus",
        "the hook's `-x` exclusions, parsed from `.pre-commit-config.yaml` — one definition,",
        "so the register and the hook cannot drift apart. If a marker is ever legitimately",
        "needed in a non-src file (e.g. an alembic version or a script), it must land with",
        "this register regenerated in the SAME commit — the drift interlock is RED until it is.",
        "",
        f"**{len(rows)} suppression lines across {len({f for f, _ in rows})} files.**",
        "",
        "| File | Source line (verbatim) |",
        "|------|------------------------|",
    ]
    for rel, line in rows:
        escaped = line.replace("|", "\\|")
        row = f"| `{rel}` | `{escaped}` |"
        if any(t in line.lower() for t in _PRAGMA_TRIGGERS):
            row += _PRAGMA
        out.append(row)
    return "\n".join(out).rstrip("\n") + "\n"


def main() -> None:
    DOC_PATH.write_text(generate(), encoding="utf-8")
    print(f"wrote {DOC_PATH}")


if __name__ == "__main__":
    main()
