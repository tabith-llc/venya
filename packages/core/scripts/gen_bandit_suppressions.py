# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Generate docs/bandit-nosec-suppressions.md from the live source tree.

The previous hand-maintained register rotted to 0/49 accurate rows (venya-dev
ticket docs-staleness-sweep-20260919): line numbers drift, sites move, new
suppressions never got added. This generator scans every non-test source line
carrying a `nosec` marker and emits it VERBATIM — rows are keyed on file +
line content, never line numbers, so ordinary edits above a site don't rot
the doc. Adding/removing/editing a suppression changes the doc -> the
interlock test (packages/core/tests/test_bandit_suppressions_doc.py) goes
RED until regenerated:

    uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py

Scope mirrors the pre-commit bandit hook: `packages/*/src` only (all five
tests/ dirs are hook-excluded, so their suppressions are not security-
relevant and are not listed).
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_PATH = REPO_ROOT / "docs" / "bandit-nosec-suppressions.md"
NOSEC_RE = re.compile(r"#\s*nosec")

# detect-secrets "Secret Keyword" fires on verbatim-quoted source lines that
# look like assignments of a passphrase-named constant (e.g. the B105-suppressed
# env-var-NAME lines in server ca.py). These rows quote lines ALREADY committed
# in source (they passed the hook there), so an inline pragma here cannot mask
# a new leak — it only stops re-flagging the quotation. Rule is content-keyed,
# so regeneration stays deterministic and the drift interlock stays byte-exact.
_PRAGMA_TRIGGERS = ("password", "passphrase", "secret", "token", "api_key")
_PRAGMA = " <!-- pragma: allowlist secret -->"


def scan() -> list[tuple[str, str]]:
    """(repo-relative file, stripped verbatim line) for every nosec marker."""
    rows: list[tuple[str, str]] = []
    for src in sorted(REPO_ROOT.glob("packages/*/src")):
        for py in sorted(src.rglob("*.py")):
            rel = py.relative_to(REPO_ROOT).as_posix()
            for line in py.read_text(encoding="utf-8").splitlines():
                if NOSEC_RE.search(line):
                    rows.append((rel, line.strip()))
    return rows


def generate() -> str:
    rows = scan()
    out = [
        "# Bandit `# nosec` Suppressions",
        "",
        "<!-- GENERATED FILE — DO NOT HAND-EDIT.",
        "     Source of truth: every `nosec` marker under packages/*/src.",
        "     Regenerate: uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py",
        "     Enforced by packages/core/tests/test_bandit_suppressions_doc.py (drift = RED). -->",
        "",
        "Every suppression in the scanned source, verbatim. All entries are intentional —",
        "false positives or deliberate design decisions; the comment on each line carries its",
        "justification. Rows are keyed on file + line content (line numbers drift and are",
        "deliberately not recorded). Scope = `packages/*/src` — the same tree the pre-commit",
        "bandit hook scans (tests dirs are hook-excluded).",
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
