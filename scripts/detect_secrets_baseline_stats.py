# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Print ``.detect-secrets-baseline`` counts by the only method that is right (refs #550).

WHY THIS EXISTS. The baseline is JSON whose top-level ``results`` object is keyed by
scanned filename, so ``len(json['results'])`` is the file count. The document ALSO
carries the string ``"filename"`` in 45 other places: every recorded finding repeats
its own ``"filename"``, and ``filters_used`` carries
``{"path": "detect_secrets.filters.common.is_baseline_file",
"filename": ".detect-secrets-baseline"}`` — the baseline references ITSELF as filter
configuration, not as a scanned file. So any method that tokenizes the document
over-counts. Measured at dev ``dbbf1dc`` (22 files / 44 findings / 491 lines):

    grep -c '"filename"' .detect-secrets-baseline                       -> 45  WRONG
    grep -o '"filename": "[^"]*"' | sort -u | wc -l                     -> 23  WRONG (self-reference)
    grep -c 'filename:' .detect-secrets-baseline                        -> 0   WRONG (the key is quoted)
    python3 -c "import json;print(len(json.load(open(...))['results']))" -> 22 RIGHT

A lane that uses a wrong method "discovers" drift that does not exist, and the
tempting remedy — regenerate or hand-edit the baseline — is exactly what the
anti-weakening rule forbids. This tool is the one place the method is written down,
so lanes stop re-inventing greps; it reads the file and prints each number WITH its
method. It never writes the baseline: there is no code path here that mutates it.

SCOPE. Reporting only (refs #550 AC-3, design-minimal for a LOW hazard). The shrink
guard is a separate concern and lives in ``scripts/detect_secrets_baseline_guard.py``;
this module imports nothing from it and changes none of its logic.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASELINE_FILENAME = ".detect-secrets-baseline"

#: How each published number is derived — printed with it, so a count is never a bare guess.
METHODS = {
    "files": "len(json['results'])",
    "findings": "sum(len(v) for v in json['results'].values())",
    "lines": "count of newline characters (equals `wc -l` on a file with a trailing newline)",
}


def stats_of(baseline_text: str) -> dict[str, int]:
    """``files`` / ``findings`` / ``lines`` for one baseline document.

    Unparseable content raises so a caller never reports numbers it could not read.
    """
    data = json.loads(baseline_text)
    results = data.get("results")
    if not isinstance(results, dict):
        raise TypeError("baseline content has no 'results' object")
    return {
        "files": len(results),
        "findings": sum(len(secrets) for secrets in results.values()),
        "lines": baseline_text.count("\n"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Count the detect-secrets baseline by JSON parsing, never by grep.")
    parser.add_argument("--baseline", default=BASELINE_FILENAME, help="baseline path (default: %(default)s)")
    parser.add_argument("--json", action="store_true", help="emit one machine-readable line, methods included")
    args = parser.parse_args(argv)

    try:
        stats = stats_of(Path(args.baseline).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        print(f"baseline stats cannot read {args.baseline}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({name: stats[name] for name in ("files", "findings", "lines")} | {"methods": METHODS}))
        return 0

    for name in ("files", "findings", "lines"):
        print(f"{stats[name]:>5} {name:<8} (METHOD: {METHODS[name]})")
    print(f"source: {args.baseline} — read only, never written by this tool (refs #550)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
