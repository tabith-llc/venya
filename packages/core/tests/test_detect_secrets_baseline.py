# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the committed .detect-secrets-baseline must cover the full tree.

The detect-secrets pre-commit hook refreshes the baseline only for the files it
is passed (staged files), so findings in never-staged files never enter the
baseline and resurface as a confusing NEW finding in some future changeset
(ticket detect-secrets-baseline-scope-drift). This test runs the same scan the
hook runs (detect-secrets 1.5.0, same --exclude-files arg) over the whole tree
and asserts zero delta against the committed baseline.

Hosted in core alongside the other repo-wide generated-artifact interlocks
(test_bandit_suppressions_doc.py); the baseline is a scan artifact with no
runtime import.
"""

import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE = REPO_ROOT / ".detect-secrets-baseline"


def _findings(scan_output: dict) -> set:
    return {
        (filename, secret["type"], secret["hashed_secret"])
        for filename, secrets in scan_output["results"].items()
        for secret in secrets
    }


def _full_tree_scan(tmp_path: Path) -> dict:
    """Run the hook's scan semantics over every tracked file.

    The temp copy stands in for the committed baseline so the repo file is
    never mutated; the tracked baseline itself is excluded from the scan
    (mirroring the hook's is_baseline_file self-exclusion).
    """
    tool = shutil.which("detect-secrets")
    assert tool, "detect-secrets missing from the test env (core dev group)"
    copy = tmp_path / BASELINE.name
    copy.write_text(BASELINE.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(
        [
            tool,
            "scan",
            "--baseline",
            str(copy),
            "--exclude-files",
            "target/",
            # the hook self-excludes the baseline via the is_baseline_file filter,
            # which only fires when --baseline is given the repo-relative name;
            # on the temp copy, exclude the tracked baseline file by regex instead
            "--exclude-files",
            r"\.detect-secrets-baseline$",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(copy.read_text(encoding="utf-8"))


def test_scanner_version_matches_baseline_version():
    """The dev-group pin and the hook rev must agree (tool-drift half)."""
    committed = json.loads(BASELINE.read_text(encoding="utf-8"))
    tool = shutil.which("detect-secrets")
    assert tool, "detect-secrets missing from the test env (core dev group)"
    out = subprocess.run([tool, "--version"], check=True, capture_output=True, text=True)
    assert out.stdout.strip() == committed["version"], (
        "installed detect-secrets != baseline's recording version — "
        "sync the core dev-group pin with the .pre-commit-config.yaml rev"
    )


def test_full_tree_scan_equals_committed_baseline(tmp_path):
    committed = json.loads(BASELINE.read_text(encoding="utf-8"))
    fresh = _full_tree_scan(tmp_path)
    added = _findings(fresh) - _findings(committed)
    stale = _findings(committed) - _findings(fresh)
    assert not added, (
        "unbaselined findings — the committed baseline does not cover the full tree; "
        "resync: detect-secrets scan --baseline .detect-secrets-baseline --exclude-files 'target/'\n"
        + "\n".join(f"  + {f} | {t} | {h}" for f, t, h in sorted(added))
    )
    assert not stale, "stale baseline entries — recorded secrets no longer scan in the tree\n" + "\n".join(
        f"  - {f} | {t} | {h}" for f, t, h in sorted(stale)
    )
