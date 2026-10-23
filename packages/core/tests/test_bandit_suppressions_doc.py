# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock for docs/bandit-nosec-suppressions.md (GENERATED — never hand-edit).

Same pattern as test_cli_reference_doc.py: the committed doc must byte-equal a
fresh regeneration, so adding/removing/editing any `nosec` suppression without
regenerating is RED. Plus a scanner sanity pair (a known site is found; a
non-marker string is not treated as one).
"""

import importlib.util
import subprocess
from pathlib import Path

_CORE_PKG = Path(__file__).resolve().parents[1]
_REPO_ROOT = _CORE_PKG.parents[1]
_DOC = _REPO_ROOT / "docs" / "bandit-nosec-suppressions.md"
_GEN = _CORE_PKG / "scripts" / "gen_bandit_suppressions.py"

_spec = importlib.util.spec_from_file_location("gen_bandit_suppressions", _GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def test_doc_matches_regeneration():
    assert _DOC.exists(), f"{_DOC} missing — run scripts/gen_bandit_suppressions.py"
    assert _DOC.read_text(encoding="utf-8") == gen.generate(), (
        "bandit-nosec-suppressions.md drifted from the source tree; regenerate: "
        "uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py"
    )


def test_scanner_finds_known_site():
    """Positive half: a long-lived suppression is in the scan."""
    rows = gen.scan()
    assert any(
        rel.endswith("executor/src/executor/executor.py") and "B404" in line for rel, line in rows
    ), "known subprocess-import B404 suppression not found — scanner broken"


def test_scanner_ignores_non_markers():
    """Negative half: only lines with a # nosec marker are rows."""
    rows = gen.scan()
    assert all("# " in line or "#" in line for _, line in rows)
    assert not any("nosec" not in line.lower() for _, line in rows)
    # this very test file mentions 'nosec' in prose but lives under tests/ — excluded by scope
    assert not any(rel.endswith("test_bandit_suppressions_doc.py") for rel, _ in rows)


def test_doc_lists_every_scanned_file():
    text = _DOC.read_text(encoding="utf-8")
    for rel in {f for f, _ in gen.scan()}:
        assert f"`{rel}`" in text, f"{rel} missing from the doc"


def test_scanner_scope_covers_non_src_tracked_files():
    """Widened scope (refs 485): the register scans what the hook scans.

    The old src-only glob missed the tracked non-src files bandit does scan
    (alembic tree, scripts); they must be in the scanned set now, while the
    hook's own -x exclusions still hold.
    """
    rels = {p.relative_to(_REPO_ROOT).as_posix() for p in gen.scanned_files()}
    assert "packages/core/alembic/env.py" in rels
    assert any(r.startswith("packages/core/alembic/versions/") for r in rels)
    assert "packages/core/scripts/gen_bandit_suppressions.py" in rels
    assert "packages/cli/scripts/gen_cli_reference.py" in rels
    assert not any("/tests/" in r for r in rels), "hook-excluded tests/ leaked into scope"
    assert not any("/.venv/" in r for r in rels), "hook-excluded .venv leaked into scope"


def test_scanner_picks_up_marker_outside_src(tmp_path):
    """Paired negative (refs 485): a marker OUTSIDE packages/*/src IS picked up.

    Temp tree whose only in-scope marker sits in an alembic version file — a
    file class the old src-only glob could never see. The old scan() took no
    root argument and globbed packages/*/src under the real repo, so it could
    never return this row; the test cannot pass pre-fix.
    """
    (tmp_path / "packages" / "demo" / "alembic" / "versions").mkdir(parents=True)
    (tmp_path / "packages" / "core" / "tests").mkdir(parents=True)
    alembic = tmp_path / "packages" / "demo" / "alembic" / "versions" / "0001_demo.py"
    alembic.write_text("op = 1  # nosec B999 — outside-src marker\n", encoding="utf-8")
    excluded = tmp_path / "packages" / "core" / "tests" / "test_demo.py"
    excluded.write_text("op = 2  # nosec B999 — hook-excluded\n", encoding="utf-8")
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n"
        "  - repo: https://github.com/PyCQA/bandit\n"
        "    rev: 1.7.9\n"
        "    hooks:\n"
        "      - id: bandit\n"
        '        args: ["-r", "packages/", "-x", "packages/core/tests/"]\n',
        encoding="utf-8",
    )
    # the scanned set is the hook's file set restricted to tracked files —
    # make the temp tree a (throwaway) repo so both files are tracked
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)

    rows = gen.scan(tmp_path)
    assert {rel for rel, _ in rows} == {"packages/demo/alembic/versions/0001_demo.py"}, (
        "outside-src marker not picked up (or hook-excluded file leaked) — "
        "the register scope has drifted from the hook's file set"
    )
