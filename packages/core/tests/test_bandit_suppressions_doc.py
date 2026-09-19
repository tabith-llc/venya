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
