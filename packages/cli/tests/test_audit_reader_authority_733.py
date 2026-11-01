# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: #733 AC5 — the reader-facing audit surfaces name the authoritative column.

`execution_sessions` holds two texts for one command: `command` (the stored display
copy, rendered by `render_command`) and `command_argv` (the argument list exactly as
submitted). Before this row the truthful one was undocumented on every reader side —
`git grep -l 'command_argv' -- docs packages/cli packages/mcp` returned 0 files at tip
`d6811649` — so a reader comparing two renderings had nothing in the product's own text
to say which one wins.

These cells read the shipped text, not a lane's prose, and each can fail: a page that
drops the column name reddens them.
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1].parents[1]
_DOCS = _REPO_ROOT / "docs"

# The pages that describe what an audit reader is handed, plus the generated CLI page
# (docs/cli-reference.md renders the live parser's help — test_cli_reference_doc.py is
# what keeps that file equal to `venya audit --help`, so asserting here covers the CLI
# face without reaching into argparse internals).
_AUTHORITY_PAGES = ("architecture.md", "example-workflow.md", "cli-reference.md")


def _doc(name: str) -> str:
    path = _DOCS / name
    assert path.is_file(), f"expected shipped doc {name} to exist"
    return path.read_text(encoding="utf-8")


def test_audit_reader_pages_name_the_authoritative_column():
    """The AC's own predicate, inverted: the shipped pages name the column.

    Rejects the tip state outright, where the count was zero files and the truthful
    column appeared nowhere a human or an agent reads."""
    naming = [n for n in _AUTHORITY_PAGES if "command_argv" in _doc(n)]
    missing = set(_AUTHORITY_PAGES) - set(naming)
    assert not missing, f"pages that never name execution_sessions.command_argv: {sorted(missing)}"


def test_each_page_states_which_text_wins_not_that_two_exist():
    """Naming both columns is not enough — the reader needs the precedence rule."""
    for name in _AUTHORITY_PAGES:
        text = _doc(name)
        assert "authoritative" in text, f"{name} names the column but never says it wins"


def test_no_reader_face_is_claimed_as_a_carrier_of_the_list():
    """Paired negative on the doc move (iid 713 AC3 / R-2631 no-echo bar, and the AC's
    own limit: it asks that the column be NAMED, not that its contents be printed).
    Every page that names it must also say the audit response does not carry it, so no
    reader is taught to expect argv bodies on a face that will never show them."""
    for name in ("architecture.md", "example-workflow.md"):
        text = _doc(name)
        assert (
            "not part of that response" in text or "not part of this response" in text
        ), f"{name} names command_argv without telling the reader it is not delivered here"
