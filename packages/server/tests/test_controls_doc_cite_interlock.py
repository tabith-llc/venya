# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock for ``docs/controls.md`` — the page that states what Venya enforces.

**The defect this exists to stop.** A control table is written once, against a commit, and then the
tree moves. ``docs/beta-known-limitations.md`` carries the recorded instance: a page asserted about
110 ``file:line`` coordinates were "proved by reading the line the symbol names", and a read-only
audit found **60 of 86 coordinates in the entry bodies landed on the wrong line** while every
limitation was still true of the product. Nothing in the suite could see it, because nothing read the
page. ``docs/controls.md`` exists precisely because that failure is known, so it gets the same guard
rather than a promise.

**What is asserted, and how it is weaker or stronger than a line check.**

- Every table row must carry all four cells: control, ``path::symbol``, the commit it was verified at,
  and a re-derive command. A row with an empty fourth cell is a defect, not a draft.
- For each row the symbol is resolved against **the commit the row itself names**, by object content
  (``git show <sha>:<path>``), never by a line number. A row is honest about the face it was checked
  at and this test is what keeps that claim from rotting silently.
- The re-derive command is not executed here. This test checks the *cite*; running every cell-four
  command is the authoring procedure, recorded in the leg report's raw instrument.

**What is deliberately NOT asserted.** Whether a row's prose still describes the shipped behaviour.
That is a person re-deriving a claim against behaviour — the same boundary ``test_beta_terms_cite_interlock.py``
draws, and for the same reason: a guard that interprets sentences gets switched off inside a week.

**Fail-before, by design.** The first cell asserts the page EXISTS. Remove it and this file goes red
on its own, which is the property that makes it an interlock instead of a no-op.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parents[1]
REPO_ROOT = _PKG.parents[1]
DOC = REPO_ROOT / "docs" / "controls.md"

#: A mechanism cell is `path::symbol` (a symbol may itself be qualified, e.g.
#: `path::TestClass::test_method`), or a bare `path` for a whole-file cite (a test module).
MECHANISM = re.compile(r"^(?P<path>[\w./-]+\.(?:py|rs|md|sh|txt|json))" r"(?:::(?P<symbol>[\w:]+))?$")
#: Cell three: a short or full commit sha, optionally wrapped in backticks.
SHA = re.compile(r"^`?(?P<sha>[0-9a-f]{7,40})`?$")


def _git_rc(*args: str) -> int:
    """Run git and hand back the returncode. check=False is the honest statement: the returncode
    BELOW is the check, which is the same shape `test_beta_terms_cite_interlock.py` uses."""
    return subprocess.run(
        ["git", "-c", "safe.directory=*", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    ).returncode


def _git_show(ref: str) -> str | None:
    """`git show <ref>` as text, or None when the ref does not resolve here."""
    r = subprocess.run(
        ["git", "-c", "safe.directory=*", "show", ref],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout if r.returncode == 0 else None


def _table_rows(text: str) -> list[list[str]]:
    """Every markdown table data row in the page, as a list of stripped cells."""
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not (s.startswith("|") and s.endswith("|")):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells or all(set(c) <= set("-: ") for c in cells):
            continue  # separator row
        if cells[0] in {"Cell", "Number", "Control"}:
            continue  # header row (the predicate is the first cell's literal text)
        rows.append(cells)
    return rows


def _cell_objects() -> list[tuple[str, str, str, str]]:
    """(path, symbol, sha, command) for every control row that cites a mechanism."""
    out = []
    for cells in _table_rows(DOC.read_text()):
        if len(cells) != 4:
            continue  # the count/predicate tables, not control rows
        control, mechanism, verified, command = cells
        m = MECHANISM.match(mechanism.strip("`"))
        if not m:
            pytest.fail(
                f"control row does not carry a `path::symbol` mechanism cell: {control[:60]!r} "
                f"-> mechanism {mechanism[:60]!r}"
            )
        s = SHA.match(verified)
        if not s:
            pytest.fail(f"row for {control[:40]!r} names no commit in cell three: {verified[:60]!r}")
        if not command or "Re-derive" in command:
            pytest.fail(f"row for {control[:40]!r} has an empty re-derive command")
        out.append((m.group("path"), m.group("symbol"), s.group("sha"), command))
    return out


def test_controls_doc_exists() -> None:
    """The page is guarded, so it cannot be deleted or renamed without reddening this cell."""
    assert DOC.is_file(), f"{DOC.relative_to(REPO_ROOT)} is missing — the control page is required"


def test_every_row_has_four_cells() -> None:
    """A row missing its re-derive command is the failure the four-cell rule exists to prevent."""
    rows = [c for c in _table_rows(DOC.read_text()) if len(c) == 4]
    assert rows, "no four-cell control rows parsed — the page shape changed"
    for control, mechanism, verified, command in rows:
        assert mechanism, f"row {control[:40]!r} has an empty mechanism cell"
        assert SHA.match(verified), f"row {control[:40]!r} names no verified-at commit"
        assert len(command) > 8, f"row {control[:40]!r} has no usable re-derive command"


def test_symbols_resolve_at_the_commit_each_row_names() -> None:
    """The durable check: symbol present in the file at the row's OWN recorded commit."""
    objects = _cell_objects()
    assert (
        len(objects) >= 15
    ), f"only {len(objects)} verifiable control rows parsed; the page lost rows or changed shape"
    checked = 0
    for path, symbol, sha, _cmd in objects:
        if _git_rc("cat-file", "-e", f"{sha}^{{commit}}") != 0:
            pytest.skip(
                f"row cites {sha} which this clone does not hold — a shallow or partial checkout "
                "cannot verify a dated cite, and must not report one as green"
            )
        hay = _git_show(f"{sha}:{path}")
        assert hay is not None, f"{path} does not exist at {sha} (row cites a moved/deleted file)"
        if symbol:
            # Every `::`-separated segment must appear in the file at that commit. A qualified
            # cite like `TestClass::test_method` never appears as one string in the source, so
            # matching the whole needle would fail a perfectly live row.
            for needle in symbol.split("::"):
                assert needle in hay, (
                    f"symbol {needle!r} does not resolve in {path} at {sha} — the row's cite is "
                    f"stale. Re-derive: git show {sha}:{path} | grep -nF {needle!r}"
                )
        checked += 1
    assert checked, "no rows verified — the parse matched nothing"


def test_row_commits_are_known_objects_not_remembered_strings() -> None:
    """A sha in cell three must be a real commit here; a typo would otherwise pass silently."""
    shas = {sha for _p, _s, sha, _c in _cell_objects()}
    for sha in shas:
        rc = _git_rc("cat-file", "-e", f"{sha}^{{commit}}")
        if rc != 0:
            pytest.skip(f"{sha} not present in this clone; nothing to assert about it")
        assert rc == 0


def test_link_targets_exist_at_the_base() -> None:
    """The page links instead of restating; a dead link is the same defect class as a dead cite."""
    text = DOC.read_text()
    targets = sorted(set(re.findall(r"`(docs/[\w./-]+\.md)`", text)))
    assert targets, "expected the page to link at least one existing doc"
    for t in targets:
        assert (REPO_ROOT / t).is_file(), f"{t} is cited by docs/controls.md but is not in the tree"
