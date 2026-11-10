# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock for docs/beta-known-limitations.md — the beta terms page a design partner signs.

**The defect this exists to stop.** The page carried ~110 `file:line` coordinates and asserted each one
"was proved by reading the line the symbol names". A read-only audit at `28d0a93d3adf` (2026-10-18)
found **60 of the 86 coordinates in the entry bodies land on the wrong line** — a blank, a comment, or
a different function — while every one of the page's *limitations* was still true of the product. The
numbers rot within a day or two on this tree; the page's own maintenance note says so. Nothing in the
suite could see it, because nothing read the page: `git grep -l 'beta-known-limitations' <dev> --
'packages/*/tests/*'` returned **zero files** before this cell existed.

**What is asserted here, and what is deliberately NOT.**

- **Durable assertion (always on):** every coordinate on the page names a tracked file that exists,
  and the symbol the surrounding prose names for that cite **exists in that file**. This survives any
  merge, because it never claims a line number is current.
- **Not asserted today:** that each number sits on the line its symbol names. The owner ruled
  *"claim-truth now, numbers re-pinned at the cut commit with a checked assertion"*
  (2026-10-18), and `dev` moved twice while the page was being corrected — so a hand-pinned number is
  a number re-dug at every merge. The **generator** (`packages/server/scripts/gen_beta_terms_pins.py`)
  is what re-pins them — the **live** coordinates, never the digits inside the dated pass-record block
  below `DATED_BLOCK_FIRST_PAGE_LINE`, which are a history a named commit was measured at and are held
  to the symbol rule only — and it runs **at the cut commit**. When it has run, the pinned-at sha below is
  the current one and the strict cell becomes live; until then that cell reports the pins as
  UNVERIFIED rather than dressing a stale number up as green.
- **Never asserted:** the page's prose. Whether a limitation still describes the shipped tree is a
  person's re-derivation against behaviour (the audit method: read the entry's claim, grep the
  mechanism, confirm or refute it). A guard that interprets sentences gets switched off inside a week.

Provenance law binds the pin block: if `HEAD` has moved past the pinned sha in an affected file, the
pins read UNVERIFIED, not green. That is `test_pinned_sha_is_not_yet_current_is_honest`, below.

**Co-landing procedure (learned the expensive way at #675/#745, leg 918).** A suite run at one branch tip proves
that tip alone. Sibling branches here must be run TOGETHER, because the machinery in this file reads generated
state that another branch legitimately rewrites. `merge-tree` rc 0 is a text splice, not a test. The check, from a
venue whose venv matches the tree it is running:

    git fetch --force origin refs/heads/<sibling-branch>:refs/remotes/origin/<sibling-branch>
    git checkout -B tmp-coface-<leg> <this-tip> && git merge --no-edit origin/<sibling-branch>
    uv run -p 3.14 --directory packages/server pytest tests/test_beta_terms_cite_interlock.py -q   # both orders
    git switch <this-branch> && git branch -D tmp-coface-<leg>          # explicit names, never --prune

Measured at `5cf9cf86` against `7a804334`: 19 passed forward, 19 passed in reverse, and the whole `server` suite at
the joint face 3158 passed / 0 failed / 30 skipped door OFF. The in-suite carrier for the class is
`test_a_shipped_manifest_rekey_cannot_break_these_cells`, which needs no second branch to prove its point.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

_PKG = Path(__file__).resolve().parents[1]
REPO_ROOT = _PKG.parents[1]
DOC = REPO_ROOT / "docs" / "beta-known-limitations.md"
_GEN = _PKG / "scripts" / "gen_beta_terms_pins.py"

_spec = importlib.util.spec_from_file_location("gen_beta_terms_pins", _GEN)
gen = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
# Register BEFORE exec: @dataclass resolves string annotations through sys.modules[cls.__module__],
# and a module loaded by spec alone is not registered — without this the whole file errors at import.
sys.modules["gen_beta_terms_pins"] = gen
_spec.loader.exec_module(gen)

#: The sha the coordinates were last RE-PINNED by the generator, or ``None`` when they never have
#: been. Set by running the generator at the cut commit (`--write`) and filling this in from ITS
#: OWN stdout, in the same changeset. It is no longer ``None``: the generator ran at `25ece37`
#: (`d3897ec`, 105 cites re-pinned, manifest 96 -> 93 keys). At the face named below `--write`
#: reported `re-pinned 105 cites and re-keyed 4 manifest keys at 35bc369d…` — 4 coordinates moved
#: because the `audit` help line and the fresh-store print shifted `cli.py` by 6 lines and
#: `commands.py` by 4, and the other 101 re-resolved to the lines they already printed; the
#: coordinates are exact there BY VERIFICATION, not by inheritance. Earlier strikes: the
#: `v0.1.0beta2` cut against `f1eb83d4` (`--check` rc 0, `would change: False`, 105 cites, manifest
#: 93/93 keys at that face); the beta1 strike was `e8f19821`, the face the beta1 cut commit was
#: written on.
#: A commit cannot contain its own sha, so this
#: value names the settled release face the pin was struck against (the parent of the commit that
#: sets it) rather than the one the generator first ran at: the strict cell diffs `PINNED_AT..HEAD`
#: over `CITED_ROOTS`, `packages/` is one of those roots, so this very file counts as moved and the
#: cell RE-RESOLVES all 105 cites against the live tree and asserts agreement. A merge that moves a
#: cited symbol from here forward reddens the suite instead of quietly publishing a stale line.
PINNED_AT: str | None = (
    "c1b08544ae14449ab71f8144059e38e5825f0fb0"  # pragma: allowlist secret — a git commit sha at the house form used by test_serial_cap_64_676.py:34 and test_admin_revoke_already_revoked_262.py:30; not a credential
)

#: Files whose churn invalidates the pins — the tree the cites point into.
CITED_ROOTS = ("packages/", "install-venya-core.sh", "install-venya-executor.sh", "venya-common.sh")


def _git(*args: str) -> str:
    # check=False is the honest statement: the returncode below IS the check.
    r = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr[:200]}")
    return r.stdout


def _text() -> str:
    assert DOC.is_file(), f"{DOC} missing — the beta terms page is a release gate artifact"
    return DOC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# The durable assertion: named symbol exists in the named file.
# --------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------
# The key-collision audit (#675, a prior worker lane): a duplicate dict key is SILENT in Python.
# --------------------------------------------------------------------------------------

_MANIFEST_PY = _PKG / "scripts" / "beta_terms_cites.py"


def test_manifest_has_no_duplicate_keys() -> None:
    """Source keys must equal runtime keys, and no key may carry two meanings.

    `test_every_cite_is_manifested_and_its_symbol_exists` asks the manifest what each cite means, so a
    manifest that LOST an entry to a repeated key answers confidently and wrongly — every metric stays
    green on the surviving meaning. That is the failure this cell exists to catch, and it is not
    catchable from the runtime dict: `len(MANIFEST)` cannot see what Python already discarded. Counting
    keys in the SOURCE, before the dict collapses them, is the only way.
    """
    src = _MANIFEST_PY.read_text(encoding="utf-8")
    n_src, n_run, dups = gen.audit_keys(src)
    assert n_src == n_run, (
        f"MANIFEST declares {n_src} keys but holds {n_run}: {n_src - n_run} were silently discarded by a "
        "repeated dict key. Delete the redundant entry or give it a distinct coordinate."
    )
    conflicting = {k: v for k, v in dups.items() if len(set(v)) > 1}
    assert not conflicting, f"duplicate keys with DIFFERENT values, one meaning is lost: {conflicting}"


def test_positive_control_a_planted_duplicate_goes_red() -> None:
    """RED BEFORE GREEN on the real predicate — the same lesson the false-symbol falsifier teaches.

    Half 1 plants a duplicate key over a real entry with a DIFFERENT value and shows the audit that
    guards the cut reports it. Half 2 shows the untouched manifest passes the identical call, so a
    broken harness cannot pass the red half by accident.
    """
    src = _MANIFEST_PY.read_text(encoding="utf-8")
    clean = gen.audit_keys(src)
    assert clean[0] == clean[1], f"the shipped manifest already fails its own audit: {clean[2]}"
    victim = next(iter(gen._load_manifest().MANIFEST))
    lines = src.split("\n")
    node = gen._manifest_dict_node(ast.parse(src))
    assert node is not None and node.end_lineno, "no MANIFEST literal to plant into"
    # Splice INSIDE the MANIFEST literal. Appending at end-of-file would land in DATED_OVERRIDES (the
    # last dict in the file) and the audit would correctly see nothing — a fixture that tests nothing is
    # worse than no fixture, which is what this line cost to learn.
    i = node.end_lineno - 1
    planted = "\n".join(
        lines[:i] + [f'    {victim!r}: ("some/other/file.py", "x", 7, "pin"),', lines[i]] + lines[i + 1 :]
    )
    p_src, p_run, p_dups = gen.audit_keys(planted)
    assert p_src > p_run, "planted duplicate did NOT change the source/runtime counts — the audit is decoration"
    assert (
        victim in p_dups and len(set(p_dups[victim])) > 1
    ), f"FALSIFIER FAILED: audit_keys did not report the planted key {victim!r} as value-conflicting"
    assert gen.manifest_key_problems(planted), "manifest_key_problems returned nothing on a corrupt manifest"
    assert gen.manifest_key_problems(src) == [], "the untouched manifest reports problems"


def test_rekey_refuses_a_collision_instead_of_clobbering_it() -> None:
    """The exact shape that made a hand union green-and-wrong must be a refusal, not a write.

    A re-pin can move one cite ONTO a coordinate another cite is leaving; if the two carry different
    values, last-wins silently re-assigns a meaning. `main()` refuses that case before it renames
    anything, and the predicate it uses is the merge this cell exercises — first on a fixture that MUST
    collide, then on a swap that must NOT be called a clobber.
    """
    man = gen._load_manifest().MANIFEST
    keys = list(man)
    a, b = keys[0], keys[1]

    def merge(moved: dict[str, str]) -> list[str]:
        grouped: dict[str, list] = {}
        for k in keys:
            grouped.setdefault(moved.get(k, k), []).append(tuple(man[k]))
        return [k for k, v in grouped.items() if len(v) > 1 and len(set(v)) > 1]

    # The collision: `a` lands on b's key while b stays put -> two different values share one key.
    assert merge({a: b}) == [b], "the fixture's collision was not detected — the guard proves nothing"
    # The harmless case the same code must ALLOW: a genuine swap, where each key ends up with one value.
    assert merge({a: b, b: a}) == [], "a two-way swap was called a clobber — --write would refuse a good re-pin"


def test_every_cite_is_manifested_and_its_symbol_exists() -> None:
    """The durable assertion, and the reason the manifest exists.

    Every coordinate on the page must be a DECIDED cite: named in the manifest, pointing at a
    tracked file, with a symbol that is verifiably present in that file today. An unmanifested
    token is RED — a new cite on a page a partner signs is a claim somebody has to own.
    """
    files = gen._tracked_files()
    cites = gen.parse_cites(_text(), files)
    assert cites, "the page carries no cites at all — this cell would pass by checking nothing"
    bad = gen.check_symbols(cites, files)
    assert not bad, "cite integrity failures on the beta terms page:\n" + "\n".join(bad)


def test_positive_control_a_planted_false_symbol_goes_red() -> None:
    """RED BEFORE GREEN, on the real predicate — a guard that cannot fail is decoration.

    Half 1: take one genuine cite, swap its curated symbol for one that exists nowhere, and show
    the SAME function that guards the page reports it. Half 2: the untouched page passes it. Both
    halves run in this cell, so a broken harness cannot pass the red half by accident.
    """
    files = gen._tracked_files()
    cites = [c for c in gen.parse_cites(_text(), files) if c.kind == "pin" and c.path in files]
    assert cites, "no pinnable cites to falsify against"
    target = cites[0]
    BOGUS = "zzz_symbol_that_cannot_exist_in_any_venya_file_zzz"
    assert not any(BOGUS in ln for ln in files[target.path]), "the bogus literal is real?! falsifier proves nothing"

    planted = gen.Cite(
        path=target.path,
        start=target.start,
        end=target.end,
        symbol=BOGUS,
        line=target.line,
        occurrence=1,
        kind="pin",
    )
    red = gen.check_symbols([planted], files)
    assert red, (
        "FALSIFIER FAILED: check_symbols accepted a symbol that exists in no file. "
        "This guard would pass a fabricated cite, so it guards nothing."
    )
    # GREEN half: the page as it stands passes the same call.
    assert gen.check_symbols(cites, files) == [], "the untouched page fails its own integrity check"

    # And the occurrence arm: an occurrence beyond the real hit count must refuse, not clamp.
    over = gen.Cite(
        path=target.path,
        start=target.start,
        end=target.end,
        symbol=target.symbol,
        line=target.line,
        occurrence=9999,
        kind="pin",
    )
    assert gen.resolve([over], files)[0][1] is None, "an out-of-range occurrence resolved — that is a guess"


def test_ambiguous_bare_filenames_are_not_accepted_cites() -> None:
    """`auth.py` matches two tracked files, `config.py` three — a cite that could mean either is
    not a citation, it is a coin toss. Full paths are therefore mandatory in the LIVE entries.

    Scoped to the entries on purpose: the maintenance block below them is a dated record whose
    digits are quoted from older passes, and it is held to the symbol rule, not the path rule.
    """
    DATED_BLOCK_FIRST_PAGE_LINE = gen._load_manifest().DATED_BLOCK_FIRST_PAGE_LINE

    files = gen._tracked_files()
    offenders: list[str] = []
    for c in gen.parse_cites(_text(), files):
        if c.line >= DATED_BLOCK_FIRST_PAGE_LINE:
            continue
        matches = gen._basename_matches(c.path, files)
        if len(matches) != 1:
            offenders.append(f"  page:{c.line} {c.token} -> {len(matches)} tracked files")
    assert not offenders, "ambiguous cite path(s) in a live entry:\n" + "\n".join(offenders)


def test_generated_output_touches_digits_only() -> None:
    """The generator may re-pin numbers and nothing else.

    If it ever edits prose it is authoring a release disclosure, and an authored disclosure is not
    reviewable. Compared line-wise: differing lines must differ only in digits.
    """
    text = _text()
    try:
        new = gen.generate(text)
    except ValueError as e:
        # A refusal is a legitimate outcome at an unpinned face; it must be a NAMED refusal.
        assert "cite integrity failed" in str(e) or "cannot re-pin" in str(e), str(e)[:200]
        print("generator refuses at this face — see the message; nothing was written")
        return
    if new == text:
        return
    a, b = text.split("\n"), new.split("\n")
    assert len(a) == len(b), "generator changed line COUNT — it rewrites tokens, it does not reflow prose"

    def _canon(t: str) -> str:
        # A cite token is (path):N — both the digits and the PATH spelling are the generator's
        # business (`.../executors.py:702` normalises to the full path). Prose is not. So collapse
        # an entire cite to one marker, then collapse digits, and require the rest to be identical.
        t = re.sub(r"[A-Za-z0-9_.\-/]+\.(?:py|sh|md|rs|ps1|toml):\d+(?:-\d+)?", "CITE", t)
        return re.sub(r"\d+", "#", t)

    offenders = []
    for i, (x, y) in enumerate(zip(a, b), 1):
        if x == y:
            continue
        if re.sub(r"\d+", "#", x) == re.sub(r"\d+", "#", y):
            continue  # digits only
        if _canon(x) == _canon(y):
            continue  # digits and/or the cite token's path spelling
        offenders.append(f"  line {i}:\n    -{x.strip()[:120]}\n    +{y.strip()[:120]}")
    assert not offenders, (
        "the generator changed something that is not a cite (prose is a person's, on a release "
        "disclosure):\n" + "\n".join(offenders)
    )


def test_the_page_shape_is_what_the_release_points_at() -> None:
    """Cheap existence + shape cells, so a rename cannot quietly make this guard vacuous."""
    text = _text()
    assert "Beta known limitations" in text, "the H1 moved; the release pointers need updating with it"
    entries = re.findall(r"^### ", text, re.MULTILINE)
    assert len(entries) >= 8, f"expected the disclosed entries, found {len(entries)}"
    files = gen._tracked_files()
    cites = gen.parse_cites(text, files)
    print(
        f"beta terms page: {len(text.splitlines())} lines, {len(entries)} entries, "
        f"{len(cites)} coordinates ({sum(1 for c in cites if c.kind == 'pin')} pinnable, "
        f"{sum(1 for c in cites if c.kind == 'dated')} dated records)"
    )


# --------------------------------------------------------------------------------------
# The pin discipline: live only once the generator has actually re-pinned at a named sha.
# --------------------------------------------------------------------------------------


def test_pin_state_is_declared_not_assumed() -> None:
    """Until someone RUNS the generator, PINNED_AT is None and this cell says so out loud.

    A green strict cell at a tip nobody re-pinned at would be the exact lie that started this:
    numbers asserted as proved at a face that had already moved.
    """
    if PINNED_AT is None:
        # The honest state today. Not skipped — asserted, so a later seat sees the obligation.
        assert _git("rev-parse", "HEAD").strip() != "0" * 40
        print(
            "beta terms coordinates are UNVERIFIED: the generator has never run. "
            "Run `uv run -p 3.14 --directory packages/server python scripts/gen_beta_terms_pins.py "
            "--write` AT THE CUT COMMIT and set PINNED_AT in the same changeset."
        )
        return
    assert PINNED_AT.strip(), "PINNED_AT must be a sha"
    _git("cat-file", "-e", f"{PINNED_AT}^{{commit}}")  # raises if the pin is not a commit here


def test_pins_match_the_tree_they_claim_at_when_pinned() -> None:
    """Strict assertion: live ONLY when PINNED_AT names a real run of the generator.

    This is the cell that becomes the cut-commit gate. It reddens if a merge moved a cited symbol
    after the pin, because then the page's numbers describe a commit that is no longer HEAD — and it
    is held to the same boundary the generator is. A cite at or below ``DATED_BLOCK_FIRST_PAGE_LINE``
    is a record of what a named past pass measured, so its digits are not a claim about today's tree
    and are not compared against it; its SYMBOL is still asserted, by
    ``test_every_cite_is_manifested_and_its_symbol_exists``, which is the symbol rule the dated block
    has always been under.
    """
    if PINNED_AT is None:
        print("strict pin check deferred: generator has not run (see PINNED_AT)")
        return
    moved = _git("diff", "--name-only", PINNED_AT, "HEAD", "--", *CITED_ROOTS).strip()
    if not moved:
        return
    files = gen._tracked_files()
    bad = []
    for c in gen.parse_cites(_text(), files):
        if not c.symbol or c.path not in files:
            continue
        if c.kind != "pin":
            continue  # a dated record's digits are history; its symbol is checked, its line is not
        lines = files[c.path]
        # #684-class resolver defect: this took the FIRST line containing the symbol, while the
        # generator takes the c.occurrence-th one. Three pin rows declare occurrence >= 2, so the
        # cell could report MOVED on a page that was right. One resolver now, shared with the two
        # cells below, so the strict path and the generator cannot answer differently.
        actual = _resolve_for_test(lines, c.symbol, c.occurrence)
        if actual is not None and actual != c.start:
            bad.append(f"  page:{c.line} {c.token} says {c.start}, symbol {c.symbol!r} is at {actual}")
    assert not bad, f"cited symbols moved since {PINNED_AT} — re-run the generator at the cut commit:\n" + "\n".join(
        bad
    )


def _resolve_for_test(lines: list[str], symbol: str, occurrence: int) -> int | None:
    """The one resolver, shared by the strict cell and its negative halves."""
    hits = [i for i, ln in enumerate(lines, 1) if symbol in ln]
    return hits[occurrence - 1] if 0 < occurrence <= len(hits) else None


def test_agrees_with_the_generator_resolver_on_every_pinned_symbol() -> None:
    """The strict cell and the generator must not answer differently for any real pin row.

    This is the drift guard. The defect this leg fixed was two implementations of one rule: the
    generator took the Nth hit, the cell took the first, and the cell never read ``occurrence``.
    Runs whether or not ``PINNED_AT`` is set, so the agreement is asserted today, not only at the cut.
    """
    files = gen._tracked_files()
    text = _text()
    mismatches = []
    checked = 0
    for c in gen.parse_cites(text, files):
        if not c.symbol or c.path not in files or c.kind != "pin":
            continue
        mine = _resolve_for_test(files[c.path], c.symbol, c.occurrence)
        theirs = gen.resolve([c], files)[0][1]
        checked += 1
        if mine != theirs:
            mismatches.append(
                f"  page:{c.line} {c.token} symbol={c.symbol!r} occ={c.occurrence}: cell={mine} generator={theirs}"
            )
    assert checked > 0, "the pin manifest resolved nothing — this cell would be vacuous"
    assert (
        not mismatches
    ), f"cell resolver and generator resolver disagree on {len(mismatches)} pin row(s):\n" + "\n".join(mismatches)


def test_occurrence_2_pin_resolves_to_the_second_line_and_first_line_pin_reddens() -> None:
    """Paired negative for the resolver, on a planted symbol that occurs twice.

    Positive half: a row declaring ``occurrence=2`` pointing at the SECOND line passes.
    Negative half: the same fixture pointing at the FIRST line is a mismatch, so a pin that ignores
    ``occurrence`` cannot pass silently.
    Control: the pre-fix expression is computed here and shown to answer a DIFFERENT line from the
    generator on this same fixture — that is the wrongness this leg removed, stated in a cell that
    goes green either way.
    """
    lines = [
        "def unrelated(): pass",
        "needle_fn = 1",
        "    return needle_fn",
    ]
    containing = [i for i, ln in enumerate(lines, 1) if "needle_fn" in ln]
    assert containing == [2, 3], "the planted fixture must actually carry two occurrences"

    cite = gen.Cite(path="x/y.py", start=3, end=3, symbol="needle_fn", line=42, occurrence=2)
    # generator's own answer, and the cell's answer, agree on the second line
    assert gen.resolve([cite], {"x/y.py": lines})[0][1] == 3
    assert _resolve_for_test(lines, cite.symbol, cite.occurrence) == 3

    # positive half: a pin claiming line 3 is NOT a move
    assert _resolve_for_test(lines, cite.symbol, cite.occurrence) == cite.start

    # negative half: the same row claiming the FIRST line is a move, and reddens the strict check
    wrong = gen.Cite(path="x/y.py", start=2, end=2, symbol="needle_fn", line=42, occurrence=2)
    assert _resolve_for_test(lines, wrong.symbol, wrong.occurrence) != wrong.start

    # control: the shape this cell had before the fix takes the first hit, and disagrees with the
    # generator on this fixture. Computed, never asserted as correct.
    first_match = next((i for i, ln in enumerate(lines, 1) if cite.symbol in ln), None)
    assert first_match == 2, "the old resolver's answer is what makes this a real paired negative"
    assert first_match != cite.start


# --------------------------------------------------------------------------------------
# The dated block is a record, not a claim (#675 machinery defect, found at #745's gate).
#
# One token can hold two roles on this page: `install-venya-executor.sh:558` is a LIVE entry at
# page 247 ("the executor installer rewrites this key on every run") and part of a dated
# "did not move" roster at page 1209. The manifest keys by token, so it cannot tell them apart,
# and a blanket re-pin rewrites history: turning the roster's `558` into today's line asserts that
# a named past pass measured the current tree. The boundary is not a new class —
# `DATED_BLOCK_FIRST_PAGE_LINE` is declared in the manifest and already honoured by the
# ambiguous-path cell above; the pin machinery alone ignored it. These cells scope it by that one
# constant and prove the scope has bounds: the same token, above the boundary, is still re-pinned.
# --------------------------------------------------------------------------------------

_MOVED_TOKEN = "install-venya-executor.sh:558"
_MOVED_PATH = "install-venya-executor.sh"
_MOVED_SYMBOL = "printf 'relay_client_ids = "
_LIVE_PAGE_LINE = 247
_RECORD_PAGE_LINE = 1209
_SYMBOL_LINE_IN_FAKE_TREE = 609


def _planted_manifest(boundary: int) -> SimpleNamespace:
    """The manifest the paired-negative cells classify against, declared here rather than borrowed.

    Why this exists: the fixture's token is a LIVE coordinate, and moving live coordinates is what
    the generator is for. Leg 904's legitimate ``--write`` re-keyed ``install-venya-executor.sh:558``
    to ``:609`` and left ``:558`` only in ``DATED_OVERRIDES`` — so at the 913+904 face the shipped data
    answered "dated" for BOTH fixture rows, ``generate()`` moved nothing, and four cells in this file
    went red (measured at the co-landed face in both merge orders: 4 failed / 14 passed). A fixture
    whose premise is a value the machinery rewrites is a snapshot, not a test.

    So the token's ROLE is stated here. What stays production: the classifier, ``resolve()``,
    ``check_symbols()`` and ``generate()`` under test are the shipped code, and the region boundary is
    read from the shipped manifest by the caller and never copied into this file, so the number still
    has exactly one definition.
    """
    return SimpleNamespace(
        MANIFEST={_MOVED_TOKEN: (_MOVED_PATH, _MOVED_SYMBOL, 1, "pin")},
        DATED_OVERRIDES={},
        DATED_BLOCK_FIRST_PAGE_LINE=boundary,
    )


def _plant_manifest_in(module, monkeypatch=None) -> None:
    """Point one generator module at the planted manifest, keeping its shipped boundary."""
    boundary = module._load_manifest().DATED_BLOCK_FIRST_PAGE_LINE
    planted = _planted_manifest(boundary)
    if monkeypatch is not None:
        monkeypatch.setattr(module, "_load_manifest", lambda: planted)
    else:
        # a generator imported by path inside a cell has no monkeypatch to borrow
        module._load_manifest = lambda: planted  # type: ignore[attr-defined]


def _files_with_symbol_at(line: int) -> dict[str, list[str]]:
    """A tracked-file map where the cited symbol sits on ``line`` and nowhere else."""
    lines = [f"    filler line {i}" for i in range(1, line)]
    lines.insert(line - 1, f'    {_MOVED_SYMBOL}"%s-relay"]\\n\' "$CORE_HOSTNAME"')
    lines.append("    trailer")
    return {"install-venya-executor.sh": lines}


def _one_token_two_roles_page() -> str:
    """A page carrying the SAME coordinate once as a live entry and once inside the record."""
    lines = ["plain prose"] * 1300
    lines[_LIVE_PAGE_LINE - 1] = f"- the installer rewrites this key on every run (`{_MOVED_TOKEN}`)"
    lines[_RECORD_PAGE_LINE - 1] = f"- the cites that were re-read and did not move: … and `{_MOVED_TOKEN}`"
    return "\n".join(lines)


def _change_report(before: str, after: str) -> list[int]:
    return [i for i, (a, b) in enumerate(zip(before.split("\n"), after.split("\n")), 1) if a != b]


def test_the_classifier_is_where_the_region_decides(monkeypatch) -> None:
    """parse_cites gives the two roles different kinds; that single decision is the whole fix."""
    _plant_manifest_in(gen, monkeypatch)
    files = _files_with_symbol_at(_SYMBOL_LINE_IN_FAKE_TREE)
    cites = {c.line: c for c in gen.parse_cites(_one_token_two_roles_page(), files)}
    assert cites[_LIVE_PAGE_LINE].kind == "pin", "the live row lost its pin role — the scope is over-broad"
    assert cites[_RECORD_PAGE_LINE].kind == "dated", "the record row is still pinnable — history gets rewritten"
    # and the record is still a citation about a real thing, not a skipped row
    assert cites[_RECORD_PAGE_LINE].symbol == _MOVED_SYMBOL, "a dated row lost its symbol, so the symbol rule is gone"
    assert gen.resolve([cites[_RECORD_PAGE_LINE]], files)[0][1] is None, "resolve() would still answer a line for it"
    assert gen.resolve([cites[_LIVE_PAGE_LINE]], files)[0][1] == _SYMBOL_LINE_IN_FAKE_TREE


def test_generate_repins_the_live_row_and_leaves_the_record_digits_alone(monkeypatch) -> None:
    """The paired negative, end to end: same token, opposite treatment, decided by region."""
    _plant_manifest_in(gen, monkeypatch)
    monkeypatch.setattr(gen, "_tracked_files", lambda: _files_with_symbol_at(_SYMBOL_LINE_IN_FAKE_TREE))
    page = _one_token_two_roles_page()
    out = gen.generate(page)
    changed = _change_report(page, out)
    assert changed == [_LIVE_PAGE_LINE], f"expected one live row to move, got pages {changed}"
    assert f"{_MOVED_TOKEN.split(':')[0]}:{_SYMBOL_LINE_IN_FAKE_TREE}" in out.split("\n")[_LIVE_PAGE_LINE - 1]
    assert (
        out.split("\n")[_RECORD_PAGE_LINE - 1] == page.split("\n")[_RECORD_PAGE_LINE - 1]
    ), "the dated roster's digits moved — a record was edited"


def test_the_older_machinery_rewrote_the_record_too(tmp_path) -> None:
    """RED BEFORE GREEN, on a real run of the pre-fix code — not an emulation of it.

    The generator resolves its manifest as a sibling of ``__file__`` and REPO_ROOT three parents up,
    so both files are laid down in a nested directory and imported by path, the same way the module
    header of this file loads the current one. Same fixture, same fake tree, one difference: the
    classifier had no region test. If this cell ever goes green without failing, the fixture no
    longer discriminates and the scoping above is decoration.
    """
    pre_dir = tmp_path / "repo" / "packages" / "server" / "scripts"
    pre_dir.mkdir(parents=True)
    (pre_dir / "gen_beta_terms_pins.py").write_text(
        _git("show", "a788ece3:packages/server/scripts/gen_beta_terms_pins.py"), encoding="utf-8"
    )
    (pre_dir / "beta_terms_cites.py").write_text(_MANIFEST_PY.read_text(encoding="utf-8"), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_beta_terms_pins_prefix", pre_dir / "gen_beta_terms_pins.py")
    assert spec and spec.loader
    old = importlib.util.module_from_spec(spec)
    sys.modules["gen_beta_terms_pins_prefix"] = old
    spec.loader.exec_module(old)

    files = _files_with_symbol_at(_SYMBOL_LINE_IN_FAKE_TREE)
    _plant_manifest_in(old)
    old_cites = {c.line: c for c in old.parse_cites(_one_token_two_roles_page(), files)}
    assert old_cites[_RECORD_PAGE_LINE].kind == "pin", "the fixture no longer distinguishes old from new classification"
    old._tracked_files = lambda: files
    old_out = old.generate(_one_token_two_roles_page())
    assert _change_report(_one_token_two_roles_page(), old_out) == [
        _LIVE_PAGE_LINE,
        _RECORD_PAGE_LINE,
    ], "the pre-fix generator did not touch the record line either — this defect is not what the scoping fixes"


def test_a_dated_row_whose_symbol_is_gone_still_goes_red(monkeypatch) -> None:
    """Scoping narrows the POSITION rule only; the symbol rule stays armed on the record."""
    _plant_manifest_in(gen, monkeypatch)
    files = {"install-venya-executor.sh": ["    something else entirely"]}
    cites = gen.parse_cites(_one_token_two_roles_page(), files)
    red = gen.check_symbols(cites, files)
    assert any(
        f"page:{_RECORD_PAGE_LINE}" in line for line in red
    ), f"a dated record citing a symbol that is not in the file passed unnoticed: {red}"


def test_the_boundary_is_declared_once() -> None:
    """No second copy of the number: the manifest's constant is the only definition of where the
    dated record starts, and the two consumers read it, they do not restate it."""
    boundary = str(gen._load_manifest().DATED_BLOCK_FIRST_PAGE_LINE)
    for path in (_PKG / "scripts" / "gen_beta_terms_pins.py", _PKG / "tests" / "test_beta_terms_cite_interlock.py"):
        body = path.read_text(encoding="utf-8")
        offenders = [ln.strip() for ln in body.splitlines() if re.search(rf"\b{boundary}\b", ln)]
        assert not offenders, f"{path.name} hardcodes the dated boundary instead of the constant: {offenders}"
    # and the fixture in this file sits on the right sides of it, or the paired negative proves nothing
    assert (
        _LIVE_PAGE_LINE < int(boundary) <= _RECORD_PAGE_LINE
    ), f"fixture pages {[_LIVE_PAGE_LINE, _RECORD_PAGE_LINE]} no longer straddle the boundary {boundary}"


_MAINTENANCE_HEADING = "## How to read an entry, and how this list is maintained"


def test_the_dated_boundary_still_lands_on_the_maintenance_heading() -> None:
    """The number is a claim about the page's shape, so the page checks it back.

    A boundary that drifts is worse than no boundary: too early and live coordinates stop being
    re-pinned (the state #675 found — 660 sat inside a live entry and exempted a live carrier at
    page 772), too late and a dated record's digits get rewritten. Pinning the boundary to the
    heading the page itself uses for its maintenance block means a re-flow reddens this cell on the
    next merge instead of quietly changing what the guard exempts.
    """
    boundary = gen._load_manifest().DATED_BLOCK_FIRST_PAGE_LINE
    page_lines = _text().split("\n")
    assert page_lines[boundary - 1].strip() == _MAINTENANCE_HEADING, (
        f"line {boundary} is {page_lines[boundary - 1].strip()[:60]!r}, not the maintenance heading — "
        "re-derive DATED_BLOCK_FIRST_PAGE_LINE from the page, never from this message"
    )
    # the entries above it are the live disclosure body, and the roster below it is history
    assert any(line.startswith("## ") for line in page_lines[: boundary - 1]), "no live section above the boundary"
    assert _MAINTENANCE_HEADING not in "\n".join(page_lines[: boundary - 1]), "the heading appears twice"
    roster = [c for c in gen.parse_cites(_text(), gen._tracked_files()) if c.line >= boundary]
    assert roster and all(
        c.kind == "dated" or not c.symbol for c in roster
    ), "a coordinate inside the maintenance block is still classified pinnable"


def test_a_shipped_manifest_rekey_cannot_break_these_cells(monkeypatch) -> None:
    """The face leg 913 lacked, written as a check instead of a lesson.

    Both halves run in one cell, so this is not a claim about a fixture nobody can break.

    Half 1 reproduces the defect on purpose: take the shipped manifest and drop the fixture's token,
    which is exactly what a legitimate ``--write`` does to a LIVE coordinate when it re-keys it, and
    show that a fixture borrowing that answer collapses — both rows come back ``dated`` because the
    token survives only in the dated-note dict. That collapse is the 913+904 co-landing red (4 failed
    / 14 passed, both merge orders) this leg exists to remove.

    Half 2 is the same page, the same fake tree and the same shipped classifier/resolve/generate code
    with the premise planted: the live row is a pin, the record row is dated, and exactly one line
    moves. A cell that reads production data as its own fixture breaks at the next cut; a cell that
    reads a planted premise and still calls the production code does not.
    """
    shipped = gen._load_manifest()
    rekeyed = SimpleNamespace(
        MANIFEST={k: v for k, v in shipped.MANIFEST.items() if k != _MOVED_TOKEN},
        DATED_OVERRIDES=dict(shipped.DATED_OVERRIDES),
        DATED_BLOCK_FIRST_PAGE_LINE=shipped.DATED_BLOCK_FIRST_PAGE_LINE,
    )
    assert _MOVED_TOKEN in dict(
        shipped.DATED_OVERRIDES
    ), "half 1 needs the dated-note entry for this token or the reproduction proves nothing"
    files = _files_with_symbol_at(_SYMBOL_LINE_IN_FAKE_TREE)
    page = _one_token_two_roles_page()

    monkeypatch.setattr(gen, "_load_manifest", lambda: rekeyed)
    monkeypatch.setattr(gen, "_tracked_files", lambda: files)
    borrowed = {c.line: c.kind for c in gen.parse_cites(page, files)}
    assert borrowed[_LIVE_PAGE_LINE] != "pin", (
        f"the re-key no longer collapses a borrowed premise ({borrowed[_LIVE_PAGE_LINE]!r}); "
        "this cell's second half would then be proving nothing"
    )
    assert gen.generate(page) == page, "the borrowed-premise face moved something after all"

    _plant_manifest_in(gen, monkeypatch)
    planted = {c.line: c for c in gen.parse_cites(page, files)}
    assert planted[_LIVE_PAGE_LINE].kind == "pin" and planted[_RECORD_PAGE_LINE].kind == "dated", planted
    assert _change_report(page, gen.generate(page)) == [_LIVE_PAGE_LINE]
