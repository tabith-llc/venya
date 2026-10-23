# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the pip-audit hook runs against the OSV feed, and the tree says so (#568).

The dependency-CVE gate ships its feed choice on ONE YAML line in ``.pre-commit-config.yaml``.
Nothing in the repo asserted that line stays where it is: drop the flag in a future edit and the
pip-audit hook keeps running, every suite stays green, and the advisory gate silently changes
where it looks — the mako advisory that the OSV feed surfaced would no longer be visible.

This file is the missing enforcement, in the repo's own derive-both-sides shape (the pattern home
is ``test_detect_secrets_baseline.py::test_resync_remedy_names_every_configured_exclusion``,
#553): the config is read AS TEXT, its ``entry:`` command is read back out with ``shlex``, and the
result is compared to the named constant — never to a second hand-written copy of the flag.

Why the choice lives in the product tree: ``features/`` and ``dep-ledger.md`` are doc-repo files
that are absent from the product tree, so no product test can read them; ``EXPECTED_FEED_ARGS``
below is the in-repo home of the decision, and the dep-cadence prose stays authority-of-record
only.

Why a sibling reader instead of importing ``scripts/detect_secrets_baseline_guard.py``: that
guard's ``config_hook_args()`` is written for the detect-secrets hook's single-line ``args:``
LIST, and this hook ships a single-line ``entry:`` STRING. The discipline that travels is the
read-as-text rule — a spread-over-lines entry is reported unreadable, never guessed at — so this
file mirrors it locally and leaves the guard's own interlock untouched.

Negative halves below each mutate an in-memory copy of the config text only; the committed file
is never written.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"

#: The in-repo home of the feed choice (#568). The shipped hook entry and this constant are the
#: two sides every cell below compares; the flag literal is written nowhere else in this file
#: except here — see the one-hand-written-home cell.
EXPECTED_FEED_ARGS = ("--vulnerability-service", "osv")

#: How the hook invokes the tool: runner + the feed args rendered from the constant.
COMMAND_TEMPLATE = "uv run pip-audit {feed}"

#: YAML folded/literal block indicators — an entry that starts with one of these is a spread.
_BLOCK_SCALAR_MARKERS = {">", "|", "|-", ">-", ">+", "|+"}

_UNREADABLE = (
    "the pip-audit hook entry is spread over several lines; this reader reports it unreadable "
    "and never guesses at a spread — keep the entry on one line as the repo ships it"
)

_HOOK_ID_RE = re.compile(r"^\s*-\s+id:\s*pip-audit\s*$")
_ANY_HOOK_ID_RE = re.compile(r"^\s*-\s+id:\s*\S+\s*$")
_ENTRY_RE = re.compile(r"^(\s*)entry:\s*(.*?)\s*$")


def _hook_block(lines: list[str]) -> tuple[int, int]:
    """The (start, end) line indices of the pip-audit hook block in config TEXT."""
    start = None
    for index, line in enumerate(lines):
        if _HOOK_ID_RE.match(line):
            start = index
            break
    if start is None:
        raise ValueError("no pip-audit hook entry in the pre-commit config")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if _ANY_HOOK_ID_RE.match(lines[index]):
            end = index
            break
    return start, end


def pip_audit_entry(text: str) -> str:
    """The pip-audit hook's single-line ``entry:`` command, read as text.

    Read as text on purpose, mirroring ``guard.config_hook_args``: a hook block with no entry
    line, an entry with an empty or block-scalar value, or an entry continued on a deeper-indented
    following line is reported unreadable rather than parsed by guesswork.
    """
    lines = text.splitlines()
    start, end = _hook_block(lines)

    entry_at = None
    for index in range(start + 1, end):
        match = _ENTRY_RE.match(lines[index])
        if match:
            entry_at = (index, len(match.group(1)), match.group(2))
            break
    if entry_at is None:
        raise ValueError("the pip-audit hook block carries no entry: line at all")

    index, indent, value = entry_at
    if not value or value in _BLOCK_SCALAR_MARKERS:
        raise ValueError(_UNREADABLE)
    for follow in lines[index + 1 : end]:
        if not follow.strip():
            continue
        if len(follow) - len(follow.lstrip()) > indent:
            raise ValueError(_UNREADABLE)
        break
    return value


def read_feed_pair(entry: str) -> tuple[str, str]:
    """Derive the (flag, value) feed pair an ENTRY command text actually passes.

    Accepts both spellings of the same pair (``--flag value`` and ``--flag=value``) so a harmless
    reformat is not read as a change of feed; the pair COUNT is not negotiable — zero pairs means
    the gate is blind, two means the choice is ambiguous.
    """
    tokens = shlex.split(entry)
    flag = EXPECTED_FEED_ARGS[0]

    pairs: list[tuple[str, str]] = []
    for position, token in enumerate(tokens):
        if token == flag:
            if position + 1 >= len(tokens):
                raise ValueError(f"{flag} is passed with no value: {entry!r}")
            pairs.append((flag, tokens[position + 1]))
        elif token.startswith(f"{flag}="):
            pairs.append((flag, token.split("=", 1)[1]))

    if len(pairs) != 1:
        raise ValueError(
            f"the pip-audit hook entry passes {len(pairs)} feed args, exactly one is required; "
            f"parsed entry {tokens!r}, the tree's named choice is {EXPECTED_FEED_ARGS!r}"
        )
    return pairs[0]


def read_feed_choice(text: str) -> tuple[str, str]:
    """The feed pair of the pip-audit hook entry in pre-commit config TEXT."""
    return read_feed_pair(pip_audit_entry(text))


def assert_feed_choice(text: str) -> tuple[str, str]:
    """Read the pair through the same parser and refuse unless it IS the tree's named choice."""
    pair = read_feed_choice(text)
    if pair != EXPECTED_FEED_ARGS:
        raise ValueError(
            f"the shipped entry reads {pip_audit_entry(text)!r}, which gives feed {pair!r}, but "
            f"the tree names {EXPECTED_FEED_ARGS!r} — the OSV gate is not what the hook runs (#568)"
        )
    return pair


def _config_with_entry(value: str) -> str:
    """The committed config text with the pip-audit entry replaced, IN MEMORY ONLY.

    A value containing newlines is rendered as a spread: the first line keeps the shipped
    indentation, every later line sits two columns deeper.
    """
    lines = CONFIG.read_text(encoding="utf-8").splitlines()
    start, end = _hook_block(lines)
    for index in range(start + 1, end):
        match = _ENTRY_RE.match(lines[index])
        if match:
            indent = match.group(1)
            parts = value.split("\n")
            replacement = [f"{indent}entry: {parts[0]}"]
            replacement += [f"{indent}  {part}" for part in parts[1:]]
            return "\n".join(lines[:index] + replacement + lines[index + 1 :]) + "\n"
    raise AssertionError("the committed config carries no pip-audit entry line to replace")


def _config_without_hook() -> str:
    """The committed config text with the whole pip-audit hook block removed, IN MEMORY ONLY."""
    lines = CONFIG.read_text(encoding="utf-8").splitlines()
    start, end = _hook_block(lines)
    return "\n".join(lines[:start] + lines[end:]) + "\n"


def _config_text() -> str:
    return CONFIG.read_text(encoding="utf-8")


def test_committed_config_carries_the_named_feed_choice():
    """Positive half: the shipped hook entry passes exactly the feed the tree names.

    The failure text shows the parsed entry and the constant, so a future edit reads as a
    difference between two derivable values, not as a bare assert (the remedy-names-the-command
    discipline).
    """
    pair = assert_feed_choice(_config_text())
    assert pair == EXPECTED_FEED_ARGS, (
        f"the shipped entry reads {pip_audit_entry(_config_text())!r} → {pair!r}, the named "
        f"constant is {EXPECTED_FEED_ARGS!r} — one side moved (#568)"
    )


def test_config_and_constant_agree_through_the_same_parser():
    """Both sides derived, never hand-quoted at the assert site (the #553 lesson).

    The constant side is rendered into a command and fed through the SAME reader as the config
    side, so the comparison is parser-to-parser. A hand-written duplicate of the flag at this
    assert site is the shape the #553 defect had.
    """
    rendered = COMMAND_TEMPLATE.format(feed=shlex.join(EXPECTED_FEED_ARGS))
    from_constant = read_feed_pair(rendered)
    from_config = read_feed_choice(_config_text())

    assert from_constant == from_config, (
        f"the same parser reads {from_constant!r} out of the rendered constant and {from_config!r} "
        f"out of the shipped hook entry — the two sides no longer agree (#568)"
    )
    assert (
        from_config == EXPECTED_FEED_ARGS
    ), f"the config side disagrees with the named constant {EXPECTED_FEED_ARGS!r}: {from_config!r}"


def test_dropping_the_feed_arg_is_refused():
    """Negative half 1: entry with the flag removed → the gate goes blind, and says so."""
    blind = COMMAND_TEMPLATE.format(feed="")
    with pytest.raises(ValueError, match="exactly one is required"):
        assert_feed_choice(_config_with_entry(blind))


def test_a_different_feed_value_is_refused():
    """Negative half 2: entry rewritten to the other feed → refuses, the choice moved."""
    moved = COMMAND_TEMPLATE.format(feed=f"{EXPECTED_FEED_ARGS[0]} pypi")
    with pytest.raises(ValueError, match="but the tree names"):
        assert_feed_choice(_config_with_entry(moved))


def test_a_duplicated_feed_arg_is_refused():
    """Negative half 3: the pair spelled twice → ambiguous, so it is refused."""
    doubled = COMMAND_TEMPLATE.format(feed=f"{shlex.join(EXPECTED_FEED_ARGS)} {shlex.join(EXPECTED_FEED_ARGS)}")
    with pytest.raises(ValueError, match="exactly one is required"):
        assert_feed_choice(_config_with_entry(doubled))


def test_an_entry_spread_over_lines_is_unreadable():
    """Negative half 4: the same command spread across lines → unreadable, never guessed."""
    spread = "uv run pip-audit" + f" {EXPECTED_FEED_ARGS[0]}" + "\n" + EXPECTED_FEED_ARGS[1]
    with pytest.raises(ValueError, match="spread over several lines"):
        assert_feed_choice(_config_with_entry(spread))


def test_a_missing_pip_audit_hook_is_refused():
    """Negative half 5: the whole hook block deleted → the reader refuses to call that audited."""
    with pytest.raises(ValueError, match="no pip-audit hook entry"):
        assert_feed_choice(_config_without_hook())


def test_the_feed_flag_has_exactly_one_hand_written_home():
    """No second copy of the flag may be typed into this file (#553's stale-copy scan, sibling).

    The search token is derived from the constant, so this line does not match itself; the one
    line that must match is the constant definition above.
    """
    flag = EXPECTED_FEED_ARGS[0]
    source = Path(__file__).read_text(encoding="utf-8")
    typed = [line.strip() for line in source.splitlines() if flag in line]

    assert len(typed) == 1, (
        f"the feed flag literal appears on {len(typed)} lines of this test file, exactly one is "
        f"allowed (the EXPECTED_FEED_ARGS definition) — a hand-written second copy is how the "
        f"#553 defect hid: {typed}"
    )
