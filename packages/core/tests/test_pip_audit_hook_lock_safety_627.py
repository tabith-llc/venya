# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the pip-audit hook must audit the lockfile, never rewrite it (#627).

The hook's ``entry:`` read ``uv run pip-audit …``. ``uv run`` syncs the project environment before
executing, and that sync REWRITES tracked ``uv.lock`` whenever the lock disagrees with a just-edited
``packages/*/pyproject.toml`` — the very paths the hook's ``files:`` pattern fires on. A commit
attempt therefore landed tracked lines the committer never chose (observed at the beta1 nameplate
pen: ``revision = 3`` -> ``5`` plus seven version lines, 16 lines total) while pip-audit itself
printed "No known vulnerabilities found" and the chain failed only on "files were modified by this
hook". Retrying such a commit ships a lockfile change inside a commit that has nothing to do with it.

The defect is the WRITE, not the check, so this file guards both halves:

* the entry must carry a flag that forbids uv from touching ``uv.lock`` (``NO_WRITE_ASSERTIONS``); and
* the entry must still be the same audit — ``pip-audit``, the named feed, firing on member
  ``pyproject.toml`` edits — so no future "fix" makes the hook quiet by dropping or narrowing it.

Read-as-text discipline comes from ``test_pip_audit_feed_interlock.py`` (#568), including that
file's reason for a local reader instead of an import: the shipped entry is a single-line string and
a spread-over-lines entry is reported unreadable, never guessed at. The feed choice is re-derived
here rather than trusted from that file so the two interlocks cannot drift apart silently.

Every negative below mutates an in-memory copy of the config text, or a string built from the
shipped entry; the committed file is never written by this test.
"""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".pre-commit-config.yaml"

#: The runner the hook calls, its subcommand, and the tool it audits. Every cell below is derived
#: through these names, so a renamed runner or a removed tool is a parse failure, not a silent pass.
RUNNER = "uv"
RUN_SUBCOMMAND = "run"
TOOL = "pip-audit"

#: Flags that tell ``uv run`` it may not write the lockfile. Either one answers #627: the first
#: asserts the lock is current and fails the run when it is not, the second audits the committed
#: lock without checking it. The tree ships the stricter of the pair; this interlock guards the
#: CLASS — no lockfile write from inside a commit attempt — which is what regressing it would mean.
NO_WRITE_ASSERTIONS = ("--locked", "--frozen")

#: The audit question, unchanged by the #627 fix. #568 owns the feed choice; this file re-derives it
#: locally so a change to one interlock cannot silently undo the other.
EXPECTED_FEED_ARGS = ("--vulnerability-service", "osv")

#: A member manifest path the hook must fire on. The name is not load-bearing — the pattern is.
SAMPLE_MEMBER_MANIFEST = "packages/core/pyproject.toml"

_BLOCK_SCALAR_MARKERS = {">", "|", "|-", ">-", ">+", "|+"}

_UNREADABLE = (
    "the pip-audit hook entry is spread over several lines; this reader reports it unreadable "
    "and never guesses at a spread — keep the entry on one line as the repo ships it"
)

_HOOK_ID_RE = re.compile(r"^\s*-\s+id:\s*pip-audit\s*$")
_ANY_HOOK_ID_RE = re.compile(r"^\s*-\s+id:\s*\S+\s*$")
_ENTRY_RE = re.compile(r"^(\s*)entry:\s*(.*?)\s*$")
_FILES_RE = re.compile(r"^\s*files:\s*(.*?)\s*$")


# ------------------------------------------------------------------ config readers


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
    """The pip-audit hook's single-line ``entry:`` command, read as text."""
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


def hook_files_pattern(text: str) -> str:
    """The pip-audit hook's ``files:`` regex, unquoted from config TEXT.

    ``ast.literal_eval`` is the unquoter: the shipped value is a double-quoted scalar and YAML and
    Python agree on that form, so the pattern is read rather than string-matched. A missing files
    line is reported, never assumed to mean "everything".
    """
    lines = text.splitlines()
    start, end = _hook_block(lines)
    for index in range(start + 1, end):
        match = _FILES_RE.match(lines[index])
        if match:
            return str(ast.literal_eval(match.group(1)))
    raise ValueError("the pip-audit hook block carries no files: line, so when it runs is unknown")


def split_entry(entry: str) -> tuple[list[str], list[str]]:
    """Split an ENTRY command into (uv-side argv, tool-side argv) at the tool token.

    The split point matters because a flag after the tool belongs to the tool and not to uv — which
    is the difference between the #627 fix and an assertion that guards nothing.
    """
    tokens = shlex.split(entry)
    if len(tokens) < 2 or tokens[0] != RUNNER or tokens[1] != RUN_SUBCOMMAND:
        raise ValueError(f"the entry does not run `{RUNNER} {RUN_SUBCOMMAND}`: {tokens!r}")
    try:
        tool_at = tokens.index(TOOL, 2)
    except ValueError as exc:
        raise ValueError(f"the entry does not invoke `{TOOL}` at all — the audit is gone: {tokens!r}") from exc
    return tokens[2:tool_at], tokens[tool_at + 1 :]


def lock_assertions(entry: str) -> list[str]:
    """The uv-side tokens of ENTRY that forbid a lockfile write.

    Exactly one is required: none is the #627 defect, two is a contradiction about what the hook
    promises the lockfile, and a near-miss spelling is none of the above because uv never sees an
    assertion in it.
    """
    runner_argv, _ = split_entry(entry)
    found = [token for token in runner_argv if token in NO_WRITE_ASSERTIONS]
    if len(found) != 1:
        raise ValueError(
            f"the pip-audit hook entry carries {len(found)} lockfile-write assertions on the uv "
            f"side of its argv, exactly one is required; parsed uv-side argv {runner_argv!r}, the "
            f"accepted flags are {NO_WRITE_ASSERTIONS!r} — without one, `uv run` re-locks tracked "
            f"uv.lock inside the commit attempt (#627)"
        )
    return found


def assert_no_write(entry: str) -> str:
    """The single accepted assertion an ENTRY carries, or a refusal."""
    return lock_assertions(entry)[0]


def feed_pair(entry: str) -> tuple[str, str]:
    """The (flag, value) feed pair the tool side of ENTRY passes.

    Both spellings of the same pair (``--flag value`` and ``--flag=value``) are accepted so a
    harmless reformat is not read as a change of feed; the pair COUNT is not negotiable — zero pairs
    means the gate is blind, two means the choice is ambiguous.
    """
    _, tool_argv = split_entry(entry)
    flag = EXPECTED_FEED_ARGS[0]
    pairs: list[tuple[str, str]] = []
    for position, token in enumerate(tool_argv):
        if token == flag:
            if position + 1 >= len(tool_argv):
                raise ValueError(f"{flag} is passed with no value: {tool_argv!r}")
            pairs.append((flag, tool_argv[position + 1]))
        elif token.startswith(f"{flag}="):
            pairs.append((flag, token.split("=", 1)[1]))

    if len(pairs) != 1:
        raise ValueError(
            f"the pip-audit hook entry passes {len(pairs)} feed args, exactly one is required; "
            f"parsed tool-side argv {tool_argv!r}, the tree's named choice is {EXPECTED_FEED_ARGS!r}"
        )
    return pairs[0]


def assert_feed_choice(entry: str) -> tuple[str, str]:
    """Read the pair through the same parser and refuse unless it IS the tree's named choice."""
    pair = feed_pair(entry)
    if pair != EXPECTED_FEED_ARGS:
        raise ValueError(
            f"the shipped entry reads {entry!r}, which gives feed {pair!r}, but the tree names "
            f"{EXPECTED_FEED_ARGS!r} — the OSV gate is not what the hook runs (#568, #627)"
        )
    return pair


def assert_fires_on_member_manifest(text: str) -> str:
    """Refuse unless the hook's ``files:`` pattern still matches a member manifest path."""
    pattern = hook_files_pattern(text)
    if not re.search(pattern, SAMPLE_MEMBER_MANIFEST):
        raise ValueError(
            f"the pip-audit hook's files pattern {pattern!r} no longer matches "
            f"{SAMPLE_MEMBER_MANIFEST!r}, so an edit of that shape would not run the audit — the "
            f"pattern may be narrowed but not away from the manifests that trigger #627"
        )
    return pattern


# ------------------------------------------------------------------ in-memory mutators


def _config_text() -> str:
    return CONFIG.read_text(encoding="utf-8")


def _shipped_entry() -> str:
    return pip_audit_entry(_config_text())


def _rebuild_entry(runner_argv: list[str], tool_argv: list[str]) -> str:
    """An ENTRY command text rebuilt from its two halves, in shipped order."""
    return shlex.join([RUNNER, RUN_SUBCOMMAND] + runner_argv + [TOOL] + tool_argv)


def _entry_replacing_assertion(new_assertion: str) -> str:
    """The shipped entry with its uv-side assertion replaced, token for token."""
    runner_argv, tool_argv = split_entry(_shipped_entry())
    assertion = assert_no_write(_shipped_entry())
    replaced = [new_assertion if token == assertion else token for token in runner_argv]
    return _rebuild_entry(replaced, tool_argv)


def _entry_without_assertion() -> str:
    """The shipped entry with its assertion removed — the pre-fix form, DERIVED.

    Hand-typing the old command would freeze a second copy of it here; dropping the token the
    positive cell just read keeps this negative true as the entry travels.
    """
    runner_argv, tool_argv = split_entry(_shipped_entry())
    assertion = assert_no_write(_shipped_entry())
    return _rebuild_entry([token for token in runner_argv if token != assertion], tool_argv)


def _entry_with_assertion_after_the_tool() -> str:
    """The shipped entry with the assertion moved onto the tool's argv, where uv never sees it."""
    runner_argv, tool_argv = split_entry(_shipped_entry())
    assertion = assert_no_write(_shipped_entry())
    kept = [token for token in runner_argv if token != assertion]
    return _rebuild_entry(kept, [assertion] + tool_argv)


def _entry_without_feed_pair() -> str:
    """The shipped entry with the feed pair removed — a blind gate, not a quiet one."""
    runner_argv, tool_argv = split_entry(_shipped_entry())
    flag, value = feed_pair(_shipped_entry())
    return _rebuild_entry(runner_argv, [token for token in tool_argv if token not in (flag, value)])


def _entry_with_feed_pair_spelled_twice() -> str:
    """The shipped entry with the feed pair duplicated — an ambiguous choice."""
    runner_argv, tool_argv = split_entry(_shipped_entry())
    flag, value = feed_pair(_shipped_entry())
    return _rebuild_entry(runner_argv, tool_argv + [flag, value])


def _entry_replacing_feed_value(new_value: str) -> str:
    """The shipped entry with the feed VALUE rewritten, flag untouched."""
    runner_argv, tool_argv = split_entry(_shipped_entry())
    value = feed_pair(_shipped_entry())[1]
    swapped = [new_value if token == value else token for token in tool_argv]
    return _rebuild_entry(runner_argv, swapped)


def _config_with_entry(value: str) -> str:
    """The committed config text with the pip-audit entry replaced, IN MEMORY ONLY."""
    lines = _config_text().splitlines()
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


def _config_with_files(value: str) -> str:
    """The committed config text with the pip-audit ``files:`` line replaced, IN MEMORY ONLY."""
    lines = _config_text().splitlines()
    start, end = _hook_block(lines)
    for index in range(start + 1, end):
        match = _FILES_RE.match(lines[index])
        if match:
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            return "\n".join(lines[:index] + [f'{indent}files: "{value}"'] + lines[index + 1 :]) + "\n"
    raise AssertionError("the committed config carries no pip-audit files line to replace")


def _config_without_files_line() -> str:
    """The committed config text with the pip-audit ``files:`` line deleted, IN MEMORY ONLY."""
    lines = _config_text().splitlines()
    start, end = _hook_block(lines)
    for index in range(start + 1, end):
        if _FILES_RE.match(lines[index]):
            return "\n".join(lines[:index] + lines[index + 1 :]) + "\n"
    raise AssertionError("the committed config carries no pip-audit files line to remove")


def _config_without_hook() -> str:
    """The committed config text with the whole pip-audit hook block removed, IN MEMORY ONLY."""
    lines = _config_text().splitlines()
    start, end = _hook_block(lines)
    return "\n".join(lines[:start] + lines[end:]) + "\n"


# --------------------------------------------------------------------- positive halves


def test_committed_entry_carries_a_lockfile_write_assertion():
    """Positive half of the #627 guard: the shipped entry forbids uv from re-locking.

    The failure text names the parsed entry and the accepted flags, so a future edit reads as a
    difference between two derivable values rather than as a bare assert.
    """
    entry = _shipped_entry()
    assertion = assert_no_write(entry)
    assert assertion in NO_WRITE_ASSERTIONS, (
        f"the shipped entry {entry!r} asserts {assertion!r}, which is not one of " f"{NO_WRITE_ASSERTIONS!r}"
    )


def test_committed_entry_still_asks_the_same_audit_question():
    """The #627 fix changed WHERE uv reads the lock from, not WHAT is audited.

    Same tool, same single feed pair (#568's choice): this is the cell that refuses a "fix" which
    makes the hook quiet by dropping pip-audit or its feed instead of dropping the write.
    """
    entry = _shipped_entry()
    pair = assert_feed_choice(entry)
    assert pair == EXPECTED_FEED_ARGS, (
        f"the shipped entry reads {entry!r} → feed {pair!r}, but the tree names "
        f"{EXPECTED_FEED_ARGS!r} — the audit question moved (#568, #627)"
    )


def test_the_hook_still_fires_on_member_manifest_edits():
    """Positive half of the narrowing guard: a member pyproject edit still runs the audit."""
    pattern = assert_fires_on_member_manifest(_config_text())
    assert pattern, "the pip-audit hook ships no files pattern at all"


# --------------------------------------------------------------------- negative halves


def test_the_pre_fix_entry_form_is_refused():
    """Paired negative 1: the entry as it shipped before #627 is refused.

    This is the exact revert case — config line back to a bare ``uv run`` — and it must go red in
    the suite, not in someone's commit attempt.
    """
    with pytest.raises(ValueError, match="lockfile-write assertions"):
        assert_no_write(_entry_without_assertion())


@pytest.mark.parametrize("near_miss", ["--lock", "--freeze", "--locked=true"])
def test_a_near_miss_assertion_is_not_an_assertion(near_miss: str):
    """Paired negative 2: a spelled-almost-right flag forbids nothing."""
    with pytest.raises(ValueError, match="lockfile-write assertions"):
        assert_no_write(_entry_replacing_assertion(near_miss))


def test_two_assertions_together_are_refused():
    """Paired negative 3: both accepted flags is a contradiction, not belt-and-braces."""
    both = " ".join(NO_WRITE_ASSERTIONS)
    with pytest.raises(ValueError, match="lockfile-write assertions"):
        assert_no_write(_entry_replacing_assertion(both))


def test_an_assertion_after_the_tool_reaches_pip_audit_not_uv():
    """Paired negative 4: the right flag in the wrong half of the argv guards nothing.

    ``uv run pip-audit --locked …`` hands the flag to pip-audit; uv re-locks anyway.
    """
    with pytest.raises(ValueError, match="lockfile-write assertions"):
        assert_no_write(_entry_with_assertion_after_the_tool())


def test_dropping_the_feed_arg_is_refused():
    """Paired negative 5: an entry that audits with no named feed is refused."""
    with pytest.raises(ValueError, match="exactly one is required"):
        assert_feed_choice(_entry_without_feed_pair())


def test_a_different_feed_value_is_refused():
    """Paired negative 6: the choice moved to the other feed — the gate is not the tree's."""
    with pytest.raises(ValueError, match="but the tree names"):
        assert_feed_choice(_entry_replacing_feed_value("pypi"))


def test_a_duplicated_feed_arg_is_refused():
    """Paired negative 7: the pair spelled twice is ambiguous, so it is refused."""
    with pytest.raises(ValueError, match="exactly one is required"):
        assert_feed_choice(_entry_with_feed_pair_spelled_twice())


def test_an_entry_without_the_tool_is_refused():
    """Paired negative 8: an entry that keeps the assertion but drops pip-audit is refused."""
    assertion = assert_no_write(_shipped_entry())
    with pytest.raises(ValueError, match="does not invoke"):
        split_entry(f"{RUNNER} {RUN_SUBCOMMAND} {assertion} python -c pass")


def test_a_narrowed_files_pattern_is_refused():
    """Paired negative 9: a files: pattern that no longer fires on member manifests is refused."""
    with pytest.raises(ValueError, match="no longer matches"):
        assert_fires_on_member_manifest(_config_with_files("^docs/.*$"))


def test_a_missing_files_line_is_refused():
    """Paired negative 10: no files: line means when the hook runs is unknown, so it is refused."""
    with pytest.raises(ValueError, match="no files: line"):
        assert_fires_on_member_manifest(_config_without_files_line())


def test_a_missing_pip_audit_hook_is_refused():
    """Paired negative 11: deleting the hook is not a fix for the hook — the reader refuses.

    This is what makes "drop pip-audit from the chain" a red test rather than a tempting quiet
    option; the fail-loudly law allows no other answer to a mutating check.
    """
    with pytest.raises(ValueError, match="no pip-audit hook entry"):
        pip_audit_entry(_config_without_hook())


def test_an_entry_spread_over_lines_is_unreadable():
    """Paired negative 12: the same command spread across lines is reported, never guessed."""
    entry = _shipped_entry()
    spread = entry.replace(" --vulnerability-service", "\n  --vulnerability-service", 1)
    with pytest.raises(ValueError, match="spread over several lines"):
        pip_audit_entry(_config_with_entry(spread))
