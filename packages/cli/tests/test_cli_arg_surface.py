# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Exhaustive argparse-contract coverage for the whole `venya` CLI surface.

Ticket cli-arg-surface-test-coverage: the test matrix below is BUILT AT IMPORT
TIME by walking `create_parser()` — it cannot drift from the real CLI because
the list IS the real CLI. Add an argument and its cases grow automatically.
The only pinned literals are the per-level subcommand counts (the deliberate
tripwire: a silently dropped subparser fails the suite).

Scope is the argparse contract only: parse / validate / reject / default.
No server, no FIDO2 key, no command execution — `parse_args()` is the unit
under test; a valid parse returns a Namespace (== exit 0), a usage error
raises SystemExit(2). Execution-level side effects are per-feature tests'
and the physical e2e suites' territory.

Special shapes handled explicitly (never silently skipped):

- `run`'s `command_args` (nargs=REMAINDER) is excluded from the generic
  per-argument matrix and pinned in TestRunRemainderShape — including the
  physically verified behavior (CPython 3.14) that REMAINDER swallows unknown
  flags once a command token was seen (`run true --no-such-flag` PARSES; the
  flags belong to the remote command). The unknown-flag rejection case for
  `run` therefore rides the bare base argv.
- `init --skip-migrations` is argparse.SUPPRESS'd (deprecated no-op):
  TestSuppressedSkipMigrations pins accepted-but-hidden.
- Synthesized argvs place positionals BEFORE options: greedy nargs='+'
  options (store --roles) swallow positional tokens that follow them —
  standard argparse interleaving, physically verified.

Private argparse attributes (_actions, _SubParsersAction, _AppendAction,
_StoreTrueAction) are the introspection surface — stable across CPython
3.x and the point of this module.

DOCUMENTED LIMITATION (mutation-verified 2026-09-19): this module pins
ENFORCEMENT of the declared contract, not the declarations themselves.
Mutating cli.py to drop `required=True` reclassifies that argument's cases
(missing-required -> default-application) with the total count UNCHANGED —
green here; only feature tests catch it. Dropping `type=int` shrinks the
wrong-type cases (caught at the gate by the suite-count lineage shrinkage
rule, AGENTS.md). Dropped/added SUBCOMMANDS are caught by the pinned count
tripwire below. Pinning per-declaration literals would violate the ticket's
no-hard-coded-argument-list acceptance criterion.
"""

import argparse
import sys
from unittest.mock import patch

import pytest
from venya_cli.cli import create_parser, main

# ---------------------------------------------------------------------------
# Parser-tree walk — the matrix source of truth
# ---------------------------------------------------------------------------

PARSERS: list[tuple[tuple[str, ...], argparse.ArgumentParser]] = []


def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
    PARSERS.append((path, parser))
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                _walk(sub, path + (name,))


_walk(create_parser(), ())

PARSER_BY_PATH = dict(PARSERS)
ALL_PATHS = [path for path, _ in PARSERS]


def _arg_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    """Every argument action on `parser` except help and subparser dispatch."""
    return [a for a in parser._actions if a.dest != "help" and not isinstance(a, argparse._SubParsersAction)]


def _is_remainder(action: argparse.Action) -> bool:
    return action.nargs == argparse.REMAINDER


def _is_required(action: argparse.Action) -> bool:
    if action.option_strings:
        return action.required
    return action.nargs not in ("?", "*", argparse.REMAINDER)


def _synth(action: argparse.Action) -> tuple[list[str], object]:
    """(value tokens, expected namespace value) for one occurrence of `action`."""
    if isinstance(action, argparse._StoreTrueAction):
        return [], True
    if action.choices:
        value = next(iter(action.choices))
        return [str(value)], value
    if action.type is int:
        return ["7"], 7
    if isinstance(action, argparse._AppendAction) or action.nargs == "+":
        return ["x"], ["x"]
    return ["x"], "x"


def _argv(
    path: tuple[str, ...],
    override: tuple | None = None,
    skip_dest: str | None = None,
) -> list[str]:
    """Synthesize an argv for the command at `path`.

    Required args are always included (positionals before options — see module
    docstring). `override` = (action, tokens[, flag]) passes `tokens` to that
    action (flag defaults to its first option string). `skip_dest` omits one
    action even if required. REMAINDER actions are never synthesized here
    (pinned separately in TestRunRemainderShape).
    """
    override_action = override[0] if override else None
    pos: list[str] = []
    opts: list[str] = []
    for a in _arg_actions(PARSER_BY_PATH[path]):
        if _is_remainder(a):
            continue
        if a is override_action:
            tokens = override[1]
            if a.option_strings:
                opts.append(override[2] if len(override) > 2 else a.option_strings[0])
                opts.extend(tokens)
            else:
                pos.extend(tokens)
        elif _is_required(a) and a.dest != skip_dest:
            tokens = _synth(a)[0]
            if a.option_strings:
                opts.append(a.option_strings[0])
                opts.extend(tokens)
            else:
                pos.extend(tokens)
    return [*path, *pos, *opts]


# Derived case matrices — no hand-maintained argument list anywhere below.
_MATRIX = [(path, a) for path, parser in PARSERS for a in _arg_actions(parser) if not _is_remainder(a)]
VALID_CASES = _MATRIX
DEFAULT_CASES = [(p, a) for p, a in _MATRIX if not _is_required(a)]
MISSING_CASES = [(p, a) for p, a in _MATRIX if _is_required(a)]
CHOICES_CASES = [(p, a) for p, a in _MATRIX if a.choices]
INT_CASES = [(p, a) for p, a in _MATRIX if a.type is int]
ALIAS_CASES = [(p, a, alias) for p, a in _MATRIX if a.option_strings for alias in a.option_strings[1:]]


def _idfn(value: object) -> str:
    if isinstance(value, tuple):
        return "-".join(value) or "top"
    if isinstance(value, argparse.Action):
        return value.dest
    return str(value)


def _parse(argv: list[str]) -> argparse.Namespace:
    """Parse on a FRESH parser (never share instances across parse calls)."""
    return create_parser().parse_args(argv)


def _assert_exit2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        _parse(argv)
    assert exc.value.code == 2, f"argparse usage error must exit 2 for {argv!r}"


# ---------------------------------------------------------------------------
# Per-argument contract cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path,action", VALID_CASES, ids=_idfn)
def test_valid_invocation_parses(path, action):
    """Every argument accepts a shape-valid value and lands on its dest."""
    tokens, expected = _synth(action)
    ns = _parse(_argv(path, override=(action, tokens)))
    assert getattr(ns, action.dest) == expected


@pytest.mark.parametrize("path,action", DEFAULT_CASES, ids=_idfn)
def test_default_applied_when_omitted(path, action):
    """Every optional argument's declared default is present when omitted."""
    ns = _parse(_argv(path))
    assert getattr(ns, action.dest) == action.default


@pytest.mark.parametrize("path,action", MISSING_CASES, ids=_idfn)
def test_missing_required_rejected(path, action):
    """Omitting a required positional/option is a usage error (exit 2)."""
    _assert_exit2(_argv(path, skip_dest=action.dest))


@pytest.mark.parametrize("path,action", CHOICES_CASES, ids=_idfn)
def test_invalid_choice_rejected(path, action):
    """A value outside declared `choices` is a usage error (exit 2)."""
    _assert_exit2(_argv(path, override=(action, ["bogus-value-not-in-choices"])))


@pytest.mark.parametrize("path,action", INT_CASES, ids=_idfn)
def test_wrong_type_rejected(path, action):
    """A non-int on a type=int argument is a usage error (exit 2)."""
    _assert_exit2(_argv(path, override=(action, ["not-an-int"])))


@pytest.mark.parametrize("path,action,alias", ALIAS_CASES, ids=_idfn)
def test_every_declared_option_string_accepted(path, action, alias):
    """Short/long aliases beyond the first all parse to the same value."""
    tokens, expected = _synth(action)
    ns = _parse(_argv(path, override=(action, tokens, alias)))
    assert getattr(ns, action.dest) == expected


# ---------------------------------------------------------------------------
# Per-parser contract cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ALL_PATHS, ids=_idfn)
def test_unknown_flag_rejected(path):
    """Unknown --flag is a usage error (exit 2) on every command path.

    Unknown-flag rejection is a parser property, so one case per parser covers
    every argument's command. `run` passes here because the base argv has no
    command token yet — see TestRunRemainderShape for the post-token behavior.
    """
    _assert_exit2([*_argv(path), "--no-such-flag"])


@pytest.mark.parametrize("path", ALL_PATHS, ids=_idfn)
def test_help_exits_zero(path):
    """--help exits 0 on every command path."""
    with pytest.raises(SystemExit) as exc:
        _parse([*_argv(path), "--help"])
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Pinned structure: subcommand counts (the ONLY hard-coded literals)
# ---------------------------------------------------------------------------

# Deliberate drift tripwire per ticket: a dropped/added/renamed-nested level
# changes a count or the key set and fails loudly, forcing a conscious update.
EXPECTED_SUBCOMMAND_COUNTS: dict[tuple[str, ...], int] = {
    (): 16,
    ("admin",): 23,
    ("admin", "key-version"): 5,
    ("role",): 7,
    ("exec",): 5,
    ("exec", "cert"): 3,
    ("config",): 3,
    ("credential",): 3,
}


def test_subcommand_counts_pinned_both_directions():
    found = {}
    for path, parser in PARSERS:
        for a in parser._actions:
            if isinstance(a, argparse._SubParsersAction):
                found[path] = len(a.choices)
    assert set(found) == set(EXPECTED_SUBCOMMAND_COUNTS), "nesting levels changed"
    for path, count in found.items():
        assert count == EXPECTED_SUBCOMMAND_COUNTS[path], f"count changed at {'-'.join(path) or 'top'}"


# ---------------------------------------------------------------------------
# Special shapes — explicit, not silent
# ---------------------------------------------------------------------------


class TestSuppressedSkipMigrations:
    """`init --skip-migrations`: deprecated no-op hidden via argparse.SUPPRESS.

    Argparse contract = still accepted + hidden from help. Runtime inertness
    is commands.py territory (feature tests).
    """

    def test_accepted_and_sets_flag(self):
        ns = _parse(["init", "u", "--skip-migrations"])
        assert ns.skip_migrations is True

    def test_hidden_from_help(self):
        assert "--skip-migrations" not in PARSER_BY_PATH[("init",)].format_help()

    def test_required_positional_still_enforced(self):
        _assert_exit2(["init", "--skip-migrations"])


class TestRunRemainderShape:
    """`run` command_args = nargs=REMAINDER — excluded from the generic matrix.

    All shapes below physically verified on CPython 3.14. The leading `--` is
    captured LITERALLY at parse level; consumption happens in cmd_run (pinned
    by test_cli_run.py, ticket command-validator-sudo-inconsistency).
    """

    def test_bare_run_empty_remainder(self):
        assert _parse(["run"]).command_args == []

    def test_command_captured(self):
        assert _parse(["run", "/bin/true"]).command_args == ["/bin/true"]

    def test_leading_separator_captured_literally(self):
        assert _parse(["run", "--", "/bin/true", "x"]).command_args == ["--", "/bin/true", "x"]

    def test_options_before_remainder(self):
        ns = _parse(["run", "--secret", "s", "--", "/bin/true"])
        assert ns.secrets == ["s"]
        assert ns.command_args == ["--", "/bin/true"]

    def test_remainder_swallows_later_flags(self):
        """Deliberate REMAINDER semantics: flags after the command token belong
        to the remote command (`run ssh -o ...`), not to venya."""
        ns = _parse(["run", "true", "--no-such-flag"])
        assert ns.command_args == ["true", "--no-such-flag"]


class TestHelpAndNoCommand:
    """main()'s no-command path (prints help, returns 1) and --help (exit 0).

    Both pinned below the tee installation and the commands import, so they
    have no filesystem or network side effects.
    """

    def test_no_command_returns_one(self):
        with patch.object(sys, "argv", ["venya"]):
            assert main() == 1

    def test_main_help_exits_zero(self):
        with patch.object(sys, "argv", ["venya", "--help"]), pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
