# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Ticket cli-help-percent-interpolation — the ``store`` value help line renders literally.

argparse interpolates every ``help=`` string it renders (``HelpFormatter._expand_help``
does ``help_string % params``, where ``params`` is the action's ``vars()`` plus ``prog``),
so a bare ``%s`` in the prose is a conversion spec: Python substitutes the whole params
dict and the operator reads an ``option_strings`` / ``container`` repr — with a live object
address — where the "how to pipe a secret without a trailing newline" advice should be.

Mechanism of verification: the string under test is the RENDERED help, taken off the live
subparser built by ``create_parser()`` (the same object the arg-surface pin and the
generated-doc script walk) — through the formatter's own expansion and through
``format_help()``, never re-typed from the source file.

Why the positive is an exact match and not a substring probe: at base the params repr
EMBEDS the untouched source string (``'help': "... printf %s ..."``), so "does the help
contain ``printf %s``" is true of the broken render too — it would pass either way. The
exact-equality cell is the one that can only go green once the prose survives
interpolation, and the no-repr cell is its partner.

The paired negative runs the stdlib formatter over both spellings, so neither half rests on
a formatter that never interpolates: an undoubled ``%s`` must produce the params repr, a
doubled ``%%s`` must produce a literal ``%s``.

Scope is help TEXT only — no argument, no flag, no parse behavior — so the last cell pins
the ``store`` option surface to prove it did not move.
"""

import argparse

import pytest
from venya_cli.cli import create_parser

EXPECTED_VALUE_HELP = (
    "Secret value; '-' or omitted reads stdin BYTE-EXACT, incl. any trailing newline "
    "(interactive TTY: hidden prompt; use 'printf %s' when piping single-line values)"
)

# Fragments of the params dict argparse prints when a help string is a format spec.
REPR_MARKERS = ("'option_strings'", "'dest':", "_ArgumentGroup object at", "0x")


def _subparser(name: str) -> argparse.ArgumentParser:
    subparsers = next(a for a in create_parser()._actions if a.__class__.__name__ == "_SubParsersAction")
    return subparsers.choices[name]


def _expanded_help(parser: argparse.ArgumentParser, dest: str) -> str:
    """The one-line help exactly as the formatter expands it for display."""
    action = next(a for a in parser._actions if a.dest == dest)
    return parser._get_formatter()._expand_help(action)


@pytest.fixture(scope="module")
def store_parser() -> argparse.ArgumentParser:
    return _subparser("store")


class TestStoreValueHelpRendersLiterally:

    def test_expanded_help_is_the_prose_itself(self, store_parser):
        assert _expanded_help(store_parser, "value") == EXPECTED_VALUE_HELP

    def test_rendered_help_contains_no_argument_repr(self, store_parser):
        rendered = store_parser.format_help()
        for marker in REPR_MARKERS:
            assert marker not in rendered, f"argparse params repr leaked into help ({marker}):\n{rendered}"


class TestUndoubledPercentIsTheDefectClass:
    """Negative half: the same stdlib formatter, both spellings."""

    @staticmethod
    def _render(help_text: str) -> str:
        parser = argparse.ArgumentParser(prog="venya store")
        parser.add_argument("value", nargs="?", help=help_text)
        return parser._get_formatter()._expand_help(parser._actions[-1])

    def test_undoubled_percent_renders_the_params_repr(self):
        out = self._render("use 'printf %s' when piping")
        assert "'option_strings'" in out, out
        assert out != "use 'printf %s' when piping"

    def test_doubled_percent_renders_a_literal_percent_s(self):
        out = self._render("use 'printf %%s' when piping")
        assert out == "use 'printf %s' when piping", out


class TestStoreArgSurfaceUnchanged:
    """The fix is prose-only: the parsed surface must not move."""

    def test_store_options(self, store_parser):
        options = sorted(opt for a in store_parser._actions for opt in a.option_strings)
        assert options == [
            "--help",
            "--key-version",
            "--metadata",
            "--roles",
            "--shape",
            "--usage",
            "-h",
            "-m",
        ]
        positionals = [a.dest for a in store_parser._actions if not a.option_strings]
        assert positionals == ["key", "value"]
