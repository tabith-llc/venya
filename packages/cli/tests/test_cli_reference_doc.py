# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock for docs/cli-reference.md (GENERATED file — never hand-edit).

Three guarantees, all derived from the live parser (same source of truth as
test_cli_arg_surface.py):

1. DRIFT: regenerate-in-memory must equal the committed document byte-for-byte
   — any CLI change without a regen is RED.
2. EXAMPLE VALIDITY: every example argv in the generator's EXAMPLES table must
   parse through create_parser() — an example can never rot into invalid syntax.
3. COMPLETENESS: every leaf command path has >= 1 example, and every EXAMPLES
   key is a real command path — a new subcommand without documentation is RED,
   and an example for a deleted command is RED.

Plus: the doc must enumerate every command path (section coverage) so the
generator itself cannot silently drop a subtree.
"""

import argparse
import importlib.util
import shlex
from pathlib import Path

import pytest
from venya_cli.cli import create_parser

_CLI_PKG = Path(__file__).resolve().parents[1]
_REPO_ROOT = _CLI_PKG.parents[1]
_DOC = _REPO_ROOT / "docs" / "cli-reference.md"
_GEN = _CLI_PKG / "scripts" / "gen_cli_reference.py"

_spec = importlib.util.spec_from_file_location("gen_cli_reference", _GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def _all_paths() -> set[tuple[str, ...]]:
    paths: set[tuple[str, ...]] = set()

    def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
        paths.add(path)
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    _walk(sub, path + (name,))

    _walk(create_parser(), ())
    return paths


ALL_PATHS = _all_paths()
LEAF_PATHS = {p for p in ALL_PATHS if p and not gen.is_dispatcher(gen.PARSER_BY_PATH[p])}


class TestDocDrift:
    def test_committed_doc_matches_regeneration(self):
        """Byte-equality: the committed file IS what the generator emits now."""
        assert _DOC.exists(), f"{_DOC} missing — run scripts/gen_cli_reference.py"
        assert _DOC.read_text(encoding="utf-8") == gen.generate(), (
            "docs/cli-reference.md drifted from create_parser(); regenerate: "
            "uv run -p 3.14 --directory packages/cli python scripts/gen_cli_reference.py"
        )

    def test_every_command_path_has_a_section(self):
        """The generator cannot silently drop a subtree."""
        text = _DOC.read_text(encoding="utf-8")
        for path in sorted(ALL_PATHS - {()}):
            heading = f"venya {' '.join(path)}`"
            assert heading in text, f"no section for 'venya {' '.join(path)}'"


class TestExampleValidity:
    @pytest.mark.parametrize(
        "path,argv",
        [(p, argv) for p, entries in gen.EXAMPLES.items() for argv, _ in entries],
        ids=lambda v: " ".join(v) if isinstance(v, list) else "-".join(v),
    )
    def test_example_parses(self, path, argv):
        """Every documented invocation is syntactically valid against the shipped parser."""
        ns = create_parser().parse_args(argv)
        assert ns.command == path[0]


class TestExampleCompleteness:
    def test_every_leaf_command_has_an_example(self):
        """Negative half: an undocumented leaf command fails the suite."""
        missing = sorted(" ".join(p) for p in LEAF_PATHS - set(gen.EXAMPLES))
        assert not missing, f"leaf commands without examples: {missing}"

    def test_no_orphan_examples(self):
        """An example for a deleted/renamed command fails the suite."""
        orphans = sorted(" ".join(k) for k in gen.EXAMPLES if k not in ALL_PATHS)
        assert not orphans, f"EXAMPLES keys that are not real command paths: {orphans}"

    def test_examples_never_target_dispatcher_groups(self):
        """Groups have no behavior of their own; examples belong on leaves."""
        bad = sorted(" ".join(k) for k in gen.EXAMPLES if k in ALL_PATHS and gen.is_dispatcher(gen.PARSER_BY_PATH[k]))
        assert not bad, f"examples on dispatcher groups: {bad}"

    def test_rendered_examples_in_doc(self):
        """Each example line really appears in the committed document."""
        text = _DOC.read_text(encoding="utf-8")
        for entries in gen.EXAMPLES.values():
            for argv, _ in entries:
                line = "venya " + shlex.join(argv)
                assert line in text, f"example missing from doc: {line}"


def _row(doc: str, needle: str) -> str:
    """The single argument-table line naming `needle`, or fail."""
    rows = [line for line in doc.splitlines() if line.startswith("|") and needle in line]
    assert len(rows) == 1, f"expected exactly one doc row for {needle!r}, got {len(rows)}"
    return rows[0]


class TestHelpStringsRenderAsArgparseDisplaysThem:
    """Ticket cli-help-percent-interpolation — the generator must show what the operator sees.

    argparse expands every help string before printing it (`HelpFormatter._expand_help`
    does ``help_string % params``, and returns the string untouched when it carries no
    ``%``), so a doubled ``%%`` in the source means ONE literal percent on screen. The
    generator used to emit the stored string raw, which put ``printf %%s`` in this
    document while ``venya store --help`` correctly printed ``printf %s``.

    Non-vacuous by construction: the escape cell and the ``%(default)s``/``%(prog)s``
    cells each assert a CHANGE of bytes (two characters in, one out), and the last cell
    pins the doc row against the live CLI's own rendered help, so a doc that keeps the
    raw spelling cannot pass.
    """

    def test_escaped_percent_becomes_one_literal_percent(self):
        assert (
            gen._rendered_help("use 'printf %%s' when piping", default=None, prog="venya store")
            == "use 'printf %s' when piping"
        )

    def test_documented_default_key_substitutes(self):
        assert gen._rendered_help("value (default: %(default)s)", default="askpass", prog="venya store") == (
            "value (default: askpass)"
        )

    def test_documented_prog_key_substitutes(self):
        assert gen._rendered_help("run %(prog)s first", default=None, prog="venya store") == "run venya store first"

    def test_string_without_percent_is_returned_untouched(self):
        """The short-circuit, and the braces the CLI uses for {secret_path} survive it."""
        raw = "template; reference the secret only via {secret_path}"
        assert gen._rendered_help(raw, default=None, prog="venya store") == raw
        assert gen._rendered_help(None, default=None, prog="venya store") == ""

    def test_doc_row_matches_the_rendered_help_of_the_live_cli(self):
        doc = _DOC.read_text(encoding="utf-8")
        row = _row(doc, "`VALUE` (positional, nargs=?)")
        assert "printf %s" in row, f"doc row does not show the literal the CLI shows: {row}"
        assert "printf %%s" not in row, f"doc row leaks the argparse escape: {row}"
        # same sentence, straight off the live parser's public rendering path
        subparsers = next(a for a in create_parser()._actions if isinstance(a, argparse._SubParsersAction))
        rendered = " ".join(subparsers.choices["store"].format_help().split())
        assert "printf %s" in rendered, rendered


def test_generator_main_writes_doc(monkeypatch, tmp_path):
    """The script entrypoint writes exactly what generate() returns."""
    target = tmp_path / "cli-reference.md"
    monkeypatch.setattr(gen, "DOC_PATH", target)
    gen.main()
    assert target.read_text(encoding="utf-8") == gen.generate()
