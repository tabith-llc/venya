# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#324 follow-up: drift pin for the two version_tuple copies.

``server.routes.executors._version_tuple`` (gates the ``_ENV_SHAPE_MIN_VERSION``
wire feature) and ``venya_cli.api_client.version_tuple`` (drives the CLI
version nudge) are intentionally duplicated: the CLI ships standalone and must
not import server code (shared module = wrong dependency direction, lead note
on #324). Nobody imports across the package boundary — so this test reads BOTH
files off disk and compares them at AST level (same no-cross-import shape as
the core migration-sweep pin in ``core/tests/test_dropped_fk_model_drift.py``).

An edit to one copy without the other fails here, loudly:
- body-parity: normalized AST dumps must be identical modulo function name
  (docstrings/whitespace/comments excluded — the code is what must match);
- value-parity: both extracted sources (each with its OWN module-level
  ``_PRE_CANONICAL``) must produce equal results on sampled spellings.
"""

import ast
from pathlib import Path

import pytest

_SERVER_FILE = Path(__file__).resolve().parents[1] / "src" / "server" / "routes" / "executors.py"
_CLI_FILE = Path(__file__).resolve().parents[2] / "cli" / "src" / "venya_cli" / "api_client.py"


def _find_func(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(
        f"{name} not found at module level in the source — the copy was renamed or "
        "moved; fix this pin deliberately, do not let it pass vacuously"
    )


def _find_pre_canonical(tree: ast.Module) -> str:
    """Normalized (unparsed) source of the module-level _PRE_CANONICAL assignment."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_PRE_CANONICAL" for t in node.targets
        ):
            return ast.unparse(node)
    raise AssertionError(
        "_PRE_CANONICAL not found at module level — the parser contract broke; "
        "extend this pin deliberately, never silently"
    )


def _normalized_dump(func: ast.FunctionDef) -> str:
    """AST dump of the function modulo its name: docstring stripped, no
    attributes (whitespace/comments are invisible to the AST by definition),
    any self-reference to the function name rewritten to a placeholder."""
    body = list(func.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]  # docstrings may legitimately differ (venue context)
    probe = ast.FunctionDef(
        name="@FUNC@",
        args=func.args,
        body=body,
        decorator_list=func.decorator_list,
        returns=func.returns,
        type_comment=func.type_comment,
    )
    ast.fix_missing_locations(probe)
    for node in ast.walk(probe):
        if isinstance(node, ast.Name) and node.id == func.name:
            node.id = "@FUNC@"
    return ast.dump(ast.Module(body=[probe], type_ignores=[]), include_attributes=False)


def _parity_dumps() -> tuple[str, str]:
    server_tree = ast.parse(_SERVER_FILE.read_text(encoding="utf-8"))
    cli_tree = ast.parse(_CLI_FILE.read_text(encoding="utf-8"))
    return (
        _normalized_dump(_find_func(server_tree, "_version_tuple")),
        _normalized_dump(_find_func(cli_tree, "version_tuple")),
    )


def _executed_impls() -> tuple[object, object]:
    """Exec each copy's source (plus its own module-level _PRE_CANONICAL) in
    an isolated namespace and return both callables, under a shared name."""
    impls = []
    for path, name in ((_SERVER_FILE, "_version_tuple"), (_CLI_FILE, "version_tuple")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        func_src = ast.get_source_segment(source, _find_func(tree, name))
        assert func_src is not None
        mini = "import re\n" + _find_pre_canonical(tree) + "\n" + func_src
        namespace: dict = {}
        exec(compile(mini, str(path), "exec"), namespace)  # noqa: S102 — pin executes OUR OWN repo files, test-only
        impls.append(namespace[name])
    return impls[0], impls[1]


def test_version_tuple_bodies_are_identical_modulo_name():
    """The drift pin: edit one copy without the other and this fails."""
    server_dump, cli_dump = _parity_dumps()
    assert server_dump == cli_dump, (
        "server.routes.executors._version_tuple and venya_cli.api_client.version_tuple "
        "have DRIFTED (bodies differ modulo name/docstring) — apply the same change to "
        "both copies, or rule a shared module with an owner."
    )


def test_pin_bites_on_an_in_memory_mutation():
    """Negative half (truth-table rule): the pin must actually discriminate.
    Mutate a COPY of the CLI source text in memory only — never on disk — and
    confirm the dumps stop matching."""
    cli_text = _CLI_FILE.read_text(encoding="utf-8")
    assert 'pre_kind else "z"' in cli_text, "mutation target vanished; fix this cell deliberately"
    mutated = ast.parse(cli_text.replace('pre_kind else "z"', 'pre_kind else "y"', 1))
    server_dump, _ = _parity_dumps()
    assert server_dump != _normalized_dump(_find_func(mutated, "version_tuple"))


@pytest.mark.parametrize(
    "reported",
    ["0.1.0alpha2", "0.1.0a13", "0.1.0", "0.1.0b1", "junk", None, "", "1.2.3rc4", "junk\x00"],
)
def test_both_copies_agree_on_sampled_spellings(reported):
    """Value parity (belt): identical bodies already imply it, but this cell
    proves the extracted-both-sources harness actually runs — and each copy
    carries its own _PRE_CANONICAL, which is part of the parse contract."""
    server_impl, cli_impl = _executed_impls()
    assert server_impl(reported) == cli_impl(reported)


def test_pre_canonical_dicts_agree():
    """The load-bearing constant beside both copies is pinned too: a dict
    edit on one side (say alpha->x) would change parse results without ever
    touching the function bodies."""
    server_src = _find_pre_canonical(ast.parse(_SERVER_FILE.read_text(encoding="utf-8")))
    cli_src = _find_pre_canonical(ast.parse(_CLI_FILE.read_text(encoding="utf-8")))
    assert server_src == cli_src
