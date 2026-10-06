# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#484 drift interlock — CLI --shape help must enumerate all built-in secret shapes.

The server blesses built-in secret shapes in `server.routes.secrets.BUILTIN_SHAPES`.
The CLI advertises supported shapes at two `--shape` argument definitions (`store`
and `update-metadata`). This test guards against drift between the server's blessed
built-ins and the CLI's user-facing help text.
"""

import argparse

import pytest
from server.routes.secrets import BUILTIN_SHAPES
from venya_cli.cli import create_parser


def _get_shape_actions() -> dict[str, argparse.Action]:
    """Find all --shape argument actions across the parser tree, keyed by subcommand name."""
    parser = create_parser()
    actions: dict[str, argparse.Action] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                for sub_action in sub._actions:
                    if "--shape" in sub_action.option_strings:
                        actions[name] = sub_action
    return actions


def test_expected_shape_help_sites_exist():
    """Verify exactly the expected subcommands define a --shape flag."""
    actions = _get_shape_actions()
    assert set(actions.keys()) == {"store", "update-metadata"}


@pytest.mark.parametrize("cmd", ["store", "update-metadata"])
def test_shape_help_enumerates_all_builtin_shapes(cmd: str):
    """Every member of server.routes.secrets.BUILTIN_SHAPES must appear in --shape help."""
    actions = _get_shape_actions()
    action = actions[cmd]
    assert action.help is not None, f"Subcommand {cmd} --shape has no help text"
    missing = sorted(shape for shape in BUILTIN_SHAPES if shape not in action.help)
    assert not missing, f"Subcommand {cmd} --shape help omits builtin shapes: {missing}"


@pytest.mark.parametrize("cmd", ["store", "update-metadata"])
def test_shape_help_mentions_env_prefix(cmd: str):
    """The --shape help must mention the env:NAME prefix."""
    actions = _get_shape_actions()
    action = actions[cmd]
    assert action.help is not None
    assert "env:NAME" in action.help
