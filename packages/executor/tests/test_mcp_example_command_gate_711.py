# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: every command the shipped ``run_command`` example teaches is a
command the shipped command gate accepts (ticket mcp-example-teaches-refused-shape
#711).

Why this file sits in ``executor/tests`` and not as another string assertion in
the mcp suite: the mcp tool surface takes a shell STRING, splits it with
``shlex.split`` in ``packages/mcp/src/venya_mcp/client.py``, and the executor
then validates the resulting argv element-by-element in
``executor.executor._validate_command_structure``. A description can read
perfectly reasonably and still describe a command the product refuses — that is
exactly how #711 was born. Only the real gate, driven with the real split of the
real shipped description, tells those two apart. Cross-package cells live here
by this package's own convention (``from server...`` cells already do).

The example the row ruled in shows BOTH supported authentication postures with
the condition that selects between them: key authentication carrying an
unattended remote ``sudo`` through the session-bound ``<`` redirect, and
``sshpass`` password authentication with no remote ``sudo`` in the same command.
Showing both with their preconditions is what keeps the description from
assuming that a customer target handed us key custody.

Red before green, in file order: the refusals that must keep firing come first,
then the acceptance of the shipped examples.
"""

import asyncio
import re
import shlex

import pytest
from venya_mcp.server import list_tools

from executor.executor import _bound_secret_paths, _validate_command_structure

EXAMPLE_COMMAND_RE = re.compile(r"command: '([^']+)'")
SECRET_PATH_RE = re.compile(r"/run/secrets/venya/[A-Za-z0-9_-]+")


def _run_command_description() -> str:
    tools = asyncio.run(list_tools())
    return next(t.description for t in tools if t.name == "run_command")


def _shipped_examples() -> list[str]:
    """The example command lines out of the LIVE description, never a copy.

    Reading them out of the shipped text is the point: an example edited later
    into a shape the gate refuses reddens these cells instead of shipping.
    """
    found = EXAMPLE_COMMAND_RE.findall(_run_command_description())
    assert found, "the run_command description carries no example command to check"
    return found


def _key_example() -> str:
    """The key-authentication posture: plain ``ssh``, redirect, bound path."""
    for command in _shipped_examples():
        argv = shlex.split(command)
        if argv[:1] == ["ssh"] and any(a == "<" for a in argv):
            return command
    pytest.fail(
        "no key-authentication example carrying the session-bound redirect in the "
        "shipped run_command description — the ruled shape (#711) is not being taught"
    )


def _pair_argv(command: str) -> list[str]:
    """argv of an example that ends its redirect pair on a bound secret path, so
    the cells below transform a pair they have PROVED exists rather than string-
    replacing text a later edit may have reworded."""
    argv = shlex.split(command)
    idx = [i for i, a in enumerate(argv) if a == "<"]
    assert idx, "the example carries no standalone '<' to build a negative from"
    i = idx[0]
    assert i + 1 < len(argv) and SECRET_PATH_RE.fullmatch(
        argv[i + 1]
    ), f"the '<' at element {i} is not followed by a secret path"
    return argv


def _session_for(command: str) -> frozenset[str]:
    """The redirect allowance a caller of this example would actually hold: the
    secret paths the example itself names, spelled exactly as
    ``_bound_secret_paths`` spells them from the injected ids."""
    return _bound_secret_paths(p.rsplit("/", 1)[-1] for p in SECRET_PATH_RE.findall(command))


# --- RED FIRST: the refusals the accepted example depends on still firing ----


def test_redirect_to_an_unbound_path_is_refused() -> None:
    """The redirect is an allowance for a SESSION-BOUND secret path and nothing
    else: the shipped example's own argv with its one bound path swapped for a
    file no session ever bound."""
    argv = _pair_argv(_key_example())
    argv = ["/etc/shadow" if SECRET_PATH_RE.fullmatch(a) else a for a in argv]
    with pytest.raises(ValueError, match="SESSION-BOUND secret path"):
        _validate_command_structure(argv, _session_for(_key_example()))


def test_redirect_is_refused_when_the_session_bound_nothing() -> None:
    """The paired negative of the positive cell below, and the cell that says
    this change widened nothing: the shipped key-authentication example VERBATIM,
    in a session that bound no secret, is still refused. Its acceptance is the
    ruled allowance doing its job, not a gate that stopped checking."""
    argv = _pair_argv(_key_example())
    with pytest.raises(ValueError, match="SESSION-BOUND secret path"):
        _validate_command_structure(argv, frozenset())


def test_fused_redirect_is_refused() -> None:
    """``<`` is admitted as its OWN element only. An agent who writes it the way
    shell habit writes it — fused onto the word before it — is refused, so the
    description's promise about a standalone ``<`` is true rather than
    aspirational. Built by fusing the pair this example really carries."""
    argv = _pair_argv(_key_example())
    i = next(k for k, a in enumerate(argv) if a == "<")
    fused = argv[: i - 1] + [argv[i - 1] + "<" + argv[i + 1]] + argv[i + 2 :]
    with pytest.raises(ValueError, match="fused '<'"):
        _validate_command_structure(fused, _session_for(_key_example()))


def test_no_shipped_example_pairs_sshpass_with_a_remote_sudo() -> None:
    """The birth defect of #711: the shipped example used ``sshpass`` to carry a
    remote ``sudo``, and ``sshpass`` reads its own stdin, so the remote
    ``sudo -S`` was answered by nothing and the documented command could not do
    the job it described (docs/beta-known-limitations.md — the entry that stays
    as written). No example may teach that pairing again."""
    for command in _shipped_examples():
        argv = shlex.split(command)
        if argv[:1] == ["sshpass"]:
            assert "sudo" not in argv, f"the password example carries a remote sudo: {command!r}"


def test_description_shows_both_postures() -> None:
    """One example per admitted posture. A description that quietly dropped the
    password posture would itself be an assumption that every customer target
    granted key custody, and assuming either posture is what this row closed."""
    description = _run_command_description()
    assert len(_shipped_examples()) == 2, "both postures are shown, never one"
    lowered = description.lower()
    assert "key" in lowered and "password" in lowered
    assert "not supported in beta" in lowered, "the unsupported pairing is named, not hidden"


# --- GREEN: the shipped examples clear the gate they are shown beside --------


@pytest.mark.parametrize("command", _shipped_examples())
def test_shipped_example_clears_the_command_gate(command: str) -> None:
    """PAIRED POSITIVE, the acceptance bar the row named: each example is split
    the way the MCP client splits it, then validated by the real structural gate
    with the session the example itself implies. A description the product's own
    guard would refuse is what #711 is, so this is the cell that keeps it from
    coming back."""
    argv = shlex.split(command)
    assert argv, "an example that splits to nothing teaches nothing"
    assert _validate_command_structure(argv, _session_for(command)) == argv
