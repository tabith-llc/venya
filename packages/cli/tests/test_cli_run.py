# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for `venya run` command-argv construction.

Ticket command-validator-sudo-inconsistency: argparse REMAINDER captures a
leading `--` separator literally (verified on CPython 3.14.6), so
`venya run -- /usr/bin/ssh ...` sent `-- /usr/bin/ssh ...` to the executor —
breaking ssh-shape recognition in the validator and sandbox execution.
Route-level invariant: the argv list in the execute payload never carries the
captured separator.

Ticket execution-command-wire-unstructured-string (#322, ruling Q1=A1): the
REMAINDER argv list posts AS a list — no CLI-side join, no quoting artifacts.
The #319 interim per-arg shlex.quote cells are replaced by list-identity
cells; the CLI echo carries the shlex.join RENDERED form.
"""

import shlex
from types import SimpleNamespace
from unittest.mock import MagicMock

from venya_cli.commands import cmd_run


def _run(command_args: list[str]):
    """Drive cmd_run with a mocked APIClient; return (rc, execute_payload_command)."""
    client = MagicMock()
    client.post.side_effect = [
        {"session_id": "s1"},  # session create
        {"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0},  # execute
    ]
    args = SimpleNamespace(command_args=command_args, executor_id="exec-1", secrets=[])
    rc = cmd_run(client, args)
    payload = client.post.call_args_list[1].kwargs["json"]
    return rc, payload["command"]


class TestRunSeparatorStrip:
    def test_leading_separator_stripped(self):
        rc, command = _run(["--", "/usr/bin/ssh", "tier1@t1", "sudo", "true"])
        assert rc == 0
        assert command == ["/usr/bin/ssh", "tier1@t1", "sudo", "true"]

    def test_exactly_one_separator_consumed(self):
        """The load-bearing edge: a second leading `--` is the user's intended
        command token, not a separator — the strip must not cascade."""
        _rc, command = _run(["--", "--foo"])
        assert command == ["--foo"]

    def test_interior_separator_untouched(self):
        _rc, command = _run(["--", "ls", "--", "other"])
        assert command == ["ls", "--", "other"]

    def test_no_separator_unchanged(self):
        """Paired negative: the common shape must not be altered by the fix."""
        _rc, command = _run(["ls", "-la"])
        assert command == ["ls", "-la"]

    def test_journal_shape_reaches_executor_clean(self):
        """Route-level invariant for the observed defect: the sshpass-to-target
        shape from the E2E journal arrives without the leading `--` token that
        broke validator shape-recognition."""
        argv = [
            "--",
            "/usr/bin/sshpass",
            "-f",
            "/run/secrets/venya/1",
            "/usr/bin/ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "tier1@192.0.2.22",
            "sudo",
            "apt-get",
            "install",
            "-y",
            "apache2",
        ]
        _rc, command = _run(argv)
        assert command == argv[1:]
        assert command[0] == "/usr/bin/sshpass"

    def test_empty_command_still_rejected(self):
        """`venya run --` alone → empty command → rc 1, no session created."""
        client = MagicMock()
        args = SimpleNamespace(command_args=["--"], executor_id="exec-1", secrets=[])
        rc = cmd_run(client, args)
        assert rc == 1
        client.post.assert_not_called()


class TestRunArgWhitespace:
    """#322 structural wire fix: the argv list posts as a list, so argument
    boundaries survive to the server/audit EXACTLY — no quoting is baked into
    the wire value (the #319 interim artifacts are gone)."""

    def test_arg_with_spaces_posts_as_one_element(self):
        """#322 headline bug: `venya run -- grep error message app.log` used
        to reach the target as free words; now the quoted arg is ONE element,
        byte-identical — no shlex round trip needed to recover it."""
        _rc, command = _run(["grep", "error message", "app.log"])
        assert command == ["grep", "error message", "app.log"]

    def test_arg_with_single_quote_posts_verbatim(self):
        _rc, command = _run(["echo", "it's here", "ok"])
        assert command == ["echo", "it's here", "ok"]

    def test_metachar_arg_payload_shape(self):
        """A metachar-containing arg reaches the wire as a plain element; the
        executor's per-element gate rejects it (paired negative:
        TestValidateCommandStructure#test_rejects_metachar_inside_single_element)."""
        _rc, command = _run(["echo", "a|b"])
        assert command == ["echo", "a|b"]

    def test_echo_prints_rendered_form(self, capsys):
        """Display-only: the CLI echo renders shlex.join(argv) — the operator
        sees a copy-pasteable line, the wire stays structured."""
        _rc, _command = _run(["grep", "error message", "app.log"])
        out = capsys.readouterr().out
        assert f"Executing: {shlex.join(['grep', 'error message', 'app.log'])}" in out
