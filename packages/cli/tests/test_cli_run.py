# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for `venya run` command-string construction.

Ticket command-validator-sudo-inconsistency: argparse REMAINDER captures a
leading `--` separator literally (verified on CPython 3.14.6), so
`venya run -- /usr/bin/ssh ...` sent `-- /usr/bin/ssh ...` to the executor —
breaking ssh-shape recognition in the validator (full-string scan → false
'Dangerous pattern' rejections) and sandbox execution (`sh -c "-- ..."` → 127).
Route-level invariant: the command string in the execute payload never carries
the captured separator. MCP's run_command takes a plain string parameter and
never passes through this join — unaffected by both bug and fix.
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
        assert command == "/usr/bin/ssh tier1@t1 sudo true"

    def test_exactly_one_separator_consumed(self):
        """The load-bearing edge: a second leading `--` is the user's intended
        command token, not a separator — the strip must not cascade."""
        _rc, command = _run(["--", "--foo"])
        assert command == "--foo"

    def test_interior_separator_untouched(self):
        _rc, command = _run(["--", "ls", "--", "other"])
        assert command == "ls -- other"

    def test_no_separator_unchanged(self):
        """Paired negative: the common shape must not be altered by the fix."""
        _rc, command = _run(["ls", "-la"])
        assert command == "ls -la"

    def test_journal_shape_reaches_executor_clean(self):
        """Route-level invariant for the observed defect: the sshpass-to-target
        shape from the E2E journal arrives without the `-- ` prefix that broke
        validator shape-recognition."""
        _rc, command = _run(
            [
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
        )
        assert not command.startswith("--")
        assert command.startswith("/usr/bin/sshpass -f ")

    def test_empty_command_still_rejected(self):
        """`venya run --` alone → empty command → rc 1, no session created."""
        client = MagicMock()
        args = SimpleNamespace(command_args=["--"], executor_id="exec-1", secrets=[])
        rc = cmd_run(client, args)
        assert rc == 1
        client.post.assert_not_called()


class TestRunArgWhitespace:
    """sweep3a-low-hygiene-batch S3A-15 (interim fix; the structural wire fix
    is execution-command-wire-unstructured-string): each argument is
    shlex.quoted before the space join, so argument boundaries survive the
    string wire — the plain join word-split them (`grep 'error message'` →
    three tokens on both execution paths).
    """

    def test_arg_with_spaces_survives_to_payload_verbatim(self):
        """Audit-trail honesty: the command text that reaches the wire is the
        quoted string VERBATIM (the server passes req.command through
        unchanged into the relay, the audit event, and
        execution_sessions.command) — never a silently re-split/re-joined
        reformat. shlex.split round-trips to the exact original argv."""
        _rc, command = _run(["grep", "error message", "app.log"])
        assert command == "grep 'error message' app.log"
        assert shlex.split(command) == ["grep", "error message", "app.log"]

    def test_arg_with_single_quote_survives_to_payload(self):
        _rc, command = _run(["echo", "it's here", "ok"])
        assert command == "echo 'it'\"'\"'s here' ok"
        assert shlex.split(command) == ["echo", "it's here", "ok"]

    def test_metachar_arg_payload_shape(self):
        """A metachar-containing arg is passed quoted; the executor gate
        rejects the quoted string exactly as it rejects the unquoted form
        (paired negative: TestValidateCommandStructure in the executor
        suite, incl. the sweep3a cell for the quoted shape)."""
        _rc, command = _run(["echo", "a|b"])
        assert command == "echo 'a|b'"
