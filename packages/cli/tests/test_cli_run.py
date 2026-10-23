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


class TestRunArgvStrictUtf8Gate:
    """#334 layer 1 (posture B): a lone surrogate in argv EXECUTES on the
    remote side and then kills the server's completion audit write — worst
    failure order (side effects kept, record lost). The CLI must refuse
    LOCALLY, before any network: no client construction, no session call,
    no /health advisory. Actionable error names the offending index; the
    value is never echoed (argv may carry user-sensitive text). The
    byte-faithful relaxation path is ticketed for post-beta (#335)."""

    def test_surrogate_element_exits_before_any_client(self):
        from unittest.mock import patch

        from venya_cli.commands import run_command

        args = SimpleNamespace(command="run", command_args=["/usr/bin/touch", "a\ud800b"])
        with patch("venya_cli.commands.APIClient") as client_cls:
            rc = run_command(args)
        assert rc == 1
        client_cls.assert_not_called()  # zero HTTP: no client object was ever built

    def test_error_names_index_not_value(self, capsys):
        from unittest.mock import patch

        from venya_cli.commands import run_command

        args = SimpleNamespace(command="run", command_args=["ls", "ok", "\udfff"])
        with patch("venya_cli.commands.APIClient"):
            rc = run_command(args)
        assert rc == 1
        err = capsys.readouterr().err
        assert "argument 2" in err
        assert "refused locally" in err.lower() or "nothing was sent" in err.lower()
        assert "\udfff" not in err and "\ud800" not in err  # no value echo

    def test_normal_unicode_and_emoji_pass_the_gate(self):
        """Paired positive: astral-plane text (emoji/CJK/accents) is strict-
        encodable — the gate must let it through to the client (construction
        proves we reached the normal path; no network is actually made here
        because APIClient is mocked)."""
        from unittest.mock import patch

        from venya_cli.commands import run_command

        args = SimpleNamespace(
            command="run",
            command_args=["/usr/bin/echo", "héllo 🔐🚀 日本"],
            user_id=None,
            executor_id=None,
            secrets=None,
        )
        with patch("venya_cli.commands.APIClient") as client_cls:
            client_cls.return_value.config.access_token = "tok"
            client_cls.return_value.post.return_value = {"session_id": "s1"}
            rc = run_command(args)
        client_cls.assert_called_once()  # gate passed; normal dispatch proceeded
        assert rc in (0, 1)  # whatever the mocked dispatch returns, the gate did not fire
