# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for `venya run` executor attribution and refusal (#712 half (a)).

Two defects, one face. `cmd_run` invented an executor id when the operator gave
none — ``executor_id = getattr(args, "executor_id", None) or "default"`` — and sent
that made-up token to the server in the session body and in the execute URL, where
it failed with a message naming neither the id nor where it came from. And on the
success path it printed no executor at all, so a sandbox answer and the answer from
the host the operator meant read identically. The MCP face got its attribution at
``5719b2f0``; this is the parity half.

The owner's acceptance bar, verbatim, is what the first two cells test: the refusal
names the absence ("no executor id was configured") and the fabricated token is
never echoed. The paired negative is what stops the fix from passing by refusing
everything: a configured id still has to print.
"""

import re
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from venya_cli.api_client import APIClientError
from venya_cli.commands import cmd_run

# The refusal path must be able to find NO config file, whatever the test host
# happens to hold at /etc/venya. The control guarantees its own inputs; it does
# not inherit the caller's filesystem (root AGENTS.md §1).
_ABSENT_TOML = patch("venya_cli.commands.EXECUTOR_TOML_PATH", "/nonexistent/executor.toml")


def _args(command_args=None, executor_id=None, secrets=None):
    return SimpleNamespace(
        command_args=command_args if command_args is not None else ["/bin/echo", "hi"],
        executor_id=executor_id,
        secrets=secrets,
    )


def _client(session_ok=True):
    client = MagicMock()
    client.post.side_effect = [
        {"session_id": "s1"},  # session create
        {"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0},  # execute
    ]
    return client


class TestRefusalNamesTheAbsence:
    """Positive cell: no flag, no toml → refuse at the client, and say what is missing."""

    def test_missing_executor_id_refuses_with_the_ruled_phrase(self, capsys):
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args())
        assert rc == 1
        err = capsys.readouterr().err
        assert "no executor id was configured" in err

    def test_refusal_sends_nothing_at_all(self, capsys):
        """The other half of 'refusing loudly at the client': no session POST, no
        execute POST — the invented token never reaches the wire."""
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args())
        assert rc == 1
        client.post.assert_not_called()

    def test_fabricated_token_never_appears_in_the_error(self, capsys):
        """★ Negative cell, the owner's own bar: the string `default` must not be in
        the emitted error. An error that echoes the value the CLI invented has not
        fixed the defect — it has just moved the invention into the message."""
        client = _client()
        with _ABSENT_TOML:
            cmd_run(client, _args())
        captured = capsys.readouterr()
        assert "default" not in captured.err
        assert "default" not in captured.out

    def test_error_carries_no_argv_and_no_secret_path(self, capsys):
        """No-echo discipline (#713 AC3, same house shape): a refused command may hold
        a session-bound secret path, and argv content must not ride out in a message
        that lands in the terminal, a log, or a copy-pasted report."""
        client = _client()
        argv = ["/usr/bin/sshpass", "-f", "/run/secrets/venya/1", "/usr/bin/ssh", "tier1@t1"]
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(command_args=argv))
        assert rc == 1
        err = capsys.readouterr().err
        for token in argv:
            assert token not in err

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_id_is_absent_id_not_an_id(self, blank):
        """`--executor-id ""` is an unset id, not a dial address: it must fall through
        to the same refusal, not to an empty URL segment."""
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id=blank))
        assert rc == 1
        client.post.assert_not_called()

    def test_whitespace_id_is_trimmed_and_kept(self, capsys):
        """A stray trailing space in a shell line is a typing artifact, not a second
        executor: the id is kept, the run proceeds, and the attribution says what was
        actually dialed rather than what was typed."""
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1 "))
        assert rc == 0
        assert "(executor=exec-1)" in capsys.readouterr().out


class TestConfiguredIdStillPrints:
    """★ The paired negative that keeps the refusal honest: a configured id must still
    run and must still be attributed. Refusing everything would pass every cell above."""

    def test_flag_id_still_runs_and_is_attributed(self, capsys):
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "(executor=exec-1)" in out

    def test_flag_id_reaches_both_send_sites(self):
        """The two sites the defect lived in — the session body and the execute URL —
        still carry the caller's id, unchanged, when one IS configured."""
        client = _client()
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 0
        calls = client.post.call_args_list
        assert calls[0].kwargs["json"]["executor_id"] == "exec-1"
        assert calls[1].args[0] == "/api/v1/executors/exec-1/execute"

    def test_toml_configured_id_is_used_when_no_flag(self, tmp_path, capsys):
        """'Configured' means the file the rest of the executor plane already reads:
        executor.toml. A host with a real id there must not be refused."""
        toml = tmp_path / "executor.toml"
        toml.write_text("executor_id = 'venya-exec-9'\n", encoding="utf-8")
        client = _client()
        with patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)):
            rc = cmd_run(client, _args())
        assert rc == 0
        assert "(executor=venya-exec-9)" in capsys.readouterr().out

    def test_flag_beats_toml_id(self, tmp_path):
        """Resolution order stays flag > toml: the operator's explicit word wins over
        the file on the host, which is what the register path already does (#508)."""
        toml = tmp_path / "executor.toml"
        toml.write_text("executor_id = 'venya-exec-9'\n", encoding="utf-8")
        client = _client()
        with patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)):
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 0
        assert client.post.call_args_list[0].kwargs["json"]["executor_id"] == "exec-1"

    def test_unreadable_toml_warns_then_refuses(self, tmp_path, capsys):
        """Present but unparseable is not "no id": the operator sees the file failed to
        read (the same posture as the ca_bundle fallback in this module) and then the
        refusal, and nothing crosses the wire."""
        toml = tmp_path / "executor.toml"
        toml.write_text("executor_id = [unclosed\n", encoding="utf-8")
        client = _client()
        with patch("venya_cli.commands.EXECUTOR_TOML_PATH", str(toml)):
            rc = cmd_run(client, _args())
        assert rc == 1
        err = capsys.readouterr().err
        assert "cannot read" in err
        assert "no executor id was configured" in err
        client.post.assert_not_called()


class TestAttributionOnEveryExit:
    """AC2's shape from the merged MCP half: the attribution does not ride on a
    successful exit, it is on the answer."""

    def test_nonzero_exit_still_names_the_executor(self, capsys):
        client = MagicMock()
        client.post.side_effect = [
            {"session_id": "s1"},
            {"exit_code": 255, "stdout": "", "stderr": "ssh: connection timed out", "masked_count": 0},
        ]
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 255
        out = capsys.readouterr().out
        assert "(executor=exec-1)" in out

    def test_missing_exit_code_still_names_the_executor(self, capsys):
        """A reply that carries no `exit_code` key must not lose the attribution too."""
        client = MagicMock()
        client.post.side_effect = [{"session_id": "s1"}, {"stdout": "ok"}]
        with _ABSENT_TOML:
            cmd_run(client, _args(executor_id="exec-1"))
        assert "(executor=exec-1)" in capsys.readouterr().out

    def test_session_creation_failure_names_the_executor(self, capsys):
        """The failure paths carry it as well: 'which box' is the question an operator
        asks precisely when the call did not work."""
        client = MagicMock()
        client.post.side_effect = APIClientError("executor not found")
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 1
        assert "executor=exec-1" in capsys.readouterr().err

    def test_execute_failure_names_the_executor(self, capsys):
        client = MagicMock()
        client.post.side_effect = [{"session_id": "s1"}, APIClientError("relay timeout")]
        with _ABSENT_TOML:
            rc = cmd_run(client, _args(executor_id="exec-1"))
        assert rc == 1
        assert "executor=exec-1" in capsys.readouterr().err

    def test_success_attribution_is_the_echoed_id_not_a_guess(self, capsys):
        """AC5 discipline: the attributed value is the caller's own id, unchanged, even
        when the command text claims somewhere else. Nothing reads argv to work out
        where the command ran — the line proves it cannot."""
        client = _client()
        with _ABSENT_TOML:
            cmd_run(client, _args(command_args=["ssh", "prod-db.example"], executor_id="exec-1"))
        out = capsys.readouterr().out
        attributed = re.search(r"\(executor=([^)]*)\)", out).group(1)
        assert attributed == "exec-1"
