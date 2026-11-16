# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CLI face of leg 1424 (iid #798): the operator's own channel names the refusal.

`venya run` ended its output with "Command exited with code: 0" for a run whose egress the
sandbox proxy refused. The refusal arrives as a completed HTTP 403 written by the proxy, so
that number is the caller's client judging an answer it did receive — and the retired half
of the finding is that the exit code is not the thing to fix: the CLI must not second-guess
it. These cells pin both halves: the denial is said, and the code is left alone.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.commands import cmd_run

# No config file, whatever the test host holds at /etc/venya: the control supplies its own
# inputs instead of inheriting the machine (root AGENTS.md §1).
_ABSENT_TOML = patch("venya_cli.commands.EXECUTOR_TOML_PATH", "/nonexistent/executor.toml")


def _args():
    return SimpleNamespace(
        command_args=["/usr/bin/curl", "-sS", "http://example.com/"],
        executor_id="exec-1",
        secrets=None,
    )


def _client(answer):
    client = MagicMock()
    client.post.side_effect = [{"session_id": "s1"}, answer]
    return client


_DENIED = {
    "exit_code": 0,
    "stdout": "Approval required for example.com:80.\n",
    "stderr": "venya: the sandbox proxy refused this run's egress to example.com:80",
    "masked_count": 0,
    "egress_denied": True,
    "egress_denied_host": "example.com:80",
}


class TestDenialSaidInTheOperatorsChannel:
    def test_the_refused_destination_is_named(self, capsys):
        with _ABSENT_TOML:
            cmd_run(_client(_DENIED), _args())
        err = capsys.readouterr().err
        assert "egress to example.com:80 was refused by the sandbox policy" in err

    def test_the_message_says_the_exit_code_is_not_a_delivery(self, capsys):
        with _ABSENT_TOML:
            cmd_run(_client(_DENIED), _args())
        err = capsys.readouterr().err
        assert "your own client's answer to that refusal" in err
        assert "not a delivered request" in err

    def test_the_exit_code_is_still_the_callers_own(self, capsys):
        """The retired half of the finding, kept honest: the CLI names the refusal and does
        NOT rewrite or re-derive the caller's number. A 0 from a denied run still returns 0
        and still prints 0, because that is what the caller's client reported."""
        with _ABSENT_TOML:
            rc = cmd_run(_client(_DENIED), _args())
        assert rc == 0
        out = capsys.readouterr().out
        assert "Command exited with code: 0 (executor=exec-1)" in out

    def test_a_denial_with_no_named_destination_still_speaks(self, capsys):
        """The runtime can refuse without naming a host; the line then says so instead of
        printing an empty destination."""
        answer = dict(_DENIED, egress_denied_host="")
        with _ABSENT_TOML:
            cmd_run(_client(answer), _args())
        err = capsys.readouterr().err
        assert "egress to a destination was refused" in err and "  " not in err.split("egress to")[1][:40]


class TestADeliveredRunIsLeftAlone:
    """★ Paired negative: nothing may mark every egress as denied. The answer the operator
    gets from a run that reached its destination is the answer they got before this change."""

    def test_no_egress_keys_at_all_reads_clean(self, capsys):
        answer = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0}
        with _ABSENT_TOML:
            rc = cmd_run(_client(answer), _args())
        captured = capsys.readouterr()
        assert rc == 0
        assert "refus" not in captured.err.lower()
        assert "ok" in captured.out

    def test_egress_denied_false_reads_clean(self, capsys):
        answer = {
            "exit_code": 1,
            "stdout": "",
            "stderr": "curl: (22) The requested URL returned error: 403\n",
            "masked_count": 0,
            "egress_denied": False,
            "egress_denied_host": "",
        }
        with _ABSENT_TOML:
            rc = cmd_run(_client(answer), _args())
        captured = capsys.readouterr()
        assert rc == 1, "a caller's own non-zero code is not relabelled either"
        assert "refused by the sandbox policy" not in captured.err
