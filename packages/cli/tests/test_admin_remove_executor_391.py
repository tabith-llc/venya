# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for `venya admin remove-executor` (#391 arm (b) CLI surface).

Parser + dispatch + request shape (DELETE, encoded path segment) and loud
surfacing of the server's 404/409 refusals (nonzero exit, detail quoted on
stderr — user-remove precedent).
"""

from unittest.mock import MagicMock

from venya_cli.api_client import APIClientError
from venya_cli.cli import create_parser
from venya_cli.commands import cmd_admin, cmd_admin_remove_executor


def _args(**kw):
    return type("Args", (), kw)()


class TestParser:
    def test_remove_executor_parses(self):
        parsed = create_parser().parse_args(["admin", "remove-executor", "venya-exec-1"])
        assert parsed.admin_command == "remove-executor"
        assert parsed.executor_id == "venya-exec-1"


class TestDispatch:
    def test_admin_dispatches_remove_executor(self):
        client = MagicMock()
        client.delete.return_value = {"removed": True, "executor_id": "venya-exec-1"}
        rc = cmd_admin(client, _args(admin_command="remove-executor", executor_id="venya-exec-1"))
        assert rc == 0
        client.delete.assert_called_once_with("/api/v1/admin/executors/venya-exec-1")


class TestRequestShape:
    def test_success_message_and_exit_zero(self, capsys):
        client = MagicMock()
        client.delete.return_value = {"removed": True}
        rc = cmd_admin_remove_executor(client, _args(executor_id="venya-exec-1"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "venya-exec-1" in out
        assert "removed" in out

    def test_path_segment_is_encoded(self):
        # #354 idiom: crafted ids cannot rewrite the request path.
        client = MagicMock()
        client.delete.return_value = {}
        cmd_admin_remove_executor(client, _args(executor_id="a/b"))
        assert client.delete.call_args[0][0] == "/api/v1/admin/executors/a%2Fb"


class TestRefusalsSurfaced:
    def test_404_detail_surfaced_loudly(self, capsys):
        client = MagicMock()
        client.delete.side_effect = APIClientError("Executor not found: ghost")
        rc = cmd_admin_remove_executor(client, _args(executor_id="ghost"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "Executor not found: ghost" in err
        assert "Remove failed" in err

    def test_409_retained_sessions_refusal_surfaced_loudly(self, capsys):
        client = MagicMock()
        client.delete.side_effect = APIClientError(
            "Executor 'venya-exec-1' has 3 execution session(s) retained as audit evidence; removal refused"
        )
        rc = cmd_admin_remove_executor(client, _args(executor_id="venya-exec-1"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "retained as audit evidence; removal refused" in err
