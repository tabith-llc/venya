# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`venya exec availability` (beta3, owner word O964): a session-authorized path to the
executor availability view.

The read-role operator's gap: the only CLI route to the roster was `exec list`, which
calls the ADMIN endpoint and 403s without a client certificate, while the availability
route (`GET /api/v1/executors`, `require_role("read")`) had zero callers in the CLI.
These cells pin the added verb and its four paired negatives:

* a call with no session is refused BY NAME with its remedy, never a traceback;
* a read-role session renders the roster with `online` visible;
* the CLI DISPLAYS the server's `online` boolean and never recomputes presence from the
  timestamp (the two-sided #549 window is single-sourced in the server);
* the verb touches ONLY the availability route — `exec list`'s admin-route pin at
  test_cli_version.py:80 is the keeper of the old contract, re-run by the suite unchanged.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.api_client import APIClientAuthenticationError
from venya_cli.cli import create_parser
from venya_cli.commands import cmd_exec_group, executor_availability

ROWS = {
    "executors": [
        {
            "id": "venya-exec-1",
            "hostname": "exec-one.example",
            "online": True,
            "last_heartbeat": "2026-11-10T14:00:00Z",
            "enrolled_at": "2026-09-01T00:00:00Z",
            "status": "active",
            "version": "0.2.0",
        },
        {
            "id": "venya-exec-2",
            "hostname": "exec-two.example",
            "online": False,
            # #549 site 2 shape: a stamp AHEAD of the reading. The server refused it and
            # answered online=False; the CLI's job is to display that, never to re-judge.
            "last_heartbeat": "2099-01-01T00:00:00Z",
            "enrolled_at": "2026-09-01T00:00:00Z",
            "status": "active",
            "version": None,
        },
    ]
}


class TestAvailabilityRenders:
    def test_read_role_session_renders_online_and_offline(self, capsys):
        """(b) 200 with `online` rendered — the point of the work."""
        client = MagicMock()
        client.get.return_value = ROWS
        rc = executor_availability(client, SimpleNamespace(json=False))
        assert rc == 0
        out = capsys.readouterr().out
        assert "ONLINE" in out
        assert "online" in out and "offline" in out
        assert "venya-exec-1" in out and "venya-exec-2" in out
        # version NULL renders with the same explicit label as exec list (condition 3)
        assert "unknown (pre-B daemon)" in out

    def test_calls_only_the_availability_route(self):
        """Constraint 1, seen from this side: the new verb never touches the admin route.
        `exec list` keeps that one (pinned at test_cli_version.py:80, unmoved by this leg)."""
        client = MagicMock()
        client.get.return_value = ROWS
        executor_availability(client, SimpleNamespace(json=False))
        paths = [c.args[0] for c in client.get.call_args_list]
        assert paths == ["/api/v1/executors"]

    def test_future_stamped_row_is_offline_and_never_recomputed(self, capsys):
        """(c) paired with (b): the row carries a timestamp 70+ years ahead. A CLI that
        recomputed `now - heartbeat < 60` would call it LIVE for a decade; the shipped
        answer is the server's `online: False`, displayed."""
        client = MagicMock()
        client.get.return_value = ROWS
        rc = executor_availability(client, SimpleNamespace(json=False))
        assert rc == 0
        lines = capsys.readouterr().out.splitlines()
        exec2 = next(line for line in lines if "venya-exec-2" in line)
        assert "offline" in exec2
        # ...and the mirror: online=True is rendered online even against an impossibly OLD
        # stamp — proof the renderer reads the boolean and nothing else.
        stale_live = {
            "executors": [
                {
                    "id": "venya-exec-3",
                    "hostname": "h",
                    "online": True,
                    "last_heartbeat": "2000-01-01T00:00:00Z",
                    "enrolled_at": None,
                    "status": "active",
                    "version": "0.2.0",
                }
            ]
        }
        client2 = MagicMock()
        client2.get.return_value = stale_live
        executor_availability(client2, SimpleNamespace(json=False))
        exec3 = next(line for line in capsys.readouterr().out.splitlines() if "venya-exec-3" in line)
        assert "online" in exec3 and "offline" not in exec3

    def test_json_mode_passes_through_envelope(self, capsys):
        client = MagicMock()
        client.get.return_value = ROWS
        rc = executor_availability(client, SimpleNamespace(json=True))
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["executors"][1]["online"] is False

    def test_json_mode_on_empty_roster_still_emits_parseable_json(self, capsys):
        """House ordering (exec-audit-json-empty-case-unparseable): passthrough BEFORE the
        empty check — an empty roster is parseable `{}`, not a sentence."""
        client = MagicMock()
        client.get.return_value = {"executors": []}
        rc = executor_availability(client, SimpleNamespace(json=True))
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == {"executors": []}

    def test_empty_roster_table_mode_says_so_and_exits_zero(self, capsys):
        client = MagicMock()
        client.get.return_value = {"executors": []}
        rc = executor_availability(client, SimpleNamespace(json=False))
        assert rc == 0
        assert "No executors found." in capsys.readouterr().out


class TestAvailabilityRefusals:
    def test_no_session_refuses_by_name_with_remedy_and_no_traceback(self, capsys):
        """(a) 401 surfaces as a NAMED refusal (#729 discipline), and the remedy for this
        verb is a session — `venya login` — not a certificate."""
        client = MagicMock()
        client.get.side_effect = APIClientAuthenticationError("HTTP 401: Missing authentication token")
        rc = executor_availability(client, SimpleNamespace(json=False))
        assert rc == 1
        err = capsys.readouterr().err
        assert "Availability failed" in err
        assert "HTTP 401" in err
        assert "venya login" in err, "the refusal names the remedy, not just the error"
        assert "Traceback" not in err

    def test_dispatch_routes_availability_to_the_verb(self):
        client = MagicMock()
        client.get.return_value = ROWS
        rc = cmd_exec_group(client, SimpleNamespace(exec_command="availability", json=False))
        assert rc == 0
        paths = [c.args[0] for c in client.get.call_args_list]
        assert "/api/v1/executors" in paths


class TestAvailabilityParserWiring:
    def test_exec_availability_subcommand_parses(self):
        parser = create_parser()
        args = parser.parse_args(["exec", "availability"])
        assert args.command == "exec"
        assert args.exec_command == "availability"
        assert args.json is False

    def test_json_flag_parses(self):
        parser = create_parser()
        args = parser.parse_args(["exec", "availability", "--json"])
        assert args.json is True

    @pytest.mark.parametrize("argv", [["exec", "list"], ["exec", "status"]])
    def test_existing_exec_verbs_still_parse(self, argv):
        """The verb is ADDED; nothing was renamed or re-pointed."""
        parser = create_parser()
        args = parser.parse_args(argv)
        assert args.exec_command == argv[1]
