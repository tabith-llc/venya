# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CLI version surfaces (ticket cli-no-version-flag + feature/version-surfaces):
--version single-sourced from dist metadata, -v stays verbose, and
`venya exec list` renders the heartbeat-reported executor version with the
explicit NULL label (condition 3).
"""

from importlib.metadata import version as pkg_version
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.cli import create_parser

CLI_VERSION = pkg_version("venya-cli")


class TestVersionFlag:
    def test_version_flag_prints_metadata_and_exits_zero(self, capsys):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0
        assert CLI_VERSION in capsys.readouterr().out

    def test_v_remains_verbose_no_collision(self):
        parser = create_parser()
        args = parser.parse_args(["-v"])
        assert args.verbose is True

    def test_no_args_parse_still_yields_no_command(self):
        """The usage path is unchanged (ticket acceptance)."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestExecListRendering:
    def _rows(self):
        return {
            "executors": [
                {
                    "executor_id": "venya-exec-1",
                    "serial_number": "aabbccdd11223344",
                    "fingerprint": "ff" * 32,
                    "not_before": "2026-09-01T00:00:00Z",
                    "not_after": "2026-10-01T00:00:00Z",
                    "version": "0.2.0",
                },
                {
                    "executor_id": "venya-exec-9",
                    "serial_number": "1122334455667788",
                    "fingerprint": "ee" * 32,
                    "not_before": "2026-09-01T00:00:00Z",
                    "not_after": "2026-10-01T00:00:00Z",
                    "version": None,
                },
            ]
        }

    def test_renders_version_and_explicit_null_label(self, capsys):
        from venya_cli.commands import executor_list

        client = MagicMock()
        client.get.return_value = self._rows()
        rc = executor_list(client, SimpleNamespace(json=False))
        assert rc == 0
        out = capsys.readouterr().out
        assert "0.2.0" in out
        # condition 3: NULL renders explicitly, never blank
        assert "unknown (pre-B daemon)" in out
        client.get.assert_called_once_with("/api/v1/admin/executors")

    def test_json_mode_passes_through(self, capsys):
        import json

        from venya_cli.commands import executor_list

        client = MagicMock()
        client.get.return_value = self._rows()
        rc = executor_list(client, SimpleNamespace(json=True))
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["executors"][1]["version"] is None


class TestExecListParserWiring:
    def test_exec_list_subcommand_parses(self):
        parser = create_parser()
        args = parser.parse_args(["exec", "list"])
        assert args.command == "exec"
        assert args.exec_command == "list"
