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

import sys
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


class TestVersionSurfaceNamesTheFace:
    """R-2876: the CLI answer carries the build face too, with the version still first."""

    def test_version_flag_prints_the_release_then_a_face(self, capsys):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0
        printed = capsys.readouterr().out.strip()
        assert printed.split()[0] == CLI_VERSION, printed
        assert "(build " in printed, f"no build face on the CLI surface: {printed!r}"

    def test_a_stated_release_is_printed_verbatim(self, monkeypatch):
        """``VENYA_BUILD_COMMIT`` is an explicit statement, so it is the first token of
        the face field — the same priority ``core.version.build_identity`` applies."""
        from venya_cli.api_client import cli_version_line

        monkeypatch.setenv("VENYA_BUILD_COMMIT", "beef12345 built by the release recipe")
        assert cli_version_line() == f"{CLI_VERSION} (build beef12345)"

    def test_the_stamp_beside_core_is_read_without_importing_core(self, monkeypatch, tmp_path):
        """The route a stamped install takes, and the isolation guarantee at once.

        A stand-in package directory holding only ``BUILD_COMMIT`` is found on the
        path, and ``core`` is NOT loaded to read it: ``venya_cli`` must stay standalone
        (``test_capability_isolation.py``), so this is a path lookup, not a dependency.
        """
        from venya_cli import api_client

        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "core" / "BUILD_COMMIT").write_text("beef12345 stamped at the cut\n", encoding="utf-8")
        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.delitem(sys.modules, "core", raising=False)
        assert api_client.build_face() == "beef12345"
        assert "core" not in sys.modules, "reading the stamp imported core — the CLI is standalone"

    def test_a_malformed_stamp_is_refused_not_propagated(self, monkeypatch, tmp_path):
        """The same class at this layer: a non-UTF-8 stamp must not stop the CLI."""
        from venya_cli import api_client

        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "__init__.py").write_text("", encoding="utf-8")
        (tmp_path / "core" / "BUILD_COMMIT").write_bytes(b"\xff\xfe not utf-8 at all")
        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.delitem(sys.modules, "core", raising=False)
        assert api_client.build_face() == "unknown"

    def test_building_the_parser_reads_nothing(self, monkeypatch):
        """The other half of B1: the version answer must not be needed to BUILD a parser.

        ``create_parser`` runs for every command, so a stamp read inside it would put
        ``--help``, ``config show`` and ``exec status`` behind a file they never asked
        for. Making the answer raise proves nothing else calls it: if the read were
        still in construction, this cell dies before argparse is even built.
        """
        import venya_cli.cli as cli_module

        def boom() -> str:
            raise AssertionError("the version surface was read while building the parser")

        monkeypatch.setattr(cli_module, "cli_version_line", boom)
        parser = cli_module.create_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_no_statement_and_no_stamp_names_no_sha(self, monkeypatch):
        """The paired negative R-2876 is gated on: with neither route present the face
        is ``unknown``, never a clean-looking number this layer cannot prove."""
        from venya_cli import api_client

        monkeypatch.delenv("VENYA_BUILD_COMMIT", raising=False)
        monkeypatch.setattr(api_client, "BUILD_COMMIT_FILENAME", "no-such-stamp-1225")
        assert api_client.cli_version_line() == f"{CLI_VERSION} (build unknown)"


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
        # #324: table mode also consults the fenced /health for the core version
        # (warning pass) — the admin-list fetch itself must still happen.
        paths = [c.args[0] for c in client.get.call_args_list]
        assert "/api/v1/admin/executors" in paths

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
