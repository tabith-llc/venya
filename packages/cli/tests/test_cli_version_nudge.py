# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under the Mozilla Public
# License, v. 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Version-mismatch advisory truth table (ticket #324, rulings D1-D4).

Per-process /health check: equal versions -> silent; stale CLI -> nudge names
the CLI; stale core -> nudge names the core and NEVER advises downgrading it;
offline -> silent skip (no second error on an unreachable core); one fetch per
process, not per command. exec list: matching executor version -> quiet,
mismatch -> one warn-only line (no behavior gate — D2). Paired negatives per
the standing rule.
"""

from importlib.metadata import version as pkg_version
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from venya_cli import commands as commands_mod
from venya_cli.api_client import APIClientError, version_tuple
from venya_cli.commands import run_command

CLI_VERSION = pkg_version("venya-cli")


@pytest.fixture(autouse=True)
def _reset_version_cache():
    commands_mod._server_version_cache = commands_mod._SERVER_VERSION_UNCHECKED
    yield
    commands_mod._server_version_cache = commands_mod._SERVER_VERSION_UNCHECKED


def _health_client(version=CLI_VERSION, exc=None):
    """Fake client: /health returns `version`; other GETs return an empty list."""

    def get(path, **kwargs):
        if exc is not None:
            raise exc
        if path.endswith("/health"):
            return {"status": "ok", "version": version, "checks": {}}
        return {"executors": []}

    client = MagicMock()
    client.get.side_effect = get
    client.config.access_token = "tok"
    client.has_admin_mtls = False
    return client


def _run(client, command="list"):
    args = SimpleNamespace(command=command, server_url=None, user_id=None)
    with (
        patch("venya_cli.commands.APIClient", return_value=client),
        patch("venya_cli.commands.cmd_list", return_value=0),
    ):
        rc = run_command(args)
    return rc


class TestVersionTuple:
    def test_spellings_normalize_equal(self):
        assert version_tuple("0.1.0alpha16") == version_tuple("0.1.0a16")
        assert version_tuple("0.1.0beta1") == version_tuple("0.1.0b1")
        assert version_tuple("0.1.0alpha2") < version_tuple("0.1.0a13")

    def test_beta_sorts_between_alpha_and_final(self):
        """0.1.0beta1 is a prerelease: above the shipped alphas, below 0.1.0.

        A wrong-side sort here would nudge users the wrong way (stale-vs-
        future verdicts in the advisory truth table). The garbage-returns-
        None negative half is already pinned by
        test_unparseable_fails_closed at this tip.
        """
        assert version_tuple("0.1.0beta1") is not None
        assert version_tuple("0.1.0beta1") > version_tuple("0.1.0alpha16")
        assert version_tuple("0.1.0beta1") < version_tuple("0.1.0")

    def test_unparseable_fails_closed(self):
        for bad in (None, "", "garbage", "unknown", "0.1.0a13+local"):
            assert version_tuple(bad) is None, bad


class TestAdvisoryTruthTable:
    def test_equal_versions_silent(self, capsys):
        rc = _run(_health_client(version=CLI_VERSION))
        assert rc == 0
        captured = capsys.readouterr()
        assert "version" not in captured.err.lower()
        assert captured.out == ""

    def test_stale_cli_nudges_cli_upgrade(self, capsys):
        rc = _run(_health_client(version="99.0.0"))
        assert rc == 0  # warn-only: the command still runs (D2, no gate)
        err = capsys.readouterr().err
        assert "older than the core" in err
        assert "update the CLI" in err
        assert "downgrade" not in err.lower()

    def test_stale_core_nudges_core_upgrade_never_downgrade(self, capsys):
        rc = _run(_health_client(version="0.0.1"))
        assert rc == 0
        err = capsys.readouterr().err
        assert "newer than the core" in err
        assert "update the core" in err
        assert "downgrade" not in err.lower()

    def test_spelling_difference_silent(self, capsys):
        """PEP 440 normalization: alpha16 vs a16 is the SAME release -> silence."""
        normalized = version_tuple(CLI_VERSION)
        assert normalized is not None
        short = f"{normalized[0]}.{normalized[1]}.{normalized[2]}" + (
            "" if normalized[3] == "z" else f"{normalized[3]}{normalized[4]}"
        )
        rc = _run(_health_client(version=short))
        assert rc == 0
        assert "version" not in capsys.readouterr().err.lower()

    def test_offline_silent_skip(self, capsys):
        """D1: unreachable core -> no advisory, command proceeds to its own
        honest path; the advisory must not add a second error."""
        client = _health_client(exc=APIClientError("Connection failed: refused"))
        rc = _run(client)
        assert rc == 0  # cmd_list is patched and succeeds; advisory stayed quiet
        assert "version" not in capsys.readouterr().err.lower()

    def test_unknown_server_version_silent(self, capsys):
        """Old server without the fenced field, or an unparseable value: no
        verdict, no nudge (fail-closed)."""
        rc = _run(_health_client(version="unknown"))
        assert rc == 0
        assert "version" not in capsys.readouterr().err.lower()

    def test_one_fetch_per_process_not_per_command(self):
        client = _health_client(version="99.0.0")
        _run(client)
        _run(client)  # second command, same process
        health_calls = [c for c in client.get.call_args_list if c.args[0].endswith("/health")]
        assert len(health_calls) == 1


class TestExecListMismatch:
    def _exec_client(self, exec_version):
        client = MagicMock()

        def get(path, **kwargs):
            if path.endswith("/health"):
                return {"status": "ok", "version": CLI_VERSION, "checks": {}}
            return {
                "executors": [
                    {
                        "executor_id": "venya-exec-1",
                        "serial_number": "aabb" * 4,
                        "not_after": "2026-10-01T00:00:00Z",
                        "version": exec_version,
                    }
                ]
            }

        client.get.side_effect = get
        return client

    def test_executor_match_quiet(self, capsys):
        rc = commands_mod.executor_list(self._exec_client(CLI_VERSION), SimpleNamespace(json=False))
        assert rc == 0
        assert "Warning" not in capsys.readouterr().err

    def test_executor_mismatch_warns_without_gating(self, capsys):
        rc = commands_mod.executor_list(self._exec_client("99.0.0"), SimpleNamespace(json=False))
        assert rc == 0  # warn-only, exit code unchanged (D2)
        err = capsys.readouterr().err
        assert "venya-exec-1" in err
        assert "99.0.0" in err
        assert "upgrade the out-of-date side" in err

    def test_null_executor_version_no_verdict(self, capsys):
        """Paired negative: a pre-reporting daemon gets the explicit NULL cell
        but NO wrong-side nudge (unparseable -> no verdict)."""
        rc = commands_mod.executor_list(self._exec_client(None), SimpleNamespace(json=False))
        assert rc == 0
        captured = capsys.readouterr()
        assert "unknown (pre-B daemon)" in captured.out
        assert "Warning" not in captured.err
