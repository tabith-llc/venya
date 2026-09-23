# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the execute-path timeout (ticket cli-execution-timeout-cold-start-default).

The client must be the LAST fuse in the relay chain (server relay 300s <
nginx 330s < client default 340s): the former 30s default aborted the first
cold-sandbox run (~65s template pull) client-side while the server completed
it correctly, and the operator retry double-executed the command.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.api_client import APIClientError, execution_timeout
from venya_cli.commands import cmd_run


class TestExecutionTimeout:
    def test_default_is_last_fuse(self, monkeypatch):
        """Default 340 > nginx 330 > relay 300 — the client never fires first."""
        monkeypatch.delenv("VENYA_EXECUTION_TIMEOUT", raising=False)
        assert execution_timeout() == 340.0

    def test_env_override_respected(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTION_TIMEOUT", "45")
        assert execution_timeout() == 45.0

    def test_garbage_env_actionable_error(self, monkeypatch):
        """Paired negative: non-integer → actionable APIClientError naming the
        knob — not a raw ValueError traceback, not a silent fallback."""
        monkeypatch.setenv("VENYA_EXECUTION_TIMEOUT", "soon")
        with pytest.raises(APIClientError, match="VENYA_EXECUTION_TIMEOUT"):
            execution_timeout()

    def test_non_positive_env_rejected(self, monkeypatch):
        """Paired negative: 0/negative would mean 'no timeout' or nonsense in
        httpx — rejected loudly instead."""
        monkeypatch.setenv("VENYA_EXECUTION_TIMEOUT", "0")
        with pytest.raises(APIClientError, match="positive"):
            execution_timeout()


def _drive_run(monkeypatch):
    client = MagicMock()
    client.post.side_effect = [
        {"session_id": "s1"},  # session create (fast — client default)
        {"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0},  # execute
    ]
    args = SimpleNamespace(command_args=["echo", "hi"], executor_id="exec-1", secrets=[])
    rc = cmd_run(client, args)
    return rc, client


class TestRunPassesTimeout:
    def test_execute_post_carries_timeout_session_post_does_not(self, monkeypatch):
        monkeypatch.delenv("VENYA_EXECUTION_TIMEOUT", raising=False)
        rc, client = _drive_run(monkeypatch)
        assert rc == 0
        session_call, exec_call = client.post.call_args_list
        # execute leg gets the last-fuse timeout…
        assert exec_call.kwargs.get("timeout") == 340.0
        # …session-create (fast call) keeps the client default (no override)
        assert "timeout" not in session_call.kwargs

    def test_execute_timeout_follows_env(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTION_TIMEOUT", "120")
        rc, client = _drive_run(monkeypatch)
        assert rc == 0
        assert client.post.call_args_list[1].kwargs.get("timeout") == 120.0
