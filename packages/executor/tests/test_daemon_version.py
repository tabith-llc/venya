# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor version surfaces (feature/version-surfaces): heartbeat payload
carries the single-sourced dist version; the daemon binary answers --version.
"""

from importlib.metadata import version as pkg_version
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import ExecutorConfig

EXECUTOR_VERSION = pkg_version("executor")


class TestHeartbeatPayloadVersion:
    def test_payload_carries_single_sourced_version(self):
        from executor.daemon import ExecutorDaemon

        config = ExecutorConfig(server_url="https://example.com", executor_id="test-executor")
        daemon = ExecutorDaemon(config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.cert_manager = MagicMock()
        daemon.cert_manager.get_fingerprint.return_value = "ab" * 32
        daemon.client.post.return_value = MagicMock(json=dict)

        daemon._send_heartbeat()

        payload = daemon.client.post.call_args[1]["json"]
        assert payload["version"] == EXECUTOR_VERSION
        # wire-compat: existing keys unchanged
        assert payload["executor_id"] == "test-executor"
        assert payload["cert_fingerprint"] == "ab" * 32


class TestDaemonVersionFlag:
    def test_version_flag_prints_metadata_and_exits_zero(self, capsys):
        from executor.daemon import main

        with patch("sys.argv", ["venya-executor", "--version"]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 0
        assert EXECUTOR_VERSION in capsys.readouterr().out
