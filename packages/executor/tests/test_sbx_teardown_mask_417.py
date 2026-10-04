# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Teardown swallow-and-log in _run_command_sbx (ticket #417).

Pre-fix the finally called strategy.remove_sandbox() bare: a
subprocess-level raise there (timeout, missing sbx binary) REPLACED the
in-flight origin exception during unwind — the caller/audit recorded the
teardown error and the real command outcome was lost. Ruled shape:
swallow + WARNING naming the sandbox; a clean run stays clean.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import Executor
from executor.strategies.sbx_strategy import SbxStrategy


class TestTeardownSwallowAndLog:
    def _executor_with_mock_sbx(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        ex = Executor(command_validator=MagicMock(), session_id="s-417", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        return ex, strategy

    def _run(self, ex):
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            return ex._run_command_sbx("cmd", [], None, None)

    def test_setup_raise_and_teardown_raise_origin_surfaces(self, caplog):
        """Origin exception propagates untouched; teardown raise swallowed + logged."""
        boom = RuntimeError("copy failed")
        ex, strategy = self._executor_with_mock_sbx()
        ex._injection_result = MagicMock()  # without this the copy-secrets branch is skipped
        strategy.copy_secrets_into_sandbox.side_effect = boom
        teardown_boom = TimeoutError("sbx rm hung")
        strategy.remove_sandbox.side_effect = teardown_boom

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            with pytest.raises(RuntimeError) as ei:
                self._run(ex)

        assert ei.value is boom
        assert strategy.remove_sandbox.call_count == 1
        assert "Sandbox teardown failed" in caplog.text
        assert "venya-s-417" in caplog.text

    def test_execute_raise_and_teardown_raise_origin_surfaces(self, caplog):
        boom = ValueError("guest exec blew up")
        ex, strategy = self._executor_with_mock_sbx()
        strategy.execute_command.side_effect = boom
        strategy.remove_sandbox.side_effect = OSError("sbx binary vanished")

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            with pytest.raises(ValueError) as ei:
                self._run(ex)

        assert ei.value is boom
        assert strategy.remove_sandbox.call_count == 1
        assert "Sandbox teardown failed" in caplog.text

    def test_clean_run_teardown_raise_no_error_escapes(self, caplog):
        """Success path: teardown failure never turns a clean run into a failure."""
        ex, strategy = self._executor_with_mock_sbx()
        strategy.remove_sandbox.side_effect = TimeoutError("sbx rm hung")

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            result = self._run(ex)  # pre-fix this raised; a bare finally on a success path is a spurious failure

        assert result.stdout == b"ok"
        assert strategy.remove_sandbox.call_count == 1
        assert "Sandbox teardown failed" in caplog.text

    def test_paired_negative_normal_run_no_warning(self, caplog):
        """Normal teardown still called exactly once, nothing logged."""
        ex, strategy = self._executor_with_mock_sbx()

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            result = self._run(ex)

        assert result.stdout == b"ok"
        assert strategy.remove_sandbox.call_count == 1
        assert "Sandbox teardown failed" not in caplog.text
