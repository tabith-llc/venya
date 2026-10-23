# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL-2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#452 executor-side twin cells (unit, no network, NEW file — existing
pipeline code/tests untouched).

The server now refuses an undecodable stage-2 body with HTTP 400 instead of
answering 200-with-zero-knowledge (refs #452). These cells pin the ALREADY
EXISTING executor-side consumption of that signal: a non-200 drives the named
``RuntimeError`` in ``_send_to_stage2``, which the ``_filter_and_build_result``
wrapper catches, keeping the Stage-1 masked results. The executor must NOT
adopt an empty masked set from a refused call.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from executor.command_validator import CommandValidator
from executor.executor import Executor


@pytest.fixture()
def executor() -> Executor:
    """sbx-independent: a MagicMock injection strategy keeps this file out of
    the standing sbx-absent error class — the cells test the stage-2 WIRE
    protocol, not sandbox provisioning."""
    return Executor(
        command_validator=CommandValidator(),
        session_id="test-session-452",
        injection_strategy=MagicMock(),
    )


def _resp(status_code: int):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = {"detail": "stdout must be valid base64"}
    return r


class TestStage2RefusalAdoption452:
    """A 400 from the definitive masker keeps Stage-1 masking at ONE stage,
    never zero (the truth-table half: the empty-knowledge ADOPTION path stays
    closed)."""

    def test_400_raises_named_runtimeerror(self, executor: Executor):
        """400 -> RuntimeError naming the status (same shape the 404 cell in
        test_executor.py pins; no new wire behavior, just the new status)."""
        executor.http_client = MagicMock()
        executor.http_client.post.return_value = _resp(400)
        with pytest.raises(RuntimeError, match="Stage-2 filter returned 400"):
            executor._send_to_stage2(b"out", b"err")

    def test_400_keeps_stage1_results_and_nonempty_masked_ids(self, executor: Executor, caplog):
        """Adoption check: with Stage 1 masking one secret, a 400 from Stage 2
        must leave the Stage-1 masked stdout and the Stage-1 masked ids INTACT —
        the executor does not adopt an empty masked set."""
        stage1_stdout = b"hello [REDACTED:z1z1z1z1] world"
        caplog.set_level(logging.WARNING, logger="venya.executor")
        executor.http_client = MagicMock()
        executor.http_client.post.return_value = _resp(400)
        with patch(
            "executor.executor.filter_and_redact",
            return_value=(stage1_stdout, b"", ["z1z1z1z1"], []),
        ):
            injections = [MagicMock(secret_id="s1", value=b"secret1")]
            result = executor._filter_and_build_result(
                "echo test",
                0,
                b"hello secret1 world",
                b"",
                injections,
            )
        # Stage-1 output retained, NOT the empty-knowledge shape:
        assert result.stdout == stage1_stdout
        assert result.masked_secret_ids == ["z1z1z1z1"]
        assert result.masked_secret_ids != []
        # The documented fallback line is what fired:
        assert "Stage 2 filter failed" in caplog.text
