# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket #456 — a failed secret destroy must not read as success.

Pre-fix: ``InjectionResult.cleanup()`` ran each destroy callable inside a bare
``except Exception:`` that logged ``"Injection cleanup error"`` and moved on.
Nothing in the result said which step failed, so the run reported a clean
teardown while secret material stayed resident.

Fix pinned here:
1. ``cleanup()`` still runs EVERY callable (one failure must not skip the rest —
   that would leak more than it reports);
2. failures are recorded on the result as ``cleanup_failures`` (index, label,
   error) and exposed through ``all_clean`` / ``degraded``;
3. the WARNING names the failing step AND the resources still held
   (secret ids / mount paths / fds where knowable) — AC3;
4. the consumer ``Executor._cleanup_injections()`` surfaces a degraded summary
   and still completes the rest of teardown (bundles zeroed, registry cleared).
   Teardown degradation is never a crash and never changes the exit code.

Paired negatives: an all-green cleanup logs no warning, and a
non-``Exception`` ``BaseException`` is not swallowed.
"""

import logging
from unittest.mock import MagicMock

import pytest

from executor.bundles import SecretBundle
from executor.executor import CommandValidator, Executor
from executor.strategies.base import CleanupFailure, InjectionResult, SecretMount


def _bundle(secret_id: str = "db-password", value: bytes = b"hunter2") -> SecretBundle:
    return SecretBundle(secret_id=secret_id, value=value, wrapped_value=b"")


def _result(
    funcs: list,
    *,
    mounts: list[SecretMount] | None = None,
    fds: list[int] | None = None,
) -> InjectionResult:
    return InjectionResult(
        extra_fds=list(fds or []),
        secret_mounts=list(mounts or []),
        cleanup_funcs=list(funcs),
    )


class TestCleanupFailureRecorded:
    """§4 cells on InjectionResult.cleanup() itself."""

    def test_one_failing_step_is_degraded_and_the_others_still_run(self, caplog):
        """Load-bearing half: the failed destroy is reported, the rest still run."""
        ran: list[str] = []

        def boom() -> None:
            ran.append("boom")
            raise OSError("shm unlink failed")

        def second() -> None:
            ran.append("second")

        def third() -> None:
            ran.append("third")

        result = _result(
            [boom, second, third],
            mounts=[
                SecretMount(
                    secret_id="db-password",
                    path="/dev/shm/venya-secrets/s1/db-password",
                    container_path="/run/secrets/venya/db-password",
                )
            ],
            fds=[7],
        )

        with caplog.at_level(logging.WARNING, logger="venya.executor.strategies"):
            failures = result.cleanup()

        # every callable ran, including the ones after the failure
        assert ran == ["boom", "second", "third"]

        assert result.degraded is True
        assert result.all_clean is False
        assert len(failures) == 1
        failure = failures[0]
        assert isinstance(failure, CleanupFailure)
        assert failure.index == 0
        assert "OSError: shm unlink failed" == failure.error
        assert "boom" in failure.label

        # AC3: the log names WHICH resource failed, not just "cleanup error"
        assert len(caplog.records) == 1
        message = caplog.records[0].getMessage()
        assert "db-password" in message
        assert "/dev/shm/venya-secrets/s1/db-password" in message
        assert "fd=7" in message

    def test_all_steps_clean_is_not_degraded_and_logs_nothing(self, caplog):
        """Paired negative: a green teardown stays silent."""
        ran: list[str] = []
        result = _result([lambda: ran.append("a"), lambda: ran.append("b")])

        with caplog.at_level(logging.WARNING, logger="venya.executor.strategies"):
            failures = result.cleanup()

        assert ran == ["a", "b"]
        assert failures == []
        assert result.all_clean is True
        assert result.degraded is False
        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_two_of_three_failures_are_both_recorded_in_order(self):
        calls: list[int] = []

        def first() -> None:
            calls.append(0)
            raise RuntimeError("fifo close failed")

        def ok() -> None:
            calls.append(1)

        def third() -> None:
            calls.append(2)
            raise ValueError("bad fd")

        result = _result([first, ok, third])
        failures = result.cleanup()

        assert calls == [0, 1, 2]
        assert len(failures) == 2
        assert [f.index for f in failures] == [0, 2]
        assert failures[0].error == "RuntimeError: fifo close failed"
        assert failures[1].error == "ValueError: bad fd"
        assert "first" in failures[0].label
        assert "third" in failures[1].label

    def test_repeat_cleanup_does_not_accumulate_the_same_failure(self):
        """cleanup_failures is the record of the LATEST run, not a growing log."""

        def boom() -> None:
            raise OSError("tmpfs still mounted")

        result = _result([boom])
        first = result.cleanup()
        second = result.cleanup()

        assert len(first) == 1
        assert len(second) == 1
        assert result.degraded is True

    def test_base_exception_is_not_swallowed(self):
        """Boundary pin: only Exception subclasses are recorded, not BaseException."""

        def interrupt() -> None:
            raise KeyboardInterrupt()

        result = _result([interrupt, lambda: None])

        with pytest.raises(KeyboardInterrupt):
            result.cleanup()

        assert result.cleanup_failures == []


class TestExecutorSurfacesDegradedTeardown:
    """§4 consumer cell — executor-level, no sandbox needed."""

    def _executor(self, result: InjectionResult) -> Executor:
        strategy = MagicMock()
        executor = Executor(
            command_validator=CommandValidator(),
            session_id="test-session-456",
            injection_strategy=strategy,
        )
        executor._injection_result = result
        executor._bundles = [_bundle("db-password", b"hunter2")]
        executor._sentinel_registry = MagicMock()
        return executor

    def test_degraded_summary_is_logged_and_teardown_still_completes(self, caplog):
        def boom() -> None:
            raise OSError("tmpfs destroy failed")

        result = _result(
            [boom],
            mounts=[
                SecretMount(
                    secret_id="db-password",
                    path="/dev/shm/venya-secrets/s1/db-password",
                    container_path="/run/secrets/venya/db-password",
                )
            ],
        )
        executor = self._executor(result)
        bundle = executor._bundles[0]
        assert bundle.value == b"hunter2"

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            executor._cleanup_injections()

        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("Secret cleanup degraded" in message for message in warnings), warnings
        summary = next(message for message in warnings if "Secret cleanup degraded" in message)
        assert "1 of 1 destroy step(s) failed" in summary
        assert "db-password" in summary
        assert "tmpfs destroy failed" in summary

        # the teardown still ran to completion — no raise, no skipped step
        assert bundle.value == b"\x00" * len(b"hunter2")
        executor._sentinel_registry.clear.assert_called_once()
        assert executor._injection_result is None

    def test_clean_teardown_logs_no_degraded_warning(self, caplog):
        """Paired negative: the ordinary green path stays quiet."""
        result = _result([lambda: None])
        executor = self._executor(result)
        bundle = executor._bundles[0]

        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            executor._cleanup_injections()

        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []
        assert bundle.value == b"\x00" * len(b"hunter2")
        assert executor._injection_result is None


class TestCompletionInfoOnlyWhenClean:
    """#456 follow-up — the lead's SUPPRESS ruling, both halves.

    Pre-change: ``_cleanup_injections()`` logged ``"Cleanup complete"`` at INFO
    unconditionally, so a teardown that left secret material resident still read
    as complete in the log stream.
    """

    def _executor(self, result: InjectionResult) -> Executor:
        executor = Executor(
            command_validator=CommandValidator(),
            session_id="test-session-456",
            injection_strategy=MagicMock(),
        )
        executor._injection_result = result
        executor._bundles = [_bundle("db-password", b"hunter2")]
        executor._sentinel_registry = MagicMock()
        return executor

    def _infos(self, caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.name == "venya.executor" and r.levelno == logging.INFO]

    def test_clean_teardown_still_logs_completion_info(self, caplog):
        """Half one: green teardown keeps the INFO line."""
        executor = self._executor(_result([lambda: None]))

        with caplog.at_level(logging.INFO, logger="venya.executor"):
            executor._cleanup_injections()

        assert "Cleanup complete" in self._infos(caplog)

    def test_degraded_teardown_logs_no_completion_info_but_does_warn(self, caplog):
        """Half two: material still resident means no completion line, and the
        degraded WARNING is there instead."""

        def boom() -> None:
            raise OSError("tmpfs destroy failed")

        result = _result(
            [boom],
            mounts=[
                SecretMount(
                    secret_id="db-password",
                    path="/dev/shm/venya-secrets/s1/db-password",
                    container_path="/run/secrets/venya/db-password",
                )
            ],
        )
        executor = self._executor(result)

        with caplog.at_level(logging.INFO, logger="venya.executor"):
            executor._cleanup_injections()

        assert "Cleanup complete" not in self._infos(caplog)
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("Secret cleanup degraded" in message for message in warnings), warnings
        # the teardown itself still finished the rest of its work
        assert executor._bundles[0].value == b"\x00" * len(b"hunter2")
        executor._sentinel_registry.clear.assert_called_once()
