# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket session-audit-logger-forwarder-never-stopped (#467).

Pre-fix: ``ExecutorDaemon.create_executor`` built an ``AuditLogger`` for every
command session, and ``AuditLogger.__init__`` starts its forwarder thread
immediately (a 1 s-poll daemon thread plus its spool handles). The class had a
correct teardown — ``shutdown()`` — but only the BOOT instance was ever shut
down (``daemon.py`` ``_stop_audit_forwarder``), because ``Executor`` had no
teardown hook at all. So every command session the relay served leaked a live
thread for the whole life of the daemon: an N-threads-per-session-count leak,
and each leaked thread was killed abruptly at exit instead of draining.

Fix pinned here (static leg — the physical thread-count cell is DO-NOT-RUN
until a fleet lane; see the leg report):
1. ``Executor.close()`` — a teardown on the object that OWNS the session
   logger; it calls ``AuditLogger.shutdown()``, which keeps the ruled #436
   bounded per-session drain, and it is idempotent;
2. ``Executor.__del__`` — a last-resort GC guard that can never raise;
3. the call site: ``RelayRequestHandler.do_POST`` binds the session object and
   closes it in a ``finally``, so every reply lane (200, 422 policy, 503
   engine) stops its own forwarder. ``RelayListener.stop()`` (the landed #477
   territory) is not touched by this leg.

Paired negatives: the durable spool's contents are still forwarded before the
teardown (nothing is dropped by closing), a double close is one shutdown and no
error, a session with no logger closes cleanly, and the engine stubs in the
relay suite that have NO ``close`` still pass — which is what the ``hasattr``
guard at the call site is there for.
"""

import gc
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.audit import AuditLogger
from executor.executor import Executor
from executor.strategies.sbx_strategy import SbxStrategy

# Audit harness: reuse the plain builders from the audit suite (house pattern —
# import functions, define local fixtures under distinct names). test_audit.py's
# own cells are untouched by this leg.
from tests.test_audit import make_cert_pair, make_config, read_spool

# Relay harness: the real-PKI builders + doubles from the relay suite.
from tests.test_relay_listener import (
    ALLOWED,
    _ca,
    _client,
    _factory,
    _FakeExec,
    _leaf,
    _ok_result,
    _start,
    _url,
    _write_cert_only,
    _write_dir,
)

SESSION = "sess-467"


def _executor_with(logger: AuditLogger | MagicMock | None, session_id: str = SESSION) -> Executor:
    """An Executor holding a real (or stubbed) session logger.

    The strategy is a spec'd mock: ``Executor.__post_init__`` calls
    ``injection_strategy.validate()``, and the real SbxStrategy validates by
    looking for the ``sbx`` CLI, which is absent in this venue (the standing
    8f/39e environment class). Nothing in this row is about the strategy.
    """
    return Executor(
        command_validator=MagicMock(),
        session_id=session_id,
        injection_strategy=MagicMock(spec=SbxStrategy),
        audit_logger=logger,
    )


@pytest.fixture()
def spool_467(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def success_mock_467() -> MagicMock:
    """A configured httpx2.Client mock that returns 200 (same shape as test_audit's)."""
    response = MagicMock()
    response.status_code = 200
    client = MagicMock()
    client.post.return_value = response
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


def _live_forwarder_count() -> int:
    """How many threads other than this one are alive — the leak the row names."""
    return threading.active_count() - 1


class TestSessionLoggerIsStopped:
    """Acceptance 2: create + dispose one session logger, the thread count comes back."""

    def test_close_stops_the_forwarder_thread_and_proves_shutdown(self, spool_467: Path):
        logger = AuditLogger(make_config(spool_467), SESSION)
        executor = _executor_with(logger)
        before = _live_forwarder_count()
        assert logger._forwarder.is_alive(), "the forwarder must be running before close()"
        forwarder = logger._forwarder

        executor.close()

        assert logger._shutdown is True, "close() must reach AuditLogger.shutdown()"
        assert not forwarder.is_alive(), "the session forwarder thread must be finished"
        assert _live_forwarder_count() == before - 1, "the leaked thread must be accounted for"

    def test_thread_count_returns_to_baseline_over_several_sessions(self, spool_467: Path):
        """The leak in miniature: N sessions raise the count by N and no more."""
        baseline = _live_forwarder_count()
        loggers = [
            AuditLogger(
                make_config(spool_467, spool_path=str(spool_467 / f"spool-{i}.jsonl")),
                f"{SESSION}-{i}",
            )
            for i in range(3)
        ]
        executors = [_executor_with(logger) for logger in loggers]
        assert _live_forwarder_count() == baseline + 3

        for executor in executors:
            executor.close()

        assert _live_forwarder_count() == baseline
        assert all(logger._shutdown for logger in loggers)


class TestDrainStillHolds:
    """Acceptance 3 (paired negative): closing must not drop the spool's contents."""

    def test_close_forwards_the_sessions_own_events(self, spool_467: Path, success_mock_467: MagicMock):
        cert_paths = make_cert_pair(spool_467)
        logger = AuditLogger(make_config(spool_467), SESSION, client_cert=cert_paths)
        executor = _executor_with(logger)
        logger.emit("credential_injected", strategy="memfd")
        assert len(read_spool(spool_467)) == 1, "the event is durably spooled before close"
        logger._config.remote_url = "http://127.0.0.1:1/audit"

        with patch("executor.audit.httpx2.Client", return_value=success_mock_467) as cls:
            executor.close()

        cls.return_value.__enter__.return_value.post.assert_called()
        assert read_spool(spool_467) == [], "the bounded #436 drain must have forwarded the session's event"
        assert logger._shutdown is True

    def test_close_without_a_remote_keeps_the_spool_for_the_boot_forwarder(self, spool_467: Path):
        """Paired half: with no sink configured there is nothing to forward, so
        close() must leave the durable spool EXACTLY as it was — it never silently
        discards events, it just stops polling."""
        logger = AuditLogger(make_config(spool_467), SESSION)
        executor = _executor_with(logger)
        logger.emit("command_executed", command="echo hi", exit_code=0)
        spooled = read_spool(spool_467)
        assert len(spooled) == 1

        executor.close()

        assert read_spool(spool_467) == spooled
        assert logger._shutdown is True


class TestNoDoubleStop:
    """The negative the row demands: a second close is not an error."""

    def test_double_close_calls_shutdown_once(self):
        logger = MagicMock(spec=AuditLogger)
        executor = _executor_with(logger)

        executor.close()
        executor.close()

        logger.shutdown.assert_called_once()

    def test_close_with_no_audit_logger_does_not_raise(self):
        executor = _executor_with(None)
        executor.close()  # must not raise
        assert executor._closed is True

    def test_shutdown_itself_is_idempotent_on_the_real_logger(self, spool_467: Path):
        """The teardown close delegates to is itself repeatable — so a close
        racing another stop path cannot raise out of the relay handler."""
        logger = AuditLogger(make_config(spool_467), SESSION)
        executor = _executor_with(logger)
        executor.close()
        logger.shutdown()  # second, direct call
        assert logger._shutdown is True


class TestGcGuard:
    """``__del__`` is the backstop for a session nobody closed."""

    def test_dropped_executor_stops_its_logger(self):
        logger = MagicMock(spec=AuditLogger)
        executor = _executor_with(logger)
        del executor
        gc.collect()
        logger.shutdown.assert_called_once()

    def test_gc_guard_never_raises(self, spool_467: Path):
        """A real logger torn down by GC must not surface an exception — the
        interpreter would print it and the daemon would keep the noise."""
        executor = _executor_with(AuditLogger(make_config(spool_467), SESSION))
        del executor
        gc.collect()  # no exception escapes this call


class _ClosableExec(_FakeExec):
    """Engine stub that ALSO records close() — the production Executor shape."""

    def __init__(self, result: object = None, exc: BaseException | None = None) -> None:
        super().__init__(result=result, exc=exc)  # type: ignore[arg-type]
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


@pytest.fixture()
def relay_pk_467(tmp_path):
    """Minimal relay PKI (one CA, server leaf, allowed client) from the relay helpers."""
    from types import SimpleNamespace

    a_key, a_cert = _ca()
    srv_cert, srv_key = _leaf(a_key, a_cert, "relay-srv", server_auth=True)
    c_ok_cert, c_ok_key = _leaf(a_key, a_cert, ALLOWED)
    ca_crt = _write_cert_only(a_cert, tmp_path, "ca-a")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    c_ok = _write_dir(c_ok_cert, c_ok_key, tmp_path, "c-ok")
    from executor.config import ExecutorConfig, MtlsConfig

    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="relay-test-467",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(ca_a=ca_crt, c_ok=c_ok, config=config)


class TestCallSiteClosesEverySession:
    """Acceptance 1: the code that ends the session stops the logger.

    Each relay reply lane must close the object it created, and the pre-existing
    stubs that model a bare engine (no ``close`` at all) must keep passing —
    that pair is the proof for the ``hasattr`` guard.
    """

    def _post(self, pk, exec_obj, payload=None):
        sessions: list = []
        listener = _start(pk.config, _factory(exec_obj, sessions), [ALLOWED])
        try:
            with _client(pk.ca_a, pk.c_ok) as client:
                resp = client.post(
                    _url(listener), json=payload or {"session_id": SESSION, "command": ["echo", "hi"], "secrets": []}
                )
        finally:
            listener.stop()
        return resp

    def test_success_lane_closes_the_session(self, relay_pk_467):
        fake = _ClosableExec(result=_ok_result())
        resp = self._post(relay_pk_467, fake)
        assert resp.status_code == 200
        assert fake.close_calls == 1, "the session's forwarder is stopped on the 200 lane"

    def test_engine_raise_lane_still_closes_the_session(self, relay_pk_467):
        """The leak this row is about: an engine that raises after its logger
        started must not leave the thread behind."""
        fake = _ClosableExec(exc=TimeoutError("subprocess timed out"))
        resp = self._post(
            relay_pk_467, fake, payload={"session_id": SESSION, "command": ["sleep", "300"], "secrets": []}
        )
        assert resp.status_code == 503
        assert fake.close_calls == 1

    def test_policy_rejection_lane_closes_the_session(self, relay_pk_467):
        from executor.executor import CommandRejected

        fake = _ClosableExec(exc=CommandRejected("Command rejected: Dangerous pattern detected"))
        resp = self._post(relay_pk_467, fake, payload={"session_id": SESSION, "command": ["sudo", "rm"], "secrets": []})
        assert resp.status_code == 422
        assert fake.close_calls == 1

    def test_engine_stub_without_close_still_works(self, relay_pk_467):
        """Paired negative: the guard. Existing relay cells inject _FakeExec,
        which has no close() — the handler must not demand one."""
        fake = _FakeExec(result=_ok_result())
        assert not hasattr(fake, "close")
        resp = self._post(relay_pk_467, fake)
        assert resp.status_code == 200
        assert fake.command == ["echo", "hi"]

    def test_raising_factory_takes_the_503_lane_and_does_not_crash_the_finally(self, relay_pk_467):
        """The factory call sits inside the try, so a raising factory keeps the
        flat 503 lane it had before this change — and the finally must not trip
        over the session object it never got."""

        def _boom(_session_id: str):
            raise RuntimeError("no executor for you")

        sessions: list = []
        listener = _start(relay_pk_467.config, _boom, [ALLOWED])
        try:
            with _client(relay_pk_467.ca_a, relay_pk_467.c_ok) as client:
                resp = client.post(_url(listener), json={"session_id": SESSION, "command": ["echo"], "secrets": []})
        finally:
            listener.stop()
        assert resp.status_code == 503
        assert sessions == []


class TestBootInstanceUnchanged:
    """Acceptance 4: the boot forwarder path is not this leg's territory."""

    def test_daemon_still_owns_the_boot_forwarder_alone(self):
        """``daemon.py`` keeps exactly one BOOT_FORWARDER_SESSION_ID construction,
        and the boot teardown is still ``_stop_audit_forwarder`` — this leg added
        no shutdown call to the boot path and changed nothing there."""
        import inspect

        from executor import daemon as daemon_mod

        src = inspect.getsource(daemon_mod)
        assert src.count("BOOT_FORWARDER_SESSION_ID,") == 1, "boot forwarder is still constructed in exactly one place"
        assert "self.audit_boot_forwarder.shutdown()" in src
        # The per-session factory does NOT shut anything down at build time.
        factory_src = inspect.getsource(daemon_mod.ExecutorDaemon.create_executor)
        assert "shutdown" not in factory_src
        assert "audit_boot_forwarder" not in factory_src

    def test_close_is_on_the_executor_not_the_daemon(self):
        """The hook the ticket asked for lives on the object that owns the
        logger; the daemon's own stop path keeps its separate boot teardown."""
        assert callable(Executor.close)
        assert not hasattr(Executor, "shutdown")
