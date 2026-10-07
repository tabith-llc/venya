# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket relay-stop-unbounded-skips-cleanup-under-systemd (#477).

Pre-fix: RelayListener.stop() called server.shutdown() unconditionally. The
server is single-threaded and runs the command INLINE (up to SBX_TIMEOUT =
3600 s), so a stop during a long command blocked past systemd's default stop
deadline; the SIGKILL that followed skipped the sandbox-removal finally
(executor.py) and the temp cleanup — an orphaned secrets-bearing sandbox.

Fix pinned here (static leg — the physical systemctl cell is DO-NOT-RUN
until an owner-present fleet lane; see the leg report):
1. cooperative drain: stop() sets a no-new-commands flag BEFORE the shutdown
   request; the handler answers a flat 503 to anything racing it;
2. bounded wait: shutdown is joined with a deadline (RELAY_STOP_DEADLINE_
   SECONDS); within the deadline the in-flight command finishes and its
   teardown completes before stop() returns (acceptance-2 first arm);
   beyond it, stop() returns with a named ERROR line instead of letting the
   process sit until systemd's kill;
3. the unit declares TimeoutStopSec=45s — a static interlock below pins the
   file against the code constant so the two cannot drift.

Paired negative (acceptance 4): a normal stop with no in-flight command
still returns promptly and logs "Executor relay listener stopped".
"""

import logging
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from executor.config import ExecutorConfig, MtlsConfig
from executor.executor import CommandResult
from executor.relay_listener import RELAY_STOP_DEADLINE_SECONDS, RelayListener

# Reuse the real-PKI builders from the relay suite (house pattern imports plain
# helpers, not fixtures — fixtures are defined locally below under distinct
# names). test_relay_listener's own cells are untouched by this leg.
from tests.test_relay_listener import (
    ALLOWED,
    SERVER_CN,
    _ca,
    _client,
    _FakeExec,
    _leaf,
    _ok_result,
    _start,
    _url,
    _write_cert_only,
    _write_dir,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
UNIT_FILE = REPO_ROOT / "systemd" / "venya-executor.service"


@pytest.fixture()
def relay_pk(tmp_path) -> SimpleNamespace:
    """Server leaf + allowed/denied client certs on one CA — the same PKI
    shape the relay suite builds, from its imported helpers."""
    a_key, a_cert = _ca()
    srv_cert, srv_key = _leaf(a_key, a_cert, SERVER_CN, server_auth=True)
    c_ok_cert, c_ok_key = _leaf(a_key, a_cert, ALLOWED)
    c_ban_cert, c_ban_key = _leaf(a_key, a_cert, "disallowed-exec")
    ca_a_crt = _write_cert_only(a_cert, tmp_path, "ca-a")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    c_ok = _write_dir(c_ok_cert, c_ok_key, tmp_path, "c-ok")
    c_ban = _write_dir(c_ban_cert, c_ban_key, tmp_path, "c-ban")
    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="relay-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_a_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(ca_a=ca_a_crt, c_ok=c_ok, c_ban=c_ban, config=config)


class _SlowExec(_FakeExec):
    """Engine stub that enters, waits for release, then finishes — the
    long-running command the stop path must bound."""

    def __init__(self) -> None:
        super().__init__(result=CommandResult(command="c", exit_code=0, stdout=b"done", stderr=b""))
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = False

    def execute(self, command, secrets, env_vars=None, askpass_helper=False):
        self.command = command
        self.entered.set()
        assert self.release.wait(timeout=15), "test must release the in-flight command"
        self.finished = True
        return self._result


def _fire_request(listener: RelayListener, pk_ns, out: list) -> threading.Thread:
    """POST /execute from a peer thread; capture either the response or the
    raised error (a stop racing the reply legitimately breaks the socket)."""
    payload = {"session_id": "s-drain", "command": ["sleep", "60"], "secrets": []}

    def _go() -> None:
        with _client(pk_ns.ca_a, pk_ns.c_ok) as client:
            try:
                out.append(client.post(_url(listener), json=payload))
            except Exception as exc:
                out.append(exc)

    t = threading.Thread(target=_go, daemon=True)
    t.start()
    return t


class TestDrainRefusesNewCommands:
    """Acceptance 1, first half: while draining, NEW commands get the flat
    503 lane — no allocation, no engine call, before body handling."""

    def test_new_request_during_drain_is_503(self, relay_pk, caplog):
        fake = _FakeExec(result=_ok_result())
        listener = _start(relay_pk.config, lambda _sid: fake, [ALLOWED])
        try:
            listener._draining.set()  # stop() sets this before requesting shutdown
            with _client(relay_pk.ca_a, relay_pk.c_ok) as client:
                resp = client.post(_url(listener), json={"session_id": "s", "command": ["true"], "secrets": []})
            assert resp.status_code == 503
            assert "draining" in resp.json()["detail"]
            assert fake.command is None, "the engine must never see a drained request"
        finally:
            listener.stop()

    def test_unauthorized_peer_still_gets_403_first(self, relay_pk):
        """Paired negative: the drain gate sits BEHIND identity — an unknown
        CN must not learn the shutdown state, and rejection order is
        unchanged."""
        fake = _FakeExec(result=_ok_result())
        listener = _start(relay_pk.config, lambda _sid: fake, [ALLOWED])
        try:
            listener._draining.set()
            with _client(relay_pk.ca_a, relay_pk.c_ban) as client:
                resp = client.post(_url(listener), json={"session_id": "s", "command": ["true"]})
            assert resp.status_code == 403
        finally:
            listener.stop()


class TestBoundedStopWithInFlight:
    """Acceptance 1+2: the wait for the in-flight command is BOUNDED."""

    def test_teardown_completes_when_command_finishes_within_deadline(self, relay_pk):
        slow = _SlowExec()
        listener = _start(relay_pk.config, lambda _sid: slow, [ALLOWED])
        try:
            out: list = []
            t = _fire_request(listener, relay_pk, out)
            assert slow.entered.wait(timeout=5), "request reached the engine"

            release = threading.Timer(0.4, slow.release.set)
            release.start()
            started_at = time.monotonic()
            listener.stop(deadline_seconds=5.0)
            elapsed = time.monotonic() - started_at

            # stop waited for the in-flight command (bounded by 5 s)...
            assert 0.2 < elapsed < 5.0
            # ...and its completion — this is the arm where the engine's
            # finally (sandbox teardown) provably ran BEFORE stop returned.
            assert slow.finished is True
            t.join(timeout=5)
            assert any(getattr(r, "status_code", None) == 200 for r in out), out
        finally:
            slow.release.set()
            listener.stop()

    def test_stop_returns_at_deadline_and_logs_overflow_loudly(self, relay_pk, caplog):
        slow = _SlowExec()
        listener = _start(relay_pk.config, lambda _sid: slow, [ALLOWED])
        try:
            out: list = []
            t = _fire_request(listener, relay_pk, out)
            assert slow.entered.wait(timeout=5)

            with caplog.at_level(logging.ERROR, logger="venya.executor.relay"):
                started_at = time.monotonic()
                listener.stop(deadline_seconds=0.5)
                elapsed = time.monotonic() - started_at

            assert elapsed < 3.0, f"stop was NOT bounded: took {elapsed:.1f}s"
            assert slow.finished is False, "command deliberately still in flight"
            assert any(
                "deadline" in r.getMessage() for r in caplog.records
            ), "the overflow must name itself in the journal — no silent skip"
        finally:
            slow.release.set()
            t.join(timeout=5)
            listener.stop()


class TestPromptNormalStop:
    """Acceptance 4 paired negative: no in-flight command -> prompt return,
    the unchanged 'stopped' log line, and a re-stop that is a harmless no-op."""

    def test_normal_stop_prompt_and_logged(self, relay_pk, caplog):
        fake = _FakeExec(result=_ok_result())
        listener = _start(relay_pk.config, lambda _sid: fake, [ALLOWED])
        with caplog.at_level(logging.INFO, logger="venya.executor.relay"):
            started_at = time.monotonic()
            listener.stop()
            elapsed = time.monotonic() - started_at
        assert elapsed < 5.0
        assert "Executor relay listener stopped" in caplog.text
        listener.stop()  # idempotent no-op

    def test_requests_succeed_normally_before_any_drain(self, relay_pk):
        fake = _FakeExec(result=_ok_result())
        listener = _start(relay_pk.config, lambda _sid: fake, [ALLOWED])
        try:
            with _client(relay_pk.ca_a, relay_pk.c_ok) as client:
                resp = client.post(_url(listener), json={"session_id": "s", "command": ["true"], "secrets": []})
            assert resp.status_code == 200
            assert fake.command == ["true"]
        finally:
            listener.stop()


class TestUnitInterlock:
    """Acceptance 1, second half: the systemd unit declares a TimeoutStopSec
    consistent with the code bound — file-vs-constant drift fails here, not
    on a production VM."""

    def test_unit_declares_timeoutstopsec_beyond_the_drain_deadline(self):
        text = UNIT_FILE.read_text(encoding="utf-8")
        m = re.search(r"^TimeoutStopSec=(\d+)s\s*$", text, re.MULTILINE)
        assert m, "venya-executor.service must declare TimeoutStopSec=<n>s"
        declared = int(m.group(1))
        assert declared > int(RELAY_STOP_DEADLINE_SECONDS), (
            f"TimeoutStopSec={declared}s must exceed the relay drain bound "
            f"({RELAY_STOP_DEADLINE_SECONDS}s) plus margin — otherwise systemd kills "
            "the process while stop() is still cooperating (the #477 failure mode)"
        )

    def test_restart_always_still_present(self):
        """Paired check: the ticket's crash-loop context stays intact — we
        bounded the stop, we did not remove Restart=always."""
        assert "Restart=always" in UNIT_FILE.read_text(encoding="utf-8")


def test_stop_signature_default_is_the_module_bound():
    import inspect

    sig = inspect.signature(RelayListener.stop)
    assert sig.parameters["deadline_seconds"].default == RELAY_STOP_DEADLINE_SECONDS
