# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-3 — threaded relay listener with semaphore admission.

The listener is a ``ThreadingHTTPServer`` whose handler takes a
``threading.Semaphore(cap)`` permit around the execution section, cap coming
from the one knob pinned by the owner's RF-2 ruling (env
``VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS`` / TOML
``[executor] max_concurrent_commands``, default 1).

WHAT THE DEFAULT-1 GUARANTEE ACTUALLY IS (the honest claim, per RF-2):
  * the ADMISSION OUTCOME at cap=1 matches the old single-threaded listener —
    one command runs at a time, a second arrival never reaches the engine while
    the first holds the permit (``test_default_cap_serializes_commands``);
  * the HANDSHAKE TIMING does NOT match — the queued peer now completes its mTLS
    handshake and holds a thread plus an fd while it waits, where the
    single-threaded listener left it refused in the kernel accept backlog
    (``test_queued_peer_handshakes_before_admission``).
    This suite deliberately does NOT claim byte-identity: the carrier's original
    wording asked for a property the design does not have.

Nothing here runs a sandbox, a VM, or ``sbx`` — the engine is the injected stub
at the ``executor_factory`` seam, exactly as in tests/test_relay_listener.py.
The two bench cells that gate raising the default above 1 (cross-command leak,
pool-before-listener) are DO-NOT-RUN from this seat: they need the fleet VM and
are designed in the RF-3 carrier, not implemented here.
"""

import json
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

from executor.config import ExecutorConfig, MtlsConfig
from executor.relay_listener import RelayListener

# House pattern (see test_relay_stop_477): import the real-PKI builders from the
# relay suite as plain helpers and build fixtures locally under distinct names.
from tests.test_relay_listener import (
    ALLOWED,
    SERVER_CN,
    _ca,
    _client,
    _leaf,
    _ok_result,
    _start,
    _url,
    _write_cert_only,
    _write_dir,
)


class _ConcExec:
    """Engine stub that records how many ``execute()`` calls overlap.

    ``hold`` unset -> returns immediately. Set -> every call blocks on it, which
    is how a cell proves that a second arrival is queued at the admission point
    rather than running (or erroring) instead.
    """

    def __init__(self, hold: threading.Event | None = None) -> None:
        self.hold = hold
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.finished = 0
        self.commands: list[list[str]] = []
        self.first_entered = threading.Event()

    def execute(self, command, secrets, env_vars=None, askpass_helper=False):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.commands.append(list(command))
        self.first_entered.set()
        try:
            if self.hold is not None:
                assert self.hold.wait(timeout=20), "the test must open the gate"
            return _ok_result(stdout=b"done")
        finally:
            with self.lock:
                self.active -= 1
                self.finished += 1

    def waited_for(self, n: int, timeout: float = 5.0) -> bool:
        """True once exactly `n` calls are inside execute() at the same time."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.active >= n:
                    return True
            time.sleep(0.02)
        return False

    @property
    def call_count(self) -> int:
        with self.lock:
            return len(self.commands)


def _pk(tmp_path, cap: int | None = None) -> SimpleNamespace:
    """One CA, a server leaf, an allowed client leaf, and an ExecutorConfig.

    The CA keypair is carried on the namespace so a cell can mint ANOTHER
    client on the same CA (a valid-CA, unlisted-CN peer) — the existing suite
    builds that shape in its own fixture.
    """
    a_key, a_cert = _ca()
    srv_cert, srv_key = _leaf(a_key, a_cert, SERVER_CN, server_auth=True)
    c_ok_cert, c_ok_key = _leaf(a_key, a_cert, ALLOWED)
    ca_crt = _write_cert_only(a_cert, tmp_path, "ca")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    c_ok = _write_dir(c_ok_cert, c_ok_key, tmp_path, "c-ok")
    kwargs: dict = {"server_url": "https://core.test", "executor_id": "rf3-test", "relay_client_ids": [ALLOWED]}
    if cap is not None:
        kwargs["executor"] = {"max_concurrent_commands": cap}
    config = ExecutorConfig(mtls=MtlsConfig(ca_cert=ca_crt, cert=srv[0], key=srv[1]), **kwargs)
    return SimpleNamespace(ca=ca_crt, ca_key=a_key, ca_cert=a_cert, srv=srv, c_ok=c_ok, config=config, tmp=tmp_path)


def _banned_client(pk: SimpleNamespace, base: str) -> tuple[str, str]:
    """A client cert on the SAME CA whose CN is NOT in relay_client_ids."""
    cert, key = _leaf(pk.ca_key, pk.ca_cert, "disallowed-exec")
    return _write_dir(cert, key, pk.tmp, base)


def _post_bytes(payload: dict) -> bytes:
    body = json.dumps(payload).encode()
    return f"POST /execute HTTP/1.0\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


def _handshake_then_send(listener: RelayListener, pk: SimpleNamespace, payload: dict) -> tuple:
    """Raw mTLS client: connect, HANDSHAKE, send the request, do not read yet.

    Returns (tls_socket, handshake_done_seconds, sent_at). The point of the raw
    socket is that it separates the handshake from the response: a threaded
    listener must finish the handshake for a peer that has no permit yet.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(pk.ca)
    ctx.load_cert_chain(*pk.c_ok)
    started = time.monotonic()
    sock = socket.create_connection(("127.0.0.1", listener.port), timeout=10.0)
    tls = ctx.wrap_socket(sock)
    tls.settimeout(10.0)
    handshake_done = time.monotonic() - started
    tls.sendall(_post_bytes(payload))
    return tls, handshake_done, time.monotonic() - started


def _read_status(tls: ssl.SSLSocket) -> tuple[int, bytes]:
    resp = b""
    while True:
        part = tls.recv(65536)
        if not part:
            break
        resp += part
    status = int(resp.split(b" ", 2)[1]) if resp.startswith(b"HTTP/") else -1
    return status, resp


def _fire(listener: RelayListener, pk: SimpleNamespace, payload: dict, out: list) -> threading.Thread:
    def _go() -> None:
        with _client(pk.ca, pk.c_ok) as client:
            try:
                out.append(client.post(_url(listener), json=payload))
            except Exception as exc:  # a racing teardown is a legitimate outcome
                out.append(exc)

    t = threading.Thread(target=_go, daemon=True)
    t.start()
    return t


def _payload(session: str, marker: str) -> dict:
    return {"session_id": session, "command": ["echo", marker], "secrets": []}


class TestCapOneRegressionPin:
    """The load-bearing cell set: what default 1 does and does not preserve."""

    def test_default_cap_serializes_commands(self, tmp_path):
        """Knob UNSET -> three concurrent arrivals still run one at a time.

        Same admission outcome as the old single-threaded listener: the second
        and third never enter the engine while the first holds the permit.
        """
        pk = _pk(tmp_path)
        assert pk.config.executor.max_concurrent_commands == 1, "default must be one"
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            threads = [_fire(listener, pk, _payload(f"s{i}", f"m{i}"), out) for i in range(3)]
            assert fake.first_entered.wait(timeout=5), "first request reached the engine"
            # A settle window: with admission in the handler the other two are
            # BLOCKED, not queued in the kernel — so the engine must still see
            # exactly one call after the peer threads have all handshaken.
            time.sleep(0.5)
            assert fake.call_count == 1, f"cap=1 let {fake.call_count} commands into the engine at once"
            hold.set()
            for t in threads:
                t.join(timeout=20)
            assert fake.max_active == 1, f"commands overlapped: peak {fake.max_active}"
            assert fake.call_count == 3
            codes = [getattr(r, "status_code", r) for r in out]
            assert codes == [200, 200, 200], codes
        finally:
            hold.set()
            listener.stop()

    def test_queued_peer_handshakes_before_admission(self, tmp_path):
        """The honest half of the cap=1 pin: the TIMING differs.

        A peer that cannot be admitted still completes the mTLS handshake and
        then waits for its response, instead of sitting refused in the accept
        backlog as the single-threaded listener left it. Pinned as behaviour,
        because a reader of this suite must not assume the old timing survived.
        """
        pk = _pk(tmp_path)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        tls = None
        try:
            out: list = []
            busy = _fire(listener, pk, _payload("s-busy", "busy"), out)
            assert fake.first_entered.wait(timeout=5), "the in-flight command holds the permit"

            tls, handshake_done, sent_at = _handshake_then_send(listener, pk, _payload("s-queued", "queued"))
            # (a) the handshake COMPLETED for a peer with no permit...
            assert handshake_done < 5.0, f"handshake never completed while the slot was busy: {handshake_done:.1f}s"
            # (b) ...and admission still held: the engine never saw the queued one.
            time.sleep(0.3)
            assert fake.call_count == 1, "the queued peer was admitted while the first command ran"
            # (c) the wait is a WAIT, not a synthesized error: nothing came back yet.
            tls.settimeout(0.5)
            with pytest.raises(TimeoutError):
                tls.recv(1)
            assert fake.max_active == 1

            # (d) opening the slot lets the queued peer run and answer 200.
            hold.set()
            tls.settimeout(20.0)
            status, _resp = _read_status(tls)
            busy.join(timeout=20)
            assert status == 200, f"queued peer got {status} — RF-2 rules it waits, never 503"
            assert sent_at < 5.0
            assert sorted(fake.commands) == [["echo", "busy"], ["echo", "queued"]]
        finally:
            hold.set()
            if tls is not None:
                tls.close()
            listener.stop()

    def test_over_cap_request_carries_no_retry_after(self, tmp_path):
        """RF-2 sub-decision: over-cap is a queue, not 503 + Retry-After."""
        pk = _pk(tmp_path)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            first = _fire(listener, pk, _payload("s1", "one"), out)
            assert fake.first_entered.wait(timeout=5)
            second = _fire(listener, pk, _payload("s2", "two"), out)
            time.sleep(0.3)
            assert fake.call_count == 1
            hold.set()
            first.join(timeout=20)
            second.join(timeout=20)
            responses = [r for r in out if getattr(r, "status_code", None) is not None]
            assert len(responses) == 2, out
            for resp in responses:
                assert resp.status_code == 200, resp.status_code
                assert "retry-after" not in {k.lower() for k in resp.headers}, "RF-2 forbids Retry-After here"
        finally:
            hold.set()
            listener.stop()


class TestSemaphoreAdmission:
    """cap > 1 admits cap and blocks cap+1 until a slot frees."""

    def test_cap_two_runs_two_and_waits_for_the_third(self, tmp_path):
        pk = _pk(tmp_path, cap=2)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            threads = [_fire(listener, pk, _payload(f"s{i}", f"m{i}"), out) for i in range(3)]
            assert fake.waited_for(2), "cap=2 did not run two commands at once"
            time.sleep(0.4)
            assert fake.call_count == 2, f"the third arrived before a slot freed: {fake.call_count}"
            assert fake.max_active == 2
            hold.set()
            for t in threads:
                t.join(timeout=20)
            assert fake.call_count == 3
            assert fake.max_active == 2, f"three ran at once on a cap of 2: {fake.max_active}"
            assert all(getattr(r, "status_code", None) == 200 for r in out), out
        finally:
            hold.set()
            listener.stop()

    def test_env_spelling_sizes_admission(self, tmp_path, monkeypatch):
        """The knob is CONSUMED, not dead config: the pinned env spelling sets
        how many commands the handler admits at once."""
        monkeypatch.setenv("VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS", "2")
        pk = _pk(tmp_path)  # built from the environment, no explicit cap
        assert pk.config.executor.max_concurrent_commands == 2
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            threads = []
            out: list = []
            for i in range(2):
                threads.append(_fire(listener, pk, _payload(f"s{i}", f"m{i}"), out))
            assert fake.waited_for(2), "env cap of 2 did not admit two"
            hold.set()
            for t in threads:
                t.join(timeout=20)
        finally:
            hold.set()
            listener.stop()

    def test_toml_spelling_sizes_admission(self, tmp_path):
        """Same claim through the pinned TOML spelling, in a real config file:
        the [executor] section the owner pinned, next to the root keys and the
        [mtls] table the file actually carries."""
        pk = _pk(tmp_path)
        toml_path = tmp_path / "executor-config.toml"
        toml_path.write_text(
            "\n".join(
                [
                    'server_url = "https://core.test"',
                    'executor_id = "rf3-toml-test"',
                    f'relay_client_ids = ["{ALLOWED}"]',
                    "",
                    "[mtls]",
                    f'ca_cert = "{pk.ca}"',
                    f'cert = "{pk.srv[0]}"',
                    f'key = "{pk.srv[1]}"',
                    "",
                    "[executor]",
                    "max_concurrent_commands = 2",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        config = ExecutorConfig.from_file(toml_path)
        assert config.executor.max_concurrent_commands == 2
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(config, lambda _sid: fake, [ALLOWED])
        try:
            threads = []
            out: list = []
            for i in range(2):
                threads.append(_fire(listener, pk, _payload(f"s{i}", f"m{i}"), out))
            assert fake.waited_for(2), "TOML cap of 2 did not admit two"
            hold.set()
            for t in threads:
                t.join(timeout=20)
            assert all(getattr(r, "status_code", None) == 200 for r in out), out
        finally:
            hold.set()
            listener.stop()

    def test_a_failing_command_returns_its_permit(self, tmp_path):
        """Paired negative: permit release cannot leak on the 503 lane — a
        raising engine must not wedge the listener shut at cap=1."""
        pk = _pk(tmp_path)
        state = {"n": 0}
        lock = threading.Lock()

        def _factory(_sid: str):
            class _Boom:
                def execute(self, command, secrets, env_vars=None, askpass_helper=False):
                    with lock:
                        state["n"] += 1
                        first = state["n"] == 1
                    if first:
                        raise TimeoutError("subprocess timed out")
                    return _ok_result()

            return _Boom()

        listener = _start(pk.config, _factory, [ALLOWED])
        try:
            with _client(pk.ca, pk.c_ok) as client:
                bad = client.post(_url(listener), json=_payload("s1", "boom"))
                assert bad.status_code == 503
                good = client.post(_url(listener), json=_payload("s2", "after"))
            assert good.status_code == 200, "the permit was never returned after a failure"
        finally:
            listener.stop()

    def test_config_without_the_knob_falls_back_to_one(self):
        """Fail-closed cap read: a config object that does not carry the field
        must NOT widen concurrency by accident."""
        bare = SimpleNamespace(mtls=SimpleNamespace(cert="c", key="k", ca_cert="ca"))
        listener = RelayListener(bare, lambda _sid: None, [ALLOWED])
        assert listener._read_cap() == 1

    def test_unparseable_cap_falls_back_to_one(self):
        junk = SimpleNamespace(executor=SimpleNamespace(max_concurrent_commands="not-a-number"))
        assert RelayListener(junk, lambda _sid: None, [ALLOWED])._read_cap() == 1
        zero = SimpleNamespace(executor=SimpleNamespace(max_concurrent_commands=0))
        assert RelayListener(zero, lambda _sid: None, [ALLOWED])._read_cap() == 1


class TestAdmissionAndDrainOrder:
    """The order RF-3 forces: a peer queued BEFORE the drain may not execute
    AFTER it — #477 acceptance 1 now has two gates, not one."""

    def test_queued_peer_is_refused_at_admission_once_draining_begins(self, tmp_path):
        pk = _pk(tmp_path)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            busy = _fire(listener, pk, _payload("s-busy", "busy"), out)
            assert fake.first_entered.wait(timeout=5)
            queued = _fire(listener, pk, _payload("s-queued", "queued"), out)
            time.sleep(0.3)
            assert fake.call_count == 1, "the queued request had not reached the admission point yet"

            # The drain begins while that peer sits blocked on the permit.
            listener._draining.set()
            hold.set()
            busy.join(timeout=20)
            queued.join(timeout=20)

            by_session = {getattr(r, "status_code", None): r for r in out}
            assert 200 in by_session, f"the in-flight command did not complete: {out}"
            assert 503 in by_session, f"the queued peer was admitted after the drain began: {out}"
            assert fake.call_count == 1, f"the engine saw a command that began during the drain: {fake.commands}"
            assert fake.commands == [["echo", "busy"]]
        finally:
            hold.set()
            listener.stop()

    def test_identity_gate_still_precedes_admission(self, tmp_path):
        """Paired negative: threading must not let an unlisted CN reach the
        queue — the 403 lane sits before the permit, unchanged."""
        pk = _pk(tmp_path)
        ban = _banned_client(pk, "c-ban")
        listener = _start(pk.config, lambda _sid: _ConcExec(), [ALLOWED])
        try:
            with _client(pk.ca, ban) as client:
                resp = client.post(_url(listener), json=_payload("s", "x"))
            assert resp.status_code == 403
        finally:
            listener.stop()


class TestBoundedStopUnderConcurrency:
    """#477's bound survives the threading conversion: shutdown() no longer
    implies the engine is done, so stop() waits on the permits."""

    def test_stop_waits_for_every_in_flight_command(self, tmp_path):
        pk = _pk(tmp_path, cap=2)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            threads = [_fire(listener, pk, _payload(f"s{i}", f"m{i}"), out) for i in range(2)]
            assert fake.waited_for(2), "two commands were expected in flight"

            threading.Timer(0.4, hold.set).start()
            started_at = time.monotonic()
            listener.stop(deadline_seconds=10.0)
            elapsed = time.monotonic() - started_at

            assert elapsed < 10.0, f"stop exceeded its bound: {elapsed:.1f}s"
            assert fake.finished == 2, "stop returned while a command was still in flight"
            for t in threads:
                t.join(timeout=10)
        finally:
            hold.set()
            listener.stop()

    def test_stop_returns_at_the_deadline_and_says_so(self, tmp_path, caplog):
        import logging

        pk = _pk(tmp_path)
        hold = threading.Event()
        fake = _ConcExec(hold=hold)
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            out: list = []
            busy = _fire(listener, pk, _payload("s1", "busy"), out)
            assert fake.first_entered.wait(timeout=5)
            with caplog.at_level(logging.ERROR, logger="venya.executor.relay"):
                started_at = time.monotonic()
                listener.stop(deadline_seconds=0.5)
                elapsed = time.monotonic() - started_at
            assert elapsed < 3.0, f"stop was NOT bounded: {elapsed:.1f}s"
            assert fake.finished == 0, "the held command must still be running"
            assert any("deadline" in r.getMessage() for r in caplog.records), "overflow must name itself"
        finally:
            hold.set()
            busy.join(timeout=10)
            listener.stop()

    def test_normal_stop_is_prompt_and_idempotent(self, tmp_path):
        pk = _pk(tmp_path)
        listener = _start(pk.config, lambda _sid: _ConcExec(), [ALLOWED])
        started_at = time.monotonic()
        listener.stop()
        assert time.monotonic() - started_at < 5.0
        listener.stop()  # no-op, must not raise on the cleared server/slots

    def test_handler_admission_default_is_the_serialized_shape(self):
        """Static guard: the handler consults a server attribute named
        ``command_slots`` and start() is what wires it. If either side is
        renamed, the semaphore stops gating and the cells above would fail
        silently against a listener that admits nothing — this one fails first."""
        import inspect

        from executor import relay_listener

        src = inspect.getsource(relay_listener)
        assert "server.command_slots" in src, "start() no longer wires the admission permits"
        assert 'getattr(self.server, "command_slots", None)' in src, "the handler no longer consults the permits"
        assert "ThreadingHTTPServer(" in src, "the listener is not threaded"
        assert "threading.Semaphore(" in src, "admission is not a semaphore"
        assert "HTTPServer(" not in src.replace("ThreadingHTTPServer(", ""), "a plain HTTPServer bind came back"
