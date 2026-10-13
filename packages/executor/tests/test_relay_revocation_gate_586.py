# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#586 — the revocation accept gate at the executor's :8443 relay listener.

The carrier's claim: the product mints a CRL, publishes a CRL, and consulted
nothing at the transport. The owner's ruled resolution (option 3) is a
PYTHON-SIDE, POST-HANDSHAKE gate on the listener, consulting the single
revocation state — not nginx, not a handshake CRL (that is option 5, unruled).

What these cells pin, in the order that matters:

1. THE GATE IS A CACHE, NOT A SECOND RULEBOOK. The listener reads the ONE
   already-computed answer on this side (``DaemonState.revoked``) plus a
   boot-scope "the core answered" flag. It holds no copy of the revoked-serial
   list and does no serial or identity matching of its own — the contract
   comment in ``server/revocation.py`` names a second implementation as the
   rotation/revocation split-brain, and at :8443 the peer is the CORE's
   relay-client credential, which the executor-serial list never describes.
2. PAIRED NEGATIVES (#586 acceptance 1 + 2 + 6). Revoked refuses; unanswered
   refuses; no state wired refuses. And the half that decides whether the fix
   is real: a live, answered credential still reaches ``/execute`` exactly as
   before, with the TLS floor and the CN allowlist untouched.
3. THE REFUSAL IS THE LISTENER'S OWN (#586 acceptance 3). The gate fires while
   the daemon loop is still running — the cell asserts refusal with no
   ``stop()``, no drain, and the engine factory never invoked.
4. THE WINDOW IS HONEST (#586 criterion 4 / DoD point 4). The handshake
   completes first; the refusal closes the connection BEFORE any request byte
   is read, so the peer gets no HTTP response. The two refusal classes carry
   the owner's ruled status vocabulary (403 revoked vs 503 operational fault)
   in the journal string, and a third class is distinguishable from a revocation.
5. PER CONNECTION, NOT PER BOOT. The gate is re-consulted on every accept, so a
   revocation that lands mid-life refuses the NEXT connection without a restart
   (and the #579 context swap is not disturbed by this leg).
"""

import logging
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.relay_listener import (
    REFUSE_NO_ANSWER,
    REFUSE_NOT_WIRED,
    REFUSE_REVOKED,
    RelayListener,
    revocation_accept_reason,
)

# Reuse the real-PKI builders of the relay suite (house pattern: import plain
# helpers, define fixtures locally — tests.test_relay_rotation_579.py does the same).
from tests.test_relay_listener import (
    ALLOWED,
    SERVER_CN,
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

RELAY_LOGGER = "venya.executor.relay"


def _state(*, revoked: bool = False, answered: bool = False) -> SimpleNamespace:
    """A stand-in for ``DaemonState`` carrying exactly the two fields the gate reads."""
    return SimpleNamespace(revoked=revoked, revocation_answered=answered, executor_id="gate-test")


def _payload(session_id: str = "s1") -> dict:
    return {"session_id": session_id, "command": ["echo", "hi"], "secrets": []}


# --- 1. the verdict function itself (no sockets, no PKI) ---


class TestAcceptReasonIsACacheOfTheOneAnswer:
    """The gate's decision table. Each row is a class, and each class is distinct."""

    def test_live_and_answered_admits(self):
        assert revocation_accept_reason(_state(revoked=False, answered=True)) is None

    def test_revoked_refuses_with_the_403_class(self):
        reason = revocation_accept_reason(_state(revoked=True, answered=True))
        assert reason is REFUSE_REVOKED
        assert reason.startswith("403")

    def test_no_answer_this_boot_refuses_with_the_503_class(self):
        reason = revocation_accept_reason(_state(revoked=False, answered=False))
        assert reason is REFUSE_NO_ANSWER
        assert reason.startswith("503")

    def test_unwired_state_refuses_and_is_not_the_revoked_class(self):
        """A listener built with nothing to consult must not read as "revoked" —
        the 3 a.m. distinction the owner's split exists to preserve."""
        reason = revocation_accept_reason(None)
        assert reason is REFUSE_NOT_WIRED
        assert reason is not REFUSE_REVOKED

    def test_revoked_outranks_the_bootstrap_arm(self):
        """Ruled order on this side: a known revocation is named as a revocation,
        never as an operational fault, even if both flags are odd."""
        assert revocation_accept_reason(_state(revoked=True, answered=False)) is REFUSE_REVOKED


# --- fixtures: a real PKI listener, driven over real mTLS ---


@pytest.fixture()
def gate_pk(tmp_path) -> SimpleNamespace:
    ca_key, ca_cert = _ca()
    srv_cert, srv_key = _leaf(ca_key, ca_cert, SERVER_CN, server_auth=True)
    c_cert, c_key = _leaf(ca_key, ca_cert, ALLOWED)
    ca_crt = _write_cert_only(ca_cert, tmp_path, "ca")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    client = _write_dir(c_cert, c_key, tmp_path, "c-ok")

    from executor.config import ExecutorConfig, MtlsConfig

    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="gate-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(ca=ca_crt, srv=srv, client=client, config=config)


def _start_with(gate_pk, state, factory=None):
    fake = _FakeExec(result=_ok_result())
    sessions: list = []
    listener = _start(gate_pk.config, factory or _factory(fake, sessions), [ALLOWED], state=state)
    return listener, fake, sessions


class TestTheAnswerFlagHasOneWriter:
    """The cache discipline, pinned on the daemon side.

    `revocation_answered` is written at exactly ONE place — the poll dispatch in
    ``ExecutorDaemon._main_loop`` — and the gate only ever READS it. If a second
    writer appeared (a heartbeat, a local file, a second poll), the accept gate would
    be consulting a state that two places can disagree about: the split-brain
    ``server/revocation.py`` names in its contract comment.
    """

    @pytest.fixture()
    def daemon_config(self):
        from executor.config import ExecutorConfig

        return ExecutorConfig(server_url="https://core.test", executor_id="loop-test")

    def _drive_one_tick(self, daemon, answer):
        """Run ``_main_loop`` through exactly ONE tick, then stop the loop.

        The stop rides ``_send_heartbeat`` (the last call in the iteration): the
        loop's own ``wait`` is patched out, so without this the tick repeats forever.
        """

        def _stop_after_tick():
            daemon.state.running = False

        with (
            patch.object(daemon.cert_manager, "needs_rotation", return_value=False),
            patch.object(daemon.cert_manager, "check_revocation", return_value=answer),
            patch.object(daemon, "_send_heartbeat", side_effect=_stop_after_tick),
            patch.object(daemon._shutdown_event, "wait", return_value=False),
        ):
            daemon.state.running = True
            daemon._main_loop()

    def test_a_live_answer_opens_the_gate(self, daemon_config):
        from executor.daemon import ExecutorDaemon, RevocationStatus

        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock()
        self._drive_one_tick(daemon, RevocationStatus.NOT_REVOKED)
        assert daemon.state.revocation_answered is True
        assert revocation_accept_reason(daemon.state) is None

    def test_an_unreachable_poll_never_opens_the_gate(self, daemon_config):
        """#442 site 4's rule, carried to the listener: absence of an answer is NOT
        an assertion of liveness, so it must not read as "admit"."""
        from executor.daemon import ExecutorDaemon, RevocationStatus

        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock()
        self._drive_one_tick(daemon, RevocationStatus.UNREACHABLE)
        assert daemon.state.revocation_answered is False
        assert revocation_accept_reason(daemon.state) is REFUSE_NO_ANSWER

    def test_the_listener_holds_the_daemons_own_state_object(self, daemon_config):
        """The wiring pin: the gate reads the SAME object the main loop writes. A
        copy made at construction time would freeze the verdict at boot — the exact
        boot-scoped bug #579 fixed for the TLS context."""
        from executor.daemon import ExecutorDaemon

        daemon = ExecutorDaemon(daemon_config)
        assert daemon.relay.revocation_state is daemon.state

    def test_the_threshold_revocation_reaches_the_gate(self, daemon_config):
        """The bounded fail-closed the poll threshold already implements must reach
        :8443 without a restart: after ``max_revocation_failures`` unanswered ticks
        the state reads revoked, and the gate refuses."""
        from executor.daemon import ExecutorDaemon, RevocationStatus

        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock()
        daemon.state.running = True
        daemon.state._consecutive_revocation_failures = daemon.config.cert_rotation.max_revocation_failures - 1
        self._drive_one_tick(daemon, RevocationStatus.UNREACHABLE)
        assert daemon.state.revoked is True
        assert revocation_accept_reason(daemon.state) is REFUSE_REVOKED


class TestGateAtTheListener:
    """The physical-ish half: real TLS handshake, real accept loop, real refusal."""

    def test_live_answered_credential_still_reaches_execute(self, gate_pk):
        """#586 acceptance 2 — the paired positive. A change that refuses everything
        satisfies criterion 1 and fails HERE, and this is the half that decides
        whether the fix is real."""
        listener, _fake, sessions = _start_with(gate_pk, _state(answered=True))
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                resp = client.post(_url(listener), json=_payload())
            assert resp.status_code == 200, resp.text
            assert resp.json()["exit_code"] == 0
            assert sessions == ["s1"], "the engine was not reached"
        finally:
            listener.stop()

    def test_revoked_daemon_refuses_at_accept_without_reaching_the_engine(self, gate_pk, caplog):
        """#586 acceptance 1 + 3: the LISTENER refuses. The loop is untouched — no
        stop(), no drain — and the engine factory is never called."""
        sessions: list = []
        state = _state(revoked=True, answered=True)

        def _never_called(_sid):  # pragma: no cover - must not run
            raise AssertionError("the gate let a revoked credential through to the engine")

        listener = _start(gate_pk.config, _never_called, [ALLOWED], state=state)
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
            assert sessions == []
        finally:
            listener.stop()
        lines = _relay_lines(caplog)
        assert "403 REVOKED" in lines, lines
        assert "503" not in lines, lines

    def test_bootstrap_refusal_is_named_apart_from_revocation(self, gate_pk, caplog):
        """DoD point 3: a reader must be able to tell 'revoked' from 'broken'.

        Same listener, same peer, same closed connection — the journal line is the
        only thing that differs, so the two classes must not share a string.
        """
        listener, _fake, _sessions = _start_with(gate_pk, _state(revoked=False, answered=False))
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        lines = _relay_lines(caplog)
        assert "503 OPERATIONAL FAULT" in lines, lines
        assert "403 REVOKED" not in lines, lines

    def test_unwired_state_refuses_every_connection(self, gate_pk):
        """Fail-closed by construction: forgetting to wire the state must never be a
        way to serve. The listener binds (so the boot is observable), and every
        dial is refused."""
        bare = RelayListener(gate_pk.config, lambda _sid: None, [ALLOWED], host="127.0.0.1", port=0)
        bare.start()
        try:
            assert bare.active is True, "an unwired listener must still bind, so the refusal is observable"
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(bare), json=_payload())
        finally:
            bare.stop()

    def test_refusal_happens_after_handshake_and_before_any_request_byte(self, gate_pk):
        """The named window of option 3, asserted rather than claimed.

        The peer completes the TLS handshake (chain validation and CERT_REQUIRED are
        untouched — no security is disabled to make this cell pass) and then gets a
        closed connection with NO HTTP response at all."""
        listener, _fake, _sessions = _start_with(gate_pk, _state(revoked=True, answered=True))
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError) as excinfo:
                    client.post(_url(listener), json=_payload())
            # A refusal that reached HTTP would carry a response; this one must not.
            assert getattr(excinfo.value, "response", None) is None, "the gate answered HTTP instead of refusing"
        finally:
            listener.stop()

    def test_the_gate_is_per_connection_not_per_boot(self, gate_pk):
        """A revocation that lands mid-life refuses the NEXT connection with no
        restart — and the reverse (bootstrap → answered) admits again."""
        state = _state(revoked=False, answered=False)
        listener, _fake, sessions = _start_with(gate_pk, state)
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
                # The core answers: same listener object, same accepted port.
                state.revocation_answered = True
                resp = client.post(_url(listener), json=_payload())
                assert resp.status_code == 200, resp.text
                # And a revocation mid-life closes it again, no restart involved.
                state.revoked = True
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json={"session_id": "s2", "command": ["echo"], "secrets": []})
        finally:
            listener.stop()
        assert sessions == ["s1"]

    def test_in_flight_connection_is_not_cut_off_by_a_refusal(self, gate_pk):
        """#586 / DoD acceptance: refusal at accept never drops a connection that was
        already admitted — the admit decision is made per accept, and the handler
        thread that passed the gate runs to its response."""
        state = _state(revoked=False, answered=True)
        listener, _fake, _sessions = _start_with(gate_pk, state)
        results: dict = {}

        def _dial(tag: str) -> None:
            with _client(gate_pk.ca, gate_pk.client) as client:
                try:
                    resp = client.post(_url(listener), json=_payload(tag))
                    results[tag] = resp.status_code
                except httpx2.RequestError as exc:
                    results[tag] = f"error:{type(exc).__name__}"

        first = threading.Thread(target=_dial, args=("s1",))
        first.start()
        first.join(timeout=15)
        # Admitted, then revoked: the NEXT dial is refused, the completed one is not.
        state.revoked = True
        second = threading.Thread(target=_dial, args=("s2",))
        second.start()
        second.join(timeout=15)
        listener.stop()
        assert results.get("s1") == 200, results
        assert str(results.get("s2", "")).startswith("error:"), results


class TestRefusalIsRecorded:
    """DoD: a silent refusal is invisible to the customer whose premise is the trail."""

    def test_refusal_emits_a_relay_refused_event_when_a_sink_is_wired(self, gate_pk):
        events: list = []

        class _Sink:
            def emit(self, event_type, **fields):
                events.append((event_type, fields))

        listener = RelayListener(
            gate_pk.config,
            lambda _sid: None,
            [ALLOWED],
            host="127.0.0.1",
            port=0,
            state=_state(revoked=True, answered=True),
        )
        listener.refusal_sink = _Sink()
        listener.start()
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()

        assert events, "the refusal left no audit record"
        event_type, fields = events[0]
        assert event_type == "relay_refused"
        assert fields["reason"] == REFUSE_REVOKED
        assert fields["executor_id"] == "gate-test"
        # Value-free: no command text, no secret material, ever.
        assert set(fields) == {"reason", "peer_host", "peer_port", "executor_id"}

    def test_a_sink_that_raises_never_wedges_the_accept_loop(self, gate_pk):
        """The audit path is best-effort: a raising sink must not turn a refusal into
        an accept-loop crash, and the next connection must still be served/refused
        on its own merits."""

        class _Boom:
            def emit(self, *args, **kwargs):
                raise RuntimeError("spool down")

        state = _state(revoked=True, answered=True)
        listener = RelayListener(
            gate_pk.config,
            lambda _sid: _FakeExec(result=_ok_result()),
            [ALLOWED],
            host="127.0.0.1",
            port=0,
            state=state,
        )
        listener.refusal_sink = _Boom()
        listener.start()
        try:
            with _client(gate_pk.ca, gate_pk.client) as client:
                for _ in range(3):
                    with pytest.raises(httpx2.RequestError):
                        client.post(_url(listener), json=_payload())
            # The loop survived: flip the answer and the same listener admits.
            state.revoked = False
            resp_ok = None
            with _client(gate_pk.ca, gate_pk.client) as client:
                resp_ok = client.post(_url(listener), json=_payload("s9"))
            assert resp_ok.status_code == 200, resp_ok.text
        finally:
            listener.stop()


def _relay_lines(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if r.name == RELAY_LOGGER)
