# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#586 Gap A — the SECOND peer consult at the executor's :8443 door.

MECHANISM (named on the row before this code was written, per AC4):
``wave31-specs-20261018/wren-586-mechanism-ruling-s137.md`` — option (b), per-connection serial
verification against revocation state CARRIED TO the executor, extended from the relay population
(#597) to the EXECUTOR-serial population the poll already receives in ``revoked_serials``. It is
NOT a CRL fetch, NOT a ``VERIFY_CRL_*`` flag, and NOT a handshake-layer knob; the ruling rejects
those on three measured grounds, the first being that a default install advertises no CDP at all.

WHY THIS ARM IS NOT A DUPLICATE OF WHAT ALREADY EXISTS. Three things consult revocation today and
none of them is this door: the SELF gate (``revocation_accept_reason`` — this executor's own
credential, from the daemon's poll), the #597 relay arm (the CORE's relay-client credential, from
the registry), and the core's own dial gate (``executors.py``, refused by the core). An EXECUTOR
credential presenting as a CLIENT at another executor's :8443 was named by none of them, because
executor leaves are dual-purpose (SERVER_AUTH and CLIENT_AUTH, ``server/ca.py:52``) and this door
asked nothing of the peer but chain and CN. Chain and CN are an IDENTITY test, not a revocation
test — AC3's whole objection.

What these cells pin, in the order that matters:

1. THE CARRY, MIRRORED. ``revoked_executor_serials`` is written on DaemonState at the SAME branch
   that sets ``revocation_answered`` (one writer, same tick, same answered body), from an attribute
   written only after ``parse_revocation_payload`` accepted the body. So the door can never consult
   an executor population the core has not answered with, and an outage cannot clear it.
2. AC1, ASSERTED FROM THE EXECUTOR SIDE (AC3). A revoked peer serial dies at the accept point: the
   engine factory is never called, the handler never runs, and the refusal class the LISTENER
   recorded is ``REFUSE_PEER_EXECUTOR_REVOKED``. Nothing in this pair involves a core.
3. AC2 — THE HALF THAT DECIDES WHETHER THE FIX IS REAL. A current, non-revoked peer still reaches
   ``/execute``, gets its 200, and invokes the engine, with the TLS floor and the CN allowlist
   untouched. A change that refused everything would satisfy AC1 and fail this row.
4. THE FENCES, AS ABSENCES. No staleness/age arm in the new consult; the unreadable-serial ADMIT is
   unchanged and stays an admit; the relay arm still answers before the executor arm; the new class
   is a distinct string from both other revocation claims; and there is still no CRL machinery
   anywhere in the executor package.

#481 canonicalisation is exercised AT this door too (padded row vs unpadded certificate), which is
what AC7's "both CRL interlocks stay green" means for a change like this one.
"""

import logging
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.config import ExecutorConfig, MtlsConfig
from executor.relay_listener import (
    REFUSE_NO_ANSWER,
    REFUSE_PEER_EXECUTOR_REVOKED,
    REFUSE_PEER_REVOKED,
    REFUSE_REVOKED,
    RelayListener,
    peer_executor_revocation_refusal,
)

# House pattern: import the plain builders, keep fixtures local (test_relay_rotation_579.py and
# test_relay_revocation_gate_586.py both do this).
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

# A certificate SERIAL is a public identifier, and these are low-entropy and obviously fake on
# purpose — so they also do not trip detect-secrets, which is right to treat a long random hex
# string as secret-shaped.
REVOKED_PEER_SERIAL_INT = 0xABCD  # the executor-class leaf the refusing cells present
LIVE_PEER_SERIAL_INT = 0x9999  # the executor-class leaf the ADMITTING cell presents
REVOKED_PEER_SERIAL_CERT = "ABCD"  # the exact spelling ssl.getpeercert() yields (upper, unpadded)
REVOKED_PEER_SERIAL_ROW = "000000000000abcd"  # the exact spelling the list stores (#481 pair)


def _code_only(fn) -> str:
    """Source with the docstring removed — the absence cells need CODE, not prose.

    Copied from ``tests/test_relay_peer_revocation_597.py`` by intent, not by import: this
    sentence's own docstring names the tokens it forbids, so a scan over the whole source would
    fail on the text that states the fence.
    """
    import ast
    import inspect
    import textwrap

    src = inspect.getsource(fn)
    node = ast.parse(textwrap.dedent(src)).body[0]
    doc = ast.get_docstring(node, clean=False)
    return src.replace(doc, "") if doc else src


def _leaf_at_serial(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    serial_number: int,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """An EXECUTOR-class client leaf at a KNOWN serial: dual EKU, exactly as ``ca.py:52`` mints it.

    The known serial is the whole point — a refusal cell that cannot name the serial its own
    certificate carries is a cell that is refusing something else.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
            ),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _peer_state(*, executor=(), relay=(), revoked: bool = False, answered: bool = True) -> SimpleNamespace:
    """A DaemonState carrying exactly the fields the two peer arms and the self gate read."""
    return SimpleNamespace(
        revoked=revoked,
        revocation_answered=answered,
        revocation_fault_reason=None,
        revoked_relay_serials=frozenset(relay),
        revoked_executor_serials=frozenset(executor),
        executor_id="peer-executor-test",
    )


def _payload(session_id: str = "s1") -> dict:
    return {"session_id": session_id, "command": ["echo", "hi"], "secrets": []}


# ---------------------------------------------------------------------------
# A. THE CARRY — one writer, same branch as the answered flag, shape-guarded
# ---------------------------------------------------------------------------


class TestExecutorPopulationLands:
    """The mirror of #597's carry discipline, pointed at the executor population."""

    def test_a_fresh_manager_starts_with_an_empty_executor_set(self) -> None:
        from executor import daemon as dm
        from executor.config import ExecutorConfig as _EC

        cm = dm.CertificateManager(_EC())
        assert cm.last_executor_serials == frozenset(), "starts empty, which admits"

    def test_daemon_state_starts_with_an_empty_executor_set(self) -> None:
        from executor import daemon as dm

        st = dm.DaemonState()
        assert st.revoked_executor_serials == frozenset()
        assert (
            peer_executor_revocation_refusal(st, REVOKED_PEER_SERIAL_CERT) is None
        ), "an empty population must never be the reason a connection is refused"

    def test_the_carry_is_written_after_the_shape_guard_on_the_manager(self) -> None:
        """A malformed 200 cannot replace a good population with a partial one (#552 order)."""

        from executor import daemon as dm

        src = _code_only(dm.CertificateManager.check_revocation)
        guard = src.index("parse_revocation_payload(response)")
        at_write = src.index("self.last_executor_serials")
        assert at_write > guard, "the executor population must be written only AFTER the body passed the guard"

    def test_main_loop_carries_it_on_the_answered_branch_and_at_one_site(self) -> None:
        """THE load-bearing cell for AC6 at this door.

        The population is published on the SAME branch that sets ``revocation_answered``, so the
        question "may the door consult the executor list?" can never be answered yes while the
        answer to "has the core answered at all?" is no. And ONE writer, so a bad tick cannot
        empty a set the door had already refused from.
        """

        from executor import daemon as dm

        loop = _code_only(dm.ExecutorDaemon._main_loop)
        assert (
            "state.revoked_executor_serials = self.cert_manager.last_executor_serials" in loop
        ), "_main_loop never carries the executor population onto the state the listener reads"
        assert loop.count("revoked_executor_serials =") == 1, "more than one writer publishes the executor set"
        # same branch: the carry sits AFTER the answered flag is set, and BEFORE the branch ends
        answered = loop.index("self.state.revocation_answered = True")
        carry = loop.index("state.revoked_executor_serials =")
        assert carry > answered, "the carry must live on the answered branch, not beside it"
        # and the two carries are adjacent — one tick publishes BOTH populations or neither
        relay_carry = loop.index("state.revoked_relay_serials =")
        assert abs(carry - relay_carry) < 400, "the two peer populations drifted onto different branches"

    def test_the_poll_reads_the_population_from_the_same_answered_body(self) -> None:
        """The wire field is the one the SELF answer already uses — no second source, no
        second rulebook (``server/revocation.py:11-26`` names that as the split-brain)."""

        from executor import daemon as dm

        src = _code_only(dm.CertificateManager.check_revocation)
        assert src.count('data.get("revoked_serials"') >= 1
        assert 'last_executor_serials = frozenset(serial_match_key(s) for s in data.get("revoked_serials", []))' in src


# ---------------------------------------------------------------------------
# B. THE PURE FUNCTION — the decision table, including the admits
# ---------------------------------------------------------------------------


class TestExecutorPeerConsultIsAPureFunction:
    def test_revoked_executor_peer_serial_is_refused(self) -> None:
        st = _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,))
        assert peer_executor_revocation_refusal(st, REVOKED_PEER_SERIAL_CERT) == REFUSE_PEER_EXECUTOR_REVOKED

    @pytest.mark.parametrize("spelling", ["ABCD", "abcd", "000000000000abcd", "0xabcd", "  ABCD  "])
    def test_padded_and_unpadded_spellings_meet(self, spelling: str) -> None:
        """#481 AT this door: the row stores padded-lower, the cert presents upper-unpadded."""
        st = _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,))
        assert peer_executor_revocation_refusal(st, spelling) == REFUSE_PEER_EXECUTOR_REVOKED, spelling

    def test_a_live_serial_is_admitted(self) -> None:
        st = _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,))
        assert peer_executor_revocation_refusal(st, "9999") is None

    def test_an_adjacent_revoke_does_not_refuse_a_neighbour(self) -> None:
        st = _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,))
        assert peer_executor_revocation_refusal(st, "0000000000000001") is None

    def test_empty_population_admits_rather_than_refusing_the_unknown(self) -> None:
        assert peer_executor_revocation_refusal(_peer_state(), REVOKED_PEER_SERIAL_CERT) is None

    def test_no_state_admits(self) -> None:
        assert peer_executor_revocation_refusal(None, REVOKED_PEER_SERIAL_CERT) is None

    def test_unreadable_peer_serial_still_admits_ruling_says_not_widened(self) -> None:
        """The one true fail-open, kept as an admit ON PURPOSE.

        Converting it would refuse a healthy peer whose certificate this Python cannot parse —
        the lead's ruling says name it, price it, do not silently change it. This cell is the
        tripwire on that decision, not a claim that the admit is safe.
        """
        st = _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,))
        assert peer_executor_revocation_refusal(st, None) is None

    def test_state_without_the_new_field_admits(self) -> None:
        """A state built by an older fixture (or the shared ``_live_state``) must not be refused.

        ``getattr(state, ..., None)`` is the shape; a hard attribute read would AttributeError on
        every pre-#586 test double and turn a fixture gap into a fleet outage.
        """
        legacy = SimpleNamespace(revoked=False, revocation_answered=True, executor_id="legacy")
        assert peer_executor_revocation_refusal(legacy, REVOKED_PEER_SERIAL_CERT) is None

    def test_the_new_class_is_distinct_from_both_other_revocation_claims(self) -> None:
        """Three subjects, three sentences. Reusing a string would tell an operator to look at the
        wrong daemon — the peer that walked in, not this one, and not the core's relay pair."""
        assert REFUSE_PEER_EXECUTOR_REVOKED != REFUSE_PEER_REVOKED
        assert REFUSE_PEER_EXECUTOR_REVOKED != REFUSE_REVOKED
        assert REFUSE_PEER_EXECUTOR_REVOKED.startswith("403 REVOKED")
        assert "peer" in REFUSE_PEER_EXECUTOR_REVOKED and "executor" in REFUSE_PEER_EXECUTOR_REVOKED

    def test_no_age_or_staleness_term_exists_in_the_new_consult(self) -> None:
        """The ruled fence, asserted as an absence (same instrument as the #597 guard)."""
        src = _code_only(peer_executor_revocation_refusal)
        for banned in ("next_update", "age", "stale", "expired", "monotonic", "time()"):
            assert banned not in src, f"the executor consult grew a staleness arm ({banned!r})"
        assert "serial_match_key" in src, "the scan read no code at all — the absence assertion is vacuous"

    def test_the_new_consult_reads_the_serial_as_an_argument_and_nothing_else(self) -> None:
        src = _code_only(peer_executor_revocation_refusal)
        for not_allowed in ("request.headers", "getpeercert", ".common_name", "ssl_client", "hostname"):
            assert not_allowed not in src, f"the executor consult reaches for {not_allowed!r}"
        import inspect as _i

        assert list(_i.signature(peer_executor_revocation_refusal).parameters) == ["state", "peer_serial"]


# ---------------------------------------------------------------------------
# C. THE REAL DOOR — AC1 refusal and AC2 paired positive, from the EXECUTOR side
# ---------------------------------------------------------------------------


@pytest.fixture()
def peer_pk(tmp_path) -> SimpleNamespace:
    ca_key, ca_cert = _ca()
    srv_cert, srv_key = _leaf(ca_key, ca_cert, SERVER_CN, server_auth=True)
    # An EXECUTOR-class client leaf (dual EKU) at a serial we control, CN allowlisted on purpose:
    # the refusal below must therefore be about the SERIAL, never about the name.
    dead_cert, dead_key = _leaf_at_serial(ca_key, ca_cert, ALLOWED, REVOKED_PEER_SERIAL_INT)
    live_cert, live_key = _leaf_at_serial(ca_key, ca_cert, ALLOWED, LIVE_PEER_SERIAL_INT)
    ca_crt = _write_cert_only(ca_cert, tmp_path, "ca")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    dead = _write_dir(dead_cert, dead_key, tmp_path, "c-dead")
    live = _write_dir(live_cert, live_key, tmp_path, "c-live")
    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="peer-executor-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(ca=ca_crt, srv=srv, dead=dead, live=live, config=config)


class TestRealDoorRefusesARevokedExecutorPeer:
    """A real TLS handshake, a real presented certificate, no daemon, and no core anywhere."""

    def test_revoked_executor_peer_is_refused_at_accept_and_never_reaches_the_engine(self, peer_pk, caplog):
        listener = _start(
            peer_pk.config,
            lambda _sid: pytest.fail("the second peer consult let a revoked executor peer reach the engine"),
            [ALLOWED],
            state=_peer_state(executor=(REVOKED_PEER_SERIAL_ROW,)),
        )
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        try:
            with _client(peer_pk.ca, peer_pk.dead) as client:
                with pytest.raises(httpx2.RequestError) as excinfo:
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        assert getattr(excinfo.value, "response", None) is None, "the door answered HTTP instead of refusing"
        lines = "\n".join(r.getMessage() for r in caplog.records if r.name == RELAY_LOGGER)
        assert REFUSE_PEER_EXECUTOR_REVOKED in lines, lines
        assert "503" not in lines, lines  # a kill is not a fault, and a fault is not a kill

    def test_the_relay_arm_answers_first_at_the_real_door(self, peer_pk, caplog):
        """Deterministic precedence, proven on the door rather than asserted in prose.

        A serial named by BOTH populations must read as ONE class, and the shipped order is the #597
        relay arm first. A later leg that swapped the two consults would silently re-label which
        credential died, and this cell catches it from the journal the listener writes.
        """
        listener = _start(
            peer_pk.config,
            lambda _sid: pytest.fail("a doubly-named peer reached the engine"),
            [ALLOWED],
            state=_peer_state(executor=(REVOKED_PEER_SERIAL_ROW,), relay=(REVOKED_PEER_SERIAL_ROW,)),
        )
        caplog.set_level(logging.WARNING, logger=RELAY_LOGGER)
        try:
            with _client(peer_pk.ca, peer_pk.dead) as client:
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload())
        finally:
            listener.stop()
        lines = "\n".join(r.getMessage() for r in caplog.records if r.name == RELAY_LOGGER)
        assert REFUSE_PEER_REVOKED in lines, lines
        assert REFUSE_PEER_EXECUTOR_REVOKED not in lines, lines

    def test_the_same_peer_is_served_when_the_list_calls_it_live(self, peer_pk):
        """AC2 — the half that decides whether this fix is real.

        Same listener shape, same CA, same allowlisted CN, same TLS floor; the ONLY difference is
        that the population names nothing. The peer must reach /execute, invoke the engine, and get
        its 200. A gate that refuses everything clears AC1 and fails this row.
        """
        fake = _FakeExec(result=_ok_result())
        sessions: list = []
        listener = _start(
            peer_pk.config,
            _factory(fake, sessions),
            [ALLOWED],
            state=_peer_state(executor=(REVOKED_PEER_SERIAL_ROW,)),  # ANOTHER credential is revoked
        )
        try:
            with _client(peer_pk.ca, peer_pk.live) as client:
                resp = client.post(_url(listener), json=_payload())
            assert resp.status_code == 200, resp.text
            assert resp.json()["exit_code"] == 0
        finally:
            listener.stop()
        assert sessions == ["s1"], "the paired negative never reached the engine — the door is refusing live work"

    def test_an_empty_population_serves_the_peer_the_list_does_not_name(self, peer_pk):
        """The bootstrap shape, on the real door: empty list => admit, never refuse."""
        fake = _FakeExec(result=_ok_result())
        sessions: list = []
        listener = _start(
            peer_pk.config,
            _factory(fake, sessions),
            [ALLOWED],
            state=_peer_state(),
        )
        try:
            with _client(peer_pk.ca, peer_pk.dead) as client:
                resp = client.post(_url(listener), json=_payload())
            assert resp.status_code == 200, resp.text
        finally:
            listener.stop()
        assert sessions == ["s1"]

    def test_the_tls_floor_and_cn_allowlist_are_unchanged_by_this_arm(self, peer_pk):
        """AC5 as an absence on the real listener context.

        The context is built by the shipped ``_build_ssl_context``; this change adds a consult
        AFTER the handshake, so the floor, the anchor and ``CERT_REQUIRED`` must be byte-what-they-were.
        """
        listener = RelayListener(
            peer_pk.config,
            lambda _sid: None,
            [ALLOWED],
            host="127.0.0.1",
            port=0,
            state=_peer_state(),
        )
        ctx = listener._build_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert not (ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF), "a CRL flag appeared at the listener door"

        # And the CN gate still bites for a name that is not allowlisted — untouched by this leg.
        refused = _start(
            peer_pk.config,
            lambda _sid: pytest.fail("a non-allowlisted CN reached the engine"),
            ["some-other-core"],
            state=_peer_state(),
        )
        try:
            with _client(peer_pk.ca, peer_pk.live) as client:
                resp = client.post(_url(refused), json=_payload())
            assert resp.status_code == 403, resp.text
        finally:
            refused.stop()

    def test_the_self_gate_still_answers_before_either_peer_arm(self, peer_pk):
        """Ordering unchanged: a daemon that cannot answer about ITSELF refuses, whatever the
        executor population says — the AC6 tri-state is not outranked by a peer claim.

        Amended for #697, not weakened. This state is unanswered (``answered=False``), so the class
        the door reaches is the OPERATIONAL FAULT, which now answers HTTP 503 with its own sentence
        instead of closing silently. What the cell exists to prove is still asserted on both halves:
        the self gate fires FIRST (the revoked-peer row in the population is never consulted — the
        handler would fail the test if anything were served, and the journal names the fault class,
        not a peer class), and a peer carrying that same revoked serial still gets no HTTP answer on
        the peer cells above, which are untouched.
        """
        listener = _start(
            peer_pk.config,
            lambda _sid: pytest.fail("an unanswered daemon served a connection"),
            [ALLOWED],
            state=_peer_state(executor=(REVOKED_PEER_SERIAL_ROW,), answered=False),
        )
        try:
            with _client(peer_pk.ca, peer_pk.dead) as client:
                resp = client.post(_url(listener), json=_payload())
            assert resp.status_code == 503, resp.text
            assert resp.json()["detail"] == REFUSE_NO_ANSWER, resp.json()
        finally:
            listener.stop()

    def test_a_refused_peer_can_be_served_after_the_revoke_lands_and_the_revoke_is_reversed(self, peer_pk):
        """Per-connection, not per-boot, in BOTH directions — the mirror of the #586 gate cell.

        Population gains the serial -> next connection refused; population drops it -> next one
        served. If either half broke, the door would be a boot-time decision wearing a
        per-connection hat.
        """
        state = _peer_state()
        fake = _FakeExec(result=_ok_result())
        sessions: list = []
        listener = _start(peer_pk.config, _factory(fake, sessions), [ALLOWED], state=state)
        try:
            with _client(peer_pk.ca, peer_pk.dead) as client:
                assert client.post(_url(listener), json=_payload("s1")).status_code == 200
                state.revoked_executor_serials = frozenset({REVOKED_PEER_SERIAL_ROW})
                with pytest.raises(httpx2.RequestError):
                    client.post(_url(listener), json=_payload("s2"))
                state.revoked_executor_serials = frozenset()
                assert client.post(_url(listener), json=_payload("s3")).status_code == 200
        finally:
            listener.stop()
        assert sessions == ["s1", "s3"], sessions


# ---------------------------------------------------------------------------
# D. THE FENCES, AS TREE-WIDE ABSENCES
# ---------------------------------------------------------------------------


class TestTheRejectedOptionsStayRejected:
    """The ruling rejected option (a) on measured grounds. These cells keep the rejection real."""

    def test_no_crl_or_handshake_layer_machinery_in_the_executor_src(self) -> None:
        """The rejected option (a) forms, searched as CODE TEXT with comments stripped.

        A scan for the bare string "crl" fails on this change's own comments, which name the
        rejected mechanism precisely to say it is absent — a test that argues with its source. So
        every module is tokenized and COMMENT plus non-docstring STRING noise is dropped before the
        search, and the forms looked for are the spellings only a call site can produce. The control
        at the bottom is what makes the green above mean something: the same instrument, pointed at
        what this leg DOES ship, must find it.
        """
        import io
        import tokenize
        from pathlib import Path

        def code_text(path: Path) -> str:
            """Source with COMMENT tokens removed, and docstrings kept out by position."""
            text = path.read_text(encoding="utf-8")
            try:
                toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
            except (tokenize.TokenError, IndentationError, SyntaxError):
                pytest.fail(f"{path.name} cannot be tokenized — the absence scan would be unsound")
            doc_lines: set[int] = set()
            quote_starts = ('"""', "'''")
            for tok in toks:
                if tok.type == tokenize.STRING and tok.line.lstrip().startswith(quote_starts):
                    # a STRING token that begins a statement is a docstring or a bare literal;
                    # neither is a revocation call site, and both are prose.
                    doc_lines.update(range(tok.start[0], tok.end[0] + 1))
            kept = [tok.string for tok in toks if tok.type != tokenize.COMMENT and tok.start[0] not in doc_lines]
            return " ".join(kept)

        src = Path(__file__).resolve().parents[1] / "src" / "executor"
        forms = (
            "VERIFY_CRL_CHECK_LEAF",
            "VERIFY_CRL_CHECK_CHAIN",
            "capath",
            "load_cert_crl",
            "crl_url",
            "ocsp_load",
        )
        scanned = {p.name: code_text(p) for p in sorted(src.rglob("*.py"))}
        assert any(scanned.values()), "the scan produced no code text at all — every absence below is vacuous"
        hits = {
            name: [f for f in forms if f in text] for name, text in scanned.items() if any(f in text for f in forms)
        }
        assert not hits, f"transport-layer revocation appeared in executor CODE: {hits}"
        # positive control on the instrument, same tree, same scan: it must see what this leg shipped.
        assert (
            "peer_executor_revocation_refusal" in scanned["relay_listener.py"]
        ), "the scan cannot see the consult this leg added — the absence assertion above would be vacuous"

    def test_the_accept_point_emits_exactly_the_ruled_classes(self) -> None:
        """Cell (d) on the executor arm specifically: the new class is reachable, and nothing
        outside the ruled vocabulary can be emitted."""
        emitted: set = set()
        for state in (
            _peer_state(executor=(REVOKED_PEER_SERIAL_ROW,)),
            _peer_state(),
            None,
        ):
            for presented in (REVOKED_PEER_SERIAL_CERT, "9999", None):
                reason = peer_executor_revocation_refusal(state, presented)
                if reason is not None:
                    emitted.add(reason)
        assert emitted == {REFUSE_PEER_EXECUTOR_REVOKED}, emitted

    def test_the_refusal_is_the_listeners_own_act(self) -> None:
        """AC3 read off the code path, not off a log line someone else wrote.

        The refusing party is ``_RelayHTTPServer.get_request``: it consults the carried population
        and closes the socket itself — no daemon loop, no core dial gate, no HTTP response. The
        cells above prove the outcome; this one pins WHO decides it.
        """
        import inspect

        from executor.relay_listener import _RelayHTTPServer

        src = inspect.getsource(_RelayHTTPServer.get_request)
        assert "peer_executor_revocation_refusal" in src, "the new arm is not on the accept path"
        assert "tls_conn.shutdown" in src and "tls_conn.close" in src, "the refusal is not asserted at the door"
        assert "self.revocation_state" in src, "the accept path consults the carried state and nothing else"
        # The first arm still answers ahead of this one at the real door, so the ordering fence is
        # visible in the source as well as proven by the handshake cell that runs it.
        assert src.index("peer_revocation_refusal(") < src.index(
            "peer_executor_revocation_refusal("
        ), "the two peer consults swapped order — which class an operator reads would change silently"
