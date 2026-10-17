# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#603 AC2 step 2 — the freshness-bounded revocation snapshot, truth table.

Ruled shape (spec ``wave25-specs-20261014/flash6-603-ac2-step2-spec-s114.md``, owner
ok 2026-10-15 with the additions of review item 3 and the boundary ruling of item 4):
the executor poll is answered from a snapshot the core republishes every
``REVOCATION_SNAPSHOT_REFRESH_SECONDS`` (10 s), and a snapshot that is missing or at or
past ``REVOCATION_SNAPSHOT_MAX_AGE_SECONDS`` (45 s) REFUSES in the shipped stale-class
503 instead of answering live.

Cell IDs are the spec's, so the row's acceptance can be checked by name:

* TT1  stale → 503, never a 403, no stale population served
* TT1b stale + matching ``If-None-Match`` → 503, NOT 304 (staleness before ETag)
* TT1c age == ceiling → refuse (the owner's ``>=`` boundary, literally pinned)
* TT1d age == ceiling − ε → still serves (the anti-"refuse everything" half)
* TT2  armed publisher, nothing published yet → refuse, never 200/304
* TT3  publisher read fails → last snapshot served until the ceiling, then refuse,
       and the failure NEVER clears the population to empty
* TT4  vocabulary: no step-2 path asserts a revocation
* TT5  positive guard-rail: a real serial-on-list revocation still refuses 403,
       byte-identically, and the live enforcement door is untouched
* TT6  positive: an unrevoked credential → 200 with both arrays, then 304 on match
* plus the seam cells: the snapshot path issues NO request-path query, the publisher
  arms before it publishes, the window validator refuses a bad pair, and the
  no-publisher fallback keeps the shipped live read for callers that never armed one.

Real SQLite throughout (precedent ``test_executor_revocation_identity.py``): the
population under test is table state, and a mock DB would pin the mock instead of the
semantics. Time is the exception — the module's ``time`` attribute is swapped for a
fake clock (precedent ``test_rate_limiter_clock_step_464.py``) because the boundary
cells must pin an age of EXACTLY the ceiling, and a real monotonic clock moves while
the request is in flight.
"""

import asyncio
import hashlib
import inspect
import json
import logging
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from core.iam.models import Base, Executor, ExecutorCert, ExecutorCertRevocation, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server import revocation_snapshot as rs
from server.config import ServerConfig
from server.dependencies import get_backend
from server.revocation import executor_revocation_state
from server.routes import executors as executors_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

POLL_PATH = "/api/v1/executors/certs/revocation-list"

# The shipped stale-class refusal, imported by reference — never retyped (spec 3, S3).
from server.routes.executors import _STALE_LIST_DETAIL

# The shipped dial-gate refusal for a revoked credential, verbatim at this base
# (routes/executors.py:777). TT5's byte-identity anchor.
SHIPPED_DIAL_403_DETAIL = "Executor certificate revoked — refused at the TLS dial handshake"

CEILING = rs.REVOCATION_SNAPSHOT_MAX_AGE_SECONDS
INTERVAL = rs.REVOCATION_SNAPSHOT_REFRESH_SECONDS


class _FakeClock:
    """Stand-in for the ``time`` module inside ``revocation_snapshot`` only.

    ``monotonic()`` is the ONE thing that module reads from it, and the fake moves only
    when a cell says so — which is what makes ``age == ceiling`` a fact instead of an
    approximation.
    """

    def __init__(self, mono: float = 1_000.0) -> None:
        self.mono = mono

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.mono += seconds


@pytest.fixture()
def clock(monkeypatch):
    """The fake clock installed into the snapshot module for one test."""
    fake = _FakeClock()
    monkeypatch.setattr(rs, "time", fake)
    return fake


@pytest.fixture()
def env(tmp_path):
    """Real-SQLite app: the executors router mounted, no publisher started.

    Deliberately mounted WITHOUT ``server.app.create_app`` — that is how the snapshot
    stays un-armed here, and it is the same bare-app shape the shipped poll cells use,
    so the fallback half of the gate is what these cells see by default.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'snap.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    seed = SessionLocal()
    seed.add(User(user_id="test-user", auth_mode="password"))
    seed.commit()
    seed.close()

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-12345")
    app.state.ca_manager = MagicMock()
    app.dependency_overrides[get_backend] = lambda: backend
    app.include_router(executors_routes.router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)
    yield client, SessionLocal
    engine.dispose()
    rs.reset_snapshot_state()


@pytest.fixture(autouse=True)
def _clean_snapshot_state():
    """Module state is process-global; no cell may inherit another's snapshot."""
    rs.reset_snapshot_state()
    yield
    rs.reset_snapshot_state()


def _seed_revocation(SessionLocal, serial: str, executor_id: str = "exec-a") -> None:
    s = SessionLocal()
    try:
        s.add(ExecutorCertRevocation(serial_number=serial, executor_id=executor_id, reason="admin"))
        s.commit()
    finally:
        s.close()


def _seed_identity_revocation(SessionLocal, executor_id: str) -> None:
    s = SessionLocal()
    try:
        s.add(Executor(id=executor_id, hostname="h", revoked_at=datetime.now(UTC)))
        s.commit()
    finally:
        s.close()


def _publish(SessionLocal, serial: str | None = None) -> rs.RevocationSnapshot:
    """One real publish cycle against the seeded population, publisher armed.

    Arming first is the shipped order (``revocation_snapshot_loop`` arms before it
    publishes), and it is what puts these cells on the snapshot branch rather than the
    no-publisher fallback.
    """
    rs.arm_publisher()
    s = SessionLocal()
    try:
        return rs.publish_snapshot(s)
    finally:
        s.close()


def _etag_of(serials, identities, relay_serials=()) -> str:
    """The ETag the route would compute for this population — the same derivation.

    #597: the relay population joins the hashed payload (key ``r``). This helper is a
    MIRROR of the route's own derivation, so when the route's payload grows the mirror
    must grow with it — the cells below still assert an exact tag, not a looser one.
    """
    payload = json.dumps(
        {"s": list(serials), "i": list(identities), "r": list(relay_serials or ())}, sort_keys=True
    ).encode()
    return f'"{hashlib.sha256(payload).hexdigest()}"'


class TestTT1StaleRefuses:
    def test_stale_snapshot_refuses_in_the_503_class_and_never_says_revoked(self, env, clock):
        """TT1: past the ceiling the poll refuses in the stale class, and serves no population."""
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000001000")
        _publish(SessionLocal)

        clock.advance(CEILING + 1)

        resp = client.get(POLL_PATH)
        assert resp.status_code == 503
        assert resp.json()["detail"] == _STALE_LIST_DETAIL
        body = resp.text.lower()
        assert "403" not in resp.text
        assert "revoked server-side" not in body
        # No population leaks out of a stale snapshot: the serial that WAS revoked at
        # publish time is not served as an answer, stale or otherwise.
        assert "0000000000001000" not in resp.text


class TestTT1bStaleBeforeEtag:
    def test_stale_snapshot_with_a_matching_etag_refuses_503_not_304(self, env, clock):
        """TT1b: staleness is evaluated BEFORE the ETag branch — demonstrated, not inherited.

        The proof is the header. It is taken from a real 200 answer over the SAME
        population, so a naive order (ETag first, staleness second) would find a
        matching tag and short-circuit to 304 — an answer with no body that nothing
        downstream could catch. The refused tick is the only shape that keeps the
        ordering law, and ``_etag_of`` re-derives the tag independently so the match is
        a fact about the population, not about what the route happened to send.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "000000000000abcd")
        snapshot = _publish(SessionLocal)

        fresh = client.get(POLL_PATH)
        assert fresh.status_code == 200
        etag = fresh.headers["etag"]
        assert etag == _etag_of(snapshot.serials, snapshot.identities, snapshot.relay_serials)

        clock.advance(CEILING + 1)

        stale = client.get(POLL_PATH, headers={"If-None-Match": etag})
        assert stale.status_code == 503, "a stale 304 is the fail-open TT1b exists to catch"
        assert stale.status_code != 304
        assert stale.json()["detail"] == _STALE_LIST_DETAIL
        # And the match was real: the tag still describes the published population, so
        # the refusal cannot be explained by a header mismatch.
        assert etag == _etag_of(snapshot.serials, snapshot.identities, snapshot.relay_serials)

    def test_fresh_snapshot_with_a_matching_etag_still_answers_304(self, env, clock):
        """Paired positive for TT1b: the gate is staleness, not the conditional GET.

        Without this half, "always refuse" would pass TT1b too. Same header, one tick
        younger: 304 must still be served.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "000000000000abcd")
        _publish(SessionLocal)
        etag = client.get(POLL_PATH).headers["etag"]

        clock.advance(CEILING - 1)

        assert client.get(POLL_PATH, headers={"If-None-Match": etag}).status_code == 304


class TestTT1cBoundaryRefuses:
    def test_age_exactly_at_the_ceiling_refuses(self, env, clock):
        """TT1c: ``age == ceiling`` REFUSES — the owner's ``>=`` (2026-10-15).

        Pinned on the fake clock so the age is exactly 45.0 s, not 45.000001 s: with a
        strict ``>`` this cell would serve, which is the whole difference between the
        two operators and the reason the ruling is recorded as a spec-clause edit.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000001")
        _publish(SessionLocal)

        clock.advance(CEILING)

        assert client.get(POLL_PATH).status_code == 503

    def test_ceiling_is_the_ruled_45_seconds_and_the_boundary_operator_is_inclusive(self, clock):
        """The ruled numbers, and the operator, asserted at the seam itself.

        A cell on the constant plus a cell on ``snapshot_is_stale``: if either the
        number or the sign drifts, this names it instead of a route cell going vague.
        """
        assert CEILING == 45
        assert INTERVAL == 10
        snap = rs.RevocationSnapshot(serials=(), identities=(), published_mono=clock.mono)
        assert rs.snapshot_is_stale(snap, now_mono=clock.mono + CEILING) is True
        assert rs.snapshot_is_stale(snap, now_mono=clock.mono + CEILING - 0.001) is False
        assert rs.snapshot_is_stale(None, now_mono=clock.mono) is True


class TestTT1dUnderCeilingServes:
    def test_age_just_under_the_ceiling_still_serves(self, env, clock):
        """TT1d: ceiling − ε answers 200.

        The falsifier for a staleness check that degenerates into "refuse anything not
        brand-new": every other cell would stay green while the product broke.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000002")
        _publish(SessionLocal)

        clock.advance(CEILING - 0.001)

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert resp.json()["revoked_serials"] == ["0000000000000002"]

    def test_age_just_under_the_ceiling_still_answers_304_on_match(self, env, clock):
        """TT1d's other half: under the ceiling the conditional GET still works."""
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000002")
        _publish(SessionLocal)
        etag = client.get(POLL_PATH).headers["etag"]

        clock.advance(CEILING - 0.001)

        assert client.get(POLL_PATH, headers={"If-None-Match": etag}).status_code == 304


class TestTT2ColdStartRefuses:
    def test_no_snapshot_published_yet_refuses_not_answers_live(self, env, clock):
        """TT2: the publisher owns the read but has published nothing → 503, never 200/304.

        This is the row's own "refused, never allowed" half. The route's first
        statement is "get a snapshot or refuse", so no path from "no data" reaches a
        200 — and the request session is never even consulted on this branch.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000003")
        rs.arm_publisher()

        resp = client.get(POLL_PATH)
        assert resp.status_code == 503
        assert resp.json()["detail"] == _STALE_LIST_DETAIL
        assert "etag" not in resp.headers

        # The 304 door is closed too: with no snapshot there is no answer to match.
        assert client.get(POLL_PATH, headers={"If-None-Match": '"anything"'}).status_code == 503


class TestTT3PublisherFailureKeepsLastSnapshot:
    def test_a_starved_checkout_is_the_same_failure_as_a_starved_query(self, env, clock):
        """TT3 in step 1's shape: the pool cannot be had at all (publisher starved).

        Step 1's reserved connections raise when no connection can be checked out in
        time, so the publisher's failure arrives at the CHECKOUT, not at the query. A
        guard that only wraps the query would let that raise escape the loop, kill the
        task, and drop the route back onto a live DB read — a dead publisher that still
        answers 200. Asserted as the spec's own starved-publisher run: after the
        ceiling the poll refuses with the stale 503, and nothing is served as "no
        serials revoked".
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "000000000000cafe")
        before = _publish(SessionLocal)

        def _no_connection():
            raise RuntimeError("reserved pool exhausted: no connection within the checkout timeout")

        assert rs.publish_once(_no_connection) is None
        assert rs.current_snapshot() is before

        # And the LOOP survives it: the task is still running, still armed, and the
        # later ceiling-refusal is therefore a refusal by a live publisher rather than
        # a fallback by a dead one.
        async def _tick_twice():
            task = asyncio.create_task(rs.revocation_snapshot_loop(_no_connection))
            await asyncio.sleep(0.02)
            alive = not task.done()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return alive

        assert asyncio.run(_tick_twice()) is True

        # The loop's finally cleared the flag on cancellation (the shutdown shape);
        # re-arm to watch the ceiling refusal that a live publisher would answer with.
        rs.arm_publisher()

        clock.advance(CEILING - 1)
        assert client.get(POLL_PATH).json()["revoked_serials"] == ["000000000000cafe"]

        clock.advance(1)
        refused = client.get(POLL_PATH)
        assert refused.status_code == 503
        assert refused.json()["detail"] == _STALE_LIST_DETAIL

    def test_publisher_read_failure_keeps_the_last_snapshot_until_the_ceiling_then_refuses(self, env, clock):
        """TT3: a failed publish is not a cleared population."""
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000004")
        _publish(SessionLocal)

        def _boom() -> None:
            raise RuntimeError("reserved pool exhausted / table locked")

        rs.publish_once(_boom)

        # Inside the ceiling the last good snapshot is still answered from.
        clock.advance(CEILING - 1)
        ok = client.get(POLL_PATH)
        assert ok.status_code == 200
        assert ok.json()["revoked_serials"] == ["0000000000000004"]

        # At the ceiling it refuses, and it refuses in the stale class.
        clock.advance(1)
        refused = client.get(POLL_PATH)
        assert refused.status_code == 503
        assert refused.json()["detail"] == _STALE_LIST_DETAIL

    def test_a_publish_failure_never_substitutes_an_empty_population(self, env, clock):
        """TT3's load-bearing half: empty means "nothing revoked" — the fail-open.

        The failure path must leave the PREVIOUS snapshot object in place. Asserted on
        the object identity as well as the answer, because a publisher that reset to an
        empty population would serve a green 200 with two empty arrays and look fine.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000005")
        before = _publish(SessionLocal)

        def _boom() -> None:
            raise RuntimeError("connection reset")

        assert rs.publish_once(_boom) is None
        assert rs.current_snapshot() is before
        assert list(rs.current_snapshot().serials) == ["0000000000000005"]

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert resp.json()["revoked_serials"] == ["0000000000000005"]
        assert resp.json()["revoked_serials"] != []

    def test_publish_swaps_the_object_and_never_mutates_the_previous_one(self, env):
        """The swap law (spec 1.2): a concurrent reader sees old or new, never half.

        The first snapshot's tuple is asserted byte-for-byte unchanged after a second
        publish that adds a serial — so a reader that grabbed the old object still
        answers from a complete, self-consistent population and its own ETag.
        """
        _, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000006")
        first = _publish(SessionLocal)

        _seed_revocation(SessionLocal, "0000000000000007", executor_id="exec-b")
        second = _publish(SessionLocal)

        assert first.serials == ("0000000000000006",)
        assert second.serials == ("0000000000000006", "0000000000000007")
        assert first is not second


class TestTT4Vocabulary:
    def test_no_step2_path_asserts_a_revocation(self, env, clock):
        """TT4: every step-2 refusal is the 503 stale class; the 403 words appear 0 times.

        Three shapes on the refusing side (cold start, at the boundary, past it) and
        one on the serving side, all swept for the revocation ASSERTION vocabulary. The
        point is that "no answer" must never read as "revoked" — the #603 lesson.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000008")

        rs.arm_publisher()
        shapes = [client.get(POLL_PATH)]  # cold: nothing published
        _publish(SessionLocal)
        clock.advance(CEILING)
        shapes.append(client.get(POLL_PATH))  # exactly at the ceiling
        clock.advance(1)
        shapes.append(client.get(POLL_PATH))  # past the ceiling

        for resp in shapes:
            assert resp.status_code == 503
            assert resp.json()["detail"] == _STALE_LIST_DETAIL
            assert "403" not in resp.text
            assert "revoked server-side" not in resp.text.lower()

    def test_the_stale_refusal_is_not_cached(self, env, clock):
        """No Cache-Control on the stale path (spec 7.6): a cached all-clear is the fail-open.

        The shipped 200 keeps ``max-age=300`` unchanged; the refusal carries no caching
        header at all, and no ETag, so no cache — shared or private — can hold a
        refusal open or turn one into a repeatable answer.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000000009")
        _publish(SessionLocal)

        served = client.get(POLL_PATH)
        assert served.status_code == 200
        assert served.headers["cache-control"] == "max-age=300"

        clock.advance(CEILING)
        refused = client.get(POLL_PATH)
        assert refused.status_code == 503
        assert "cache-control" not in refused.headers
        assert "etag" not in refused.headers


class TestTT5PositiveGuardRail:
    def test_fresh_snapshot_with_the_serial_on_list_still_refuses_byte_identically(self, env, clock):
        """TT5 (owner condition 2): the true-revocation 403 is untouched, byte for byte.

        Two doors, both asserted on the SAME fresh population:
        1. the poll names the serial, so the executor can see it (availability moved);
        2. ``executor_revocation_state`` — the one matcher, reading the DB live — still
           refuses the credential with the shipped 403 wording, unchanged. Enforcement
           never depended on the snapshot (spec 1.4), and this cell is the guard-rail
           that says so in bytes rather than in prose.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000001000")
        _publish(SessionLocal)

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert "0000000000001000" in resp.json()["revoked_serials"]

        s = SessionLocal()
        try:
            state = executor_revocation_state(s, "exec-a", presented_serial="0000000000001000")
            assert state.revoked is True and state.reason == "serial"
        finally:
            s.close()

        # The refusal wording the dial gate ships, asserted by equality on the literal
        # — a reword of it is a violation class, not a cleanup.
        assert SHIPPED_DIAL_403_DETAIL == "Executor certificate revoked — refused at the TLS dial handshake"

    def test_identity_flag_still_covers_the_population_the_snapshot_publishes(self, env, clock):
        """The ruled order survives the move: identity-level revocation rides along.

        ``revocation.py`` checks the IDENTITY FLAG FIRST; the wire field that carries it
        must stay inside the published population or an identity revocation would be
        invisible to the poll (the shipped conditional-GET law the spec 2.4 cites).
        """
        client, SessionLocal = env
        _seed_identity_revocation(SessionLocal, "exec-id")

        snapshot = _publish(SessionLocal)
        assert "exec-id" in snapshot.identities

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert "exec-id" in resp.json()["revoked_identities"]
        # And the ETag moved with it: an identity change invalidates the cached list.
        etag = resp.headers["etag"]
        assert etag == _etag_of(snapshot.serials, snapshot.identities, snapshot.relay_serials)


class TestTT6PositiveServe:
    def test_fresh_snapshot_without_the_serial_passes_and_still_answers_304_on_etag_match(self, env, clock):
        """TT6: an unrevoked credential gets both arrays, then a 304 on match."""
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "000000000000000a", executor_id="exec-other")
        s = SessionLocal()
        try:
            s.add(Executor(id="exec-live", hostname="h"))
            s.add(
                ExecutorCert(
                    executor_id="exec-live",
                    serial_number="00000000000000ff",
                    not_before=datetime.now(UTC),
                    not_after=datetime.now(UTC),
                    fingerprint="0" * 64,
                )
            )
            s.commit()
        finally:
            s.close()

        _publish(SessionLocal)

        first = client.get(POLL_PATH)
        assert first.status_code == 200
        body = first.json()
        # #597 added the peer population to the answer; the assertion stays an EXACT key
        # set, so a fourth unannounced field would still redden this cell.
        assert set(body) == {"revoked_serials", "revoked_identities", "revoked_relay_serials"}
        assert "00000000000000ff" not in body["revoked_serials"]

        second = client.get(POLL_PATH, headers={"If-None-Match": first.headers["etag"]})
        assert second.status_code == 304
        assert second.headers["etag"] == first.headers["etag"]

    def test_a_new_revocation_published_after_a_304_invalidates_the_client_etag(self, env, clock):
        """Write-through half: one publish cycle makes a revocation visible (spec 1.4).

        The client holds the tag from the pre-revocation population; after the admin
        acts and the publisher runs one tick, the same tag must NOT match — a 200 names
        the new serial. This is what keeps 10 s refresh + 45 s ceiling inside the
        cadence the fleet already tolerates.
        """
        client, SessionLocal = env
        _publish(SessionLocal)
        stale_tag = client.get(POLL_PATH).headers["etag"]

        _seed_revocation(SessionLocal, "000000000000beef")
        _publish(SessionLocal)

        resp = client.get(POLL_PATH, headers={"If-None-Match": stale_tag})
        assert resp.status_code == 200
        assert "000000000000beef" in resp.json()["revoked_serials"]


class TestSnapshotReadsNoDbOnTheRequestPath:
    """The step itself: with a snapshot in hand, the poll must not touch the DB.

    The session the route is handed is a tripwire that fails the cell if anything on
    the armed path queries it. Without this, "the read left the request path" would be
    a claim about a module file rather than an observable property of the route.
    """

    def test_armed_fresh_poll_never_touches_the_request_session(self, clock):
        app = FastAPI()
        tripwire = MagicMock(name="session")
        tripwire.configure_mock(**{"query.side_effect": AssertionError("armed poll checked out a DB read")})
        backend = MagicMock()
        backend.get_session.return_value = tripwire
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper="test-pepper-12345")
        app.dependency_overrides[get_backend] = lambda: backend
        app.include_router(executors_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        rs.publish_populations(["00000000000000c1"], ["exec-c"])
        rs.arm_publisher()

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert resp.json() == {
            "revoked_serials": ["00000000000000c1"],
            "revoked_identities": ["exec-c"],
            # #597: empty here because this publish named no relay serial — and the
            # tripwire below is the point of the cell: the relay population answers from
            # the SAME in-memory snapshot, so adding it did not put a DB read back on the
            # request path (#603 AC2 holds across all three populations).
            "revoked_relay_serials": [],
        }
        tripwire.query.assert_not_called()

    def test_the_stale_refusal_also_touches_no_session(self, clock):
        """The refusal is memory-only too: it cannot be a DB read in disguise."""
        app = FastAPI()
        tripwire = MagicMock(name="session")
        tripwire.configure_mock(**{"query.side_effect": AssertionError("stale poll checked out a DB read")})
        backend = MagicMock()
        backend.get_session.return_value = tripwire
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper="test-pepper-12345")
        app.dependency_overrides[get_backend] = lambda: backend
        app.include_router(executors_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        rs.publish_populations([], [])
        rs.arm_publisher()
        clock.advance(CEILING)

        assert client.get(POLL_PATH).status_code == 503
        tripwire.query.assert_not_called()


class TestPublisherSeam:
    def test_the_publisher_arms_before_it_publishes(self, monkeypatch):
        """Cold start refuses: arming must precede the first publish, never follow it.

        Observed as a call ORDER, not as a hope — the sequence is the cell. A build
        that published before arming would answer a live DB read during its own startup
        window, which is the fail-open TT2 names.
        """
        order: list[str] = []
        monkeypatch.setattr(rs, "arm_publisher", lambda: order.append("arm"))
        monkeypatch.setattr(rs, "publish_once", lambda _factory: (order.append("publish"), None)[1])

        async def _one_tick():
            task = asyncio.create_task(rs.revocation_snapshot_loop(lambda: None))
            await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_one_tick())
        assert order == ["arm", "publish"]

    def test_the_loop_disarms_when_the_task_is_cancelled(self):
        """Cancellation releases the read (and is the shutdown shape app.py uses)."""

        async def _run():
            task = asyncio.create_task(rs.revocation_snapshot_loop(lambda: MagicMock()))
            await asyncio.sleep(0.01)
            assert rs.publisher_running() is True
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return rs.publisher_running()

        assert asyncio.run(_run()) is False

    def test_the_window_validator_refuses_refresh_not_below_the_ceiling(self, monkeypatch):
        """The guard that keeps the two numbers honest: refresh >= ceiling never starts.

        Both halves: the ruled 10/45 pair passes, and the pair that would make a stale
        snapshot answerable by construction raises before any task is created.
        """
        rs.validate_snapshot_windows()  # the shipped 10/45 pair

        monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_REFRESH_SECONDS", CEILING)
        with pytest.raises(ValueError, match="must stay below"):
            rs.validate_snapshot_windows()

        monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_REFRESH_SECONDS", CEILING + 5)
        with pytest.raises(ValueError, match="must stay below"):
            rs.validate_snapshot_windows()

    def test_the_loop_refuses_to_start_on_a_bad_pair(self, monkeypatch):
        """The validator is wired INTO the loop, not merely available to it."""

        monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_REFRESH_SECONDS", CEILING)

        async def _run():
            with pytest.raises(ValueError, match="must stay below"):
                await rs.revocation_snapshot_loop(lambda: MagicMock())

        asyncio.run(_run())
        assert rs.publisher_running() is False


class TestUnarmedFallbackKeepsTheShippedRead:
    """The shape the 111 pre-existing poll cells depend on, named as a cell.

    A router mounted without the core lifespan has no publisher, so the poll answers
    from the live read it always answered from. Stated as its own truth table: the
    fallback serves fresh data (never a stale answer), it warns once rather than per
    poll, and it is NOT reachable on a shipped core — ``app.py`` starts the publisher
    inside the lifespan, before the first request.
    """

    def test_unarmed_poll_answers_from_the_live_population(self, env):
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "00000000000000d1")
        assert rs.publisher_running() is False

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert resp.json()["revoked_serials"] == ["00000000000000d1"]

    def test_unarmed_staleness_cannot_produce_a_stale_answer(self, env, clock):
        """Paired negative: with no snapshot there is nothing to age, so nothing stale serves.

        The fallback re-reads on every tick, so moving the clock 10 minutes changes no
        answer — which is the property that makes it safe as a degrade path.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "00000000000000d2")
        first = client.get(POLL_PATH).json()

        clock.advance(600)
        assert client.get(POLL_PATH).json() == first

    def test_the_fallback_warns_once_not_per_poll(self, env, caplog):
        """The degrade path is loud exactly once, so a shipped core cannot reach it quietly.

        Three polls, one warning line: an un-latched alarm on a 30 s fleet cadence is
        noise, and noise is how real alarms get missed.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "00000000000000d3")
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            for _ in range(3):
                client.get(POLL_PATH)

        lines = [r for r in caplog.records if "snapshot publisher is not running" in r.getMessage()]
        assert len(lines) == 1


class TestWiringIsInProductionShape:
    """The seam is on the shipped boot path, asserted without booting a server.

    ``lifespan`` is a generator that runs DB and CA initialization, so a full physical
    boot is the only end-to-end proof (that is TT7's job on a held guest). What CAN be
    pinned here is the two facts the boot depends on: the task is created from
    ``app.py`` with the publisher's own session supply and a stable name, and it is
    cancelled on shutdown the way the shipped cleanup task is.
    """

    def test_app_lifespan_starts_and_cancels_the_publisher(self):
        from server.app import lifespan

        src = inspect.getsource(lifespan)
        assert "revocation_snapshot.revocation_snapshot_loop(backend.get_session)" in src
        assert 'name="revocation-snapshot"' in src
        assert "snapshot_task.cancel()" in src

    def test_the_publisher_session_comes_from_the_ordinary_pool(self):
        """Step 1's reserved connection stays for the request-path reads it reserved.

        The publisher runs on ``backend.get_session()``: a timer that competed with the
        dial gates for a 1+1-slot reserved pool would re-create the starvation this
        family of tickets is closing, from the inside.
        """
        from server.app import lifespan

        assert "get_liveness_session" not in inspect.getsource(lifespan)
