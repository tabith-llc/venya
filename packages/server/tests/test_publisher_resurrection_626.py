# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#626 — the revocation-snapshot publisher survives an escaped tick, and says what ended it.

The row: the step-2 publisher is ONE ``asyncio`` task, its ``finally`` disarmed unconditionally,
and nothing in-process re-armed it. Failure stayed safe — the poll falls back to the shipped live
read — so the gap was resurrection and evidence, not the fail-closed door. And the trigger is
narrower than "the database is down": ``publish_once`` already absorbs its own read failures, but a
``close()`` that faults in that function's ``finally`` sits OUTSIDE the ``except Exception`` beside
it, and a raise in a ``finally`` also replaces whatever the ``try`` returned. One bad teardown
therefore cost a good population AND the task, with a WARNING that latches once per process as the
only trace, ever.

Ruled shape (a) — retry the tick behind a bounded backoff, in the loop, no respawn — plus the
root-cause guard on the teardown itself. Cell map, both halves of every gate:

* TT-A  a faulting teardown ``close()`` loses neither the published population nor the task
* TT-B  a raise that still escapes the tick is retried on the SAME task; ``arm`` runs exactly once
* TT-C  the retry costs a doubling nap capped below the freshness ceiling — never a burst
* TT-D  PAIRED NEGATIVE for TT-A/TT-B: a read/checkout failure is still absorbed inside
        ``publish_once`` and never reaches the retry branch (step 2's TT3 half, unregressed)
* TT-E  PAIRED NEGATIVE (#626 AC2): an armed publisher whose snapshot ages out REFUSES in the
        shipped stale 503 class and carries no population
* TT-F  PAIRED NEGATIVE (#626 AC2): a publisher that is gone answers the CURRENT live population,
        never a stale one, never an empty one
* TT-G  #626 AC3, both halves: never-armed, shutdown-cancelled and died-at-runtime are three
        distinguishable journal states, and the un-latched-noise guard still holds
* TT-H  #626 AC5: the lifespan's cancel still disarms and is never logged as a death
* TT-I  the numbers #603 owns (45/10) and the numbers this row owns (1.0/30.0) are pinned apart,
        and the retry path reads the ordinary pool it was handed (step 1's reserved pair untouched)

Real SQLite plus the mounted router, precedent ``test_revocation_snapshot_603.py``. Where a cell
needs the retry SCHEDULE as data instead of as wall-clock time, the loop's own ``asyncio`` name is
swapped for a recorder — the same technique that file uses to swap ``time`` for a fake clock. Both
are attributes of ``revocation_snapshot``, so the patch never reaches the loop the test is running,
and the recorder passes ``to_thread`` through to the real module because the worker-thread offload
is itself part of what is under test.
"""

import asyncio
import logging
from unittest.mock import MagicMock

import pytest
from core.iam.models import Base, ExecutorCertRevocation, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server import revocation_snapshot as rs
from server.config import ServerConfig
from server.dependencies import get_backend
from server.routes import executors as executors_routes
from server.routes.executors import _STALE_LIST_DETAIL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

POLL_PATH = "/api/v1/executors/certs/revocation-list"

CEILING = rs.REVOCATION_SNAPSHOT_MAX_AGE_SECONDS
REFRESH = rs.REVOCATION_SNAPSHOT_REFRESH_SECONDS
RETRY_BASE = rs.REVOCATION_SNAPSHOT_RETRY_BACKOFF_SECONDS
RETRY_MAX = rs.REVOCATION_SNAPSHOT_RETRY_BACKOFF_MAX_SECONDS

UNARMED_MARK = "snapshot publisher is not running"
ESCAPE_MARK = "escaped its own guard"
TEARDOWN_MARK = "could not close its session"
DEATH_MARK = "publisher stopped unexpectedly"
CANCEL_MARK = "shutdown cancel"
RECOVER_MARK = "recovered after"
ABSORB_MARK = "publish failed"


class _Fatal(BaseException):
    """Not an ``Exception`` — the class the tick guard deliberately does NOT swallow."""


class _CloseFaultySession:
    """Reads through to a real session, then faults on teardown the way the row says it does.

    ``close()`` first closes the session's own DBAPI connection and then calls the SHIPPED
    ``Session.close()``, so the raise comes out of SQLAlchemy's rollback path
    (``sqlalchemy.exc.ProgrammingError`` — measured: "Cannot operate on a closed database"), not
    from a stub that throws a canned error. That is the difference between a cell that pins the
    mechanism and one that pins its own fixture, and #626 AC4 asks for the class.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def query(self, *args, **kwargs):
        return self._inner.query(*args, **kwargs)

    def close(self):
        self._inner.connection().connection.dbapi_connection.close()
        return self._inner.close()  # the shipped close, now rolling back against a dead handle


class _Recorder:
    """Stand-in for the ``asyncio`` attribute of ``revocation_snapshot``.

    ``sleep`` records each requested nap and yields without spending it, so a retry schedule reads
    as data. ``to_thread`` and ``CancelledError`` pass through to the real module: the offload and
    the cancel class are part of what is under test, and faking either would let a cell pass
    against its own fixture.
    """

    CancelledError = asyncio.CancelledError

    def __init__(self) -> None:
        self.naps: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.naps.append(seconds)
        await asyncio.sleep(0)

    def to_thread(self, fn, *args):
        return asyncio.to_thread(fn, *args)


class _FakeClock:
    """The ``time`` attribute inside ``revocation_snapshot`` only — moves when a cell says so."""

    def __init__(self, mono: float = 1_000.0) -> None:
        self.mono = mono

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.mono += seconds


@pytest.fixture()
def clock(monkeypatch):
    fake = _FakeClock()
    monkeypatch.setattr(rs, "time", fake)
    return fake


@pytest.fixture()
def recorder(monkeypatch):
    fake = _Recorder()
    monkeypatch.setattr(rs, "asyncio", fake)
    return fake


@pytest.fixture()
def env(tmp_path):
    """Real-SQLite app with the executors router mounted and no publisher started."""
    engine = create_engine(f"sqlite:///{tmp_path / 'resurrect626.db'}")
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
    """Process-global state: no cell may inherit another's snapshot, latch, or running flag."""
    rs.reset_snapshot_state()
    yield
    rs.reset_snapshot_state()


@pytest.fixture()
def tiny_windows(monkeypatch):
    """Milliseconds instead of seconds, for the cells that wait on a real event loop.

    The ceiling is deliberately NOT shrunk: TT-E's refusal depends on the ruled 45 s window, and a
    cell that moved the number it is checking would be testing its own fixture.
    """
    monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_REFRESH_SECONDS", 0.005)
    monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_RETRY_BACKOFF_SECONDS", 0.005)
    monkeypatch.setattr(rs, "REVOCATION_SNAPSHOT_RETRY_BACKOFF_MAX_SECONDS", 0.02)


def _seed_revocation(SessionLocal, serial: str, executor_id: str = "exec-a") -> None:
    s = SessionLocal()
    try:
        s.add(ExecutorCertRevocation(serial_number=serial, executor_id=executor_id, reason="admin"))
        s.commit()
    finally:
        s.close()


def _publish(SessionLocal) -> rs.RevocationSnapshot:
    """One real publish against the seeded population, armed first (the shipped order)."""
    rs.arm_publisher()
    s = SessionLocal()
    try:
        return rs.publish_snapshot(s)
    finally:
        s.close()


def _lines(caplog, needle: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if needle in r.getMessage()]


async def _drive_loop(factory, watch, *, timeout: float = 2.0):
    """Run the SHIPPED loop as one task until ``watch(state)`` says stop, then cancel it.

    ``watch`` is called with the live task after every poll interval and may return one of the
    strings ``"stop"`` (leave the loop alone; the cell wants it running) or ``"done"``; the return
    value records whether the task was still alive when the cell released it. The cancel is the
    shape ``app.py`` uses, so the shutdown path stays under test in every cell rather than being
    stepped around.
    """
    task = asyncio.create_task(rs.revocation_snapshot_loop(factory))
    outcome = {"alive": False, "waited": 0.0}
    step = 0.002
    while outcome["waited"] < timeout:
        await asyncio.sleep(step)
        outcome["waited"] += step
        alive = not task.done()
        outcome["alive"] = alive
        if watch(task) == "done":
            break
        if not alive:
            break
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return outcome["alive"]


class TestTTATeardownFault:
    def test_a_faulting_close_does_not_cost_the_published_population(self, env, caplog):
        """TT-A first half, at the function that owns it.

        The swap happens in the ``try``; the ``close()`` faults in the ``finally``. Before #626 the
        raise replaced the return, so the caller got an exception and the population that had
        ALREADY been published went unannounced with the task. Asserted as the return value
        surviving, because that is what a reader of the snapshot actually depends on.
        """
        _, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006260")
        inner = SessionLocal()

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            snapshot = rs.publish_once(lambda: _CloseFaultySession(inner))

        assert snapshot is not None, "a faulting teardown discarded a good population"
        assert list(snapshot.serials) == ["0000000000006260"]
        assert rs.current_snapshot() is snapshot, "the swap must stand when close() faults"
        lines = _lines(caplog, TEARDOWN_MARK)
        assert len(lines) == 1, lines
        assert "#626" in lines[0]
        # AC4 asks which class the guard now covers, by name. The fixture does not invent one:
        # this is SQLAlchemy's own rollback-on-close error, an ``Exception`` descendant, which is
        # exactly the family the guard takes and ``CancelledError`` is not.
        assert "ProgrammingError" in lines[0], lines[0]

    def test_a_faulting_close_does_not_end_the_task_or_reach_the_retry_branch(self, env, tiny_windows, caplog):
        """TT-A second half, through the shipped path: worker thread, teardown raise, task alive.

        Two claims, and the second is what separates the root-cause fix from the belt: the fault is
        absorbed where it happens, so the loop's retry branch never fires and no backoff is spent.
        Asserted as an absence in the journal, not as a hope.
        """
        _, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006261")

        def _faulty_teardown():
            return _CloseFaultySession(SessionLocal())

        def _watch(_task):
            return "done" if rs.current_snapshot() is not None else "again"

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            alive = asyncio.run(_drive_loop(_faulty_teardown, _watch))

        assert alive is True, "a teardown close() fault ended the publisher — #626 unfixed"
        published = rs.current_snapshot()
        assert published is not None and list(published.serials) == ["0000000000006261"]
        assert len(_lines(caplog, TEARDOWN_MARK)) >= 1
        assert _lines(caplog, ESCAPE_MARK) == [], "an absorbed teardown fault must not read as an escape"
        assert rs.publisher_running() is False, "the cancel still disarms (the shutdown shape)"


class TestTTBEscapeIsRetriedInPlace:
    def test_a_raise_that_escapes_the_tick_keeps_the_one_task_alive(self, tiny_windows, caplog, monkeypatch):
        """TT-B: the belt behind the belt, and the arm count is the no-respawn proof.

        ``publish_once`` is replaced by something that always raises an ``Exception`` — the state
        the row says used to be terminal — then cleared mid-run. Three claims: the task never
        finished, ``arm`` ran EXACTLY ONCE across all those escapes (a second arm would mean a
        respawn, which #626 AC5 forbids and which would also re-open the live-read fallback under a
        task that already owned the read), and the plane recovered on its own when the fault
        cleared. One task, start to finish — the cell never restarts it.
        """
        arms: list[str] = []
        attempts: list[int] = []
        state = {"failing": True}
        original_arm = rs.arm_publisher

        def _counting_arm():
            arms.append("arm")
            original_arm()  # the shipped arm, counted — not a re-implementation of it

        def _tick(_factory):
            attempts.append(1)
            if state["failing"]:
                raise OSError("descriptor gone — something publish_once did not absorb")
            return rs.publish_populations(["0000000000006262"], [])

        monkeypatch.setattr(rs, "arm_publisher", _counting_arm)
        monkeypatch.setattr(rs, "publish_once", _tick)

        def _watch(_task):
            if not state["failing"]:
                return "done" if rs.current_snapshot() is not None else "again"
            if len(attempts) >= 4:
                state["failing"] = False
            return "again"

        with caplog.at_level(logging.INFO, logger="venya.server"):
            alive = asyncio.run(_drive_loop(lambda: None, _watch))

        assert alive is True, "an escaped tick ended the task — the #626 defect, unfixed"
        assert arms == ["arm"], f"arm ran {arms} — a second arm is a respawn, not a retry"
        assert len(attempts) >= 5, f"only {len(attempts)} attempts; the loop stopped trying"
        assert rs.current_snapshot() is not None, "the plane never recovered after the fault cleared"
        escape_lines = _lines(caplog, ESCAPE_MARK)
        assert len(escape_lines) >= 4, escape_lines
        assert all("#626" in line and "RETRYING" in line for line in escape_lines)
        assert _lines(caplog, RECOVER_MARK), "recovery is silent; AC3 wants the end of a fault findable"


class TestTTCCostOfARetry:
    def test_the_backoff_doubles_and_holds_below_the_freshness_ceiling(self, recorder, monkeypatch):
        """TT-C: a persistent fault costs one retry per growing nap, capped. #626 AC5, measured.

        The naps are read as data from the recorder, not inferred from elapsed time: 1, 2, 4, 8,
        16, then held at the 30 s cap. None zero (a free spin against a pool that is already sick),
        none at or above the 45 s ceiling (which would let a stalled publisher sit past the window
        it exists to fill).
        """

        def _always_escapes(_factory):
            raise OSError("persistent fault under test")

        monkeypatch.setattr(rs, "publish_once", _always_escapes)

        async def _drive():
            task = asyncio.create_task(rs.revocation_snapshot_loop(lambda: None))
            for _ in range(3000):
                await asyncio.sleep(0.001)
                if len(recorder.naps) >= 7:
                    break
            assert not task.done(), "the loop died instead of retrying (#626 unfixed)"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_drive())
        assert recorder.naps[:7] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0], recorder.naps[:7]
        assert all(nap > 0 for nap in recorder.naps), "a zero nap is a retry storm"
        assert max(recorder.naps) == RETRY_MAX < CEILING


class TestTTDReadFailureStaysAbsorbed:
    def test_a_starved_checkout_never_reaches_the_retry_branch(self, recorder, env, caplog):
        """TT-D: step 2's TT3 half, re-pinned here so this change cannot regress it.

        A failure inside ``publish_once``'s ``try`` is that function's business: it returns ``None``,
        the tick comes back normal, and the cadence stays the ruled refresh. Asserted on the nap
        SET — every nap is ``REFRESH`` and not one backoff value appears — because a retry branch
        that swallowed this path would look like survival while silently changing what a pool stall
        costs. The shipped absorb line must still be there, per attempt.
        """
        _, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006263")
        calls: list[int] = []

        def _no_connection():
            calls.append(1)
            raise RuntimeError("reserved pool exhausted: no connection within the checkout timeout")

        async def _drive():
            task = asyncio.create_task(rs.revocation_snapshot_loop(_no_connection))
            for _ in range(3000):
                await asyncio.sleep(0.001)
                if len(calls) >= 4:
                    break
            alive = not task.done()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return alive

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            alive = asyncio.run(_drive())

        assert alive is True
        assert len(calls) >= 4
        assert set(recorder.naps) == {float(REFRESH)}, recorder.naps
        assert _lines(caplog, ESCAPE_MARK) == []
        assert len(_lines(caplog, ABSORB_MARK)) >= 4, "the shipped absorb path must still be loud"


class TestTTETheDoorIsUntouched:
    def test_an_armed_publisher_whose_snapshot_ages_out_refuses_in_the_stale_class(self, env, clock):
        """TT-E (#626 AC2's paired negative): survival must not become a stale answer.

        The plane is armed with a real population and nothing further is published — exactly what a
        run of escaped ticks looks like from the reader's side. Inside the ceiling the population is
        served; AT the ceiling the poll refuses with the shipped detail and carries no population at
        all. That door is #603's, ruled ``>=`` by the owner; this cell says this row did not move it.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006264")
        _publish(SessionLocal)
        assert rs.publisher_running() is True

        clock.advance(CEILING - 1)
        inside = client.get(POLL_PATH)
        assert inside.status_code == 200
        assert inside.json()["revoked_serials"] == ["0000000000006264"]

        clock.advance(1)
        refused = client.get(POLL_PATH)
        assert refused.status_code == 503
        assert refused.json()["detail"] == _STALE_LIST_DETAIL
        assert "revoked_serials" not in refused.json(), "a refusal must not carry a population"


class TestTTFDeadPublisherAnswersCurrent:
    def test_a_publisher_that_is_gone_answers_the_current_live_population(self, env):
        """TT-F (#626 AC2): the owner's accepted reading — degrade to the SHIPPED live read.

        A revocation seeded AFTER the publisher let go must still appear. That is what makes the
        fallback safe, and it is the property a "fix" that kept serving the last snapshot instead
        would quietly destroy. Never empty, never stale: an empty population IS "nothing revoked".
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006265")
        _publish(SessionLocal)
        rs.disarm_publisher()
        _seed_revocation(SessionLocal, "0000000000006266", executor_id="exec-b")

        resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        body = resp.json()
        assert body["revoked_serials"] == ["0000000000006265", "0000000000006266"], body
        assert body["revoked_serials"] != [], "an empty population IS 'nothing revoked'"


class TestTTGThreeExitsAreDistinguishable:
    def test_never_armed_and_died_at_runtime_are_not_the_same_journal(self, env, caplog, monkeypatch):
        """TT-G first half (#626 AC3): the row's complaint, answered as two different journals.

        A process that never armed a publisher says "is not running" once and nothing else. A
        process whose publisher DIED says that line too — but beside an ERROR that names the class
        and the consequence. The two are tellable apart after the fact, which is exactly what the
        single latched WARNING never allowed.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006267")

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            client.get(POLL_PATH)
        assert len(_lines(caplog, UNARMED_MARK)) == 1
        assert _lines(caplog, DEATH_MARK) == [], "a process that never armed one cannot have lost it"
        caplog.clear()

        def _fatal(_factory):
            raise _Fatal("out-of-band kill under test")

        monkeypatch.setattr(rs, "publish_once", _fatal)

        async def _drive():
            task = asyncio.create_task(rs.revocation_snapshot_loop(lambda: None))
            try:
                await task
            except _Fatal:
                return "ended"
            return "still-running"

        with caplog.at_level(logging.INFO, logger="venya.server"):
            outcome = asyncio.run(_drive())

        assert outcome == "ended", "a non-Exception escape was swallowed — survival beyond the ruled class"
        assert rs.publisher_running() is False, "the finally still disarms on a death"
        deaths = _lines(caplog, DEATH_MARK)
        assert len(deaths) == 1, deaths
        assert "_Fatal" in deaths[0], "the stoppage line must name what ended the task"
        assert "#626" in deaths[0] and "live-read path" in deaths[0]

        # And the poll after the death is still the SHIPPED fallback: current answer, and the
        # one line the row itself latches — the death line above is what makes this process
        # readable, the fallback line is deliberately not repeated.
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            resp = client.get(POLL_PATH)
        assert resp.status_code == 200
        assert resp.json()["revoked_serials"] == ["0000000000006267"], resp.json()
        assert len(_lines(caplog, UNARMED_MARK)) == 0, "the fallback latch must still be a latch"

    def test_the_fallback_still_warns_once_not_per_poll(self, env, caplog):
        """TT-G second half (#626 AC3's paired negative): the latch the row shipped stands.

        The fix cannot be "log every poll". Three polls on a disarmed plane, one line — the guard the
        module comment records on purpose, still standing beside the new retry branch.
        """
        client, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006268")
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            for _ in range(3):
                client.get(POLL_PATH)
        assert len(_lines(caplog, UNARMED_MARK)) == 1


class TestTTHShutdownStaysClean:
    def test_the_lifespan_cancel_disarms_and_is_never_logged_as_a_death(self, env, caplog, tiny_windows):
        """TT-H (#626 AC5): the intended exit stays intended, and stays quiet.

        ``app.py`` cancels this task on every core shutdown. If that path printed the death line,
        the alarm this row exists to add would arrive once per boot and be ignored — so the cancel
        is INFO and the death is ERROR, and this cell is the half that keeps them apart.
        """
        _, SessionLocal = env
        _seed_revocation(SessionLocal, "0000000000006269")
        _publish(SessionLocal)
        assert rs.publisher_running() is True

        async def _drive():
            task = asyncio.create_task(rs.revocation_snapshot_loop(SessionLocal))
            await asyncio.sleep(0.02)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with caplog.at_level(logging.INFO, logger="venya.server"):
            asyncio.run(_drive())

        assert rs.publisher_running() is False, "the shutdown cancel must still release the read"
        assert _lines(caplog, DEATH_MARK) == [], "a clean shutdown wrote a stoppage line"
        assert len(_lines(caplog, CANCEL_MARK)) == 1


class TestTTINumbersAndPoolsStayApart:
    def test_the_pair_603_owns_and_the_pair_this_row_owns_are_pinned_apart(self):
        """TT-I first half: four numbers, two owners, one cell.

        45/10 is the ruled freshness contract (#603 AC2, the owner's boundary ruling); 1.0/30.0 is
        this row's retry cost. Both are pinned here because a later leg that "tidied" the ceiling
        while touching the publisher would pass every behavioural cell in this file and still break
        the gate.
        """
        assert (CEILING, REFRESH) == (45, 10), (CEILING, REFRESH)
        assert (RETRY_BASE, RETRY_MAX) == (1.0, 30.0), (RETRY_BASE, RETRY_MAX)
        assert RETRY_BASE <= RETRY_MAX < CEILING, "a retry nap at or past the ceiling is a different rule"
        rs.validate_snapshot_windows()

    def test_the_retry_path_reads_the_factory_it_was_handed(self, monkeypatch):
        """TT-I second half (#626 AC5): step 1's reserved 1+1 pair is not this row's to spend.

        Every attempt, first or hundredth, goes through the SAME factory the loop received —
        ``backend.get_session`` on the shipped boot path. A retry that swapped in its own source
        would put a periodic timer onto the pool step 1 reserved for the request-path reads that
        still exist, and the two reserved slots are exactly what that pool is.
        """
        seen: list[object] = []
        marker = object()

        def _spy(factory):
            seen.append(factory)
            raise _Fatal("stop the loop after the ticks under test")

        monkeypatch.setattr(rs, "publish_once", _spy)

        async def _drive():
            task = asyncio.create_task(rs.revocation_snapshot_loop(marker))  # type: ignore[arg-type]
            for _ in range(2000):
                await asyncio.sleep(0.001)
                if seen:
                    break
            task.cancel()
            try:
                await task
            except _Fatal:
                pass

        asyncio.run(_drive())

        assert seen, "the loop never called through the factory it was given"
        assert all(f is marker for f in seen), "the publisher substituted its own session source"
