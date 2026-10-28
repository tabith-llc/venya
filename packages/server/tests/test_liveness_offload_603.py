# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#603 AC1 — the request-path revocation reads run OFF the event loop.

A held ``ACCESS EXCLUSIVE`` lock on ``executor_cert_revocations`` used to park the whole
single-worker core loop: the measured face was 49 seconds with zero access-log lines, and the
shipped 45 s freshness ceiling could never fire on a frozen loop
(``wave29-specs-20261016/flash1-603-tt7-s129-report.md``; re-measured at 57 s in
``wave29-specs-20261016/flash2-603-liveness-offload-s129-report.md`` §5-§6). This file judges the
two sites the leg names, on both halves of the truth table:

* POSITIVE — a real revocation still refuses in its own class, and the offload changes the
  ANSWER not at all.
* NEGATIVE — a stalled or unavailable read is never an all-clear and never a revocation
  assertion; a starved reserved pool raises the classified timeout, propagates, and is logged.
* PLACEMENT — the read runs on a worker thread, on a Session created, used and closed THERE.
  No request-scoped Session is ever handed to a thread (the shipped ``publish_once``
  discipline). The discriminator is the CLASS, not the instance (``middleware/auth.py``),
  so a MagicMock-wired harness keeps the inline read byte-for-byte instead of being moved
  onto a second mock session.

★ THE ACCEPTANCE CLAIM IS THE PAIR IN ``TestLoopAliveBehindARealLock``, and it is not a double.
"The ceiling can fire" means: while one revocation read is PARKED behind a real held
``ACCESS EXCLUSIVE``, the event loop is still running. That is observable only against an engine
with real lock waits, so that class holds a genuine lock from a second connection and measures the
loop with a ticker task — and it runs BOTH faces of the same body, inline on the loop (the
pre-offload shape, which stops the ticker) and off-loop through the shipped seam (which keeps it
firing). Against a mock the claim cannot be made at all: a double returns instantly, the loop never
stalls, and a freeze fix stays green in units while freezing a production core.

Re-land note for the reader who arrives from ``9bcab037f``: that branch was cut BEFORE the #603
bounded seam (``revocation_read.py``) landed, so its header claims about what a stall costs are
restated here against the shipped face — the seam bounds the WAIT, this module moves the read off
the loop, and both are needed (``revocation_offload`` module docstring).
"""

from __future__ import annotations

import asyncio
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import server.routes.executors as ex
from server import revocation_offload
from server.routes.executors import (
    _dial_crl_store_offloaded,
    _incumbent_exemption_offloaded,
    liveness_session_factory,
)
from sqlalchemy.exc import TimeoutError as SQLAlchemyPoolTimeout

PG_URL_ENV = "VENYA_TEST_PG_URL"
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


class _RealFactoryBackend:
    """A Backend-SHAPE double whose CLASS carries the reserved-pool method.

    A bare MagicMock answers any attribute name, which would let an offload cell pass
    without exercising the reservation branch — the same reason
    ``test_liveness_reserved_path_603.py`` subclasses ``Backend`` instead.
    """

    def __init__(self) -> None:
        self.opened_on: int | None = None
        self.closed_count = 0

    def get_liveness_session(self):
        self.opened_on = threading.get_ident()
        session = MagicMock(name="off-loop-session")
        session.close.side_effect = self._note_close
        return session

    def _note_close(self) -> None:
        self.closed_count += 1


def _request_with(backend) -> SimpleNamespace:
    """Minimal ``Request`` face — these sites touch only ``request.app.state.backend``."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(backend=backend)))


_NO_BACKEND = _request_with(None)


def _session_with_revoked_serial() -> MagicMock:
    """A session double whose answers make the REAL revocation order say "serial revoked"."""
    session = MagicMock(name="session")

    def _query(model):
        q = MagicMock()
        name = getattr(model, "__name__", "")
        if name == "ExecutorCertRevocation":
            hit = MagicMock()
            hit.revoked_at = SimpleNamespace()
            q.filter.return_value.first.return_value = hit
        else:
            q.filter.return_value.first.return_value = None
        return q

    session.query.side_effect = _query
    return session


def _ssl_error(code: int) -> Exception:
    exc = Exception("verify failed")
    exc.verify_code = code  # type: ignore[attr-defined]
    return exc


class TestPlacement:
    def test_the_reader_runs_on_a_worker_thread_not_the_calling_loop(self):
        backend = _RealFactoryBackend()
        loop_ident = threading.get_ident()

        async def _run():
            return await revocation_offload.read_off_loop(
                _request_with(backend), lambda session: threading.get_ident(), "unit/placement"
            )

        seen = asyncio.run(_run())
        assert seen != loop_ident, "the read ran on the calling thread — that is the freeze class"
        assert backend.opened_on == seen, "the Session must open on the SAME thread that reads it"

    def test_the_session_is_created_used_and_closed_inside_that_thread(self):
        backend = _RealFactoryBackend()
        read_on: list[int] = []

        async def _run():
            return await revocation_offload.read_off_loop(
                _request_with(backend),
                lambda session: read_on.append(threading.get_ident()) or "value",
                "unit/close",
            )

        assert asyncio.run(_run()) == "value"
        assert backend.closed_count == 1, "an off-loop Session must be closed by its own thread"
        assert backend.opened_on == read_on[0]

    def test_a_faulting_close_does_not_cost_the_value_already_read(self):
        """``publish_once`` discipline, second half: a teardown fault must not replace a result."""
        session = MagicMock()
        session.close.side_effect = OSError("close failed")
        got = revocation_offload.run_off_loop(lambda: session, lambda db: "read-done", "unit/fault")
        assert got == "read-done"


class TestBothNamedSitesOffload:
    def test_site_1_register_exemption_goes_through_the_offload_seam(self, monkeypatch):
        calls: list[str] = []
        real = asyncio.to_thread

        async def _spy(fn, *args, **kwargs):
            calls.append(getattr(fn, "__name__", str(fn)))
            return await real(fn, *args, **kwargs)

        monkeypatch.setattr(ex.asyncio, "to_thread", _spy)
        backend = _RealFactoryBackend()
        session = _session_with_revoked_serial()
        backend.get_liveness_session = lambda: session  # type: ignore[method-assign]

        got = asyncio.run(_incumbent_exemption_offloaded(_request_with(backend), MagicMock(), "exec-1", "abc"))
        assert got is False, "a serial on the revocation list must never read as exempt"
        assert "run_off_loop" in calls, f"expected the offload seam, saw {calls}"

    def test_site_2_dial_store_goes_through_the_offload_seam(self, monkeypatch):
        calls: list[str] = []
        real = asyncio.to_thread

        async def _spy(fn, *args, **kwargs):
            calls.append(getattr(fn, "__name__", str(fn)))
            return await real(fn, *args, **kwargs)

        monkeypatch.setattr(ex.asyncio, "to_thread", _spy)
        seen_store = MagicMock()
        monkeypatch.setattr(ex, "_ensure_dial_crl_store", lambda request, db: "/fake/store", raising=False)
        got = asyncio.run(_dial_crl_store_offloaded(_request_with(_RealFactoryBackend()), seen_store))
        assert got == "/fake/store"
        assert "run_off_loop" in calls, f"expected the offload seam, saw {calls}"
        assert seen_store.query.call_count == 0, "the REQUEST session must not be used for the off-loop read"

    def test_a_mock_backend_keeps_the_inline_read_byte_for_byte(self, monkeypatch):
        """NEGATIVE half of the discriminator: a double with no CLASS-level factory is not
        moved onto a second session — it takes the shipped inline path unchanged."""
        assert liveness_session_factory(_request_with(MagicMock())) is None
        assert liveness_session_factory(_NO_BACKEND) is None

        called: list[tuple] = []

        def _inline(db, executor_id, presented_serial):
            called.append((executor_id, presented_serial))
            return True

        monkeypatch.setattr(ex, "_incumbent_exemption_applies", _inline, raising=False)
        got = asyncio.run(_incumbent_exemption_offloaded(_NO_BACKEND, MagicMock(), "exec-9", "deadbeef"))
        assert got is True
        assert called == [("exec-9", "deadbeef")], "the inline arm must be the one that answered"

    def test_the_offload_is_at_both_named_sites_and_nowhere_else(self):
        """Structural guard for "fails without the offload": the two route arms must DISPATCH
        through the seam, not merely mention it.

        The behaviour cells above cannot see a future edit that reverts a call site to the inline
        function while leaving the wrapper defined — the wrapper would stay covered by its own cells
        and the route would stop using it. This reads the shipped call sites and reddens on that edit.
        """
        import inspect

        register_src = inspect.getsource(ex.register_executor)
        dial_src = inspect.getsource(ex.execute_command_on_executor)
        assert "await _incumbent_exemption_offloaded(" in register_src, (
            "the register arm no longer dispatches the exemption read off the loop — the #603 AC1 "
            "freeze reopens at this site"
        )
        assert "await _dial_crl_store_offloaded(" in dial_src, (
            "the dial arm no longer mints its CRL store off the loop — the #603 AC1 freeze reopens " "at this site"
        )
        # ...and each wrapper still delegates to the ONE implementation, never a second one.
        assert "_incumbent_exemption_applies" in inspect.getsource(_incumbent_exemption_offloaded)
        assert "_ensure_dial_crl_store" in inspect.getsource(_dial_crl_store_offloaded)

    def test_the_calling_site_label_reaches_the_off_loop_read(self):
        """#656's per-site vocabulary survives the hop.

        ``for_site`` writes a ``ContextVar``; ``asyncio.to_thread`` copies the calling context into
        the worker, so a read dispatched off the loop still refuses under the label that asked for it
        instead of the anonymous plane default. This is the shape that would silently re-open the
        counting hole #656 closed, so it is asserted, not assumed.
        """
        from server.revocation_read import current_site, for_site

        async def _run():
            with for_site("unit/label-crosses"):
                assert current_site() == "unit/label-crosses"
                return await revocation_offload.read_off_loop(
                    _request_with(_RealFactoryBackend()), lambda session: current_site(), "unit/label"
                )

        assert asyncio.run(_run()) == "unit/label-crosses"


class TestStarvedPool:
    def test_a_pool_timeout_is_classified_as_a_pool_fault_not_anything_else(self):
        exc = SQLAlchemyPoolTimeout("queue", None, None)  # type: ignore[arg-type]
        assert revocation_offload.is_pool_timeout(exc) is True
        wrapped = RuntimeError("outer")
        wrapped.__cause__ = exc
        assert revocation_offload.is_pool_timeout(wrapped) is True, "the DBAPI wraps — walk the chain"
        assert revocation_offload.is_pool_timeout(ValueError("unrelated")) is False

    def test_a_starved_pool_raises_never_answers_live(self):
        """The bound traded against: exhaustion must be VISIBLE, and must not fabricate an
        all-clear (an empty revocation answer is the most permissive reading possible)."""
        backend = _RealFactoryBackend()

        def _starved():
            raise SQLAlchemyPoolTimeout("queue", None, None)  # type: ignore[arg-type]

        backend.get_liveness_session = _starved  # type: ignore[method-assign]
        with pytest.raises(SQLAlchemyPoolTimeout):
            asyncio.run(
                revocation_offload.read_off_loop(_request_with(backend), lambda db: "ALL CLEAR", "unit/starved")
            )

    def test_the_starved_pool_refusal_is_logged_with_its_site(self, caplog):
        backend = _RealFactoryBackend()

        def _starved():
            raise SQLAlchemyPoolTimeout("queue", None, None)  # type: ignore[arg-type]

        backend.get_liveness_session = _starved  # type: ignore[method-assign]
        with caplog.at_level("WARNING"):
            with pytest.raises(SQLAlchemyPoolTimeout):
                try:
                    asyncio.run(
                        revocation_offload.read_off_loop(_request_with(backend), lambda db: "x", "unit/logged-site")
                    )
                except SQLAlchemyPoolTimeout as exc:
                    revocation_offload.log_pool_timeout("unit/logged-site", exc)
                    raise
        text = caplog.text
        assert "unit/logged-site" in text, "the refusal must name the site it happened at"
        assert revocation_offload.POOL_TIMEOUT_MARKER in text
        assert "NO revocation is asserted" in text


class TestRefusalClassesUnchanged:
    def test_a_stalled_mint_still_raises_into_the_dial_stale_arm(self, monkeypatch):
        """The caller's ``except Exception`` is what turns a raise into the shipped 503; the
        offload must not convert it into an all-clear path."""

        def _boom(request, db):
            raise RuntimeError("generate_crl stalled behind the table lock")

        monkeypatch.setattr(ex, "_ensure_dial_crl_store", _boom, raising=False)
        with pytest.raises(RuntimeError, match="table lock"):
            asyncio.run(_dial_crl_store_offloaded(_request_with(_RealFactoryBackend()), MagicMock()))

    def test_the_named_non_revocation_class_is_one_imported_constant(self):
        """A leg that retypes the refusal sentence is how a revocation-shaped message ends up
        naming an event that never happened. The module owns the one face."""
        assert "no revocation asserted" in ex._STALE_LIST_DETAIL.lower()
        assert (
            ex._STALE_LIST_DETAIL == "Revocation list stale or unavailable — request refused (no revocation asserted)"
        )

    def test_a_real_revocation_is_still_named_revoked_at_the_dial_verdict(self):
        """The positive half of the reject table: code 23 says REVOKED, 3 and 12 never do."""
        revoked = ex._dial_crl_verdict_for(_ssl_error(ex._X509_V_ERR_CERT_REVOKED))
        assert revoked is not None and revoked[1] == 403 and "revoked" in revoked[2].lower()
        for code in (ex._X509_V_ERR_UNABLE_TO_GET_CRL, ex._X509_V_ERR_CRL_HAS_EXPIRED):
            verdict = ex._dial_crl_verdict_for(_ssl_error(code))
            assert verdict is not None and verdict[1] == 503
            assert "revoked" not in verdict[2].lower(), "a LIST-STATE failure must not read as a revocation"


# -------------------------------------------------------------------------------------------
# ★ THE ACCEPTANCE CLAIM, on the shipping engine. See the module docstring for why this cannot
# be made against a double. Door-gated by ``VENYA_TEST_PG_URL``, house deadline on every PG
# connection, self-bounding holder released in a ``finally`` — the three conditions #614/#630's
# interlock enforces on every gated class in this repo.
# -------------------------------------------------------------------------------------------

#: The wait these cells install, in ms. Bounded ON PURPOSE at something a unit run can measure:
#: the fleet face was 49 s, and a cell that waits 49 s is a cell nobody runs. What is under test is
#: WHICH SIDE of the thread boundary absorbs the wait, not how long it is.
_HOLD_DEADLINE_MS = 1500

#: Ticker interval, and the tolerance. At 20 ms a 1.5 s wait admits ~75 beats; the inline face must
#: produce near zero, the off-loop face must produce most of them.
_TICK_SECONDS = 0.02


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"these claims need a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestLoopAliveBehindARealLockPostgresql:
    """A held ``ACCESS EXCLUSIVE`` parks the READ, not the LOOP — measured on both faces.

    1. ``test_the_fixture_lock_really_parks_the_read`` — the capability control. With the lock held,
       the read WAITS (elapsed ≥ most of the deadline) and then refuses inside the shipped bounded
       seam. If this returns in milliseconds the fixture is broken and every cell below is vacuous,
       which is why it runs first and why the other cells re-assert the wait.
    2. ``test_the_inline_read_stops_the_loop_for_the_whole_wait`` — the pre-offload shape. The same
       body run synchronously on the loop starves the ticker: near-zero beats across a wait of
       ~1.5 s. This is the falsifier half; if a future edit makes the offload a no-op this stays true
       and cell 3 goes red.
    3. ``test_the_off_loop_read_keeps_the_loop_serving_during_the_same_wait`` — the claim itself.
       Dispatched through the shipped seam, the ticker keeps firing for the whole wait and the read
       still refuses in the same class. The ANSWER is identical to cell 2; only the loop survived.
    4. ``test_a_seeded_revocation_reads_the_same_off_loop_as_on_it`` — placement changes no answer.
    """

    @staticmethod
    def _engine():
        from sqlalchemy import create_engine

        return create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)

    @staticmethod
    def _session_factory():
        from sqlalchemy.orm import sessionmaker

        engine = TestLoopAliveBehindARealLockPostgresql._engine()
        return sessionmaker(bind=engine)

    @staticmethod
    def _reader(db):
        """ONE revocation-population read, inside the shipped bounded seam.

        The same callable is driven on the loop and off it — that identity is the whole experiment.
        """
        from core.iam.models import ExecutorCertRevocation
        from server.revocation_read import bounded_read

        with bounded_read(db, site="gate/population-under-lock"):
            return db.query(ExecutorCertRevocation).all()

    @classmethod
    def _locked_fixture(cls):
        """Create the population, hold ``ACCESS EXCLUSIVE`` from a second connection.

        Returns ``(engine, holder, teardown)``. The holder is an ordinary connection whose only job
        is the lock; it releases in ``teardown``, which the caller runs in a ``finally``.
        """
        from core.iam.models import Base, ExecutorCertRevocation
        from sqlalchemy import text

        engine = cls._engine()
        Base.metadata.create_all(engine, tables=[ExecutorCertRevocation.__table__])
        holder = engine.connect()
        holder.execute(text("LOCK TABLE executor_cert_revocations IN ACCESS EXCLUSIVE MODE"))

        def teardown() -> None:
            from core.iam.models import Base as _Base

            holder.rollback()
            holder.close()
            engine.dispose()
            _Base.metadata.drop_all(engine, tables=[ExecutorCertRevocation.__table__])

        return engine, holder, teardown

    @staticmethod
    async def _drive_off_loop(factory, reader):
        """Dispatch exactly as the routes do: the shipped body, in a thread, on its OWN Session."""
        return await asyncio.to_thread(revocation_offload.run_off_loop, factory, reader, "gate/under-lock")

    @staticmethod
    async def _drive_inline(factory, reader):
        """The pre-offload shape: the same body, synchronously, on the calling loop."""
        db = factory()
        try:
            return reader(db)
        finally:
            db.close()

    @classmethod
    def _measure(cls, off_loop: bool) -> tuple[int, float, object]:
        """Run one read under a held lock; return (ticker beats, elapsed seconds, outcome).

        Never swallows: an exception is returned as the outcome so the caller asserts its CLASS. A
        cell that hangs is a cell that failed, and the holder's own deadline plus #614's bounded
        connection are what keep that bounded.
        """

        async def _main(factory):
            beats = 0
            stop = asyncio.Event()

            async def _ticker():
                nonlocal beats
                while not stop.is_set():
                    await asyncio.sleep(_TICK_SECONDS)
                    beats += 1

            tick = asyncio.ensure_future(_ticker())
            loop = asyncio.get_running_loop()
            started = loop.time()
            drive = cls._drive_off_loop if off_loop else cls._drive_inline
            try:
                outcome: object = await drive(factory, cls._reader)
            except BaseException as exc:  # recorded, asserted by the caller
                outcome = exc
            elapsed = loop.time() - started
            stop.set()
            await tick
            return beats, elapsed, outcome

        from server.revocation_read import configure_lock_timeout, reset_read_deadline_state

        configure_lock_timeout(_HOLD_DEADLINE_MS)
        factory = cls._session_factory()
        try:
            return asyncio.run(_main(factory))
        finally:
            reset_read_deadline_state()

    def test_the_fixture_lock_really_parks_the_read(self):
        """Capability control: the lock is real, the wait is real, the refusal is the shipped class."""
        from server.revocation_read import RevocationReadUnavailable

        _engine, _holder, teardown = self._locked_fixture()
        try:
            beats, elapsed, outcome = self._measure(off_loop=True)
            assert isinstance(
                outcome, RevocationReadUnavailable
            ), f"a read behind a held ACCESS EXCLUSIVE must raise the bounded-seam refusal, saw {outcome!r}"
            assert elapsed >= _HOLD_DEADLINE_MS / 1000 * 0.6, (
                f"the read answered in {elapsed:.3f}s — the lock was never held or the seam never "
                "waited, so the cells below would prove nothing"
            )
            assert beats >= 1, "the ticker never ran once — the harness is broken, not the product"
        finally:
            teardown()

    def test_the_inline_read_stops_the_loop_for_the_whole_wait(self):
        """The freeze, on the shipping engine: synchronous on the loop, the ticker starves."""
        from server.revocation_read import RevocationReadUnavailable

        _engine, _holder, teardown = self._locked_fixture()
        try:
            beats, elapsed, outcome = self._measure(off_loop=False)
            assert isinstance(outcome, RevocationReadUnavailable), f"expected the bounded refusal, saw {outcome!r}"
            assert elapsed >= _HOLD_DEADLINE_MS / 1000 * 0.6, f"the inline read did not wait ({elapsed:.3f}s)"
            allowed = int(elapsed / _TICK_SECONDS * 0.25)
            assert beats <= max(allowed, 3), (
                f"the inline read kept scheduling the loop through a {_HOLD_DEADLINE_MS} ms wait "
                f"({beats} beats) — this cell's premise is that it cannot, so it has stopped measuring"
            )
        finally:
            teardown()

    def test_the_off_loop_read_keeps_the_loop_serving_during_the_same_wait(self):
        """THE CLAIM. Same body, same lock, same refusal — and the loop never stopped serving."""
        from server.revocation_read import RevocationReadUnavailable

        _engine, _holder, teardown = self._locked_fixture()
        try:
            beats, elapsed, outcome = self._measure(off_loop=True)
            assert isinstance(
                outcome, RevocationReadUnavailable
            ), f"the offload must not change the refusal, saw {outcome!r}"
            assert elapsed >= _HOLD_DEADLINE_MS / 1000 * 0.6, f"the off-loop read did not wait ({elapsed:.3f}s)"
            expected = int(elapsed / _TICK_SECONDS)
            assert beats >= expected * 0.6, (
                f"a parked read off the loop still cost the loop its ticker ({beats} beats over "
                f"{elapsed:.3f}s, expected ~{expected}) — the offload is not keeping the loop free"
            )
        finally:
            teardown()

    def test_a_seeded_revocation_reads_the_same_off_loop_as_on_it(self):
        """No lock held: the same bounded population read answers identically on both faces.

        Placement is the only variable. This reads the ONE population the held-lock cells read
        (``executor_cert_revocations``) rather than driving ``revocation.executor_revocation_state``,
        because that function also queries ``executors`` and a gated cell must not create or drop a
        table a peer's FK depends on inside a schema these cells share — my own first draft of this
        cell had its ``drop_all`` refused by an existing ``execution_sessions`` constraint, which is
        #607's hang class met from the DDL side. The ruled-order half of the parity claim (a revoked
        serial reads NOT-exempt through ``executor_revocation_state``) is the unit face
        ``test_site_1_register_exemption_goes_through_the_offload_seam``, which drives that real
        function against a session double.
        """
        from core.iam.models import Base, ExecutorCertRevocation
        from server.revocation_read import bounded_read
        from sqlalchemy import text

        engine = self._engine()
        Base.metadata.create_all(engine, tables=[ExecutorCertRevocation.__table__])
        factory = self._session_factory()
        # A serial unique to this run: these cells share one schema with every other door-gated
        # file on the venue, and a fixed literal would collide with a peer's row in the same table.
        seed_serial = f"0000{os.getpid():04x}{threading.get_ident() & 0xFFFF:04x}"
        seed = factory()
        try:
            seed.execute(
                text("INSERT INTO executor_cert_revocations (serial_number, revoked_at) " "VALUES (:serial, now())"),
                {"serial": seed_serial},
            )
            seed.commit()

            def _reader_on(db):
                with bounded_read(db, site="gate/parity"):
                    rows = db.query(ExecutorCertRevocation).all()
                return sorted(r.serial_number for r in rows)

            on_loop = asyncio.run(self._drive_inline(factory, _reader_on))
            off_loop = asyncio.run(self._drive_off_loop(factory, _reader_on))
            assert seed_serial in on_loop, f"the seeded revocation is missing on the loop face: {on_loop!r}"
            assert on_loop == off_loop, (
                f"the same read answered differently by thread — {on_loop!r} vs {off_loop!r}; this leg "
                "moves placement, never an answer"
            )
        finally:
            seed.execute(
                text("DELETE FROM executor_cert_revocations WHERE serial_number = :serial"),
                {"serial": seed_serial},
            )
            seed.commit()
            seed.close()
            engine.dispose()
            Base.metadata.drop_all(engine, tables=[ExecutorCertRevocation.__table__])
