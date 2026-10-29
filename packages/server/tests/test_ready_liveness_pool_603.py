# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#603 AC2 residual — the ``/ready`` readiness read takes the RESERVED liveness pool.

Steps 1 and 2 of AC2 reserved the liveness connections (``Backend.LIVENESS_POOL_SIZE``,
``get_liveness_session()``) and moved the executor-mTLS revocation read onto them, but
``routes/health.py`` ``readiness_check()`` kept calling ``backend.get_session()``: the
probe that exists to say "this core can answer" was itself queueing behind business
traffic for one of the shared pool's 15 slots, and reporting ``ok`` whenever it won.

These cells are the behavior contract at that one call site. The sizing contract lives
in ``packages/core/tests/test_liveness_reserved_pool_603.py`` and is not restated here.

No cell opens a database connection or boots a guest: the supplies below are
``Backend`` subclasses whose session methods return doubles, so the assertion is about
WHICH SUPPLY THE ROUTE CHOOSES, which is the whole defect. The physical exhaustion proof
on a deployed core stays an owner-window cell.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from core.engine.backend import KEK_SIZE, Backend, BackendConfig
from fastapi import FastAPI
from starlette.testclient import TestClient

# The shipped QueuePool complaint, as a starved reserved pool raises it. Same string
# shape ``test_liveness_reserved_path_603.py`` uses for its starved supply.
_STARVED = "QueuePool limit of size 1 overflow 1 reached, connection timed out"
_SHARED_STARVED = "QueuePool limit of size 5 overflow 10 reached, connection timed out"


def _session(*, fail: str | None = None) -> MagicMock:
    """A session double that either answers ``SELECT 1`` or raises ``fail``."""
    db = MagicMock(name="session")
    if fail is not None:
        db.execute.side_effect = RuntimeError(fail)
    return db


def _app(backend: object) -> TestClient:
    """Minimal app carrying just what ``readiness_check`` reads off ``app.state``."""
    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    from server.routes import health as health_routes

    health_routes._reset_health_cache()
    app.include_router(health_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


class _ReservingBackend(Backend):
    """A backend that OWNS the reservation — the real ``Backend`` shape.

    ``get_liveness_session`` is defined on the class, so the route's class-form guard
    (``getattr(type(backend), ...)``) resolves and the read moves. ``get_session`` is
    wired to a session that FAILS THE TEST if it is ever consulted, which is what turns
    "the probe moved off the starved path" into an assertion instead of a hope.
    """

    def __init__(self, liveness_db: MagicMock, *, shared_fails: str | None = None) -> None:
        self.config = BackendConfig(database_url="sqlite://", kek=b"k" * KEK_SIZE)
        self._liveness_db = liveness_db
        self._shared = _session(fail=shared_fails)
        self.shared_consulted = False

    def get_liveness_session(self) -> MagicMock:
        return self._liveness_db

    def get_session(self) -> MagicMock:
        self.shared_consulted = True
        return self._shared


class _StarvedReservation(_ReservingBackend):
    """The reserved pool cannot hand out a connection within its short timeout."""

    def get_liveness_session(self) -> MagicMock:
        raise RuntimeError(_STARVED)


class _NonReservingBackend:
    """A supply with NO reservation at all.

    Deliberately not a ``Backend`` subclass — ``Backend`` defines
    ``get_liveness_session``, so any subclass resolves it by inheritance. This is the
    shape of the ~60 server test files that wire a ``MagicMock`` backend, and of any
    duck-typed supply: the route must keep the shipped ``get_session`` path byte-for-byte.
    """

    def __init__(self, shared_db: MagicMock) -> None:
        self._shared = shared_db
        self.shared_calls = 0

    def get_session(self) -> MagicMock:
        self.shared_calls += 1
        return self._shared


class TestReadyTakesTheReservedPool:
    """Positive half: the readiness read runs on the reserved connections."""

    def test_ready_uses_the_reserved_supply(self) -> None:
        backend = _ReservingBackend(_session())
        resp = _app(backend).get("/api/v1/ready")

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "checks": {"database": "connected"}}
        # The tripwire: reaching the shared pool would mean the reservation did not happen.
        assert backend.shared_consulted is False

    def test_ready_answers_while_the_shared_pool_is_exhausted(self) -> None:
        """The paired negative that matters for #603: a full shared pool is not the probe's problem.

        Every shared slot is held by command traffic — the exact condition that made
        ``/ready`` wait, and previously made it answer ``ok`` only by winning a race
        against business queries. The reserved connection is untouched, so readiness
        still reads ``connected``.
        """
        backend = _ReservingBackend(_session(), shared_fails=_SHARED_STARVED)
        resp = _app(backend).get("/api/v1/ready")

        assert resp.status_code == 200
        assert resp.json()["checks"]["database"] == "connected"
        assert resp.json()["status"] == "ok"
        assert backend.shared_consulted is False


class TestReadyWhenTheReservationIsStarved:
    """Negative half: a starved reservation degrades, and never grabs a shared slot.

    This cell OBSERVES the ``else`` fallback rather than trusting its absence: the
    degrade reads ``degraded``/``not_ready`` and asserts the shared supply was never
    consulted, so a future edit that quietly re-adds a shared-pool fallback under
    starvation cannot pass this file by reusing the happy path. That is the trap the
    lead named — the loud-degrade RULE is his to make, and the bytes stay as shipped.
    """

    def test_starved_reservation_degrades(self) -> None:
        backend = _StarvedReservation(_session())
        resp = _app(backend).get("/api/v1/ready")

        assert resp.status_code == 200
        assert resp.json() == {"status": "degraded", "checks": {"database": "not_ready"}}

    def test_starved_reservation_never_falls_back_to_the_shared_pool(self) -> None:
        backend = _StarvedReservation(_session())
        _app(backend).get("/api/v1/ready")

        assert backend.shared_consulted is False, (
            "the readiness probe took a shared-pool slot after its reserved "
            "connection failed — that is the starvation #603 AC2 removes"
        )


class TestDegradeIsACapacityEventNotASecurityEvent:
    """AC3's guarantee at this call site: a capacity fault never reads as a revocation.

    The route has no authz arm at all, so the guarantee here is stated as what the
    response CANNOT say: no revocation wording, no security verdict, an HTTP 200
    degraded body, and the same body for both capacity classes (shared held,
    reservation starved) so nothing about load is reported as trust.
    """

    def test_starved_reservation_body_asserts_no_security_fact(self) -> None:
        body = _app(_StarvedReservation(_session())).get("/api/v1/ready").json()
        text = str(body).lower()

        for banned in ("revoked", "revocation", "unauthorized", "forbidden", "credential"):
            assert banned not in text
        assert body["status"] == "degraded"

    def test_both_capacity_classes_answer_identically(self) -> None:
        """A starved reservation and a starved DB are one class, named by the DB check."""
        starved_reservation = _app(_StarvedReservation(_session())).get("/api/v1/ready").json()
        dead_database = _app(_ReservingBackend(_session(fail="Connection refused"))).get("/api/v1/ready").json()

        assert starved_reservation == dead_database


class TestNoReservationKeepsTheShippedPath:
    """Zero behavior delta for a supply that never had a reservation."""

    def test_non_reserving_backend_uses_the_shared_path(self) -> None:
        shared = _session()
        backend = _NonReservingBackend(shared)
        resp = _app(backend).get("/api/v1/ready")

        assert resp.status_code == 200
        assert resp.json()["checks"]["database"] == "connected"
        assert backend.shared_calls == 1

    def test_a_mock_backend_still_takes_the_shared_path(self) -> None:
        """The class-form guard, proven on the shape that would defeat an instance lookup.

        ``MagicMock`` ANSWERS any attribute on the INSTANCE, so ``getattr(backend,
        "get_liveness_session")`` would be callable and move these cells onto a second
        mock session. ``type(backend)`` does not carry it, which is why the shipped
        middleware discriminates on the class — this cell guards that choice here too.
        """
        shared_db = _session()
        backend = MagicMock()
        backend.get_session.return_value = shared_db
        assert callable(getattr(type(backend), "get_liveness_session", None)) is False

        resp = _app(backend).get("/api/v1/ready")

        assert resp.json()["checks"]["database"] == "connected"
        backend.get_session.assert_called_once()
        backend.get_liveness_session.assert_not_called()


class TestOneCallSite:
    """The reservation is not duplicated at this site (the shipped file has one)."""

    def test_ready_holds_a_single_session_acquisition(self) -> None:
        import inspect

        from server.routes.health import readiness_check

        source = inspect.getsource(readiness_check)
        # Count CALLS, not mentions — the docstring above names the accessor on
        # purpose, and a guard that counted mentions would redden on prose.
        assert source.count("get_liveness_session()") == 1
        assert source.count("get_session()") == 1
        # And no second engine is built here — this leg consumes ``befd90c``, it does
        # not re-implement it.
        assert "create_engine" not in source
