# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#603 AC2 step 1 (a′-i) — the reserved liveness path, truth table.

The reservation moves the executor-mTLS revocation read onto the ``Backend``
reserved connections. Everything here judges the two halves of that gate:

* what MUST still be refused stays refused, byte-identically (a real serial-on-list
  revocation still answers 403 with the shipped body); and
* what must NEVER be claimed is never claimed — a capacity fault is not a
  revocation, so a starved reservation refuses with the shipped raise → 500 shape
  and never with the 403 that ``daemon.py:319`` reads as permanent.

Test doubles are ``Backend`` SUBCLASSES throughout. The middleware discriminates on
``type(backend)`` (see the comment at the seam in ``middleware/auth.py``), and a
bare ``MagicMock`` answers any attribute name — an instance-level double would have
let the cells pass without exercising the real reservation branch.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.engine.backend import KEK_SIZE, Backend, BackendConfig
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.middleware.auth import SessionMiddleware

# NOTE: ``Request`` must be a MODULE-level import. This file uses
# ``from __future__ import annotations``, so route-handler annotations arrive as
# strings and FastAPI resolves them against module globals — a function-local import
# is invisible there, and the parameter silently degrades to a required query arg
# (the 422 this cell produced on first run).
from starlette.requests import Request

# The shipped refusal body on this path, verbatim at 8d46a01
# (middleware/auth.py:762). Byte-identity anchor for the positive half.
SHIPPED_403_DETAIL = "Executor mTLS authentication required"


def _query_db(row_factory):
    """A session double that dispatches by model name, like the shipped helper.

    Mirrors ``test_session_middleware.py::_make_executor_backend`` exactly, so the
    revocation verdict these cells observe is produced by the real
    ``server/revocation.py`` order and not by a stub of it.
    """
    db = MagicMock(name="session")

    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value.first.return_value = row_factory(getattr(model, "__name__", ""))
        return q

    db.query.side_effect = query_side_effect
    return db


class _ReservingBackend(Backend):
    """A Backend that OWNS a reserved pool — the real reservation branch.

    ``get_liveness_session`` is inherited from the class, so
    ``type(backend).get_liveness_session`` resolves and the middleware takes the
    reserved path. ``get_session`` (the shared pool) is wired to a session that
    FAILS THE TEST if it is ever consulted, which is what makes "the read moved"
    an assertion rather than a hope.
    """

    def __init__(self, liveness_db) -> None:
        self.config = BackendConfig(database_url="sqlite://", kek=b"k" * KEK_SIZE)
        self._liveness_db = liveness_db
        # Shared-pool tripwire: reaching it means the reservation did not happen.
        self._shared = _query_db(lambda _n: pytest.fail("shared pool served the liveness read"))

    def get_liveness_session(self):
        return self._liveness_db

    def get_session(self):
        return self._shared


class _NonReservingBackend:
    """A supply with NO reservation — the degrade half of the gate.

    Deliberately NOT a ``Backend`` subclass: ``Backend`` now defines
    ``get_liveness_session``, so any subclass resolves it through inheritance and
    takes the reserved branch unconditionally. The degrade path is for supplies
    that never had a reservation at all — which is precisely the shape of the 60
    existing mock-wired server test files (and any duck-typed backend), where
    ``type(backend)`` does not carry the method.
    """

    def __init__(self, shared_db) -> None:
        self._shared = shared_db

    def get_session(self):
        return self._shared


class _StarvedBackend(_ReservingBackend):
    """Reserved pool cannot be created / no connection checkable out."""

    def get_liveness_session(self):
        raise RuntimeError("QueuePool limit of size 1 overflow 1 reached, connection timed out")


def _rows(revoked_at=None, crl_serial=None):
    """(executor row, cert row, crl row) — the three tables the read touches."""

    def factory(name):
        if name == "Executor":
            return SimpleNamespace(id="venya-exec-1", revoked_at=revoked_at)
        if name == "ExecutorCert":
            return SimpleNamespace(serial_number="0000000000000001")
        if name == "ExecutorCertRevocation":
            if crl_serial is None:
                return None
            return SimpleNamespace(serial_number=crl_serial, revoked_at=revoked_at)
        return None

    return factory


@pytest.fixture
def cert_material(tmp_path):
    """Real CA-signed leaf + the inner-mTLS headers + the CA, via the shipped helpers.

    Module-scoped on purpose: both truth-table classes below drive the same guarded
    path. ``_exec_cert`` builds its own Root CA internally (serial 2 here, so the
    serial-history branch is the one under test) and ``_fwd`` writes the
    forwarded-cert file the middleware reads.
    """
    from .test_session_middleware import TestExecutorSessionPathAuth

    harness = TestExecutorSessionPathAuth()
    cert = harness._exec_cert(tmp_path, serial=2)
    # The middleware verifies the presented cert against the CA on app.state — the
    # shipped harness puts ``_root_ca(tmp_path)[0]`` there, and ``_exec_cert`` signs
    # with that same CA out of the same tmp_path.
    return cert, harness._fwd(tmp_path, cert), harness._root_ca(tmp_path)[0]


def _app(backend, ca_manager=None):
    """App with SessionMiddleware + one guarded stub route (module-level: both
    truth-table classes drive it)."""
    from server.config import InnerTLSConfig, ServerConfig

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(
        recovery_code_pepper="test-pepper",
        admin_mtls={"enabled": False},
        inner_mtls=InnerTLSConfig(
            enabled=True,
            cert_file="/test/inner.crt",
            key_file="/test/inner.key",
            client_ca_file="/test/inner-ca.crt",
        ),
    )
    if ca_manager is not None:
        app.state.ca_manager = ca_manager
    if backend is not None:
        app.state.backend = backend

    @app.post("/api/v1/sessions/{session_id}/filter")
    def filter_stub(request: Request):
        return {"user": getattr(request.state, "auth_user", None)}

    return app


class TestReservedPathTruthTable:
    """The gate, both halves, on the reserved connections."""

    def test_positive_serial_on_list_revocation_still_403(self, tmp_path, cert_material):
        """TRUTH TABLE 1 (the half the owner required in this changeset): a genuine
        serial-on-list revocation on the RESERVED path still answers the shipped 403
        — same status, same byte-for-byte body. A reservation that stopped refusing
        would be a fail-open, and this cell is what catches it."""
        _cert, headers, ca = cert_material
        db = _query_db(_rows(crl_serial="0000000000000002"))
        app = _app(_ReservingBackend(db), ca_manager=ca)

        resp = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""}, headers=headers
        )

        assert resp.status_code == 403
        assert resp.json() == {"detail": SHIPPED_403_DETAIL}
        # The read happened on the RESERVED session, and never on the shared pool.
        assert db.query.call_count > 0

    def test_unrevoked_passes_on_the_reserved_path(self, tmp_path, cert_material):
        """TRUTH TABLE 2: a clean credential gets its normal answer — the
        reservation added no new refusal."""
        _cert, headers, ca = cert_material
        db = _query_db(_rows())
        app = _app(_ReservingBackend(db), ca_manager=ca)

        resp = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""}, headers=headers
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["user"] == {
            "caller": "executor",
            "executor_id": "venya-exec-1",
            "presented_serial": "0000000000000002",
            "revoked": False,
        }

    def test_starved_reservation_refuses_and_never_claims_revocation(self, tmp_path, cert_material):
        """TRUTH TABLE 4: no connection on the reserved pool → FAIL CLOSED.

        Asserts both directions of the owner's condition: the request is NOT allowed
        (no 2xx, no auth_user), and the refusal is NOT the 403 revocation class —
        ``daemon.py:319`` treats 403 as permanent, so a 403 here would turn a
        capacity blip into a credential kill and assert a revocation that never
        happened.
        """
        _cert, headers, ca = cert_material
        app = _app(_StarvedBackend(_query_db(_rows())), ca_manager=ca)

        resp = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""}, headers=headers
        )

        assert resp.status_code == 500, resp.text
        assert resp.status_code != 403
        assert SHIPPED_403_DETAIL not in resp.text
        assert "revoked" not in resp.text.lower()

    def test_no_silent_allow_when_the_pool_cannot_be_checked_out(self, tmp_path, cert_material):
        """TRUTH TABLE 4b, stated as its own cell because it is the dangerous half:
        the route body must never run when revocation could not be confirmed."""
        _cert, headers, ca = cert_material
        app = _app(_StarvedBackend(_query_db(_rows())), ca_manager=ca)

        resp = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""}, headers=headers
        )

        # The stub route answers {"user": None} when the middleware allowed without
        # setting identity, and never runs at all on a raised refusal.
        assert resp.status_code == 500
        assert "user" not in resp.text


class TestDegradeWhenNoReservation:
    """The zero-behavior-delta half: a backend without a reservation is unchanged."""

    def test_non_reserving_backend_uses_the_shared_path(self, tmp_path, cert_material):
        """TRUTH TABLE 2/1 on the DEGRADE path: ``get_session`` serves the read and
        the 403 is still byte-identical. This is the shape every pre-existing
        mock-wired server test rides, and it must not change."""
        _cert, headers, ca = cert_material
        db = _query_db(_rows(crl_serial="0000000000000002"))
        app = _app(_NonReservingBackend(db), ca_manager=ca)

        resp = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/sessions/1/filter", json={"stdout": "", "stderr": ""}, headers=headers
        )

        assert resp.status_code == 403
        assert resp.json() == {"detail": SHIPPED_403_DETAIL}
        assert db.query.call_count > 0


class TestNoSecondImplementation:
    """TRUTH TABLE 5: the matching logic gained no second copy and no new caller."""

    def test_revocation_module_still_has_one_implementation(self):
        import inspect

        from server import revocation

        # One public entry point for executor revocation state — the module contract
        # comment names a second implementation as the rotation/revocation split-brain.
        public = [
            name
            for name, obj in vars(revocation).items()
            if callable(obj) and getattr(obj, "__module__", "") == revocation.__name__ and "revocation_state" in name
        ]
        assert public == ["executor_revocation_state"]

        # Signature unchanged: the reservation moved the SESSION, never the call.
        params = list(inspect.signature(revocation.executor_revocation_state).parameters)
        assert params == ["db", "executor_id", "presented_serial", "executor_row"]

    def test_middleware_still_holds_the_single_call_site(self):
        """``executor_revocation_state`` is called exactly ONCE in the middleware —
        the reservation added a session supply, not a second revocation call."""
        import inspect

        import server.middleware.auth as auth_module

        src = inspect.getsource(auth_module)
        assert src.count("executor_revocation_state(") == 1
        # And the revocation import is not duplicated into a second module-level form.
        assert src.count("from ..revocation import executor_revocation_state") == 1
