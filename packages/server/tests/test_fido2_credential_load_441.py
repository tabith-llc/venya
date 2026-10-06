# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#441 — a failed FIDO2 credential load must be loud, not an empty store.

``Fido2Manager._load_credentials_from_db`` is invoked from ``__init__`` when a
backend is configured; the only production caller is the server lifespan
(app.py, ``app.state.fido2_manager = Fido2Manager(... backend=backend)``), whose
startup contract already aborts on propagated exceptions (the ``_init_core`` /
``_verify_kek_sentinel`` pattern). Recovery shape chosen for this ticket:
**(a) fail startup loudly** — the exception is logged with
``logger.exception`` and re-raised; the lifespan propagates and the process
never serves with a silently-empty credential store.

Truth table (AC4 — both halves required):
- FAULTING session factory → loud ERROR log naming the effect + the raise
  propagates out of the constructor (startup would abort).
- FAULTING ``get_session`` itself → same.
- CLOSE-ONLY fault (query fine, ``db.close()`` raises) → does NOT abort:
  swallowed with a WARNING — the narrowed scope that the old blanket catch
  conflated with real load failures.
- HEALTHY load → store populates exactly as before.
"""

import logging
from types import SimpleNamespace

import pytest
from server.fido2.manager import Fido2Manager

RP_ID = "venya-core-1"
LOGGER_NAME = "server.fido2.manager"


class _BoomQuery(Exception):
    """Injected DB fault — stands in for connection/schema/permission errors."""


class _BoomClose(Exception):
    """Injected cleanup fault — must be distinguishable from a load fault."""


def _rows(n=2):
    return [
        SimpleNamespace(
            user_id=f"user{i}",
            credential_id=f"cred-{i}".encode(),
            public_key=f"pk-{i}".encode(),
            sign_count=i,
            label=f"key {i}",
        )
        for i in range(n)
    ]


class _FakeSession:
    """Chainable stand-in for a SQLAlchemy session: query(...).filter(...).all()."""

    def __init__(self, rows=None, query_exc=None, close_exc=None):
        self._rows = rows if rows is not None else []
        self._query_exc = query_exc
        self._close_exc = close_exc
        self.closed = False

    def query(self, model):
        return self

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        if self._query_exc is not None:
            raise self._query_exc
        return self._rows

    def close(self):
        self.closed = True
        if self._close_exc is not None:
            raise self._close_exc


class _FakeBackend:
    def __init__(self, session=None, session_exc=None):
        self._session = session
        self._session_exc = session_exc

    def get_session(self):
        if self._session_exc is not None:
            raise self._session_exc
        return self._session


@pytest.fixture
def caplog_loud(caplog):
    caplog.set_level(logging.WARNING, logger=LOGGER_NAME)
    return caplog


class TestLoadFaultIsLoudAndAborts:
    """AC1 + AC4 negative half: fault → ERROR log with effect + re-raise (shape (a))."""

    def test_query_fault_logs_loud_and_propagates(self, caplog_loud):
        session = _FakeSession(query_exc=_BoomQuery("db down"))
        with pytest.raises(_BoomQuery):
            Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=_FakeBackend(session=session))

        errors = [r for r in caplog_loud.records if r.levelno >= logging.ERROR and r.name == LOGGER_NAME]
        assert errors, "credential load fault must be logged ERROR-or-above"
        rec = errors[0]
        assert rec.exc_info is not None, "must log with exception info (logger.exception)"
        msg = rec.getMessage()
        # AC1: names the effect — not loaded, assertions will fail.
        assert "credentials not loaded" in msg
        # the session that opened must still be closed (cleanup stays wired)
        assert session.closed

    def test_get_session_fault_logs_loud_and_propagates(self, caplog_loud):
        backend = _FakeBackend(session_exc=_BoomQuery("cannot open session"))
        with pytest.raises(_BoomQuery):
            Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=backend)

        errors = [r for r in caplog_loud.records if r.levelno >= logging.ERROR and r.name == LOGGER_NAME]
        assert errors, "session-open fault must be logged ERROR-or-above"
        assert errors[0].exc_info is not None


class TestCloseFaultIsNarrowed:
    """AC2 paired half: a close-only failure is logged, NOT fatal — the old
    blanket catch made it indistinguishable from a query failure."""

    def test_close_fault_warns_but_load_survives(self, caplog_loud):
        session = _FakeSession(rows=_rows(2), close_exc=_BoomClose("close failed"))
        manager = Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=_FakeBackend(session=session))

        # store is populated — the load itself succeeded
        assert manager.store.get_user_credentials("user0")
        warnings = [r for r in caplog_loud.records if r.levelno == logging.WARNING and r.name == LOGGER_NAME]
        assert warnings, "close fault must be visible, never silent"


class TestHealthyLoad:
    """AC4 positive half — the happy path must keep working, exactly."""

    def test_healthy_load_populates_store(self, caplog_loud):
        rows = _rows(3)
        session = _FakeSession(rows=rows)
        manager = Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=_FakeBackend(session=session))

        assert session.closed
        for row in rows:
            stored = manager.store.get_credential(row.credential_id)
            assert stored is not None
            assert stored.user_id == row.user_id
            assert stored.label == row.label
        # no error/warning noise on a healthy load
        loud = [r for r in caplog_loud.records if r.levelno >= logging.WARNING and r.name == LOGGER_NAME]
        assert not loud
