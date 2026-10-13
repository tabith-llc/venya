# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#607 — ``GET /api/v1/audit`` ``key=`` is a real filter, not an advertisement.

The route declared ``key: str | None = Query(None, description="Filter by secret
key")`` and never read it, so an operator asking for one secret's history got the
whole (visibility-scoped) log and no signal. The fix applies it through the SAME
JSON-operator idiom the ``executor_id`` filter already uses on this route
(``routes/audit.py`` — ``cast(AuditEvent.fields, JSON).op("->>")(name)``), over
``fields->>'secret_key'``, the field name both key-naming event classes already
write: ``secret_value_disclosed`` and ``auditor_secret_read_denied``
(``routes/secrets.py``).

What each class here can prove, stated plainly:

``TestKeyFilterReachesTheQuery``  — the shipped-backend (PostgreSQL) SQL. A
                                    recording query lets these cells read the
                                    criteria the ROUTE built and compile them
                                    against the postgresql dialect. Proves the
                                    parameter is consumed, proves the JSON path
                                    is ``secret_key``, proves "no filter" and
                                    "filter given" are DIFFERENT statements
                                    (AC1's distinguishability half). Runs
                                    everywhere; needs no server.

``TestKeyFilterAgainstRealDb``    — a real SQLite database answering the real
                                    route. AC1's paired negative: a ``key=``
                                    that matches nothing returns EMPTY while the
                                    same rows come back with no ``key=``.
                                    Engine note, do not lose it: SQLite has no
                                    JSON type, so ``CAST(fields AS JSON)`` takes
                                    numeric affinity and the operator matches NO
                                    row — which is exactly why the empty half is
                                    provable here and the matching half is not
                                    (the shipped backend is PostgreSQL; the
                                    pre-existing ``executor_id`` filter behaves
                                    the same way). The matching half is carried
                                    by ``TestKeyFilterPostgresql`` below.
``TestKeyFilterAuthzUnchanged``   — the truth-table pair on the visibility side:
                                    the key clause is ADDED to the existing
                                    self-filter, never a substitute for it. An
                                    auditor-tier caller carries no ``user_id``
                                    clause; a non-privileged caller's key query
                                    still carries it. Nothing here widens
                                    visibility (AC3 of the row's own severity
                                    note: visibility is decided before filters).

``TestKeyFilterPostgresql``       — the behavioral pair on the engine that ships:
                                    a matching key returns the disclosure row AND
                                    the deny row and nothing else; a key that was
                                    never touched returns empty. SKIPS on a venue
                                    without a scratch database in
                                    ``VENYA_TEST_PG_URL`` (house pattern,
                                    test_init_concurrent_admin_510.py); those
                                    claims are then UNVERIFIED, not green.
"""

import json
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import audit as audit_routes
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

DISCLOSURE_EVENT = "secret_value_disclosed"
DENY_EVENT = "auditor_secret_read_denied"

DISCLOSED_KEY = "db/password"
DENIED_KEY = "app/api-token"
SECOND_KEY = "vault/second"
KEY_NOWHERE = "keys/never-touched"

PG_URL_ENV = "VENYA_TEST_PG_URL"

# (id, event_type, user_id, fields) — one row per class that names a key, one
# row that names an executor, one with no fields at all.
ROWS = [
    (DISCLOSURE_EVENT, "alice", {"outcome": "disclosed", "secret_key": DISCLOSED_KEY}),
    (DENY_EVENT, "mallory", {"outcome": "denied", "reason": "auditor-only role", "secret_key": DENIED_KEY}),
    (DISCLOSURE_EVENT, "alice", {"outcome": "disclosed", "secret_key": SECOND_KEY}),
    ("command_executed", "alice", {"executor_id": "exec-1"}),
    ("login_succeeded", "alice", None),
]


def _seed(SessionLocal):
    from core.iam.models import AuditEvent

    with SessionLocal() as s:
        for i, (event_type, user_id, fields) in enumerate(ROWS, start=1):
            s.add(
                AuditEvent(
                    id=i,
                    event_type=event_type,
                    user_id=user_id,
                    fields=json.dumps(fields) if fields is not None else None,
                    timestamp=datetime(2026, 10, 13, 12, 0, i, tzinfo=UTC),
                )
            )
        s.commit()


def _sqlite_factory():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    from core.iam.models import AuditEvent

    AuditEvent.__table__.create(engine)
    return sessionmaker(bind=engine), engine


class _RecordingQuery:
    """A real query that also reports the criteria the route handed it.

    Only ``query()`` is wrapped, so every criterion the route adds is captured
    in order while counting/ordering/paging/rows stay the real SQLAlchemy ones.
    """

    def __init__(self, real, sink):
        self._real = real
        self._sink = sink

    def filter(self, *criteria, **kwargs):
        self._sink.extend(criteria)
        self._real = self._real.filter(*criteria, **kwargs)
        return self

    def count(self):
        return self._real.count()

    def order_by(self, *args, **kwargs):
        self._real = self._real.order_by(*args, **kwargs)
        return self

    def offset(self, value, **kwargs):
        self._real = self._real.offset(value, **kwargs)
        return self

    def limit(self, value, **kwargs):
        self._real = self._real.limit(value, **kwargs)
        return self

    def all(self):
        return self._real.all()


class _RecordingDb:
    def __init__(self, SessionLocal, sink):
        self._SessionLocal = SessionLocal
        self.criteria = sink

    def query(self, model):
        return _RecordingQuery(self._SessionLocal().query(model), self.criteria)


_STARTED_PATCHERS: list = []


@pytest.fixture(autouse=True)
def _clean_leaks():
    original = audit_routes._is_admin
    yield
    audit_routes._is_admin = original
    while _STARTED_PATCHERS:
        _STARTED_PATCHERS.pop().stop()


def _app(SessionLocal, sink, *, user_id="alice", is_admin=True, tier="read-write"):
    """Real audit router over a real (or recording) session.

    ``tier`` is what the live ``require_role("auditor")`` gate resolves for the
    caller; ``is_admin`` drives ``_is_admin``. Both mirror the house helpers in
    test_audit.py so the visibility branch under test is the shipped one.
    """
    from core.iam.role_manager import RoleManager

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id, "roles": [42]}
    app.dependency_overrides[get_db] = lambda: _RecordingDb(SessionLocal, sink)
    audit_routes._is_admin = lambda db, uid: is_admin
    p = patch.object(RoleManager, "get_user_permissions", return_value={1: tier})
    p.start()
    _STARTED_PATCHERS.append(p)
    return app


def _get(app, params=None):
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/v1/audit", params=params or {})
    assert resp.status_code == 200, resp.text
    return resp


def _pg_sql(criteria):
    """The captured criteria, rendered as the statement PostgreSQL would run."""
    from core.iam.models import AuditEvent
    from sqlalchemy import select

    stmt = select(AuditEvent)
    for c in criteria:
        stmt = stmt.where(c)
    return str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


def _key_clauses(criteria):
    return [c for c in criteria if "secret_key" in _pg_sql([c])]


class TestKeyFilterReachesTheQuery:
    """AC1 distinguishability + AC2 machinery, at the shipped-dialect level."""

    def test_key_param_adds_a_secret_key_clause(self):
        sink = []
        app = _app(*_sqlite_factory()[:1], sink)
        _get(app, {"key": DISCLOSED_KEY})
        clauses = _key_clauses(sink)
        assert len(clauses) == 1, f"route built {len(clauses)} key clauses, expected 1"
        sql = _pg_sql(clauses)
        assert "CAST(audit_events.fields AS JSON) ->> 'secret_key'" in sql, sql
        assert DISCLOSED_KEY in sql, sql

    def test_no_key_param_adds_no_key_clause(self):
        """The paired half of distinguishability: the ignored-filter bug is
        exactly these two requests producing the SAME statement."""
        sink_no = []
        _get(_app(*_sqlite_factory()[:1], sink_no))
        assert _key_clauses(sink_no) == []

        sink_yes = []
        _get(_app(*_sqlite_factory()[:1], sink_yes), {"key": DISCLOSED_KEY})
        assert len(_key_clauses(sink_yes)) == 1
        assert _pg_sql(sink_yes) != _pg_sql(sink_no)

    def test_key_clause_is_the_executor_id_idiom_not_a_new_path(self):
        """AC2: same JSON operator, different member name — no second query path."""
        sink = []
        app = _app(*_sqlite_factory()[:1], sink)
        _get(app, {"key": DISCLOSED_KEY, "executor_id": "exec-1"})
        sql = _pg_sql(sink)
        assert "->> 'secret_key'" in sql, sql
        assert "->> 'executor_id'" in sql, sql
        assert sql.count("CAST(audit_events.fields AS JSON)") == 2, sql

    def test_empty_key_is_still_a_filter(self):
        """``?key=`` (present, empty) means "rows naming the empty key", not
        "no filter" — the query param is ``str``, so the empty string is a
        value and must narrow, never widen back to the full log."""
        sink = []
        app = _app(*_sqlite_factory()[:1], sink)
        _get(app, {"key": ""})
        assert len(_key_clauses(sink)) == 1, _pg_sql(sink)


class TestKeyFilterAgainstRealDb:
    """AC1 paired negative, answered by a real database (SQLite venue)."""

    def test_key_matching_nothing_returns_empty(self):
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink)
        body = _get(app, {"key": KEY_NOWHERE}).json()
        assert body["events"] == [], body
        assert body["total"] == 0, body

    def test_no_key_returns_the_seeded_rows(self):
        """The half that makes the above mean something: the same request
        without the filter is NOT empty, so the empty answer came from the
        filter being evaluated rather than from an empty log."""
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink)
        body = _get(app).json()
        assert body["total"] == len(ROWS), body
        assert {e["event_type"] for e in body["events"]} == {
            DISCLOSURE_EVENT,
            DENY_EVENT,
            "command_executed",
            "login_succeeded",
        }

    def test_null_and_other_shaped_fields_rows_survive_a_key_query(self):
        """A key query over a log that holds a NULL-``fields`` row and rows
        naming no key must return an answer, not an error.

        Engine honesty: on SQLite every JSON clause is inert, so this cell
        proves the route builds and runs the query without raising here; it
        does NOT prove the same on PostgreSQL, where an invalid-JSON ``fields``
        value would make ``CAST(fields AS JSON)`` an error. Every writer on
        this table stores ``json.dumps`` output (``AuditEvent.serialize_fields``
        validates a dict to JSON text), so the valid-JSON premise holds by
        construction — the PostgreSQL class below carries the live half.
        """
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink)
        body = _get(app, {"key": DISCLOSED_KEY, "event_type": "login_succeeded"}).json()
        assert body["events"] == []


class TestKeyFilterAuthzUnchanged:
    """The filter must ride INSIDE the visibility decision, never replace it."""

    def test_auditor_tier_key_query_carries_no_self_filter(self):
        """P: auditor-tier, not an admin → full log, filtered only by key."""
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink, user_id="auditor-1", is_admin=False, tier="auditor")
        _get(app, {"key": DISCLOSED_KEY})
        sql = _pg_sql(sink)
        assert "secret_key" in sql, sql
        assert "audit_events.user_id =" not in sql, sql

    def test_non_privileged_key_query_keeps_the_self_filter(self):
        """N paired negative: a caller who is not admin and holds no
        auditor-tier membership still gets the ``user_id`` self-filter on the
        same request — the key clause is added to it, not swapped for it."""
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink, user_id="alice", is_admin=False, tier="read-write")
        _get(app, {"key": DISCLOSED_KEY})
        sql = _pg_sql(sink)
        assert "secret_key" in sql, sql
        assert "audit_events.user_id = 'alice'" in sql, sql

    def test_non_privileged_key_query_returns_only_own_rows(self):
        """The behavioral same-half: mallory's deny row is not in alice's
        answer even though both are readable by an auditor."""
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink, user_id="alice", is_admin=False, tier="read-write")
        body = _get(app, {"key": DISCLOSED_KEY}).json()
        assert {e["user_id"] for e in body["events"]} <= {"alice"}, body

    def test_non_human_caller_still_gets_empty(self):
        """mTLS/no-user_id callers keep the empty-answer branch (no user_id in
        the statement at all, and no rows)."""
        from core.iam.role_manager import RoleManager
        from starlette.middleware.base import BaseHTTPMiddleware

        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = FastAPI()
        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        app.state.backend = backend
        app.include_router(audit_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "executor-cn", "roles": [42]}
        app.dependency_overrides[get_db] = lambda: _RecordingDb(SessionLocal, sink)
        p = patch.object(RoleManager, "get_user_permissions", return_value={1: "read-write"})
        p.start()
        _STARTED_PATCHERS.append(p)

        class AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                return await call_next(request)

        app.add_middleware(AuthMiddleware)
        # The empty-answer branch needs user_id to be ABSENT, which the shipped
        # gate's own "identity carries no user" 403 now prevents for tiered
        # routes — so this pins the handler branch directly.
        import asyncio

        resp = asyncio.run(
            audit_routes.audit_list(
                user=None,
                key=DISCLOSED_KEY,
                start_date=None,
                end_date=None,
                days=None,
                hours=None,
                event_type=None,
                executor_id=None,
                limit=100,
                offset=0,
                auth_user={},
                db=_RecordingDb(SessionLocal, sink),
            )
        )
        assert resp.total == 0
        assert resp.events == []
        assert _key_clauses(sink) == [], "empty-answer branch must not even build a query"


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"the matching-key half needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestKeyFilterPostgresql:
    """AC1 positive + AC3 both classes, on the engine that ships.

    WRITTEN, NOT RUN ON THIS LEG — the spec bars guests, so this class skipped
    and its claims are unverified here. Point ``VENYA_TEST_PG_URL`` at a SCRATCH
    database (it drops and recreates ``audit_events``); never at anything live.

    This is the cell SQLite cannot substitute: ``CAST(fields AS JSON) ->>
    'secret_key'`` is real JSON navigation on PostgreSQL, so a matching key
    answers with the disclosure row AND the deny row, and a key nobody touched
    answers empty.
    """

    def _factory(self):
        from core.iam.models import AuditEvent

        engine = create_engine(os.environ[PG_URL_ENV])
        AuditEvent.__table__.drop(engine, checkfirst=True)
        AuditEvent.__table__.create(engine)
        return sessionmaker(bind=engine), engine

    def test_matching_key_returns_both_secret_classes_and_nothing_else(self):
        SessionLocal, engine = self._factory()
        try:
            _seed(SessionLocal)
            sink = []
            app = _app(SessionLocal, sink)
            body = _get(app, {"key": DISCLOSED_KEY}).json()
            assert body["total"] == 1, body
            assert [e["event_type"] for e in body["events"]] == [DISCLOSURE_EVENT], body
            assert body["events"][0]["fields"]["secret_key"] == DISCLOSED_KEY, body
        finally:
            engine.dispose()

    def test_deny_class_answers_the_same_filter(self):
        SessionLocal, engine = self._factory()
        try:
            _seed(SessionLocal)
            sink = []
            app = _app(SessionLocal, sink)
            body = _get(app, {"key": DENIED_KEY}).json()
            assert [e["event_type"] for e in body["events"]] == [DENY_EVENT], body
        finally:
            engine.dispose()

    def test_untouched_key_is_empty_while_the_log_is_not(self):
        SessionLocal, engine = self._factory()
        try:
            _seed(SessionLocal)
            sink = []
            app = _app(SessionLocal, sink)
            assert _get(app, {"key": KEY_NOWHERE}).json()["total"] == 0
            assert _get(app, {"key": KEY_NOWHERE}).json()["total"] < _get(app).json()["total"]
        finally:
            engine.dispose()

    def test_null_fields_row_survives_a_key_query(self):
        """The PostgreSQL half of the null-fields cell above: the row carrying
        no ``fields`` at all must be filtered out, not raise."""
        SessionLocal, engine = self._factory()
        try:
            _seed(SessionLocal)
            sink = []
            app = _app(SessionLocal, sink)
            body = _get(app, {"key": DISCLOSED_KEY, "event_type": "login_succeeded"}).json()
            assert body == {"events": [], "total": 0, "limit": 100, "offset": 0}, body
        finally:
            engine.dispose()
