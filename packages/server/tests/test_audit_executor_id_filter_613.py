# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#613 — does the shipped ``executor_id`` audit filter MATCH on the production dialect?

The row (#613) is an INVESTIGATION, not a defect claim: ``GET /api/v1/audit`` has filtered on
``executor_id`` for a long time through a JSON-path operator over a **TEXT** column —
``packages/server/src/server/routes/audit.py``, ``audit_list`` (the clause is
``cast(AuditEvent.fields, JSON).op("->>")("executor_id") == executor_id``) — and the repo held **no
record of a PostgreSQL-backed run that seeded audit rows and showed ``executor_id=`` actually
narrowing them**. The column is Text on both planes: ``core.iam.models.AuditEvent.fields``
(``fields = Column(Text, nullable=True)``, class ``AuditEvent``) and migration ``001_initial_schema``
(``sa.Text()`` on ``audit_events``), so the application — not the database — owns the JSON reading.

Why the standing harness cannot answer it. SQLite has no JSON type, so ``CAST(fields AS JSON)`` takes
numeric affinity and evaluates to the integer ``0`` for a JSON text value; the ``->>`` operator against
that matches **no row at all**. The shipped statement is the thing under test, so this file does NOT
work around that (no dropped cast, no raw-text ``->>``, no dialect branch — AC3). One cell below pins
the inertness on SQLite as a tripwire instead of hiding it.

What each class here can prove, stated plainly:

``TestVenueGateHonesty``           — runs anywhere, no server. The gate's own truth table, added by the s125 follow-on
                                    leg: an UNREACHABLE ``VENYA_TEST_PG_URL`` must refuse loudly out of the driver
                                    (``OperationalError``) rather than take the skip branch, and the shipped ``skipif``
                                    decorators are read on the AST to prove each gate keys on the variable's PRESENCE
                                    and its skip reason names the variable. A gate that connected-and-swallowed would
                                    turn a misconfigured venue GREEN — the shape #613/#614/#630 all exist to stop.

``TestExecutorIdFilterStatement``  — runs anywhere, no server. A capturing query reads the criteria the
                                    ROUTE built and compiles them against the **postgresql** dialect, so
                                    these cells name the exact statement the PostgreSQL class below
                                    executes: with ``executor_id=`` the WHERE carries
                                    ``CAST(audit_events.fields AS JSON) ->> 'executor_id'``; without the
                                    parameter that clause is absent. One more cell pins the shipped line
                                    itself — the clause must REBIND ``query`` — because a capturing
                                    wrapper reapplies whatever it records, so "built then discarded" is
                                    a mutation these cells cannot otherwise see (#607's row names that
                                    blind spot from its own falsification run). Plus the SQLite half of
                                    the dialect fact: that same shipped statement returns **zero** rows
                                    from a log that does hold the value, which is why the matching half
                                    is not provable on the test engine.

``TestExecutorIdFilterPostgresql`` — AC1, the answer to the row's question, on the engine that ships.
                                    A real PostgreSQL database seeds rows naming TWO distinct
                                    ``executor_id`` values in the TEXT ``fields`` payload, and the truth
                                    table is driven from the real route in both directions: ``A`` returns
                                    A's rows and never B's, ``B`` returns B's rows and never A's, and a
                                    value nobody seeded returns EMPTY while the same log without the
                                    filter is not empty. A filter that always returned everything and a
                                    filter that always returned nothing both pass a one-sided test, so
                                    all three cells are required.

                                    Falsification, not just green: with the shipped clause DELETED, all
                                    seven cells in this file go RED (named in the #613 report). With the
                                    clause built but not rebound, the rebind guard goes RED while the six
                                    behavioral cells stay green — which is exactly why that guard exists.

``TestExecutorIdFilterPostgresql`` SKIPS on a venue without a scratch database in ``VENYA_TEST_PG_URL``
(house pattern, ``test_init_concurrent_admin_510.py``); on such a venue the matching half is
UNVERIFIED, not green. Point the variable at a SCRATCH database — the class drops and recreates
``audit_events`` only; never point it at anything live.

**Driver shape, because a wrong URL here is loud but misleading:** use the psycopg2 form the repo depends on
(``packages/core/pyproject.toml`` → ``psycopg2-binary>=2.9.0``; nothing in ``uv.lock`` declares psycopg 3) —
``postgresql+psycopg2://<user>@/<db>?host=<socket-dir>&port=<port>`` for a unix-socket cluster, or
``postgresql+psycopg2://<user>:<pw>@127.0.0.1:5432/<db>`` for a TCP one. A ``postgresql+psycopg://`` (psycopg 3)
URL neither skips nor passes: it raises ``ModuleNotFoundError`` inside the SQLAlchemy dialect and the three
PostgreSQL cells go RED. Re-measured both ways at this tip against the s125 fixture: psycopg2 →
``10 passed``; psycopg3 → ``3 failed, 7 passed``. That red is a venue wiring error, not a product result.
"""

import ast
import json
import os
from datetime import UTC, datetime
from typing import ClassVar
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

PG_URL_ENV = "VENYA_TEST_PG_URL"
# R1 (#614): one deadline, one name, shared by every PostgreSQL-gated cell in this repo.
# `lock_timeout` bounds the wait when a read transaction left open by an earlier cell pins this
# cell's DROP TABLE; `statement_timeout` is the backstop for a stall that is not a lock wait, set
# far above the milliseconds these cells actually take.
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}

# Two distinct executor identities, plus one no writer ever stored.
EXEC_A = "exec-alpha"
EXEC_B = "exec-beta"
EXEC_ABSENT = "exec-never-seeded"

SHIPPED_PG_PREDICATE = "CAST(audit_events.fields AS JSON) ->> 'executor_id'"

# (id, event_type, user_id, fields) — two rows per executor so "only A's rows" reads as a count and as
# a membership test, one row with NULL fields, one row whose fields name no executor at all.
ROWS = [
    ("command_executed", "alice", {"executor_id": EXEC_A, "outcome": "ok"}),
    ("command_executed", "bob", {"executor_id": EXEC_A, "outcome": "ok"}),
    ("command_executed", "alice", {"executor_id": EXEC_B, "outcome": "ok"}),
    ("executor_registered", None, {"executor_id": EXEC_B, "serial_number": "0000000000001000"}),
    ("login_succeeded", "alice", None),
    ("executor_cert_revoked", "alice", {"reason": "rotation"}),
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
                    timestamp=datetime(2026, 10, 15, 12, 0, i, tzinfo=UTC),
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


class _CapturingQuery:
    """A real query that also reports the criteria the route handed it.

    Only ``filter()`` records, so every criterion the route adds is captured in order while
    counting/ordering/paging/rows stay the real SQLAlchemy ones against a real database.
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


class _CapturingDb:
    """Yields real sessions (and closes them) while capturing the route's criteria.

    The session closes in the dependency's teardown, which is the shipped ``get_db`` shape: an
    idle-in-transaction read here is exactly what pins a later cell's ``DROP TABLE`` (#607 s105 hang).
    """

    def __init__(self, SessionLocal, sink):
        self._SessionLocal = SessionLocal
        self.criteria = sink

    def query(self, model):
        session = self._SessionLocal()
        _OPEN_SESSIONS.append(session)
        return _CapturingQuery(session.query(model), self.criteria)


# Sessions and engines this file opened, tracked so they are released before any DDL.
# An open read transaction holds an AccessShareLock on audit_events, which makes a later DROP TABLE
# wait forever — the #607 s105 hang, inside a fixture. Disposal is part of the ordering, not tidiness
# (R1 #614: every PG connection this repo opens carries the shared _PG_DEADLINE for the same reason).
_OPEN_SESSIONS: list = []
_PG_ENGINES: list = []
_STARTED_PATCHERS: list = []


@pytest.fixture(autouse=True)
def _release_leaks():
    original = audit_routes._is_admin
    yield
    while _OPEN_SESSIONS:
        _OPEN_SESSIONS.pop().close()
    while _PG_ENGINES:
        _PG_ENGINES.pop().dispose()
    audit_routes._is_admin = original
    while _STARTED_PATCHERS:
        _STARTED_PATCHERS.pop().stop()


def _app(SessionLocal, sink, *, user_id="alice", is_admin=True, tier="read-write"):
    """Real audit router over a real session, with the route's criteria captured.

    ``tier`` drives the live ``require_role("auditor")`` gate and ``is_admin`` drives ``_is_admin``,
    both mirroring the house helpers in ``test_audit.py`` / ``test_audit_key_filter_607.py`` so the
    visibility branch taken here is the shipped one. Default is an admin caller: the executor filter
    under test is then the ONLY narrowing in the statement, so a wrong count cannot be blamed on the
    self-filter.
    """
    from core.iam.role_manager import RoleManager

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id, "roles": [42]}
    app.dependency_overrides[get_db] = lambda: _CapturingDb(SessionLocal, sink)
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


def _executor_clauses(criteria):
    return [c for c in criteria if "->> 'executor_id'" in _pg_sql([c])]


class TestVenueGateHonesty:
    """The gate's own truth table, so a broken engine path cannot read as a skip-that-looks-green.

    #614 gated the timeout of these cells and #630 hunts gated tests that hide where they cannot run. This is the
    property next to them, pinned here because #613's class is the one a reviewer re-runs first. The gate keys on the
    variable BEING SET, never on whether a connection happened to succeed. So:

    * no variable at all        -> SKIPPED, with the reason naming the variable, so CI on a box without postgres stays
                                   honest, and stays honest for the right reason;
    * variable set, unreachable -> **RED**, an ``OperationalError`` from the driver — never a skip, never a pass.

    Two of these three cells need no server: the refusal IS the assertion.
    """

    # A socket path with nothing behind it, and a port with nothing listening — both fail before reading any row.
    UNREACHABLE: ClassVar[list] = [
        (
            "postgresql+psycopg2://agent@/venya_gate_honesty?host=/tmp/tabichat/no-such-sock-dir&port=59999",
            "no socket",
        ),
        ("postgresql+psycopg2://agent@127.0.0.1:59999/venya_gate_honesty", "connection refused"),
    ]

    @pytest.mark.parametrize("url,label", UNREACHABLE, ids=["no-socket", "refused"])
    def test_an_unreachable_gated_url_refuses_loudly_rather_than_skipping(self, url, label):
        from sqlalchemy.exc import OperationalError

        engine = create_engine(url, connect_args=_PG_DEADLINE)
        try:
            with pytest.raises(OperationalError) as caught:
                engine.connect()
            detail = str(caught.value)
            assert label in detail or "OperationalError" in detail, detail[:200]
        finally:
            engine.dispose()

    def test_the_gate_keys_on_presence_of_the_variable_not_on_reachability(self):
        """Every PostgreSQL-gated class in this suite skips on the mere ABSENCE of the variable.

        That is what gives the two cells above meaning. A gate written as "try to connect, skip if it fails" would
        turn a misconfigured venue GREEN — the failure mode #613 and #630 both name — so the condition has to be a pure
        presence test. Checked on the AST, not on a run, so it holds on a venue with no postgres at all.
        """
        from pathlib import Path

        here = Path(__file__).resolve()
        root = here.parent
        scanned = 0
        for path in sorted(root.glob("*.py")):
            if path.resolve() == here:
                continue
            text = path.read_text(encoding="utf-8")
            if PG_URL_ENV not in text:
                continue
            tree = ast.parse(text)
            # Files spell the variable as a module constant (`PG_URL_ENV = "VENYA_TEST_PG_URL"`) or as the literal.
            names = _env_var_names(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.ClassDef) and node.name.endswith("Postgresql")):
                    continue
                gates = [d for d in node.decorator_list if isinstance(d, ast.Call) and _callee_name(d.func) == "skipif"]
                assert gates, f"{path.name}:{node.name} — a gated class with no skipif decorator"
                gate = gates[0]
                condition = ast.unparse(gate.args[0]) if gate.args else ast.unparse(_kw(gate, "condition"))
                assert condition.startswith("not "), f"{path.name}:{node.name} skips on {condition!r}, not on absence"
                assert _reads_the_gate_variable(condition, names), (
                    f"{path.name}:{node.name} skips on {condition!r}, which reads no os.environ[{PG_URL_ENV}] — a gate "
                    "probing reachability or another variable can silence a misconfigured venue"
                )
                reason = ast.unparse(_kw(gate, "reason"))
                # The reason may spell the variable or interpolate a name bound to it; both read at a console.
                assert PG_URL_ENV in reason or any(n in reason for n in names), (
                    f"{path.name}:{node.name}: the skip reason {reason!r} never names the gate variable, so a skip"
                    f" here is not diagnosable to {PG_URL_ENV}"
                )
                scanned += 1

        assert scanned >= 4, f"only {scanned} gated classes inspected — this check would be near-vacuous"


def _env_var_names(tree: ast.Module) -> set:
    """Module-level names bound to the exact gate variable, plus the literal itself."""
    out = {PG_URL_ENV}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        if ast.literal_eval(node.value) == PG_URL_ENV:
                            out.add(target.id)
                    except (ValueError, TypeError):
                        pass
    return out


def _kw(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    raise AssertionError(f"{name}= not found on {ast.dump(call)[:80]}")


def _reads_the_gate_variable(condition: str, names: set) -> bool:
    """True when the condition is a read of `os.environ`, keyed on the gate variable.

    Deliberately dumb: the point is not to parse Python, it is to prove the gate keys on the VARIABLE (presence). A gate
    that instead probed reachability — a connect-and-swallow helper, another variable, a hard-coded False — holds no
    `environ` read of one of these names, and fails this check.
    """
    if "environ" not in condition:
        return False
    return any(name in condition for name in names)


def _callee_name(func) -> str:
    """``pytest.mark.skipif`` → ``skipif``; a bare ``skipif`` → ``skipif``."""
    return getattr(func, "attr", None) or getattr(func, "id", "")


class TestExecutorIdFilterStatement:
    """Names the statement the PostgreSQL cells run, pins it as APPLIED, pins the SQLite blind spot."""

    def test_the_shipped_clause_rebinds_the_query_rather_than_being_built_and_discarded(self):
        """Closes at the source line the one mutation these capturing cells cannot see.

        ``_CapturingQuery.filter()`` reattaches every criterion it records — that is what makes the
        PostgreSQL class below a round trip rather than a mock — so a route that built the predicate
        and dropped it (``query.filter(...)`` with no rebinding) would still read green here, because
        the test wrapper reapplies it on the product's behalf. #607's row names exactly that blind
        spot from its own venue-falsification run, so this cell pins the shipped text instead.
        """
        import inspect

        source = inspect.getsource(audit_routes.audit_list)
        applied = [
            line.strip()
            for line in source.splitlines()
            if "executor_id" in line and line.strip().startswith("query = query.filter(")
        ]
        assert applied, (
            "the executor_id filter must REBIND query (`query = query.filter(...)`); a bare "
            "`query.filter(...)` builds a criterion that no statement ever runs"
        )
        clause = applied[0]
        assert '.op("->>")' in clause and '("executor_id")' in clause, clause

    def test_executor_id_param_compiles_to_the_shipped_pg_json_predicate(self):
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        _get(_app(SessionLocal, sink), {"executor_id": EXEC_A})
        clauses = _executor_clauses(sink)
        assert len(clauses) == 1, f"route built {len(clauses)} executor_id clauses, expected 1"
        sql = _pg_sql(clauses)
        assert SHIPPED_PG_PREDICATE in sql, sql
        assert EXEC_A in sql, sql

    def test_no_executor_id_param_adds_no_json_predicate(self):
        """The distinguishability half: with and without the parameter are DIFFERENT statements.
        An ignored filter and an applied one would otherwise look the same from the response alone."""
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink_no = []
        _get(_app(SessionLocal, sink_no))
        assert _executor_clauses(sink_no) == []

        sink_yes = []
        _get(_app(SessionLocal, sink_yes), {"executor_id": EXEC_A})
        assert len(_executor_clauses(sink_yes)) == 1
        assert _pg_sql(sink_yes) != _pg_sql(sink_no)

    def test_the_shipped_statement_is_inert_on_sqlite_and_that_is_why_this_is_gated(self):
        """The dialect fact of #613, pinned physically rather than narrated.

        The SAME request that the PostgreSQL class answers with rows returns **zero** rows here, while
        the unfiltered log holds all six — because SQLite gives ``CAST(fields AS JSON)`` numeric
        affinity, not a JSON value. So the empty answer here is the engine, not the product, and the
        matching half lives only in ``TestExecutorIdFilterPostgresql``.

        This cell is a tripwire, not an endorsement of SQLite support: it goes RED if the shipped
        statement changes to something SQLite can evaluate (a dropped cast, a raw-text ``->>``, a
        dialect branch — all forbidden by AC3 of the row) or if the test engine stops being SQLite.
        Either way, re-read #613 before editing it.
        """
        SessionLocal, _ = _sqlite_factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink)
        filtered = _get(app, {"executor_id": EXEC_A}).json()
        assert filtered["events"] == [], filtered
        assert filtered["total"] == 0, filtered
        # ...and the log is not empty, which is what makes the zero above an engine artifact.
        assert _get(app).json()["total"] == len(ROWS)


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"the matching-executor_id half needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestExecutorIdFilterPostgresql:
    """AC1 — the row's question, answered by a real PostgreSQL on the shipped statement.

    ``CAST(fields AS JSON) ->> 'executor_id'`` is genuine JSON navigation here (that is the whole
    difference from the SQLite harness), so a seeded executor id must narrow and an unseeded one must
    come back empty. All three cells are the truth table: two directions of matching plus the
    reject-half.
    """

    def _factory(self):
        from core.iam.models import AuditEvent

        while _OPEN_SESSIONS:
            _OPEN_SESSIONS.pop().close()
        engine = create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)
        _PG_ENGINES.append(engine)
        AuditEvent.__table__.drop(engine, checkfirst=True)
        AuditEvent.__table__.create(engine)
        return sessionmaker(bind=engine)

    def test_executor_a_returns_its_rows_and_never_bs(self):
        SessionLocal = self._factory()
        _seed(SessionLocal)
        sink = []
        body = _get(_app(SessionLocal, sink), {"executor_id": EXEC_A}).json()
        assert body["total"] == 2, body
        assert {e["fields"]["executor_id"] for e in body["events"]} == {EXEC_A}, body
        assert EXEC_B not in json.dumps(body), body

    def test_executor_b_returns_its_rows_and_never_as(self):
        """The other direction, so the filter is not pinned to the first value it met. One of the two
        B rows is written by an executor with no ``user_id``, so this also shows the narrowing is the
        JSON member and not the caller half of the WHERE."""
        SessionLocal = self._factory()
        _seed(SessionLocal)
        sink = []
        body = _get(_app(SessionLocal, sink), {"executor_id": EXEC_B}).json()
        assert body["total"] == 2, body
        assert {e["fields"]["executor_id"] for e in body["events"]} == {EXEC_B}, body
        assert EXEC_A not in json.dumps(body), body

    def test_unseeded_executor_is_empty_while_the_log_is_not(self):
        """The paired negative. Without the second assertion this cell would also pass on an empty
        table, which is how a filter that matches nothing at all looks green."""
        SessionLocal = self._factory()
        _seed(SessionLocal)
        sink = []
        app = _app(SessionLocal, sink)
        body = _get(app, {"executor_id": EXEC_ABSENT}).json()
        assert body == {"events": [], "total": 0, "limit": 100, "offset": 0}, body
        assert _get(app).json()["total"] == len(ROWS)
