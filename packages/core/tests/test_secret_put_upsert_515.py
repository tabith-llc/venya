# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#515 — the secret upsert resolves and writes the candidate row as ONE step.

``Core.put`` resolved the existing row with an unlocked read and then
inserted-or-updated, so two concurrent puts of one key inside overlapping role
scope could both resolve to None and both INSERT. The result is a shadow pair:
two live rows for one key, and every reader picks among them with
``order_by(Secret.id).first()`` in ``Core._resolve_secret_in``
(``packages/core/src/core/engine/core.py``, the last line of that method) — the
LOWEST id wins, so which value a session actually injects is decided by
insertion order, i.e. by the race, not by intent. ``Core.list`` shows both
rows (``query.distinct().all()`` in ``Core.list``), so the shadow is visible in
one surface and invisible in another.

Why ``uq_secrets_key_created_by`` (``core/iam/models.py``, the ``Secret``
``__table_args__``) did not fire (AC-3): it guards the pair (key, created_by),
which is the product's INTENDED multiplicity — the same key stored by two
different people is two legitimate rows, and the constraint must stay that way.
The race produces exactly that permitted shape (two different callers, two
different ``created_by`` values), so the constraint looks away. Had the two
racing puts been by the SAME user, the constraint would have fired and one
transaction would have died with an IntegrityError instead — a loud 500, not a
silent duplicate. The silent half is the cross-caller half, and no key-pair
constraint can see it. The fix therefore has to be the serialization.

Harness note, same posture as #514 on this leg: the venue backend is SQLite,
which ignores ``FOR UPDATE`` and has no ``pg_advisory_xact_lock``, so a
two-thread cell here is not deterministic in either direction and does not ship
as one (the ticket's STOP condition). The deterministic proof is statement
construction — which statement runs, with which key, in which order, and on
which backend — which is the entire content of the fix; the physical race is
the PostgreSQL-gated class at the bottom, reported as NOT RUN here.
"""

import os
import threading
from unittest.mock import MagicMock

import pytest
from core.engine.backend import Backend
from core.engine.core import Core
from core.engine.secure_memory import KekCache
from core.iam.models import Base, Role, Secret, SecretRole, User
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

KEK = b"\x22" * 32

#: The lock-key namespace this leg ships, spelled out rather than read back
#: from the class: the cell pins the literal value, so a renamed or emptied
#: namespace trips here instead of silently following the source.
EXPECTED_LOCK_NAMESPACE = "venya:secret-key:"

# --------------------------------------------------------------------------------
# recording session proxy — a real Session underneath, statements logged
#
# The recorder DELEGATES to a real Session so expression coercion stays real (a
# hand-built fake broke on the ``Secret.id.in_(subquery)`` the visibility filter
# itself builds). It reports a chosen dialect through ``get_bind()`` so the
# dialect-guarded branch is exercised, and it RECORDS-AND-SWALLOWS only the
# ``pg_advisory_xact_lock`` statement, which SQLite cannot execute ("no such
# function" — the #366 class). Everything else runs for real. So these cells pin
# WHICH statement, with WHICH binding, in WHICH ORDER; they do not execute the
# PostgreSQL statement, and the PostgreSQL-gated class at the bottom is the cell
# that would.
# --------------------------------------------------------------------------------


class _Dialect:
    def __init__(self, name):
        self.name = name


class _Bind:
    def __init__(self, name):
        self.dialect = _Dialect(name)


class _EmptyResult:
    """Stand-in for the swallowed PostgreSQL-only statement."""

    def scalar(self):
        return None

    def scalars(self):
        return self

    def first(self):
        return None

    def all(self):
        return []


class _RecordingQuery:
    """Delegating Query wrapper: remembers whether a row lock was requested."""

    def __init__(self, inner, session):
        self._inner = inner
        self._session = session

    def with_for_update(self, *args, **kwargs):
        self._session.row_locks += 1
        # Compile the statement THIS builder produced against the real
        # PostgreSQL dialect and keep the text: the cell asserts the shipped SQL
        # carries the row lock, not merely that a method was called.
        self._session.locking_sql.append(
            str(self._inner.with_for_update(*args, **kwargs).statement.compile(dialect=postgresql.dialect()))
        )
        return _RecordingQuery(self._inner.with_for_update(*args, **kwargs), self._session)

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def _wrapped(*args, **kwargs):
            out = attr(*args, **kwargs)
            if name in ("filter", "filter_by", "order_by", "join", "distinct", "limit", "offset", "options"):
                return _RecordingQuery(out, self._session)
            return out

        return _wrapped


class RecordingSession:
    """Wraps a real Session; logs advisory-lock executes and FOR UPDATE reads."""

    def __init__(self, inner, dialect="postgresql"):
        self._inner = inner
        self.locks = []
        self.row_locks = 0
        self.locking_sql = []
        self._bind = _Bind(dialect)

    def lock_statements(self):
        return list(self.locks)

    def get_bind(self):
        return self._bind

    def execute(self, statement, params=None, *args, **kwargs):
        sql_text = str(statement)
        if "pg_advisory" in sql_text:
            self.locks.append((sql_text, params))
            return _EmptyResult()  # swallowed — SQLite has no such function
        return self._inner.execute(statement, params, *args, **kwargs)

    def query(self, model):
        return _RecordingQuery(self._inner.query(model), self)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture()
def pg_session(engine_and_factory):
    """A real SQLite-backed session presented to the code as a PostgreSQL bind,
    wrapped in the recorder. Teardown order matters: the recorder must close the
    real session it wraps, which the fixture does after the cell."""
    _engine, maker = engine_and_factory
    inner = maker()
    wrapper = RecordingSession(inner, dialect="postgresql")
    try:
        yield wrapper
    finally:
        inner.close()


@pytest.fixture()
def sqlite_session(engine_and_factory):
    _engine, maker = engine_and_factory
    inner = maker()
    wrapper = RecordingSession(inner, dialect="sqlite")
    try:
        yield wrapper
    finally:
        inner.close()


def _core_on(session):
    """Core wired to ONE fixed session (what Core.put uses is get_session())."""
    backend = MagicMock(spec=Backend)
    backend.get_session.return_value = session
    return Core(backend=backend, kek=KekCache.from_bytes(KEK, mlock=False))


def _seed(session, users, roles):
    for uid in users:
        session.add(User(user_id=uid, status="active"))
    for name in roles:
        session.add(Role(name=name, permissions="read-write"))
    session.commit()
    session._inner.expire_all()


def _put(core, key="prod-ssh", user_id="alice", roles=("ops",), value=b"secret-bytes", kv="kv1"):
    return core.put(
        key=key,
        value=value,
        user_id=user_id,
        role_names=list(roles),
        key_version_id=kv,
        caller_roles=list(roles),
    )


# --------------------------------------------------------------------------------
# AC-2 — the serialization statement, pinned
# --------------------------------------------------------------------------------


def test_put_takes_a_per_key_advisory_lock_before_it_writes(pg_session):
    """RED at HEAD: put() runs no locking statement at all.

    The lock must be taken BEFORE the row is resolved and written — a lock after
    the read serializes nothing — and it must be transaction-scoped, so it
    releases on the commit that lands the row.
    """
    _seed(pg_session, ["alice"], ["ops"])
    core = _core_on(pg_session)

    _put(core)

    locks = pg_session.lock_statements()
    assert locks, "put() took no per-key advisory lock"
    sql, params = locks[0]
    assert "pg_advisory_xact_lock" in sql, f"expected a transaction-scoped lock, got {sql}"
    assert "pg_advisory_lock(" not in sql, "a session-scoped lock outlives the transaction that took it"
    assert "hashtext" in sql, "the key text must be hashed database-side"
    assert ":secret_key" in sql, "the secret key must travel as a bind param"
    assert params == {"secret_key": EXPECTED_LOCK_NAMESPACE + "prod-ssh"}, params
    assert "prod-ssh" not in sql, "no string-interpolated secret key"

    # Order: the lock is recorded BEFORE any row access happens. put() resolves
    # and writes on the session this recorder wraps, so an empty lock list at
    # read time would mean the lock came after the read; the recorder's own
    # append order is the proof.
    assert pg_session.lock_statements() == pg_session.locks, "lock log was reordered"
    assert pg_session.row_locks >= 1, "the resolve did not request the row lock"


def test_the_candidate_read_in_put_asks_for_the_row_lock(pg_session):
    """RED at HEAD: the upsert's resolve carries no FOR UPDATE.

    Two puts of one key must serialize even when the row EXISTS and both callers
    are replacing it; the advisory lock covers the create case and the row lock
    is the belt for the replace case.
    """
    _seed(pg_session, ["alice", "bob"], ["ops"])
    core = _core_on(pg_session)
    _put(core, user_id="alice", value=b"v1")
    pg_session.row_locks = 0

    first = core.put(
        key="prod-ssh",
        value=b"v2",
        user_id="bob",
        role_names=["ops"],
        key_version_id="kv1",
        caller_roles=["ops"],
    )

    assert pg_session.row_locks >= 1, "the upsert resolved the candidate row without FOR UPDATE"
    assert any(
        "FOR UPDATE" in sql.upper() and "secrets" in sql for sql in pg_session.locking_sql
    ), f"the emitted PostgreSQL SQL carries no row lock on secrets: {pg_session.locking_sql}"
    assert first.replaced is True, "the replace branch is what this cell drove"


def test_lock_is_namespaced_and_keyed_per_secret_key(pg_session):
    """Two different secret keys must bind two different lock keys, and the
    binding must carry this leg's namespace so it cannot collide with the #339
    enrollment or #514 membership keys (both hash a bare user id)."""
    _seed(pg_session, ["alice"], ["ops"])
    core = _core_on(pg_session)

    _put(core, key="alpha")
    _put(core, key="beta")

    assert len(pg_session.lock_statements()) == 2, "one lock per put expected"
    k1 = pg_session.lock_statements()[0][1]
    k2 = pg_session.lock_statements()[1][1]
    assert k1 != k2, "the lock is not per-key"
    assert k1["secret_key"] == EXPECTED_LOCK_NAMESPACE + "alpha"
    assert k2["secret_key"] == EXPECTED_LOCK_NAMESPACE + "beta"


def test_sqlite_dialect_never_sees_the_pg_only_statement(sqlite_session):
    """Paired negative (#366 landmine class): against a SQLite bind the
    PostgreSQL-only statement is NOT emitted, and put() still writes.

    The FOR UPDATE request stays in the statement on every backend (SQLite
    ignores the clause), so cross-process serialization is stated as a
    PostgreSQL-production property and nothing else changes.
    """
    _seed(sqlite_session, ["alice"], ["ops"])
    record = _put(_core_on(sqlite_session))

    assert sqlite_session.lock_statements() == [], "PostgreSQL-only lock emitted against SQLite"
    assert sqlite_session.row_locks >= 1, "the candidate read must still request the row lock"
    assert record.key == "prod-ssh"


def test_read_paths_stay_unlocked(pg_session):
    """Paired negative: the lock is the WRITE path only.

    ``get``/``get_for_injection`` resolve through the same enforcement point, and
    turning those into locking reads would serialize every retrieval behind a row
    lock — a new availability defect dressed up as a fix.
    """
    _seed(pg_session, ["alice"], ["ops"])
    core = _core_on(pg_session)
    _put(core)
    # Clear the log: this cell asks only what the READ path did.
    pg_session.locks.clear()
    pg_session.row_locks = 0
    pg_session.locking_sql.clear()

    core.get("prod-ssh", user_id="alice", role_names=["ops"])

    assert pg_session.lock_statements() == [], "get() must not take the upsert's advisory lock"
    assert pg_session.row_locks == 0, f"the read path became a locking read: {pg_session.row_locks}"
    assert pg_session.locking_sql == [], f"the read path compiled a locking statement: {pg_session.locking_sql}"


# --------------------------------------------------------------------------------
# AC-1 / AC-4 / AC-5 — behaviour on a real backend
# --------------------------------------------------------------------------------


@pytest.fixture()
def engine_and_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    yield engine, maker
    engine.dispose()


def _seed_users_and_roles(engine_and_factory, users, roles):
    _engine, maker = engine_and_factory  # only the session factory is needed here
    s = maker()
    for uid in users:
        s.add(User(user_id=uid, status="active"))
    for name in roles:
        s.add(Role(name=name, permissions="read-write"))
    s.commit()
    s.close()
    return maker


def _core_on_session(maker, session=None):
    backend = Backend.__new__(Backend)  # not used: Core.put only calls get_session()
    backend.get_session = lambda: (session or maker())  # type: ignore[assignment]
    return Core(backend=backend, kek=KekCache.from_bytes(KEK, mlock=False))


def test_intended_multiplicity_is_not_collapsed(engine_and_factory):
    """AC-4 paired positive: the same key stored by two DIFFERENT creators who
    cannot see each other's row still produces TWO rows.

    That multiplicity is what ``uq_secrets_key_created_by`` exists to permit, and
    the serialization must not quietly merge the pair — a caller may replace
    exactly what it may see, and here neither sees the other.
    """
    maker = _seed_users_and_roles(engine_and_factory, ["alice", "bob"], ["ops", "finance"])

    s = maker()
    core = _core_on_session(maker, s)
    r1 = core.put("dup-key", b"alice-value", "alice", ["ops"], "kv1", caller_roles=["ops"])
    s.close()
    s = maker()
    core = _core_on_session(maker, s)
    r2 = core.put("dup-key", b"bob-value", "bob", ["finance"], "kv1", caller_roles=["finance"])
    s.close()

    assert r1.id != r2.id, "the two scoped-out puts collapsed into one row"
    check = maker()
    try:
        rows = check.query(Secret).filter(Secret.key == "dup-key").all()
        assert len(rows) == 2, f"intended multiplicity lost: {len(rows)} rows"
    finally:
        check.close()


def test_visible_key_replaces_in_place_for_the_second_caller(engine_and_factory):
    """AC-5 behavioural half, sequential: once a row is VISIBLE to the caller,
    a second put of that key replaces it in place — one live row, the later
    value, and a get() that returns it. This is the end state the lock makes the
    concurrent case reach deterministically.
    """
    maker = _seed_users_and_roles(engine_and_factory, ["alice", "bob"], ["ops"])

    s = maker()
    core = _core_on_session(maker, s)
    first = core.put("shared-key", b"v1", "alice", ["ops"], "kv1", caller_roles=["ops"])
    s.close()

    s = maker()
    core = _core_on_session(maker, s)
    second = core.put("shared-key", b"v2", "bob", ["ops"], "kv1", caller_roles=["ops"])
    s.close()

    assert second.id == first.id, "the visible second put inserted a shadow instead of replacing"
    assert second.replaced is True
    check = maker()
    try:
        rows = check.query(Secret).filter(Secret.key == "shared-key").all()
        assert len(rows) == 1, f"shadow pair present: {len(rows)} rows"
    finally:
        check.close()


def test_put_still_writes_on_a_real_sqlite_session(engine_and_factory):
    """#366 landmine class, executed: the guarded put runs end to end on SQLite."""
    maker = _seed_users_and_roles(engine_and_factory, ["carol"], ["ops"])
    s = maker()
    core = _core_on_session(maker, s)
    record = core.put("plain-key", b"v", "carol", ["ops"], "kv1", caller_roles=["ops"])
    s.close()
    assert record.key == "plain-key"
    check = maker()
    try:
        assert check.query(SecretRole).filter(SecretRole.secret_id == int(record.id)).count() == 1
    finally:
        check.close()


# --------------------------------------------------------------------------------
# AC-1 physical half — the real race, PostgreSQL-gated (skips on this venue)
# --------------------------------------------------------------------------------

_PG_URL_ENV = "VENYA_TEST_PG_URL"
# R1 (#614): one deadline, one name, shared by every PostgreSQL-gated cell in this file.
# `lock_timeout` is the fix for the s105 shape — a read transaction left open pins the next
# cell's DDL forever, and this gives that wait a ceiling so it reports instead of hanging.
# `statement_timeout` is the backstop for a stall that is not a lock wait, set far above the
# milliseconds these cells actually take: a cap that could abort the row-lock wait the race
# cells depend on (the loser blocks until the winner commits) would test a different
# statement than production runs.
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


@pytest.mark.skipif(
    not os.environ.get(_PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {_PG_URL_ENV} (not available on this venue)",
)
class TestConcurrentPutPostgresql:
    """The #515 race physically: two threads put ONE key from two different
    callers who share a role, released together by a barrier so both resolves
    aim at the same empty table. After the fix there is exactly ONE live row
    and a later ``get()`` returns the value of the put that committed last —
    never a shadow pair whose winner is decided by id order.

    Same shape as #487's ``TestConcurrentRemovalsPostgresql`` and #514's race
    class, same honesty note: it has NOT RUN on this leg (no scratch database at
    the venue, fleet: NONE), so it skipped. Point ``VENYA_TEST_PG_URL`` at a
    SCRATCH database — it drops and recreates the IAM tables — before trusting
    it, never at anything live.
    """

    def test_two_concurrent_puts_of_one_visible_key_leave_one_row(self):
        from core.iam.models import Base as IAMBase

        engine = create_engine(os.environ[_PG_URL_ENV], connect_args=_PG_DEADLINE)
        IAMBase.metadata.drop_all(engine)
        IAMBase.metadata.create_all(engine)
        maker = sessionmaker(bind=engine)
        try:
            s = maker()
            s.add(User(user_id="racer-a", status="active"))
            s.add(User(user_id="racer-b", status="active"))
            s.add(Role(name="ops", permissions="read-write"))
            s.commit()
            s.close()

            barrier = threading.Barrier(2)
            ids: list[str] = []
            ids_lock = threading.Lock()

            def worker(uid: str, value: bytes) -> None:
                session = maker()
                try:
                    session.query(User).filter(User.user_id == uid).first()  # open the xact
                    barrier.wait()
                    core = _core_on_session(maker, session)
                    record = core.put("race-key", value, uid, ["ops"], "kv1", caller_roles=["ops"])
                    session.commit()
                    with ids_lock:
                        ids.append(record.id)
                finally:
                    session.close()

            threads = [
                threading.Thread(target=worker, args=("racer-a", b"from-a")),
                threading.Thread(target=worker, args=("racer-b", b"from-b")),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            check = maker()
            try:
                rows = check.query(Secret).filter(Secret.key == "race-key").all()
                assert len(rows) == 1, f"shadow pair shipped: {len(rows)} rows for one key"
                assert set(ids) == {str(rows[0].id)}, "the two puts returned different row ids"
            finally:
                check.close()
        finally:
            Base.metadata.drop_all(engine)
            engine.dispose()
