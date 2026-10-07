# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#514 — the auditor separation-of-duties verdict runs on a SERIALIZED read.

``RoleManager.add_member`` computed the guard's resulting tier-set from an
unlocked read, so two concurrent grants (auditor + non-auditor) for one user
each saw only its own tier, both passed, and the mixture the ruling calls
IMPOSSIBLE shipped anyway — this is the ONE enforcement point, so defeating it
defeats the rule everywhere.

The fix is the shape this tree already ships twice (#339
``enrollment_manager.create_enrollment_token``, #510
``server/routes/init.py::_lock_first_admin_bootstrap``) plus the in-class
precedent ``_locked_admin_roster`` (#487): a per-user transaction-scoped
``pg_advisory_xact_lock`` (the only thing that serializes an EMPTY set — ``FOR
UPDATE`` locks matched rows, and the racing case has none yet) plus ``FOR
UPDATE`` on the memberships that do exist.

HARNESS NOTE, stated plainly (the ticket's STOP condition is a non-deterministic
concurrency cell, so this is how it is answered): the venue backend is SQLite,
which ignores ``FOR UPDATE`` and has no ``pg_advisory_xact_lock``. A two-THREAD
cell here cannot be deterministic in either direction — it would not fail at
HEAD and would not prove the lock after the fix. So the deterministic proof is
STATEMENT CONSTRUCTION, exactly what #339 shipped for the same reason: these
cells pin which statement runs, with which key, in which order — and the whole
content of the fix IS the statement. The physical race lives in the
PostgreSQL-gated class at the bottom of this file (the #487 shape); it skips on
this venue and is reported as NOT RUN, never as a passing proof. The real-
backend cells in the middle pin that the guard's BEHAVIOUR is untouched and that
the PG-only statement never reaches SQLite (the #366 landmine class, executed
rather than asserted).
"""

import os
import pathlib
import threading

import pytest
from core.iam.models import Base, Role, RoleMember, User
from core.iam.role_manager import RoleManager, SeparationOfDutiesError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# --------------------------------------------------------------------------------
# statement-recording fake
# --------------------------------------------------------------------------------


class _Dialect:
    def __init__(self, name: str) -> None:
        self.name = name


class _Bind:
    def __init__(self, name: str) -> None:
        self.dialect = _Dialect(name)


class _FakeRole:
    def __init__(self, role_id: int, permissions: str) -> None:
        self.id = role_id
        self.permissions = permissions


class _FakeMember:
    """RoleMember-shaped row — ``.role.permissions`` is what the guard reads."""

    def __init__(self, user_id: str, role: _FakeRole) -> None:
        self.user_id = user_id
        self.role_id = role.id
        self.role = role


class _FakeQuery:
    def __init__(self, db, model) -> None:
        self._db = db
        self._model = model
        self._locked = False

    @property
    def _recorder(self):
        return self._db.calls

    def filter(self, *args, **kwargs):
        return self

    def with_for_update(self):
        self._locked = True
        return self

    def first(self):
        self._recorder.append(("first", self._model, self._locked))
        if self._model is User:
            return User(user_id="someone")
        return None

    def all(self):
        self._recorder.append(("all", self._model, self._locked))
        if self._model is RoleMember:
            return list(self._db.existing_members)
        return []


class _FakeDb:
    """Records (kind, model, locked) per read and (execute, sql, params) per statement."""

    def __init__(self, dialect: str = "postgresql") -> None:
        self.calls: list[object] = []
        self.existing_members: list[_FakeMember] = []
        self._bind = _Bind(dialect)

    def get_bind(self):
        return self._bind

    def execute(self, statement, params=None):
        self.calls.append(("execute", str(statement), params))

    def query(self, model):
        self.calls.append(("query", model))
        return _FakeQuery(self, model)

    def add(self, obj):
        self.calls.append(("add", obj))

    def flush(self):
        self.calls.append(("flush",))

    def delete(self, obj):
        self.calls.append(("delete", obj))

    def lock_statements(self):
        return [c for c in self.calls if c[0] == "execute" and "advisory" in c[1]]

    def membership_reads(self):
        """(order-index, kind, locked?) for every RoleMember read, in call order."""
        return [(i, c[1], c[2]) for i, c in enumerate(self.calls) if c[0] in ("first", "all") and c[1] is RoleMember]


def _grant(db, permissions: str = "auditor") -> RoleManager:
    """A RoleManager whose role lookup answers with one role of the given tier."""
    manager = RoleManager(db)
    manager.get_role = lambda role_id: _FakeRole(role_id, permissions)  # type: ignore[method-assign]
    return manager


# --------------------------------------------------------------------------------
# AC-2 — the serialization statement, pinned deterministically
# --------------------------------------------------------------------------------


def test_per_user_advisory_lock_precedes_the_membership_read():
    """RED at HEAD: no advisory-lock statement exists at all.

    The lock must be taken BEFORE the read the SoD verdict computes from — a
    lock acquired after the read guards nothing.
    """
    db = _FakeDb()
    _grant(db).add_member("alice", 101)

    locks = db.lock_statements()
    assert locks, "no per-user advisory lock taken before the SoD membership read"
    reads = db.membership_reads()
    assert reads, "the guard never read the user's memberships"
    assert (
        db.calls.index(locks[0]) < reads[0][0]
    ), f"advisory lock at {db.calls.index(locks[0])} must precede the membership read at {reads[0][0]}"


def test_advisory_lock_is_xact_scoped_keyed_on_the_target_and_bound():
    """AC-2: transaction-scoped, keyed on the TARGET user, namespaced, and the
    user id travels as a bind param — never interpolated.

    * ``pg_advisory_xact_lock`` (not the session-scoped form): released at
      commit/rollback, so a grant can never park the key forever.
    * Keyed on the target user, so two admins granting to two different users
      stay independent; keying on the caller would serialize the admin plane.
    * Prefixed namespace, so this lock cannot collide with the #339 enrollment
      lock, which hashes a bare user id in the same advisory key space.
    """
    db = _FakeDb()
    _grant(db).add_member("alice", 101)

    sql = db.lock_statements()[0][1]
    params = db.lock_statements()[0][2]
    assert "pg_advisory_xact_lock" in sql, f"expected a transaction-scoped lock, got {sql}"
    assert "pg_advisory_lock(" not in sql, "session-scoped locks outlive the grant"
    assert "hashtext" in sql, "the key text must be hashed database-side"
    assert ":user_id" in sql, "the user id must travel as a bind param"
    assert params == {"user_id": RoleManager.MEMBERSHIP_LOCK_PREFIX + "alice"}, params
    assert "alice" not in sql, "no string-interpolated user id"

    other = _FakeDb()
    _grant(other).add_member("bob", 101)
    assert other.lock_statements()[0][2] != params, "the lock key is not per-user"


def test_sod_membership_read_carries_for_update():
    """AC-2 belt: the read the verdict computes FROM asks for the row lock.

    FOR UPDATE is what interlocks this read with the rows that DO exist, and it
    is the same posture ``_locked_admin_roster`` (#487) takes on this table.
    """
    db = _FakeDb()
    # The existing membership is SAME-tier so the add is allowed: this cell is
    # about which statement the verdict read through, not about the refusal.
    db.existing_members = [_FakeMember("carol", _FakeRole(7, "auditor"))]
    _grant(db).add_member("carol", 101)

    reads = db.membership_reads()
    assert reads, "no membership read happened"
    assert any(locked for _i, _kind, locked in reads), f"the SoD membership read is unlocked: {reads}"


def test_existing_tiers_still_refuse_through_the_locked_read():
    """Paired negative on the fake: the locked read is not a no-op — an
    existing non-auditor membership still produces the refusal."""
    db = _FakeDb()
    db.existing_members = [_FakeMember("dan", _FakeRole(7, "read-write"))]
    with pytest.raises(SeparationOfDutiesError) as exc:
        _grant(db).add_member("dan", 101)
    assert exc.value.tiers == ["auditor", "read-write"]


def test_sqlite_dialect_never_sees_the_pg_only_statement():
    """Paired negative (#366 landmine class): against a SQLite bind the
    PostgreSQL-only statement is NOT emitted.

    ``pg_advisory_xact_lock``/``hashtext`` on SQLite is a runtime "no such
    function" 500 — the exact regression the #366 guard exists to prevent. The
    FOR UPDATE request still goes out (SQLite ignores the clause), so the
    statement shape is unchanged on every backend.
    """
    db = _FakeDb(dialect="sqlite")
    _grant(db).add_member("erin", 101)

    assert db.lock_statements() == [], "PostgreSQL-only lock emitted against SQLite"
    assert any(
        locked for _i, _kind, locked in db.membership_reads()
    ), "the FOR UPDATE request must stay in the statement on every backend"


def test_remove_member_takes_the_same_per_user_lock():
    """AC-6: the delete path shares the grant path's lock key.

    A removal can never PRODUCE a mixed tier-set (it only shrinks one), so the
    SoD verdict needs no delete-side half — that is the answer AC-6 asks for.
    What the shared key buys is a consistent lock order, so a concurrent grant
    and removal for one user serialize rather than the grant answering off a
    row the removal is deleting. The last-admin half of remove's guards was
    already locked by ``_locked_admin_roster`` (#487).
    """
    db = _FakeDb()
    manager = _grant(db)
    manager.get_role_by_name = lambda name: None  # type: ignore[method-assign]
    db.existing_members = [_FakeMember("frank", _FakeRole(101, "auditor"))]

    manager.remove_member("frank", 101, caller_user_id=None)

    locks = db.lock_statements()
    assert locks, "remove_member did not take the per-user advisory lock"
    assert locks[0][2] == {"user_id": RoleManager.MEMBERSHIP_LOCK_PREFIX + "frank"}


def test_leg_ships_no_schema_migration():
    """AC-3 companion: this leg ships NO migration.

    The partial-unique-index backstop the ticket asks to consider is not
    expressible against ``role_members`` — that table carries no tier column.
    The tier lives on ``roles.permissions``, one FK away, and it can FLIP at
    runtime through ``update_role``. The only index-shaped alternative is an
    expression over ``role_id`` backed by a function lying about being
    IMMUTABLE: PostgreSQL accepts it and then keeps the entry stale on every
    tier flip, so the "backstop" would both refuse legitimate grants and fail to
    refuse the mixture it exists to refuse. A stale guard is worse than none, so
    AC-3 is ruled out — the full reasoning is in the leg report.
    """
    versions_dir = pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions"
    versions = sorted(p.name for p in versions_dir.glob("*.py"))
    assert versions, "alembic versions dir not found — this check is broken"
    assert not any(
        token in name.lower() for name in versions for token in ("sod", "auditor", "role_member")
    ), "unexpected schema migration in this leg — AC-3 was ruled out"


# --------------------------------------------------------------------------------
# AC-4 / AC-5 — behaviour retained on a real backend
# --------------------------------------------------------------------------------


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    s = maker()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _seed_user(session, user_id):
    session.add(User(user_id=user_id, status="active"))
    session.commit()


def _mk_role(session, name, permissions):
    role = Role(name=name, permissions=permissions)
    session.add(role)
    session.commit()
    return role


def test_grants_still_work_on_a_real_session(session):
    """AC-4 paired positives, real backend, and the #366 runtime half: the
    guard is not weakened by the serialization, and the PG-only statement never
    reaches SQLite — an executed cell, not just an asserted one.

    * auditor onto a clean slate — legal;
    * auditor + auditor — legal, still one tier;
    * non-auditor + non-auditor — legal;
    * a single-role add — unaffected.
    """
    _seed_user(session, "p1")
    aud1 = _mk_role(session, "aud-1", "auditor")
    aud2 = _mk_role(session, "aud-2", "auditor")
    rd = _mk_role(session, "read-1", "read")
    rw = _mk_role(session, "rw-1", "read-write")

    rm = RoleManager(session)
    assert rm.add_member("p1", aud1.id).role_id == aud1.id
    session.commit()
    rm.add_member("p1", aud2.id)
    session.commit()
    assert {m.role_id for m in rm.get_user_roles("p1")} == {aud1.id, aud2.id}

    _seed_user(session, "p2")
    rm.add_member("p2", rd.id)
    session.commit()
    rm.add_member("p2", rw.id)
    session.commit()
    assert {m.role_id for m in rm.get_user_roles("p2")} == {rd.id, rw.id}


def test_duplicate_membership_still_refused(session):
    """AC-4 paired negative: moving the duplicate check onto the locked read
    did not lose it."""
    _seed_user(session, "dup1")
    aud = _mk_role(session, "aud-dup", "auditor")
    rm = RoleManager(session)
    rm.add_member("dup1", aud.id)
    session.commit()
    with pytest.raises(Exception) as exc:
        rm.add_member("dup1", aud.id)
    assert "already a member" in str(exc.value)


def test_sequential_sod_refusal_and_audit_payload_still_fire(session):
    """AC-5 paired negative: the sequential refusal survives, and it still
    carries the structured payload the server writes ``auditor_sod_denied``
    from (``routes/roles.py::_audit_sod_denied`` reads ``error.user_id``,
    ``role_id`` and ``tiers`` — no re-query, no message matching)."""
    _seed_user(session, "n1")
    rd = _mk_role(session, "read-n1", "read")
    aud = _mk_role(session, "aud-n1", "auditor")

    rm = RoleManager(session)
    rm.add_member("n1", rd.id)
    session.commit()

    with pytest.raises(SeparationOfDutiesError) as exc:
        rm.add_member("n1", aud.id)

    assert exc.value.user_id == "n1"
    assert exc.value.role_id == aud.id
    assert exc.value.tiers == ["auditor", "read"]
    session.rollback()
    assert [m.role_id for m in rm.get_user_roles("n1")] == [rd.id], "the refused grant left a row behind"


def test_removal_still_works_on_a_real_session(session):
    """AC-6 behavioural half: the delete path still deletes, and the added
    lock statement does not break it on SQLite."""
    _seed_user(session, "r1")
    aud = _mk_role(session, "aud-r1", "auditor")
    rm = RoleManager(session)
    rm.add_member("r1", aud.id)
    session.commit()

    assert rm.remove_member("r1", aud.id, caller_user_id=None) is True
    session.commit()
    assert rm.get_user_roles("r1") == []


# --------------------------------------------------------------------------------
# AC-1 physical half — the real race, PostgreSQL-gated (skips on this venue)
# --------------------------------------------------------------------------------

_PG_URL_ENV = "VENYA_TEST_PG_URL"


@pytest.mark.skipif(
    not os.environ.get(_PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {_PG_URL_ENV} (not available on this venue)",
)
class TestConcurrentMixedGrantPostgresql:
    """The #514 race physically: two threads grant DIFFERENT tiers to one user,
    released together by a barrier so both guard reads aim at the same
    pre-grant state. Exactly one grant may land, and the final tier-set must
    never be mixed.

    Same shape as #487's ``TestConcurrentRemovalsPostgresql``, same honesty
    note: this has NOT RUN on this leg (no scratch database at the venue, and
    the leg spec says fleet: NONE), so it skipped. Point ``VENYA_TEST_PG_URL``
    at a SCRATCH database — it drops and recreates the IAM tables — before
    trusting it, never at anything live.
    """

    def _factory(self, engine):
        return sessionmaker(bind=engine)

    def test_one_of_two_concurrent_mixed_grants_is_refused(self):
        engine = create_engine(os.environ[_PG_URL_ENV])
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        factory = self._factory(engine)
        try:
            s = factory()
            s.add(User(user_id="race-1", status="active"))
            s.add(Role(name="race-aud", permissions="auditor"))
            s.add(Role(name="race-rw", permissions="read-write"))
            s.commit()
            aud_id = s.query(Role).filter(Role.name == "race-aud").one().id
            rw_id = s.query(Role).filter(Role.name == "race-rw").one().id
            s.close()

            outcomes: list[str] = []
            outcomes_lock = threading.Lock()
            barrier = threading.Barrier(2)

            def worker(role_id: int) -> None:
                session = factory()
                try:
                    # Open the transaction before the release so both guard
                    # reads target the same pre-grant state.
                    session.query(User).filter(User.user_id == "race-1").first()
                    barrier.wait()
                    try:
                        RoleManager(session).add_member("race-1", role_id)
                        session.commit()
                        verdict = f"granted:{role_id}"
                    except SeparationOfDutiesError:
                        session.rollback()
                        verdict = f"refused:{role_id}"
                    with outcomes_lock:
                        outcomes.append(verdict)
                finally:
                    session.close()

            threads = [threading.Thread(target=worker, args=(rid,)) for rid in (aud_id, rw_id)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            check = factory()
            try:
                tiers = {m.role.permissions for m in check.query(RoleMember).filter_by(user_id="race-1")}
            finally:
                check.close()

            assert len(outcomes) == 2, f"a thread died: {outcomes}"
            assert sorted(outcomes) == sorted([f"granted:{aud_id}", f"refused:{rw_id}"]) or sorted(outcomes) == sorted(
                [f"refused:{aud_id}", f"granted:{rw_id}"]
            ), f"both grants landed or both refused: {sorted(outcomes)}"
            assert len(tiers) == 1, f"mixed tier-set shipped: {sorted(tiers)}"
        finally:
            Base.metadata.drop_all(engine)
            engine.dispose()
