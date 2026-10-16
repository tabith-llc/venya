# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the first-admin bootstrap race (#510).

``POST /init`` guarded "already initialized" with an UNLOCKED count and
``POST /init/complete`` never re-checked it, so two concurrent bootstrap flows
each ended with a full administrator: both step-1 calls read a count of zero,
each committed its own pending admin, and both step-2 calls enrolled.

These cells bind the REAL init routes to a real SQLite database (the #450
harness shape) and drive the state two concurrent step-1 calls leave behind —
TWO pending admin rows, each with its own membership — then complete both
ceremonies in order. Exactly one may enroll.

Backend honesty (stated rather than hidden): SQLite ignores ``FOR UPDATE`` and
has no ``pg_advisory_xact_lock``, so a green cell here proves the
in-transaction RE-CHECK, not the cross-process lock. The lock is pinned two
other ways — by statement construction (the #339 precedent) and by a
PostgreSQL-gated race class that SKIPS on a venue without a scratch database
(the #487 precedent). Which cell proves which AC is written on the cell.
"""

import json
import os
from types import SimpleNamespace

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import AuditEvent, Base, Role, RoleMember, User, WebAuthnCredential
from fastapi import FastAPI
from server.fido2.manager import Fido2Store, StoredCredential, WebAuthnError
from server.routes import init as init_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

PG_URL_ENV = "VENYA_TEST_PG_URL"
# R1 (#614): every engine a PostgreSQL cell builds is tracked and disposed when that cell
# ends, so a connection left checked out (and whatever transaction it still holds) cannot pin
# the NEXT file's drop_all. Disposal is part of the ordering, not cleanup for tidiness: the
# #607 s105 hang was exactly one idle-in-transaction read blocking a later DROP.
_PG_ENGINES: list = []


@pytest.fixture(autouse=True)
def _dispose_pg_engines():
    yield
    while _PG_ENGINES:
        _PG_ENGINES.pop().dispose()


# R1 (#614): one deadline, one name, shared by every PostgreSQL-gated cell in this file.
# `lock_timeout` is the fix for the s105 shape — a read transaction left open pins the next
# cell's DDL forever, and this gives that wait a ceiling so it reports instead of hanging.
# `statement_timeout` is the backstop for a stall that is not a lock wait, set far above the
# milliseconds these cells actually take: a cap that could abort the row-lock wait the race
# cells depend on (the loser blocks until the winner commits) would test a different
# statement than production runs.
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


class PerUserFido2:
    """Mock manager that issues one challenge per user and consumes it once.

    ``MockFido2Manager`` in test_init.py returns a single fixed challenge id,
    which cannot express two concurrent bootstrap flows; this one keys the
    challenge to the user so the second flow's step 2 is a distinct ceremony.
    Credential ids differ per user — the unique constraint on
    webauthn_credentials.credential_id must not be what refuses the loser.
    """

    def __init__(self):
        self._challenges = {}
        self.store = Fido2Store()

    def start_registration(self, user_id, username, existing_credential_ids=None):
        challenge_id = f"challenge-{user_id}"
        self._challenges[challenge_id] = {"user_id": user_id}
        return challenge_id, {
            "challenge": "dGVzdC1jaGFsbGVuZ2U",
            "rp": {"id": "localhost", "name": "Venya"},
            "user": {"id": "YWxpY2U", "name": user_id, "displayName": user_id},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "excludeCredentials": [],
            "attestation": "none",
        }

    def finish_registration(self, challenge_id, response):
        stored = self._challenges.pop(challenge_id, None)
        if stored is None:
            raise WebAuthnError("Challenge not found or expired")
        user_id = stored["user_id"]
        return StoredCredential(
            user_id=user_id,
            credential_id=f"cred-{user_id}".encode(),
            public_key=b"test-public-key",
            sign_count=0,
        )

    def stored_user_ids(self):
        return sorted(cred.user_id for cred in self.store._credentials.values())


def _stack(tmp_path, seed=None, fido2=None):
    """Real init routes + real SQLite, optionally seeded.

    No middleware: every /api/v1/init route sits in the public set, so the
    requests these cells send are the ones an unauthenticated caller can send
    in the bootstrap window — that window is the bug's whole surface.
    """
    db_path = tmp_path / "init510.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    if seed is not None:
        s = SessionLocal()
        seed(s)
        s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    fido = fido2 if fido2 is not None else PerUserFido2()
    app = FastAPI()
    app.state.backend = backend
    # No app.state.config on purpose: init_core bootstraps a CA from
    # config.ca_dir, and a config object here would point that at the real
    # /var/lib/venya/ca. The recovery-code pepper falls back to "" — the same
    # shape test_init.py's real-DB stack uses.
    app.state.fido2_manager = fido
    app.include_router(init_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), SessionLocal, fido


def _seed_roles(session):
    session.add_all(
        [
            Role(name="admin", permissions="read-write", description="System administrator — full access"),
            Role(name="user", permissions="read", description="Regular user — read-only access"),
        ]
    )
    session.commit()


def _seed_two_pending_admins(session):
    """THE RACE STATE: two pending admins, each with an admin membership.

    Two concurrent ``POST /init`` calls with different user_ids commit exactly
    this (each reads an enrolled count of zero, each inserts its own pending
    row). Written as a seeder instead of two HTTP calls because SQLite
    serializes requests, so the second call supersedes the first under Finding B
    and the interleaving never appears.
    """
    _seed_roles(session)
    admin_role = session.query(Role).filter(Role.name == "admin").one()
    for uid in ("alice", "bob"):
        session.add(User(user_id=uid, auth_mode="security-key", enrolled_at=None))
        session.add(RoleMember(user_id=uid, role_id=admin_role.id))
    session.commit()


def _complete(client, user_id):
    return client.post(
        "/api/v1/init/complete",
        json={
            "user_id": user_id,
            "challenge_id": f"challenge-{user_id}",
            # Valid base64url in id/rawId: the browser adapter converts them
            # before the ceremony is verified, so a malformed value dies there
            # and never reaches the code under test.
            "response": {"id": "dGVzdC1jcmVk", "rawId": "dGVzdC1jcmVk"},
        },
    )


def _enrolled_admins(session):
    return [u.user_id for u in session.query(User).filter(User.enrolled_at.isnot(None)).order_by(User.user_id).all()]


def _fields(row):
    """AuditEvent.fields round-trips as JSON text off a real DB read."""
    return json.loads(row.fields) if isinstance(row.fields, str) else row.fields


def _outcomes(session):
    rows = session.query(AuditEvent).filter(AuditEvent.event_type == "first_admin_enrolled").all()
    return sorted(str(_fields(r).get("outcome")) for r in rows)


class TestConcurrentFirstAdminEnrollment:
    """AC1 + AC3: at most one administrator may come out of the bootstrap."""

    def test_second_complete_is_refused(self, tmp_path):
        """RED at HEAD — both step-2 calls used to enroll.

        Proves, on the SQLite backend: the in-transaction re-check in
        init_complete refuses the loser, and the loser writes NO credential, NO
        recovery-code hash and NO enrolled_at, while the refusal itself lands a
        lifecycle audit row (AC1's audit half).
        """
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        fido.start_registration("bob", "bob")
        client, SessionLocal, fido = _stack(tmp_path, seed=_seed_two_pending_admins, fido2=fido)

        first = _complete(client, "alice")
        assert first.status_code == 201, first.text
        assert first.json()["success"] is True

        second = _complete(client, "bob")
        assert second.status_code == 409, second.text

        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["alice"], "exactly one admin may be enrolled"
            assert s.query(User).filter(User.user_id == "bob").one().enrolled_at is None
            assert s.query(User).filter(User.recovery_code_hash.isnot(None)).count() == 1, "loser wrote no code hash"
            assert [c.user_id for c in s.query(WebAuthnCredential).all()] == ["alice"], "loser stored no credential"
            assert _outcomes(s) == ["enrolled", "refused_already_initialized"]
        assert fido.stored_user_ids() == ["alice"], "loser's key never reached the in-memory store"

    def test_refusal_names_the_cause_and_is_not_a_500(self, tmp_path):
        """AC1: a named refusal, not a silent 500.

        The CLI lowercases the server detail and pattern-matches "already
        initialized" (cli/fido2_client.py carries ``detail`` through;
        cli/commands.py ``cmd_init`` branches on it), so the phrase is a
        contract — pinned here for the step-2 refusal, as step 1 already pins it.
        """
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        fido.start_registration("bob", "bob")
        client, _, _ = _stack(tmp_path, seed=_seed_two_pending_admins, fido2=fido)

        assert _complete(client, "alice").status_code == 201
        second = _complete(client, "bob")
        assert second.status_code == 409, second.text
        detail = second.json()["detail"].lower()
        assert "already initialized" in detail, detail
        assert not any(tok in detail for tok in ("insert", "select", "unique", "constraint", "psycopg", "traceback"))

    def test_refusal_is_stable_across_retries(self, tmp_path):
        """The loser is refused on STATE, not on a burnt challenge: with its
        challenge re-issued (a fresh ceremony), the answer is 409 again and the
        roster is still one admin."""
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        fido.start_registration("bob", "bob")
        client, SessionLocal, _ = _stack(tmp_path, seed=_seed_two_pending_admins, fido2=fido)

        assert _complete(client, "alice").status_code == 201
        assert _complete(client, "bob").status_code == 409

        fido.start_registration("bob", "bob")  # a second ceremony for the same user
        assert _complete(client, "bob").status_code == 409
        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["alice"]

    def test_step_one_still_refuses_after_enrollment(self, tmp_path):
        """PAIRED NEGATIVE for the step-1 change: the existing 409 stays. The
        advisory lock added to step 1 must not turn a completed core's refusal
        into a supersede or a 201."""
        fido = PerUserFido2()
        client, SessionLocal, _ = _stack(tmp_path, seed=_seed_roles, fido2=fido)
        assert client.post("/api/v1/init", json={"user_id": "alice"}).status_code == 201
        assert _complete(client, "alice").status_code == 201

        resp = client.post("/api/v1/init", json={"user_id": "mallory"})
        assert resp.status_code == 409, resp.text
        assert "already initialized" in resp.json()["detail"]
        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["alice"]


class TestSupersedeAndHappyPathStayGreen:
    """AC4 + the ordinary flow: the fix must not brick a legitimate bootstrap."""

    def test_abandoned_pending_is_superseded_then_completes(self, tmp_path):
        """AC4, same-user form: a key-less failed ceremony leaves a PENDING
        admin; a fresh ``venya init`` supersedes it and completes. No lock
        change may turn that retry into a 409."""
        client, SessionLocal, _ = _stack(tmp_path, seed=_seed_roles)

        # The abandoned row a device-less init commits before it dies.
        with SessionLocal() as s:
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            s.add(User(user_id="dusty", auth_mode="security-key", enrolled_at=None))
            s.add(RoleMember(user_id="dusty", role_id=admin_role.id))
            s.commit()

        assert client.post("/api/v1/init", json={"user_id": "dusty"}).status_code == 201
        resp = _complete(client, "dusty")
        assert resp.status_code == 201, resp.text
        assert resp.json()["recovery_code"]
        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["dusty"]
            assert s.query(WebAuthnCredential).count() == 1

    def test_abandoned_pending_under_a_new_user_id_still_completes(self, tmp_path):
        """AC4, different-user form: pending 'alice' is superseded by a fresh
        init for 'bob', whose ceremony then completes — one admin, not zero and
        not two. Completing the superseded 'alice' afterwards answers the
        pre-existing 400 ("No pending enrollment"), which the CLI word-maps."""
        client, SessionLocal, _ = _stack(tmp_path, seed=_seed_roles)
        assert client.post("/api/v1/init", json={"user_id": "alice"}).status_code == 201
        assert client.post("/api/v1/init", json={"user_id": "bob"}).status_code == 201

        assert _complete(client, "bob").status_code == 201
        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["bob"]
        assert _complete(client, "alice").status_code == 400

    def test_single_flow_init_completes_end_to_end(self, tmp_path):
        """The ordinary, unhurried bootstrap: step 1 then step 2 → 201 with a
        recovery code, one credential, one enrolled admin, one enrollment
        audit row and no refusal row."""
        client, SessionLocal, _ = _stack(tmp_path)

        step1 = client.post("/api/v1/init", json={"user_id": "alice"})
        assert step1.status_code == 201, step1.text
        assert step1.json()["challenge_id"] == "challenge-alice"

        step2 = _complete(client, "alice")
        assert step2.status_code == 201, step2.text
        assert len(step2.json()["recovery_code"].split("-")) == 8

        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["alice"]
            assert s.query(User).filter(User.user_id == "alice").one().status == "active"
            assert s.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == "alice").count() == 1
            assert _outcomes(s) == ["enrolled"]
            assert s.query(AuditEvent).filter(AuditEvent.event_type == "admin_initialized").count() == 1


class _RecordingDb:
    """A fake Session that reports a dialect and records the statements.

    Statement-construction cells only (the #339 precedent): SQLite cannot run
    pg_advisory_xact_lock/hashtext, so the lock's text, key and ORDERING
    relative to the reads are pinned here, and a separate cell drives the same
    route on a SQLite-named bind to pin the #366 dialect guard. ``first_values``
    is consumed in call order so a cell can name each read's answer.
    """

    class _Q:
        def __init__(self, db, models):
            self._db = db
            self._models = models

        def filter(self, *args, **kwargs):
            return self

        def join(self, *args, **kwargs):
            return self

        def with_for_update(self):
            self._db.calls.append(("for_update", self._models))
            return self

        def count(self):
            self._db.calls.append(("count", self._models))
            return 0

        def all(self):
            self._db.calls.append(("all", self._models))
            return []

        def first(self):
            self._db.calls.append(("first", self._models))
            if self._db.first_values:
                return self._db.first_values.pop(0)
            return None

    def __init__(self, dialect="postgresql", first_values=None):
        self.dialect_name = dialect
        self.calls = []
        self.first_values = list(first_values or [])

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect_name))

    def execute(self, statement, params=None):
        self.calls.append(("execute", str(statement), params))

    def query(self, *models):
        return _RecordingDb._Q(self, models)

    def add(self, obj):
        self.calls.append(("add", type(obj).__name__))

    def flush(self):
        self.calls.append(("flush", None))

    def commit(self):
        self.calls.append(("commit", None))

    def rollback(self):
        # get_db rolls back on any exception escaping the route, and the 409
        # refusal IS an exception — a fake without this method turns the
        # refusal into a 500 and hides what it pins.
        self.calls.append(("rollback", None))

    def close(self):
        self.calls.append(("close", None))


class _FakeBackend:
    def __init__(self, db):
        self._db = db

    def get_session(self):
        return self._db


def _app_with(db, fido):
    app = FastAPI()
    app.state.backend = _FakeBackend(db)
    # ca_dir points nowhere real: init_core would bootstrap a CA from it. Only
    # step-2 cells read this config (the recovery-code pepper).
    app.state.config = SimpleNamespace(recovery_code_pepper="pep", ca_dir="/nonexistent-510", ca_security=None)
    app.state.fido2_manager = fido
    app.include_router(init_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


def _pending_user(user_id="alice"):
    return SimpleNamespace(
        user_id=user_id, auth_mode="security-key", status=None, enrolled_at=None, recovery_code_hash=None
    )


class TestLockStatementConstruction:
    """AC2: the serialization statement, pinned as text, key and ordering."""

    def test_helper_emits_the_advisory_lock_on_a_pg_bind(self):
        db = _RecordingDb("postgresql")
        init_routes._lock_first_admin_bootstrap(db)
        executes = [c for c in db.calls if c[0] == "execute"]
        assert len(executes) == 1, db.calls
        stmt, params = executes[0][1], executes[0][2]
        assert "pg_advisory_xact_lock" in stmt
        assert "hashtext" in stmt
        assert ":key" in stmt, "the key must travel as a bind param, not interpolated"
        assert params == {"key": init_routes.INIT_BOOTSTRAP_LOCK_KEY}
        assert init_routes.INIT_BOOTSTRAP_LOCK_KEY not in stmt.split(":key")[0]

    def test_helper_is_a_no_op_on_sqlite(self):
        """The #366 class: on SQLite the same statement is a runtime "no such
        function" 500, so the guard must skip it entirely."""
        db = _RecordingDb("sqlite")
        init_routes._lock_first_admin_bootstrap(db)
        assert [c for c in db.calls if c[0] == "execute"] == [], db.calls

    def test_both_steps_use_one_key(self):
        """One key on purpose: step 1 and step 2 must serialize against each
        other, not merely against themselves."""
        one, two = _RecordingDb("postgresql"), _RecordingDb("postgresql")
        init_routes._lock_first_admin_bootstrap(one)
        init_routes._lock_first_admin_bootstrap(two)
        one_lock = next(c for c in one.calls if c[0] == "execute")
        two_lock = next(c for c in two.calls if c[0] == "execute")
        assert one_lock[2] == two_lock[2]

    def test_step_one_takes_the_lock_before_its_reads(self):
        db = _RecordingDb("postgresql", first_values=[None])  # no admin role yet
        app = FastAPI()
        app.state.backend = _FakeBackend(db)
        app.state.fido2_manager = PerUserFido2()
        app.include_router(init_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/init", json={"user_id": "alice"})
        assert resp.status_code == 201, resp.text
        kinds = [c[0] for c in db.calls]
        assert "execute" in kinds, f"no lock statement; calls={kinds}"
        assert kinds.index("execute") < kinds.index("first"), "lock must precede the already-initialized read"

    def test_step_two_takes_the_lock_before_its_reads(self):
        db = _RecordingDb(
            "postgresql",
            first_values=[SimpleNamespace(id=1, name="admin"), _pending_user("alice"), None],
        )
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        client = _app_with(db, fido)
        resp = _complete(client, "alice")
        assert resp.status_code == 201, resp.text
        kinds = [c[0] for c in db.calls]
        assert "execute" in kinds, f"no lock statement; calls={kinds}"
        assert kinds.index("execute") < kinds.index("first"), "lock must precede the roster reads"
        assert "for_update" in kinds, "the already-initialized re-check must be the locked variant"

    def test_step_two_on_sqlite_runs_without_the_pg_functions(self):
        """Runtime landmine cell (#366): the route must complete on a SQLite
        bind with no hashtext error, whatever the statement pins say."""
        db = _RecordingDb(
            "sqlite",
            first_values=[SimpleNamespace(id=1, name="admin"), _pending_user("alice"), None],
        )
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        client = _app_with(db, fido)
        resp = _complete(client, "alice")
        assert resp.status_code == 201, resp.text
        assert [c for c in db.calls if c[0] == "execute"] == [], db.calls

    def test_step_two_refuses_when_a_locked_read_finds_an_enrolled_admin(self):
        """The re-check's REFUSING half, pinned by construction: with the third
        read answering an admin id, the route answers 409 and adds nothing —
        no credential object, no user write."""
        db = _RecordingDb(
            "postgresql",
            first_values=[SimpleNamespace(id=1, name="admin"), _pending_user("alice"), ("bob",)],
        )
        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        client = _app_with(db, fido)
        resp = _complete(client, "alice")
        assert resp.status_code == 409, resp.text
        added = [c for c in db.calls if c[0] == "add"]
        assert added == [("add", "AuditEvent")], f"only the audit row may be added; got {added}"
        # The refusal commits its audit row, then raises; get_db's rollback
        # afterwards therefore lands on an empty transaction.
        kinds = [c[0] for c in db.calls]
        assert kinds.index("commit") < kinds.index("rollback"), kinds


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestConcurrentBootstrapPostgresql:
    """AC2 + AC6, physically: the two-connection race on PostgreSQL.

    WRITTEN, NOT RUN ON THIS LEG — the spec bars VMs and fleet, so this class
    skipped and its claims are unverified against a live server. Point
    VENYA_TEST_PG_URL at a SCRATCH database (it drops and recreates the IAM
    tables); never at anything live.

    This is the cell the SQLite suite cannot substitute: two Session objects on
    two connections released together by a barrier, so both step-2 re-checks
    aim at the same instant. The advisory lock makes the second wait for the
    first transaction to commit; its re-read then sees the enrolled admin
    (READ COMMITTED re-evaluates the locking scan) and refuses. Before the fix
    the outcome is timing-dependent — that is the race itself.
    """

    def _engine_and_factory(self):
        engine = create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)
        _PG_ENGINES.append(engine)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        return engine, sessionmaker(bind=engine)

    def test_two_connections_one_admin(self):
        import threading

        _, SessionLocal = self._engine_and_factory()
        s = SessionLocal()
        try:
            s.add_all([Role(name="admin", permissions="read-write"), Role(name="user", permissions="read")])
            s.commit()
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            for uid in ("alice", "bob"):
                s.add(User(user_id=uid, auth_mode="security-key", enrolled_at=None))
                s.add(RoleMember(user_id=uid, role_id=admin_role.id))
            s.commit()
        finally:
            s.close()

        fido = PerUserFido2()
        fido.start_registration("alice", "alice")
        fido.start_registration("bob", "bob")
        app = FastAPI()
        # The backend IS the per-request factory: `get_db` yields `backend.get_session()`, so wrapping
        # the shim in _FakeBackend hands the ROUTE the shim itself, which has neither get_bind() nor
        # execute() — the advisory-lock call in routes/init.py then raised AttributeError, both threads
        # got a 500, and the cell asserted on an empty admin list without ever reaching the lock. Pass
        # it directly (the shape test_init_reset_race_511.py:649 uses) and get_session() returns a real
        # Session, so this cell exercises the same engine path production does.
        app.state.backend = _SessionPerRequest(SessionLocal)
        app.state.config = SimpleNamespace(recovery_code_pepper="pep")
        app.state.fido2_manager = fido
        app.include_router(init_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        barrier = threading.Barrier(2)
        codes = {}

        def run(uid):
            barrier.wait(timeout=10)
            codes[uid] = _complete(client, uid).status_code

        threads = [threading.Thread(target=run, args=(uid,)) for uid in ("alice", "bob")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        s = SessionLocal()
        try:
            assert len(_enrolled_admins(s)) == 1, _enrolled_admins(s)
            assert s.query(WebAuthnCredential).count() == 1
            assert sorted(codes.values()) == [201, 409], codes
        finally:
            s.close()


class _SessionPerRequest:
    """Hands each get_session() call its own Session — two connections, one race."""

    def __init__(self, factory):
        self._factory = factory

    def get_session(self):
        return self._factory()


class TestSeededStateSanity:
    """Guard against a green cell that proves nothing: the seeder really does
    leave two pending admins, and the loser's ceremony really is a distinct
    challenge from the winner's."""

    def test_seeder_leaves_two_pending_admins(self, tmp_path):
        _, SessionLocal, _ = _stack(tmp_path, seed=_seed_two_pending_admins)
        with SessionLocal() as s:
            assert s.query(User).filter(User.enrolled_at.is_(None)).count() == 2
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            assert s.query(RoleMember).filter(RoleMember.role_id == admin_role.id).count() == 2

    def test_complete_without_a_ceremony_is_refused_before_the_guard(self, tmp_path):
        """PAIRED NEGATIVE for the guard's placement: a request with no issued
        challenge still dies in attestation (400), never with the 409 — so the
        refusal cannot be reached by skipping step 1."""
        client, _, _ = _stack(tmp_path, seed=_seed_two_pending_admins)
        resp = client.post(
            "/api/v1/init/complete",
            json={
                "user_id": "bob",
                "challenge_id": "challenge-nobody",
                "response": {"id": "dGVzdC1jcmVk", "rawId": "dGVzdC1jcmVk"},
            },
        )
        assert resp.status_code == 400, resp.text
        assert "Challenge not found" in resp.json()["detail"]
