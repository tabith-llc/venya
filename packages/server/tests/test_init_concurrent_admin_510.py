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
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

PG_URL_ENV = "VENYA_TEST_PG_URL"
#: The statement the #510 guard sends, and the write it exists to cover. Matched on purpose
#: (substring, not line numbers) so a reformat of the route cannot silently un-pin the #645 cells.
_ADVISORY_LOCK = "pg_advisory_xact_lock"
_ENROLLMENT_WRITE = "INSERT INTO webauthn_credentials"


def _shape(log):
    """A per-caller statement sketch for a failure message — pid, held-face, statement label only."""
    return {
        ident: [(pid, "HELD" if held else "NOT-HELD", stmt[:44]) for pid, held, stmt in rows]
        for ident, rows in log.items()
    }


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
            s.add(User(user_id="admin-user", auth_mode="security-key", enrolled_at=None))
            s.add(RoleMember(user_id="admin-user", role_id=admin_role.id))
            s.commit()

        assert client.post("/api/v1/init", json={"user_id": "admin-user"}).status_code == 201
        resp = _complete(client, "admin-user")
        assert resp.status_code == 201, resp.text
        assert resp.json()["recovery_code"]
        with SessionLocal() as s:
            assert _enrolled_admins(s) == ["admin-user"]
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

    RUN on the PostgreSQL door (s126, base `04eb349`, socket venue — see the #645 cells at the
    bottom of this class for what each one proves). Point VENYA_TEST_PG_URL at a SCRATCH database
    (it drops and recreates the IAM tables); never at anything live.

    Which cell proves which half (#645): the barrier race below proves the OUTCOME — one enrolled
    admin, the loser refused, on two real connections. It is NOT by itself the paired negative: it
    measured 2-of-3 GREEN with the ``db.execute(...)`` at routes/init.py:122-125 neutered, because
    thread timing alone can also produce [201, 409]. The #645 cells under it are the paired negative:
    one watches the statement arrive on the wire, one watches PostgreSQL refuse to let the bootstrap
    pass while another transaction holds the key, and one watches the key stay GRANTED to its own
    backend across the decision read and the enrollment write (and gone once that transaction ends).
    The third is the scope half, and it is the one that reddens on a lock that is taken and then
    released before the route decides — a shape the first two read green (see
    ``test_the_guard_is_held_across_the_decision_and_the_write``).

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

    def _pg_stack(self, SessionLocal, *user_ids):
        """Roles + PENDING admins + issued ceremonies — the state step 2 reads."""
        ids = user_ids or ("alice", "bob")
        with SessionLocal() as s:
            _seed_roles(s)
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            for uid in ids:
                s.add(User(user_id=uid, auth_mode="security-key", enrolled_at=None))
                s.add(RoleMember(user_id=uid, role_id=admin_role.id))
            s.commit()
        fido = PerUserFido2()
        for uid in ids:
            fido.start_registration(uid, uid)
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
        return TestClient(app, raise_server_exceptions=False), fido

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

    # ---- #645 AC2: the paired negative. All three cells below FAIL if the advisory lock leaves the route,
    # ---- and each of the three catches a face the others cannot (sent / waited-on / held-over-the-write).

    def test_the_route_sends_the_advisory_statement_from_both_connections(self):
        """AC2, first half — the statement arrives on the WIRE, once per racing connection.

        Pins the ``db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), ...)`` inside
        :func:`server.routes.init._lock_first_admin_bootstrap` (`routes/init.py:122-125` at base
        `04eb349`; grep the symbol, numbers rot), reached from the step-2 call site in
        :func:`init_complete` (`routes/init.py:637`).

        WHY a witness and not a row count: `test_two_connections_one_admin` above measures the
        race OUTCOME, and the outcome can also be produced by timing alone — measured at s126 with
        that ``db.execute`` neutered, it stayed GREEN on 2 of 3 runs (`assert 2 == 1`, left
        `['alice', 'bob']`, on the third). This cell cannot be satisfied by luck: an engine
        `before_cursor_execute` witness counts what psycopg2 actually hands PostgreSQL, and the
        assertion is one advisory statement from each of the two connections with the key bound as
        a parameter. Neuter the statement and `sent` is empty — no timing argument available.
        """
        import threading

        engine, SessionLocal = self._engine_and_factory()
        client, _ = self._pg_stack(SessionLocal)

        sent: list = []
        tally = threading.Lock()

        def witness(conn, cursor, statement, parameters, context, executemany):
            if "pg_advisory_xact_lock" in statement:
                with tally:
                    sent.append((threading.get_ident(), statement, parameters))

        event.listen(engine, "before_cursor_execute", witness)
        codes, bodies = {}, {}
        try:
            barrier = threading.Barrier(2)

            def run(uid):
                barrier.wait(timeout=10)
                resp = _complete(client, uid)
                codes[uid] = resp.status_code
                bodies[uid] = resp.text[:160]

            threads = [threading.Thread(target=run, args=(uid,)) for uid in ("alice", "bob")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        finally:
            event.remove(engine, "before_cursor_execute", witness)

        # AC3 first: the codes are asserted BEFORE the rows, so a harness 500 reads as a code, not
        # as "zero admins" — the swallowing that made #510's red uninformative.
        assert sorted(codes.values()) == [201, 409], f"codes={codes} bodies={bodies}"
        assert len(sent) == 2, f"expected one advisory statement per racing connection, saw {sent}"
        assert len({ident for ident, _, _ in sent}) == 2, f"not two connections: {sent}"
        assert all("hashtext" in stmt for _, stmt, _ in sent), sent
        assert all(params == {"key": init_routes.INIT_BOOTSTRAP_LOCK_KEY} for _, _, params in sent), sent

        with SessionLocal() as s:
            assert len(_enrolled_admins(s)) == 1, _enrolled_admins(s)
            assert s.query(WebAuthnCredential).count() == 1

    def test_the_route_waits_for_the_key_a_competing_transaction_holds(self):
        """AC2, second half (CAUSAL) — PostgreSQL itself refuses to let the bootstrap pass.

        The wire witness above proves the statement goes out; this one proves the statement is what
        serializes. A competing transaction takes the SAME key and holds it. On the shipping route
        the request then parks inside `pg_advisory_xact_lock` — visible as an ungranted advisory row
        for `hashtext(key)` in `pg_locks` — and only completes after the holder commits. Neuter the
        `db.execute` in :func:`_lock_first_admin_bootstrap` and the request returns 201 WHILE ANOTHER
        TRANSACTION HOLDS THE KEY, so the `blocked` assertion fails immediately; nothing here depends
        on two threads landing in the same millisecond.

        The holder is a competitor for the lock, not a stand-in for the route: the enrollment under
        test is performed by the real `/init/complete` route on a real connection.
        """
        import threading
        import time

        _, SessionLocal = self._engine_and_factory()
        client, _ = self._pg_stack(SessionLocal, "alice")
        key = init_routes.INIT_BOOTSTRAP_LOCK_KEY

        waiting_sql = text(
            "SELECT pid, classid, objid FROM pg_locks"
            " WHERE locktype = 'advisory' AND NOT granted"
            "   AND objid::bigint = hashtext(:key)::bigint"
        )

        holder = SessionLocal()
        observer = SessionLocal()
        box: dict = {}
        done = threading.Event()
        try:
            holder.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})
            assert holder.in_transaction(), "the holder must keep its transaction open to hold the key"
            objid = holder.execute(text("SELECT hashtext(:key)"), {"key": key}).scalar()

            def run():
                box["resp"] = _complete(client, "alice")
                done.set()

            racer = threading.Thread(target=run, daemon=True)
            racer.start()

            waited = []
            deadline = time.monotonic() + 5.0
            # Exit on EITHER observation: a wait row appeared (serialized) or the request came back
            # while the holder still had the key (not serialized) — the second is the mutation face.
            while not waited and not done.is_set() and time.monotonic() < deadline:
                waited = observer.execute(waiting_sql, {"key": key}).fetchall()
                if not waited and not done.is_set():
                    time.sleep(0.05)

            # AC3: the code is asserted before the row counts below, and an early 500 would surface
            # here as "the request finished" rather than as an empty admin list.
            blocked = not done.is_set()
            holder.commit()  # release the key; the route must then go through
            racer.join(timeout=30)

            assert blocked, (
                f"the bootstrap completed while another transaction held advisory key {key!r} "
                f"(hashtext {objid}); the route is not serializing on it. Observed "
                f"status={box.get('resp').status_code if 'resp' in box else 'still running'} "
                f"body={box.get('resp').text[:160] if 'resp' in box else ''}"
            )
            assert waited, f"no ungranted advisory lock row for hashtext({key!r}) = {objid} was ever observed"
            assert done.is_set(), "the request never finished after the holder released the key"
            assert box["resp"].status_code == 201, box["resp"].text[:200]
        finally:
            observer.close()
            holder.close()

        with SessionLocal() as s:
            assert len(_enrolled_admins(s)) == 1, _enrolled_admins(s)
            assert s.query(WebAuthnCredential).count() == 1

    def test_the_guard_is_held_across_the_decision_and_the_write(self):
        """AC2, third half (SCOPE) — the key is HELD over the decision and the write, not merely sent.

        WHAT THE TWO CELLS ABOVE DO NOT PROVE. The wire witness pins that the statement arrives; the
        causal wait pins that PostgreSQL parks a caller behind the key. Both are satisfied by a guard
        that is taken and then RELEASED before the route decides — a ``commit``/``rollback`` inserted
        between the lock and the re-check, or a session whose next statement lands on a second
        connection — and by a session-scoped ``pg_advisory_lock``, which holds the key past the commit
        and leaks it onto a pooled connection's next borrower. Measured on this leg against the shipped 19-cell
        file at ``492fe4e``, 8 runs per face (battery: ``flash1-645-mutation-battery-s134.py``; a single run of a
        timing red is an anecdote, so the cell ships with its repeat count):

        * guard taken, then released by a commit before the decision (M5b) — the shipped file read FULLY GREEN in
          2 of 8 runs. Its reds elsewhere were the barrier outcome cell (3/8) and the wire witness's ``codes``
          assertion (4/8): both schedule-shaped, both already disclaimed by this class's docstring. The causal-wait
          cell — the one that claims serialization — was red in 0 of 8.
        * session-scoped lock (M6) — 3 red cells, steady 8/8, and again not the causal one.

        This cell is red in 8 of 8 on M5b and 8 of 8 on M6, and on M5b it is the only cell that gets there.

        HOW THIS PINS IT WITHOUT A TIMING ARGUMENT. A ``before_cursor_execute`` witness asks the issuing
        BACKEND, on a raw DBAPI cursor of that same connection, two things at every statement: your pid,
        and whether ``pg_locks`` shows the key GRANTED to that pid right now. The assertions then read
        one caller's own statement log in that caller's own order, which no scheduler can change: the
        guard is the FIRST statement, every statement after it is sampled with the key granted, and
        every one of them runs on the SAME backend the guard was taken on. Release-early, key-drift and
        connection-migration each break a row with no race and no sleep. The last assertion is the other
        half of scope: once both responses are back, NO backend may still hold the key — read from the
        server, so swapping the function name cannot walk past it.

        The two-connection race is driven because AC2 asks for the two-caller outcome specifically;
        nothing here depends on how the two interleave.
        """
        import threading

        engine, SessionLocal = self._engine_and_factory()
        client, _ = self._pg_stack(SessionLocal)
        key = init_routes.INIT_BOOTSTRAP_LOCK_KEY

        # One predicate, two spellings, on purpose: the probe runs on a raw psycopg2 cursor (`%s`)
        # because it must not re-enter SQLAlchemy inside its own execute hook; the read-back runs
        # through a Session (`:key`). hashtext() returns a signed int4 while pg_locks stores the key as
        # an oid, so the low 32 bits are what a granted row can match — masked, never assumed positive.
        probe_sql = (
            "SELECT pg_backend_pid(), EXISTS ("
            "  SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted"
            "    AND pid = pg_backend_pid()"
            "    AND objid::bigint = (hashtext(%s)::bigint & 4294967295))"
        )
        left_sql = text(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted"
            "   AND objid::bigint = (hashtext(:key)::bigint & 4294967295)"
        )

        log: dict = {}
        tally = threading.Lock()

        def witness(conn, cursor, statement, parameters, context, executemany):
            probe = cursor.connection.cursor()
            try:
                probe.execute(probe_sql, (key,))
                pid, held = probe.fetchone()
            finally:
                probe.close()
            with tally:
                log.setdefault(threading.get_ident(), []).append((pid, bool(held), statement.replace("\n", " ")))

        event.listen(engine, "before_cursor_execute", witness)
        codes, bodies = {}, {}
        try:
            barrier = threading.Barrier(2, timeout=10)

            def run(uid):
                barrier.wait(timeout=10)
                resp = _complete(client, uid)
                codes[uid] = resp.status_code
                bodies[uid] = resp.text[:160]

            threads = [threading.Thread(target=run, args=(uid,)) for uid in ("alice", "bob")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        finally:
            event.remove(engine, "before_cursor_execute", witness)

        # AC3 first: codes before any lock table or row count, so a harness fault reads as a code.
        assert sorted(codes.values()) == [201, 409], f"codes={codes} bodies={bodies}"
        assert len(log) == 2, f"both callers must reach the engine, saw {len(log)} logs: {_shape(log)}"

        for ident, rows in log.items():
            guards = [i for i, (_, _, stmt) in enumerate(rows) if _ADVISORY_LOCK in stmt]
            assert len(guards) == 1, f"{ident}: expected exactly one guard statement, saw indexes {guards}"
            gi = guards[0]
            assert gi == 0, (
                f"{ident}: the guard is the {gi + 1}th statement of its own transaction, not the first — the "
                f"route decided before PostgreSQL could park it: {_shape(log)}"
            )
            guard_pid = rows[gi][0]
            covered = rows[gi + 1 :]
            assert covered, f"{ident}: nothing followed the guard, so it covers no decision: {_shape(log)}"
            # The guard's own row is sampled BEFORE it executes, so it is legitimately unheld there;
            # everything it exists to protect comes after it.
            unheld = [stmt[:70] for _, held, stmt in covered if not held]
            assert not unheld, (
                f"{ident}: the key was NOT granted to its own backend at {len(unheld)} statement(s) taken after "
                f"the guard — it left the transaction early, or never covered the decision: {unheld}"
            )
            moved = [(pid, stmt[:60]) for pid, _, stmt in covered if pid != guard_pid]
            assert not moved, (
                f"{ident}: the guard was taken on backend {guard_pid} but {len(moved)} statement(s) it is "
                f"supposed to cover ran on another backend: {moved}"
            )
            assert any(
                "FOR UPDATE" in stmt.upper() for _, _, stmt in covered
            ), f"{ident}: no guarded decision read reached the wire, so the held rows prove nothing: {_shape(log)}"

        writers = [ident for ident, rows in log.items() if any(_ENROLLMENT_WRITE in stmt for _, _, stmt in rows)]
        assert (
            len(writers) == 1
        ), f"exactly one caller may write the credential inside a guard, saw {len(writers)}: {_shape(log)}"

        with SessionLocal() as s:
            leftovers = s.execute(left_sql, {"key": key}).fetchall()
            assert leftovers == [], (
                f"advisory key {key!r} is still granted to backend pid(s) {[r[0] for r in leftovers]} after the "
                "bootstrap committed — the production guard is transaction-scoped, and a session-scoped lock "
                "would follow the pooled connection to its next borrower"
            )
            assert len(_enrolled_admins(s)) == 1, _enrolled_admins(s)
            assert s.query(WebAuthnCredential).count() == 1


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
