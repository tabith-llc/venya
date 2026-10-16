# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the reset-gate staleness race (#511).

``POST /api/v1/init/reset`` gated authority with ``require_admin_when_initialized``,
a FastAPI DEPENDENCY. Dependencies run before the handler body, so the gate's
answer is a snapshot of a moment that has already passed by the time the deletes
execute. The window #450 deliberately leaves open — an unauthenticated caller may
reset a core with no identity yet, because that is the ``venya init
--installation-reset`` bootstrap — is exactly the window this race drives through:

    attacker's reset passes the gate (core still looks uninitialized)
    operator's ``init_complete`` commits an enrolled admin
    attacker's handler body deletes the identity set that just landed

The fix re-asserts the precondition at the moment of the effect — the same
check-and-consume shape ``routes/executors.py`` uses for enrollment tokens — and
does it inside the first-admin bootstrap lock (#510) so a concurrent
``init_complete`` cannot commit in between.

Backend honesty, stated rather than hidden (the #510 posture): SQLite has no
``pg_advisory_xact_lock``, so the lock is skipped there (the #366 dialect guard).
The SQLite cells below therefore prove the IN-TRANSACTION RE-CHECK and its
ordering; the lock itself is pinned by statement construction, and the
two-connection version of this race lives in a PostgreSQL-gated class that
SKIPS on a venue with no scratch database. No cell here mocks the predicate: the
interleaving is a real second transaction committing a real enrolled admin.
"""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import (
    AuditEvent,
    Base,
    EnrollmentToken,
    Role,
    RoleMember,
    User,
    WebAuthnCredential,
)
from core.iam.models import (
    Session as SessionModel,
)
from fastapi import FastAPI, HTTPException
from server.dependencies import get_db
from server.middleware.auth import SessionMiddleware
from server.routes import init as init_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

RESET = "/api/v1/init/reset"
ADMIN_BEARER = "bearer-admin-511"


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite (the #450 helper).

    The model's ``timezone=True`` is a PostgreSQL-only flag; without this the
    middleware's aware-now expiry comparison TypeErrors on round-tripped naive
    rows. Production reads return aware values, where this changes nothing.
    """
    if getattr(SessionModel, "_race511_utc_loader", False):
        return
    SessionModel._race511_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _engine(tmp_path, name):
    engine = create_engine(f"sqlite:///{tmp_path / name}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)


def _http_stack(tmp_path, seed):
    """Real middleware + real init routes + real SQLite, seeded by ``seed``.

    The #450 shape: every identity in these cells is one the middleware can
    actually produce, and no dependency is overridden.
    """
    _sqlite_utc_loader()
    engine, SessionLocal = _engine(tmp_path, "reset511_http.db")
    s = SessionLocal()
    seed(s)
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{tmp_path / 'reset511_http.db'}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    from server.config import ServerConfig

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-unused")
    app.state.backend = backend
    app.include_router(init_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), SessionLocal


def _seed_empty(_session):
    """A core nobody has initialized yet."""


def _seed_roles(session):
    session.add_all(
        [
            Role(name="admin", permissions="read-write", description="System administrator — full access"),
            Role(name="user", permissions="read", description="Regular user — read-only access"),
        ]
    )
    session.commit()


def _seed_enrolled_admin(session, bearer=None, admin=True, user_id="admin-511"):
    """A completed bootstrap: enrolled admin, credential row, optional session."""
    now = datetime.now(UTC)
    admin_role = Role(name="admin", permissions="read-write")
    user_role = Role(name="user", permissions="read")
    session.add_all([admin_role, user_role])
    session.flush()
    session.add(User(user_id=user_id, auth_mode="webauthn", status="active", enrolled_at=now))
    session.flush()
    session.add(RoleMember(user_id=user_id, role_id=admin_role.id if admin else user_role.id))
    session.add(
        WebAuthnCredential(
            user_id=user_id,
            credential_id=f"CRED-{user_id}".encode(),
            public_key=b"pk",
            label="key",
            created_at=now,
        )
    )
    if bearer is not None:
        session.add(
            SessionModel(
                user_id=user_id,
                access_token=bearer,
                access_token_jti=f"jti-{bearer}",
                created_at=now,
                expires_at=now + timedelta(minutes=15),
                access_token_expires_at=now + timedelta(minutes=5),
            )
        )
    session.commit()


def _commit_enrolled_admin(SessionLocal, user_id="operator-admin"):
    """THE INTERLEAVING, as a real second transaction.

    This is what a concurrent ``POST /init/complete`` leaves behind: an enrolled
    admin with an admin membership and a stored credential. Written on its own
    session — the operator's connection — so the attacker's session sees committed
    state it did not read when its gate ran.
    """
    now = datetime.now(UTC)
    with SessionLocal() as s:
        admin_role = s.query(Role).filter(Role.name == "admin").first()
        if admin_role is None:
            admin_role = Role(name="admin", permissions="read-write")
            s.add(admin_role)
            s.flush()
        s.add(User(user_id=user_id, auth_mode="webauthn", status="active", enrolled_at=now))
        s.flush()
        s.add(RoleMember(user_id=user_id, role_id=admin_role.id))
        s.add(
            WebAuthnCredential(
                user_id=user_id,
                credential_id=f"CRED-{user_id}".encode(),
                public_key=b"pk",
                label="key",
                created_at=now,
            )
        )
        s.commit()


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else (row.fields or {})


def _events(session, event_type):
    return [e for e in session.query(AuditEvent).all() if e.event_type == event_type]


class TestGateAnswerGoesStale:
    """AC1: the wipe must be refused when identity lands between gate and handler.

    These cells call the real gate and the real handler in request order on ONE
    shared session — which is what FastAPI gives a request, since ``get_db`` is
    cached per request — with the operator's commit driven in between by a second
    session. Nothing is mocked: the predicate is the real ``deployment_is_initialized``
    reading a real database.
    """

    def _stack(self, tmp_path):
        engine, SessionLocal = _engine(tmp_path, "reset511_direct.db")
        backend = Backend(
            BackendConfig(database_url=f"sqlite:///{tmp_path / 'reset511_direct.db'}", kek=b"k" * KEK_SIZE)
        )
        backend._engine = engine
        backend._session_factory = SessionLocal
        return SessionLocal, backend

    def test_interleaving_really_does_flip_the_predicate(self, tmp_path):
        """Guard against a green cell that proves nothing.

        The attacker's session answers False on the gate's read and True after the
        operator commits — so the refusal below is reached by the race, not by a
        stub, and the handler's re-read is a genuine fresh look at committed state.
        """
        SessionLocal, _backend = self._stack(tmp_path)
        with SessionLocal() as s:
            _seed_roles(s)

        attacker = SessionLocal()
        try:
            assert init_routes.deployment_is_initialized(attacker) is False
            _commit_enrolled_admin(SessionLocal)
            assert init_routes.deployment_is_initialized(attacker) is True
        finally:
            attacker.close()
        with SessionLocal() as s:
            assert [u.user_id for u in s.query(User).filter(User.enrolled_at.isnot(None)).all()] == ["operator-admin"]

    def test_reset_refused_when_identity_lands_after_the_gate(self, tmp_path):
        """RED at HEAD: the gate passed as bootstrap, then an admin appeared.

        The handler must refuse, and the admin that landed in the window must
        survive with its credential and membership intact.
        """
        SessionLocal, backend = self._stack(tmp_path)
        with SessionLocal() as s:
            _seed_roles(s)

        attacker = SessionLocal()
        try:
            request = SimpleNamespace(
                state=SimpleNamespace(auth_user=None), app=SimpleNamespace(state=SimpleNamespace())
            )
            auth = init_routes.require_admin_when_initialized(request, backend, attacker)
            assert auth == {"caller": "bootstrap", "user_id": None}, "gate opened the bootstrap window"

            _commit_enrolled_admin(SessionLocal)

            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(init_routes.init_reset(db=attacker, auth_user=auth))
            assert excinfo.value.status_code == 409, excinfo.value.detail
        finally:
            attacker.rollback()
            attacker.close()

        with SessionLocal() as s:
            admin = s.query(User).filter(User.user_id == "operator-admin").one()
            assert admin.enrolled_at is not None
            assert s.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == "operator-admin").count() == 1
            assert s.query(RoleMember).filter(RoleMember.user_id == "operator-admin").count() == 1
            assert s.query(Role).filter(Role.name.in_(["admin", "user"])).count() == 2

    def test_refusal_is_audited_with_the_reason(self, tmp_path):
        """AC5: the refusal leaves its own record, value-free, naming the cause."""
        SessionLocal, backend = self._stack(tmp_path)
        with SessionLocal() as s:
            _seed_roles(s)

        attacker = SessionLocal()
        try:
            request = SimpleNamespace(
                state=SimpleNamespace(auth_user=None), app=SimpleNamespace(state=SimpleNamespace())
            )
            auth = init_routes.require_admin_when_initialized(request, backend, attacker)
            _commit_enrolled_admin(SessionLocal)
            with pytest.raises(HTTPException):
                asyncio.run(init_routes.init_reset(db=attacker, auth_user=auth))
        finally:
            attacker.rollback()
            attacker.close()

        with SessionLocal() as s:
            rows = _events(s, "core_reset_refused")
            assert len(rows) == 1, [(_e.event_type, _fields(_e)) for _e in s.query(AuditEvent).all()]
            assert rows[0].user_id is None, "the bootstrap window has no principal to name"
            assert _fields(rows[0]) == {
                "outcome": "refused",
                "reason": "initialized_after_gate",
                "wipe_executed": False,
            }
            # The wipe did not run, so no lifecycle deletion rows were invented.
            assert _events(s, "user_deleted") == []
            assert _events(s, "role_deleted") == []

    def test_refusal_names_the_cause_and_is_not_a_500(self, tmp_path):
        """AC1: a named refusal the operator can act on, with no internals."""
        SessionLocal, backend = self._stack(tmp_path)
        with SessionLocal() as s:
            _seed_roles(s)

        attacker = SessionLocal()
        try:
            request = SimpleNamespace(
                state=SimpleNamespace(auth_user=None), app=SimpleNamespace(state=SimpleNamespace())
            )
            auth = init_routes.require_admin_when_initialized(request, backend, attacker)
            _commit_enrolled_admin(SessionLocal)
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(init_routes.init_reset(db=attacker, auth_user=auth))
        finally:
            attacker.rollback()
            attacker.close()

        detail = str(excinfo.value.detail).lower()
        assert "already initialized" in detail, detail
        assert not any(
            tok in detail for tok in ("insert", "select", "delete", "unique", "constraint", "psycopg", "traceback")
        )


class TestLegitimatePathsStayGreen:
    """AC3 + AC4: the guard must not brick the flows the #450 truth table protects."""

    def test_bootstrap_reset_on_a_genuinely_empty_core_still_wipes(self, tmp_path):
        """AC3, the paired positive: no identity at the gate and none in the
        handler's re-check → the ``venya init --installation-reset`` window stays
        open and the reset answers 200."""
        client, SessionLocal = _http_stack(tmp_path, _seed_empty)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert _events(s, "core_reset_refused") == []

    def test_pending_enrollment_still_resettable(self, tmp_path):
        """Finding B posture retained: a PENDING admin is not identity, so the
        bootstrap reset still clears it (and the guard stays quiet)."""

        def seed(session):
            _seed_roles(session)
            admin_role = session.query(Role).filter(Role.name == "admin").one()
            session.add(User(user_id="pending-admin", auth_mode="security-key", status="pending_enrollment"))
            session.flush()
            session.add(RoleMember(user_id="pending-admin", role_id=admin_role.id))
            session.commit()

        client, SessionLocal = _http_stack(tmp_path, seed)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "pending-admin").count() == 0
            assert _events(s, "core_reset_refused") == []

    def test_admin_reset_of_an_initialized_core_still_wipes(self, tmp_path):
        """AC4's positive half, and the guard's discriminator: an identity-bearing
        caller is EXPECTED to see an initialized core, so the re-check must not
        refuse the legitimate admin reset."""
        client, SessionLocal = _http_stack(tmp_path, lambda s: _seed_enrolled_admin(s, bearer=ADMIN_BEARER))
        s = SessionLocal()
        s.add(EnrollmentToken(user_id="admin-511", token_hash="th", expires_at=datetime.now(UTC)))
        s.commit()
        s.close()

        resp = client.post(RESET, headers={"Authorization": f"Bearer {ADMIN_BEARER}"})

        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id != "system").count() == 0
            assert s.query(WebAuthnCredential).count() == 0
            assert _events(s, "user_deleted") and _events(s, "role_deleted")
            assert _events(s, "core_reset_refused") == []

    def test_anonymous_reset_still_answers_401(self, tmp_path):
        """AC4: the existing negative is retained — an initialized core, no
        identity offered, refused by the gate with the #450 wording, nothing deleted."""
        client, SessionLocal = _http_stack(tmp_path, _seed_enrolled_admin)

        resp = client.post(RESET)

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == "Authentication required to reset an initialized core"
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "admin-511").count() == 1

    def test_non_admin_session_still_answers_403(self, tmp_path):
        """AC4, the other half: an authenticated non-admin keeps the 403."""
        client, SessionLocal = _http_stack(
            tmp_path,
            lambda s: _seed_enrolled_admin(s, bearer="bearer-plain-511", admin=False, user_id="plain-511"),
        )

        resp = client.post(RESET, headers={"Authorization": "Bearer bearer-plain-511"})

        assert resp.status_code == 403, resp.text
        with SessionLocal() as s:
            assert s.query(User).count() == 1


class _RecordingDb:
    """A fake Session that reports a dialect and records the statement ORDER.

    Statement-construction cells only (the #339/#510 precedent): SQLite cannot run
    ``pg_advisory_xact_lock``/``hashtext``, so the reset guard's ordering — lock,
    then re-check, then any delete — is pinned here, and one cell drives the same
    route on a SQLite-named bind to pin the #366 dialect guard. ``first_values`` is
    consumed in call order so a cell can name each read's answer.
    """

    class _Q:
        def __init__(self, db, models):
            self._db = db
            self._models = models

        def filter(self, *args, **kwargs):
            return self

        def join(self, *args, **kwargs):
            return self

        def in_(self, *args, **kwargs):
            return self

        def first(self):
            self._db.calls.append(("first", self._models))
            if self._db.first_values:
                return self._db.first_values.pop(0)
            return None

        def all(self):
            self._db.calls.append(("all", self._models))
            return []

        def count(self):
            self._db.calls.append(("count", self._models))
            return 0

        def delete(self):
            self._db.calls.append(("delete", self._models))
            return 0

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

    def commit(self):
        self.calls.append(("commit", None))

    def rollback(self):
        # get_db rolls back when the 409 refusal escapes the route; a fake without
        # this method turns the refusal into a 500 and hides what it pins.
        self.calls.append(("rollback", None))

    def close(self):
        self.calls.append(("close", None))


class _FakeBackend:
    def __init__(self, db):
        self._db = db

    def get_session(self):
        return self._db


def _app_with(db):
    """One session for the whole request — the gate and the handler share it,
    exactly as they share the cached ``get_db`` session in production."""
    app = FastAPI()
    app.state.backend = _FakeBackend(db)
    app.state.config = SimpleNamespace(recovery_code_pepper="pep")
    app.include_router(init_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


class TestGuardPlacement:
    """AC2: WHERE the re-check sits, pinned by construction."""

    def test_reset_takes_the_lock_before_reading_the_state(self):
        """The lock goes out before the HANDLER's read, so a concurrent
        init_complete cannot commit in the gap the gate left open.

        The two reads that precede the lock are the gate's own look at the state —
        that is the dependency-before-handler ordering this ticket is about, and it
        is why the re-check after the lock has to exist at all.
        """
        db = _RecordingDb("postgresql", first_values=[None, None, None, None])
        client = _app_with(db)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        kinds = [c[0] for c in db.calls]
        assert "execute" in kinds, f"no lock statement; calls={kinds}"
        lock_at, delete_at = kinds.index("execute"), kinds.index("delete")
        assert [
            i for i, k in enumerate(kinds) if k == "first" and lock_at < i < delete_at
        ], f"no re-check read between the lock and the wipe; calls={kinds}"

    def test_reset_refuses_before_any_delete(self):
        """With the re-check reading identity (the third read answers a user id,
        after the two gate reads say uninitialized), the route adds only the audit
        row and issues NO delete at all."""
        db = _RecordingDb("postgresql", first_values=[None, None, ("operator-admin",)])
        client = _app_with(db)

        resp = client.post(RESET)

        assert resp.status_code == 409, resp.text
        kinds = [c[0] for c in db.calls]
        assert "delete" not in kinds, f"the wipe ran; calls={kinds}"
        assert [c for c in db.calls if c[0] == "add"] == [("add", "AuditEvent")]
        # Denial-side shape: the refusal row rides its own commit before the raise.
        assert kinds.count("commit") == 1, kinds
        detail = resp.json()["detail"].lower()
        assert "already initialized" in detail, detail

    def test_deletes_follow_the_recheck_on_a_clear_bootstrap(self):
        """The ordering the guard depends on, stated positively: gate reads, then
        the lock, then the re-check reads, then the deletes."""
        db = _RecordingDb("postgresql", first_values=[None, None, None, None])
        client = _app_with(db)

        assert client.post(RESET).status_code == 200

        kinds = [c[0] for c in db.calls]
        assert "delete" in kinds, kinds
        assert kinds.index("first") < kinds.index("delete"), "the re-check must precede the wipe"

    def test_reset_on_a_sqlite_bind_makes_no_pg_statements(self):
        """Runtime landmine cell (#366): the guard must not turn a legitimate
        reset into a "no such function" 500 on SQLite."""
        db = _RecordingDb("sqlite", first_values=[None, None, None, None])
        client = _app_with(db)

        resp = client.post(RESET)

        assert resp.status_code == 200, resp.text
        assert [c for c in db.calls if c[0] == "execute"] == [], db.calls


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


@pytest.mark.skipif(
    not __import__("os").environ.get(PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestResetVersusInitCompletePostgresql:
    """AC1 + AC2 physically, on two connections (WRITTEN, NOT RUN ON THIS LEG).

    The spec bars VMs and fleet for this leg, so this class skipped and its claims
    are unverified against a live server. Point ``VENYA_TEST_PG_URL`` at a SCRATCH
    database — it drops and recreates the IAM tables — never at anything live.

    This is the cell SQLite cannot substitute: a bootstrap reset and an
    ``init_complete`` released together against one PostgreSQL. The legal outcomes
    are the two orderings the lock produces — the reset wipes first and the
    enrollment then finds no pending row, or the enrollment lands first and the
    reset refuses. The ILLEGAL outcome is the bug: ``init_complete`` reporting 201
    (an operator holding a recovery code for an admin the reset then deleted).
    """

    def test_reset_never_deletes_a_committed_enrollment(self):
        import os
        import threading

        from tests.test_init_concurrent_admin_510 import PerUserFido2

        engine = create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)
        _PG_ENGINES.append(engine)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        # The state a step-1 init leaves: roles plus one PENDING admin whose
        # ceremony is in flight.
        with SessionLocal() as s:
            _seed_roles(s)
            admin_role = s.query(Role).filter(Role.name == "admin").one()
            s.add(User(user_id="operator-admin", auth_mode="security-key", enrolled_at=None))
            s.flush()
            s.add(RoleMember(user_id="operator-admin", role_id=admin_role.id))
            s.commit()

        fido = PerUserFido2()
        fido.start_registration("operator-admin", "operator-admin")

        def _client():
            app = FastAPI()
            app.state.backend = _SessionPerRequestBackend(SessionLocal)
            app.state.config = SimpleNamespace(recovery_code_pepper="pep")
            app.state.fido2_manager = fido
            app.include_router(init_routes.router, prefix="/api/v1")
            return TestClient(app, raise_server_exceptions=False)

        reset_client, complete_client = _client(), _client()
        codes = {}
        barrier = threading.Barrier(2)

        def run_reset():
            barrier.wait(timeout=10)
            codes["reset"] = reset_client.post(RESET).status_code

        def run_complete():
            barrier.wait(timeout=10)
            codes["complete"] = complete_client.post(
                "/api/v1/init/complete",
                json={
                    "user_id": "operator-admin",
                    "challenge_id": "challenge-operator-admin",
                    "response": {"id": "dGVzdC1jcmVk", "rawId": "dGVzdC1jcmVk"},
                },
            ).status_code

        threads = [threading.Thread(target=t) for t in (run_reset, run_complete)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        with SessionLocal() as s:
            survived = s.query(User).filter(User.user_id == "operator-admin").first()
            enrolled = survived is not None and survived.enrolled_at is not None
            # The bug shape: the operator was told 201 (a recovery code in hand)
            # and the unauthenticated reset then deleted that identity.
            assert not (codes.get("complete") == 201 and codes.get("reset") == 200 and not enrolled), codes
            if codes.get("complete") == 201:
                assert codes.get("reset") == 409, f"a live enrollment must refuse the wipe: {codes}"
                assert enrolled


class _SessionPerRequestBackend:
    """Hands each get_session() call its own Session — two connections, one race."""

    def __init__(self, factory):
        self._factory = factory

    def get_session(self):
        return self._factory()
