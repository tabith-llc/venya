"""Truth-table tests for Core.delete() against REAL foreign-key constraints.

Regression guard for ticket secret-delete-fk-500: DELETE /secrets/{key}
returned an unhandled 500 (psycopg2 ForeignKeyViolation on
execution_session_secrets) for any secret ever injected by an execution
session — a rotation dead-end. The pre-existing delete tests used
MagicMock(spec=Backend); a mock session can never raise an FK violation,
which is why the bug shipped (same species as the cli-409/F7
unit-green-insufficient signatures).

These tests bind the real Core.delete code path to a real SQLAlchemy session
on SQLite with PRAGMA foreign_keys=ON so the constraint physically fires.
The production Backend cannot bind to SQLite (its engine connect listener
executes PostgreSQL SET statements and re-raises), so a minimal get_session()
stub supplies the real sessions — engine plumbing is orthogonal to the
defect under test.
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.engine.core import Core
from core.iam.models import (
    Base,
    ExecutionSession,
    Executor,
    Role,
    Secret,
    SecretRole,
    SessionSecret,
    User,
)
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker


class RealSessionBackend:
    """Minimal backend stand-in supplying REAL SQLite sessions."""

    def __init__(self, session_factory):
        self._factory = session_factory

    def get_session(self):
        return self._factory()


@pytest.fixture()
def backend():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    s.add(User(user_id="admin1", status="active"))
    s.add(Executor(id="exec-t1", hostname="exec-t1", status="active"))
    s.add(Role(name="admin"))
    s.commit()
    s.close()

    yield RealSessionBackend(factory)
    engine.dispose()


def _seed_secret(backend, key="probe-secret", with_session_ref=True):
    """Seed a secret (+role scope, +expired-session join row). Returns (secret_id, session_id|None)."""
    s = backend.get_session()
    secret = Secret(
        key=key,
        encrypted_value=b"ct",
        nonce=b"nonce",
        wrapped_dek=b"dek",
        key_version_id="v1",
        created_by="admin1",
        meta={},
    )
    s.add(secret)
    s.flush()
    s.add(SecretRole(secret_id=secret.id, role_id=s.query(Role).first().id))
    sess_id = None
    if with_session_ref:
        sess = ExecutionSession(
            user_id="admin1",
            executor_id="exec-t1",
            expires_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        s.add(sess)
        s.flush()
        s.add(SessionSecret(session_id=sess.id, secret_id=secret.id, wrapped_value="wrapped"))
        sess_id = sess.id
    s.commit()
    sid = secret.id
    s.close()
    return sid, sess_id


class TestDeleteFkTruthTable:
    def test_delete_referenced_secret_succeeds(self, backend):
        """POSITIVE (the regression): FK-referenced secret deletes cleanly."""
        sid, sess_id = _seed_secret(backend)
        core = Core(backend=backend)

        assert core.delete("probe-secret", "admin1") is True

        s = backend.get_session()
        try:
            assert s.get(Secret, sid) is None
            assert s.query(SessionSecret).filter(SessionSecret.secret_id == sid).count() == 0
            assert s.query(SecretRole).filter(SecretRole.secret_id == sid).count() == 0
            # Session history survives — only the ephemeral join rows go.
            assert s.get(ExecutionSession, sess_id) is not None
        finally:
            s.close()

    def test_delete_unreferenced_secret_still_works(self, backend):
        sid, _ = _seed_secret(backend, key="lonely", with_session_ref=False)
        core = Core(backend=backend)

        assert core.delete("lonely", "admin1") is True

        s = backend.get_session()
        try:
            assert s.get(Secret, sid) is None
        finally:
            s.close()

    def test_delete_missing_returns_false(self, backend):
        core = Core(backend=backend)
        assert core.delete("nope", "admin1") is False

    def test_fk_enforcement_is_real(self, backend):
        """Harness guard: raw deletion of a referenced secret row WITHOUT the
        cleanup must raise IntegrityError. If this ever passes silently, FK
        enforcement is off and the truth table above proves nothing."""
        sid, _ = _seed_secret(backend, key="raw-probe")
        s = backend.get_session()
        try:
            with pytest.raises(IntegrityError):
                s.query(Secret).filter(Secret.id == sid).delete()
                s.commit()
            s.rollback()
        finally:
            s.close()
