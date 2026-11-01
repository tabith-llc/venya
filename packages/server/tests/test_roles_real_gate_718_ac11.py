# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#718 AC11 — the cell that fails the wrong way: the REAL gate, after the boot re-apply.

The gap this file closes: every other cell that exercises the admin door REPLACES the gate
(#730's filed class — `dependency_overrides[require_admin]`), and the gate's own unit cells mock
the role manager. Nothing until now drove boot → re-apply → `require_admin` end to end with a
HUMAN session. This file does, in the #450 real-stack harness shape: the real
``server.middleware.auth.SessionMiddleware``, the real ``routes/admin`` router, the real
``require_admin`` dependency, the real ``RoleManager``, a real file-backed SQLite — and ZERO
``dependency_overrides``. The caller's identity arrives the way production delivers it: a bearer
token over a real ``sessions`` row, validated by the middleware's own gate stack
(``check_expiry``, the persisted ``access_token_expires_at``, the user-active predicate).

Both halves, per root AGENTS §2 (a filter/gate/permission check ships with its paired negative):

  NEGATIVE (the bug's face): an initialised core whose ``roles`` table was emptied, a live human
  session, the admin route — the REAL gate answers 403 with the exact shipped string
  ``Admin role not found`` (``dependencies.py``, ``require_admin``'s human-plane lookup).

  POSITIVE (the remedy's face): the same stack, the same session, after the ruled R-2623 boot
  re-apply (``role_seed.ingest_seed_roles`` — the function the app lifespan calls) puts the two
  product roles back and the human holds ``admin`` — the route answers 200 and the exact 403
  string is asserted ABSENT. That is AC11's own bar: "asserted absent on the happy path."

What this cell does NOT cover, stated so no later seat quotes it for more: the machine-plane
cert path and a served core (AC10) stay owner-present physical cells; nothing here touches a VM.
"""

from datetime import UTC, datetime, timedelta

from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import Base, User
from core.iam.models import Session as SessionModel
from core.iam.role_manager import RoleManager
from fastapi import FastAPI
from server.middleware.auth import SessionMiddleware
from server.role_seed import ingest_seed_roles
from server.routes import admin as admin_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

# The exact shipped strings, pinned from dependencies.py at this face — never from a paraphrase.
ADMIN_ROLE_NOT_FOUND = "Admin role not found"
BEARER = "bearer-ac11-real-gate"
ADMIN_LIST_PATH = "/api/v1/admin/users"
HUMAN = "ac11-human-admin"


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite.

    SQLite has no timestamptz (the model's ``timezone=True`` is a PG-only flag), so the
    middleware's aware-now expiry comparisons TypeError on round-tripped naive rows.
    Production (PostgreSQL) returns aware values, where this listener changes nothing.
    Copied in shape from ``test_init_reset_guard_450.py`` — the same problem, the same
    instrument, kept local so a peer's edit to that file cannot redden this cell.
    """
    if getattr(SessionModel, "_ac11_utc_loader", False):
        return
    SessionModel._ac11_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _seed_human_session(session):
    """An active user with a live bearer session and NO role rows — the #718 state itself.

    Every timestamp is offset-aware UTC (root §13); SQLite round-trips them naive and the
    loader above restores the offset, which is exactly the pair production's PG face does not
    need. The session is well inside every gate the middleware runs: idle window, hard cap,
    persisted token expiry, and ``is_user_active``.
    """
    now = datetime.now(UTC)
    session.add(
        User(
            user_id=HUMAN,
            display_name="AC11 real-gate human",
            status="active",
            auth_mode="security-key",
            enrolled_at=now - timedelta(minutes=2),
        )
    )
    session.add(
        SessionModel(
            user_id=HUMAN,
            created_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
            access_token=BEARER,
            access_token_jti="jti-ac11",
            access_token_expires_at=now + timedelta(seconds=300),
        )
    )
    session.commit()


def _stack(tmp_path):
    """Real middleware + real admin routes + real SQLite, with the roles table EMPTY.

    No ``dependency_overrides`` anywhere in this function or its cells: the gate runs as
    shipped, and the identity is one the middleware itself can produce from a bearer token.
    """
    _sqlite_utc_loader()
    db_path = tmp_path / "ac11.db"
    engine = create_engine(f"sqlite:///{db_path}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    _seed_human_session(s)
    s.close()

    from server.config import ServerConfig

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = factory

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-unused")
    app.state.backend = backend
    app.include_router(admin_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), factory, backend


def _get_as_human(client):
    return client.get(ADMIN_LIST_PATH, headers={"Authorization": f"Bearer {BEARER}"})


def test_empty_roles_real_gate_answers_the_named_403(tmp_path):
    """PAIRED NEGATIVE first — the state the row exists for, refused by the REAL gate.

    A cell that only asserted the happy path would pass equally on a gate that had been
    replaced or had stopped looking anything up. This one pins that the gate is live BEFORE
    the remedy: a valid session, no roles at all, and the answer is the exact shipped
    ``Admin role not found`` from ``require_admin``'s human-plane lookup.
    """
    client, _factory, _backend = _stack(tmp_path)
    resp = _get_as_human(client)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == ADMIN_ROLE_NOT_FOUND


def test_after_boot_reapply_real_gate_resolves_admin(tmp_path):
    """AC11's bar, verbatim: remedy applied, HUMAN session, ``require_admin`` resolves a real
    admin role, and the exact 403 string is asserted ABSENT on the happy path.

    The remedy is the ruled R-2623 shape called the way the lifespan calls it
    (``role_seed.ingest_seed_roles`` over the backend); the membership is written through the
    real ``RoleManager``, not a hand-placed row, so a drift in the grant path reddens this
    cell too. Then the SAME request that earned 403 above answers 200 — and the refusal
    string appears nowhere in the response body.
    """
    client, factory, backend = _stack(tmp_path)
    assert _get_as_human(client).json()["detail"] == ADMIN_ROLE_NOT_FOUND  # gate is live first

    created = ingest_seed_roles(backend)
    assert created == ["admin", "user"], created

    s = factory()
    try:
        rm = RoleManager(s)
        admin_role = rm.get_role_by_name("admin")
        assert admin_role is not None
        rm.add_member(HUMAN, admin_role.id)
        s.commit()
    finally:
        s.close()

    resp = _get_as_human(client)
    assert resp.status_code == 200, resp.text
    assert ADMIN_ROLE_NOT_FOUND not in resp.text
    assert resp.json()["users"][0]["user_id"] == HUMAN
