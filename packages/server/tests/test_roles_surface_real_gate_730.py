# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#730 — the roles surface crossed by the REAL gate, with its paired negatives.

Why this file exists. The role-writer cells in ``test_roles.py`` replaced the thing they were
supposed to test: ``test_roles.py::_create_test_app`` set ``dependency_overrides[require_admin]`` and
mounted its own local middleware class, so a change to the shipped gate could land with that whole
suite green and no cell ever reaching the code that actually refuses. Those cells do useful work —
they pin request validation, error mapping and the SoD audit shape inside the route bodies — and they
keep doing it. What they cannot do is answer "does the shipped refusal still fire?", because
``require_admin`` and the route bodies resolve ``RoleManager`` through the SAME function-local import
(``server/dependencies.py`` ``require_admin`` and eight sites in ``routes/roles.py``), so a per-cell
patch of that class patches the gate and the handler as one object. The gate cells live here, away
from that patch.

The stack is the #450/#718 real-stack shape: the shipped ``server.middleware.auth.SessionMiddleware``,
a file-backed SQLite, the real ``RoleManager``, the real ``require_admin`` / ``require_role``, and ZERO
``dependency_overrides``. A caller's identity arrives the way production delivers it — a bearer token
over a real ``sessions`` row.

LAYER, stated per negative (root AGENTS §2 asks for the paired check; #730 asks for the honest one).
#729 moved the five WRITERS to ``/api/v1/admin/roles…`` and left the three READERS where they were, so
the two halves now sit on opposite sides of one predicate: ``SessionMiddleware._is_admin_route`` is
``path.startswith("/api/v1/admin/")``, TRUE for the writers and FALSE for the readers. What that
predicate actually does is posture-dependent, and this stack runs the shipped library default —
``AdminMTLSConfig.enabled`` is False unless the deployment writes ``VENYA_ADMIN_MTLS__ENABLED=true``,
and the middleware's admin-certificate branch is entered only when it is True. So each refusal here
names who refused it, and at which posture:

  MIDDLEWARE   an unauthenticated request dies before any dependency runs, at either posture — the
               ``require_admin`` body never executes, proven by a write that stays unwritten. Which
               branch says so is posture-dependent: this stack leaves ``AdminMTLSConfig.enabled`` at
               its shipped default of False, so the session branch answers 401 ``Missing
               authentication token``; at the enabled posture the certificate branch is entered
               first and answers 403 on these writers. The dying is invariant, the 401 is not.
  GATE         with the certificate branch inert at this posture, the five writers refuse a session
               caller who holds no admin role, from ``require_admin``'s human-plane lookup, and an
               executor-class caller is refused by the shipped ``require_admin`` / ``require_role``
               branches. The executor rows inject identity the way the middleware's own executor
               grant builds it, because the middleware attaches NO executor identity on a roles path
               at any posture — its executor grants name ``/api/v1/heartbeat``,
               ``/api/v1/audit/ingest`` and the
               ``^/api/v1/sessions/[^/]+/(secrets/revoke|filter)$`` shape only. Crediting the
               middleware with either denial would claim a check it never performed.
  ROUTE        the three readers answer a caller who holds any membership.

The other posture — ``admin_mtls`` enabled, a BEARER caller refused on ``/api/v1/admin/roles`` at the
middleware's own certificate gate with 403 ``Admin access requires valid client certificate`` before
any dependency runs — is pinned at this face by ``test_roles_writer_admin_prefix_729.py``,
``TestRealMiddlewareDenials``. It is not re-pinned here: that file's cells replace ``require_admin``
with an entry marker, so what they observe is the middleware refusing and not the real gate, and this
file's stack leaves the flag at its default, so it could not observe it at all. Combining the enabled
posture with the unaltered gate needs certificate material and a served core — #730's AC7, the
owner-present physical cell.

Not covered here: the machine-plane admin certificate at the ENABLED posture with the real gate
behind it (an owner-present physical cell, see #730 AC7) and anything on a VM.

RED FACE, stated as a command a stranger can copy (#730 AC3). Put the replaced gate back into a
scratch copy of THIS file and six of the sixteen cells go red — the five refusals and the other-403
cell — because a laundered ``require_admin`` admits the non-admin caller and the write lands:

    cp packages/server/tests/test_roles_surface_real_gate_730.py packages/server/tests/zz_ctl.py
    # insert one line into _stack, before app.add_middleware(SessionMiddleware):
    #   app.dependency_overrides[server_deps.require_admin] = lambda: {"user_id": "x", "caller": "admin"}
    uv run -p 3.14 --directory packages/server pytest tests/zz_ctl.py -q
    rm -f packages/server/tests/zz_ctl.py packages/server/tests/__pycache__/zz_ctl*.pyc

Observed at this leg's re-pathed face (the tip named in the leg-823 report, base `6ea54e81`): **6
failed, 10 passed**, the six named in
`/tabith/wave44-specs-20261101/823-logs/redface-control-override-put-back.txt`. The runnable
pre-change face for this file is `f1eb83d4…` (leg 819's AC3 line); this file is absent from `6ea54e81`
and its cells there drove ``/api/v1/roles``, so the control above — not a checkout — is what a reader
of this face can run.
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import Base, Role, RoleMember, User
from core.iam.models import Session as SessionModel
from core.iam.role_manager import RoleManager
from fastapi import Depends, FastAPI
from server import dependencies as server_deps
from server.config import ServerConfig
from server.middleware.auth import SessionMiddleware
from server.role_seed import ingest_seed_roles
from server.routes import roles as roles_routes
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

# Exact shipped strings, read off dependencies.py and middleware/auth.py at this face — never a
# paraphrase, because a reworded refusal is supposed to redden the cell that pins it.
ADMIN_PERMISSION_REQUIRED = "Admin permission required"
ADMIN_ROLE_NOT_FOUND = "Admin role not found"
INVALID_OR_EXPIRED = "Invalid or expired token"
EXECUTOR_ROLE_GATE_DENIED = "Executor callers are not permitted on role-gated routes"
MISSING_TOKEN = "Missing authentication token"

MEMBER = "730-member-caller"  # holds the seeded "user" role: a reader, not a writer
ADMIN = "730-admin-caller"  # holds the seeded "admin" role in the granted stack only
TARGET = "730-target-user"  # the subject of member add / remove
BEARERS = {MEMBER: "bearer-730-member", ADMIN: "bearer-730-admin", TARGET: "bearer-730-target"}

ROLE_BODY = {"name": "730-new-role", "permissions": "read", "description": "written by the gate cells"}


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite.

    SQLite has no timestamptz (the model's ``timezone=True`` is a PG-only flag), so the middleware's
    aware-now expiry comparisons TypeError on round-tripped naive rows. Production (PostgreSQL)
    returns aware values, where this listener changes nothing. Kept local by house convention — #450,
    #511 and #718 AC11 each carry their own so a peer's edit cannot redden this cell.
    """
    Model730 = SessionModel
    if getattr(Model730, "_surface730_utc_loader", False):
        return
    Model730._surface730_utc_loader = True

    @event.listens_for(Model730, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _add_user_and_session(s, user_id: str) -> None:
    """An active user with a live bearer session, inside every gate the middleware runs."""
    now = datetime.now(UTC)
    s.add(
        User(
            user_id=user_id,
            display_name=f"#730 role-gate surface {user_id}",
            status="active",
            auth_mode="security-key",
            enrolled_at=now - timedelta(minutes=30),
        )
    )
    s.add(
        SessionModel(
            user_id=user_id,
            created_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
            access_token=BEARERS[user_id],
            access_token_jti=f"jti-730-{user_id}",
            access_token_expires_at=now + timedelta(seconds=300),
        )
    )


def _role_id(factory, name: str) -> int:
    s = factory()
    try:
        return s.execute(select(Role.id).where(Role.name == name)).scalar_one()
    finally:
        s.close()


def _stack(tmp_path, *, with_admin: bool):
    """Real middleware + real roles routes + real SQLite, with the gate unaltered.

    ``with_admin=False`` is the negative stack: both product seed roles exist — so a writer refusal is
    ``Admin permission required`` and not the different, also-shipped ``Admin role not found`` — the
    caller holds a real membership, and nobody holds admin. ``with_admin=True`` adds the admin
    membership through the real ``RoleManager``, the way a grant happens in production.

    No ``dependency_overrides`` and no ``RoleManager`` patch appears in THIS stack: the gate runs as
    shipped and answers from real rows. (``TestExecutorCallerIsRefusedAtTheGate`` is the file's one
    override, of ``get_current_user`` alone, and it says so on its own docstring — that stack mounts
    no middleware because the identity it drives is one no middleware produces on these paths.)
    """
    _sqlite_utc_loader()
    db_path = tmp_path / "surface730.db"
    engine = create_engine(f"sqlite:///{db_path}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    for user_id in BEARERS:
        _add_user_and_session(s, user_id)
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = factory

    # The two product roles, applied by the function the app lifespan applies.
    assert ingest_seed_roles(backend) == ["admin", "user"]

    # The member caller holds the seeded "user" role; nobody holds admin yet.
    s = factory()
    try:
        rm = RoleManager(s)
        rm.add_member(MEMBER, _role_id(factory, "user"))
        rm.add_member(TARGET, _role_id(factory, "user"))
        s.commit()
    finally:
        s.close()

    if with_admin:
        s = factory()
        try:
            rm = RoleManager(s)
            rm.add_member(ADMIN, _role_id(factory, "admin"))
            s.commit()
        finally:
            s.close()

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper-unused")
    app.state.backend = backend
    app.include_router(roles_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), factory, backend


def _as(caller: str):
    return {"Authorization": f"Bearer {BEARERS[caller]}"}


def _role_names(factory) -> list[str]:
    s = factory()
    try:
        return sorted(s.execute(select(Role.name)).scalars().all())
    finally:
        s.close()


def _member_pairs(factory) -> set[tuple[str, int]]:
    s = factory()
    try:
        return {(m.user_id, m.role_id) for m in s.execute(select(RoleMember)).scalars().all()}
    finally:
        s.close()


# The five writers, each gated by ``require_admin`` (routes/roles.py, pinned by @router decorator),
# at the ``/api/v1/admin/roles…`` paths #729 moved them to. The ids name that surface on purpose: a
# cell id reading "roles" while the request goes to "admin/roles" is how a stale path hides.
WRITERS = [
    pytest.param("post", "/api/v1/admin/roles", ROLE_BODY, id="POST-admin-roles-create"),
    pytest.param(
        "put",
        "/api/v1/admin/roles/{user_role}",
        {"description": "refused rewrite"},
        id="PUT-admin-roles-update",
    ),
    pytest.param("delete", "/api/v1/admin/roles/{user_role}", None, id="DELETE-admin-roles-delete"),
    pytest.param(
        "post",
        "/api/v1/admin/roles/{user_role}/members",
        {"user_id": TARGET},
        id="POST-admin-members-add",
    ),
    pytest.param(
        "delete",
        "/api/v1/admin/roles/{user_role}/members/" + TARGET,
        None,
        id="DELETE-admin-members-remove",
    ),
]


class TestWritersRefuseANonAdminSessionCaller:
    """PAIRED NEGATIVES, GATE layer: five writers, one real session caller who holds a role but not
    admin. Each answers the exact shipped 403 from ``require_admin``'s human-plane lookup, and the
    mutation never happens — which is the half a ``dependency_overrides`` stack cannot show, because
    in that stack there is nothing standing between the request and the write."""

    @pytest.mark.parametrize("verb, path_tpl, body", WRITERS)
    def test_writer_refuses_and_the_write_does_not_land(self, tmp_path, verb, path_tpl, body):
        client, factory, _backend = _stack(tmp_path, with_admin=False)
        user_role = _role_id(factory, "user")
        admin_role = _role_id(factory, "admin")
        path = path_tpl.replace("{user_role}", str(user_role))
        roles_before = _role_names(factory)
        members_before = _member_pairs(factory)

        kwargs = {"headers": _as(MEMBER)}
        if body is not None:
            kwargs["json"] = body
        resp = getattr(client, verb)(path, **kwargs)

        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == ADMIN_PERMISSION_REQUIRED
        # The refusal happened BEFORE the handler: nothing was created, renamed or deleted.
        assert _role_names(factory) == roles_before
        assert _member_pairs(factory) == members_before
        # And the caller is genuinely a non-admin, so this is the gate refusing and not a typo in the
        # fixture: the same real RoleManager the gate uses says so.
        s = factory()
        try:
            rm = RoleManager(s)
            assert rm.has_permission(MEMBER, admin_role, "read-write") is False
            assert rm.get_role_by_name("admin") is not None  # not the other 403, "Admin role not found"
        finally:
            s.close()

    def test_the_same_five_writers_admit_an_admin_session_caller(self, tmp_path):
        """POSITIVE half of the same five: the ONLY difference is the admin membership, granted
        through the real ``RoleManager``. A gate that refused everyone would pass the negatives above;
        this cell is what makes those refusals mean something."""
        client, factory, _backend = _stack(tmp_path, with_admin=True)
        user_role = _role_id(factory, "user")
        hdr = _as(ADMIN)

        created = client.post("/api/v1/admin/roles", json=ROLE_BODY, headers=hdr)
        assert created.status_code == 201, created.text
        assert created.json()["name"] == "730-new-role"

        renamed = client.put(f"/api/v1/admin/roles/{user_role}", json={"description": "admin rewrite"}, headers=hdr)
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["description"] == "admin rewrite"

        added = client.post(f"/api/v1/admin/roles/{user_role}/members", json={"user_id": ADMIN}, headers=hdr)
        assert added.status_code == 201, added.text
        assert (ADMIN, user_role) in _member_pairs(factory)

        removed = client.delete(f"/api/v1/admin/roles/{user_role}/members/{TARGET}", headers=hdr)
        assert removed.status_code == 200, removed.text
        assert (TARGET, user_role) not in _member_pairs(factory)

        deleted = client.delete(f"/api/v1/admin/roles/{created.json()['id']}", headers=hdr)
        assert deleted.status_code == 200, deleted.text
        assert "730-new-role" not in _role_names(factory)


class TestMiddlewareRefusesBeforeTheGateRuns:
    """MIDDLEWARE layer. A request with no bearer token never reaches ``require_admin``: the shipped
    ``SessionMiddleware`` answers for it, and the write the request asked for stays unwritten. The
    request below is the GATE half of the surface — a writer, now an admin route — and it dies before
    any dependency runs at either posture, because the identity check is entered first in both. The
    ANSWER it dies on is posture-specific: this stack leaves ``admin_mtls.enabled`` at its shipped
    default of False, so the session branch speaks 401 ``Missing authentication token``, and it is
    that sentence the cell below asserts. At the enabled posture the certificate branch is entered
    first — ``SessionMiddleware.dispatch`` runs the ``admin_mtls.enabled`` block ahead of its own
    ``Extract token`` line — so the answer is 403 ``Admin access requires valid client certificate``
    whatever the bearer header claims, which is ``test_roles_writer_admin_prefix_729.py``'s
    ``TestRealMiddlewareDenials`` on this same path, not a cell here."""

    def test_unauthenticated_writer_dies_at_401_with_the_write_unlanded(self, tmp_path):
        client, factory, _backend = _stack(tmp_path, with_admin=True)
        before = _role_names(factory)

        resp = client.post("/api/v1/admin/roles", json=ROLE_BODY)

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == MISSING_TOKEN
        assert _role_names(factory) == before  # the dependency body never executed

    def test_an_unknown_token_is_refused_by_the_middleware_not_the_gate(self, tmp_path):
        """The paired face: a bearer that names no session row is the middleware's problem too, and
        the refusal is the middleware's own ``Invalid or expired token`` — never the gate's 403 — so a
        reader cannot mistake a broken-identity 401 for an authorization decision."""
        client, _factory, _backend = _stack(tmp_path, with_admin=True)
        resp = client.get("/api/v1/roles", headers={"Authorization": "Bearer no-such-session-730"})
        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == INVALID_OR_EXPIRED


class TestExecutorCallerIsRefusedAtTheGate:
    """GATE layer, and labelled as such on purpose. The middleware's three executor grants name
    neither roles prefix — not ``/api/v1/roles``, which #729 left to the readers, and not
    ``/api/v1/admin/roles``, where it moved the writers — so no executor request can be driven here
    end to end without changing product code, which #730 does not do. Identity is therefore injected
    in exactly the dict shape the middleware's executor branch builds (``caller``/``executor_id``/
    ``presented_serial``/``revoked``, NO ``user_id``) and the REAL gate dependency answers. Overriding
    the identity lookup is not laundering: the cell is about the gate's decision, and ``require_admin``
    and ``require_role`` are mounted unaltered."""

    @staticmethod
    def _executor_identity():
        return {
            "caller": "executor",
            "executor_id": "exec-730",
            "presented_serial": "1234",
            "revoked": False,
        }

    @staticmethod
    def _app_on_real_stack(tmp_path, dependency):
        """A one-route app whose ONLY override is the identity, with the real gate on the route.

        The stack is built by ``_stack`` so the backend, the seed roles and the rows are the same real
        ones the HTTP cells above use; only its middleware is left off, because the identity this cell
        tests is one that middleware cannot produce on this path.
        """
        _client, _factory, backend = _stack(tmp_path, with_admin=True)
        app = FastAPI()
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper="test-pepper-unused")

        from server.dependencies import get_current_user

        app.dependency_overrides[get_current_user] = TestExecutorCallerIsRefusedAtTheGate._executor_identity

        @app.get("/probe")
        def _probe(
            _caller: dict = Depends(dependency),  # noqa: B008 -- DI in a default arg
        ) -> dict:
            return {"reached": True}  # pragma: no cover - the gate must answer first

        return TestClient(app, raise_server_exceptions=False), _factory

    def test_require_admin_denies_an_executor_caller_with_the_shipped_403(self, tmp_path):
        client, _factory = self._app_on_real_stack(tmp_path, server_deps.require_admin)
        resp = client.get("/probe")
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == ADMIN_PERMISSION_REQUIRED

    def test_require_role_denies_an_executor_caller_with_its_own_shipped_403(self, tmp_path):
        """The tiered gate the three readers use, same class of caller, a DIFFERENT shipped string —
        pinned separately so a change to either refusal reddens the cell that names it."""
        client, _factory = self._app_on_real_stack(tmp_path, server_deps.require_role("read"))
        resp = client.get("/probe")
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == EXECUTOR_ROLE_GATE_DENIED


class TestReadersAdmitAnyMembership:
    """ROUTE layer, the three ``require_role("read")`` readers. ``read`` is the floor of the closed
    tier vocabulary, so ANY membership passes — the caller here holds the seeded ``user`` role and no
    admin, which is precisely the caller the writers above refuse."""

    def test_roles_list_answers_a_non_admin_member(self, tmp_path):
        client, _factory, _backend = _stack(tmp_path, with_admin=False)
        resp = client.get("/api/v1/roles", headers=_as(MEMBER))
        assert resp.status_code == 200, resp.text
        names = {r["name"] for r in resp.json()["roles"]}
        assert {"admin", "user"} <= names

    def test_roles_get_answers_a_non_admin_member(self, tmp_path):
        client, factory, _backend = _stack(tmp_path, with_admin=False)
        resp = client.get(f"/api/v1/roles/{_role_id(factory, 'user')}", headers=_as(MEMBER))
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "user"

    def test_member_list_answers_about_a_group_the_caller_holds(self, tmp_path):
        client, factory, _backend = _stack(tmp_path, with_admin=False)
        user_role = _role_id(factory, "user")
        resp = client.get(f"/api/v1/roles/{user_role}/members", headers=_as(MEMBER))
        assert resp.status_code == 200, resp.text
        assert {m["user_id"] for m in resp.json()["members"]} == {MEMBER, TARGET}

    def test_member_list_of_a_group_the_caller_is_outside_stays_404(self, tmp_path):
        """The #448 scoping half, on the real stack: a reader admitted by the gate still does not get
        the admin roster, and the deny is the indistinguishable 404, never a 403."""
        client, factory, _backend = _stack(tmp_path, with_admin=False)
        admin_role = _role_id(factory, "admin")
        resp = client.get(f"/api/v1/roles/{admin_role}/members", headers=_as(MEMBER))
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"] == f"Role {admin_role} not found"

    def test_anonymous_caller_reads_nothing(self, tmp_path):
        """Negative pair for the readers: with no session the middleware answers, and no role list or
        roster is served."""
        client, _factory, _backend = _stack(tmp_path, with_admin=False)
        for path in ("/api/v1/roles", "/api/v1/roles/1", "/api/v1/roles/1/members"):
            resp = client.get(path)
            assert resp.status_code == 401, f"{path} -> {resp.text}"
            assert resp.json()["detail"] == MISSING_TOKEN


class TestGateStringsAreTheShippedOnes:
    """The two 403s a session caller can get from ``require_admin`` are DIFFERENT strings for
    different states, and the pair is the diagnosis. No admin role row at all -> ``Admin role not
    found``; the row exists and the caller is outside it -> ``Admin permission required``. #730's
    complaint was that no cell could tell these apart, because the gate was replaced."""

    def test_missing_admin_role_row_answers_the_other_403(self, tmp_path):
        client, factory, _backend = _stack(tmp_path, with_admin=False)
        user_role = _role_id(factory, "user")
        s = factory()
        try:
            s.query(RoleMember).filter(RoleMember.role_id == _role_id(factory, "admin")).delete()
            s.query(Role).filter(Role.name == "admin").delete()
            s.commit()
        finally:
            s.close()

        resp = client.post("/api/v1/admin/roles", json=ROLE_BODY, headers=_as(MEMBER))
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == ADMIN_ROLE_NOT_FOUND
        assert user_role is not None  # the caller's own membership survived; only the admin row went
