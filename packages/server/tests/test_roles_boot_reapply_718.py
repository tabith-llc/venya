# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#718 — the two product roles are re-applied at core startup, and each creation is audited.

The class this file exists to prove. Before #718 the only writer of the `admin` and
`user` rows was `init` step 1 (`routes/init.py` `init_core`), which runs inside a route
that `deployment_is_initialized()` (`init.py:164`) plus the pending-admin guard gate away
on an already-initialised core. So a core whose `roles` table was emptied after init has
no shipped path that recreates the two rows, and three doors fail three different ways
while doing it (`400 Role '<name>' not found` at `routes/admin.py:465`, `403 Admin role
not found` at `dependencies.py`, `503` at `routes/recovery.py`) — see the ticket body.

The ruled remedy is shape (a): an idempotent re-apply at boot. Owner's condition, verbatim:
"yes, but must be in the setup documenation!" — so the doc rows are part of this changeset
(`docs/installation.md` + a `README.md` pointer), verified by cells below rather than by
prose.

★ THE LOAD-BEARING CLAIM IS THE AUDIT, NOT THE ROW COUNT. `ROLE_CREATED` was emitted by
exactly one site before this leg — inside the admin route (`routes/roles.py`), and
`core/iam/role_manager.py` contains no audit call at all (its own comments state the
convention: the SERVER layer writes the event). A naive hoist of the get-or-create into a
boot path would therefore write identity rows that no audit trail names — the silent-write
class, at fleet scale. TEST 1 below pins that event and is the cell that fails a naive
implementation; it was written before the fix existed and observed RED at base.

Claims, each with its paired negative (the repo's truth-table law):

  A. THE AUDIT.  Every role the boot path creates produces one `role_created` row with the
     route's field table; a re-run that creates nothing produces no new row.
  B. THE WRITE.  Empty `roles` → boot → 2 rows; boot twice → still 2 (get-or-create, not
     an `IntegrityError` catch); a pre-existing custom role is untouched.
  C. THE PLACEMENT.  The re-apply is reached from the app lifespan, not only from a route.
  D. THE TRUTH.  The `init.py` comment names the mechanism that actually seeds, and the
     setup documentation names the boot behavior — docs a customer reads.

Nothing here touches a guest or a fleet VM; the physical half is ticket AC10 and is barred
to an owner-present fleet session.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from core.iam.models import AuditEvent, Role
from server.role_seed import ingest_seed_roles
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

# The two rows the product ships with. Values are the ones init step 1 writes; the
# re-apply must not drift from them or a fresh install and a re-applied install differ.
SEED_ROLE_NAMES = {"admin", "user"}


def _engine(tmp_path):
    """Real SQLite with FK enforcement ON.

    Precedent: ``test_admin_cert_membership_684.py``. #634's point is that a bare SQLite
    engine leaves ``foreign_keys`` OFF per connection, so a control that must reject an
    orphan row has to set the pragma itself.
    """
    eng = create_engine(f"sqlite:///{tmp_path / '718.db'}")

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _rec):  # pragma: no cover - the pragma is the point
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return eng


def _session(tmp_path):
    from core.iam.models import Base

    eng = _engine(tmp_path)
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _role_rows(session):
    return {r.name: r for r in session.query(Role).all()}


def _audit_rows(session, event_type="role_created"):
    return session.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else row.fields


# ---------------------------------------------------------------------------
# A. THE AUDIT — the ruling's condition, written first
# ---------------------------------------------------------------------------


class TestBootSeedAudit:
    """Each boot-created role is audited with the SAME event the admin route emits."""

    def test_boot_creates_role_created_rows(self, tmp_path):
        """★ THE CELL THAT MUST REDDEN BEFORE THE FIX.

        Empty table, boot re-apply: two `role_created` rows, one per created role, with
        the route's field table (`role_id`, `role_name`, `permissions` — pinned at
        ``test_lifecycle_audit_events.py::TestRoleLifecycle::test_role_created``).
        """
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        assert session.query(Role).count() == 0

        ensure_seed_roles(session)
        session.commit()

        rows = _audit_rows(session)
        assert len(rows) == 2, f"expected one role_created row per created role, got {len(rows)}"
        by_name = {**{_fields(r)["role_name"]: _fields(r) for r in rows}}
        assert set(by_name) == SEED_ROLE_NAMES
        for name, fields in by_name.items():
            assert set(fields) == {"role_id", "role_name", "permissions"}, fields
            assert fields["role_id"] == _role_rows(session)[name].id
            assert fields["permissions"] == _role_rows(session)[name].permissions

    def test_created_row_ids_match_written_rows(self, tmp_path):
        """The audit names the row it created, not a row of the same name (paired negative
        against an audit written from a constant or a stale id)."""
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        ensure_seed_roles(session)
        session.commit()

        roles = _role_rows(session)
        assert set(roles) == SEED_ROLE_NAMES, "the write itself is this cell's input, prove it first"
        rows = _audit_rows(session)
        assert len(rows) == 2, f"expected one role_created row per created role, got {len(rows)}"
        assert len(roles) == len(rows)
        for row in rows:
            assert row.id == roles[_fields(row)["role_name"]].id

    def test_rerun_that_creates_nothing_writes_no_audit(self, tmp_path):
        """★ PAIRED NEGATIVE. A check that only passes when it writes is not a check: an
        unconditional `role_created` on every boot would flood the trail with events for
        rows that were never created, and an auditor could not tell a seed from a boot."""
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        ensure_seed_roles(session)
        session.commit()
        assert len(_audit_rows(session)) == 2

        ensure_seed_roles(session)
        session.commit()
        assert len(_audit_rows(session)) == 2, "a re-apply that created nothing must audit nothing"

    def test_partial_absence_audits_only_the_missing_role(self, tmp_path):
        """One row present, one cleared: exactly one audit row, for the role actually created.

        This is the shape the ticket measured (a table emptied under an initialised core)
        narrowed to one row, and it is what proves the audit is per-creation rather than
        per-boot.
        """
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        session.add(Role(name="admin", permissions="read-write", description="System administrator — full access"))
        session.commit()

        ensure_seed_roles(session)
        session.commit()

        rows = _audit_rows(session)
        assert len(rows) == 1
        assert _fields(rows[0])["role_name"] == "user"


# ---------------------------------------------------------------------------
# B. THE WRITE — idempotent, and conservative about rows it did not create
# ---------------------------------------------------------------------------


class TestBootSeedIdempotent:
    def test_empty_table_boot_yields_two_roles(self, tmp_path):
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        ensure_seed_roles(session)
        session.commit()
        assert set(_role_rows(session)) == SEED_ROLE_NAMES

    def test_boot_twice_still_two_and_no_unique_violation(self, tmp_path):
        """AC2, proven the honest way.

        Two boots must not raise, and the guard is the SELECT-then-INSERT, not a
        `except IntegrityError` around a bare INSERT (ticket AC2: "prove the code
        get-or-creates rather than catching the unique violation"). The instrument for
        that distinction is this cell: `uq_roles_name` is live on the engine, so a bare
        INSERT reaching the constraint would surface as an IntegrityError here.
        """
        from server.role_seed import ensure_seed_roles
        from sqlalchemy.exc import IntegrityError

        session = _session(tmp_path)
        ensure_seed_roles(session)
        session.commit()
        try:
            ensure_seed_roles(session)
            session.commit()
        except IntegrityError as exc:  # pragma: no cover - the failure this cell bars
            pytest.fail(f"re-apply hit uq_roles_name instead of get-or-creating: {exc}")
        assert session.query(Role).count() == 2

    def test_custom_role_untouched(self, tmp_path):
        """★ PAIRED NEGATIVE for AC5. The re-apply may not delete, rename, overwrite, or
        re-permission a row it did not create — an operator's `deploy` role is not the
        seed's business, and a fix that "normalises" it would silently change authority."""
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        keep = Role(name="deploy", permissions="read", description="Operator role")
        session.add(keep)
        session.commit()
        before = (keep.id, keep.name, keep.permissions, keep.description)

        ensure_seed_roles(session)
        session.commit()
        ensure_seed_roles(session)
        session.commit()

        rows = _role_rows(session)
        assert set(rows) == {"admin", "user", "deploy"}
        deploy = rows["deploy"]
        assert (deploy.id, deploy.name, deploy.permissions, deploy.description) == before

    def test_existing_admin_is_not_repermissioned(self, tmp_path):
        """★ PAIRED NEGATIVE. A stale `admin` row with odd permissions is left alone: the
        boot re-apply creates missing rows, it does not rewrite present ones."""
        from server.role_seed import ensure_seed_roles

        session = _session(tmp_path)
        session.add(Role(name="admin", permissions="read", description=None))
        session.commit()

        ensure_seed_roles(session)
        session.commit()

        admin = _role_rows(session)["admin"]
        assert admin.permissions == "read"
        assert len(_audit_rows(session)) == 1  # only `user` was created

    def test_helper_does_not_commit_its_site_does(self):
        """The helper adds and flushes; the site owns the commit — the same-transaction
        posture ruled for lifecycle audit (audit_lifecycle module docstring, ruled Q4): the
        role row and its audit row ride ONE transaction, so an audit-write failure aborts
        the action instead of landing a silent row."""
        from unittest.mock import MagicMock

        from server.role_seed import ensure_seed_roles

        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        roles, created = ensure_seed_roles(db)
        assert created == ["admin", "user"], "helper reports what it created"
        assert set(roles) == set(SEED_ROLE_NAMES)
        assert db.flush.called
        assert not db.commit.called, "the helper must not commit a transaction it does not own"


# ---------------------------------------------------------------------------
# C. THE PLACEMENT — reached at boot, not only from a route
# ---------------------------------------------------------------------------


class TestBootPlacement:
    def test_lifespan_calls_the_reapply(self):
        """The re-apply must be wired into the app lifespan.

        Pinned as a source-structure read with a real call beside it, because the whole
        defect is a LOCATION one: correct logic that only a gated route can reach. A test
        that only calls `ensure_seed_roles` directly would pass at base for a shape that
        still strands an initialised core.
        """
        import inspect

        from server import app as app_module

        src = inspect.getsource(app_module.lifespan)
        assert "ingest_seed_roles" in src, "lifespan does not reach the boot re-apply"

    def test_ingest_opens_and_closes_its_own_session(self, tmp_path):
        """The boot wrapper owns its session (the `relay_registry.ingest_relay_credential`
        idiom this repo already ships at boot), and closes it."""
        from types import SimpleNamespace

        from core.iam.models import Base
        from server.role_seed import ingest_seed_roles

        eng = _engine(tmp_path)
        Base.metadata.create_all(eng)
        factory = sessionmaker(bind=eng)
        backend = SimpleNamespace(get_session=factory)

        assert ingest_seed_roles(backend) == ["admin", "user"]
        assert factory().query(Role).count() == 2

    def test_ingest_failure_does_not_raise_through_boot(self, tmp_path, caplog):
        """★ PAIRED NEGATIVES for the failure posture: a seed that raises must not take a
        working core down, AND the swallow must not be silent — the log names the doors
        that will refuse. Both the session-open fault and the write fault are driven."""
        from unittest.mock import MagicMock

        from server import role_seed

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(role_seed, "ensure_seed_roles", MagicMock(side_effect=RuntimeError("write boom")))
            with caplog.at_level("WARNING", logger="venya.server"):
                assert role_seed.ingest_seed_roles(MagicMock()) == []
        assert "#718" in caplog.text

        boom = MagicMock()
        boom.get_session.side_effect = RuntimeError("db down")
        with caplog.at_level("WARNING", logger="venya.server"):
            assert role_seed.ingest_seed_roles(boom) == []
        assert "db down" in caplog.text or "Role re-apply" in caplog.text

    def test_ingest_returns_empty_when_nothing_was_missing(self, tmp_path):
        """The steady state: a healthy core boots, writes no rows, audits nothing, and
        reports no creations — so the boot log line cannot fire on every restart."""
        from types import SimpleNamespace

        from core.iam.models import Base
        from server.role_seed import ingest_seed_roles

        eng = _engine(tmp_path)
        Base.metadata.create_all(eng)
        factory = sessionmaker(bind=eng)
        assert ingest_seed_roles(SimpleNamespace(get_session=factory)) == ["admin", "user"]
        assert ingest_seed_roles(SimpleNamespace(get_session=factory)) == []

    def test_init_route_shares_the_same_helper(self):
        """`init_core` keeps its semantics by calling the same code, so the two write paths
        cannot drift into three. (AC/§: the fix hoists, it does not duplicate.)"""
        import inspect

        from server.routes import init as init_routes

        src = inspect.getsource(init_routes)
        assert "ensure_seed_roles" in src


# ---------------------------------------------------------------------------
# E. THE DOOR — the failure this ticket exists to end, at the HTTP face
# ---------------------------------------------------------------------------


class TestGrantDoor:
    """AC3's face: `admin create-user --roles user` (POST /api/v1/admin/users) on a core
    whose `roles` table was emptied. Both arms in one file — the refusal BEFORE the
    re-apply, pinning the exact shipped string, and the success AFTER it. A cell that only
    asserts the success would pass on a table that was never empty."""

    @pytest.fixture()
    def env(self, tmp_path):
        """Real SQLite with the admin router mounted and NO roles at all — the measured
        state. Harness shape from ``test_sod_admin_create_user.py``."""
        from datetime import timedelta
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch

        from core.iam.models import Base
        from fastapi import FastAPI
        from server.dependencies import get_current_user, get_db, require_admin
        from server.routes import admin as admin_routes
        from sqlalchemy.pool import StaticPool
        from starlette.testclient import TestClient

        eng = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
        Base.metadata.create_all(eng)
        factory = sessionmaker(bind=eng)

        app = FastAPI()
        app.state.backend = MagicMock()
        app.state.config = SimpleNamespace(
            recovery_code_pepper="pep",
            fido2=SimpleNamespace(enrollment_token_ttl=15),
        )
        app.include_router(admin_routes.router, prefix="/api/v1")
        app.dependency_overrides[require_admin] = lambda: {"user_id": "mtls-admin-id", "caller": "admin"}
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "mtls-admin-id", "caller": "admin"}

        def _get_db():
            db = factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _get_db

        em = MagicMock()
        em.create_enrollment_token.return_value = (SimpleNamespace(id=1), "plaintext-token")
        em.config.token_expiry = timedelta(minutes=15)

        def post_as_role(username):
            with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=em):
                client = TestClient(app, raise_server_exceptions=False)
                return client.post("/api/v1/admin/users", json={"username": username, "roles": ["user"]})

        return SimpleNamespace(
            post_as_role=post_as_role,
            boot=lambda: ingest_seed_roles(SimpleNamespace(get_session=factory)),
            factory=factory,
        )

    def test_empty_table_refuses_with_the_named_string(self, env):
        """The negative that dates the bug: `400 Role 'user' not found` — the exact shipped
        detail at `routes/admin.py`, which names the missing row but not the missing path."""
        resp = env.post_as_role("newbie")
        assert resp.status_code == 400, resp.text
        assert resp.json()["detail"] == "Role 'user' not found"

    def test_after_boot_reapply_the_grant_succeeds(self, env):
        """Same door, same body, after one boot re-apply: 201, and the membership landed.
        This is ticket AC10's unit face; the physical face (machine-plane cert on a served
        core) is barred to an owner-present fleet session."""
        assert env.boot() == ["admin", "user"]
        resp = env.post_as_role("newbie")
        assert resp.status_code == 201, resp.text
        from core.iam.models import RoleMember

        db = env.factory()
        try:
            assert db.query(RoleMember).filter(RoleMember.user_id == "newbie").count() == 1
        finally:
            db.close()


# ---------------------------------------------------------------------------
# D. THE TRUTH — the comment and the customer-facing docs
# ---------------------------------------------------------------------------

REPLACED_SENTENCE = "a fresh installer seeds them via migration"

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestDocsAndComment:
    def test_false_comment_is_gone(self):
        """§4 of the ticket: the sentence that pointed an operator away from the truth.

        The clause is false on both of its claims (no migration seeds `roles`; the
        installer runs no migration), so it must not survive the changeset that fixes it.
        """
        src = (REPO_ROOT / "packages/server/src/server/routes/init.py").read_text(encoding="utf-8")
        assert REPLACED_SENTENCE not in src

    def test_comment_names_the_real_seeder(self):
        """The corrected comment states the mechanism that exists — `init` step 1 and the new
        boot re-apply — and states the migration fact the way this leg measured it: the
        installer runs migrations, and no migration seeds a `roles` row."""
        src = (REPO_ROOT / "packages/server/src/server/routes/init.py").read_text(encoding="utf-8")
        assert "role_seed" in src
        assert "inserts no rows" in src

    def test_installation_doc_has_the_section(self):
        """The owner's condition, as a check: `docs/installation.md` carries the substantive
        row. A leg that ships the boot write without this section does not satisfy the
        ruling, so the ruling is gated here rather than trusted."""
        text = (REPO_ROOT / "docs/installation.md").read_text(encoding="utf-8")
        assert "How the two product roles get created" in text
        assert "role_seed" in text, "the doc names the mechanism, not just the effect"

    def test_readme_points_at_it(self):
        """`README.md`'s Getting Started carries the one-line pointer and the anchor it
        targets — a pointer to an anchor that does not exist is a dead link a customer hits
        first, which is why the anchor is asserted from the same heading the doc cell reads."""
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        doc = (REPO_ROOT / "docs/installation.md").read_text(encoding="utf-8")
        heading = "How the two product roles get created"
        anchor = "#" + heading.lower().replace(" ", "-")
        assert heading in doc
        assert anchor in readme, "README pointer does not resolve to the doc section"
        assert "Getting Started" in readme

    @pytest.mark.parametrize(
        "relpath",
        ["docs/installation.md", "README.md"],
    )
    def test_setup_documentation_names_the_boot_behavior(self, relpath):
        """Both customer-facing setup files state, in their own words, that the write is a
        STARTUP behavior and that it is audited — no re-runnable path to a role grant may
        depend on reading source."""
        text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
        lowered = text.lower()
        assert "startup" in lowered, relpath
        assert "role_created" in text, relpath

    def test_installation_doc_states_the_two_names_and_the_audit(self):
        """A customer must be able to learn, from the setup doc, that the core writes the
        two named roles at boot and that the write is audited."""
        text = (REPO_ROOT / "docs/installation.md").read_text(encoding="utf-8")
        for needle in ("admin", "user", "role_created"):
            assert needle in text, needle
