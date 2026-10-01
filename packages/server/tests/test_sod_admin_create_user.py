# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""SoD bypass via admin create-user (ticket sod-bypass-admin-create-user).

admin_create_user minted role memberships by direct ORM, skipping the ONE
enforcement point (core RoleManager.add_member). These cells run against a
REAL sqlite session (re-query the DB, not just the status code): a mixed
{auditor, non-auditor} grant through POST /admin/users must die 409 with an
auditor_sod_denied row EXACTLY like the sibling role-members endpoint
(parity is the point), and must leave NOTHING behind: no user row, no
membership, no phantom user_created lifecycle event (complete-or-nothing,
ticket admin-lifecycle-audit-events posture).
"""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import AuditEvent, Base, Role, RoleMember, User
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db, require_admin
from server.routes import admin as admin_routes
from server.routes import roles as roles_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

ADMIN_ACTOR = {"user_id": "mtls-admin-id", "caller": "admin"}


@pytest.fixture()
def env():
    """Real sqlite engine seeded with roles + one pre-existing auditor member."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    seed = factory()
    auditor = Role(name="auditor", permissions="auditor", description="audit tier")
    ops = Role(name="ops", permissions="read", description="plain read")
    seed.add_all([auditor, ops])
    carol = User(user_id="carol", status="active")
    seed.add(carol)
    seed.flush()
    seed.add(RoleMember(user_id="carol", role_id=auditor.id))
    seed.commit()
    auditor_id, ops_id = auditor.id, ops.id
    seed.close()

    app = FastAPI()
    app.state.backend = MagicMock()  # require_admin is overridden; keep attr alive
    app.state.config = SimpleNamespace(
        recovery_code_pepper="pep",
        fido2=SimpleNamespace(enrollment_token_ttl=15),
    )
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(roles_routes.router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: ADMIN_ACTOR
    app.dependency_overrides[get_current_user] = lambda: ADMIN_ACTOR

    def _get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_db
    client = TestClient(app, raise_server_exceptions=False)
    return SimpleNamespace(client=client, factory=factory, auditor_id=auditor_id, ops_id=ops_id, engine=engine)


def _em_mock():
    em = MagicMock()
    em.create_enrollment_token.return_value = (SimpleNamespace(id=1), "plaintext-token")
    em.config.token_expiry = timedelta(minutes=15)
    return em


def _post_create(client, roles):
    with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=_em_mock()):
        return client.post("/api/v1/admin/users", json={"username": "newbie", "roles": roles})


def _events(factory, event_type):
    db = factory()
    try:
        return db.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()
    finally:
        db.close()


def _count(factory, model, **filters):
    db = factory()
    try:
        q = db.query(model)
        for key, value in filters.items():
            q = q.filter(getattr(model, key) == value)
        return q.count()
    finally:
        db.close()


class TestPositives:
    def test_p1_normal_roles_create_roundtrip(self, env):
        resp = _post_create(env.client, ["ops"])
        assert resp.status_code == 201, resp.text
        assert _count(env.factory, User, user_id="newbie") == 1
        db = env.factory()
        try:
            member = db.query(RoleMember).filter(RoleMember.user_id == "newbie").all()
            assert [m.role_id for m in member] == [env.ops_id]
        finally:
            db.close()
        rows = _events(env.factory, "user_created")
        assert len(rows) == 1
        import json

        assert json.loads(rows[0].fields)["target_user_id"] == "newbie"
        assert not _events(env.factory, "auditor_sod_denied")

    def test_p2_auditor_only_create_succeeds(self, env):
        assert _post_create(env.client, ["auditor"]).status_code == 201
        assert _count(env.factory, RoleMember, user_id="newbie") == 1


class TestMixedGrantRejected:
    def test_n1_mixed_409_zero_user_rows(self, env):
        """THE BYPASS cell: pre-fix this returned 201 and minted the mixed
        memberships through the front door."""
        resp = _post_create(env.client, ["auditor", "ops"])
        assert resp.status_code == 409, resp.text
        assert _count(env.factory, User, user_id="newbie") == 0
        assert _count(env.factory, RoleMember, user_id="newbie") == 0

    def test_n1b_denial_event_exact_sibling_shape(self, env):
        resp = _post_create(env.client, ["auditor", "ops"])
        assert resp.status_code == 409
        rows = _events(env.factory, "auditor_sod_denied")
        assert len(rows) == 1
        import json

        fields = json.loads(rows[0].fields)
        assert fields == {
            "outcome": "denied",
            "reason": "separation of duties: auditor tier is exclusive",
            "action": "add_member",
            "target_user_id": "newbie",
            "role_id": env.ops_id,
            "attempted_tiers": ["auditor", "read"],
        }
        assert rows[0].user_id == ADMIN_ACTOR["user_id"]

    def test_n2_no_phantom_user_created_event(self, env):
        """The #298 lifecycle row must not exist when the action it would
        describe never happened (complete-or-nothing)."""
        _post_create(env.client, ["auditor", "ops"])
        assert not _events(env.factory, "user_created")

    def test_n3_preexisting_members_untouched(self, env):
        before = _count(env.factory, RoleMember, user_id="carol")
        assert _post_create(env.client, ["auditor", "ops"]).status_code == 409
        assert _count(env.factory, RoleMember, user_id="carol") == before == 1


class TestSiblingParity:
    def test_same_input_same_error_class_and_event_shape(self, env):
        """Mixed grant via POST /admin/users and via the roles-member endpoint
        produce the SAME status, SAME denial event shape (fields apart from
        the target ids), SAME error-class detail — the whole point of
        rerouting instead of guard-copying."""
        import json

        admin_resp = _post_create(env.client, ["auditor", "ops"])
        assert admin_resp.status_code == 409
        admin_event = _events(env.factory, "auditor_sod_denied")[0]

        sibling_resp = env.client.post(
            f"/api/v1/roles/{env.ops_id}/members",
            json={"user_id": "carol"},  # carol is already auditor-tier
        )
        assert sibling_resp.status_code == 409
        events = _events(env.factory, "auditor_sod_denied")
        assert len(events) == 2
        sibling_event = events[1]

        a_fields, s_fields = json.loads(admin_event.fields), json.loads(sibling_event.fields)
        assert a_fields["outcome"] == s_fields["outcome"] == "denied"
        assert a_fields["reason"] == s_fields["reason"]
        assert a_fields["action"] == s_fields["action"] == "add_member"
        assert a_fields["attempted_tiers"] == s_fields["attempted_tiers"] == ["auditor", "read"]
        assert admin_event.user_id == sibling_event.user_id == ADMIN_ACTOR["user_id"]
        # detail: both carry the add_member guard's own message (no per-route rewording)
        assert "Separation of duties" in admin_resp.json()["detail"]
        assert "Separation of duties" in sibling_resp.json()["detail"]


class TestExistingBehaviorHeld:
    def test_unknown_role_still_400(self, env):
        assert _post_create(env.client, ["ghost"]).status_code == 400

    def test_duplicate_user_still_400(self, env):
        assert _post_create(env.client, ["ops"]).status_code == 201
        assert _post_create(env.client, ["ops"]).status_code == 400
