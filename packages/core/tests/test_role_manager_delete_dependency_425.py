# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth-table tests for RoleManager.delete_role against REAL dependencies (#425).

DEFECT A: deleting a role that still has members reached SQLAlchemy's
delete-dependency machinery, which tried to blank-out the primary-key column
role_members.role_id and raised an internal AssertionError instead of a
dependency message. These cells bind the real manager to a real SQLite
session with PRAGMA foreign_keys=ON (same harness pattern as
test_secret_delete_fk.py) so the dependency machinery physically fires.
"""

import pytest
from core.iam.models import Base, Role, RoleMember, Secret, SecretRole, User
from core.iam.role_manager import RoleManager, RoleManagerError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    s = factory()
    s.add(User(user_id="member1", status="active"))
    s.add(Role(name="operator", permissions="read"))
    s.add(Role(name="empty-role", permissions="read"))
    s.add(
        Secret(
            key="scoped", encrypted_value=b"ct", nonce=b"n", wrapped_dek=b"d", key_version_id="v1", created_by="member1"
        )
    )
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _role_id(session, name):
    return session.query(Role).filter(Role.name == name).one().id


class TestDeleteRoleDependency:
    def test_nonempty_role_delete_raises_dependency_message(self, session):
        """RED2: role with a member -> RoleManagerError naming the member
        dependency, not an internal assertion surfacing."""
        rid = _role_id(session, "operator")
        session.add(RoleMember(user_id="member1", role_id=rid))
        session.commit()

        rm = RoleManager(session)
        with pytest.raises(RoleManagerError) as excinfo:
            rm.delete_role(rid)

        assert "member" in str(excinfo.value).lower()
        assert session.get(Role, rid) is not None

    def test_role_with_secret_scopes_raises_dependency_message(self, session):
        """Same crash class: role scoped to a secret -> human dependency
        message instead of the role_members.role_id blank-out assertion."""
        rid = _role_id(session, "operator")
        sid = session.query(Secret).one().id
        session.add(SecretRole(secret_id=sid, role_id=rid))
        session.commit()

        rm = RoleManager(session)
        with pytest.raises(RoleManagerError) as excinfo:
            rm.delete_role(rid)

        assert "secret" in str(excinfo.value).lower()
        assert session.get(Role, rid) is not None

    def test_empty_role_delete_still_succeeds(self, session):
        """Negative (truth table): the empty-role path stays working."""
        rid = _role_id(session, "empty-role")
        rm = RoleManager(session)
        assert rm.delete_role(rid) is True
        session.commit()
        assert session.get(Role, rid) is None

    def test_missing_role_returns_false(self, session):
        rm = RoleManager(session)
        assert rm.delete_role(9999) is False
