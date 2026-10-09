# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for require_role dependency factory (C-06) and require_admin (L-11)."""

from datetime import UTC
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Depends, FastAPI
from server.dependencies import get_current_user, require_admin, require_role
from starlette.testclient import TestClient

# #449: the stated reason the role gate gives an executor-class caller. Cell-level
# assertions pin the TEXT, not just the status — two different 403s exist on these
# routes (the gate refusal and the route's own identity checks), and a status-only
# assertion cannot tell them apart.
EXECUTOR_GATE_REFUSAL = "Executor callers are not permitted on role-gated routes"
NO_USER_ID_REFUSAL = "Caller identity carries no user to authorize"


def _make_rm_mock(user_permissions):
    """Create a mock RoleManager.

    Args:
        user_permissions: Dict mapping user_id -> {role_id: permission}.
    """
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: user_permissions.get(uid, {})
    return rm


def _create_app(auth_user, permission, with_backend=True):
    """Create a minimal app with one route protected by require_role."""
    app = FastAPI()
    if with_backend:
        app.state.backend = MagicMock()

    @app.get("/protected")
    async def protected(_=Depends(require_role(permission))):
        return {"result": "ok"}

    # Override get_current_user so it doesn't need a Bearer token.
    # The real get_current_user checks for an Authorization: Bearer header
    # first; the override bypasses that check and returns a fixed user dict.
    if auth_user is not None:
        app.dependency_overrides[get_current_user] = lambda: auth_user

    return app


class TestRequireRoleRead:
    """Tests for require_role("read")."""

    def test_passes_with_any_role_membership(self):
        """A user with a read role passes require_role("read")."""
        rm = _make_rm_mock({"user1": {1: "read"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"
        rm.get_user_permissions.assert_called_once_with("user1")

    def test_passes_with_read_write_role(self):
        """A read-write role satisfies the read requirement."""
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200

    def test_denied_for_user_with_no_roles(self):
        """A user with zero role memberships gets 403 on require_role("read")."""
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"


class TestRequireRoleReadWrite:
    """Tests for require_role("read-write")."""

    def test_passes_with_read_write_role(self):
        """A user with a read-write role passes require_role("read-write")."""
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"

    def test_denied_for_read_only_user(self):
        """A read-only user gets 403 on require_role("read-write")."""
        rm = _make_rm_mock({"user1": {1: "read"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"

    def test_denied_for_user_with_no_roles(self):
        """A user with zero roles gets 403 on require_role("read-write")."""
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"

    def test_any_read_write_role_suffices(self):
        """One read-write role among several roles is enough."""
        rm = _make_rm_mock({"user1": {1: "read", 2: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200


class TestRequireRoleAuditor:
    """Tests for require_role("auditor") — audit-visibility tier (ticket
    auditor-role). Auditor OR read-write passes; plain read is DENIED
    (audit access is auditor-scoped); auditor never satisfies read-write."""

    def test_passes_with_auditor_role(self):
        rm = _make_rm_mock({"user1": {1: "auditor"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "auditor")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"

    def test_denied_for_read_only_user(self):
        """Acceptance: read-role users CANNOT query audit-gated routes."""
        rm = _make_rm_mock({"user1": {1: "read"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "auditor")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Auditor permission required"

    def test_passes_with_read_write_role(self):
        """Regression pin: read-write EXCEEDS auditor — admin (seeded
        read-write) must not lose audit-log access."""
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "auditor")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200

    def test_denied_for_user_with_no_roles(self):
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "auditor")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Auditor permission required"

    def test_auditor_denied_on_read_write_gate(self):
        """KEY paired negative (acceptance: auditor cannot create secrets /
        execute commands — those routes are require_role("read-write"))."""
        rm = _make_rm_mock({"user1": {1: "auditor"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Read-write permission required"

    def test_auditor_passes_read_gate(self):
        """Acceptance: auditor CAN list roles/executors/secrets metadata —
        those routes stay require_role("read") = any membership."""
        rm = _make_rm_mock({"user1": {1: "auditor"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200

    def test_executor_refused_auditor_gate_without_role_lookup(self):
        """#449: an executor is REFUSED on the auditor tier, never waved through.

        The old cell pinned the opposite ("bypass holds on the new tier"), which was
        the blanket pass this ticket removes. Refusal happens BEFORE any role lookup,
        so the never-hits-RoleManager half of the old assertion still holds and is
        kept; the 403 and its stated reason are what is new. A route body that never
        ran is also asserted (no ``result`` key in the response), so this cell cannot
        pass under the old code.
        """
        rm = _make_rm_mock({})
        rm.get_user_permissions.side_effect = AssertionError("role lookup must not run for executors")
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"caller": "executor", "executor_id": "exec-1"}, "auditor")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == EXECUTOR_GATE_REFUSAL
        assert "result" not in resp.json(), "route body ran — the gate did not refuse"
        rm.get_user_permissions.assert_not_called()


class TestRequireRoleExecutorRefusal:
    """#449: executor-class (mTLS) callers are refused by every TIERED role gate.

    Renamed from ``TestRequireRoleExecutorBypass``: a class named for a bypass that
    no longer exists would be a lie in the test tree. The single source of executor
    reachability is the middleware PATH MATCHER (``server/middleware/auth.py``), not
    this gate — see the AC4 note in ``require_role._checker``.
    """

    def test_executor_refused_without_role_lookup(self):
        """Executor user_info (no user_id) is refused 403 and never hits RoleManager.

        The refusal must be a 403 with a stated reason, not the KeyError→500 the
        role lookup would have produced for an identity carrying no ``user_id``.
        """
        rm = _make_rm_mock({})
        rm.get_user_permissions.side_effect = AssertionError("role lookup must not run for executors")
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app(
                {"caller": "executor", "executor_id": "exec-1"},
                "read-write",
            )
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == EXECUTOR_GATE_REFUSAL
        assert resp.status_code != 500, "authorization failure surfaced as a server fault"
        rm.get_user_permissions.assert_not_called()


class TestRequireRoleAuthAndBackend:
    """Authentication and backend prerequisite behavior."""

    def test_unauthenticated_returns_401(self):
        """No auth_user on request state -> 401 from get_current_user."""
        app = _create_app(None, "read")
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_backend_not_initialized_returns_503(self):
        """No backend on app state -> 503 from get_backend."""
        app = _create_app({"user_id": "user1"}, "read", with_backend=False)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 503


class TestRequireRoleFactory:
    """Factory-time validation and session lifecycle."""

    def test_invalid_permission_raises_value_error(self):
        """require_role("execute") raises ValueError at factory call time."""
        with pytest.raises(ValueError, match="Must be 'none', 'read', 'auditor', or 'read-write'"):
            require_role("execute")

    def test_auditor_permission_accepted_by_factory(self):
        """Positive factory cell: the widened validation set includes auditor."""
        checker = require_role("auditor")
        assert checker._venya_guard == "auditor"

    def test_empty_permission_raises_value_error(self):
        """require_role("") raises ValueError at factory call time."""
        with pytest.raises(ValueError):
            require_role("")

    def test_db_session_closed_after_check(self):
        """The DB session opened for the role lookup is always closed."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_rm_mock({"user1": {1: "read-write"}})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read-write")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        backend.get_session.assert_called_once()
        session.close.assert_called_once()

    def test_db_session_closed_on_denial(self):
        """The DB session is closed even when the check returns 403."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_rm_mock({})
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        session.close.assert_called_once()

    def test_db_rollback_on_role_lookup_error(self):
        """A failure in the role lookup rolls the session back before re-raising."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session

        def _boom(uid):
            raise RuntimeError("db down")

        rm = MagicMock()
        rm.get_user_permissions.side_effect = _boom
        with patch("server.dependencies.RoleManager", return_value=rm):
            app = _create_app({"user_id": "user1"}, "read")
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 500
        session.rollback.assert_called_once()
        session.close.assert_called_once()


def _create_admin_app(auth_user, with_backend=True):
    """Create a minimal app with one route protected by require_admin."""
    app = FastAPI()
    if with_backend:
        app.state.backend = MagicMock()

    @app.get("/protected")
    async def protected(_=Depends(require_admin)):
        return {"result": "ok"}

    if auth_user is not None:
        app.dependency_overrides[get_current_user] = lambda: auth_user

    return app


def _make_admin_rm_mock(has_admin, role_exists=True, permission_error=None):
    rm = MagicMock()
    rm.get_role_by_name.return_value = SimpleNamespace(id=1) if role_exists else None
    if permission_error is not None:
        rm.has_permission.side_effect = permission_error
    else:
        rm.has_permission.return_value = has_admin
    return rm


class TestRequireAdmin:
    """Session lifecycle tests for require_admin (L-11)."""

    def test_admin_passes(self):
        """A user with the admin role passes; session is closed."""
        rm = _make_admin_rm_mock(has_admin=True)
        with patch("core.iam.role_manager.RoleManager", return_value=rm):
            app = _create_admin_app({"user_id": "admin1"})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"
        rm.has_permission.assert_called_once_with("admin1", 1, "read-write")

    def test_denied_for_non_admin(self):
        """A user without admin permission gets 403; session is closed."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_admin_rm_mock(has_admin=False)
        with patch("core.iam.role_manager.RoleManager", return_value=rm):
            app = _create_admin_app({"user_id": "user1"})
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin permission required"
        session.close.assert_called_once()

    def test_denied_when_admin_role_missing(self):
        """403 when the admin role does not exist."""
        rm = _make_admin_rm_mock(has_admin=True, role_exists=False)
        with patch("core.iam.role_manager.RoleManager", return_value=rm):
            app = _create_admin_app({"user_id": "user1"})
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin role not found"

    def test_db_rollback_on_lookup_error(self):
        """A failure in the admin lookup rolls the session back before re-raising."""
        backend = MagicMock()
        session = MagicMock()
        backend.get_session.return_value = session
        rm = _make_admin_rm_mock(has_admin=True, permission_error=RuntimeError("db down"))
        with patch("core.iam.role_manager.RoleManager", return_value=rm):
            app = _create_admin_app({"user_id": "admin1"})
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 500
        session.rollback.assert_called_once()
        session.close.assert_called_once()

    def test_executor_denied_403_without_user_id_lookup(self):
        """An executor (no user_id) hitting require_admin gets 403, not 500.

        Executors carry no user_id and admin routes are human-only, so the
        guard must deny before any DB access (mirrors require_role's executor
        branch, but denies instead of passing).
        """
        backend = MagicMock()
        rm = _make_admin_rm_mock(has_admin=True)
        rm.has_permission.side_effect = AssertionError("admin lookup must not run for executors")
        with patch("core.iam.role_manager.RoleManager", return_value=rm):
            app = _create_admin_app({"caller": "executor", "executor_id": "exec-1"})
            app.state.backend = backend
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/protected")
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin permission required"
        backend.get_session.assert_not_called()


class TestGetCurrentSessionOperatorMaxCap:
    """C-10-related (fixed 2026-08-21): the per-request hard cap must honor the
    operator's server_config.session.max_session_duration, not the core 4h
    default (same bug class M-28 fixed in maintenance.py)."""

    @staticmethod
    def _call(config, created_age_seconds, expires_in_seconds=600):
        from datetime import datetime, timedelta

        from server.dependencies import get_current_session

        now = datetime.now(UTC)
        session = SimpleNamespace(
            id="s1",
            created_at=now - timedelta(seconds=created_age_seconds),
            expires_at=now + timedelta(seconds=expires_in_seconds),
            access_token="tok",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = session
        request = SimpleNamespace(
            cookies={"venya_access_token": "tok"},
            app=SimpleNamespace(state=SimpleNamespace(config=config)),
        )
        return get_current_session(request, db)

    def test_operator_cap_rejects_session_beyond_it(self):
        """2h-old session with operator max=1h -> rejected (the old 4h core
        default would have allowed it)."""
        config = SimpleNamespace(session=SimpleNamespace(max_session_duration=3600))
        assert self._call(config, created_age_seconds=7200) is None

    def test_core_default_cap_when_no_operator_config(self):
        """No operator config -> core 4h default: 2h-old session allowed,
        5h-old session rejected."""
        assert self._call(None, created_age_seconds=7200) is not None
        assert self._call(None, created_age_seconds=18000) is None


class TestAuditorOnlyPermissionsHelper:
    """auditor_only_permissions — the union predicate behind the value-deny
    and issuance-deny (auditor-role rework, ruling 1b). Truth table with
    paired negatives."""

    def test_all_auditor_is_true(self):
        from server.dependencies import auditor_only_permissions

        assert auditor_only_permissions({1: "auditor"}) is True
        assert auditor_only_permissions({1: "auditor", 2: "auditor"}) is True

    def test_union_with_any_other_tier_is_false(self):
        """1b union paired negative: auditor+read (or +read-write) keeps
        value access — the deny must NOT fire."""
        from server.dependencies import auditor_only_permissions

        assert auditor_only_permissions({1: "auditor", 2: "read"}) is False
        assert auditor_only_permissions({1: "auditor", 2: "read-write"}) is False

    def test_empty_membership_is_false(self):
        """Empty map is False: the helper never grants; read gates reject
        no-membership callers before the deny is consulted."""
        from server.dependencies import auditor_only_permissions

        assert auditor_only_permissions({}) is False


class TestRequireRoleAttachesRoleMap:
    """F2 lookup design: require_role's _checker attaches its already-fetched
    role map to user_info so value-gating handlers reuse it request-scoped."""

    def test_read_gate_attaches_role_map(self):
        rm = _make_rm_mock({"user1": {1: "auditor"}})
        app = FastAPI()
        app.state.backend = MagicMock()

        @app.get("/echo")
        async def echo(user=Depends(require_role("read"))):
            return {"map": user.get("_role_permissions")}

        app.dependency_overrides[get_current_user] = lambda: {"user_id": "user1"}
        with patch("server.dependencies.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/echo")
        assert resp.status_code == 200
        # JSON coerces the int role-id keys to strings on the way out.
        assert resp.json()["map"] == {"1": "auditor"}

    def test_executor_refused_attaches_no_map(self):
        """#449: an executor is refused before any role fetch — so the body never
        runs and no ``_role_permissions`` map can exist anywhere in the response.

        The old cell asserted 200 + ``map is None`` (the pass, with nothing
        attached). Under the refusal the route body is never entered, so the
        response is the gate's 403 envelope: ``detail`` present, ``map`` absent.
        Asserting the ABSENCE of the body's key is strictly stronger than the old
        ``map is None``, which the pass produced trivially.
        """
        rm = _make_rm_mock({})
        rm.get_user_permissions.side_effect = AssertionError("executor must not trigger lookup")
        app = FastAPI()
        app.state.backend = MagicMock()

        @app.get("/echo")
        async def echo(user=Depends(require_role("read"))):
            return {"map": user.get("_role_permissions")}

        app.dependency_overrides[get_current_user] = lambda: {
            "caller": "executor",
            "executor_id": "exec-1",
        }
        with patch("server.dependencies.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/echo")
        assert resp.status_code == 403
        assert resp.json()["detail"] == EXECUTOR_GATE_REFUSAL
        assert "map" not in resp.json(), "route body ran for an executor caller"
