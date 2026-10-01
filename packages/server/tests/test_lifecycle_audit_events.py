# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Lifecycle audit events (ticket admin-lifecycle-audit-events, A3 truth table).

Owner ruling batch 2026-09-30: 16 lifecycle sites emit value-free audit rows
in the SAME TRANSACTION as the action (complete-or-nothing); refresh emits
ZERO rows; login_failed is variant-B (no username, no user id, no IP — ever);
the mTLS/session principal lands in user_id verbatim (migration-022
convention); all construction flows through the single server-side writer
audit_lifecycle.audit_lifecycle (grep-pinned below).

House discipline: real route handlers over mocked stacks (MagicMock db +
captured db.add), paired positives/negatives, no mocked crypto.
"""

import json
import logging
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from server.routes import auth as auth_routes
from server.routes import auth_browser as auth_browser_routes
from server.routes import credentials as credentials_routes
from server.routes import enroll as enroll_routes
from server.routes import init as init_routes
from server.routes import recovery as recovery_routes
from server.routes import roles as roles_routes
from starlette.testclient import TestClient

USER_ID = "user1"  # the principal every login fixture uses — must NEVER appear in a login_failed row
CLI_MODE_ROUTES = "/api/v1/auth/login/complete"

LIFECYCLE_EVENT_STRINGS = [
    "admin_initialized",
    "first_admin_enrolled",
    "break_glass_recovery_used",
    "session_started",
    "session_ended",
    "login_failed",
    "user_created",
    "user_updated",
    "user_deleted",
    "role_created",
    "role_updated",
    "role_deleted",
    "member_added",
    "member_removed",
    "credential_added",
    "credential_removed",
]


def _lifecycle_events(db):
    """AuditEvent objects passed to db.add (house pattern from test_admin)."""
    from core.iam.models import AuditEvent

    return [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], AuditEvent)]


def _by_type(events, event_type):
    return [e for e in events if e.event_type == event_type]


def _f(event):
    return json.loads(event.fields) if isinstance(event.fields, str) else event.fields


def _app(router, backend=None, auth_user=None, extra_state=None, fido2_manager=None):
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    app.state.backend = backend or MagicMock()
    if fido2_manager is not None:
        app.state.fido2_manager = fido2_manager
    for key, value in (extra_state or {}).items():
        setattr(app.state, key, value)
    app.include_router(router, prefix="/api/v1")
    if auth_user is not None:
        app.dependency_overrides[get_current_user] = lambda: auth_user
        app.dependency_overrides[require_admin] = lambda: auth_user

        class _AuthUserMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                request.state.auth_user = auth_user
                return await call_next(request)

        app.add_middleware(_AuthUserMiddleware)
    return app


# ---------------------------------------------------------------------------
# Single-writer pins


class TestSingleWriter:
    def test_event_strings_constructed_only_in_helper(self):
        """No route may construct or name a lifecycle event — the helper
        module is the ONLY writer (ruled build shape)."""
        routes_dir = Path(auth_routes.__file__).parent
        helper = routes_dir.parent / "audit_lifecycle.py"
        helper_text = helper.read_text()
        for name in LIFECYCLE_EVENT_STRINGS:
            assert f'"{name}"' in helper_text
        for py in routes_dir.glob("*.py"):
            text = py.read_text()
            for name in LIFECYCLE_EVENT_STRINGS:
                assert f'"{name}"' not in text, f"{py.name} hard-codes lifecycle event {name}"

    @pytest.mark.parametrize(
        "module_name",
        ["init", "auth", "auth_browser", "enroll", "recovery", "admin", "roles", "credentials"],
    )
    def test_every_lifecycle_route_file_uses_the_helper(self, module_name):
        text = (Path(auth_routes.__file__).parent / f"{module_name}.py").read_text()
        assert "audit_lifecycle" in text

    def test_helper_rejects_unknown_event_type(self):
        from server.audit_lifecycle import audit_lifecycle

        with pytest.raises(ValueError):
            audit_lifecycle(MagicMock(), "role_renamed_by_typo", "someone", {})


# ---------------------------------------------------------------------------
# Init


def _init_db(admin_role=None):
    db = MagicMock()
    state = {"count": 0}

    class Q:
        def filter(self, *a, **k):
            return self

        def join(self, *a, **k):
            return self

        def first(self):
            return admin_role

        def all(self):
            return []

        def count(self):
            return 0

    db.query.return_value = Q()
    db.delete.side_effect = lambda obj: None
    state["db"] = db
    return db


class TestInitEvents:
    def test_admin_initialized_row(self):
        db = _init_db()
        fido = MagicMock()
        fido.start_registration.return_value = ("cid", {"challenge": "dGVzdA=="})
        app = _app(
            init_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            extra_state={"config": SimpleNamespace(ca_dir="/tmp/ca", ca_security=None)},
            fido2_manager=fido,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/init", json={"user_id": "firstadmin"})
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "admin_initialized")
        assert len(rows) == 1
        assert rows[0].user_id == "firstadmin"  # self-asserted id as stored (ruled Q5)
        assert _f(rows[0])["outcome"] == "pending_created"
        assert _f(rows[0])["roles_seeded"] == ["admin", "user"]
        db.commit.assert_called_once()  # SAME transaction: one commit, not an extra one

    def test_first_admin_enrolled_row(self):
        pending = SimpleNamespace(
            user_id="firstadmin", auth_mode="security-key", status=None, enrolled_at=None, recovery_code_hash=None
        )
        db = MagicMock()
        admin_role = SimpleNamespace(id=1, name="admin")

        class Q:
            def filter(self, *a, **k):
                return self

            def join(self, *a, **k):
                return self

            def first(self):
                return admin_role  # role lookup; user query handled below

        q = Q()

        def query(*models):
            return q

        db.query.side_effect = query
        # the user lookup chain must return the pending user: patch the second .first()
        calls = {"n": 0}
        orig_first = q.first

        def first():
            calls["n"] += 1
            return pending if calls["n"] == 2 else orig_first()

        q.first = first  # type: ignore[method-assign]

        fido = MagicMock()
        cred = SimpleNamespace(user_id="firstadmin", credential_id=b"c", public_key=b"p", sign_count=0)
        fido.finish_registration.return_value = cred

        app = _app(
            init_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            extra_state={
                "config": SimpleNamespace(recovery_code_pepper="pep"),
                "fido2_manager": fido,
            },
            fido2_manager=fido,
        )
        with (
            patch("server.fido2.browser_adapter.browser_registration_to_fido2", return_value={}),
            patch("server.routes.init._generate_recovery_code", return_value="SUP3R-CODE"),
            patch("server.routes.init._hash_recovery_code", return_value="hash"),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/init/complete",
                json={"user_id": "firstadmin", "challenge_id": "cid", "response": {"id": "x"}},
            )
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "first_admin_enrolled")
        assert len(rows) == 1
        assert rows[0].user_id == "firstadmin"
        fields = _f(rows[0])
        assert fields["recovery_code_issued"] is True
        assert "SUP3R-CODE" not in json.dumps(fields)


class TestInitNegatives:
    def test_already_initialized_409_writes_no_lifecycle_row(self):
        enrolled = SimpleNamespace(user_id="boss")
        db = MagicMock()

        class Q:
            def filter(self, *a, **k):
                return self

            def join(self, *a, **k):
                return self

            def first(self):
                return SimpleNamespace(id=1, name="admin", user_id="boss")

            def count(self):
                return 1  # enrolled member exists

            def all(self):
                return [enrolled]

        db.query.return_value = Q()
        app = _app(
            init_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            extra_state={"config": SimpleNamespace(ca_dir="/tmp/ca2", ca_security=None)},
            fido2_manager=MagicMock(),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/init", json={"user_id": "second"})
        assert resp.status_code == 409
        assert not _lifecycle_events(db)


# ---------------------------------------------------------------------------
# Login / sessions


def _session_config():
    return {
        "config": SimpleNamespace(
            session=SimpleNamespace(session_timeout=900, access_token_ttl=900, max_session_duration=3600)
        )
    }


class TestSessionEvents:
    def test_cli_login_success_session_started(self):
        db = MagicMock()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID, "credential_id": b"cred"}
        session_mock = SimpleNamespace(id=1, access_token_jti="jti-cli-1")
        token_mock = SimpleNamespace(token="access-token-xyz", jti="jti-cli-1")
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_routes.router, backend=backend, extra_state=_session_config(), fido2_manager=fido)
        with patch("core.iam.session_manager.SessionManager") as sm, patch("core.iam.role_manager.RoleManager") as rm:
            sm.return_value.create_session.return_value = (session_mock, token_mock)
            rm.return_value.get_user_roles.return_value = []
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(CLI_MODE_ROUTES, json={"challenge_id": "c", "response": {"id": "x"}})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "session_started")
        assert len(rows) == 1
        assert rows[0].user_id == USER_ID
        assert _f(rows[0]) == {"mode": "cli", "session_jti": "jti-cli-1"}
        db.commit.assert_called_once()  # rides the login's own commit

    def test_browser_login_success_session_started(self):
        db = MagicMock()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID, "credential_id": b"cred"}
        session_mock = SimpleNamespace(id=1, access_token_jti="jti-br-1")
        token_mock = SimpleNamespace(token="tok", jti="jti-br-1")
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(
            auth_browser_routes.router,
            backend=backend,
            extra_state=_session_config(),
            fido2_manager=fido,
        )
        with (
            patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.session_manager.SessionManager") as sm,
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            sm.return_value.create_session.return_value = (session_mock, token_mock)
            rm.return_value.get_user_roles.return_value = []
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/browser/assert",
                json={"challenge_id": "c", "response": {"id": "x", "response": {}}},
            )
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "session_started")
        assert len(rows) == 1
        assert _f(rows[0]) == {"mode": "browser", "session_jti": "jti-br-1"}

    def test_cli_status_gate_login_failed_row_value_free(self):
        from core.iam.session_manager import UserNotActiveError

        db = MagicMock()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID, "credential_id": b"cred"}
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_routes.router, backend=backend, extra_state=_session_config(), fido2_manager=fido)
        with (
            patch("core.iam.session_manager.SessionManager") as sm,
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            sm.return_value.create_session.side_effect = UserNotActiveError(USER_ID, "disabled")
            rm.return_value.get_user_roles.return_value = []
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(CLI_MODE_ROUTES, json={"challenge_id": "c", "response": {"id": "x"}})
        # Response byte-identical to the pre-admin-lifecycle-audit-events shape
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Login verification failed"}
        rows = _by_type(_lifecycle_events(db), "login_failed")
        assert len(rows) == 1
        assert rows[0].user_id is None  # variant B: no principal
        fields = _f(rows[0])
        assert fields["outcome"] == "failed" and fields["mode"] == "cli"
        assert USER_ID not in json.dumps(fields)

    def test_browser_assertion_failure_login_failed(self):
        from server.fido2.manager import WebAuthnError

        db = MagicMock()
        fido = MagicMock()
        fido.finish_authentication.side_effect = WebAuthnError("assertion rejected")
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(
            auth_browser_routes.router,
            backend=backend,
            extra_state=_session_config(),
            fido2_manager=fido,
        )
        with patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/login/browser/assert",
                json={"challenge_id": "c", "response": {"id": "x", "response": {}}},
            )
        assert resp.status_code == 401  # detail stays str(e) — unchanged shape
        rows = _by_type(_lifecycle_events(db), "login_failed")
        assert len(rows) == 1
        assert rows[0].user_id is None
        assert USER_ID not in json.dumps(_f(rows[0]))

    @pytest.mark.parametrize(
        "identifier",
        [USER_ID, "alice@corp.example", "10.27.27.35", "2001:db8::1"],
    )
    def test_login_failed_rows_never_carry_principles_or_ips(self, identifier):
        """Q6 variant B parametrized negative over identifier shapes."""
        db = MagicMock()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID, "credential_id": b"cred"}
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_routes.router, backend=backend, extra_state=_session_config(), fido2_manager=fido)
        from core.iam.session_manager import UserNotActiveError

        with (
            patch("core.iam.session_manager.SessionManager") as sm,
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            sm.return_value.create_session.side_effect = UserNotActiveError(USER_ID, "disabled")
            rm.return_value.get_user_roles.return_value = []
            client = TestClient(app, raise_server_exceptions=False)
            client.post(CLI_MODE_ROUTES, json={"challenge_id": "c", "response": {"id": "x"}})
        rows = _by_type(_lifecycle_events(db), "login_failed")
        assert rows
        blob = json.dumps([_f(r) for r in rows]) + " ".join(str(r.user_id) for r in rows)
        assert identifier not in blob
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", blob)  # no IPv4 anywhere
        assert "@" not in blob  # no email-shaped identifiers


class TestRefreshZeroRows:
    def test_cli_refresh_writes_no_lifecycle_row(self):
        db = MagicMock()
        session_mock = SimpleNamespace(id=1, access_token="old", access_token_jti="jti")
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_routes.router, backend=backend, extra_state=_session_config())
        with patch("core.iam.session_manager.SessionManager") as sm:
            sm.return_value.check_refresh_window.return_value = True
            sm.return_value.refresh_token.return_value = SimpleNamespace(token="new-token", jti="jti-2")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/refresh", headers={"authorization": "Bearer old"})
        assert resp.status_code == 200  # ruled OUT — must stay silent in the lifecycle audit
        assert not _lifecycle_events(db)


# ---------------------------------------------------------------------------
# Logout


class TestLogoutEvents:
    def _app_with_logout(self, db, revoke_side_effect=None):
        app = _app(
            auth_browser_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            extra_state=_session_config(),
        )
        session_mock = SimpleNamespace(id=7, access_token_jti="jti-out")
        user_info = {"user_id": USER_ID}
        return app, session_mock, user_info, revoke_side_effect

    def test_session_ended_revoked_true(self):
        db = MagicMock()
        app, session_mock, user_info, _ = self._app_with_logout(db)
        with (
            patch.object(auth_browser_routes, "_get_session_from_cookie", return_value=(db, session_mock, user_info)),
            patch("core.iam.session_manager.SessionManager") as sm,
        ):
            sm.return_value.revoke_session.return_value = None
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/logout/browser")
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "session_ended")
        assert len(rows) == 1
        assert rows[0].user_id == USER_ID
        assert _f(rows[0]) == {"mode": "browser", "session_jti": "jti-out", "revoked": True}

    def test_session_ended_revoked_false_on_swallowed_failure(self):
        db = MagicMock()
        app, session_mock, user_info, _ = self._app_with_logout(db)
        with (
            patch.object(auth_browser_routes, "_get_session_from_cookie", return_value=(db, session_mock, user_info)),
            patch("core.iam.session_manager.SessionManager") as sm,
        ):
            sm.return_value.revoke_session.side_effect = RuntimeError("db down")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/logout/browser")
        # logout-swallows-revoke-failure owns the swallowed failure — this
        # leg must NOT change control flow:
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "session_ended")
        assert len(rows) == 1
        assert _f(rows[0])["revoked"] is False


# ---------------------------------------------------------------------------
# Recovery


class TestRecoveryEvent:
    def test_break_glass_row_value_free(self, caplog):
        import hashlib

        pepper = "test-pepper"
        code = "recovery-123"
        code_hash = hashlib.sha256((pepper + code).encode()).hexdigest()
        admin_user = SimpleNamespace(user_id="oldadmin", recovery_code_hash=code_hash)

        seq = iter([admin_user, None, SimpleNamespace(id=1, name="admin")])

        class Q:
            def filter(self, *a, **k):
                return self

            def join(self, *a, **k):
                return self

            def first(self):
                return next(seq)

        db = MagicMock()
        db.query.side_effect = lambda *a, **k: Q()
        app = _app(
            recovery_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            extra_state={"config": SimpleNamespace(recovery_code_pepper=pepper)},
        )
        caplog.set_level(logging.DEBUG)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "newadmin"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "break_glass_recovery_used")
        assert len(rows) == 1
        assert rows[0].user_id == "oldadmin"
        fields = _f(rows[0])
        assert fields == {"new_user_id": "newadmin", "code_consumed": True}
        blob = json.dumps(fields) + "".join(r.getMessage() for r in caplog.records)
        assert (
            code not in blob and code_hash not in blob
        )  # code never in fields (caplog carries the pre-existing critical line)


# ---------------------------------------------------------------------------
# Admin user lifecycle


def _admin_app(db, auth_user=None):
    return _app(
        admin_routes.router,
        backend=MagicMock(get_session=MagicMock(return_value=db)),
        auth_user=auth_user or {"user_id": "mtls-admin-id", "caller": "admin"},
    )


class TestUserLifecycle:
    """First cells double as the admin_enroll LIVE-PROOF (ruled Q1 condition)."""

    def test_admin_enroll_live_proof_user_created(self):
        mock_em = MagicMock()
        mock_em.create_enrollment_token.return_value = (SimpleNamespace(id=1), "enc-token")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        app = _admin_app(db)
        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/enroll", json={"user_id": "newuser", "auth_mode": "security-key"})
        # LIVE-PROOF: the deprecated endpoint still creates (201) -> ruled in as user_created
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "user_created")
        assert len(rows) == 1
        assert rows[0].user_id == "mtls-admin-id"  # migration-022 principal verbatim
        assert _f(rows[0])["target_user_id"] == "newuser"
        assert "enc-token" not in json.dumps(_f(rows[0]))  # token NEVER in fields

    def test_create_user_row_with_roles(self):
        mock_em = MagicMock()
        mock_em.create_enrollment_token.return_value = (SimpleNamespace(id=2), "tok2")
        mock_em.config.token_expiry = __import__("datetime").timedelta(minutes=30)
        role = SimpleNamespace(id=9, name="auditor")

        db = MagicMock()
        # query chains: existing-user lookup -> None; each role lookup -> role
        q = MagicMock()
        q.filter.return_value.first.side_effect = iter([None, role])
        db.query.return_value = q
        with patch("core.iam.enrollment_manager.EnrollmentManager", return_value=mock_em):
            app = _admin_app(db)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users", json={"username": "carol", "roles": ["auditor"]})
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "user_created")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert fields["target_user_id"] == "carol"
        assert fields["roles"] == ["auditor"]
        assert fields["enrollment_token_created"] is True
        assert "tok2" not in json.dumps(fields)

    def test_user_updated_changed_field_names(self):
        user = SimpleNamespace(
            user_id="carol", display_name=None, status="active", auth_mode=None, session_timeout=None
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        app = _admin_app(db)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.put("/api/v1/admin/users/carol", json={"status": "disabled"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "user_updated")
        assert len(rows) == 1
        assert _f(rows[0])["changed_fields"] == ["status"]
        assert _f(rows[0])["target_user_id"] == "carol"

    def test_user_deleted_with_cascade_counts(self):
        user = SimpleNamespace(user_id="carol", id=3)
        db = MagicMock()

        class Q:
            def filter(self, *a, **k):
                return self

            def first(self):
                return user

            def delete(self):
                return 2

        db.query.side_effect = lambda *a, **k: Q()
        app = _admin_app(db)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/admin/users/carol")
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "user_deleted")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert fields["target_user_id"] == "carol"
        assert fields["memberships_removed"] == 2
        assert fields["sessions_revoked"] == 2
        assert fields["tokens_revoked"] == 2

    def test_negatives_write_no_rows(self):
        db = MagicMock()

        class Q:
            def filter(self, *a, **k):
                return self

            def first(self):
                return None

        db.query.return_value = Q()
        app = _admin_app(db)
        client = TestClient(app, raise_server_exceptions=False)
        assert client.put("/api/v1/admin/users/ghost", json={"status": "disabled"}).status_code == 404
        assert client.delete("/api/v1/admin/users/ghost").status_code == 404
        assert not _lifecycle_events(db)


# ---------------------------------------------------------------------------
# Roles lifecycle


def _roles_app(db, auth_user=None):
    return _app(
        roles_routes.router,
        backend=MagicMock(get_session=MagicMock(return_value=db)),
        auth_user=auth_user or {"user_id": "mtls-admin-id", "caller": "admin"},
    )


class TestRoleLifecycle:
    def test_role_created(self):
        role = SimpleNamespace(id=5, name="deploy", permissions="read", description=None)
        db = MagicMock()
        with patch("core.iam.role_manager.RoleManager.create_role", return_value=role):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            resp = client.post("/api/v1/roles", json={"name": "deploy", "permissions": "read"})
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "role_created")
        assert len(rows) == 1
        assert _f(rows[0]) == {"role_id": 5, "role_name": "deploy", "permissions": "read"}

    def test_role_updated(self):
        role = SimpleNamespace(id=5, name="deploy", permissions="read", description="d")
        db = MagicMock()
        with (
            patch("core.iam.role_manager.RoleManager.update_role", return_value=role),
            patch("core.iam.role_manager.RoleManager.get_role_members", return_value=[]),
        ):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            resp = client.put("/api/v1/roles/5", json={"description": "new desc"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "role_updated")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert fields["role_id"] == 5
        assert fields["changed_fields"] == ["description"]

    def test_role_deleted_member_count(self):
        role = SimpleNamespace(id=5, name="deploy")
        members = [SimpleNamespace(user_id="a"), SimpleNamespace(user_id="b")]
        db = MagicMock()
        with (
            patch("core.iam.role_manager.RoleManager.get_role", return_value=role),
            patch("core.iam.role_manager.RoleManager.delete_role", return_value=True),
            patch("core.iam.role_manager.RoleManager.get_role_members", return_value=members),
        ):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/5")
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "role_deleted")
        assert len(rows) == 1
        assert _f(rows[0]) == {"role_id": 5, "role_name": "deploy", "members_affected": 2}

    def test_member_added_and_removed(self):
        db = MagicMock()
        membership = SimpleNamespace(user_id="carol", role_id=5)
        with patch("core.iam.role_manager.RoleManager.add_member", return_value=membership):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            resp = client.post("/api/v1/roles/5/members", json={"user_id": "carol"})
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "member_added")
        assert len(rows) == 1
        assert _f(rows[0]) == {"role_id": 5, "target_user_id": "carol"}

        db2 = MagicMock()
        with patch("core.iam.role_manager.RoleManager.remove_member", return_value=True):
            client = TestClient(_roles_app(db2), raise_server_exceptions=False)
            resp = client.delete("/api/v1/roles/5/members/carol")
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db2), "member_removed")
        assert len(rows) == 1
        assert _f(rows[0]) == {"role_id": 5, "target_user_id": "carol"}

    def test_sod_denial_still_audited_lifecycle_not(self):
        """Existing denial rows untouched; NO role_updated on a refused tier flip."""
        from core.iam.role_manager import SeparationOfDutiesError

        db = MagicMock()
        err = SeparationOfDutiesError("mixed", user_id="carol", role_id=5, tiers={"auditor", "read"})
        with patch("core.iam.role_manager.RoleManager.update_role", side_effect=err):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            resp = client.put("/api/v1/roles/5", json={"permissions": "auditor"})
        assert resp.status_code == 409
        events = _lifecycle_events(db)
        assert not _by_type(events, "role_updated")
        assert _by_type(events, "auditor_sod_denied")  # pre-existing denial row preserved


# ---------------------------------------------------------------------------
# Credentials lifecycle


def _elev_db():
    db = MagicMock()

    class Q:
        def filter(self, *a, **k):
            return self

        def first(self):
            return SimpleNamespace(id=1)

    db.query.return_value = Q()
    db.execute.return_value = SimpleNamespace(rowcount=1)
    return db


class TestCredentialEvents:
    def test_credential_added(self):
        cred = SimpleNamespace(user_id=USER_ID, credential_id=b"nc", public_key=b"pk", sign_count=1)
        db = _elev_db()
        fido = MagicMock()
        fido.finish_registration.return_value = cred
        app = _app(
            credentials_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user=USER_ID,
            fido2_manager=fido,
        )
        with patch("server.routes.credentials.browser_registration_to_fido2", return_value={}):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/credentials/add/browser/complete",
                json={"challenge_id": "c", "response": {"id": "x", "response": {}}, "label": "Backup key"},
                headers={"X-Elevation-Token": "elev"},
            )
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "credential_added")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert fields["elevated"] is True
        assert rows[0].user_id == USER_ID
        blob = json.dumps(fields)
        assert "pk" not in blob and "nc" not in blob  # never the handle bytes/public key

    def test_credential_removed(self):
        mock_cred = SimpleNamespace(id=5, is_active=True, credential_id=b"cred-5")
        active = [SimpleNamespace(id=1, is_active=True), mock_cred]

        class Q:
            def filter(self, *a, **k):
                return self

            def with_for_update(self):
                return self

            def all(self):
                return active

            def first(self):
                return mock_cred

        db = MagicMock()
        db.query.side_effect = lambda *a, **k: Q()
        app = _app(
            credentials_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user=USER_ID,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/credentials/5", headers={"X-Elevation-Token": "elev"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "credential_removed")
        assert len(rows) == 1
        assert _f(rows[0]) == {"credential_id": 5, "elevated": True}

    def test_last_credential_guard_no_row(self):
        mock_cred = SimpleNamespace(id=5, is_active=True, credential_id=b"c")

        class Q:
            def filter(self, *a, **k):
                return self

            def with_for_update(self):
                return self

            def all(self):
                return [mock_cred]  # only one active -> refuse

            def first(self):
                return mock_cred

        db = MagicMock()
        db.query.side_effect = lambda *a, **k: Q()
        app = _app(
            credentials_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user=USER_ID,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/v1/credentials/5", headers={"X-Elevation-Token": "elev"})
        assert resp.status_code == 400
        assert not _lifecycle_events(db)


# ---------------------------------------------------------------------------
# Same-transaction posture (ruled Q4)


class TestSameTxnPosture:
    def test_audit_insert_failure_aborts_the_action(self):
        """complete-or-nothing: a failing commit (where the audit row rides)
        takes the lifecycle action down with it — no silent success."""
        user = SimpleNamespace(
            user_id="carol", display_name=None, status="active", auth_mode=None, session_timeout=None
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        db.commit.side_effect = RuntimeError("audit flush blew up")
        app = _admin_app(db)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.put("/api/v1/admin/users/carol", json={"status": "disabled"})
        assert resp.status_code == 400  # action FAILED — never a success with no row
        assert resp.json() == {"detail": "User configuration failed"}

    def test_role_created_rows_share_the_create_transaction(self):
        role = SimpleNamespace(id=6, name="ops", permissions="read", description=None)
        db = MagicMock()
        with patch("core.iam.role_manager.RoleManager.create_role", return_value=role):
            client = TestClient(_roles_app(db), raise_server_exceptions=False)
            assert client.post("/api/v1/roles", json={"name": "ops", "permissions": "read"}).status_code == 201
        commits = [i for i, c in enumerate(db.method_calls) if c[0] == "commit"]
        event_add_idx = next(i for i, c in enumerate(db.method_calls) if c[0] == "add" and "AuditEvent" in repr(c))
        assert commits and event_add_idx < min(commits)  # added BEFORE the single commit
        db.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Enroll-complete (session_started, mode=enrollment)


class TestEnrollCompleteEvent:
    def test_session_started_enrollment(self):
        # Local driver mirroring test_enroll_browser._run_enroll_complete,
        # returning the captured db for row assertions.
        from datetime import UTC, datetime, timedelta

        from core.iam.enrollment_manager import EnrollmentManager

        mock_token = SimpleNamespace(
            user_id=1,
            state="in_progress",
            token_hash="th",
            binding_hash="bh",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        mock_user = SimpleNamespace(id=1, user_id="newuser", status="pending_enrollment", display_name="N", roles=[])
        mock_cred = SimpleNamespace(user_id="1", credential_id=b"c", public_key=b"p", sign_count=0)
        mock_session = SimpleNamespace(id=1, access_token_jti="jti-enr")
        mock_access = SimpleNamespace(token="at", jti="jti-enr")

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        backend = MagicMock(get_session=MagicMock(return_value=db))
        fido = MagicMock()
        fido.finish_registration.return_value = mock_cred
        config = SimpleNamespace(
            session=SimpleNamespace(session_timeout=900, access_token_ttl=900, max_session_duration=3600),
            fido2=SimpleNamespace(enrollment_token_ttl=15),
        )
        app = FastAPI()
        app.state.fido2_manager = fido
        app.state.backend = backend
        app.state.config = config
        app.include_router(enroll_routes.router, prefix="/api/v1")

        em = MagicMock()
        em.get_token_by_plaintext.return_value = mock_token
        em.complete_enrollment.return_value = None
        sm = MagicMock()
        sm.create_session.return_value = (mock_session, mock_access)
        with (
            patch("server.routes.enroll.verify_binding_hash", return_value=True),
            patch.object(EnrollmentManager, "__init__", lambda self, db, config=None: None),
            patch.object(EnrollmentManager, "get_token_by_plaintext", em.get_token_by_plaintext),
            patch.object(EnrollmentManager, "complete_enrollment", em.complete_enrollment),
            patch("core.iam.session_manager.SessionManager", return_value=sm),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/enroll/browser/complete",
                json={
                    "enrollment_token": "test-token",
                    "challenge_id": "c",
                    "response": {"id": "dGVzdA==", "response": {}},
                    "label": "Primary",
                },
            )
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "session_started")
        assert len(rows) == 1
        assert rows[0].user_id == "newuser"
        assert _f(rows[0]) == {"mode": "enrollment", "session_jti": "jti-enr"}
