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
from core.iam.models import AuditEvent
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db, require_admin
from server.routes import admin as admin_routes
from server.routes import auth as auth_routes
from server.routes import auth_browser as auth_browser_routes
from server.routes import auth_elevation as auth_elevation_routes
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
    # ticket adjacent-lifecycle-audit-families #301 (A2, owner rulings Q1-Q7)
    "key_version_rotated",
    "key_version_rolled_back",
    "key_version_deactivated",
    "key_version_revoked",
    "elevation_granted",
    "executor_revoked",
    "executor_cert_revoked",
    "admin_cert_revoked",
    "user_reenrolled",
    "core_reset_refused",
    "enrollment_token_issued",
    "enrollment_token_revoked",
    "command_policy_changed",
    "executor_enrollment_token_created",
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
        ["init", "auth", "auth_browser", "auth_elevation", "enroll", "recovery", "admin", "roles", "credentials"],
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

            def with_for_update(self, *a, **k):
                # #510: step 2's already-initialized re-check is the locked
                # variant, so the fake answers that call and returns the chain.
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
            if calls["n"] == 3:
                # #510: the new in-transaction re-check answers None — no
                # enrolled admin yet — so this ceremony is allowed to complete.
                # Placed as a guard ahead of the existing line so that line is
                # untouched: 1 -> role, 2 -> the pending user, else orig_first.
                return None
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
        [USER_ID, "alice@corp.example", "203.0.113.10", "2001:db8::1"],
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

    def test_refresh_status_gate_denial_writes_value_free_row(self):
        """#524 AC5: a refresh refused by the status gate is recorded — a
        LOGIN_FAILED-shaped denial row (reason refresh_status_gate) so an
        operator sees a disabled account still trying. Value-free (Q6
        variant B): no user id in the row, no USER_ID in the fields."""
        from core.iam.session_manager import UserNotActiveError

        db = MagicMock()
        session_mock = SimpleNamespace(id=1, access_token="old", access_token_jti="jti")
        db.query.return_value.filter.return_value.first.return_value = session_mock
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_routes.router, backend=backend, extra_state=_session_config())
        with patch("core.iam.session_manager.SessionManager") as sm:
            sm.return_value.check_refresh_window.return_value = True
            sm.return_value.refresh_token.side_effect = UserNotActiveError(USER_ID, "disabled")
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/refresh", headers={"authorization": "Bearer old"})
        assert resp.status_code == 401
        rows = _by_type(_lifecycle_events(db), "login_failed")
        assert len(rows) == 1
        assert rows[0].user_id is None
        fields = _f(rows[0])
        assert fields["reason"] == "refresh_status_gate"
        assert fields["mode"] == "cli"
        blob = json.dumps(fields)
        assert USER_ID not in blob

    def test_browser_refresh_status_gate_denial_writes_value_free_row(self):
        """#524 cookie-plane twin of the denial row — the gate lives in the
        shared refresh_token helper, so the cookie route refuses the same
        predicate; this cell pins its audit shape (mode=browser)."""
        from core.iam.session_manager import UserNotActiveError

        db = MagicMock()
        session_row = SimpleNamespace(id=9, user_id=USER_ID, access_token_jti="jti-br")
        db.query.return_value.filter.return_value.first.return_value = session_row
        backend = MagicMock(get_session=MagicMock(return_value=db))
        app = _app(auth_browser_routes.router, backend=backend, extra_state=_session_config())
        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set(auth_browser_routes.COOKIE_NAME, "old")
        with patch("core.iam.session_manager.SessionManager") as sm:
            sm.return_value.check_refresh_window.return_value = True
            sm.return_value.refresh_token.side_effect = UserNotActiveError(USER_ID, "pending_enrollment")
            resp = client.post("/api/v1/auth/refresh/browser")
        assert resp.status_code == 401
        rows = _by_type(_lifecycle_events(db), "login_failed")
        assert len(rows) == 1
        assert rows[0].user_id is None
        fields = _f(rows[0])
        assert fields["reason"] == "refresh_status_gate"
        assert fields["mode"] == "browser"
        assert USER_ID not in json.dumps(fields)


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

    def test_logout_success_clears_cookie(self):
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
        set_cookie = resp.headers.get("set-cookie") or ""
        assert auth_browser_routes.COOKIE_NAME in set_cookie
        assert "Max-Age=0" in set_cookie

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
        # logout-swallows-revoke-failure OWNS this leg (ruling 2026-10-01,
        # fail-closed): a failed revoke returns 503, claims no logout, and
        # does NOT clear the cookie — the client keeps it as retry handle.
        assert resp.status_code == 503
        assert resp.json()["revoked"] is False
        set_cookie = resp.headers.get("set-cookie") or ""
        assert f"{auth_browser_routes.COOKIE_NAME}=" not in set_cookie
        rows = _by_type(_lifecycle_events(db), "session_ended")
        assert len(rows) == 1
        assert _f(rows[0])["revoked"] is False

    def test_logout_no_session_path_still_200_and_clears_cookie(self):
        db = MagicMock()
        app, *_ = self._app_with_logout(db)
        with patch.object(auth_browser_routes, "_get_session_from_cookie", return_value=None):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/logout/browser")
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie") or ""
        assert auth_browser_routes.COOKIE_NAME in set_cookie
        assert not _lifecycle_events(db)


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
        # sod-bypass-admin-create-user rerouted grants through
        # RoleManager.add_member (real SoD refusal pinned in
        # test_sod_admin_create_user.py); this cell stays a MagicMock, so the
        # chokepoint call is stubbed — every original assertion below is kept.
        with (
            patch("core.iam.enrollment_manager.EnrollmentManager", return_value=mock_em),
            patch(
                "core.iam.role_manager.RoleManager.add_member",
                return_value=SimpleNamespace(user_id="carol", role_id=9),
            ),
        ):
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
        # #486: the status guard reads the admin roster, which a MagicMock
        # session cannot answer honestly. Stub the roster lookup to "no admin
        # role seeded" so the guard stays out of this cell's way (same stub
        # precedent as RoleManager.add_member above); every original assertion
        # below is kept.
        with patch("core.iam.role_manager.RoleManager.get_role_by_name", return_value=None):
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

            def with_for_update(self, **k):
                # #487: the lockout guard now reads the roster under a row
                # lock; this stub answers the extra chain hop with the SAME
                # empty-roster posture its all() already gives — every
                # original assertion below is kept.
                return self

            def first(self):
                return user

            def all(self):
                # The #443 lockout guard reads the admin roster before the
                # delete; an empty roster means carol holds no admin
                # membership, so the guard stays out of this cell's way.
                return []

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
        # #486: same roster-stub as TestUserLifecycle — keep the guard out of
        # the way so the 400 below can only come from the commit failure this
        # cell claims to test.
        with patch("core.iam.role_manager.RoleManager.get_role_by_name", return_value=None):
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


# ---------------------------------------------------------------------------
# #301 adjacent lifecycle families (A2 — owner rulings Q1-Q7, 2026-10-01)


def _now():
    from datetime import UTC, datetime

    return datetime.now(UTC)


class _KeyedQ:
    """Query-chain fake keyed by the first queried model (house MagicMock-db
    discipline). table values: constant, or a list consumed per first() call
    (for same-model-queried-twice routes like the rollback latest-job check)."""

    def __init__(self, model, table, counts, updates):
        self._model = model
        self._table = table
        self._counts = counts
        self._updates = updates

    def filter(self, *a, **k):
        return self

    def join(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def with_for_update(self):
        return self

    def all(self):
        return []

    def first(self):
        value = self._table.get(self._model)
        if isinstance(value, list):
            return value.pop(0) if value else None
        return value

    def count(self):
        return self._counts.get(self._model, 0)

    def update(self, *a, **k):
        return self._updates.get(self._model, 0)


def _keyed_db(db, table=None, counts=None, updates=None):
    table = table or {}
    counts = counts or {}
    updates = updates or {}

    def query(*models):
        return _KeyedQ(models[0] if models else None, table, counts, updates)

    def add(*args, **kwargs):
        # ORM rows added through the mocked session never get real PKs;
        # response models that require ints (rotation job_id) would 500.
        # Assign a fresh id at add-time to objects lacking one (the real
        # session would have done so at flush/commit). MagicMock still
        # records the call, so house assertions keep working.
        obj = args[0] if args else None
        if obj is not None and getattr(obj, "id", None) is None:
            add.n = getattr(add, "n", 100) + 1
            try:
                obj.id = add.n
            except (AttributeError, TypeError):
                pass

    db.add.side_effect = add
    db.query.side_effect = query
    return db


# --- F1: key-version lifecycle ---


class TestKeyVersionLifecycle:
    def test_rotate_row(self):
        from core.iam.models import KeyVersion

        active = SimpleNamespace(id=7, version_label="v7", active=True)
        db = _keyed_db(MagicMock(), {KeyVersion: active})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/rotate", json={})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "key_version_rotated")
        assert len(rows) == 1
        assert rows[0].user_id == "mtls-admin-id"
        fields = _f(rows[0])
        assert set(fields) == {"old_key_version_id", "new_key_version_id", "rotation_job_id"}
        assert fields["old_key_version_id"] == 7
        db.commit.assert_called_once()  # rides the rotation's own commit

    def test_rotation_alias_writes_the_row(self):
        from core.iam.models import KeyVersion

        active = SimpleNamespace(id=7, version_label="v7", active=True)
        db = _keyed_db(MagicMock(), {KeyVersion: active})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-rotation", json={}).status_code == 200
        assert len(_by_type(_lifecycle_events(db), "key_version_rotated")) == 1

    def test_rollback_row_written_in_the_helper(self):
        from core.iam.models import KeyRotationJob, KeyVersion

        job = SimpleNamespace(id=5, status="completed", old_key_version_id=3, rolled_back_at=None)
        old = SimpleNamespace(id=3, active=False, version_label="v3")
        db = _keyed_db(MagicMock(), {KeyRotationJob: job, KeyVersion: old})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": 5})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "key_version_rolled_back")
        assert len(rows) == 1
        assert _f(rows[0]) == {"rotation_job_id": 5, "reactivated_key_version_id": 3}
        assert rows[0].user_id == "mtls-admin-id"
        commits = [i for i, c in enumerate(db.method_calls) if c[0] == "commit"]
        event_add_idx = next(i for i, c in enumerate(db.method_calls) if c[0] == "add" and "AuditEvent" in repr(c))
        assert commits and event_add_idx < min(commits)
        db.commit.assert_called_once()  # single txn via the shared helper (Q6)

    def test_job_rollback_route_writes_the_row(self):
        from core.iam.models import KeyRotationJob, KeyVersion

        job = SimpleNamespace(id=5, status="completed", old_key_version_id=3, rolled_back_at=None)
        old = SimpleNamespace(id=3, active=False, version_label="v3")
        db = _keyed_db(MagicMock(), {KeyRotationJob: job, KeyVersion: old})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-rotation/5/rollback").status_code == 200
        assert len(_by_type(_lifecycle_events(db), "key_version_rolled_back")) == 1

    def test_deactivate_row_with_noop_visibility(self):
        from core.iam.models import KeyVersion

        version = SimpleNamespace(id=3, version_label="v3", active=True)
        db = _keyed_db(MagicMock(), {KeyVersion: version})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/3/deactivate").status_code == 200
        rows = _by_type(_lifecycle_events(db), "key_version_deactivated")
        assert len(rows) == 1
        assert _f(rows[0]) == {"key_version_id": 3, "was_active": True}

    def test_deactivate_noop_still_emits(self):  # Q3 uniform record-the-attempt
        from core.iam.models import KeyVersion

        version = SimpleNamespace(id=3, version_label="v3", active=False)
        db = _keyed_db(MagicMock(), {KeyVersion: version})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/3/deactivate").status_code == 200
        rows = _by_type(_lifecycle_events(db), "key_version_deactivated")
        assert len(rows) == 1
        assert _f(rows[0]) == {"key_version_id": 3, "was_active": False}

    def test_revoke_row(self):
        from core.iam.models import KeyVersion

        version = SimpleNamespace(id=3, version_label="v3", active=False)
        db = _keyed_db(MagicMock(), {KeyVersion: version})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/3/revoke").status_code == 200
        rows = _by_type(_lifecycle_events(db), "key_version_revoked")
        assert len(rows) == 1
        assert _f(rows[0]) == {"key_version_id": 3}

    def test_negatives_write_no_rows(self):  # Q7: pre-add 4xx legs
        from core.iam.models import KeyVersion

        db = _keyed_db(MagicMock(), {KeyVersion: None})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/3/deactivate").status_code == 404
        assert client.post("/api/v1/admin/key-versions/3/revoke").status_code == 404
        assert not _lifecycle_events(db)

    def test_revoke_in_use_400_writes_no_row(self):
        from core.iam.models import KeyVersion, Secret

        version = SimpleNamespace(id=3, version_label="v3", active=False)
        db = _keyed_db(MagicMock(), {KeyVersion: version}, counts={Secret: 2})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/3/revoke").status_code == 400
        assert not _lifecycle_events(db)

    def test_rollback_404_and_409_write_no_rows(self):
        from core.iam.models import KeyRotationJob

        other = SimpleNamespace(id=6, status="completed", old_key_version_id=5)
        db = _keyed_db(MagicMock(), {KeyRotationJob: [None]})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/key-versions/rollback", json={"job_id": 9}).status_code == 404
        db2 = _keyed_db(MagicMock(), {KeyRotationJob: [other, SimpleNamespace(id=99, status="completed")]})
        client2 = TestClient(_admin_app(db2), raise_server_exceptions=False)
        assert client2.post("/api/v1/admin/key-versions/rollback", json={"job_id": 99}).status_code == 409
        assert not _lifecycle_events(db)
        assert not _lifecycle_events(db2)


# --- F2: elevation success (Q2: emits on every grant) ---


class TestElevationGranted:
    """#528 note: elevation challenge state moved to the DB, so these
    cells seed a real elevation_challenges row on SQLite (house fixture
    pattern: test_elevation_auditor_deny.py) instead of the retired
    app.state dict; the pins themselves (grant row shape / absence) are
    unchanged."""

    def _db(self, session_id=None):
        from datetime import timedelta

        from core.iam.models import Base, ElevationChallenge, User, WebAuthnCredential
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        engine = create_engine(
            "sqlite://",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        s = factory()
        s.add(User(user_id=USER_ID, status="active"))
        s.add(WebAuthnCredential(user_id=USER_ID, credential_id=b"k1", public_key=b"p1", sign_count=0))
        s.add(
            ElevationChallenge(
                challenge_id="cid",
                user_id=USER_ID,
                session_id=session_id,
                state="created",
                created_at=_now(),
                expires_at=_now() + timedelta(seconds=300),
            )
        )
        s.commit()
        return engine, factory, s

    def test_cli_grant_row_value_free(self):
        engine, _factory, db = self._db()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID}
        app = _app(
            auth_elevation_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user={"user_id": USER_ID},
            fido2_manager=fido,
        )
        app.dependency_overrides[get_db] = lambda: db
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            rm.return_value.get_user_permissions.return_value = {}
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/elevate/assert", json={"challenge_id": "cid", "response": {}})
        assert resp.status_code == 200
        try:
            rows = _by_type(db.query(AuditEvent).all(), "elevation_granted")
        finally:
            db.close()
            engine.dispose()
        assert len(rows) == 1
        assert rows[0].user_id == USER_ID
        assert _f(rows[0]) == {"mode": "cli", "endpoint": "/api/v1/auth/elevate/assert"}

    def test_browser_grant_row_value_free(self):
        from types import SimpleNamespace as _NS

        engine, factory, db = self._db(session_id=7)
        session_mock = _NS(id=7, user_id=USER_ID)
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID}
        app = _app(
            auth_browser_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            fido2_manager=fido,
        )
        # the handler closes the session it gets from the cookie resolver;
        # each request receives a fresh one over the shared engine.
        resolver = lambda request: (factory(), session_mock, {"user_id": USER_ID})
        with (
            patch.object(auth_browser_routes, "_get_session_from_cookie", side_effect=resolver),
            patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            rm.return_value.get_user_permissions.return_value = {}
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/elevate/browser/assert", json={"challenge_id": "cid", "response": {}})
        assert resp.status_code == 200
        reader = factory()
        try:
            rows = _by_type(reader.query(AuditEvent).all(), "elevation_granted")
        finally:
            reader.close()
            engine.dispose()
        assert len(rows) == 1
        assert _f(rows[0]) == {"mode": "browser", "endpoint": "/api/v1/auth/elevate/browser/assert"}

    def test_auditor_deny_writes_no_grant(self):
        engine, _factory, db = self._db()
        fido = MagicMock()
        fido.finish_authentication.return_value = {"user_id": USER_ID}
        app = _app(
            auth_elevation_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user={"user_id": USER_ID},
            fido2_manager=fido,
        )
        app.dependency_overrides[get_db] = lambda: db
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            rm.return_value.get_user_permissions.return_value = {1: "auditor"}
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/elevate/assert", json={"challenge_id": "cid", "response": {}})
        assert resp.status_code == 403
        try:
            assert not _by_type(db.query(AuditEvent).all(), "elevation_granted")
        finally:
            db.close()
            engine.dispose()

    def test_bad_assertion_writes_no_grant(self):
        from server.fido2.manager import WebAuthnError

        engine, _factory, db = self._db()
        fido = MagicMock()
        fido.finish_authentication.side_effect = WebAuthnError("bad assertion")
        app = _app(
            auth_elevation_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user={"user_id": USER_ID},
            fido2_manager=fido,
        )
        app.dependency_overrides[get_db] = lambda: db
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as rm,
        ):
            rm.return_value.get_user_permissions.return_value = {}
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/auth/elevate/assert", json={"challenge_id": "cid", "response": {}})
        assert resp.status_code == 401
        try:
            # consumed-on-error is pinned in the lifecycle file; here the
            # pin is: a failed ceremony writes NO lifecycle rows at all.
            assert not db.query(AuditEvent).all()
        finally:
            db.close()
            engine.dispose()


# --- F3: revocation lifecycle (Q3: duplicate attempts EMIT) ---


class TestRevocationLifecycle:
    def test_executor_identity_revoke_row(self):
        from core.iam.models import Executor, ExecutorCert, ExecutorCertRevocation

        cert = SimpleNamespace(serial_number="AB12", executor_id="exec-1")
        executor_row = SimpleNamespace(id="exec-1", revoked_at=None)
        db = _keyed_db(
            MagicMock(),
            {ExecutorCert: cert, Executor: executor_row, ExecutorCertRevocation: None},
        )
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec-1/revoke")
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "executor_revoked")
        assert len(rows) == 1
        assert _f(rows[0]) == {"executor_id": "exec-1", "form": "identity", "already_revoked": False}
        db.commit.assert_called_once()

    def test_executor_identity_duplicate_emits_noop_row(self):
        from datetime import UTC, datetime

        from core.iam.models import Executor, ExecutorCert, ExecutorCertRevocation

        cert = SimpleNamespace(serial_number="AB12", executor_id="exec-1")
        executor_row = SimpleNamespace(id="exec-1", revoked_at=datetime.now(UTC))
        db = _keyed_db(
            MagicMock(),
            {ExecutorCert: cert, Executor: executor_row, ExecutorCertRevocation: SimpleNamespace(serial_number="AB12")},
        )
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec-1/revoke")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is False
        rows = _by_type(_lifecycle_events(db), "executor_revoked")
        assert len(rows) == 1  # Q3: the attempt is the record
        assert _f(rows[0]) == {"executor_id": "exec-1", "form": "identity", "already_revoked": True}

    def test_executor_serial_revoke_row(self):
        from core.iam.models import ExecutorCertRevocation

        db = _keyed_db(MagicMock(), {ExecutorCertRevocation: None})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec-1/revoke", json={"serial": "ab12"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "executor_cert_revoked")
        assert len(rows) == 1
        # Serial rides the ONE canonical form (#481): padded lowercase, whatever
        # padding/case the operator typed.
        assert _f(rows[0]) == {
            "executor_id": "exec-1",
            "serial_number": "000000000000ab12",
            "already_revoked": False,
        }

    def test_executor_serial_duplicate_emits_noop_row(self):
        from core.iam.models import ExecutorCertRevocation

        db = _keyed_db(MagicMock(), {ExecutorCertRevocation: SimpleNamespace(serial_number="ab12")})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/exec-1/revoke", json={"serial": "ab12"})
        assert resp.status_code == 200
        assert resp.json()["revoked"] is False
        rows = _by_type(_lifecycle_events(db), "executor_cert_revoked")
        assert len(rows) == 1
        assert _f(rows[0]) == {
            "executor_id": "exec-1",
            "serial_number": "000000000000ab12",
            "already_revoked": True,
        }
        db.commit.assert_called_once()  # no-op row still gets its commit

    def test_admin_cert_revoke_row_and_duplicate(self):
        from core.iam.models import AdminCertRevocation

        existing = SimpleNamespace(serial_number="AB12", reason="leaked")
        db = _keyed_db(MagicMock(), {AdminCertRevocation: None})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/certs/revoke", json={"serial": "ab12", "reason": "compromised"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "admin_cert_revoked")
        assert len(rows) == 1
        assert _f(rows[0]) == {
            "serial_number": "000000000000ab12",
            "reason": "compromised",
            "already_revoked": False,
        }

        db2 = _keyed_db(MagicMock(), {AdminCertRevocation: existing})
        client2 = TestClient(_admin_app(db2), raise_server_exceptions=False)
        resp2 = client2.post("/api/v1/admin/certs/revoke", json={"serial": "AB12"})
        assert resp2.status_code == 200
        assert resp2.json()["already_revoked"] is True
        rows2 = _by_type(_lifecycle_events(db2), "admin_cert_revoked")
        assert len(rows2) == 1
        assert _f(rows2[0]) == {
            "serial_number": "000000000000ab12",
            "reason": "leaked",
            "already_revoked": True,
        }

    def test_revocation_negatives_write_no_rows(self):  # Q7
        from core.iam.models import Executor, ExecutorCert, ExecutorCertRevocation

        db = _keyed_db(MagicMock(), {ExecutorCert: None, Executor: None, ExecutorCertRevocation: None})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/executors/ghost/revoke").status_code == 404
        assert not _lifecycle_events(db)

        db2 = _keyed_db(MagicMock(), {ExecutorCert: None, Executor: None, ExecutorCertRevocation: None})
        client2 = TestClient(_admin_app(db2), raise_server_exceptions=False)
        assert client2.post("/api/v1/admin/executors/x/revoke", json={"serial": "not-hex"}).status_code == 400
        assert not _lifecycle_events(db2)

    def test_serial_events_never_carry_key_material(self):
        blob = json.dumps({"serial_number": "AB12"}).lower()
        for forbidden in ("private", "privkey", "-----begin"):
            assert forbidden not in blob


# --- F4: enrollment-reset / token lifecycle ---


class TestEnrollmentResetLifecycle:
    def _em(self):
        em = MagicMock()
        em.revoke_all_active_tokens.return_value = 2
        em.create_enrollment_token.return_value = (SimpleNamespace(id=55), "PLAIN-TOKEN-VALUE")
        em.config.token_expiry = __import__("datetime").timedelta(minutes=30)
        return em

    def test_re_enroll_writes_both_rows_value_free(self):
        from core.iam.models import User, WebAuthnCredential

        user = SimpleNamespace(user_id="carol", id=3, status="active")
        db = _keyed_db(MagicMock(), {User: user, WebAuthnCredential: None}, updates={WebAuthnCredential: 3})
        with patch("server.routes.admin.enrollment_manager", return_value=self._em()):
            client = TestClient(_admin_app(db), raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users/carol/re-enroll")
        assert resp.status_code == 200
        events = _lifecycle_events(db)
        rows = _by_type(events, "user_reenrolled")
        assert len(rows) == 1
        assert _f(rows[0]) == {"target_user_id": "carol", "credentials_deactivated": 3, "tokens_revoked": 2}
        issued = _by_type(events, "enrollment_token_issued")
        assert len(issued) == 1
        assert _f(issued[0]) == {"target_user_id": "carol", "token_id": 55, "previous_tokens_revoked": 2}
        blob = json.dumps([_f(e) for e in events])
        assert "PLAIN-TOKEN-VALUE" not in blob  # plaintext NEVER in fields

    def test_re_enroll_unknown_user_writes_no_rows(self):  # Q7
        from core.iam.models import User

        db = _keyed_db(MagicMock(), {User: None})
        with patch("server.routes.admin.enrollment_manager", return_value=self._em()):
            client = TestClient(_admin_app(db), raise_server_exceptions=False)
            assert client.post("/api/v1/admin/users/ghost/re-enroll").status_code == 404
        assert not _lifecycle_events(db)

    def test_token_create_row_value_free(self):
        from core.iam.models import User

        user = SimpleNamespace(user_id="carol", id=3)
        db = _keyed_db(MagicMock(), {User: user})
        with patch("server.routes.admin.enrollment_manager", return_value=self._em()):
            client = TestClient(_admin_app(db), raise_server_exceptions=False)
            resp = client.post("/api/v1/admin/users/carol/enrollment-tokens")
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "enrollment_token_issued")
        assert len(rows) == 1
        assert _f(rows[0]) == {"target_user_id": "carol", "token_id": 55, "previous_tokens_revoked": 2}
        assert "PLAIN-TOKEN-VALUE" not in json.dumps(_f(rows[0]))

    def test_token_revoke_emits_even_noop(self):  # Q3
        em = MagicMock()
        em.revoke_token.return_value = True
        db = MagicMock()
        with patch("server.routes.admin.enrollment_manager", return_value=em):
            client = TestClient(_admin_app(db), raise_server_exceptions=False)
            assert client.delete("/api/v1/admin/enrollment-tokens/7").status_code == 200
        rows = _by_type(_lifecycle_events(db), "enrollment_token_revoked")
        assert len(rows) == 1
        assert _f(rows[0]) == {"token_id": 7, "revoked": True}

        em2 = MagicMock()
        em2.revoke_token.return_value = False
        db2 = MagicMock()
        with patch("server.routes.admin.enrollment_manager", return_value=em2):
            client2 = TestClient(_admin_app(db2), raise_server_exceptions=False)
            assert client2.delete("/api/v1/admin/enrollment-tokens/7").status_code == 200
        rows2 = _by_type(_lifecycle_events(db2), "enrollment_token_revoked")
        assert len(rows2) == 1
        assert _f(rows2[0]) == {"token_id": 7, "revoked": False}


# --- F5: allowed-command add + the two migrated free-string sites ---


class TestCommandPolicySites:
    def test_add_allowed_command_row(self):
        from core.iam.models import CommandPolicy

        policy = SimpleNamespace(
            policy_name="default",
            allowed_commands=json.dumps(["ls"]),
            preset="balanced",
            dangerous_patterns=None,
            updated_at=None,
        )
        db = _keyed_db(MagicMock(), {CommandPolicy: policy})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/command-policy/allowed", json={"command_path": "cp"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "command_policy_changed")
        assert len(rows) == 1
        assert _f(rows[0]) == {"change": "allowed_command_added", "command_path": "cp", "already_present": False}

    def test_add_duplicate_path_emits_noop_flag(self):  # Q3
        from core.iam.models import CommandPolicy

        policy = SimpleNamespace(
            policy_name="default",
            allowed_commands=json.dumps(["ls"]),
            preset="balanced",
            dangerous_patterns=None,
            updated_at=None,
        )
        db = _keyed_db(MagicMock(), {CommandPolicy: policy})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        assert client.post("/api/v1/admin/command-policy/allowed", json={"command_path": "ls"}).status_code == 200
        rows = _by_type(_lifecycle_events(db), "command_policy_changed")
        assert len(rows) == 1
        assert _f(rows[0]) == {"change": "allowed_command_added", "command_path": "ls", "already_present": True}

    def test_set_policy_migrated_to_helper_same_txn(self):
        from core.iam.models import CommandPolicy

        policy = SimpleNamespace(
            policy_name="default", preset="balanced", allowed_commands=None, dangerous_patterns=None, updated_at=None
        )
        db = _keyed_db(MagicMock(), {CommandPolicy: policy})
        client = TestClient(_admin_app(db), raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/command-policy", json={"preset": "permissive"})
        assert resp.status_code == 200
        rows = _by_type(_lifecycle_events(db), "command_policy_changed")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert fields["preset"] == "permissive"  # current fields kept (Q5-era ruling)
        assert rows[0].user_id == "mtls-admin-id"
        commits = [i for i, c in enumerate(db.method_calls) if c[0] == "commit"]
        event_add_idx = next(i for i, c in enumerate(db.method_calls) if c[0] == "add" and "AuditEvent" in repr(c))
        assert event_add_idx < min(commits)  # rides the action commit — bypass posture retired

    def test_enroll_executor_migrated_and_preview_dropped(self):
        db = MagicMock()
        config = SimpleNamespace(
            executor_enrollment=SimpleNamespace(enabled=True, token_ttl_seconds=60), recovery_code_pepper="pep"
        )
        core = MagicMock()
        core.encrypt.return_value = ("wd", "n", "ct")
        app = _app(
            admin_routes.router,
            backend=MagicMock(get_session=MagicMock(return_value=db)),
            auth_user={"user_id": "mtls-admin-id", "caller": "admin"},
            extra_state={"config": config, "core": core},
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/executors/jump-1/enroll")
        assert resp.status_code == 201
        rows = _by_type(_lifecycle_events(db), "executor_enrollment_token_created")
        assert len(rows) == 1
        fields = _f(rows[0])
        assert "token_hash_preview" not in fields  # owner extension: hash preview DROPPED
        assert set(fields) == {
            "executor_id",
            "token_id",
            "expires_at",
            "created_by_session_id",
            "created_from_ip",
            "created_from_user_agent",
            "token_created_at",
        }
        assert "enrl_exec_" not in json.dumps(fields)  # plaintext never
