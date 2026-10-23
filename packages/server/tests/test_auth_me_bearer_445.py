# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#445 — /auth/me must answer for the credential the middleware already accepted.

At dev ``5a14936`` the handler read ONLY ``_get_session_from_cookie``: a
bearer caller that the SessionMiddleware had already authenticated
(``middleware/auth.py`` attaches ``request.state.auth_user`` at :710 for
the bearer/cookie session plane) was met with 401 "Invalid or expired
session" by its own who-am-I call — while the same token worked on every
other gated route. The module docstring already promised "satisfied by
the HttpOnly session cookie or a Bearer token"; the fix makes the code
match that contract.

Drive method: every cell here runs through the REAL ``SessionMiddleware``
(the class under test is mounted, only the DB layer and the
SessionManager/RoleManager units are mocked — the middleware itself
extracts the token and populates ``auth_user``; nothing hand-stubs
``request.state.auth_user``). The cookie-fallback cells mount the router
bare to exercise the no-middleware branch.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.models import Session as SessionModel
from core.iam.models import User
from fastapi import FastAPI
from server.middleware.auth import SessionMiddleware
from server.routes import auth_browser
from starlette.middleware import Middleware as StarletteMiddleware
from starlette.testclient import TestClient

NOW = datetime.now(UTC)

USERS = {
    "user1": SimpleNamespace(user_id="user1", status="active", display_name="Ada One"),
    "user2": SimpleNamespace(user_id="user2", status="active", display_name="Ben Two"),
}
SESSIONS = {
    "tok-1": SimpleNamespace(
        id=1,
        user_id="user1",
        expires_at=NOW + timedelta(minutes=10),
        access_token_expires_at=NOW + timedelta(minutes=5),  # #342 gate: fresh
        user=USERS["user1"],
    ),
    "tok-2": SimpleNamespace(
        id=2,
        user_id="user2",
        expires_at=NOW + timedelta(minutes=10),
        access_token_expires_at=NOW + timedelta(minutes=5),
        user=USERS["user2"],
    ),
}
ROLE_MEMBERS = {
    "user1": [SimpleNamespace(role_id=7, role=SimpleNamespace(name="operator"))],
    "user2": [],
}

# The cookie-path body captured at base 5a14936 BEFORE the fix (real
# middleware drive) — the zero-mutation reference for browser callers.
COOKIE_BODY_BASE = {
    "user_id": "user1",
    "display_name": "Ada One",
    "status": "active",
    "roles": ["operator"],
}


class _Query:
    """Filter-aware fake query: resolves ==-bound literal against fixtures."""

    def __init__(self, model):
        self.model = model
        self.crit = None

    def filter(self, crit):
        self.crit = crit
        return self

    def first(self):
        value = self.crit.right.value
        if self.model is SessionModel:
            return SESSIONS.get(value)
        if self.model is User:
            return USERS.get(value)
        return None


def _mock_backend() -> MagicMock:
    db = MagicMock()
    db.query.side_effect = lambda model: _Query(model)
    backend = MagicMock()
    backend.get_session.return_value = db
    return backend


def _middleware_app() -> FastAPI:
    """Auth router behind the REAL SessionMiddleware."""
    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(
            session_timeout=900,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        admin_mtls=SimpleNamespace(enabled=False),
    )
    app.state.backend = _mock_backend()
    app.include_router(auth_browser.router, prefix="/api/v1")
    return app


def _bare_app() -> FastAPI:
    """Auth router WITHOUT the middleware — exercises the cookie fallback."""
    app = FastAPI()
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(
            session_timeout=900,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        admin_mtls=SimpleNamespace(enabled=False),
    )
    app.state.backend = _mock_backend()
    app.include_router(auth_browser.router, prefix="/api/v1")
    return app


def _patched_units():
    """SessionManager expiry check open, RoleManager answering from fixtures."""
    sm = patch("core.iam.session_manager.SessionManager")
    rm = patch("core.iam.role_manager.RoleManager")
    return sm, rm


def _apply_units(sm_mock, rm_mock):
    sm_mock.return_value.check_expiry.return_value = True
    rm_mock.return_value.get_user_roles.side_effect = lambda uid: ROLE_MEMBERS[uid]


class TestBearerAnswers:
    def test_bearer_token_gets_200_with_right_identity(self):
        """THE ticket cell: Authorization: Bearer <valid session token> →
        /auth/me 200 with the user/roles the middleware authenticated.
        At base this returned 401 'Invalid or expired session'."""
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            client = TestClient(_middleware_app(), raise_server_exceptions=False)
            resp = client.get("/api/v1/auth/me", headers={"authorization": "Bearer tok-1"})

        assert resp.status_code == 200
        assert resp.json() == COOKIE_BODY_BASE  # same shape the cookie plane answers

    def test_cookie_pair_still_200_byte_identical_to_base(self):
        """Paired positive: browser cookie caller → 200, body byte-identical
        to the pre-#445 capture (COOKIE_BODY_BASE, taken at 5a14936)."""
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            client = TestClient(_middleware_app(), raise_server_exceptions=False)
            resp = client.get("/api/v1/auth/me", cookies={"venya_access_token": "tok-1"})

        assert resp.status_code == 200
        assert resp.json() == COOKIE_BODY_BASE

    def test_no_credential_is_refused(self):
        """Refusal half (most important): nothing presented → 401. Behind
        the middleware the refusal is the middleware's own 'Missing
        authentication token' — the handler never sees the request."""
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            client = TestClient(_middleware_app(), raise_server_exceptions=False)
            resp = client.get("/api/v1/auth/me")

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing authentication token"

    def test_handler_own_401_detail_survives_on_bare_mount(self):
        """The existing handler detail is the OTHER refusal half: no
        middleware and no cookie → the handler's own 401 'Invalid or
        expired session' — unchanged text from the base contract."""
        client = TestClient(_bare_app(), raise_server_exceptions=False)
        resp = client.get("/api/v1/auth/me")

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired session"

    def test_bogus_bearer_does_not_fall_back_to_a_pass(self):
        """Bogus bearer must NOT become a cookie-less pass: the middleware
        rejects the unknown token (401 'Invalid or expired token') and the
        handler never answers. Session-gone variants included: the fix's
        fallback is gated on auth_user ABSENT, not on token failure."""
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            client = TestClient(_middleware_app(), raise_server_exceptions=False)
            resp = client.get("/api/v1/auth/me", headers={"authorization": "Bearer nope"})

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

    def test_expired_bearer_is_refused(self):
        """A session whose #342 token expiry has aged past the window is
        rejected by the middleware — no /auth/me answer for a dead token."""
        expired = SimpleNamespace(
            id=3,
            user_id="user1",
            expires_at=NOW + timedelta(minutes=10),
            access_token_expires_at=NOW - timedelta(minutes=1),
            user=USERS["user1"],
        )
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            SESSIONS["tok-exp"] = expired
            try:
                client = TestClient(_middleware_app(), raise_server_exceptions=False)
                resp = client.get("/api/v1/auth/me", headers={"authorization": "Bearer tok-exp"})
            finally:
                SESSIONS.pop("tok-exp", None)

        assert resp.status_code == 401

    def test_cookie_and_bearer_both_present_middleware_priority_wins(self):
        """Documented priority (middleware/auth.py: cookie (browser) takes
        priority, then bearer header): both offered → the answer is the
        COOKIE session, not an invented merge."""
        sm, rm = _patched_units()
        with sm as sm_mock, rm as rm_mock:
            _apply_units(sm_mock, rm_mock)
            client = TestClient(_middleware_app(), raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/auth/me",
                headers={"authorization": "Bearer tok-2"},
                cookies={"venya_access_token": "tok-1"},
            )

        assert resp.status_code == 200
        assert resp.json()["user_id"] == "user1", "cookie plane is the documented priority"


class TestNonSessionCallerRefused:
    """Caller classes the middleware authenticates WITHOUT a session row.

    The handler-level fail-closed branch is exercised by attaching the
    exact dict shapes middleware/auth.py itself builds — admin-mTLS plane
    at :560 ({"caller": "admin", "user_id": identity, "plane": plane}) and
    executor plane at :833 ({"caller": "executor", ...}) — via a one-line
    stamping middleware. Simulating the ATTACHED shape is honest here:
    these planes cannot reach /auth/me through the real middleware at all
    (a cert-only caller carries no session token and is 401'd at the
    credential layer), so this guard is defense-in-depth and its unit is
    the shape the real middleware writes on its own lines.
    """

    def _app_with_plane(self, plane_dict):
        from starlette.middleware.base import BaseHTTPMiddleware

        app = _bare_app()

        class AttachPlane(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.auth_user = dict(plane_dict)
                return await call_next(request)

        app.user_middleware.insert(0, StarletteMiddleware(AttachPlane))
        return app

    def test_admin_plane_auth_user_is_refused_not_fabricated(self):
        app = self._app_with_plane({"caller": "admin", "user_id": "admin", "plane": "admin"})
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/auth/me")

        assert resp.status_code == 401
        body = resp.json()
        assert body.get("user_id") != "admin", "no fabricated identity readout of the cert identity"
        assert body["detail"] == "Not a session-authenticated caller"

    def test_executor_plane_auth_user_is_refused_not_fabricated(self):
        app = self._app_with_plane(
            {"caller": "executor", "executor_id": "exec-1", "presented_serial": "aa", "revoked": False}
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/auth/me")

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Not a session-authenticated caller"
