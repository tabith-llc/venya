# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#341: the browser cookie plane rides the configured session timeout.

Cells: the cookie helper honors a stacked session_timeout (no hardcoded 300);
the middleware re-issues Set-Cookie when it slides the session row; the
browser refresh route is middleware-public and self-gated handler-side; bearer
clients are untouched (paired negatives).
"""

import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.middleware.auth import SessionMiddleware
from server.routes import auth_browser
from starlette.responses import Response
from starlette.testclient import TestClient


def test_set_session_cookie_follows_configured_timeout():
    response = Response()
    auth_browser._set_session_cookie(response, "tok-abc", 1234)
    header = response.headers["set-cookie"]
    assert "venya_access_token=tok-abc" in header
    assert "Max-Age=1234" in header


def test_login_and_refresh_handlers_pass_configured_timeout():
    src = inspect.getsource(auth_browser)
    assert "_set_session_cookie(response, access_token.token, sc.session_timeout)" in src
    assert "_set_session_cookie(response, new_token.token, sc.session_timeout)" in src
    # The hardcoded constant is gone.
    assert "COOKIE_MAX_AGE" not in src


def _make_app_and_client(session, session_timeout=1234, cookie=True):
    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(
            session_timeout=session_timeout,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        admin_mtls=SimpleNamespace(enabled=False),
    )

    @app.get("/api/v1/protected")
    def protected():
        return {"ok": True}

    db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value.first.return_value = session
        return q

    db.query.side_effect = query_side_effect
    backend = MagicMock()
    backend.get_session.return_value = db
    app.state.backend = backend

    client = TestClient(app, raise_server_exceptions=False)
    if cookie:
        client.cookies.set(auth_browser.COOKIE_NAME, "tok-abc")
    else:
        client.headers.update({"Authorization": "Bearer tok-abc"})
    return app, client


def _sliding_session():
    # Nearing expiry (<5 min left) — the middleware's own extension trigger.
    return SimpleNamespace(
        id=1,
        user_id="user1",
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
        user=SimpleNamespace(user_id="user1", status="active"),
        access_token_jti="jti-1",
        # #342 gate: fresh persisted bearer expiry (future).
        access_token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_sliding_extension_reissues_cookie():
    session = _sliding_session()
    _, client = _make_app_and_client(session)
    with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
        "core.iam.role_manager.RoleManager"
    ) as mock_rm:
        mock_sm.return_value.check_expiry.return_value = True
        mock_rm.return_value.get_user_roles.return_value = []
        resp = client.get("/api/v1/protected")
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "venya_access_token=tok-abc" in set_cookie, f"no re-issued cookie; headers={dict(resp.headers)}"
    assert "Max-Age=1234" in set_cookie


def test_bearer_extension_does_not_set_cookie():
    # Paired negative: same sliding extension, bearer plane — no cookie header.
    session = _sliding_session()
    _, client = _make_app_and_client(session, cookie=False)
    with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
        "core.iam.role_manager.RoleManager"
    ) as mock_rm:
        mock_sm.return_value.check_expiry.return_value = True
        mock_rm.return_value.get_user_roles.return_value = []
        resp = client.get("/api/v1/protected")
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers


def test_browser_refresh_is_public_and_bearer_refresh_unchanged():
    # Exact registered path: prefix "/api/v1" + decorator "/auth/refresh/browser".
    assert "/api/v1/auth/refresh/browser" in SessionMiddleware.PUBLIC_PATHS
    # Paired negative: the bearer twin's membership is unchanged.
    assert "/api/v1/auth/refresh" in SessionMiddleware.PUBLIC_PATHS


def test_browser_refresh_handler_self_gates_without_cookie():
    src = inspect.getsource(auth_browser.browser_refresh)
    assert "session is None" in src
    assert "Invalid or expired session" in src
