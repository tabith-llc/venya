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
    assert "session_model is None" in src
    assert "Invalid or expired session" in src
    # #526: the self-gate is the HARD-CAP window (bearer-tier Option A), not
    # the shared get_current_session idle check — the promise in the
    # middleware's PUBLIC_PATHS note is now actually implemented here.
    assert "check_refresh_window" in src
    assert "Depends(get_current_session)" not in src


# ---------------------------------------------------------------------------
# #526 browser-refresh-unreachable-for-idle-expired-session — the cookie
# refresh must revive idle-expired rows inside the hard cap (bearer-tier
# Option A parity), and still 401 past the cap.


def _idle_expired_row():
    """created 1h ago (< 4h cap), idle-past the 900s session_timeout —
    exactly the kind of row this endpoint exists to revive."""
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=21,
        user_id="u1",
        user=SimpleNamespace(user_id="u1", status="active"),
        created_at=now - timedelta(hours=1),
        expires_at=now - timedelta(minutes=10),
        access_token="tok-idle",
        access_token_jti="jti-idle",
        access_token_expires_at=now - timedelta(minutes=10),
    )


def _refresh_app(row):
    app = FastAPI()
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(session_timeout=900, access_token_ttl=300, max_session_duration=14400),
        admin_mtls=SimpleNamespace(enabled=False),
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = row
    backend = MagicMock()
    backend.get_session.return_value = db
    app.state.backend = backend
    app.include_router(auth_browser.router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set(auth_browser.COOKIE_NAME, "tok-idle")
    return app, client, db


def test_idle_expired_cookie_refresh_revives_same_row():
    """#526 AC1 PAIRED POSITIVE, RED at HEAD: inside the hard cap but past
    the idle timeout, /auth/refresh/browser must 200 — new cookie written,
    expires_at slid forward, and the SAME session row rotated in place (no
    new Session row minted). At HEAD get_current_session's idle check
    401'd exactly this shape."""
    row = _idle_expired_row()
    _, client, db = _refresh_app(row)
    resp = client.post("/api/v1/auth/refresh/browser")
    assert resp.status_code == 200, resp.text
    set_cookie = resp.headers.get("set-cookie", "")
    assert auth_browser.COOKIE_NAME in set_cookie
    assert row.access_token != "tok-idle"  # rotated
    assert auth_browser.COOKIE_NAME + "=" + row.access_token in set_cookie  # cookie rides the NEW token
    assert row.expires_at > datetime.now(UTC)  # slid forward
    assert row.id == 21  # same row
    # No new session minted: db.add is never handed a fresh Session row.
    from core.iam.models import Session as SessionModel

    added = [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], SessionModel)]
    assert not added
    db.commit.assert_called()


def test_past_hard_cap_cookie_refresh_401_uniform():
    """#526 AC2/AC5 PAIRED NEGATIVE: created beyond max_session_duration —
    refresh dies, re-auth (FIDO2) required. 401 in the uniform expired
    shape, NO cookie written, row untouched."""
    now = datetime.now(UTC)
    row = _idle_expired_row()
    row.created_at = now - timedelta(hours=5)  # past the 4h cap
    row.expires_at = now + timedelta(minutes=5)  # even a live idle clock must not save it
    _, client, db = _refresh_app(row)
    resp = client.post("/api/v1/auth/refresh/browser")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired session"
    assert "set-cookie" not in resp.headers
    assert row.access_token == "tok-idle"  # not rotated
    db.commit.assert_not_called()


def test_garbage_cookie_refresh_401():
    """Unknown token -> None row -> the uniform 401 (not a 500)."""
    _, client, _ = _refresh_app(None)
    resp = client.post("/api/v1/auth/refresh/browser")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired session"


def test_no_cookie_refresh_401():
    _, client, _ = _refresh_app(_idle_expired_row())
    client.cookies.clear()
    resp = client.post("/api/v1/auth/refresh/browser")
    assert resp.status_code == 401


def test_active_live_cookie_refresh_still_works():
    """Positive retained: the ordinary (not idle-expired) cookie refresh keeps
    working through the same dedicated path."""
    row = _idle_expired_row()
    row.expires_at = datetime.now(UTC) + timedelta(minutes=10)
    _, client, _ = _refresh_app(row)
    resp = client.post("/api/v1/auth/refresh/browser")
    assert resp.status_code == 200
    assert "set-cookie" in resp.headers


def test_get_current_session_idle_check_untouched():
    """#526 AC4 scope pin: the shared dependency keeps its strict idle
    rejection (other handlers riding it must not widen). Verified against a
    row that is idle-expired but inside the hard cap."""
    from fastapi import FastAPI as _FastAPI
    from server.dependencies import get_current_session

    app = _FastAPI()
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(session_timeout=900, access_token_ttl=300, max_session_duration=14400),
        clock_skew=SimpleNamespace(token_tolerance_seconds=60),
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _idle_expired_row()
    request = SimpleNamespace(app=app, cookies={auth_browser.COOKIE_NAME: "tok-idle"})
    assert get_current_session(request, db) is None
