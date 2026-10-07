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
import json
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


# ---------------------------------------------------------------------------
# #523 browser-logout-skips-revoke-when-idle-expired


def _expired_row():
    """Idle-expired (session_timeout 900s, expires_at 10 min past) but inside
    the 4h hard cap — exactly the row check_refresh_window keeps revivable."""
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=7,
        user_id="u1",
        created_at=now - timedelta(hours=1),
        expires_at=now - timedelta(minutes=10),
        access_token="tok-idle",
        access_token_jti="jti-idle",
        user=SimpleNamespace(user_id="u1", status="active"),
    )


def _logout_app(row):
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


def _fields(event):
    return json.loads(event.fields) if isinstance(event.fields, str) else event.fields


def _audit_rows(db):
    from core.iam.models import AuditEvent

    return [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], AuditEvent)]


def test_idle_expired_logout_revokes_the_row():
    """#523 PAIRED NEGATIVE, RED at HEAD: a cookie whose session is
    idle-expired-but-inside-the-hard-cap logs out -> the DB row is revoked
    (deleted), not merely cookie-cleared. At HEAD the validator's None result
    took an early return and revoke was never reached."""
    row = _expired_row()
    _, client, db = _logout_app(row)
    resp = client.post("/api/v1/auth/logout/browser")
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "Max-Age=0" in set_cookie  # cookie still cleared
    db.delete.assert_called_once_with(row)  # the row itself revoked
    ended = [e for e in _audit_rows(db) if e.event_type == "session_ended"]
    assert len(ended) == 1
    assert ended[0].user_id == "u1"
    fields = _fields(ended[0])
    assert fields["revoked"] is True
    # AC4: the operator-readable distinction from a live-session logout.
    assert fields["session_expired"] is True
    assert fields["mode"] == "browser"


def test_garbage_token_logout_is_clean_200_no_exception():
    """#523 AC2 paired shape: a cookie holding an unknown/garbage token has
    nothing to revoke — still a clean 200, cookie cleared, NO audit row (so
    the negative case does not become a 500 or a fake logout event)."""
    _, client, db = _logout_app(None)
    resp = client.post("/api/v1/auth/logout/browser")
    assert resp.status_code == 200
    assert "Max-Age=0" in resp.headers.get("set-cookie", "")
    db.delete.assert_not_called()
    assert not _audit_rows(db)


def test_expired_logout_revoke_failure_is_fail_closed():
    """The ruling 2026-10-01 fail-closed shape carries to the revoked-row
    half of #523: if the revoke raises, the logout refuses to claim success
    (503, revoked=False row, cookie kept as the retry handle)."""
    row = _expired_row()
    _, client, db = _logout_app(row)
    db.delete.side_effect = RuntimeError("db down")
    resp = client.post("/api/v1/auth/logout/browser")
    assert resp.status_code == 503
    body = resp.json()
    assert body["revoked"] is False
    set_cookie = resp.headers.get("set-cookie", "")
    assert f"{auth_browser.COOKIE_NAME}=" not in set_cookie
    ended = [e for e in _audit_rows(db) if e.event_type == "session_ended"]
    assert len(ended) == 1
    assert _fields(ended[0])["revoked"] is False


def test_no_cookie_logout_still_clean_200():
    """Paired negative retained: no cookie at all — the early path is
    unchanged (200 + cookie-clear directive, nothing touched in the DB)."""
    _, client, db = _logout_app(_expired_row())
    client.cookies.clear()
    resp = client.post("/api/v1/auth/logout/browser")
    assert resp.status_code == 200
    db.delete.assert_not_called()
    assert not _audit_rows(db)
