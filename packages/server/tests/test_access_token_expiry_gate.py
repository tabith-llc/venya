# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#342: bearer validation enforces the persisted token expiry.

Gate cells over the harness idiom of test_session_middleware.py (mock backend,
SessionManager patched): aged token -> 401 (the bug at base: this passed
vacuously), fresh token -> 200, NULL expiry -> 401 fail-closed. Session-level
gates (check_expiry path) unchanged — paired negatives below.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.middleware.auth import SessionMiddleware
from starlette.testclient import TestClient


def _app_with(session, *, expiry="fresh"):
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
    return app


def _session_row(**overrides):
    now = datetime.now(UTC)
    row = SimpleNamespace(
        id=1,
        user_id="user1",
        created_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(minutes=10),
        user=SimpleNamespace(user_id="user1", status="active"),
        access_token_jti="jti-1",
        access_token_expires_at=now + timedelta(seconds=300),
    )
    for k, v in overrides.items():
        setattr(row, k, v)
    return row


def _get(app):
    with patch("core.iam.session_manager.SessionManager") as mock_sm, patch(
        "core.iam.role_manager.RoleManager"
    ) as mock_rm:
        mock_sm.return_value.check_expiry.return_value = True
        mock_rm.return_value.get_user_roles.return_value = []
        client = TestClient(app, raise_server_exceptions=False)
        client.headers.update({"Authorization": "Bearer tok-abc"})
        return client.get("/api/v1/protected")


def test_aged_token_is_rejected():
    # Paired-negative cell: this is the bug — at base the request passes.
    session = _session_row(access_token_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    resp = _get(_app_with(session))
    assert resp.status_code == 401


def test_fresh_token_passes():
    session = _session_row()
    resp = _get(_app_with(session))
    assert resp.status_code == 200


def test_null_expiry_fails_closed():
    session = _session_row(access_token_expires_at=None)
    resp = _get(_app_with(session))
    assert resp.status_code == 401


def test_session_level_gates_unchanged():
    # Paired negative: session idle/hard-cap gate still governs as before —
    # check_expiry False -> 401 regardless of a fresh token timestamp.
    session = _session_row()
    app = _app_with(session)
    with patch("core.iam.session_manager.SessionManager") as mock_sm:
        mock_sm.return_value.check_expiry.return_value = False
        client = TestClient(app, raise_server_exceptions=False)
        client.headers.update({"Authorization": "Bearer tok-abc"})
        resp = client.get("/api/v1/protected")
    assert resp.status_code == 401
