# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Elevation session binding (#527 elevation-not-session-bound).

Half 1 (bearer plane): the challenge stores the starting session; the
assert must refuse when the CALLER rides a different session of the same
user — mirroring the browser twin's ruled shape ("Elevation challenge
session mismatch"). Half 2: issued elevation tokens record the earning
session_id on BOTH planes so the revoke path (core test:
test_session_revoke_elevation_527.py) can delete them with the session.

Truth-table pairs: cross-session assert REFUSED / same-session assert
ACCEPTED; mTLS-shaped contexts with no session on either side pass the
gate inertly (no 500, no behavior change).
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.models import ElevationToken
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import auth_browser as auth_browser_routes
from server.routes import auth_elevation as auth_elevation_routes
from starlette.testclient import TestClient


def _cli_app(challenges, user_info):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    app.state._elevation_challenges = challenges
    app.include_router(auth_elevation_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user_info
    db = MagicMock()
    app.dependency_overrides[get_db] = lambda: db
    return app, db


def _assert_cli(app):
    with (
        patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/auth/elevate/assert",
            json={"challenge_id": "c1", "response": {"id": "dGVzdA=="}},
        )


def _added(db, kind):
    return [o for o in (c.args[0] for c in db.add.call_args_list) if isinstance(o, kind)]


class TestBearerSessionGate:
    def test_cross_session_assert_refused(self):
        """PAIRED NEGATIVE, RED at HEAD: challenge started in session 1 is
        asserted with session 2's bearer token of the SAME user -> 401
        'Elevation challenge session mismatch'; no ElevationToken row is
        created; the challenge stays CONSUMED (pop-up-front, #345 pattern —
        stated choice: consumed, so a denied ceremony never leaves a slot)."""
        now = datetime.now(UTC)
        challenges = {"c1": {"user_id": "user1", "session_id": 1, "created_at": now}}
        app, db = _cli_app(challenges, {"user_id": "user1", "session_id": 2})
        resp = _assert_cli(app)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge session mismatch"
        assert not _added(db, ElevationToken)
        assert "c1" not in challenges  # consumed even on refusal

    def test_same_session_assert_accepted(self):
        """Positive retained: same user AND same session -> 200 + token."""
        now = datetime.now(UTC)
        challenges = {"c1": {"user_id": "user1", "session_id": 1, "created_at": now}}
        app, db = _cli_app(challenges, {"user_id": "user1", "session_id": 1})
        resp = _assert_cli(app)
        assert resp.status_code == 200
        tokens = _added(db, ElevationToken)
        assert len(tokens) == 1
        assert tokens[0].session_id == 1  # the earning session recorded

    def test_user_mismatch_shape_unchanged(self):
        """The pre-existing user gate keeps its order and detail (the new
        session gate must not convert user mismatch into session mismatch)."""
        now = datetime.now(UTC)
        challenges = {"c1": {"user_id": "someone-else", "session_id": 1, "created_at": now}}
        app, _db = _cli_app(challenges, {"user_id": "user1", "session_id": 1})
        resp = _assert_cli(app)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge user mismatch"

    def test_context_without_sessions_gate_inert(self):
        """mTLS/admin contexts (auditor-deny fixtures' shape): no session_id
        on either side -> None == None, gate inert, old behavior stands."""
        now = datetime.now(UTC)
        challenges = {"c1": {"user_id": "user1", "created_at": now}}
        app, db = _cli_app(challenges, {"user_id": "user1"})
        resp = _assert_cli(app)
        assert resp.status_code == 200
        tokens = _added(db, ElevationToken)
        assert len(tokens) == 1
        assert tokens[0].session_id is None


class TestBrowserPlaneIssuanceBinding:
    def test_browser_elevate_assert_records_session(self):
        """Cookie plane: the session that completed the ceremony is recorded
        on the token row (the revoke-delete path needs it)."""
        now = datetime.now(UTC)
        session_row = SimpleNamespace(id=42, user_id="user1")
        db = MagicMock()
        app = FastAPI()
        app.state.fido2_manager = MagicMock()
        app.state._elevation_challenges = {
            "c1": {"user_id": "user1", "session_id": 42, "created_at": now},
        }
        app.include_router(auth_browser_routes.router, prefix="/api/v1")
        with (
            patch(
                "server.routes.auth_browser._get_session_from_cookie",
                return_value=(db, session_row, {"user_id": "user1"}),
            ),
            patch(
                "server.routes.auth_browser.browser_assertion_to_fido2",
                return_value={},
            ),
            patch("core.iam.role_manager.RoleManager") as mock_rm,
        ):
            mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/auth/elevate/browser/assert",
                json={"challenge_id": "c1", "response": {"id": "dGVzdA==", "response": {}}},
            )
        assert resp.status_code == 200
        tokens = _added(db, ElevationToken)
        assert len(tokens) == 1
        assert tokens[0].session_id == 42
