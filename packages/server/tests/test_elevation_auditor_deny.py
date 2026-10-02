# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Elevation-token ISSUANCE deny for auditor-only callers (auditor-role
rework, ruling 1c-ii: diagnostics — the authoritative value-deny is the
secrets_get unmask chokepoint; issuance refusal is the last gate before the
token exists).

Both assert endpoints are covered (browser twin the original ticket missed).
BLANKET consequence pinned here by comment per the owner ruling: the same
token gates self-service credential-add (credentials._verify_elevation),
so an auditor-only user CANNOT add their own security key — release-notes
wording in CHANGELOG.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.models import AuditEvent, ElevationToken
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import auth_browser as auth_browser_routes
from server.routes import auth_elevation as auth_elevation_routes
from starlette.testclient import TestClient

DENY_DETAIL = "insufficient role: auditor cannot elevate"


def _added(db):
    """Objects passed to db.add (house MagicMock-session pattern)."""
    return [call.args[0] for call in db.add.call_args_list]


def _deny_events(db):
    return [o for o in _added(db) if isinstance(o, AuditEvent) and o.event_type == "auditor_elevation_denied"]


def _cli_app(user_id="user1"):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    app.state._elevation_challenges = {
        "c1": {"user_id": user_id, "created_at": datetime.now(UTC)},
    }
    app.include_router(auth_elevation_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id}
    db = MagicMock()
    app.dependency_overrides[get_db] = lambda: db
    return app, db


def _assert_cli(app, tier_map):
    with (
        patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = tier_map
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/auth/elevate/assert",
            json={"challenge_id": "c1", "response": {"id": "dGVzdA=="}},
        )


class TestElevateAssertAuditorDeny:
    def test_auditor_only_denied_403_no_token_issued(self):
        """Deny fires BEFORE token creation: NO ElevationToken add, and
        exactly one value-free auditor_elevation_denied AuditEvent
        (owner ruling 2026-09-30: denials are audit-logged; the event
        commit is the only commit on the deny path)."""
        app, db = _cli_app()
        resp = _assert_cli(app, {1: "auditor"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
        assert not any(isinstance(o, ElevationToken) for o in _added(db))
        events = _deny_events(db)
        assert len(events) == 1
        assert events[0].user_id == "user1"
        assert "elevation_token" not in events[0].fields
        db.commit.assert_called_once()
        # H1 (elevation twin): audit-write failure must not upgrade the
        # denial — same handler, fail-closed guard; asserted at the secrets
        # chokepoint cell (test_secrets.py H1).

    def test_read_write_issue_passes(self):
        """Paired positive: read-write caller gets its token (unchanged)
        and ZERO deny events (N2 negative-half)."""
        app, db = _cli_app()
        resp = _assert_cli(app, {1: "read-write"})
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        db.add.assert_called()
        assert _deny_events(db) == []

    def test_union_issue_passes(self):
        """1b union: auditor+read is not auditor-only — issuance passes,
        zero deny events."""
        app, db = _cli_app()
        resp = _assert_cli(app, {1: "auditor", 2: "read"})
        assert resp.status_code == 200
        db.add.assert_called()
        assert _deny_events(db) == []

    def test_non_member_issue_passes(self):
        """Empty membership map passes the ISSUANCE gate (helper is False;
        issuance refusal is diagnostics-only per 1c-ii — nothing here grants
        or denies value access, and value paths are read-gated elsewhere)."""
        app, _db = _cli_app()
        resp = _assert_cli(app, {})
        assert resp.status_code == 200


def _browser_app(user_id="user1", session_id="sess-1"):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    app.state._elevation_challenges = {"c1": {"session_id": session_id, "created_at": datetime.now(UTC)}}
    app.include_router(auth_browser_routes.router, prefix="/api/v1")
    db = MagicMock()
    session = SimpleNamespace(id=session_id, user_id=user_id)
    return app, db, session


def _assert_browser(app, db, session, tier_map):
    with (
        patch(
            "server.routes.auth_browser._get_session_from_cookie",
            return_value=(db, session, {"user_id": session.user_id}),
        ),
        patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = tier_map
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "c1", "response": {"id": "dGVzdA==", "response": {}}},
        )


class TestBrowserElevateAssertAuditorDeny:
    """Browser twin mirror (auth_browser.browser_elevate_assert) — the CLI
    deny alone would leave the browser elevation path issuing tokens to
    auditor-only callers."""

    def test_auditor_only_denied_403_challenge_consumed(self):
        """Browser twin deny (P3): 403, one value-free auditor_elevation_
        denied event committed, no token add. #345 flipped this pin: the
        assert pops the challenge up-front, so the denial consumes the
        entry — the pre-fix "denied ceremony slot stays live" residue is
        exactly what the ruling retired."""
        app, db, session = _browser_app()
        resp = _assert_browser(app, db, session, {1: "auditor"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
        assert not any(isinstance(o, ElevationToken) for o in _added(db))
        events = _deny_events(db)
        assert len(events) == 1
        assert events[0].user_id == "user1"
        assert "elevation_token" not in events[0].fields
        db.commit.assert_called_once()
        # Pop-up-front (#345): the denial path leaves no live entry.
        assert "c1" not in app.state._elevation_challenges

    def test_read_write_issue_passes(self):
        app, db, session = _browser_app()
        resp = _assert_browser(app, db, session, {1: "read-write"})
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        db.add.assert_called()
        assert _deny_events(db) == []

    def test_union_issue_passes(self):
        app, db, session = _browser_app()
        resp = _assert_browser(app, db, session, {1: "auditor", 2: "read"})
        assert resp.status_code == 200
        assert _deny_events(db) == []

    def test_audit_write_failure_still_denies_403(self):
        """H1 twin: AuditEvent commit blows up -> STILL a loud 403, never
        a 200 and never a 500 (fail-closed guard; the denial is the
        security control, the log line is the loud side-effect)."""
        app, db, session = _browser_app()
        db.commit.side_effect = RuntimeError("audit store down")
        resp = _assert_browser(app, db, session, {1: "auditor"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
        assert _deny_events(db)  # the event was attempted before the failed commit
