# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Browser elevation-challenge lifecycle (ticket browser-elevation-challenge-
unbounded, #345): the CLI pattern (auth_elevation) is reused on the browser
twin — created_at on store, stale-sweep on touch, pop-up-front on assert so an
abandoned ceremony, a WebAuthn-error assert, or an auditor denial never leaves
a live entry lingering until restart.

Truth-table pairs: stale entries pruned / fresh entries kept; the entry is
consumed on EVERY assert path (deny and error included).
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from server.routes import auth_browser as routes
from starlette.testclient import TestClient

FRESH = {"session_id": "sess-1", "user_id": "user1", "created_at": datetime.now(UTC)}
STALE = {
    "session_id": "other",
    "user_id": "other",
    "created_at": datetime.now(UTC) - timedelta(seconds=routes.ELEVATION_TOKEN_TTL_SECONDS * 5 + 10),
}


def _app(challenges):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    app.state.fido2_manager.start_authentication.return_value = ("new-cid", {"challenge": "chal"})
    app.state._elevation_challenges = challenges
    app.include_router(routes.router, prefix="/api/v1")
    db = MagicMock()
    session = SimpleNamespace(id="sess-1", user_id="user1")
    return app, db, session


def _post_challenge(app, db, session):
    with patch(
        "server.routes.auth_browser._get_session_from_cookie",
        return_value=(db, session, {"user_id": session.user_id}),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        return client.post("/api/v1/auth/elevate/browser/challenge")


def _post_assert(app, db, session, challenge_id="c1", finish_error=None):
    app.state.fido2_manager.finish_authentication.side_effect = finish_error
    with patch(
        "server.routes.auth_browser._get_session_from_cookie",
        return_value=(db, session, {"user_id": session.user_id}),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": challenge_id, "response": {"id": "dGVzdA==", "response": {}}},
        )


class TestStoreLifecycle:
    def test_stored_challenge_carries_created_at(self):
        app, db, session = _app({})
        resp = _post_challenge(app, db, session)
        assert resp.status_code == 200
        entry = app.state._elevation_challenges["new-cid"]
        assert isinstance(entry["created_at"], datetime)

    def test_challenge_touch_prunes_stale_but_keeps_fresh(self):
        """Stale half + paired negative: a fresh entry survives the sweep."""
        app, db, session = _app({"stale": dict(STALE), "fresh": dict(FRESH)})
        resp = _post_challenge(app, db, session)
        assert resp.status_code == 200
        assert "stale" not in app.state._elevation_challenges
        assert "fresh" in app.state._elevation_challenges

    def test_assert_touch_prunes_stale(self):
        app, db, session = _app({"c1": dict(FRESH), "stale": dict(STALE)})
        _post_assert(app, db, session)
        assert "stale" not in app.state._elevation_challenges


def _post_assert_permissions(app, db, session, tier_map):
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


class TestPopUpFront:
    def test_webauthn_error_assert_consumes_challenge(self):
        """Pre-fix residue: a failed assertion left the entry live."""
        from server.fido2.manager import WebAuthnError

        app, db, session = _app({"c1": dict(FRESH)})
        resp = _post_assert(app, db, session, finish_error=WebAuthnError("bad assertion"))
        assert resp.status_code == 401
        assert "c1" not in app.state._elevation_challenges

    def test_auditor_deny_consumes_challenge(self):
        """The worst residue class from the ticket: a denied ceremony slot
        stays live. Pop-up-front makes the denial consume the entry."""
        app, db, session = _app({"c1": dict(FRESH)})
        resp = _post_assert_permissions(app, db, session, {1: "auditor"})
        assert resp.status_code == 403
        assert "c1" not in app.state._elevation_challenges

    def test_session_mismatch_consumes_challenge(self):
        """Wrong-session caller cannot leave the rightful owner's entry
        lingering for a later replay window — the entry is gone either way."""
        app, db, session = _app({"c1": {**FRESH, "session_id": "someone-else"}})
        resp = _post_assert(app, db, session)
        assert resp.status_code == 401
        assert "c1" not in app.state._elevation_challenges

    def test_success_assert_consumes_challenge_once(self):
        """Paired positive: the success leg still works and cannot be
        replayed (entry gone, second attempt 401 not-found)."""
        app, db, session = _app({"c1": dict(FRESH)})
        resp = _post_assert_permissions(app, db, session, {})
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        assert "c1" not in app.state._elevation_challenges
        resp2 = _post_assert(app, db, session)
        assert resp2.status_code == 401
