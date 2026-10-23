# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Elevation session binding (#527 elevation-not-session-bound).

Half 1: the assert must refuse when the CALLER rides a different session
of the same user — the challenge stores the starting session on both
planes and the check compares them (bearer plane gained the gate; the
browser twin already had it). Half 2: issued elevation tokens record the
earning session_id on BOTH planes so the revoke path (core test:
test_session_revoke_elevation_527.py) can delete them with the session.

#528 moved the challenge store to the elevation_challenges table; these
cells run on real SQLite rows (house fixture pattern:
test_admin_delete_dependencies_425.py).

Truth-table pairs: cross-session assert REFUSED / same-session ACCEPTED;
mTLS-shaped contexts with no session on either side pass the gate inertly
(no 500, no behavior change).
"""

from datetime import UTC, datetime, timedelta
from itertools import count
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import Base, ElevationChallenge, ElevationToken, User, WebAuthnCredential
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import auth_browser as auth_browser_routes
from server.routes import auth_elevation as auth_elevation_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

CHALLENGE_TTL = 60 * 5


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(User(user_id="user1", status="active"))
    s.add(WebAuthnCredential(user_id="user1", credential_id=b"k1", public_key=b"p1", sign_count=0))
    s.commit()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


@pytest.fixture()
def caller():
    return {"user_id": "user1", "session_id": 11}


@pytest.fixture()
def cli(session, caller):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    n = count()
    app.state.fido2_manager.start_authentication.side_effect = lambda user_id=None: (
        f"cid-{next(n)}",
        {"challenge": "chal"},
    )
    app.include_router(auth_elevation_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: caller
    app.dependency_overrides[get_db] = lambda: session
    client = TestClient(app, raise_server_exceptions=False)

    def post_challenge():
        return client.post("/api/v1/auth/elevate/challenge")

    def post_assert(cid):
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as mock_rm,
        ):
            mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
            return client.post(
                "/api/v1/auth/elevate/assert",
                json={"challenge_id": cid, "response": {"id": "dGVzdA=="}},
            )

    return client, post_challenge, post_assert


def _challenge_row(session, cid):
    session.expire_all()
    return session.query(ElevationChallenge).filter_by(challenge_id=cid).first()


class TestBearerSessionGate:
    def test_cross_session_assert_refused(self, session, cli, caller):
        """PAIRED NEGATIVE: challenge started in session 11 is asserted with
        session 22's bearer token of the SAME user -> 401 'Elevation
        challenge session mismatch'; no ElevationToken row; the challenge
        stays CONSUMED (the claim commits before the checks — a denied
        ceremony never re-arms, #345 meaning on the DB store)."""
        _client, post_challenge, post_assert = cli
        cid = post_challenge().json()["challenge_id"]
        caller["session_id"] = 22
        resp = post_assert(cid)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge session mismatch"
        assert session.query(ElevationToken).count() == 0
        assert _challenge_row(session, cid).state == "consumed"

    def test_same_session_assert_accepted(self, session, cli):
        """Positive retained: same user AND same session -> 200, and the
        minted token records the earning session (half 2)."""
        _client, post_challenge, post_assert = cli
        cid = post_challenge().json()["challenge_id"]
        resp = post_assert(cid)
        assert resp.status_code == 200
        tokens = session.query(ElevationToken).all()
        assert len(tokens) == 1
        assert tokens[0].session_id == 11

    def test_user_mismatch_shape_unchanged(self, session, cli, caller):
        """The pre-existing user gate keeps its order and detail (the new
        session gate must not convert user mismatch into session mismatch)."""
        _client, post_challenge, post_assert = cli
        cid = post_challenge().json()["challenge_id"]
        caller["user_id"] = "user2"  # same session, different user
        resp = post_assert(cid)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge user mismatch"


class TestNoSessionContextsInert:
    def test_context_without_sessions_gate_inert(self, session, cli, caller):
        """mTLS/admin contexts: no session_id on the caller -> the stored
        binding is NULL and the comparison is None == None, gate inert."""
        del caller["session_id"]
        _client, post_challenge, post_assert = cli
        cid = post_challenge().json()["challenge_id"]
        assert _challenge_row(session, cid).session_id is None
        resp = post_assert(cid)
        assert resp.status_code == 200
        tokens = session.query(ElevationToken).all()
        assert len(tokens) == 1
        assert tokens[0].session_id is None


class TestBrowserPlaneBinding:
    def test_browser_plane_stores_and_binds(self, session):
        """Cookie plane challenge stores the binding in the DB (row with the
        cookie session), and a completed assert mints a token carrying that
        session_id — the revoke path needs it."""
        ns = SimpleNamespace(id=77, user_id="user1")
        app = FastAPI()
        app.state.fido2_manager = MagicMock()
        n = count()
        app.state.fido2_manager.start_authentication.side_effect = lambda user_id=None: (
            f"bcid-{next(n)}",
            {"challenge": "chal"},
        )
        app.include_router(auth_browser_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)
        resolver = lambda request: (session, ns, {"user_id": "user1"})
        with patch("server.routes.auth_browser._get_session_from_cookie", side_effect=resolver):
            cid = client.post("/api/v1/auth/elevate/browser/challenge").json()["challenge_id"]
            row = _challenge_row(session, cid)
            assert row is not None
            assert row.session_id == 77
            assert row.user_id == "user1"
            with (
                patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}),
                patch("core.iam.role_manager.RoleManager") as mock_rm,
            ):
                mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
                resp = client.post(
                    "/api/v1/auth/elevate/browser/assert",
                    json={"challenge_id": cid, "response": {"id": "dGVzdA==", "response": {}}},
                )
        assert resp.status_code == 200
        tokens = session.query(ElevationToken).all()
        assert len(tokens) == 1
        assert tokens[0].session_id == 77

    def test_legacy_unbound_row_still_consumable_by_owner(self, session):
        """Back-compat pin: a pre-#527 style row (NULL session) claimed by a
        caller with NO session context still passes — migration of old
        pending ceremonies is not a refusal."""
        session.add(
            ElevationChallenge(
                challenge_id="legacy-cid",
                user_id="user1",
                session_id=None,
                state="created",
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL),
            )
        )
        session.commit()
        app = FastAPI()
        app.state.fido2_manager = MagicMock()
        app.include_router(auth_elevation_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "user1"}
        app.dependency_overrides[get_db] = lambda: session
        client = TestClient(app, raise_server_exceptions=False)
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as mock_rm,
        ):
            mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
            resp = client.post(
                "/api/v1/auth/elevate/assert",
                json={"challenge_id": "legacy-cid", "response": {"id": "dGVzdA=="}},
            )
        assert resp.status_code == 200
