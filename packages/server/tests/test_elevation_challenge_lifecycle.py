# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Elevation-challenge lifecycle (tickets browser-elevation-challenge-
unbounded #345 + #528).

#345 ruled the semantics: created_at on store, stale pruning on touch, and
CONSUME-ON-ALL-PATHS — an abandoned ceremony, a WebAuthn-error assert, or a
denied assert never leaves a live challenge. #528 moved the store from the
per-process app.state dict to the elevation_challenges table; the pins
survive the move, now proven on rows: the claim is an atomic state flip
(single-consume), expired rows are pruned at the next challenge, and every
refusal path leaves the row consumed.

Truth-table pairs: stale row pruned / fresh row claimable; first claim
consumes / second claim refused; error path consumes / success path
consumes exactly once.
"""

from datetime import UTC, datetime, timedelta
from itertools import count
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import Base, ElevationChallenge, ElevationToken, User, WebAuthnCredential
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.fido2.manager import WebAuthnError
from server.routes import auth_elevation as auth_elevation_routes
from server.routes.auth_elevation import ELEVATION_TOKEN_TTL_SECONDS
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

TTL_WINDOW = ELEVATION_TOKEN_TTL_SECONDS * 5


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
    """Mutable caller context — flip session_id mid-test to prove the gate."""
    return {"user_id": "user1", "session_id": 11}


@pytest.fixture()
def client(session, caller):
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
    return TestClient(app, raise_server_exceptions=False), app


def _post_challenge(client):
    return client.post("/api/v1/auth/elevate/challenge")


def _post_assert(client, cid):
    with (
        patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
        return client.post(
            "/api/v1/auth/elevate/assert",
            json={"challenge_id": cid, "response": {"id": "dGVzdA=="}},
        )


def _row(session, cid):
    session.expire_all()
    return session.query(ElevationChallenge).filter(ElevationChallenge.challenge_id == cid).first()


class TestStoreOnChallenge:
    def test_challenge_stores_db_row(self, client, session):
        """AC6(#528): binding persists in the DB, not app.state — the row
        carries user, session, and a TTL-window life."""
        c, _app = client
        resp = _post_challenge(c)
        assert resp.status_code == 200
        cid = resp.json()["challenge_id"]
        row = _row(session, cid)
        assert row is not None
        assert row.state == "created"
        assert row.user_id == "user1"
        assert row.session_id == 11
        assert row.expires_at >= row.created_at  # window set at store

    def test_no_per_process_dict_is_created(self, client):
        """#528: the app.state store is gone — routes must not lazily
        re-create _elevation_challenges."""
        c, app = client
        _post_challenge(c)
        assert not hasattr(app.state, "_elevation_challenges")

    def test_expired_rows_pruned_on_next_challenge(self, client, session):
        """Stale-sweep twin (#345): an abandoned ceremony dies at the next
        touch; a fresh row is left alone."""
        past = datetime.now(UTC) - timedelta(seconds=TTL_WINDOW + 60)
        session.add(
            ElevationChallenge(
                challenge_id="cid-stale",
                user_id="user1",
                session_id=11,
                state="created",
                created_at=past,
                expires_at=past + timedelta(seconds=TTL_WINDOW),
            )
        )
        session.add(
            ElevationChallenge(
                challenge_id="cid-live",
                user_id="user1",
                session_id=11,
                state="created",
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(seconds=TTL_WINDOW),
            )
        )
        session.commit()
        c, _app = client
        assert _post_challenge(c).status_code == 200
        assert _row(session, "cid-stale") is None
        assert _row(session, "cid-live") is not None


class TestClaimSemantics:
    def test_unknown_challenge_denied_401(self, client):
        c, _app = client
        resp = _post_assert(c, "cid-never-issued")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge not found or expired"

    def test_expired_challenge_denied_401(self, client, session):
        """PAIRED negative: row exists but outlived its window -> the claim's
        expires_at guard refuses it (not a silent pass)."""
        past = datetime.now(UTC) - timedelta(seconds=TTL_WINDOW + 60)
        session.add(
            ElevationChallenge(
                challenge_id="cid-expired",
                user_id="user1",
                session_id=11,
                state="created",
                created_at=past,
                expires_at=past + timedelta(seconds=TTL_WINDOW),
            )
        )
        session.commit()
        c, _app = client
        resp = _post_assert(c, "cid-expired")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge not found or expired"

    def test_success_consumes_row_and_issues_token(self, client, session):
        c, _app = client
        cid = _post_challenge(c).json()["challenge_id"]
        resp = _post_assert(c, cid)
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        assert _row(session, cid).state == "consumed"
        assert session.query(ElevationToken).count() == 1

    def test_second_claim_refused_single_consume(self, client, session):
        """AC4(#528): the same challenge cannot fund two tokens — the claim
        is atomic, the second assert sees state != created."""
        c, _app = client
        cid = _post_challenge(c).json()["challenge_id"]
        assert _post_assert(c, cid).status_code == 200
        resp2 = _post_assert(c, cid)
        assert resp2.status_code == 401
        assert resp2.json()["detail"] == "Elevation challenge not found or expired"
        assert session.query(ElevationToken).count() == 1

    def test_webauthn_error_consumes(self, client, session):
        """Pop-up-front meaning survives the DB move: a WebAuthn-error
        assert consumes the row — the failed ceremony does not re-arm."""
        c, app = client
        cid = _post_challenge(c).json()["challenge_id"]
        app.state.fido2_manager.finish_authentication.side_effect = WebAuthnError("bad assertion")
        resp = _post_assert(c, cid)
        assert resp.status_code == 401
        assert _row(session, cid).state == "consumed"
        assert session.query(ElevationToken).count() == 0

    def test_session_mismatch_consumes(self, client, session, caller):
        """#527 ruling on the DB store: refusal consumes the claim
        (committed before the checks) — the other session cannot simply
        retry with the same challenge, and no token is minted."""
        c, _app = client
        cid = _post_challenge(c).json()["challenge_id"]
        caller["session_id"] = 22
        resp = _post_assert(c, cid)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge session mismatch"
        assert _row(session, cid).state == "consumed"
        assert session.query(ElevationToken).count() == 0
