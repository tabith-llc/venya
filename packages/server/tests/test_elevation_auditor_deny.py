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

#528 moved the challenge store from app.state to the elevation_challenges
table, so these cells now run on real SQLite rows (house pattern:
test_admin_delete_dependencies_425.py): deny events are read back from the
DB, and the consume-on-deny pin (#345) is the row's state.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import AuditEvent, Base, ElevationChallenge, ElevationToken, User, WebAuthnCredential
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import auth_browser as auth_browser_routes
from server.routes import auth_elevation as auth_elevation_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

DENY_DETAIL = "insufficient role: auditor cannot elevate"
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


def _seed_challenge(session, cid="c1", user_id="user1", session_id=None):
    session.add(
        ElevationChallenge(
            challenge_id=cid,
            user_id=user_id,
            session_id=session_id,
            state="created",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL),
        )
    )
    session.commit()


def _deny_events(session):
    session.expire_all()
    return session.query(AuditEvent).filter(AuditEvent.event_type == "auditor_elevation_denied").all()


def _tokens(session):
    session.expire_all()
    return session.query(ElevationToken).all()


def _cli_client(session, caller):
    app = FastAPI()
    app.state.fido2_manager = MagicMock()
    app.include_router(auth_elevation_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: caller
    app.dependency_overrides[get_db] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def _assert_cli(client, tier_map):
    with (
        patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = tier_map
        return client.post(
            "/api/v1/auth/elevate/assert",
            json={"challenge_id": "c1", "response": {"id": "dGVzdA=="}},
        )


class TestElevateAssertAuditorDeny:
    def test_auditor_only_denied_403_no_token_issued(self, session):
        """Deny fires BEFORE token creation: NO ElevationToken row, exactly
        one value-free auditor_elevation_denied AuditEvent committed (owner
        ruling 2026-09-30), and the challenge row CONSUMED (#345 semantics
        on the DB store: the claim commits before the checks, so a denied
        ceremony never re-arms)."""
        _seed_challenge(session)
        client = _cli_client(session, {"user_id": "user1"})
        resp = _assert_cli(client, {1: "auditor"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
        assert _tokens(session) == []
        events = _deny_events(session)
        assert len(events) == 1
        assert events[0].user_id == "user1"
        assert "elevation_token" not in events[0].fields
        session.expire_all()
        assert session.query(ElevationChallenge).filter_by(challenge_id="c1").one().state == "consumed"

    def test_read_write_issue_passes(self, session):
        """Paired positive: read-write caller gets its token (unchanged)
        and zero deny events (N2 negative-half)."""
        _seed_challenge(session)
        client = _cli_client(session, {"user_id": "user1"})
        resp = _assert_cli(client, {1: "read-write"})
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        assert _deny_events(session) == []
        assert len(_tokens(session)) == 1

    def test_union_issue_passes(self, session):
        """1b union: auditor+read is not auditor-only — issuance passes,
        zero deny events."""
        _seed_challenge(session)
        client = _cli_client(session, {"user_id": "user1"})
        resp = _assert_cli(client, {1: "auditor", 2: "read"})
        assert resp.status_code == 200
        assert _deny_events(session) == []

    def test_non_member_issue_passes(self, session):
        """Empty membership map passes the ISSUANCE gate (helper is False;
        issuance refusal is diagnostics-only per 1c-ii — nothing here grants
        or denies value access, and value paths are read-gated elsewhere)."""
        _seed_challenge(session)
        client = _cli_client(session, {"user_id": "user1"})
        resp = _assert_cli(client, {})
        assert resp.status_code == 200


class _FlakyCommit:
    """Delegating session whose Nth commit raises — simulates the audit
    store blowing up AFTER the claim commit landed."""

    def __init__(self, real, fail_on):
        self._real = real
        self._fail_on = fail_on
        self._n = 0

    def commit(self):
        self._n += 1
        if self._n == self._fail_on:
            raise RuntimeError("audit store down")
        return self._real.commit()

    def __getattr__(self, name):
        return getattr(self._real, name)


def _assert_browser(client, resolver, tier_map):
    with (
        patch("server.routes.auth_browser._get_session_from_cookie", side_effect=resolver),
        patch("server.routes.auth_browser.browser_assertion_to_fido2", return_value={}),
        patch("core.iam.role_manager.RoleManager") as mock_rm,
    ):
        mock_rm.return_value.get_user_permissions.return_value = tier_map
        return client.post(
            "/api/v1/auth/elevate/browser/assert",
            json={"challenge_id": "c1", "response": {"id": "dGVzdA==", "response": {}}},
        )


class TestBrowserElevateAssertAuditorDeny:
    """Browser twin mirror (auth_browser.browser_elevate_assert) — the CLI
    deny alone would leave the browser elevation path issuing tokens to
    auditor-only callers."""

    def _resolver(self, session):
        ns = SimpleNamespace(id=77, user_id="user1")

        def _resolve(request):
            return session, ns, {"user_id": "user1"}

        return _resolve

    def test_auditor_only_denied_403_challenge_consumed(self, session):
        """Browser twin deny (P3): 403, one value-free auditor_elevation_
        denied event committed, no token row. #345 flipped this pin: the
        assert consumes the challenge up-front — the pre-fix "denied
        ceremony slot stays live" residue is exactly what the ruling
        retired; on the DB store the pin is the row's state."""
        _seed_challenge(session, session_id=77)
        client = TestClient(self._app(), raise_server_exceptions=False)
        resp = _assert_browser(client, self._resolver(session), {1: "auditor"})
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
        assert _tokens(session) == []
        events = _deny_events(session)
        assert len(events) == 1
        assert events[0].user_id == "user1"
        assert "elevation_token" not in events[0].fields
        session.expire_all()
        assert session.query(ElevationChallenge).filter_by(challenge_id="c1").one().state == "consumed"

    def _app(self):
        app = FastAPI()
        app.state.fido2_manager = MagicMock()
        app.include_router(auth_browser_routes.router, prefix="/api/v1")
        return app

    def test_read_write_issue_passes(self, session):
        _seed_challenge(session, session_id=77)
        client = TestClient(self._app(), raise_server_exceptions=False)
        resp = _assert_browser(client, self._resolver(session), {1: "read-write"})
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        assert _deny_events(session) == []

    def test_union_issue_passes(self, session):
        _seed_challenge(session, session_id=77)
        client = TestClient(self._app(), raise_server_exceptions=False)
        resp = _assert_browser(client, self._resolver(session), {1: "auditor", 2: "read"})
        assert resp.status_code == 200
        assert _deny_events(session) == []

    def test_audit_write_failure_still_denies_403(self, session):
        """H1 twin: the AUDIT commit (2nd commit on the deny path — the
        claim committed first) blows up -> STILL a loud 403, never a 200
        and never a 500 (fail-closed guard; the denial is the security
        control, the log line is the loud side-effect). The claim stays
        consumed — it committed before the checks."""
        _seed_challenge(session, session_id=77)
        flaky = _FlakyCommit(session, fail_on=2)
        ns = SimpleNamespace(id=77, user_id="user1")
        client = TestClient(self._app(), raise_server_exceptions=False)
        resp = _assert_browser(
            client,
            lambda request: (flaky, ns, {"user_id": "user1"}),
            {1: "auditor"},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == DENY_DETAIL
