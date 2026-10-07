# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Elevation challenge state is process-portable (#528).

The defect: the pending ceremony's auth binding lived in
app.state._elevation_challenges — per uvicorn worker. Issue on one worker
and assert on another (or restart mid-ceremony) and the assert saw no
entry: 401 "Elevation challenge not found or expired".

These cells pin the fix from the OUTSIDE: each "worker" is its own engine
+ FastAPI app over the same SQLite file, so a challenge stored by A is
genuinely claimed by B through shared storage, not through a lucky
same-process global. Restart = dispose the engine, build a fresh one.

Truth-table pairs: cross-worker assert ACCEPTED / cross-worker SECOND
assert (already consumed) REFUSED with an audit row; unknown-ceremony
denial carries the uniform 401 and a value-free audit row (no challenge
id, no token material — AC2).
"""

import json
from datetime import UTC, datetime, timedelta
from itertools import count
from unittest.mock import MagicMock, patch

from core.iam.models import AuditEvent, Base, ElevationChallenge, ElevationToken, User, WebAuthnCredential
from fastapi import FastAPI
from server.dependencies import get_current_user, get_db
from server.routes import auth_elevation as auth_elevation_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient


class _Worker:
    """One 'worker' = its own engine/session factory + app over the file."""

    def __init__(self, db_path, caller):
        engine = create_engine(f"sqlite:///{db_path}")
        self.factory = sessionmaker(bind=engine)
        app = FastAPI()
        app.state.fido2_manager = MagicMock()
        n = count()
        app.state.fido2_manager.start_authentication.side_effect = lambda user_id=None: (
            f"cid-{next(n)}-{id(self)}",
            {"challenge": "chal"},
        )
        app.include_router(auth_elevation_routes.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: dict(caller)

        def _db():
            return self.factory()

        app.dependency_overrides[get_db] = _db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.app = app

    def challenge(self):
        resp = self.client.post("/api/v1/auth/elevate/challenge")
        assert resp.status_code == 200
        return resp.json()["challenge_id"]

    def assert_cid(self, cid):
        with (
            patch("server.routes.auth_elevation.browser_assertion_to_fido2", return_value={}),
            patch("core.iam.role_manager.RoleManager") as mock_rm,
        ):
            mock_rm.return_value.get_user_permissions.return_value = {1: "read-write"}
            return self.client.post(
                "/api/v1/auth/elevate/assert",
                json={"challenge_id": cid, "response": {"id": "dGVzdA=="}},
            )


def _seed(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(User(user_id="user1", status="active"))
    s.add(WebAuthnCredential(user_id="user1", credential_id=b"k1", public_key=b"p1", sign_count=0))
    s.commit()
    s.close()
    engine.dispose()


CALLER = {"user_id": "user1", "session_id": 11}


def _fields(event):
    """AuditEvent.fields serializes dicts to JSON text at the column."""
    return json.loads(event.fields) if isinstance(event.fields, str) else event.fields


def _read_rows(db_path, model):
    engine = create_engine(f"sqlite:///{db_path}")
    s = sessionmaker(bind=engine)()
    try:
        return s.query(model).all()
    finally:
        s.close()
        engine.dispose()


class TestCrossProcessCeremony:
    def test_challenge_issued_on_one_worker_asserts_on_another(self, tmp_path):
        """AC1(#528): the ceremony survives the worker hop — the binding
        lives in the DB, and the assert's claim reads it from shared
        storage. At HEAD (dict store) the second client had no entry and
        the whole test file REDs."""
        db = tmp_path / "venya.db"
        _seed(db)
        worker_a = _Worker(db, CALLER)
        cid = worker_a.challenge()
        worker_b = _Worker(db, CALLER)
        resp = worker_b.assert_cid(cid)
        assert resp.status_code == 200
        assert resp.json()["elevation_token"]
        rows = _read_rows(db, ElevationChallenge)
        assert [r.state for r in rows if r.challenge_id == cid] == ["consumed"]
        tokens = _read_rows(db, ElevationToken)
        assert len(tokens) == 1
        assert tokens[0].session_id == 11

    def test_restart_mid_ceremony_is_assertable(self, tmp_path):
        """Restart variant: same file, brand-new engine after the issue —
        the pre-fix dict died with the process; the row does not."""
        db = tmp_path / "venya.db"
        _seed(db)
        worker_a = _Worker(db, CALLER)
        cid = worker_a.challenge()
        del worker_a  # "process exits"
        worker_c = _Worker(db, CALLER)
        assert worker_c.assert_cid(cid).status_code == 200

    def test_second_worker_cannot_reconsume(self, tmp_path):
        """PAIRED NEGATIVE: single-consume holds ACROSS processes — the
        already-consumed row funds exactly one token; the third worker's
        assert gets the uniform 401 plus the denial audit row."""
        db = tmp_path / "venya.db"
        _seed(db)
        worker_a = _Worker(db, CALLER)
        cid = worker_a.challenge()
        assert _Worker(db, CALLER).assert_cid(cid).status_code == 200
        resp = _Worker(db, CALLER).assert_cid(cid)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge not found or expired"
        assert len(_read_rows(db, ElevationToken)) == 1
        denials = [e for e in _read_rows(db, AuditEvent) if e.event_type == "elevation_challenge_denied"]
        assert len(denials) == 1


class TestDenialAuditRow:
    def test_unknown_ceremony_denied_with_value_free_audit(self, tmp_path):
        """AC2(#528): a claim that finds nothing fails closed with the
        uniform 401 AND an audit row. Value-free by construction: the row
        carries outcome/reason/user_id/endpoint only — never the challenge
        id, never token material."""
        db = tmp_path / "venya.db"
        _seed(db)
        worker = _Worker(db, CALLER)
        resp = worker.assert_cid("cid-never-issued")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Elevation challenge not found or expired"
        denials = [e for e in _read_rows(db, AuditEvent) if e.event_type == "elevation_challenge_denied"]
        assert len(denials) == 1
        event = denials[0]
        assert event.user_id == "user1"
        blob = str(event.fields)
        assert "cid-never-issued" not in blob
        assert set(_fields(event)) == {"outcome", "reason", "user_id", "endpoint"}

    def test_expired_ceremony_denial_also_audited(self, tmp_path):
        """The expired half of 'not found or expired' takes the same path:
        row present but outlived its window -> uniform 401 + audit row, and
        the row is NOT flipped to consumed by the failed claim (the atomic
        UPDATE's guard matched zero rows)."""
        db = tmp_path / "venya.db"
        _seed(db)
        engine = create_engine(f"sqlite:///{db}")
        s = sessionmaker(bind=engine)()
        past = datetime.now(UTC) - timedelta(seconds=400)
        s.add(
            ElevationChallenge(
                challenge_id="cid-dead",
                user_id="user1",
                session_id=11,
                state="created",
                created_at=past,
                expires_at=past + timedelta(seconds=300),
            )
        )
        s.commit()
        s.close()
        engine.dispose()
        worker = _Worker(db, CALLER)
        assert worker.assert_cid("cid-dead").status_code == 401
        rows = _read_rows(db, ElevationChallenge)
        assert [r.state for r in rows if r.challenge_id == "cid-dead"] == ["created"]
        denials = [e for e in _read_rows(db, AuditEvent) if e.event_type == "elevation_challenge_denied"]
        assert len(denials) == 1
