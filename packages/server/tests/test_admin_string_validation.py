# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Admin-plane string validation (ticket admin-plane-string-validation #356):
status/auth_mode/preset become Literal enums enumerated from source; user_id
becomes a bounded pattern mirroring the alembic-009 CHECK on users.user_id
(String(64), lowercase alnum + hyphen, 2-64); display_name/label get bounded
pattern fields with the #334 strict-UTF-8 posture (lone surrogates rejected
pre-commit — 422, never a psycopg 500 after side effects).

Truth table: every accept has its paired reject, and every reject pins that
the handler never ran (no DB mutation, no DB error surfaced).
"""

import pytest
from core.iam.models import (
    Base,
    CommandPolicy,
    Role,
    RoleMember,
    User,
)
from fastapi import FastAPI
from pydantic import ValidationError
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

ADMIN = {"user_id": "admin-1"}


def _build_app(tmp_path):
    """Real SQLite app (admin routes only) seeded with one active user —
    rejects must show the row UNTOUCHED, which mocks cannot prove."""
    db_path = tmp_path / "adminval.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    s = SessionLocal()
    s.add(User(user_id="alice", status="active", auth_mode="security-key", display_name="Alice"))
    role = Role(name="admin", permissions="read-write")
    s.add(role)
    s.flush()
    s.add(RoleMember(user_id="alice", role_id=role.id))
    s.commit()
    s.close()

    app = FastAPI()
    app.include_router(admin_routes.router, prefix="/api/v1")
    # Same sanitized-422 handler production wires (test_execution_relay.py
    # pattern): the default FastAPI 422 echoes the rejected surrogate into
    # the response body and dies encoding it — bare-500, message lost.
    from fastapi.exceptions import RequestValidationError
    from server.app import _validation_error_handler

    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[require_admin] = lambda: ADMIN

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    from server.dependencies import get_db

    app.dependency_overrides[get_db] = _db
    return TestClient(app, raise_server_exceptions=False), SessionLocal


class TestStatusAuthModeLiteral:
    def test_configure_valid_status_passes(self, tmp_path):
        client, SessionLocal = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"status": "disabled"})
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().status == "disabled"

    def test_configure_invalid_status_422_no_write(self, tmp_path):
        """Paired negative (the headline class): status='pwned' must be a
        loud 422 — never a silently stored junk value that breaks the
        auth gate (session_manager is_active checks == 'active')."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"status": "pwned"})
        assert resp.status_code == 422
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().status == "active"

    def test_configure_invalid_auth_mode_422_no_write(self, tmp_path):
        client, SessionLocal = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"auth_mode": "quantum"})
        assert resp.status_code == 422
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().auth_mode == "security-key"

    @pytest.mark.parametrize("mode", ["security-key", "webauthn"])
    def test_configure_documented_modes_pass(self, tmp_path, mode):
        client, _ = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"auth_mode": mode})
        assert resp.status_code == 200, resp.text

    def test_configure_mtls_mode_rejected_422(self, tmp_path):
        """'mtls' exists in source (executors.py) but ONLY as a daemon-set
        value written directly on the registration path — never via the
        admin plane. Exposing it here would let an admin flip a human row
        to a mode whose auth requires a forged cert header; the ruling
        enumerates from source = the admin-plane writers (security-key,
        webauthn)."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"auth_mode": "mtls"})
        assert resp.status_code == 422
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().auth_mode == "security-key"

    def test_enroll_invalid_auth_mode_422(self, tmp_path):
        client, SessionLocal = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/enroll", json={"user_id": "bob-1", "auth_mode": "telepathy"})
        assert resp.status_code == 422
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="bob-1").first() is None


class TestUserIdBounded:
    def test_enroll_junk_user_id_422_pre_db(self, tmp_path):
        """RULING-INPUT paired cell: junk user_id -> 422 with NO DB error
        surfaced (pre-fix: passed validation, died inside the transaction
        on the alembic-009 CHECK — 500 class)."""
        client, _ = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/enroll", json={"user_id": "Bad User!"})
        assert resp.status_code == 422
        text = resp.text.lower()
        assert "psycopg" not in text and "constraint" not in text and "sqlalchemy" not in text

    def test_enroll_surrogate_user_id_422(self, tmp_path):
        client, _ = _build_app(tmp_path)
        # Raw JSON with the escaped surrogate: what a real client sends over
        # the wire (json.dumps ensure_ascii keeps it as \ud800; the server's
        # json.loads yields the lone surrogate Python str that reaches the
        # model). httpx cannot serialize a raw surrogate, hence the content=
        # body here.
        resp = client.post(
            "/api/v1/admin/enroll",
            content=b'{"user_id": "x\\ud800y"}',
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_configure_path_junk_user_id_422_not_404_or_500(self, tmp_path):
        client, _ = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/Bad%20User%21", json={"status": "active"})
        assert resp.status_code == 422

    def test_remove_path_junk_user_id_422(self, tmp_path):
        client, _ = _build_app(tmp_path)
        resp = client.request("DELETE", "/api/v1/admin/users/UNDER_SCORE", json=None)
        assert resp.status_code == 422

    def test_valid_user_id_passes(self, tmp_path):
        client, _ = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/enroll", json={"user_id": "bob-1"})
        assert resp.status_code in (200, 201), resp.text


class TestPresetLiteral:
    @pytest.mark.parametrize("preset", ["strict", "balanced", "permissive"])
    def test_documented_presets_pass(self, tmp_path, preset):
        client, SessionLocal = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/command-policy", json={"preset": preset})
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(CommandPolicy).filter_by(policy_name="default").one().preset == preset

    def test_invalid_preset_422_policy_untouched(self, tmp_path):
        """Paired negative — this value propagates FLEET-WIDE via the
        command-policy wire (executors.py); 'yolo' must never reach the row."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/command-policy", json={"preset": "yolo"})
        assert resp.status_code == 422
        with SessionLocal() as s:
            assert s.query(CommandPolicy).filter_by(policy_name="default").first() is None


class TestLabelBounded:
    """The ruling names the bounded field 'label' — the only admin/credential
    field literally so named is credentials.label (models.py:511 String(64)).
    Model-level paired cells: <=64 strict-UTF-8 accepted, 65 and a lone
    surrogate rejected at validation (pre-DB, #334 posture B reusable)."""

    def test_credential_label_bounds(self):
        from server.routes.credentials import CredentialAddStartRequest

        ok = CredentialAddStartRequest(label="Backup key")
        assert ok.label == "Backup key"
        assert len(CredentialAddStartRequest(label="x" * 64).label) == 64
        with pytest.raises(ValidationError):
            CredentialAddStartRequest(label="x" * 65)
        with pytest.raises(ValidationError):
            CredentialAddStartRequest(label="ok\ud800tail")
