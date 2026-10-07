# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#520 admin-display-name-width-500 — display_name bound against String(128).

``User.display_name`` is ``String(128)`` (core/iam/models.py:49) but the two
admin request models that write it — ``AdminCreateUserRequest`` (writer:
``admin_create_user``, POST /admin/users) and ``AdminConfigureUserRequest``
(writer: ``admin_configure_user``, PUT /admin/users/{user_id}) — carried no
``max_length``. An over-width value reached psycopg and surfaced as a 500
instead of a 422 — the #334 posture class, ceremony-free route, hence LOW.
Fix: ``max_length=128`` on both models (the sibling bounded-field idiom:
credentials.label, executor_id, revocation reason).

Truth table (paired-negative law):
  129 chars -> 422, field named, NO row written/changed (both routes)  RED at HEAD.
  128 chars -> accepted (at-limit).
  absent/None -> still accepted (the field stays optional).
"""

from pathlib import Path

import pytest
from core.iam.models import (
    Base,
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
COL_WIDTH = 128  # String(128) — core/iam/models.py:49


def _build_app(tmp_path: Path):
    """Real SQLite app (admin routes only) seeded with two usable admins —
    rejects must show the row UNTOUCHED, which mocks cannot prove
    (test_admin_string_validation.py harness, reused)."""
    db_path = tmp_path / "displaywidth.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    s = SessionLocal()
    s.add(User(user_id="alice", status="active", auth_mode="security-key", display_name="Alice"))
    s.add(User(user_id="bob", status="active", auth_mode="security-key", display_name="Bob"))
    role = Role(name="admin", permissions="read-write")
    s.add(role)
    s.flush()
    s.add(RoleMember(user_id="alice", role_id=role.id))
    s.add(RoleMember(user_id="bob", role_id=role.id))
    s.commit()
    s.close()

    app = FastAPI()
    app.include_router(admin_routes.router, prefix="/api/v1")
    # Same sanitized-422 handler production wires: the default FastAPI 422
    # echoes the rejected input into the response body.
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


class TestDisplayNameWidth520:
    def test_create_over_width_422_no_row(self, tmp_path):
        """AC1 (RED at HEAD): 129-char display_name on create-user -> 422
        naming the field; NO user row written, and no DB-layer error
        surfaced (that was the 500)."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/users", json={"username": "carol", "display_name": "x" * (COL_WIDTH + 1)})
        assert resp.status_code == 422, resp.text
        assert "display_name" in resp.text
        text = resp.text.lower()
        assert "psycopg" not in text and "sqlalchemy" not in text and "constraint" not in text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="carol").first() is None

    def test_configure_over_width_422_row_unchanged(self, tmp_path):
        """AC1 paired negative on the SECOND writer site
        (AdminConfigureUserRequest): 129 chars -> 422, the incumbent row
        keeps its old display_name."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.put("/api/v1/admin/users/alice", json={"display_name": "y" * (COL_WIDTH + 1)})
        assert resp.status_code == 422, resp.text
        assert "display_name" in resp.text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().display_name == "Alice"

    def test_create_at_limit_accepted(self, tmp_path):
        """AC3 paired positive: exactly 128 chars creates the user with the
        value stored."""
        client, SessionLocal = _build_app(tmp_path)
        name = "n" * COL_WIDTH
        resp = client.post("/api/v1/admin/users", json={"username": "dave", "display_name": name})
        assert resp.status_code in (200, 201), resp.text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="dave").one().display_name == name

    def test_configure_at_limit_accepted(self, tmp_path):
        client, SessionLocal = _build_app(tmp_path)
        name = "m" * COL_WIDTH
        resp = client.put("/api/v1/admin/users/alice", json={"display_name": name})
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().display_name == name

    def test_absent_and_none_still_accepted(self, tmp_path):
        """The bound must not make the optional field mandatory. Note the
        pre-existing configure-route semantics pinned here too: ``display_name:
        null`` is a no-op (the writer treats None as 'not supplied' — clearing
        a set display_name is not exposed on this model and is out of #520
        scope)."""
        client, SessionLocal = _build_app(tmp_path)
        resp = client.post("/api/v1/admin/users", json={"username": "eve"})
        assert resp.status_code in (200, 201), resp.text
        resp = client.post("/api/v1/admin/users", json={"username": "frank", "display_name": None})
        assert resp.status_code in (200, 201), resp.text
        resp = client.put("/api/v1/admin/users/alice", json={"display_name": None})
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(User).filter_by(user_id="alice").one().display_name == "Alice"

    def test_model_level_bounds_create_request(self):
        """Direct model cell: AdminCreateUserRequest carries the bound — a
        refactor that drops it fails here even if route tests are rewritten.
        128 ok / 129 ValidationError."""
        ok = admin_routes.AdminCreateUserRequest(username="alice", display_name="n" * COL_WIDTH)
        assert len(ok.display_name) == COL_WIDTH
        with pytest.raises(ValidationError):
            admin_routes.AdminCreateUserRequest(username="alice", display_name="n" * (COL_WIDTH + 1))

    def test_model_level_bounds_configure_request(self):
        """Second writer model, same pin."""
        ok = admin_routes.AdminConfigureUserRequest(display_name="m" * COL_WIDTH)
        assert len(ok.display_name) == COL_WIDTH
        with pytest.raises(ValidationError):
            admin_routes.AdminConfigureUserRequest(display_name="m" * (COL_WIDTH + 1))


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
