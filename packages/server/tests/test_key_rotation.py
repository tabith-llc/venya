# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Key rotation option-2 contract — real SQLite end-to-end, zero DB mocks.

Ticket key-rotation-worker-missing (ruled 2026-09-17): rotate is a
synchronous label-boundary rotation (single KEK, no secret re-wrap), the job
row is terminal on return, rollback is a real flip-back of the active
version, and the at-most-one-active invariant lives in a partial unique
index (migration 028 — raced in the core suite). Replaces the mock-backed
rotate/rollback tests, which pinned the old 202/pending fiction and could
not observe DB state (mock-backed suites missed DB-semantics bugs three
times before — real-DB truth table per verification discipline).
"""

from unittest.mock import MagicMock

from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE, decrypt_secret, encrypt_secret
from core.iam.models import (
    Base,
    KeyRotationJob,
    KeyRotationSecret,
    KeyVersion,
    Role,
    RoleMember,
    Secret,
    User,
)
from fastapi import FastAPI
from server.dependencies import get_current_user, require_admin
from server.routes import admin as admin_routes
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user"}
NOTE = "no re-wrap: single-KEK alpha semantics"


def _build_app(tmp_path, seed_active_v1: bool = True, secret_count: int = 1):
    """Real Backend over SQLite (Backend._create_engine bypassed — it issues
    PostgreSQL-only SET pragmas; same injection pattern as test_secrets)."""
    db_path = tmp_path / "rotation.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    s = SessionLocal()
    if seed_active_v1:
        s.add(KeyVersion(version_label="v1", active=True, rotation_pending=False))
    s.add(User(user_id="test-user"))
    role = Role(name="dev", permissions="read-write")
    s.add(role)
    s.flush()
    s.add(RoleMember(user_id="test-user", role_id=role.id))
    for i in range(secret_count):
        wrapped_dek, nonce, ciphertext = encrypt_secret(kek, f"value-{i}".encode())
        s.add(
            Secret(
                key=f"sec-{i}",
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                key_version_id="v1",
                created_by="test-user",
            )
        )
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.state.backend = backend
    app.state.core = backend.get_core()
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER
    return TestClient(app, raise_server_exceptions=False), SessionLocal, kek


def _rotate(client) -> dict:
    resp = client.post("/api/v1/admin/key-versions/rotate", json={})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_rotate_completes_synchronously_and_flips_active(tmp_path):
    client, SessionLocal, _ = _build_app(tmp_path)
    data = _rotate(client)
    assert data["status"] == "completed"
    assert data["note"] == NOTE
    assert data["old_key_version_id"] == 1
    assert data["new_key_version_id"] == 2

    with SessionLocal() as s:
        actives = s.query(KeyVersion).filter(KeyVersion.active.is_(True)).all()
        assert len(actives) == 1
        assert actives[0].id == 2
        assert actives[0].version_label != "v1"
        assert actives[0].rotation_pending is False
        old = s.get(KeyVersion, 1)
        assert old.active is False

        job = s.get(KeyRotationJob, data["job_id"])
        assert job.status == "completed"
        assert job.total_secrets == 1
        assert job.completed_secrets == 0  # truthful: nothing is re-wrapped
        assert job.failed_count == 0
        assert job.started_at is not None and job.completed_at is not None
        assert job.old_key_version_id == 1 and job.new_key_version_id == 2
        # Bookkeeping rows for a worker that does not exist are no longer created:
        assert s.query(KeyRotationSecret).count() == 0


def test_new_active_observable_via_active_endpoint(tmp_path):
    """Acceptance: rotation produces a new ACTIVE version observable via
    GET /key-versions/active (the flag-free store's resolution path)."""
    client, SessionLocal, _ = _build_app(tmp_path)
    _rotate(client)
    with SessionLocal() as s:
        new_label = s.query(KeyVersion).filter(KeyVersion.active.is_(True)).one().version_label
    resp = client.get("/api/v1/key-versions/active")
    assert resp.status_code == 200, resp.text
    assert resp.json()["key_version_id"] == new_label


def test_old_secret_untouched_and_decryptable_after_rotate(tmp_path):
    """Rotation is a label boundary: existing secrets keep their stored
    label and their ciphertext still decrypts with the same KEK."""
    client, SessionLocal, kek = _build_app(tmp_path)
    _rotate(client)
    with SessionLocal() as s:
        secret = s.query(Secret).filter(Secret.key == "sec-0").one()
        assert secret.key_version_id == "v1"  # label NOT rewritten
        assert decrypt_secret(kek, secret.wrapped_dek, secret.nonce, secret.encrypted_value) == b"value-0"


def test_rotate_with_no_prior_active_creates_first(tmp_path):
    client, SessionLocal, _ = _build_app(tmp_path, seed_active_v1=False, secret_count=0)
    data = _rotate(client)
    assert data["status"] == "completed"
    assert data["old_key_version_id"] is None
    with SessionLocal() as s:
        actives = s.query(KeyVersion).filter(KeyVersion.active.is_(True)).all()
        assert len(actives) == 1
        assert s.get(KeyRotationJob, data["job_id"]).total_secrets == 0


def test_rollback_flips_active_back(tmp_path):
    client, SessionLocal, _ = _build_app(tmp_path)
    data = _rotate(client)
    resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": data["job_id"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rolled_back"] is True
    assert body["job_id"] == data["job_id"]
    assert body["restored_secrets_count"] == 0  # truthful zero — nothing was re-wrapped

    with SessionLocal() as s:
        assert s.get(KeyVersion, 1).active is True  # old reactivated
        assert s.get(KeyVersion, 2).active is False  # new deactivated
        job = s.get(KeyRotationJob, data["job_id"])
        assert job.status == "rolled_back"
        assert job.rolled_back_at is not None


def test_rollback_by_id_route_same_semantics(tmp_path):
    client, SessionLocal, _ = _build_app(tmp_path)
    data = _rotate(client)
    resp = client.post(f"/api/v1/admin/key-rotation/{data['job_id']}/rollback")
    assert resp.status_code == 200, resp.text
    assert resp.json()["rolled_back"] is True
    with SessionLocal() as s:
        assert s.get(KeyVersion, 1).active is True
        assert s.get(KeyVersion, 2).active is False


def test_double_rollback_rejected_409(tmp_path):
    client, _, _ = _build_app(tmp_path)
    data = _rotate(client)
    first = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": data["job_id"]})
    assert first.status_code == 200
    second = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": data["job_id"]})
    assert second.status_code == 409
    assert "rolled_back" in second.json()["detail"]


def test_legacy_pending_job_rollback_rejected_409(tmp_path):
    """Negative: pre-fix 'pending' job rows are not roll-backable (nothing ran)."""
    client, SessionLocal, _ = _build_app(tmp_path)
    with SessionLocal() as s:
        s.add(KeyRotationJob(status="pending", total_secrets=0, completed_secrets=0, failed_count=0))
        s.commit()
        job_id = s.query(KeyRotationJob).one().id
    resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": job_id})
    assert resp.status_code == 409
    assert "pending" in resp.json()["detail"]


def test_rollback_not_latest_job_rejected_409(tmp_path):
    """Negative: rolling back under a newer rotation would silently undo it."""
    client, _, _ = _build_app(tmp_path)
    job1 = _rotate(client)["job_id"]
    job2 = _rotate(client)["job_id"]
    resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": job1})
    assert resp.status_code == 409
    assert str(job2) in resp.json()["detail"]
    # The latest job still rolls back cleanly:
    ok = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": job2})
    assert ok.status_code == 200


def test_rollback_missing_job_404(tmp_path):
    client, _, _ = _build_app(tmp_path)
    resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": 999})
    assert resp.status_code == 404
    resp2 = client.post("/api/v1/admin/key-rotation/999/rollback")
    assert resp2.status_code == 404


def test_rollback_first_rotation_rejected_409(tmp_path):
    """Negative: a rotation that created the FIRST version has no prior to
    reactivate — rolling it back would recreate the zero-active outage."""
    client, _, _ = _build_app(tmp_path, seed_active_v1=False, secret_count=0)
    data = _rotate(client)
    assert data["old_key_version_id"] is None
    resp = client.post("/api/v1/admin/key-versions/rollback", json={"job_id": data["job_id"]})
    assert resp.status_code == 409
    assert "first key version" in resp.json()["detail"]


def test_alias_route_same_contract(tmp_path):
    client, SessionLocal, _ = _build_app(tmp_path)
    resp = client.post("/api/v1/admin/key-rotation", json={})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "completed"
    assert data["note"] == NOTE
    with SessionLocal() as s:
        assert s.query(KeyVersion).filter(KeyVersion.active.is_(True)).count() == 1


def test_concurrent_rotate_integrity_maps_to_409():
    """Route-level paired negative: a lost DB race (IntegrityError from the
    partial unique index on commit) surfaces as 409 — never a 500, never a
    second active version. The race itself is proven in the core suite
    (test_migration_028_single_active.py::test_concurrent_active_inserts…)."""
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = MagicMock(id=1)
    db.query.return_value.filter.return_value.update.return_value = 1
    db.query.return_value.count.return_value = 0
    db.commit.side_effect = IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    backend = MagicMock()
    backend.get_session.return_value = db
    app = FastAPI()
    app.state.backend = backend
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/api/v1/admin/key-versions/rotate", json={})
    assert resp.status_code == 409
    assert "Concurrent rotation" in resp.json()["detail"]
