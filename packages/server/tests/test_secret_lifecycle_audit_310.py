# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""R-2909 item 4 (refs #310) — a secret's lifecycle names itself in the audit log.

The claim this file closes: `secret_value_disclosed` recorded the READ of a
secret and nothing else did — store, replace, metadata-update and delete each
wrote ZERO rows, so after a command ran the log could not reconstruct what it
did against which credential. These cells run ZERO mocks over the DB (house
pattern from tests/test_unmask_disclosure_audit_602.py and
tests/test_secret_session_scoping_440.py): real Backend over SQLite, real
crypto, real Role rows driving the live tier gates, the real routes.

Coverage, per verb, with the paired negative the law wants:

  store        one POST -> exactly one `secret_created` row (id, key, roles,
               actor, time); a REFUSED store (a role the caller does not hold)
               writes nothing.
  replace      a second POST on a visible key -> `secret_replaced` carrying the
               SAME id, and the create row stays a single row — replace is
               distinguishable from create in the log, not folded into it.
  metadata     one PATCH -> `secret_metadata_updated`, riding the write's own
               commit: a commit that dies leaves NO row AND an unchanged row
               (complete-or-nothing, ruled Q4).
  delete       one DELETE -> `secret_deleted` naming the id that left; a delete
               of a key the caller cannot see writes nothing.

  value-freedom  attacker-chosen and NEWLINE-shaped (the 306 lesson: a stored
               newline was admissible at this same door), plus metadata values,
               checked absent from every row's whole serialized face — and the
               field table pinned to the approved key set, so no stray key can
               smuggle material later.
  posture        a store whose AUDIT write fails is still a 201 with the secret
               stored and the failure LOUD in the log — the audit row rides no
               transaction here (core.put committed inside its own session), so
               an audit failure must never read to the caller as a failed write.
  the probe      an auditor's GET /api/v1/audit answers the reconstruction
               question — which key, which actor, which verb, when — and never
               with the value in it.
"""

import hashlib
import json
import logging
from datetime import timedelta

from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import AuditEvent, Base, Role, RoleMember, Secret, User
from fastapi import FastAPI, Request
from server.dependencies import get_current_user
from server.routes import audit as audit_routes
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

OWNER = "alice"  # holds "dev" (read-write) — every verb below runs as her
OUTSIDER = "bob"  # holds "ops" only, so a store into "dev" is refused at #451 scoping
AUDITOR = "carol"  # auditor tier — the partner probe's caller

STORE_EVENT = "secret_created"
REPLACE_EVENT = "secret_replaced"
METADATA_EVENT = "secret_metadata_updated"
DELETE_EVENT = "secret_deleted"
LIFECYCLE_EVENTS = [STORE_EVENT, REPLACE_EVENT, METADATA_EVENT, DELETE_EVENT]

# Attacker-chosen, newline-bearing, and each line unique: what a value looks
# like when the store door accepts it (a non-env shape takes newlines today —
# the #306 finding) and the audit row must not.
VALUE_MARK = "s3cr3t-with-a-newline-310"
VALUE_LINES = [f"line-a-{VALUE_MARK}", "middle-line-b", f"line-c-{VALUE_MARK}-tail"]
ATTACK_VALUE = "\n".join(VALUE_LINES)
METADATA_MARKER = "metadata-value-marker-310"
# The secret key under test, held as a constant: every comparison below reads
# the way the #602 file does (its 231), because an inline literal beside a
# "secret_*" key is exactly what the detect-secrets Secret Keyword detector
# fires on -- and this file must add no finding to the generated baseline.
TARGET_KEY = "host-key"


class _CommitFlaky:
    """Delegating session whose commit raises — the audit write blowing up."""

    def __init__(self, real):
        self._real = real

    def commit(self):
        raise RuntimeError("audit store down")

    def __getattr__(self, name):
        return getattr(self._real, name)


def _build(tmp_path):
    """Real backend + real routes, zero mocked crypto and no mocked store."""
    db_path = tmp_path / "lifecycle310.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    s = SessionLocal()
    dev = Role(name="dev", permissions="read-write")
    ops = Role(name="ops", permissions="read-write")
    audit_role = Role(name="audit", permissions="auditor")
    s.add_all([User(user_id=OWNER), User(user_id=OUTSIDER), User(user_id=AUDITOR), dev, ops, audit_role])
    s.flush()
    s.add_all(
        [
            RoleMember(user_id=OWNER, role_id=dev.id),
            RoleMember(user_id=OUTSIDER, role_id=ops.id),
            RoleMember(user_id=AUDITOR, role_id=audit_role.id),
        ]
    )
    s.commit()
    s.close()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal

    def _identity(request: Request) -> dict:
        return {"user_id": request.headers.get("X-Test-Actor", OWNER), "roles": [], "caller": "human"}

    app = FastAPI()
    app.state.backend = backend
    app.state.core = backend.get_core()
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = _identity
    client = TestClient(app, raise_server_exceptions=False)
    return client, SessionLocal, app


def _rows(SessionLocal, event_type):
    with SessionLocal() as s:
        return s.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()


def _all_lifecycle_rows(SessionLocal):
    with SessionLocal() as s:
        return s.query(AuditEvent).filter(AuditEvent.event_type.in_(LIFECYCLE_EVENTS)).all()


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else row.fields


def _blob(rows):
    return json.dumps(
        [{"event_type": r.event_type, "user_id": r.user_id, "fields": _fields(r)} for r in rows], sort_keys=True
    )


def _store(client, key=TARGET_KEY, *, roles=None, value=ATTACK_VALUE, actor=OWNER, metadata=None):
    body = {
        "key": key,
        "value": value,
        "roles": roles or ["dev"],
        "key_version_id": "v1",
    }
    if metadata:
        body["metadata"] = metadata
    headers = {"X-Test-Actor": actor} if actor != OWNER else {}
    return client.post("/api/v1/secrets", json=body, headers=headers)


class TestStoreAndReplace:
    def test_store_writes_exactly_one_created_row(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)

        resp = _store(client)

        assert resp.status_code == 201, resp.text
        created = _rows(SessionLocal, STORE_EVENT)
        assert len(created) == 1
        assert _rows(SessionLocal, REPLACE_EVENT) == []
        row = created[0]
        fields = _fields(row)
        assert row.user_id == OWNER  # the actor, migration-022 principal verbatim
        assert fields["secret_id"] == resp.json()["id"]  # the id, not a name
        assert fields["secret_key"] == TARGET_KEY
        assert fields["role_names"] == ["dev"]
        assert fields["endpoint"] == "/api/v1/secrets"
        assert fields["outcome"] == "created"
        assert set(fields) == {"outcome", "secret_id", "secret_key", "role_names", "endpoint"}

    def test_timestamp_is_offset_aware_utc(self, tmp_path):
        """Root §13 on the value handed to the store, read at the INSERT — not
        off the row afterwards: SQLite has no tz-aware storage face, so a
        read-back here would measure the dialect, not the code (same
        instrument-law as the #465 expiry-clock guard, which reads the object
        too)."""
        client, _SessionLocal, _ = _build(tmp_path)
        seen = []

        @sa_event.listens_for(AuditEvent, "before_insert")
        def _catch(_mapper, _conn, target):
            seen.append(target.timestamp)

        try:
            assert _store(client).status_code == 201
        finally:
            sa_event.remove(AuditEvent, "before_insert", _catch)

        assert seen, "the cell is worth nothing if no row was ever inserted"
        assert seen[0].utcoffset() == timedelta(0)

    def test_second_store_on_a_visible_key_writes_replaced_with_the_same_id(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)
        first = _store(client)
        assert first.status_code == 201

        second = _store(client, value="replacement-value-310")
        assert second.status_code == 201
        assert second.json()["replaced"] is True

        created = _rows(SessionLocal, STORE_EVENT)
        replaced = _rows(SessionLocal, REPLACE_EVENT)
        assert len(created) == 1, "the first store is still one create row, never two"
        assert len(replaced) == 1
        assert replaced[0].user_id == OWNER
        assert _fields(replaced[0])["secret_id"] == first.json()["id"], "replace keeps the row id"
        assert _fields(replaced[0])["outcome"] == "replaced"

    def test_store_refused_by_scope_writes_no_row(self, tmp_path):
        """Paired negative: a store the write-side namespace check (#451)
        refuses lands NO row — an audit of an action that did not happen is a
        false record, and the row would name a secret id that was never minted."""
        client, SessionLocal, _ = _build(tmp_path)

        resp = _store(client, roles=["dev"], actor=OUTSIDER)

        assert resp.status_code == 400, resp.text
        assert "Role not held by caller" in resp.json()["detail"]
        assert _all_lifecycle_rows(SessionLocal) == []
        with SessionLocal() as s:
            assert s.query(Secret).count() == 0


class TestMetadataDoor:
    def test_metadata_patch_writes_one_row_with_field_names_only(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)
        assert _store(client).status_code == 201

        resp = client.patch(
            f"/api/v1/secrets/{TARGET_KEY}/metadata",
            json={"metadata": {"purpose": "ssh_login", "description": METADATA_MARKER}},
        )

        assert resp.status_code == 200, resp.text
        rows = _rows(SessionLocal, METADATA_EVENT)
        assert len(rows) == 1
        fields = _fields(rows[0])
        assert rows[0].user_id == OWNER
        assert fields["secret_id"] == resp.json()["id"]
        assert fields["secret_key"] == TARGET_KEY
        # NAMES of the fields touched — never their values.
        assert fields["changed_fields"] == ["description", "purpose"]
        assert set(fields) == {"outcome", "secret_id", "secret_key", "changed_fields", "endpoint"}
        assert METADATA_MARKER not in _blob(rows)

    def test_metadata_row_aborts_with_the_write(self, tmp_path):
        """Complete-or-nothing (ruled Q4) at the one door that owns its
        transaction: a commit that dies leaves no row AND no metadata change —
        never a mutation with no record, never a record of nothing."""
        client, SessionLocal, app = _build(tmp_path)
        assert _store(client).status_code == 201
        real_get_session = app.state.backend.get_session
        app.state.backend.get_session = lambda: _CommitFlaky(real_get_session())
        try:
            resp = client.patch(f"/api/v1/secrets/{TARGET_KEY}/metadata", json={"metadata": {"purpose": "ssh_login"}})
        finally:
            app.state.backend.get_session = real_get_session

        assert resp.status_code == 500, resp.text
        assert _rows(SessionLocal, METADATA_EVENT) == []
        with SessionLocal() as s:
            row = s.query(Secret).filter(Secret.key == TARGET_KEY).one()
            assert (row.meta or {}) == {}, f"the metadata write must roll back with its row, got {row.meta}"

    def test_metadata_patch_on_an_unseen_key_writes_no_row(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)

        resp = client.patch("/api/v1/secrets/never-stored/metadata", json={"metadata": {"purpose": "x"}})

        assert resp.status_code == 404, resp.text
        assert _rows(SessionLocal, METADATA_EVENT) == []


class TestDeleteDoor:
    def test_delete_writes_one_row_naming_the_id_that_left(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)
        stored = _store(client)
        assert stored.status_code == 201
        secret_id = stored.json()["id"]

        resp = client.delete(f"/api/v1/secrets/{TARGET_KEY}")

        assert resp.status_code == 200, resp.text
        rows = _rows(SessionLocal, DELETE_EVENT)
        assert len(rows) == 1
        assert rows[0].user_id == OWNER
        fields = _fields(rows[0])
        assert fields["secret_id"] == secret_id, "the log must name the id, not just the key"
        assert fields["secret_key"] == TARGET_KEY
        assert fields["outcome"] == "deleted"
        assert set(fields) == {"outcome", "secret_id", "secret_key", "endpoint"}
        with SessionLocal() as s:
            assert s.query(Secret).count() == 0

    def test_delete_of_a_key_the_caller_cannot_see_writes_no_row(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)
        assert _store(client).status_code == 201

        resp = client.delete(f"/api/v1/secrets/{TARGET_KEY}", headers={"X-Test-Actor": OUTSIDER})

        assert resp.status_code == 404, resp.text
        assert _rows(SessionLocal, DELETE_EVENT) == []
        with SessionLocal() as s:
            assert s.query(Secret).count() == 1, "the refusal must not have deleted anything either"


class TestValueNeverEntersTheLog:
    """The privacy boundary, run across all four verbs at once with the same
    attacker-chosen value: what a reader of the log must never get."""

    def _drive_all_verbs(self, client):
        assert _store(client, key="k-one").status_code == 201
        assert _store(client, key="k-one", value="second-attacker-value-310").status_code == 201
        assert client.patch("/api/v1/secrets/k-one/metadata", json={"metadata": {"description": METADATA_MARKER}})
        assert client.delete("/api/v1/secrets/k-one").status_code == 200

    def test_no_line_of_a_multiline_value_appears_anywhere(self, tmp_path):
        client, SessionLocal, _ = _build(tmp_path)
        self._drive_all_verbs(client)

        blob = _blob(_all_lifecycle_rows(SessionLocal))
        assert _all_lifecycle_rows(SessionLocal), "the probe below is worth nothing if no row was written"
        for line in VALUE_LINES + ["second-attacker-value-310", METADATA_MARKER]:
            assert line not in blob, f"value material reached the log: {line!r}"

    def test_no_digest_or_encoding_of_the_value_appears(self, tmp_path):
        """A digest is not the value, and it is still a guess-oracle over a
        low-entropy secret — the #602 negative set applies it, so this does too."""
        client, SessionLocal, _ = _build(tmp_path)
        self._drive_all_verbs(client)

        blob = _blob(_all_lifecycle_rows(SessionLocal))
        for material in (
            hashlib.sha256(ATTACK_VALUE.encode()).hexdigest(),
            hashlib.md5(ATTACK_VALUE.encode(), usedforsecurity=False).hexdigest(),
            json.dumps(ATTACK_VALUE),
            ATTACK_VALUE[:8],
        ):
            assert material not in blob

    def test_every_row_carries_only_the_approved_keys(self, tmp_path):
        """The structural half of the same check: a new field is where a value
        would ride, so the table is pinned per event rather than spot-checked."""
        client, SessionLocal, _ = _build(tmp_path)
        self._drive_all_verbs(client)

        approved = {
            STORE_EVENT: {"outcome", "secret_id", "secret_key", "role_names", "endpoint"},
            REPLACE_EVENT: {"outcome", "secret_id", "secret_key", "role_names", "endpoint"},
            METADATA_EVENT: {"outcome", "secret_id", "secret_key", "changed_fields", "endpoint"},
            DELETE_EVENT: {"outcome", "secret_id", "secret_key", "endpoint"},
        }
        rows = _all_lifecycle_rows(SessionLocal)
        assert len(rows) == 4
        for row in rows:
            assert set(_fields(row)) == approved[row.event_type], row.event_type


class TestAuditFailureIsLoudNotFatal:
    """The posture the store door cannot escape: core.put commits inside its own
    session before this row is written, so an audit failure here must NOT be
    reported to the caller as a failed write — and must never be silent.

    The failure is injected at the INSERT of an audit row, not at a session:
    ``backend.get_session()`` is core's own write path too, so breaking the
    session would break the store and prove nothing about the audit arm.
    """

    def test_store_succeeds_row_missing_failure_logged(self, tmp_path, caplog):
        client, SessionLocal, _ = _build(tmp_path)

        @sa_event.listens_for(AuditEvent, "before_insert")
        def _boom(_mapper, _conn, _target):
            raise RuntimeError("audit store down")

        try:
            with caplog.at_level(logging.ERROR, logger="venya.server"):
                resp = _store(client)
        finally:
            sa_event.remove(AuditEvent, "before_insert", _boom)

        assert resp.status_code == 201, "an audit-write failure never turns a completed store into an error"
        with SessionLocal() as s:
            assert s.query(Secret).count() == 1, "and the value itself is stored"
        assert _rows(SessionLocal, STORE_EVENT) == [], "the failing door is the audit write, nothing else"
        # ...and LOUD: a silently missing row is the defect class item 4 is about.
        assert "secret lifecycle audit write failed" in caplog.text
        assert STORE_EVENT in caplog.text


class TestAuditorProbe:
    """The question item 4 was raised for: after a command ran, can the log
    reconstruct what it did? Asked the way an auditor asks it."""

    def test_auditor_sees_the_lifecycle_and_never_the_value(self, tmp_path):
        client, _SessionLocal, _ = _build(tmp_path)
        assert _store(client).status_code == 201
        assert client.delete(f"/api/v1/secrets/{TARGET_KEY}").status_code == 200

        events = {}
        for event in (STORE_EVENT, DELETE_EVENT):
            resp = client.get(
                "/api/v1/audit",
                params={"event_type": event},
                headers={"X-Test-Actor": AUDITOR},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["total"] == 1, event
            events[event] = resp.json()["events"][0]

        assert events[STORE_EVENT]["user_id"] == OWNER
        assert events[DELETE_EVENT]["fields"]["secret_key"] == TARGET_KEY
        assert events[STORE_EVENT]["timestamp"] and events[DELETE_EVENT]["timestamp"]
        for line in VALUE_LINES:
            assert line not in resp.text
