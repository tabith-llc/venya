# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#602 AC1 shape (a) — a successful elevation-gated unmask writes a
disclosure audit event.

The claim (README zero-trust parenthetical): values leave the server only
through the elevation-gated unmask route or the mTLS executor-injection path,
and "every disclosure is an audit event". Before this ticket the injection arm
had its rows and the human-unmask arm had NONE on its success path — only the
auditor-only DENY wrote one (`auditor_secret_read_denied`).

The fix writes `secret_value_disclosed` through the single lifecycle writer,
AFTER `core.get` returns the value and BEFORE the route's `db.commit()`, so the
row rides the elevation-token burn's transaction (helper posture, ruled Q4:
complete-or-nothing). These cells pin that ordering:

  positive (AC3 iii)      one successful unmask -> exactly ONE disclosure row,
                          and the response still carries the plaintext;
  privacy (AC2)           the row names WHICH key, WHO and WHEN — never the
                          value, never the token, never a digest of either;
  paired negatives (AC3)  (i) a denied unmask writes the DENY and NO
                          disclosure row; (ii) a failed burn still refuses 401
                          with NO disclosure row (both #442 cause classes);
  masked read             writes no disclosure row — a masked read discloses
                          nothing;
  value-fetch failure     no row AND no burned token (nothing was disclosed);
  commit failure          no row AND no burned token — the row and the burn
                          are one unit, never a logged disclosure whose token
                          is still live nor a burned token with no log;
  the partner probe (AC5) an auditor-tier GET /api/v1/audit after one
                          successful disclosure returns the row, with the
                          value nowhere in the answer.

House pattern (test_fail_open_elevation_442.py): REAL Backend over SQLite with
REAL crypto, real Role rows driving the live tier gates, and the real
conditional-UPDATE burn — so burned / expired / unknown are genuinely distinct
row states, not a mocked rowcount. No mocked crypto, no mocked audit store.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.core import CoreAccessError
from core.engine.encryption import KEK_SIZE, encrypt_secret
from core.iam.models import AuditEvent, Base, ElevationToken, Role, RoleMember, Secret, User
from fastapi import FastAPI, Request
from server.dependencies import get_current_user, get_db
from server.routes import audit as audit_routes
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

DISCLOSURE_EVENT = "secret_value_disclosed"
DENY_EVENT = "auditor_secret_read_denied"

PLAINTEXT = "unmask602-top-secret-value"
READER = "reader-user"  # holds a "read" tier role — the human who unmasks
AUDITOR_ONLY = "auditor-only-user"  # every membership is auditor tier -> value deny
AUDIT_VIEWER = "audit-viewer-user"  # auditor tier -> full audit-log visibility
SESSION_ID = 7  # the caller's session row id, as the auth middleware reports it

TARGET_KEY = "unmask602-secret"
TOKEN = "unmask602-elevation-token"


def _mint(SessionLocal, token, *, user_id=READER, used=False, valid_for_seconds=120):
    """Insert a real ElevationToken row; return the plaintext token string."""
    with SessionLocal() as s:
        s.add(
            ElevationToken(
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                user_id=user_id,
                used=used,
                expires_at=datetime.now(UTC) + timedelta(seconds=valid_for_seconds),
            )
        )
        s.commit()
    return token


def _rows(SessionLocal, event_type):
    with SessionLocal() as s:
        return s.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else row.fields


def _token_is_burned(SessionLocal, token):
    with SessionLocal() as s:
        row = (
            s.query(ElevationToken)
            .filter(ElevationToken.token_hash == hashlib.sha256(token.encode()).hexdigest())
            .one_or_none()
        )
        return None if row is None else row.used


class _CommitFlaky:
    """Delegating session whose commit raises — the audit write blowing up
    inside the action's transaction (house pattern from
    test_elevation_auditor_deny.py's _FlakyCommit)."""

    def __init__(self, real):
        self._real = real

    def commit(self):
        raise RuntimeError("audit store down")

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture()
def harness(tmp_path):
    """Real Backend + the real secrets and audit routers + live role gates.

    Identity is chosen per request from the X-Test-Actor header, so one app
    exercises the reader, the auditor-only deny and the auditor-tier audit
    read without mocking the role manager: every tier below comes from a real
    Role row.
    """
    db_path = tmp_path / "unmask602.db"
    engine = create_engine(f"sqlite:///{db_path}")

    @sa_event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, PLAINTEXT.encode())
    with SessionLocal() as s:
        s.add_all(
            [
                User(user_id=READER),
                User(user_id=AUDITOR_ONLY),
                User(user_id=AUDIT_VIEWER),
                Role(name="reader", permissions="read"),
                Role(name="audit", permissions="auditor"),
            ]
        )
        s.flush()
        reader_role = s.query(Role).filter_by(name="reader").one()
        audit_role = s.query(Role).filter_by(name="audit").one()
        s.add_all(
            [
                RoleMember(user_id=READER, role_id=reader_role.id),
                RoleMember(user_id=AUDITOR_ONLY, role_id=audit_role.id),
                RoleMember(user_id=AUDIT_VIEWER, role_id=audit_role.id),
            ]
        )
        s.add(
            Secret(
                key=TARGET_KEY,
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                key_version_id="v1",
                created_by=READER,
                meta={},
            )
        )
        s.commit()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal

    def _identity(request: Request) -> dict:
        return {
            "user_id": request.headers.get("X-Test-Actor", READER),
            "roles": [],
            "caller": "human",
            "session_id": SESSION_ID,
        }

    app = FastAPI()
    app.state.backend = backend
    app.state.core = backend.get_core()
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = _identity

    client = TestClient(app, raise_server_exceptions=False)
    yield client, SessionLocal, app


def _unmask(client, token, *, actor=READER, key=TARGET_KEY):
    return client.get(
        f"/api/v1/secrets/{key}",
        params={"unmask": True},
        headers={"X-Test-Actor": actor, "X-Elevation-Token": token},
    )


class TestDisclosurePositive:
    """AC3 (iii): the positive that did not exist anywhere before this ticket."""

    def test_successful_unmask_writes_one_disclosure_row(self, harness):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN)

        resp = _unmask(client, token)

        assert resp.status_code == 200, resp.text
        # The response is untouched by the audit change: the caller still gets
        # the plaintext, unmasked.
        assert resp.json()["value"] == PLAINTEXT
        assert resp.json()["masked"] is False

        rows = _rows(SessionLocal, DISCLOSURE_EVENT)
        assert len(rows) == 1, f"expected exactly one disclosure row, got {len(rows)}"
        fields = _fields(rows[0])
        assert rows[0].user_id == READER  # the actor, migration-022 principal verbatim
        assert fields["outcome"] == "disclosed"
        assert fields["secret_key"] == TARGET_KEY  # AC2: the auditor learns WHICH key
        assert fields["endpoint"] == "/api/v1/secrets/{key}"
        assert fields["session_id"] == SESSION_ID  # an id, never the token
        assert rows[0].timestamp is not None
        # The single-use burn still lands, in the SAME transaction as the row.
        assert _token_is_burned(SessionLocal, token) is True

    def test_masked_read_writes_no_disclosure_row(self, harness):
        """A masked read discloses nothing, so it must write nothing — the
        guard against the row migrating to the non-elevated arm."""
        client, SessionLocal, _ = harness

        resp = client.get(f"/api/v1/secrets/{TARGET_KEY}", headers={"X-Test-Actor": READER})

        assert resp.status_code == 200, resp.text
        assert resp.json()["masked"] is True
        assert resp.json()["value"] != PLAINTEXT
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []


class TestDisclosureIsValueFree:
    """AC2: the privacy boundary. The row is about the ACT of disclosure, never
    the VALUE — pinned as a negative over every shape the secret could take in
    a field table (plaintext, digest, the elevation token, its digest)."""

    @pytest.mark.parametrize(
        "material",
        [
            PLAINTEXT,
            hashlib.sha256(PLAINTEXT.encode()).hexdigest(),
            hashlib.md5(PLAINTEXT.encode(), usedforsecurity=False).hexdigest(),
            TOKEN,
            hashlib.sha256(TOKEN.encode()).hexdigest(),
        ],
        ids=["plaintext", "sha256-plaintext", "md5-plaintext", "token", "token-digest"],
    )
    def test_no_value_or_credential_bytes_in_the_row(self, harness, material):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN)

        resp = _unmask(client, token)
        assert resp.status_code == 200, resp.text

        rows = _rows(SessionLocal, DISCLOSURE_EVENT)
        assert len(rows) == 1
        blob = json.dumps(
            [
                {
                    "event_type": r.event_type,
                    "user_id": r.user_id,
                    "fields": _fields(r),
                }
                for r in rows
            ]
        )
        assert material not in blob

    def test_field_table_is_the_approved_set(self, harness):
        """No stray field smuggles value material: the table is exactly the
        four approved keys (the actor and the timestamp live as row columns)."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN)

        resp = _unmask(client, token)
        assert resp.status_code == 200, resp.text

        rows = _rows(SessionLocal, DISCLOSURE_EVENT)
        assert len(rows) == 1
        assert set(_fields(rows[0])) == {"outcome", "secret_key", "endpoint", "session_id"}


class TestDisclosureNegatives:
    """AC3 (i) and (ii): the arms that must NOT write the new row."""

    def test_denied_unmask_writes_deny_row_and_no_disclosure_row(self, harness):
        """AC3 (i): the auditor-only chokepoint deny keeps its own row, gains
        none, and still refuses BEFORE the burn — the token stays live."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN, user_id=AUDITOR_ONLY)

        resp = _unmask(client, token, actor=AUDITOR_ONLY)

        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == "insufficient role: auditor cannot read secret values"
        assert len(_rows(SessionLocal, DENY_EVENT)) == 1
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []
        assert _token_is_burned(SessionLocal, token) is False

    def test_burned_token_refuses_401_and_writes_no_disclosure_row(self, harness):
        """AC3 (ii), first cause class: the conditional burn matched no row
        because the token was already consumed (#442 site 1)."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN, used=True)

        resp = _unmask(client, token)

        assert resp.status_code == 401, resp.text
        assert "value" not in resp.json()
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []

    def test_unknown_token_refuses_401_and_writes_no_disclosure_row(self, harness):
        """AC3 (ii), second cause class: no token row exists at all."""
        client, SessionLocal, _ = harness

        resp = _unmask(client, "unmask602-never-minted")

        assert resp.status_code == 401, resp.text
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []

    def test_expired_token_refuses_401_and_writes_no_disclosure_row(self, harness):
        """AC3 (ii), third cause class: past expiry (beyond the skew tolerance)."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN, valid_for_seconds=-600)

        resp = _unmask(client, token)

        assert resp.status_code == 401, resp.text
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []
        # and it is not consumed by a refusal that failed elevation
        assert _token_is_burned(SessionLocal, token) is False


class TestDisclosureRidesTheBurnTransaction:
    """§4.2 ordering, made physical: the row exists only when a value actually
    left, and it commits or aborts together with the burn."""

    def test_value_fetch_failure_leaves_no_row_and_no_burn(self, harness):
        client, SessionLocal, app = harness
        token = _mint(SessionLocal, TOKEN)

        def _boom(**_kwargs):
            raise CoreAccessError("simulated store failure")

        # The route calls core.get(...) on app.state.core; swapping the method
        # on that one instance is the only way to make the FETCH fail after the
        # burn flushed, with every gate and session still live.
        real_get = app.state.core.get
        app.state.core.get = _boom
        try:
            resp = _unmask(client, token)
        finally:
            app.state.core.get = real_get

        assert resp.status_code == 404, resp.text
        # The CoreAccessError arm (its detail is the message) — not the
        # catch-all, which is what the commit-failure cell below takes.
        assert resp.json()["detail"] == "simulated store failure"
        # Added after core.get returns, so the row was never added at all.
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []
        # The burn was flushed but never committed: the rollback on the escaping
        # exception took the UPDATE back with it, so the token is still spendable.
        assert _token_is_burned(SessionLocal, token) is False

    def test_commit_failure_leaves_no_row_and_no_burn(self, harness):
        client, SessionLocal, app = harness
        token = _mint(SessionLocal, TOKEN)
        real_factory = app.state.backend.session_factory

        def _flaky_db():
            session = real_factory()
            try:
                yield _CommitFlaky(session)
            finally:
                session.close()

        # The route's own session is the one whose commit dies (the audit row
        # and the burn share it). get_db is overridden, not the backend
        # factory: the role gate and core keep working sessions, so the only
        # thing failing here is the disclosure's own transaction.
        app.dependency_overrides[get_db] = _flaky_db
        try:
            resp = _unmask(client, token)
        finally:
            app.dependency_overrides.pop(get_db, None)

        assert resp.status_code == 404, resp.text
        # The catch-all arm — proves the RuntimeError came from the commit, not
        # from the value fetch (whose detail is the CoreAccessError message).
        assert resp.json()["detail"] == "Secret retrieval failed"
        assert _rows(SessionLocal, DISCLOSURE_EVENT) == []
        assert _token_is_burned(SessionLocal, token) is False


class TestPartnerProbe:
    """AC5 — the query that motivated the ticket: what an auditor sees after
    one successful human disclosure (the README sells this log to exactly that
    persona)."""

    def test_auditor_read_shows_the_disclosure_and_never_the_value(self, harness):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN)

        disclosure = _unmask(client, token)
        assert disclosure.status_code == 200, disclosure.text

        resp = client.get(
            "/api/v1/audit",
            params={"event_type": DISCLOSURE_EVENT},
            headers={"X-Test-Actor": AUDIT_VIEWER},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        event = body["events"][0]
        assert event["event_type"] == DISCLOSURE_EVENT
        assert event["user_id"] == READER
        assert event["fields"]["secret_key"] == TARGET_KEY
        assert event["fields"]["outcome"] == "disclosed"
        assert event["timestamp"]
        # The probe in one line: the key and the actor appear; the value does
        # not appear anywhere in the auditor's answer.
        assert PLAINTEXT not in resp.text

    def test_auditor_read_after_only_a_denial_shows_no_disclosure(self, harness):
        """Negative half of the probe: a log holding only a denial still answers
        empty to the disclosure query — which is what every arm looked like
        before this ticket."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, TOKEN, user_id=AUDITOR_ONLY)

        denied = _unmask(client, token, actor=AUDITOR_ONLY)
        assert denied.status_code == 403, denied.text
        assert len(_rows(SessionLocal, DENY_EVENT)) == 1

        resp = client.get(
            "/api/v1/audit",
            params={"event_type": DISCLOSURE_EVENT},
            headers={"X-Test-Actor": AUDIT_VIEWER},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] == 0
        assert resp.json()["events"] == []
