# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#442 site 1 — a FAILED elevation attempt is refused, not answered masked.

The defect (``routes/secrets.py``, the ``result.rowcount == 0`` branch of the
unmask path): the atomic conditional burn matched no row — the token was
unknown, already consumed, or past expiry — and the route then fell through to
a normal masked ``core.get(...)`` and returned HTTP 200. A caller who FAILED
elevation got a successful-looking response carrying a real secret value,
indistinguishable on the wire from a legitimate masked read.

Ruled fix (lead ruling R2): that branch refuses with **401** — the failing
thing is the caller's elevation CREDENTIAL, not its authorization, so the
vocabulary is ``auth_elevation.py``'s (``:136/:144/:153/:256/:262``), not this
file's token-REQUIRED 403s (``:434/:459/:492``, a different condition). A
WARNING names the key and the user id; never the token.

Truth table, both halves, on a REAL Backend over SQLite (the burn is a real
conditional UPDATE, so burned / expired / unknown are genuinely the three
distinct row states rather than a mocked rowcount):

  rejected — burned token, expired token, token with no row at all  → 401,
             no value in the body at all, and the refusal must NOT burn or
             un-burn anything;
  accepted — a valid unconsumed token                               → the same
             plaintext answer as before this change (the happy path is
             untouched).
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE, encrypt_secret
from core.iam.models import Base, ElevationToken, Role, RoleMember, Secret, User
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}
UNMASKED_READ_VALUE = "elev442-plaintext-value"
DETAIL = "Elevation token is invalid, expired, or already used"


@pytest.fixture()
def harness(tmp_path):
    """Real Backend + real secrets router + real require_role chain."""
    db_path = tmp_path / "fail_open_elevation.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    kek = b"k" * KEK_SIZE
    # Real crypto so the happy-path cell exercises the genuine unmask read
    # (wrapped DEK + nonce + ciphertext produced by the same helper the engine
    # consumes) rather than a patched-over core.
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, UNMASKED_READ_VALUE.encode())
    with SessionLocal() as s:
        role = Role(name="dev", permissions="read-write")
        s.add_all([User(user_id="test-user"), role])
        s.flush()
        s.add(RoleMember(user_id="test-user", role_id=role.id))
        s.add(
            Secret(
                key="elev442-secret",
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                key_version_id="v1",
                created_by="test-user",
                meta={},
            )
        )
        s.commit()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.state.backend = backend
    app.state.core = backend.get_core()
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: dict(TEST_USER)

    client = TestClient(app, raise_server_exceptions=False)
    yield client, SessionLocal, backend


def _mint(SessionLocal, token, *, used=False, valid_for_seconds=120, user_id="test-user"):
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


def _token_row_state(SessionLocal, token):
    with SessionLocal() as s:
        row = (
            s.query(ElevationToken)
            .filter(ElevationToken.token_hash == hashlib.sha256(token.encode()).hexdigest())
            .one_or_none()
        )
        return None if row is None else row.used


class TestElevationRefusal:
    """Negative half: every failed elevation is a refusal, never a masked 200."""

    def test_burned_token_refused_401(self, harness):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, "elev442-burned", used=True)

        resp = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == DETAIL
        # The guard the old masked answer leaked: NOTHING value-shaped in the body.
        assert "value" not in resp.json()
        assert "masked" not in resp.json()
        # Refusing must not alter the already-burned row.
        assert _token_row_state(SessionLocal, token) is True

    def test_expired_token_refused_401_and_not_burned(self, harness):
        client, SessionLocal, _ = harness
        # Past the clock-skew tolerance (default 60s) so the expiry check is the
        # thing that rejects it, not a fixture artifact.
        token = _mint(SessionLocal, "elev442-expired", valid_for_seconds=-600)

        resp = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == DETAIL
        assert "value" not in resp.json()
        # An expired token stays un-consumed: the refusal does not burn it, and
        # does not silently resurrect it either.
        assert _token_row_state(SessionLocal, token) is False

    def test_unknown_token_refused_401(self, harness):
        """No matching row at all — the third cause class in the same branch."""
        client, SessionLocal, _ = harness

        resp = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": "elev442-never-minted"},
        )

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == DETAIL
        assert "value" not in resp.json()
        with SessionLocal() as s:
            assert s.query(ElevationToken).count() == 0

    def test_foreign_user_token_refused_401(self, harness):
        """A VALID, unconsumed token minted for another user is a refusal too —
        the user_id predicate in the conditional UPDATE is part of the same
        rowcount==0 branch, and before this fix it answered masked."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, "elev442-foreign", user_id="someone-else")

        resp = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == DETAIL
        # And it must not be consumed by a caller who does not own it.
        assert _token_row_state(SessionLocal, token) is False

    def test_refusal_logs_key_and_user_never_the_token(self, harness, caplog):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, "elev442-logcheck-secret-material", used=True)

        with caplog.at_level(logging.WARNING, logger="venya.server"):
            client.get(
                "/api/v1/secrets/elev442-secret",
                params={"unmask": True},
                headers={"X-Elevation-Token": token},
            )

        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("elev442-secret" in m and "test-user" in m for m in warnings), warnings
        # The token is credential material: it must not reach the log (the #13
        # header-transport work exists precisely to keep it out of access logs).
        assert all(token not in m for m in warnings), warnings

    def test_masked_read_without_any_token_still_200(self, harness):
        """Paired negative-of-the-negative: the plain masked read (unmask not
        requested) is untouched by this change — no elevation, no refusal."""
        client, _, _ = harness
        resp = client.get("/api/v1/secrets/elev442-secret")

        assert resp.status_code == 200, resp.text
        assert resp.json()["masked"] is True
        # The masked read must not leak the plaintext it is standing in for.
        assert resp.json()["value"] != UNMASKED_READ_VALUE


class TestElevationHappyPathIntact:
    """Positive half: a valid unconsumed token still gets plaintext, exactly as
    before #442 (the ruled constraint — sites 1-3 change the FAULT case only)."""

    def test_valid_token_still_yields_plaintext(self, harness):
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, "elev442-valid")

        resp = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["value"] == UNMASKED_READ_VALUE
        assert resp.json()["masked"] is False
        # And the single-use burn still lands: the row is now consumed.
        assert _token_row_state(SessionLocal, token) is True

    def test_valid_token_second_use_refused(self, harness):
        """Same token, twice: first consumes and answers plaintext, the SECOND is
        a 401 refusal. This is the exact sequence the masked fall-through used
        to answer with a 200 + masked value."""
        client, SessionLocal, _ = harness
        token = _mint(SessionLocal, "elev442-double-spend")

        first = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )
        second = client.get(
            "/api/v1/secrets/elev442-secret",
            params={"unmask": True},
            headers={"X-Elevation-Token": token},
        )

        assert first.status_code == 200, first.text
        assert first.json()["masked"] is False
        assert second.status_code == 401, second.text
        assert second.json()["detail"] == DETAIL
        assert "value" not in second.json()
