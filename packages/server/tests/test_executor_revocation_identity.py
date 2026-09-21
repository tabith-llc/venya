# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for identity-based executor revocation.

Ticket executor-revocation-by-identity, user rulings 2026-09-20 (hybrid):

- Revocation state has ONE source: server.revocation.executor_revocation_state
  (identity flag FIRST, then serial history). Dial gates, heartbeat, list
  display, and the register terminal check are all its clients — condition 2
  forbids a second implementation.
- Identity form (`revoke-executor <id>`) sets Executor.revoked_at (TERMINAL
  for alpha — no un-revoke) AND CRLs the current record serial.
- Serial form (`--serial`) CRLs one credential WITHOUT touching the identity
  (ruling 1) — but a serial form on the CURRENT RECORD SERIAL still refuses
  dial (condition 1) because the helper checks the record serial when none
  is presented.
- F6: register/rotate auto-revokes the REPLACED serial in the same
  transaction (first registration and identical-serial no-ops exempt).
- Condition 4: register under a revoked identity 403s even with a valid
  token; the token IS consumed by validation before the terminal check —
  pinned here so the behavior is recorded, and the runbook documents that
  re-enrollment needs a NEW executor_id.

Real SQLite (precedent: test_secrets/test_init) — multi-table state
(Executor, ExecutorCert, ExecutorCertRevocation, tokens, roles) is the
subject under test; mock DBs would pin the mocks, not the semantics.
"""

import hashlib
import hmac
import itertools
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import (
    AuditEvent,
    Base,
    Executor,
    ExecutorCert,
    ExecutorCertRevocation,
    ExecutorEnrollmentToken,
    Role,
    RoleMember,
    User,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.config import ServerConfig
from server.dependencies import get_backend, get_current_user, require_admin
from server.revocation import executor_revocation_state
from server.routes import admin as admin_routes
from server.routes import executors as executors_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PEPPER = "test-pepper-12345"
TEST_USER = {"user_id": "test-user"}


def _generate_test_csr(cn="test-exec"):
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_mock_ca():
    """Mock CA whose sign_csr yields certs with DISTINCT incrementing serials."""
    mock_ca = MagicMock()
    counter = itertools.count(0x5000)  # start clear of seeded test serials

    def _sign(csr, executor_id, crl_url=None):
        cert = MagicMock()
        cert.serial_number = next(counter)
        cert.not_valid_before_utc = datetime.now(UTC)
        cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=30)
        cert.public_bytes.return_value = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        return cert

    mock_ca.sign_csr.side_effect = _sign
    mock_ca.compute_serial_hex.side_effect = lambda s: format(s, "016x")
    mock_ca.compute_fingerprint.return_value = "AA:BB:CC"
    mock_ca.get_ca_cert_pem.return_value = b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
    mock_ca.purge_expired_revocations.return_value = 0
    return mock_ca


@pytest.fixture()
def env(tmp_path):
    """Real-SQLite app environment: routes wired, auth overridden, roles seeded."""
    engine = create_engine(f"sqlite:///{tmp_path / 'rev.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    seed = SessionLocal()
    seed.add(User(user_id="test-user", auth_mode="password"))
    role = Role(name="operators", permissions="read-write", description="test")
    seed.add(role)
    seed.flush()
    seed.add(RoleMember(user_id="test-user", role_id=role.id))
    seed.commit()
    seed.close()

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.config = ServerConfig(recovery_code_pepper=PEPPER)
    app.state.ca_manager = _make_mock_ca()
    app.state.core = MagicMock()
    app.state.core.encrypt.return_value = (b"wrapped_dek", b"nonce", b"ciphertext")
    app.dependency_overrides[get_backend] = lambda: backend
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[require_admin] = lambda: TEST_USER

    # Executor auth state for the heartbeat route (ticket
    # sec-endpoint-ratelimit-hardening #7): production sets this via
    # _validate_executor_mtls; this bare app injects the same shape. Only the
    # heartbeat cells read request.state directly — the bearer-flow tests use
    # the dependency overrides above, which replace get_current_user entirely.
    from starlette.middleware.base import BaseHTTPMiddleware

    class _ExecAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": "exec-a"}
            return await call_next(request)

    app.add_middleware(_ExecAuth)

    app.include_router(executors_routes.router, prefix="/api/v1")
    app.include_router(admin_routes.router, prefix="/api/v1")

    client = TestClient(app, raise_server_exceptions=False)
    yield client, SessionLocal
    engine.dispose()


def _seed_executor(SessionLocal, executor_id="exec-a", revoked_at=None, enrolled=True):
    s = SessionLocal()
    s.add(
        Executor(
            id=executor_id,
            hostname=executor_id,
            enrolled_at=datetime.now(UTC) if enrolled else None,
            revoked_at=revoked_at,
            status="active",
        )
    )
    s.commit()
    s.close()


def _seed_cert(SessionLocal, executor_id="exec-a", serial="0000000000001000"):
    s = SessionLocal()
    s.add(
        ExecutorCert(
            executor_id=executor_id,
            serial_number=serial,
            not_before=datetime.now(UTC),
            not_after=datetime.now(UTC) + timedelta(days=30),
            fingerprint="AA:BB:CC",
        )
    )
    s.commit()
    s.close()


def _seed_revocation(SessionLocal, serial, executor_id="exec-a", reason="Admin revocation"):
    s = SessionLocal()
    s.add(
        ExecutorCertRevocation(
            serial_number=serial, executor_id=executor_id, revoked_at=datetime.now(UTC), reason=reason
        )
    )
    s.commit()
    s.close()


def _mint_token(SessionLocal, token, executor_id="exec-a"):
    s = SessionLocal()
    token_hash = hmac.new(PEPPER.encode(), token.encode(), hashlib.sha256).hexdigest()
    s.add(
        ExecutorEnrollmentToken(
            token_hash=token_hash,
            executor_id=executor_id,
            state="created",
            created_by="test-user",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    s.commit()
    s.close()


def _register(client, executor_id="exec-a", token=None, headers=None):
    body = {"executor_id": executor_id, "csr_pem": _generate_test_csr(executor_id)}
    if token:
        body["enrollment_token"] = token
    return client.post("/api/v1/executors/register", json=body, headers=headers or {})


# --- Helper semantics (the ONE source, condition 2) ---


class TestHelperSemantics:
    def test_identity_flag_first(self, env):
        _, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _seed_cert(SessionLocal)
        state = executor_revocation_state(SessionLocal(), "exec-a")
        assert state.revoked and state.reason == "identity"

    def test_record_serial_in_crl_no_flag(self, env):
        """Condition 1 core: serial form on the CURRENT RECORD SERIAL revokes
        without the identity flag — and the helper still reports revoked."""
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        state = executor_revocation_state(SessionLocal(), "exec-a")
        assert state.revoked and state.reason == "serial"

    def test_clean_not_revoked(self, env):
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        assert executor_revocation_state(SessionLocal(), "exec-a").revoked is False

    def test_presented_serial_checked(self, env):
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000002222")
        state = executor_revocation_state(SessionLocal(), "exec-a", presented_serial="0000000000002222")
        assert state.revoked and state.reason == "serial"

    def test_presented_serial_casefolded(self, env):
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        _seed_revocation(SessionLocal, "0000000000002222")
        state = executor_revocation_state(SessionLocal(), "exec-a", presented_serial="0000000000002222".upper())
        assert state.revoked

    def test_stale_serial_revocation_does_not_taint_identity(self, env):
        """a722 cell: an OLD serial in the CRL while the record points elsewhere
        is NOT revocation of the current identity."""
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000000aaa")
        assert executor_revocation_state(SessionLocal(), "exec-a").revoked is False


# --- Admin revoke route: identity + serial forms ---


class TestAdminRevokeForms:
    def test_identity_form_sets_flag_and_crls_record_serial(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = client.post("/api/v1/admin/executors/exec-a/revoke")
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        assert s.query(Executor).filter_by(id="exec-a").first().revoked_at is not None
        assert s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000001000").first() is not None
        s.close()

    def test_identity_form_idempotent(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client.post("/api/v1/admin/executors/exec-a/revoke")
        resp2 = client.post("/api/v1/admin/executors/exec-a/revoke")
        assert resp2.json()["revoked"] is False
        s = SessionLocal()
        assert s.query(ExecutorCertRevocation).count() == 1  # no duplicate row
        assert s.query(Executor).filter_by(id="exec-a").first().revoked_at is not None  # flag kept
        s.close()

    def test_serial_form_crls_without_identity(self, env):
        """a722 acceptance shape: credential killed, identity untouched."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000000AAA"})
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        row = s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000000aaa").first()
        assert row is not None and row.executor_id == "exec-a"  # attributed
        assert s.query(Executor).filter_by(id="exec-a").first().revoked_at is None  # identity untouched
        s.close()

    def test_serial_form_bad_hex_400(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "not-hex-zzz"})
        assert resp.status_code == 400

    def test_serial_form_idempotent(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000000aaa"})
        resp2 = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000000aaa"})
        assert resp2.json()["revoked"] is False


# --- Register: terminal gate (condition 4) + F6 auto-revoke ---


class TestRegisterTerminalAndAutoRevoke:
    def test_revoked_identity_with_valid_token_403_and_token_not_burned(self, env):
        """Condition 4, pinned — WITH A RECORDED DEVIATION from the ruling's
        expectation: the ruling assumed the token would be consumed by
        validation before the terminal check. Observed product behavior: the
        403 escapes the route → get_db's rollback-on-exception contract rolls
        back the consumption UPDATE too → the token survives as 'created'
        (and expires unused — it is bound to the terminal identity, so it can
        never succeed). Strictly friendlier to the admin than the assumed
        burn; deviation reported in the results file and runbook wording."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _mint_token(SessionLocal, "enrl_exec_valid1")
        resp = _register(client, token="enrl_exec_valid1")
        assert resp.status_code == 403
        assert "revoked" in resp.json()["detail"].lower()
        s = SessionLocal()
        tok = s.query(ExecutorEnrollmentToken).first()
        assert tok.state == "created"  # rollback preserved it (see docstring)
        assert s.query(ExecutorCert).count() == 0  # no cert issued
        s.close()

    def test_revoked_identity_tokenless_403(self, env):
        client, SessionLocal = env
        client.app.state.config = ServerConfig(
            recovery_code_pepper=PEPPER,
            executor_enrollment={"require_token": False},
        )
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        resp = _register(client)
        assert resp.status_code == 403

    def test_serial_history_does_not_block_re_registration(self, env):
        """Negative: serial-form revocation kills the credential, not the
        identity — re-registration with a token still works."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        _mint_token(SessionLocal, "enrl_exec_valid2")
        resp = _register(client, token="enrl_exec_valid2")
        assert resp.status_code == 201

    def test_re_registration_auto_revokes_replaced_serial(self, env):
        """F6: the predecessor serial is CRLed in the same transaction."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _mint_token(SessionLocal, "enrl_exec_valid3")
        resp = _register(client, token="enrl_exec_valid3")
        assert resp.status_code == 201
        new_serial = resp.json()["serial_number"]
        assert new_serial != "0000000000001000"
        s = SessionLocal()
        old_row = s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000001000").first()
        assert old_row is not None and old_row.executor_id == "exec-a"
        assert "replac" in (old_row.reason or "").lower()
        cert = s.query(ExecutorCert).filter_by(executor_id="exec-a").first()
        assert cert.serial_number == new_serial  # record converged
        s.close()

    def test_first_registration_mints_no_revocation(self, env):
        """Negative: nothing to auto-revoke on first registration."""
        client, SessionLocal = env
        _mint_token(SessionLocal, "enrl_exec_valid4")
        resp = _register(client, token="enrl_exec_valid4")
        assert resp.status_code == 201
        s = SessionLocal()
        assert s.query(ExecutorCertRevocation).count() == 0
        s.close()


# --- Wire: revocation list carries identities, ETag covers both ---


class TestRevocationListWire:
    def test_both_arrays_present(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, executor_id="exec-a", revoked_at=datetime.now(UTC))
        _seed_revocation(SessionLocal, "0000000000001000", executor_id="exec-a")
        resp = client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked_serials"] == ["0000000000001000"]
        assert data["revoked_identities"] == ["exec-a"]

    def test_etag_covers_identities(self, env):
        client, SessionLocal = env
        r1 = client.get("/api/v1/executors/certs/revocation-list")
        etag1 = r1.headers["etag"]
        assert (
            client.get("/api/v1/executors/certs/revocation-list", headers={"If-None-Match": etag1}).status_code == 304
        )
        _seed_executor(SessionLocal, executor_id="exec-b", revoked_at=datetime.now(UTC))
        r2 = client.get("/api/v1/executors/certs/revocation-list", headers={"If-None-Match": etag1})
        assert r2.status_code == 200  # identity addition invalidates the ETag
        assert "exec-b" in r2.json()["revoked_identities"]


# --- Heartbeat: helper-driven revoked flag ---


class TestHeartbeatRevokedFlag:
    def _beat(self, client, executor_id="exec-a"):
        return client.post("/api/v1/heartbeat", json={"executor_id": executor_id, "cert_fingerprint": "AA:BB:CC"})

    def test_identity_revoked_true(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _seed_cert(SessionLocal)
        resp = self._beat(client)
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True
        # WRITE-GUARD PIN (ruling B1, ticket sec-endpoint-ratelimit-hardening):
        # the revoked beat got its advisory 200 {revoked:true} (F3
        # cooperative-stop channel preserved) but wrote NOTHING — a revoked
        # identity cannot stamp last_heartbeat/status and race its own
        # revoked presentation in list_executors.
        from core.iam.models import Executor

        s = SessionLocal()
        try:
            row = s.query(Executor).filter(Executor.id == "exec-a").first()
            assert row.last_heartbeat is None
        finally:
            s.close()

    def test_record_serial_revoked_true(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        assert self._beat(client).json()["revoked"] is True

    def test_clean_false(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        assert self._beat(client).json()["revoked"] is False


# --- List display (client of the helper, condition 2) ---


class TestListStatusDisplay:
    def _statuses(self, client):
        resp = client.get("/api/v1/executors")
        assert resp.status_code == 200
        return {e["id"]: e["status"] for e in resp.json()["executors"]}

    def test_identity_revoked_shows_revoked(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        assert self._statuses(client)["exec-a"] == "revoked"

    def test_stale_serial_keeps_active(self, env):
        """a722 list cell (condition 3): serial form on an off-record serial
        must NOT leak identity semantics into the display."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000000aaa")
        assert self._statuses(client)["exec-a"] == "active"

    def test_current_record_serial_revoked_shows_revoked(self, env):
        """Condition 1 consistency: the credential the identity runs on is
        dead -> display agrees with the dial refusal."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        assert self._statuses(client)["exec-a"] == "revoked"


# --- Admin cert list: client of the shared state (condition-2 sweep catch) ---


class TestAdminListRevocationSource:
    def _listed_ids(self, client):
        resp = client.get("/api/v1/admin/executors")
        assert resp.status_code == 200
        return {e["executor_id"] for e in resp.json()["executors"]}

    def test_identity_revoked_excluded_even_with_clean_serial(self, env):
        """The sweep catch: identity flag alone (serial NOT in CRL — a state
        the old batch filter could not see) excludes the executor."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _seed_cert(SessionLocal, serial="0000000000001000")
        assert "exec-a" not in self._listed_ids(client)

    def test_clean_included(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        assert "exec-a" in self._listed_ids(client)

    def test_serial_revoked_record_excluded(self, env):
        """Pre-existing behavior preserved: CRLed record serial drops out."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        assert "exec-a" not in self._listed_ids(client)

    def test_stale_serial_revocation_keeps_listing(self, env):
        """a722 cell: an off-record revoked serial must NOT drop the executor."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000000aaa")
        assert "exec-a" in self._listed_ids(client)


# --- Dial gates (ruling 4 mandatory enforcement) ---


class TestDialGates:
    def _session_payload(self, executor_id="exec-a"):
        return {"executor_id": executor_id, "secret_keys": []}

    def test_session_create_refused_identity(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        resp = client.post("/api/v1/executors/sessions", json=self._session_payload())
        assert resp.status_code == 403 and "revoked" in resp.json()["detail"].lower()

    def test_session_create_refused_serial_form_on_record_serial(self, env):
        """Condition 1 EXPLICIT CELL: serial-form revocation of the current
        record serial refuses dial even though the identity flag is unset."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        resp = client.post("/api/v1/executors/sessions", json=self._session_payload())
        assert resp.status_code == 403

    def test_session_create_allowed_clean(self, env):
        """Paired negative: clean executor is NOT refused at the gate."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        resp = client.post("/api/v1/executors/sessions", json=self._session_payload())
        assert resp.status_code != 403

    def test_execute_refused_identity_with_preexisting_session(self):
        """Session created BEFORE the revocation still refuses at execute.

        Mock-db cell by necessity: sqlite hands back naive datetimes for the
        route's aware expiry comparison (storage-engine artifact, production is
        timestamptz) — this cell targets the GATE, so the session/executor rows
        are mocks with aware timestamps."""
        app = FastAPI()
        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper=PEPPER)
        app.state.ca_manager = _make_mock_ca()
        app.state.core = MagicMock()
        app.dependency_overrides[get_backend] = lambda: backend
        app.dependency_overrides[get_current_user] = lambda: {"user_id": "test-user", "caller": "executor"}
        app.include_router(executors_routes.router, prefix="/api/v1")

        session_row = MagicMock()
        session_row.user_id = "test-user"
        session_row.executor_id = "exec-a"
        session_row.expires_at = datetime.now(UTC) + timedelta(minutes=10)
        executor_row = MagicMock()
        executor_row.id = "exec-a"
        executor_row.revoked_at = datetime.now(UTC)

        def _q(model):
            m = MagicMock()
            if model.__name__ == "ExecutionSession":
                m.filter.return_value.first.return_value = session_row
            elif model.__name__ == "Executor":
                m.filter.return_value.first.return_value = executor_row
            else:
                m.filter.return_value.first.return_value = None
            return m

        db.query.side_effect = _q

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/exec-a/execute", json={"session_id": "sess-1", "command": "id"})
        assert resp.status_code == 403 and "revoked" in resp.json()["detail"].lower()


# --- Phase 2: incumbent serial-match exemption (executor-rotation-require-token-400 ruling 2(a)) ---
# Truth table user-confirmed 2026-09-20: C1-C6 + preserved negatives.
# C5/C6 are the ruled-named cells — pinned as NAMED tests (approval condition 2).


def _incumbent_headers(serial, cn="exec-a", verified="SUCCESS"):
    """nginx-forwarded client-cert headers ($ssl_client_serial is uppercase;
    DER strips leading zero bytes — normalization is the server's job)."""
    return {
        "X-Client-Verified": verified,
        "X-Client-Subject": f"O=Venya,CN={cn}",
        "X-Client-Serial": serial,
    }


class TestIncumbentExemption:
    @pytest.fixture(autouse=True)
    def _reset_rate_limiters(self):
        """Isolate the module-level limiter cache (pattern: test_executor_enrollment)
        — 11 register calls on one executor_id/ip would otherwise trip the 5/min cap."""
        from server import rate_limit as _rl

        saved = dict(_rl._LIMITERS)
        _rl._LIMITERS.clear()
        yield
        _rl._LIMITERS.clear()
        _rl._LIMITERS.update(saved)

    def test_c1_incumbent_serial_match_exempts_tokenless(self, env):
        """C1: presented == record, clean state → tokenless rotate exempt (201);
        F6 CRLs the replaced serial; audit marks incumbent_exempt."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000001000"))
        assert resp.status_code == 201
        assert resp.json()["serial_number"] != "0000000000001000"
        s = SessionLocal()
        crl_row = s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000001000").first()
        assert crl_row is not None and "replac" in (crl_row.reason or "").lower()
        audit = s.query(AuditEvent).filter_by(event_type="executor_registered").first()
        # AuditEvent.fields is JSON-serialized by the @validates decorator
        audit_fields = json.loads(audit.fields) if isinstance(audit.fields, str) else audit.fields
        assert audit_fields.get("incumbent_exempt") is True
        assert audit_fields.get("with_token") is False
        s.close()

    def test_c2_diverged_serial_no_exemption(self, env):
        """C2 paired negative: presented != record (diverged/predecessor), clean → 400."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000002222"))
        assert resp.status_code == 400
        assert "Enrollment token required" in resp.json()["detail"]

    def test_c3_identity_revoked_no_exemption_even_on_record_match(self, env):
        """C3: identity flag is terminal — exemption refused even with the
        exact record serial in hand (revocation-state check runs FIRST)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000001000"))
        assert resp.status_code == 400

    def test_c4_crled_serial_no_exemption_even_on_record_match(self, env):
        """C4: presented serial in the CRL (serial-form on the record) → no exemption."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000001000"))
        assert resp.status_code == 400

    def test_c5_revoked_then_re_enrolled_old_serial_no_exemption(self, env):
        """C5 (RULED-NAMED): an old credential CRLed by F6 after a token
        re-enrollment never regains the exemption — the old serial 400s even
        though a fresh clean record exists."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000009999")  # fresh record post re-enrollment
        _seed_revocation(SessionLocal, "0000000000001000", reason="Replaced by re-registration/rotation")
        resp = _register(client, headers=_incumbent_headers("0000000000001000"))
        assert resp.status_code == 400

    def test_c6_revocation_precedes_record_match(self, env):
        """C6 (RULED-NAMED) — ordering cell: with the presented serial BOTH
        CRLed AND equal to the record serial, the revocation state must win.
        A match-first implementation would exempt (201); a revocation-skipping
        implementation would not consult the shared helper with the presented
        serial — the spy pins both halves."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        seen = {}
        real = executors_routes.executor_revocation_state

        def _spy(db, executor_id, presented_serial=None, **kw):
            seen["presented"] = presented_serial
            return real(db, executor_id, presented_serial=presented_serial, **kw)

        with patch.object(executors_routes, "executor_revocation_state", _spy):
            resp = _register(client, headers=_incumbent_headers("0000000000001000"))
        assert resp.status_code == 400
        assert seen["presented"] == "0000000000001000"

    def test_no_client_cert_tokenless_still_400(self, env):
        """Preserved negative (Phase 1): no mTLS headers → the old 400."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client)
        assert resp.status_code == 400
        assert "Enrollment token required" in resp.json()["detail"]

    def test_unverified_cert_no_exemption(self, env):
        """Preserved negative: X-Client-Verified != SUCCESS → 400 even with a
        perfect serial + CN (nginx only ever forwards SUCCESS for chain-verified certs)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000001000", verified="FAILED"))
        assert resp.status_code == 400

    def test_cn_mismatch_no_exemption(self, env):
        """Paired negative: the record serial presented under a foreign CN → 400
        (CN is the discriminator; serials are not transferable across identities)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers("0000000000001000", cn="exec-b"))
        assert resp.status_code == 400

    def test_empty_serial_header_no_exemption(self, env):
        """nginx drops an empty $ssl_client_serial; a forwarded "" must not exempt."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers(""))
        assert resp.status_code == 400

    def test_nginx_serial_case_and_padding_normalized(self, env):
        """$ssl_client_serial is uppercase and DER strips leading zero bytes:
        "ABCDEF" must match record "0000000000abcdef" (else ~1/16 of rotations
        flake on a leading-zero serial)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000abcdef")
        resp = _register(client, headers=_incumbent_headers("ABCDEF"))
        assert resp.status_code == 201
