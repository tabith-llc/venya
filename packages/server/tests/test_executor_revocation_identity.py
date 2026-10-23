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

#634 TRANCHE 1 — this file is the engine-builder that had the largest blind surface on the board: 40
cells went red the moment `PRAGMA foreign_keys=ON` was installed, every one of them the same
`INSERT INTO executor_certs` whose parent `users.user_id` had never been seeded. Two things follow, and
both are in this file now:

1. **The engine enforces.** `env` attaches the shipped connect-listener shape
   (`test_secret_delete_fk.py:56-61`), so the declared `executor_certs.executor_id -> users.user_id`
   constraint is actually consulted instead of merely present in the DDL.
2. **The seeds are honest.** A cert row now cannot exist without the machine identity it points at —
   which is exactly what production does at registration (`routes/executors.py:1090`,
   `User(user_id=…, auth_mode="mtls", status="active")`). The seeds were not made to pass by deleting
   the constraint or the assertion; they were made to pass by supplying the parent, which is the
   failure mode #634 exists to close.

`TestEnforcementIsLive` at the bottom of this file is the AC2 paired negative: it proves the
enforcement is what refuses, and that the refusal is not an unrelated constraint or a mock.
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
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PEPPER = "test-pepper-12345"
TEST_USER = {"user_id": "test-user"}

# #449: the role gate's stated refusal for an executor-class caller. Cells that
# target an IN-BODY check assert their reason is NOT this string — several distinct
# 403s live on these routes and status alone cannot separate them.
EXECUTOR_GATE_REFUSAL = "Executor callers are not permitted on role-gated routes"


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


def _make_mock_ca(real_manager=None):
    """Mock CA whose sign_csr yields certs with DISTINCT incrementing serials.

    #314: when a real CAManager is supplied (env fixture), verification-side
    surface (load_ca/get_ca_cert_pem) is REAL against the temp CA dir; only
    the issuance serials stay scripted."""
    if real_manager is not None:
        return real_manager
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
    # No `purge_expired_revocations` stub here any more (#685): the executor CA manager has no
    # purge path to stub, and leaving one in a mock is how a closed hazard keeps a name.
    return mock_ca


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Real-SQLite app environment: routes wired, auth overridden, roles seeded.

    #634: this engine ENFORCES foreign keys. Before tranche 1 it was built with no
    ``PRAGMA foreign_keys`` listener, so SQLite consulted the declared constraints never and 40
    cells here were inserting ``executor_certs`` rows whose ``users.user_id`` parent did not exist.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'rev.db'}")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        # Shipped shape, copied from the file that already does this (test_secret_delete_fk.py:56-61).
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

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

    from server.ca import CAManager
    from server.config import CASecurityConfig, InnerTLSConfig

    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    # #537: the write path refuses to mint an unencrypted CA key, so this CA is
    # created with a passphrase var that IS set (test-local name; the plaintext
    # configuration it used to rely on no longer exists).
    monkeypatch.setenv("TEST_CA_KEY_PASSPHRASE_REVOC", "test_passphrase_revoc")
    real_ca = CAManager(str(ca_dir), CASecurityConfig(key_passphrase_env="TEST_CA_KEY_PASSPHRASE_REVOC"))
    real_ca.initialize()
    cert_prefix = tmp_path / "certfiles"
    cert_prefix.mkdir()

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.config = ServerConfig(
        recovery_code_pepper=PEPPER,
        ca_dir=str(ca_dir),
        inner_mtls=InnerTLSConfig(
            enabled=True,
            cert_file="/test/inner.crt",
            key_file="/test/inner.key",
            client_ca_file="/test/inner-ca.crt",
        ),
    )
    app.state.ca_manager = _make_mock_ca(real_ca)
    app.state.test_cert_prefix = cert_prefix
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


def _seed_machine_identity(SessionLocal, executor_id="exec-a"):
    """Create the parent `users` row an executor credential points at, as registration does.

    #634: `executor_certs.executor_id` is `ForeignKey("users.user_id", ondelete="CASCADE")`, and with
    enforcement installed a cert row cannot exist without it. Production creates that identity during
    registration (`routes/executors.py:1084-1094`: `auth_mode="mtls"`, and `status="active"` because
    there is no WebAuthn ceremony for an mTLS machine identity to wait on), so the seed says the same
    thing rather than inventing a shape that only a test would accept.
    """
    s = SessionLocal()
    # Look it up by user_id, NOT by s.get(User, executor_id): `id` is the integer primary key here and
    # `user_id` is the unique natural key, so a get() by that name silently misses and double-inserts.
    if s.query(User).filter_by(user_id=executor_id).first() is None:
        s.add(
            User(
                user_id=executor_id,
                auth_mode="mtls",
                status="active",
                enrolled_at=datetime.now(UTC),
            )
        )
        s.commit()
    s.close()


def _seed_executor(SessionLocal, executor_id="exec-a", revoked_at=None, enrolled=True):
    _seed_machine_identity(SessionLocal, executor_id)
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
    # #634: the parent first. Every one of this file's 40 FK violations was an executor_certs row
    # inserted with no users row behind it.
    _seed_machine_identity(SessionLocal, executor_id)
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


class TestSerialFormLeadingZeroSerial:
    """Truth table for ticket cert-serial-canonicalization-mismatch (#481) on
    the EXECUTOR side: the serial-form revocation stored zero-padded while the
    middleware presented unpadded, so ~1/16 of certificates got a revocation
    that recorded green and never refused anything. Serial under test:
    0x0a1b2c3d4e5f6071 — padded "0a1b2c3d4e5f6071", unpadded "a1b2c3d4e5f6071".
    """

    PADDED = "0a1b2c3d4e5f6071"
    UNPADDED = "a1b2c3d4e5f6071"

    def test_serial_form_revocation_of_leading_zero_serial_refuses(self, env):
        """(e) the defect: revoke the padded record serial of a leading-zero
        certificate, then present it the way the middleware does (canonical) and
        the way a legacy presentation did (unpadded) — BOTH refuse."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial=self.PADDED)
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": self.PADDED})
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        try:
            state = executor_revocation_state(s, "exec-a", presented_serial=self.PADDED)
            assert state.revoked and state.reason == "serial"
            # The unpadded presentation the middleware used before #481 — this is
            # the shape that silently never matched.
            state = executor_revocation_state(s, "exec-a", presented_serial=self.UNPADDED)
            assert state.revoked and state.reason == "serial"
        finally:
            s.close()

    def test_operator_unpadded_revoke_stores_canonical_and_refuses(self, env):
        """(e') the operator half: typing the serial WITHOUT padding revokes the
        same certificate, and the row lands in the one canonical form."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial=self.PADDED)
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": self.UNPADDED.upper()})
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        try:
            row = s.query(ExecutorCertRevocation).filter_by(executor_id="exec-a").first()
            assert row is not None and row.serial_number == self.PADDED
            state = executor_revocation_state(s, "exec-a", presented_serial=self.PADDED)
            assert state.revoked and state.reason == "serial"
        finally:
            s.close()

    def test_legacy_unpadded_row_still_refuses_after_the_change(self, env):
        """(e'') tolerance half: a row ALREADY stored unpadded (no migration
        rewrites it) still refuses the certificate it names."""
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial=self.PADDED)
        _seed_revocation(SessionLocal, self.UNPADDED)
        s = SessionLocal()
        try:
            state = executor_revocation_state(s, "exec-a", presented_serial=self.PADDED)
            assert state.revoked and state.reason == "serial"
        finally:
            s.close()

    def test_unrevoked_leading_zero_serial_is_admitted(self, env):
        """(e-b) the admitted half: the SAME leading-zero serial with no
        revocation row is not revoked (a gate that only rejects proves nothing).
        A row for a DIFFERENT leading-zero serial must not refuse it either."""
        _, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial=self.PADDED)
        s = SessionLocal()
        try:
            assert executor_revocation_state(s, "exec-a", presented_serial=self.PADDED).revoked is False
        finally:
            s.close()
        _seed_revocation(SessionLocal, "0999999999999999", executor_id="exec-a")
        s = SessionLocal()
        try:
            assert executor_revocation_state(s, "exec-a", presented_serial=self.PADDED).revoked is False
        finally:
            s.close()

    def test_identity_form_path_is_unchanged(self, env):
        """(e-b') the ticket's BOUNDED half: identity-form revocation is
        representation-free and is still checked FIRST — this fix must not
        reorder or touch it."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial=self.PADDED)
        resp = client.post("/api/v1/admin/executors/exec-a/revoke")
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        try:
            state = executor_revocation_state(s, "exec-a", presented_serial=self.UNPADDED)
            assert state.revoked and state.reason == "identity"
        finally:
            s.close()


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
        """#685 re-pair of the a722 cell.

        This cell used to POST a serial no credential holds (`…0AAA` against a record row of
        `…1000`) and assert `200 / revoked=True` plus a stored row "attributed" to `exec-a` —
        that expectation WAS the defect, pinned as expected behavior. The refusal half belongs
        here now; the a722 intent the cell was written to prove (credential killed, identity
        untouched) moved to `test_serial_form_recorded_serial_leaves_identity_alone`, which uses
        the serial the credential actually holds. Nothing deleted, nothing loosened: one
        expectation inverted to the ruled truth table and the positive re-landed next door.
        """
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000000AAA"})
        assert resp.status_code == 404
        assert "0000000000000aaa" in resp.json()["detail"]  # names WHAT was unknown, in the ONE form
        s = SessionLocal()
        row = s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000000aaa").first()
        assert row is None  # refused BEFORE the insert — no phantom published to daemons or the CRL
        assert s.query(AuditEvent).filter_by(event_type="executor_cert_revoked").first() is None
        assert s.query(Executor).filter_by(id="exec-a").first().revoked_at is None  # identity untouched
        s.close()

    def test_serial_form_recorded_serial_leaves_identity_alone(self, env):
        """The a722 acceptance shape, re-landed on a serial the credential actually holds:
        credential killed, identity untouched."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000001000"})
        assert resp.status_code == 200 and resp.json()["revoked"] is True
        s = SessionLocal()
        row = s.query(ExecutorCertRevocation).filter_by(serial_number="0000000000001000").first()
        assert row is not None and row.executor_id == "exec-a"  # attributed to a real holder
        assert s.query(Executor).filter_by(id="exec-a").first().revoked_at is None  # identity untouched
        s.close()

    def test_serial_form_bad_hex_400(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        resp = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "not-hex-zzz"})
        assert resp.status_code == 400

    def test_serial_form_idempotent(self, env):
        """#685: the repeat face is unchanged, but the fixture now repeats a REAL revocation.

        It used to POST `…0aaa` twice against a record row of `…1000`, so the first call was the
        blind insert and the second was "idempotent" only because the defect had just written the
        row. Same assertion, same semantics proven — a serial the store vouches for, revoked twice,
        answers `revoked=False` the second time with exactly one row.
        """
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal)
        client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000001000"})
        resp2 = client.post("/api/v1/admin/executors/exec-a/revoke", json={"serial": "0000000000001000"})
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
        timestamptz) — this cell targets the in-BODY revoked-executor gate (#449
        re-pin), so the session/executor rows are mocks with aware timestamps.

        #449 changed the CALLER, not the control. The old double was
        ``{"user_id": "test-user", "caller": "executor"}`` — a hybrid the
        middleware can never emit (``middleware/auth.py:834`` writes
        ``caller/executor_id/presented_serial/revoked`` and NO ``user_id``), and
        the only thing that carried it into the body was the blanket executor pass
        this ticket removes. It is now a production-realistic HUMAN bearer holding a
        read-write role, which passes ``require_role("read-write")`` honestly.

        The assertion pins the REASON TEXT, not just the status: three different 403s
        exist on this route (the gate's executor refusal, "Read-write permission
        required", and this revoked-Executor deny), and a status-only assert cannot
        tell them apart.
        """
        app = FastAPI()
        db = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = db
        app.state.backend = backend
        app.state.config = ServerConfig(recovery_code_pepper=PEPPER)
        app.state.ca_manager = _make_mock_ca()
        app.state.core = MagicMock()
        app.dependency_overrides[get_backend] = lambda: backend
        app.dependency_overrides[get_current_user] = lambda: {
            "user_id": "test-user",
            "caller": "human",
            "session_id": "sess-bearer-1",
        }
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

        # The human double holds a read-write role, so require_role passes on its
        # own merits and the request reaches the body — that is the point: this cell
        # must exercise the route's revoked-executor check, not some gate on the way.
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
        with patch("server.dependencies.RoleManager", return_value=rm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/v1/executors/exec-a/execute", json={"session_id": "sess-1", "command": ["id"]})
            # PAIRED HALF (this is what makes the re-pin stronger than the old cell,
            # not merely re-worded): the OLD fixture shape — the production-impossible
            # ``user_id`` + ``caller=executor`` hybrid — must now be refused BY THE
            # GATE and must never reach this body. Under the blanket pass this request
            # answered the revoked-executor detail below, which is exactly how the old
            # cell rode the pass into the route body.
            app.dependency_overrides[get_current_user] = lambda: {
                "user_id": "test-user",
                "caller": "executor",
            }
            hybrid = client.post("/api/v1/executors/exec-a/execute", json={"session_id": "sess-1", "command": ["id"]})
            # The human request above performed exactly one lookup; the executor
            # request must have added none (call COUNT, not .called — the human
            # double legitimately hit the role table first).
            lookups_after_hybrid = rm.get_user_permissions.call_count

        assert resp.status_code == 403, resp.text
        detail = resp.json()["detail"]
        # The gate's executor refusal and the tier deny must NOT be what answered.
        assert detail != EXECUTOR_GATE_REFUSAL, "refused by the role gate — the body never ran"
        assert detail != "Read-write permission required"
        # The in-body revoked-executor deny (routes/executors.py, dial gate #2).
        assert "revoked" in detail.lower(), detail
        assert "Executor 'exec-a' is revoked" in detail, detail
        assert "refusing to route execution" in detail, detail

        # Paired half verdict: refused at the gate with the gate's own reason, and no
        # role lookup was attempted for an identity that carries no role.
        assert hybrid.status_code == 403, hybrid.text
        assert hybrid.json()["detail"] == EXECUTOR_GATE_REFUSAL, hybrid.json()
        assert lookups_after_hybrid == 1, f"executor request performed {lookups_after_hybrid - 1} extra role lookup(s)"


# --- Phase 2: incumbent serial-match exemption (executor-rotation-require-token-400 ruling 2(a)) ---
# Truth table user-confirmed 2026-09-20: C1-C6 + preserved negatives.
# C5/C6 are the ruled-named cells — pinned as NAMED tests (approval condition 2).


def _incumbent_headers(client_app, serial_hex, cn="exec-a"):
    """Write a Root-CA-signed leaf (CN, fixed serial) into the fixture's
    cert prefix and return the forwarded-cert-file header (#314 — the only
    identity carrier; the old X-Client-* trio is retired)."""
    try:
        from .conftest import forwarded_headers, make_leaf
    except ImportError:
        from conftest import forwarded_headers, make_leaf

    ca_cert, ca_key = client_app.state.ca_manager.load_ca()
    cert = make_leaf(ca_cert, ca_key, cn=cn, serial=int(serial_hex, 16))
    return forwarded_headers(client_app.state.test_cert_prefix, cert)


def _foreign_ca_headers(client_app, serial_hex="0000000000001000", cn="exec-a"):
    """Cross-plane leaf: signed by a DIFFERENT CA (admin-plane shape)."""
    try:
        from .conftest import forwarded_headers, make_leaf
    except ImportError:
        from conftest import forwarded_headers, make_leaf

    admin_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    admin_ca = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")]))
        .public_key(admin_key.public_key())
        .serial_number(9)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(admin_key, hashes.SHA256())
    )
    cert = make_leaf(admin_ca, admin_key, cn=cn, serial=int(serial_hex, 16))
    return forwarded_headers(client_app.state.test_cert_prefix, cert)


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
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000"))
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
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000002222"))
        assert resp.status_code == 400
        assert "Enrollment token required" in resp.json()["detail"]

    def test_c3_identity_revoked_no_exemption_even_on_record_match(self, env):
        """C3: identity flag is terminal — exemption refused even with the
        exact record serial in hand (revocation-state check runs FIRST)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, revoked_at=datetime.now(UTC))
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000"))
        assert resp.status_code == 400

    def test_c4_crled_serial_no_exemption_even_on_record_match(self, env):
        """C4: presented serial in the CRL (serial-form on the record) → no exemption."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        _seed_revocation(SessionLocal, "0000000000001000")
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000"))
        assert resp.status_code == 400

    def test_c5_revoked_then_re_enrolled_old_serial_no_exemption(self, env):
        """C5 (RULED-NAMED): an old credential CRLed by F6 after a token
        re-enrollment never regains the exemption — the old serial 400s even
        though a fresh clean record exists."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000009999")  # fresh record post re-enrollment
        _seed_revocation(SessionLocal, "0000000000001000", reason="Replaced by re-registration/rotation")
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000"))
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
            resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000"))
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

    def test_unparseable_cert_pem_no_exemption(self, env):
        """Preserved negative: garbage behind the forwarded-cert header
        verifies as NOTHING → no exemption even though the record serial + CN
        are perfect. #314 content transport: the header carries URL-encoded
        PEM, so the guard here is parse failure (not a filesystem read)."""
        import urllib.parse

        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        bogus = urllib.parse.quote_from_bytes(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")
        resp = _register(client, headers={"x-client-cert-pem": bogus})
        assert resp.status_code == 400

    def test_cn_mismatch_no_exemption(self, env):
        """Paired negative: the record serial presented under a foreign CN → 400
        (CN is the discriminator; serials are not transferable across identities)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_incumbent_headers(client.app, "0000000000001000", cn="exec-b"))
        assert resp.status_code == 400

    def test_empty_cert_pem_header_no_exemption(self, env):
        """An empty forwarded-cert-pem header must not exempt (fails closed)."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers={"x-client-cert-pem": ""})
        assert resp.status_code == 400

    def test_concatenated_cert_pem_no_exemption(self, env):
        """#314 content guard: two concatenated PEM blocks (BEGIN count != 1)
        are refused — a stack of certs is never treated as one identity."""
        import urllib.parse

        try:
            from .conftest import make_leaf, pem_bytes
        except ImportError:
            from conftest import make_leaf, pem_bytes

        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        ca_cert, ca_key = client.app.state.ca_manager.load_ca()
        one = pem_bytes(make_leaf(ca_cert, ca_key, cn="exec-a", serial=int("0000000000001000", 16)))
        stacked = urllib.parse.quote_from_bytes(one + one)
        resp = _register(client, headers={"x-client-cert-pem": stacked})
        assert resp.status_code == 400

    def test_cross_plane_cert_no_exemption(self, env):
        """#314 ruled-Q4 row: an Admin-CA (foreign-chain) cert with the exact
        record serial + CN is refused at the executor-plane chain check."""
        client, SessionLocal = env
        _seed_executor(SessionLocal)
        _seed_cert(SessionLocal, serial="0000000000001000")
        resp = _register(client, headers=_foreign_ca_headers(client.app, "0000000000001000"))
        assert resp.status_code == 400


class TestEnforcementIsLive:
    """#634 AC2 — the paired negative that makes tranche 1 a fix instead of a decoration.

    The row's load-bearing criterion is not "add the pragma", it is "show a cell that FAILS if the
    pragma were silently off". A file can carry a listener nobody's engine uses, or a cell that refuses
    for a reason that has nothing to do with foreign keys (a NOT NULL, a unique index, a mock). Both
    read green forever. These cells are written so that cannot happen here: the SAME insert is made
    against two engines differing in exactly one line — the listener — and the outcomes must differ.

    Re-runnable proof of the dependency, from a clean tree::

        # enforcement installed (this file as committed): 40 cells green, the orphan refused
        # delete the 3-line listener from `env` and re-run:  the 40 come back RED

    That second command is the mutation #634 exists to make expensive, and it is what the interlock in
    ``packages/core/tests/test_sqlite_fk_blindspot_interlock_634.py`` now holds shut.
    """

    def test_the_declared_constraint_actually_refuses_an_orphan_row(self, env):
        """POSITIVE: an executor_certs row with no parent users row is REFUSED.

        Asserted on the real exception the constraint produces, not on a broad ``except``: SQLAlchemy
        wraps the sqlite driver error, and the driver names the class ("FOREIGN KEY constraint failed").
        If enforcement were off this insert would silently succeed and the cell would fail here, not
        somewhere friendlier.
        """
        _client, SessionLocal = env
        from sqlalchemy.exc import IntegrityError

        s = SessionLocal()
        with pytest.raises(IntegrityError) as excinfo:
            s.add(
                ExecutorCert(
                    executor_id="exec-never-registered",  # no users.user_id by this name exists
                    serial_number="000000000000dead",
                    not_before=datetime.now(UTC),
                    not_after=datetime.now(UTC) + timedelta(days=30),
                    fingerprint="AA:BB:CC",
                )
            )
            s.commit()
        assert "FOREIGN KEY constraint failed" in str(excinfo.value), str(excinfo.value)
        s.rollback()
        s.close()

    def test_the_same_insert_is_accepted_when_the_pragma_is_off(self, tmp_path):
        """NEGATIVE: same DDL, same row, no listener — and it is ACCEPTED. This is the dependency proof.

        Without this half the positive cell could be passing on an unrelated constraint and the row
        would re-create its own defect while looking fixed. The only difference between the two engines
        is the three-line ``PRAGMA foreign_keys=ON`` listener.
        """
        blind_engine = create_engine(f"sqlite:///{tmp_path / 'blind.db'}")
        Base.metadata.create_all(blind_engine)
        BlindLocal = sessionmaker(bind=blind_engine)

        s = BlindLocal()
        s.add(
            ExecutorCert(
                executor_id="exec-never-registered",
                serial_number="000000000000dead",
                not_before=datetime.now(UTC),
                not_after=datetime.now(UTC) + timedelta(days=30),
                fingerprint="AA:BB:CC",
            )
        )
        s.commit()  # must NOT raise: the constraint is declared and not consulted
        assert (
            s.query(ExecutorCert).filter_by(executor_id="exec-never-registered").first() is not None
        ), "a blind engine accepted nothing — the negative half is not exercising what it claims"
        s.close()
        blind_engine.dispose()

    def test_the_enforced_engine_is_the_one_the_fixture_hands_out(self, env):
        """Third leg of the triangle: the pragma is live ON the fixture's own connection.

        Proving the two outcomes differ is not quite proving THIS engine is the enforcing one — an
        inherited global listener would also do it. So read the pragma back off the live connection and
        assert the value, the same way the shipped factory-policy file reads it.
        """
        _client, SessionLocal = env
        s = SessionLocal()
        row = s.exec_driver_sql("PRAGMA foreign_keys").first() if hasattr(s, "exec_driver_sql") else None
        if row is None:  # a ORM Session exposes the connectable, not the driver cursor
            row = s.connection().exec_driver_sql("PRAGMA foreign_keys").first()
        assert row is not None and int(row[0]) == 1, f"PRAGMA foreign_keys reads {row!r} on the fixture engine"
        s.close()

    def test_seeding_a_cert_still_works_because_the_parent_is_created(self, env):
        """Guard on the fix itself: the 40 cells went green by ADDING the parent, not by dropping rows.

        If a later seat "fixes" a red here by removing the seed or skipping the assert, this cell is
        the one that says the FK is satisfied by real state.
        """
        _client, SessionLocal = env
        _seed_executor(SessionLocal, executor_id="exec-a")
        _seed_cert(SessionLocal, executor_id="exec-a", serial="0000000000001000")
        s = SessionLocal()
        assert s.query(ExecutorCert).filter_by(executor_id="exec-a").count() == 1
        assert s.query(User).filter_by(user_id="exec-a").first() is not None, "the cert has no machine identity"
        s.close()
