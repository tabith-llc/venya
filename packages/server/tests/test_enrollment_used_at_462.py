# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#462 enrollment-token ``used_at`` records the true clock, not the check clock.

``register_executor`` consumes its enrollment token with ONE bound value
(``effective_expiry_check_time(tolerance)`` = true now minus tolerance) serving
two purposes: the expiry WHERE-predicate (correct — the skew relaxation is by
design) and ``SET ... used_at = :now`` (wrong — the forensic column lands up to
``tolerance`` seconds earlier than the real consumption, and disagrees with the
``executor_registered`` audit event written in the same request).

Cells (truth table, per ticket AC 1-3):
- AC2 positive: with a NONZERO tolerance, the consumed token's ``used_at`` is
  within a second of the request time.
- AC2 relaxation intact: a token already expired BUT inside tolerance still
  registers (the predicate keeps the tolerance-adjusted clock).
- AC3 paired negative: a token expired OUTSIDE tolerance is still refused —
  401, the class the pre-check raises (see the existing
  ``test_token_expired_returns_401`` sibling, untouched here).
- Discovery: the audit event timestamp and ``used_at`` AGREE within a second at
  the fixed tip and diverge by the tolerance at base.

Real SQLite throughout — the consumption is a raw ``text()`` UPDATE, so a mock
session would never show what the column actually holds. The ORM precedent for
the true clock is ``core/iam/enrollment_manager.py:204``
(``token.used_at = datetime.now(UTC)``).
"""

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from core.iam.models import AuditEvent, Base, ExecutorEnrollmentToken
from fastapi import FastAPI
from server.config import ClockSkewConfig, ExecutorEnrollmentConfig, ServerConfig
from server.routes import executors as executors_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

PEPPER = "test-pepper-462"
TOLERANCE = 60  # nonzero by design — the defect only shows with a skew window


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Isolate the module-level limiter cache (same posture as the enrollment suite)."""
    from server import rate_limit as _rl

    saved = dict(_rl._LIMITERS)
    _rl._LIMITERS.clear()
    yield
    _rl._LIMITERS.clear()
    _rl._LIMITERS.update(saved)


def _token_hash(plaintext: str) -> str:
    return hmac.new(PEPPER.encode("utf-8"), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()


def _make_mock_ca():
    """CA stub: registration reaches the DB only after signing succeeds."""
    mock_ca = MagicMock()
    mock_cert = MagicMock()
    mock_cert.serial_number = 462
    mock_cert.not_valid_before_utc = datetime.now(UTC)
    mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
    mock_cert.public_bytes.return_value = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    mock_ca.sign_csr.return_value = mock_cert
    mock_ca.compute_serial_hex.return_value = "00:00:00:00:00:00:01:ce"
    mock_ca.compute_fingerprint.return_value = "SHA256:46:46"
    mock_ca.get_ca_cert_pem.return_value = b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
    return mock_ca


def _build(tmp_path, tolerance: int = TOLERANCE):
    """Real SQLite + the real register route, with a configured skew tolerance."""
    engine = create_engine(f"sqlite:///{tmp_path / 'used462.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.ca_manager = _make_mock_ca()
    app.state.config = ServerConfig(
        recovery_code_pepper=PEPPER,
        clock_skew=ClockSkewConfig(token_tolerance_seconds=tolerance),
        executor_enrollment=ExecutorEnrollmentConfig(require_token=False),
    )
    app.include_router(executors_routes.router, prefix="/api/v1")

    client = TestClient(app, raise_server_exceptions=False)
    return SessionLocal, client


def _seed_token(SessionLocal, executor_id: str, plaintext: str, expires_at: datetime):
    s = SessionLocal()
    s.add(
        ExecutorEnrollmentToken(
            executor_id=executor_id,
            token_hash=_token_hash(plaintext),
            state="created",
            created_by="admin",
            expires_at=expires_at,
        )
    )
    s.commit()
    s.close()


def _register(client, executor_id: str, plaintext: str, csr_pem: str):
    return client.post(
        "/api/v1/executors/register",
        json={"executor_id": executor_id, "csr_pem": csr_pem, "enrollment_token": plaintext},
    )


def _as_utc(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; treat them as the UTC they were written as."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class TestUsedAtTrueClock:
    """AC2 — the record column carries the consumption time, not the check time."""

    def test_used_at_matches_request_time_with_nonzero_tolerance(self, tmp_path, _executor_ids_resolvable):
        """Consumed token's used_at is within ~1s of the real request time."""
        SessionLocal, client = _build(tmp_path, tolerance=TOLERANCE)
        _seed_token(SessionLocal, "used462-a", "enrl_exec_used462_a", datetime.now(UTC) + timedelta(minutes=10))

        before = datetime.now(UTC)
        response = _register(client, "used462-a", "enrl_exec_used462_a", _csr())
        after = datetime.now(UTC)

        assert response.status_code == 201, response.text

        s = SessionLocal()
        token = s.query(ExecutorEnrollmentToken).filter_by(executor_id="used462-a").one()
        assert token.state == "consumed"
        assert token.used_at is not None
        used_at = _as_utc(token.used_at)
        s.close()

        # Base behaviour: used_at == now - tolerance (60s early) -> this fails.
        drift_before = (before - used_at).total_seconds()
        drift_after = (used_at - after).total_seconds()
        assert -1.0 <= drift_before <= 1.0, f"used_at is {drift_before}s before the request window"
        assert -1.0 <= drift_after <= 1.0, f"used_at is {drift_after}s after the request window"

    def test_audit_event_and_used_at_agree(self, tmp_path, _executor_ids_resolvable):
        """Discovery cell: the DB row and its own audit twin carry one clock.

        At base these diverge by the configured tolerance (the audit event is
        written on the true clock, used_at on the shifted one).
        """
        SessionLocal, client = _build(tmp_path, tolerance=TOLERANCE)
        _seed_token(SessionLocal, "used462-b", "enrl_exec_used462_b", datetime.now(UTC) + timedelta(minutes=10))

        response = _register(client, "used462-b", "enrl_exec_used462_b", _csr())
        assert response.status_code == 201, response.text

        s = SessionLocal()
        token = s.query(ExecutorEnrollmentToken).filter_by(executor_id="used462-b").one()
        audit = s.query(AuditEvent).filter_by(event_type="executor_registered").one()
        gap = abs((_as_utc(audit.timestamp) - _as_utc(token.used_at)).total_seconds())
        s.close()

        assert gap <= 1.0, f"used_at and the executor_registered audit event differ by {gap:.1f}s"


class TestSkewRelaxationIntact:
    """AC2 second half + AC3 paired negative — the predicate keeps the tolerance."""

    def test_expired_within_tolerance_still_registers(self, tmp_path, _executor_ids_resolvable):
        """A token 30s past expiry inside a 60s window is still accepted."""
        SessionLocal, client = _build(tmp_path, tolerance=TOLERANCE)
        _seed_token(SessionLocal, "used462-c", "enrl_exec_used462_c", datetime.now(UTC) - timedelta(seconds=30))

        response = _register(client, "used462-c", "enrl_exec_used462_c", _csr())
        assert response.status_code == 201, response.text

        s = SessionLocal()
        token = s.query(ExecutorEnrollmentToken).filter_by(executor_id="used462-c").one()
        assert token.state == "consumed"
        s.close()

    def test_expired_outside_tolerance_still_refused(self, tmp_path, _executor_ids_resolvable):
        """Paired negative: 300s past expiry against a 60s window is a 401.

        Refusal class quoted from the existing sibling
        ``test_token_expired_returns_401`` (pre-check raises 401 "expired");
        no existing assertion was touched.
        """
        SessionLocal, client = _build(tmp_path, tolerance=TOLERANCE)
        expired = datetime.now(UTC) - timedelta(seconds=300)
        _seed_token(SessionLocal, "used462-d", "enrl_exec_used462_d", expired)

        response = _register(client, "used462-d", "enrl_exec_used462_d", _csr())
        assert response.status_code == 401, response.text
        assert "expired" in response.json()["detail"].lower()

        s = SessionLocal()
        token = s.query(ExecutorEnrollmentToken).filter_by(executor_id="used462-d").one()
        assert token.state == "created"
        assert token.used_at is None
        s.close()


def _csr() -> str:
    """Fresh P-256 CSR for the registration body."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "used462")])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()
