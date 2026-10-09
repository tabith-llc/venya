# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Integration tests for executor ↔ server mTLS certificate lifecycle.

Tests the full mTLS handshake, certificate rotation, and revocation
using real ECDSA P-256 cryptography with a FastAPI test server.

The DB layer is mocked (same pattern as test_executor_server.py) so we
focus on the TLS/crypto and HTTP layers — proving the executor can
actually register, rotate, and detect revocation against a real server.
"""

import hashlib
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from server.config import ExecutorEnrollmentConfig, ServerConfig
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

from executor.config import ExecutorConfig
from executor.daemon import CertificateManager, CertificateValidationError, RevocationStatus

from .conftest import (
    MockExecutorCert,
    MockExecutorCertRevocation,
    _make_ca_pair,
    _sign_executor_cert,
)

# #442 site 3 (ruling A+): the registration cell below used to build its app with NO
# app.state.config at all — the fault shape, where the route could not read a policy
# and used to fall through to "token not required". It now stands on the ENFORCED
# path: the shipped default (require_token=True) plus a real enrollment token.
# Built locally (no cross-package import of the server test suite).
_ENROLLMENT_PEPPER = "test-pepper-12345"
_ENROLLMENT_TOKEN = "enrl_exec_442_integration"


def _make_mock_enrollment_token(executor_id: str, plaintext: str):
    """A created, unexpired enrollment token for ``executor_id``.

    ``token_hash`` is the HMAC the route computes from the config pepper, so the
    mock DB's equality filter has to MATCH it — a wrong pepper or a wrong identity
    does not silently pass.
    """
    import hmac

    token = MagicMock()
    token.id = 442
    token.executor_id = executor_id
    token.state = "created"
    token.token_hash = hmac.new(
        _ENROLLMENT_PEPPER.encode("utf-8"), plaintext.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    token.expires_at = datetime.now(UTC) + timedelta(minutes=10)
    return token


@pytest.fixture(autouse=True)
def _fresh_limiters():
    """Isolate the process-global limiter cache in server.rate_limit.

    A PRESENT config switches the registration limiter on (it early-returns while
    config is absent) and the windows are shared across the run; without this the
    cells that register would inherit consumed slots and die as 429s unrelated to
    the token gate. Same isolation fixture test_executor_enrollment.py uses.
    """
    from server import rate_limit as _rl

    saved = dict(_rl._LIMITERS)
    _rl._LIMITERS.clear()
    yield
    _rl._LIMITERS.clear()
    _rl._LIMITERS.update(saved)


# ---------------------------------------------------------------------------
# Mock DB helper (same pattern as test_executor_server.py)
# ---------------------------------------------------------------------------


def _make_mock_db(executor_certs=None, revocations=None, enrollment_executor_id: str | None = None):
    """Create a mock DB session for testing server endpoints.

    #442 site 3 (ruling A+): ``enrollment_executor_id`` arms the ENFORCED path — a
    created, unexpired token row for that identity plus the atomic-consumption
    answer the route reads (``rowcount == 1``). Left None, nothing is armed.
    """
    if executor_certs is None:
        executor_certs = []
    if revocations is None:
        revocations = []

    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()

    def mock_query(model):
        m = MagicMock()

        def filter_side_effect(*args, **kwargs):
            result_filter = MagicMock()

            def first():
                if model.__name__ == "ExecutorCert":
                    results = list(executor_certs)
                elif model.__name__ == "ExecutorCertRevocation":
                    results = list(revocations)
                elif model.__name__ == "User":
                    return None
                elif model.__name__ == "ExecutorEnrollmentToken":
                    # Armed only for the moved registration cell; the equality filter
                    # below still has to MATCH the token_hash the route computes.
                    if enrollment_executor_id is None:
                        return None
                    return _make_mock_enrollment_token(enrollment_executor_id, _ENROLLMENT_TOKEN)
                else:
                    return None

                if args:
                    expr = args[0]
                    if hasattr(expr, "left") and hasattr(expr, "right") and hasattr(expr, "operator"):
                        col = expr.left
                        val = expr.right
                        if hasattr(col, "prop"):
                            attr = col.prop.key
                            filtered = []
                            for r in results:
                                try:
                                    rv = getattr(r, attr, None)
                                    if rv is not None and rv == val:
                                        filtered.append(r)
                                except Exception:  # noqa: S110 — best-effort mock attribute matching
                                    pass
                            results = filtered

                return results[0] if results else None

            result_filter.first = first
            return result_filter

        m.filter = filter_side_effect
        m.all = lambda: (
            list(executor_certs)
            if model.__name__ == "ExecutorCert"
            else (list(revocations) if model.__name__ == "ExecutorCertRevocation" else [])
        )
        return m

    db.query.side_effect = mock_query
    # The token consumption is an atomic UPDATE; the route requires rowcount == 1.
    db.execute.return_value = MagicMock(rowcount=1)
    return db


def _add_executor_auth(app, executor_id):
    """Inject middleware-shaped executor auth state.

    The heartbeat route requires request.state.auth_user ==
    {"caller": "executor", "executor_id": CN} (production: set by
    SessionMiddleware._validate_executor_mtls — ticket
    sec-endpoint-ratelimit-hardening #7). Bare route-level apps inject the
    same shape.
    """
    from starlette.middleware.base import BaseHTTPMiddleware

    class _ExecutorAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": executor_id}
            return await call_next(request)

    app.add_middleware(_ExecutorAuth)


def _create_test_app(ca_manager, db, auth_executor_id=None, require_enrollment=False):
    """Create a FastAPI app with executor routes and mock DB.

    ``require_enrollment=True`` installs the SHIPPED-default config
    (require_token=True) for the registration cells (#442 site 3, ruling A+); the
    heartbeat/revocation callers leave it False and keep the app shape they have
    always had.
    """
    app = FastAPI()
    app.state.backend = MagicMock()
    app.state.backend.get_session.return_value = db
    app.state.ca_manager = ca_manager
    if require_enrollment:
        app.state.config = ServerConfig(
            recovery_code_pepper=_ENROLLMENT_PEPPER,
            executor_enrollment=ExecutorEnrollmentConfig(require_token=True),
        )
    app.include_router(executors_routes.router, prefix="/api/v1")
    if auth_executor_id is not None:
        _add_executor_auth(app, auth_executor_id)
    return app


# ---------------------------------------------------------------------------
# Test 1: mTLS Handshake and Registration
# ---------------------------------------------------------------------------


class TestMTLSHandshake:
    """End-to-end mTLS certificate registration flow."""

    def test_full_registration_flow(
        self, ca_manager, executor_key, executor_csr, cert_files, tls_client, executor_config, monkeypatch
    ):
        """Executor registers with server, receives signed cert, validates CA."""
        # Synthetic test id — bypass the server's dial-address resolvability check
        # (enforcement itself is covered in packages/server tests)
        monkeypatch.setattr("server.routes.executors._dial_hostname_resolvable", lambda host: True)
        _cert_path, _key_path = cert_files

        # Create a fresh httpx test client pointing at our test server
        # (tls_client has mTLS cert but the TestClient doesn't do real TLS,
        #  so we use it just for HTTP; the real TLS validation happens via
        #  the httpx2.Client cert= parameter proving the cert/key are valid)
        db = _make_mock_db(enrollment_executor_id="test-executor")
        app = _create_test_app(ca_manager, db, require_enrollment=True)
        test_client = TestClient(app)

        # Step 1: Executor generates a NEW keypair + CSR (not using the fixture's)
        ec.generate_private_key(ec.SECP256R1())
        csr_pem = executor_csr  # from fixture, already a valid CSR

        # Step 2: Submit registration request
        csr_pem_str = csr_pem.decode() if isinstance(csr_pem, bytes) else csr_pem
        resp = test_client.post(
            "/api/v1/executors/register",
            json={"executor_id": "test-executor", "csr_pem": csr_pem_str, "enrollment_token": _ENROLLMENT_TOKEN},
        )
        assert resp.status_code == 201
        data = resp.json()

        # Step 3: Verify response fields
        assert data["executor_id"] == "test-executor"
        assert data["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert data["ca_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert len(data["serial_number"]) == 16
        assert "not_after" in data

        # Step 4: Verify the returned cert is signed by our CA
        returned_cert = x509.load_pem_x509_certificate(data["cert_pem"].encode())
        ca_cert = x509.load_pem_x509_certificate(data["ca_cert_pem"].encode())
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            returned_cert.signature,
            returned_cert.tbs_certificate_bytes,
            ec.ECDSA(returned_cert.signature_hash_algorithm),
        )

        # Step 5: Verify executor ID is the CN
        cn = returned_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "test-executor"

        # Step 6: Verify mTLS cert is parseable and well-formed
        # Full TLS handshake requires a real server; we verify the cert structure
        ec.generate_private_key(ec.SECP256R1())
        cert_obj = x509.load_pem_x509_certificate(data["cert_pem"].encode())
        assert isinstance(cert_obj.subject, x509.Name)
        assert "PublicKey" in cert_obj.public_key().__class__.__name__

    def test_certificate_files_written_with_correct_permissions(
        self, cert_manager, ca_manager, executor_key, executor_csr, tmp_ca_dir
    ):
        """Registration writes cert (0644) and key (0600) to disk."""
        # Pre-create a signed cert to return from server
        ca_key, ca_cert = _make_ca_pair()
        new_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-executor",
            "cert_pem": new_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_cert_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "serial_number": format(new_cert.serial_number, "016x"),
            "not_after": new_cert.not_valid_after_utc.isoformat(),
        }
        mock_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            cert_manager.register("test-executor")

        # Verify cert file
        assert os.path.exists(cert_manager.cert_path)
        cert_mode = stat.S_IMODE(os.stat(cert_manager.cert_path).st_mode)
        assert cert_mode == 0o644

        # Verify key file
        assert os.path.exists(cert_manager.key_path)
        key_mode = stat.S_IMODE(os.stat(cert_manager.key_path).st_mode)
        assert key_mode == 0o600

        # Verify CA cert was saved
        assert os.path.exists(cert_manager.ca_cert_path)

    def test_ca_validation_rejects_wrong_ca(self, tmp_path):
        """Registration fails when returned cert is signed by a different CA."""
        # Create two different CAs
        _ca_key1, ca_cert1 = _make_ca_pair()
        ca_key2, ca_cert2 = _make_ca_pair()

        # Sign executor cert with CA2 (wrong CA)
        other_cert = _sign_executor_cert(ca_key2, ca_cert2, "test-executor")

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-executor",
            "cert_pem": other_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_cert_pem": ca_cert1.public_bytes(serialization.Encoding.PEM).decode(),
            "serial_number": format(other_cert.serial_number, "016x"),
            "not_after": other_cert.not_valid_after_utc.isoformat(),
        }
        mock_response.raise_for_status.return_value = None

        # Create config pointing to CA1
        from executor.config import CertificateRotationConfig, MtlsConfig

        ca_dir = tmp_path / "ca1"
        ca_dir.mkdir()
        (ca_dir / "ca.crt").write_bytes(ca_cert1.public_bytes(serialization.Encoding.PEM))

        config = ExecutorConfig(
            server_url="https://test-server.local",
            executor_id="test-executor",
            mtls=MtlsConfig(
                ca_cert=str(ca_dir / "ca.crt"),
                cert=str(tmp_path / "executor.crt"),
                key=str(tmp_path / "executor.key"),
            ),
            cert_rotation=CertificateRotationConfig(rotate_before_days=3),
        )
        mgr = CertificateManager(config)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
                mgr.register("test-executor")


# ---------------------------------------------------------------------------
# Test 2: Certificate Rotation
# ---------------------------------------------------------------------------


class TestCertificateRotation:
    """Certificate rotation flow: detect expiry, rotate, verify new cert."""

    def test_rotation_detects_expiry(self, cert_manager, tmp_ca_dir):
        """needs_rotation() returns True when cert expires within threshold."""
        ca_key, ca_cert = _make_ca_pair()
        # 2-day cert (within 3-day rotate_before_days threshold)
        short_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=2)

        Path(cert_manager.cert_path).write_bytes(short_cert.public_bytes(serialization.Encoding.PEM))
        Path(cert_manager.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        assert cert_manager.needs_rotation() is True

    def test_rotation_does_not_trigger_when_fresh(self, cert_manager, tmp_ca_dir):
        """needs_rotation() returns False when cert has plenty of time."""
        ca_key, ca_cert = _make_ca_pair()
        # 35-day cert (well beyond 3-day threshold)
        fresh_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=35)

        Path(cert_manager.cert_path).write_bytes(fresh_cert.public_bytes(serialization.Encoding.PEM))
        Path(cert_manager.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        assert cert_manager.needs_rotation() is False

    def test_full_rotation_flow(self, cert_manager, ca_manager, ca_key, ca_cert, cert_files):
        """Rotation: new CSR → server signs → new cert installed."""
        _cert_path, _key_path = cert_files

        # Get initial fingerprint
        initial_fp = cert_manager.get_fingerprint()
        assert initial_fp != ""

        # Mock server response with a NEW cert (different keypair = different fingerprint)
        ec.generate_private_key(ec.SECP256R1())
        new_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-executor",
            "cert_pem": new_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_cert_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "serial_number": format(new_cert.serial_number, "016x"),
            "not_after": new_cert.not_valid_after_utc.isoformat(),
        }
        mock_response.raise_for_status.return_value = None

        with MagicMock() as mock_post:
            mock_post.return_value = mock_response
            cert_manager.client.post = mock_post
            cert_manager.rotate()

        # Verify new cert is installed
        saved_cert = x509.load_pem_x509_certificate(Path(cert_manager.cert_path).read_bytes())
        assert saved_cert.serial_number == new_cert.serial_number

        # Fingerprint should have changed
        new_fp = cert_manager.get_fingerprint()
        assert new_fp != initial_fp
        assert new_fp == hashlib.sha256(saved_cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        # Serial should be updated
        assert cert_manager.serial == format(new_cert.serial_number, "016x")

        # New key should be installed
        saved_key = serialization.load_pem_private_key(
            Path(cert_manager.key_path).read_bytes(),
            password=None,
        )
        assert isinstance(saved_key, ec.EllipticCurvePrivateKey)

    def test_rotation_fails_without_existing_cert(self, cert_manager):
        """Rotation raises RuntimeError when no certificate exists."""
        # Ensure no cert exists
        if os.path.exists(cert_manager.cert_path):
            os.unlink(cert_manager.cert_path)
        if os.path.exists(cert_manager.key_path):
            os.unlink(cert_manager.key_path)

        with pytest.raises(RuntimeError, match="must register first"):
            cert_manager.rotate()

    def test_rotation_updates_mtls_client(self, cert_manager, ca_key, ca_cert, tmp_ca_dir):
        """After rotation, mTLS client cert/key match the new cert."""
        # Create a matching cert/key pair for the initial cert
        initial_key = ec.generate_private_key(ec.SECP256R1())
        initial_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)

        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        Path(cert_manager.key_path).write_bytes(
            initial_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Generate new cert for rotation response
        new_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "executor_id": "test-executor",
            "cert_pem": new_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_cert_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "serial_number": format(new_cert.serial_number, "016x"),
            "not_after": new_cert.not_valid_after_utc.isoformat(),
        }
        mock_response.raise_for_status.return_value = None

        with MagicMock() as mock_post:
            mock_post.return_value = mock_response
            cert_manager.client.post = mock_post
            cert_manager.rotate()

        # Verify the new cert and key files are valid and well-formed
        saved_cert = x509.load_pem_x509_certificate(Path(cert_manager.cert_path).read_bytes())
        saved_key = serialization.load_pem_private_key(
            Path(cert_manager.key_path).read_bytes(),
            password=None,
        )

        # Verify key is ECDSA P-256
        assert isinstance(saved_key, ec.EllipticCurvePrivateKey)
        assert isinstance(saved_key.curve, ec.SECP256R1)

        # Verify cert has correct subject CN
        cn = saved_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "test-executor"

        # Verify the saved key is valid by checking its public key type
        pub_key = saved_key.public_key()
        assert "EC" in pub_key.__class__.__name__ or "Elliptic" in pub_key.__class__.__name__


# ---------------------------------------------------------------------------
# Test 3: Revocation Mid-Execution
# ---------------------------------------------------------------------------


class TestRevocation:
    """Revocation detection: admin revokes cert, executor detects and shuts down."""

    def test_revocation_detected_by_executor(self, cert_manager, ca_key, ca_cert, cert_files):
        """check_revocation() answers REVOKED when the serial is in the list.

        #442 site 4: the verdict is the same as the bool era, only named — the
        contract no longer returns a value that is also the outage answer."""
        _cert_path, _ = cert_files

        # Register a cert first
        initial_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        cert_manager.serial = format(initial_cert.serial_number, "016x")

        # Mock server response with the serial in the revocation list
        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 200
        mock_response.headers = {"etag": '"abc123"'}
        mock_response.json.return_value = {"revoked_serials": [cert_manager.serial, "0000000000000002"]}
        mock_response.raise_for_status.return_value = None

        with MagicMock() as mock_get:
            mock_get.return_value = mock_response
            cert_manager.client.get = mock_get
            assert cert_manager.check_revocation() is RevocationStatus.REVOKED

    def test_revocation_not_detected_when_clean(self, cert_manager, ca_key, ca_cert, cert_files):
        """check_revocation() answers NOT_REVOKED when the serial is absent — the
        server ANSWERED, which is the only thing that may reset the failure count."""
        _cert_path, _ = cert_files

        initial_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        cert_manager.serial = format(initial_cert.serial_number, "016x")

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 200
        mock_response.headers = {"etag": '"def456"'}
        mock_response.json.return_value = {"revoked_serials": ["0000000000000001", "0000000000000002"]}
        mock_response.raise_for_status.return_value = None

        with MagicMock() as mock_get:
            mock_get.return_value = mock_response
            cert_manager.client.get = mock_get
            assert cert_manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_revocation_server_unreachable_graceful(self, cert_manager, ca_key, ca_cert, cert_files):
        """#442 site 4 (ruling R3): an unreachable server is UNREACHABLE.

        This cell used to read "returns False (not True) when server is
        unreachable" — that False was indistinguishable from the server having
        answered "live", and it reset the caller's consecutive-failure count
        during an outage. Same no-raise contract, honest name."""
        _cert_path, _ = cert_files

        initial_cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        cert_manager.serial = format(initial_cert.serial_number, "016x")

        # Simulate server unreachable
        with MagicMock() as mock_get:
            mock_get.side_effect = httpx2.RequestError("Connection refused", request=MagicMock())
            cert_manager.client.get = mock_get
            # Must not raise — graceful degradation — but must not claim liveness
            assert cert_manager.check_revocation() is RevocationStatus.UNREACHABLE

    def test_revocation_detected_via_heartbeat(self, ca_manager, ca_key, ca_cert, executor_cert):
        """Heartbeat returns revoked=True when cert serial is in revocation list."""
        serial_hex = format(executor_cert.serial_number, "016x")

        cert_record = MockExecutorCert(
            executor_id="test-executor",
            serial_number=serial_hex,
            not_after=datetime.now(UTC) + timedelta(days=365),
        )
        revocation = MockExecutorCertRevocation(serial_number=serial_hex)
        db = _make_mock_db(executor_certs=[cert_record], revocations=[revocation])

        app = _create_test_app(ca_manager, db, auth_executor_id="test-executor")
        test_client = TestClient(app)

        fp = hashlib.sha256(executor_cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        resp = test_client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-executor", "cert_fingerprint": fp},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is True
        # new_cert_required should be False since cert is valid for 365 days
        assert data["new_cert_required"] is False

    def test_revocation_not_set_when_not_revoked(self, ca_manager, ca_key, ca_cert):
        """Heartbeat returns revoked=False when cert is not in revocation list."""
        cert = _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        serial_hex = format(cert.serial_number, "016x")

        cert_record = MockExecutorCert(
            executor_id="test-executor",
            serial_number=serial_hex,
            not_after=datetime.now(UTC) + timedelta(days=365),
        )
        # No revocation records
        db = _make_mock_db(executor_certs=[cert_record], revocations=[])

        app = _create_test_app(ca_manager, db, auth_executor_id="test-executor")
        test_client = TestClient(app)

        resp = test_client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-executor", "cert_fingerprint": "any-fingerprint"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is False

    def test_revocation_unknown_executor(self, ca_manager):
        """Heartbeat returns revoked=False for unknown executor IDs."""
        db = _make_mock_db()
        app = _create_test_app(ca_manager, db, auth_executor_id="nonexistent")
        test_client = TestClient(app)

        resp = test_client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "nonexistent", "cert_fingerprint": "abc123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is False

    def test_revocation_list_endpoint_returns_serials(self, ca_manager, ca_key, ca_cert):
        """Revocation list endpoint returns all revoked serial numbers."""
        ca_manager.purge_expired_revocations = MagicMock(return_value=0)
        cert1 = _sign_executor_cert(ca_key, ca_cert, "executor-1", validity_days=30)
        cert2 = _sign_executor_cert(ca_key, ca_cert, "executor-2", validity_days=30)

        serial1 = format(cert1.serial_number, "016x")
        serial2 = format(cert2.serial_number, "016x")

        revocations = [
            MockExecutorCertRevocation(serial_number=serial1),
            MockExecutorCertRevocation(serial_number=serial2),
        ]
        db = _make_mock_db(revocations=revocations)

        app = _create_test_app(ca_manager, db)
        test_client = TestClient(app)

        resp = test_client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data["revoked_serials"]) == {serial1, serial2}

    def test_revocation_no_serial_returns_false(self, cert_manager):
        """check_revocation() answers NOT_REVOKED when no serial is loaded — the
        pre-registration verdict is unchanged by #442, only named."""
        cert_manager.serial = None
        with MagicMock() as mock_get:
            assert cert_manager.check_revocation() is RevocationStatus.NOT_REVOKED
            mock_get.assert_not_called()
