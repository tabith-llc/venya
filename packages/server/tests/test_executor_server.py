"""Server-side tests for executor registration, revocation, heartbeat, and CA manager."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from starlette.testclient import TestClient

from server.ca import CAManager
from server.routes import executors as executors_routes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_dir(tmp_path):
    """Create a temporary CA directory."""
    d = tmp_path / "ca"
    d.mkdir()
    return str(d)


@pytest.fixture
def ca_manager(ca_dir):
    """Create and initialize a CAManager."""
    manager = CAManager(ca_dir)
    manager.initialize()
    return manager


@pytest.fixture
def executor_keypair():
    """Generate an ECDSA P-256 keypair for testing."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def executor_csr(executor_keypair):
    """Create a CSR for testing."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(executor_keypair, hashes.SHA256())
    )
    return csr


@pytest.fixture
def signed_cert(ca_manager, executor_keypair):
    """Create a signed certificate for testing."""
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-executor")])
    ).sign(executor_keypair, hashes.SHA256())
    return ca_manager.sign_csr(csr, "test-executor")


# ---------------------------------------------------------------------------
# Data classes for mock DB records
# ---------------------------------------------------------------------------


@dataclass
class MockExecutorCert:
    executor_id: str
    serial_number: str
    not_after: object  # datetime or mock


@dataclass
class MockExecutorCertRevocation:
    serial_number: str


# ---------------------------------------------------------------------------
# CAManager tests
# ---------------------------------------------------------------------------


class TestCAManager:
    """Tests for CAManager."""

    def test_initialize_creates_ca_files(self, ca_dir):
        manager = CAManager(ca_dir)
        assert not manager.has_ca
        manager.initialize()
        assert manager.has_ca
        key_path = Path(ca_dir) / "ca.key"
        cert_path = Path(ca_dir) / "ca.crt"
        assert key_path.exists()
        assert cert_path.exists()
        assert oct(key_path.stat().st_mode)[-3:] == "600"
        assert oct(cert_path.stat().st_mode)[-3:] == "644"

    def test_initialize_fails_when_ca_exists(self, ca_manager):
        with pytest.raises(RuntimeError, match="already exists"):
            ca_manager.initialize()

    def test_load_ca_returns_valid_cert_and_key(self, ca_manager):
        cert, key = ca_manager.load_ca()
        assert isinstance(cert, x509.Certificate)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_sign_csr_produces_valid_cert(self, ca_manager, executor_keypair):
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "my-executor")])
        ).sign(executor_keypair, hashes.SHA256())
        cert = ca_manager.sign_csr(csr, "my-executor")
        ca_cert, ca_key = ca_manager.load_ca()
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "my-executor"

    def test_sign_csr_replaces_csr_cn_with_executor_id(self, ca_manager, executor_keypair):
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-cn")])
        ).sign(executor_keypair, hashes.SHA256())
        cert = ca_manager.sign_csr(csr, "correct-executor-id")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "correct-executor-id"

    def test_compute_fingerprint_matches_der_hash(self, ca_manager, signed_cert):
        fp = ca_manager.compute_fingerprint(signed_cert)
        der = signed_cert.public_bytes(serialization.Encoding.DER)
        expected = hashlib.sha256(der).hexdigest()
        assert fp == expected

    def test_compute_serial_hex_format(self, ca_manager, signed_cert):
        serial_hex = ca_manager.compute_serial_hex(signed_cert.serial_number)
        assert len(serial_hex) == 16
        assert serial_hex == serial_hex.lower()
        int(serial_hex, 16)

    def test_get_ca_cert_pem(self, ca_manager):
        pem = ca_manager.get_ca_cert_pem()
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")

    def test_restore_ca_key_rejects_invalid_padding(self, ca_dir):
        """restore_ca_key() should reject invalid PKCS7 padding (M-26)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        # Craft a valid encrypted payload: salt(16) + iv(16) + ciphertext
        passphrase = b"test_passphrase"
        salt = b"\x00" * 16
        iv = b"\x01" * 16

        # Derive key the same way restore_ca_key does
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
        key = kdf.derive(passphrase)

        # Encrypt a minimal PEM-like plaintext with AES-CBC
        plaintext = b"-----BEGIN PRIVATE KEY-----\ntest data here\n-----END PRIVATE KEY-----\n"
        # PKCS7 pad
        pad_len = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([pad_len]) * pad_len

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Create valid payload
        valid_payload = salt + iv + ciphertext

        # Corrupt the last byte of the ciphertext to break padding
        corrupted_ciphertext = bytearray(ciphertext)
        corrupted_ciphertext[-1] ^= 0xFF
        corrupted_payload = salt + iv + bytes(corrupted_ciphertext)

        manager = CAManager(ca_dir)

        # Valid payload should succeed (writes to disk)
        manager.restore_ca_key(valid_payload, "test_passphrase")
        assert Path(ca_dir, "ca.key").exists()

        # Corrupted payload should be rejected
        with pytest.raises(ValueError, match="Invalid passphrase or corrupted data"):
            manager.restore_ca_key(corrupted_payload, "test_passphrase")


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_mock_db(executor_certs=None, revocations=None):
    """Create a mock DB session for testing endpoints."""
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
                else:
                    return None

                # Apply simple equality filters from SQLAlchemy BinaryExpression
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
                                except Exception:
                                    pass
                            results = filtered

                return results[0] if results else None

            result_filter.first = first
            return result_filter

        m.filter = filter_side_effect
        m.all = lambda: list(executor_certs) if model.__name__ == "ExecutorCert" else (list(revocations) if model.__name__ == "ExecutorCertRevocation" else [])
        return m

    db.query.side_effect = mock_query
    return db


# ---------------------------------------------------------------------------
# Executor registration endpoint tests
# ---------------------------------------------------------------------------


class TestExecutorRegistration:
    """Tests for POST /executors/register."""

    def _create_app(self, ca_manager, db):
        app = FastAPI()
        app.state.backend = MagicMock()
        app.state.backend.get_session.return_value = db
        app.state.ca_manager = ca_manager
        app.include_router(executors_routes.router, prefix="/api/v1")
        return app

    def test_register_success(self, ca_manager, executor_csr, executor_keypair):
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        csr_pem = executor_csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "test-exec-1", "csr_pem": csr_pem},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["executor_id"] == "test-exec-1"
        assert data["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert data["ca_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert len(data["serial_number"]) == 16
        assert "not_after" in data

    def test_register_invalid_csr_returns_400(self, ca_manager):
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "test", "csr_pem": "not-a-valid-csr"},
        )
        assert resp.status_code == 400

    def test_register_weak_ecdsa_curve_returns_400(self, ca_manager):
        """CSR with weak ECDSA curve (P-192) is rejected."""
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app, raise_server_exceptions=False)
        weak_key = ec.generate_private_key(ec.SECP192R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak-ecdsa")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(weak_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "weak-ecdsa", "csr_pem": csr_pem},
        )
        assert resp.status_code == 400
        assert "curve" in resp.json()["detail"].lower() or "unsupported" in resp.json()["detail"].lower()

    def test_register_auto_creates_user(self, ca_manager, executor_csr, executor_keypair):
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        csr_pem = executor_csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "new-exec", "csr_pem": csr_pem},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["executor_id"] == "new-exec"


# ---------------------------------------------------------------------------
# Revocation list endpoint tests
# ---------------------------------------------------------------------------


class TestRevocationList:
    """Tests for GET /executors/certs/revocation-list."""

    def _create_app(self, ca_manager, db):
        app = FastAPI()
        app.state.backend = MagicMock()
        app.state.backend.get_session.return_value = db
        ca_manager.purge_expired_revocations = MagicMock(return_value=0)
        app.state.ca_manager = ca_manager
        app.include_router(executors_routes.router, prefix="/api/v1")
        return app

    def test_empty_revocation_list(self, ca_manager):
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked_serials"] == []

    def test_revocation_list_with_entries(self, ca_manager):
        revocations = [
            MockExecutorCertRevocation(serial_number="abc123def4560001"),
            MockExecutorCertRevocation(serial_number="abc123def4560002"),
        ]
        db = _make_mock_db(revocations=revocations)
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data["revoked_serials"]) == {"abc123def4560001", "abc123def4560002"}

    def test_revocation_list_returns_etag(self, ca_manager):
        """GET /executors/certs/revocation-list should return an ETag header."""
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        assert "etag" in resp.headers

    def test_revocation_list_304_on_etag_match(self, ca_manager):
        """GET /executors/certs/revocation-list should return 304 when ETag matches."""
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)

        resp1 = client.get("/api/v1/executors/certs/revocation-list")
        assert resp1.status_code == 200
        etag = resp1.headers["etag"]

        resp2 = client.get("/api/v1/executors/certs/revocation-list", headers={"If-None-Match": etag})
        assert resp2.status_code == 304
        assert resp2.headers["etag"] == etag

    def test_revocation_list_cache_control(self, ca_manager):
        """GET /executors/certs/revocation-list should return Cache-Control header."""
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.get("/api/v1/executors/certs/revocation-list")
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "max-age=300"


# ---------------------------------------------------------------------------
# Heartbeat endpoint tests
# ---------------------------------------------------------------------------


class TestHeartbeat:
    """Tests for POST /heartbeat."""

    def _create_app(self, ca_manager, db):
        app = FastAPI()
        app.state.backend = MagicMock()
        app.state.backend.get_session.return_value = db
        app.state.ca_manager = ca_manager
        app.include_router(executors_routes.router, prefix="/api/v1")
        return app

    def test_heartbeat_no_executor(self, ca_manager):
        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "unknown-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is False
        assert data["new_cert_required"] is False

    def test_heartbeat_revoked_executor(self, ca_manager):
        from datetime import datetime, timezone, timedelta
        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
        )
        revocation = MockExecutorCertRevocation(serial_number="abc123")
        db = _make_mock_db(executor_certs=[cert_record], revocations=[revocation])
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revoked"] is True

    def test_heartbeat_cert_expiring_soon(self, ca_manager):
        from datetime import datetime, timezone, timedelta
        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db = _make_mock_db(executor_certs=[cert_record])
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["new_cert_required"] is True

    def test_heartbeat_cert_not_expiring(self, ca_manager):
        from datetime import datetime, timezone, timedelta
        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(timezone.utc) + timedelta(days=20),
        )
        db = _make_mock_db(executor_certs=[cert_record])
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["new_cert_required"] is False
