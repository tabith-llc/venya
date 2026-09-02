"""Server-side tests for executor registration, revocation, heartbeat, and CA manager."""

import hashlib
import types
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from server.ca import CAManager
from server.routes import executors as executors_routes
from starlette.testclient import TestClient

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
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(executor_keypair, hashes.SHA256())
    return csr


@pytest.fixture
def signed_cert(ca_manager, executor_keypair):
    """Create a signed certificate for testing."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-executor")]))
        .sign(executor_keypair, hashes.SHA256())
    )
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
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "my-executor")]))
            .sign(executor_keypair, hashes.SHA256())
        )
        cert = ca_manager.sign_csr(csr, "my-executor")
        ca_cert, _ca_key = ca_manager.load_ca()
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
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
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-cn")]))
            .sign(executor_keypair, hashes.SHA256())
        )
        cert = ca_manager.sign_csr(csr, "correct-executor-id")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "correct-executor-id"

    def test_sign_csr_dual_eku(self, ca_manager, executor_keypair):
        """Executor leaf must carry both serverAuth and clientAuth EKU.

        The relay listener (B0.1) presents the executor leaf as a TLS server
        cert, while the executor also uses it as a TLS client for
        registration/heartbeat. A clientAuth-only leaf causes
        num=26 (unsuitable certificate purpose) on the core's outbound relay
        context (e2e-discovered, 2026-09-02).
        """
        from cryptography.x509.oid import ExtendedKeyUsageOID

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ektor")]))
            .sign(executor_keypair, hashes.SHA256())
        )
        cert = ca_manager.sign_csr(csr, "ektor")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_sign_csr_has_aki_and_ski(self, ca_manager, executor_keypair):
        """Executor leaf must carry AKI and SKI (e2e-discovered: Python ssl
        rejects cert chains where the intermediate/leaf lacks AKI with
        Missing Authority Key Identifier)."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aki-check")]))
            .sign(executor_keypair, hashes.SHA256())
        )
        cert = ca_manager.sign_csr(csr, "aki-check")
        # AKI points to the CA
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki.value.key_identifier is not None
        # SKI is the leaf's own key hash
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski.value.digest is not None

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

    def test_restore_ca_key_rejects_corrupted_data(self, ca_dir):
        """restore_ca_key() should reject tampered or wrong-passphrase data (AES-GCM)."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # Craft a valid encrypted payload: salt(16) + nonce(12) + ciphertext(tag auto-appended)
        passphrase = b"test_passphrase"
        salt = b"\x00" * 16
        nonce = b"\x01" * 12

        # Derive key the same way restore_ca_key does
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
        key = kdf.derive(passphrase)

        # Encrypt a minimal PEM-like plaintext with AES-GCM
        plaintext = b"-----BEGIN PRIVATE KEY-----\ntest data here\n-----END PRIVATE KEY-----\n"

        cipher = AESGCM(key)
        encrypted = cipher.encrypt(nonce, plaintext, None)

        # Create valid payload
        valid_payload = salt + nonce + encrypted

        manager = CAManager(ca_dir)

        # Valid payload should succeed (writes to disk)
        manager.restore_ca_key(valid_payload, "test_passphrase")
        assert Path(ca_dir, "ca.key").exists()

        # Corrupted ciphertext should be rejected by GCM tag check
        corrupted_ciphertext = bytearray(encrypted)
        corrupted_ciphertext[-1] ^= 0xFF
        corrupted_payload = salt + nonce + bytes(corrupted_ciphertext)
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
    return db


# ---------------------------------------------------------------------------
# Hostname resolution helper
# ---------------------------------------------------------------------------


class TestResolveExecutorHostname:
    """Pure-function tests for the non-null hostname contract (S1)."""

    def _request(self, client_host):
        if client_host is None:
            return types.SimpleNamespace(client=None)
        return types.SimpleNamespace(client=types.SimpleNamespace(host=client_host))

    def test_client_supplied_wins(self):
        req = types.SimpleNamespace(hostname="exec-1.internal")
        assert executors_routes.resolve_executor_hostname(self._request("127.0.0.1"), req) == "exec-1.internal"

    def test_client_supplied_is_stripped(self):
        req = types.SimpleNamespace(hostname="  exec-1.internal  ")
        assert executors_routes.resolve_executor_hostname(self._request("127.0.0.1"), req) == "exec-1.internal"

    def test_falls_back_to_forwarded_address(self):
        req = types.SimpleNamespace(hostname=None)
        assert executors_routes.resolve_executor_hostname(self._request("10.27.28.14"), req) == "10.27.28.14"

    def test_blank_supplied_falls_back_to_forwarded(self):
        req = types.SimpleNamespace(hostname="   ")
        assert executors_routes.resolve_executor_hostname(self._request("10.27.28.14"), req) == "10.27.28.14"

    def test_none_client_returns_sentinel(self):
        from server.routes.executors import UNRESOLVED_HOST

        req = types.SimpleNamespace(hostname=None)
        r = executors_routes.resolve_executor_hostname(self._request(None), req)
        assert r == UNRESOLVED_HOST
        # The contract the column depends on: never NULL.
        assert r != ""
        assert r is not None


# ---------------------------------------------------------------------------
# Executor registration endpoint tests
# ---------------------------------------------------------------------------


class TestExecutorRegistration:
    """Tests for POST /executors/register."""

    def _make_db_with_executor(self, db, existing):
        """Wrap db.query so Executor lookups return ``existing`` (else None)."""
        orig = db.query.side_effect

        def q(model):
            if model.__name__ == "Executor":
                m = MagicMock()
                m.all = list
                m.filter = lambda *a, **k: MagicMock(first=lambda: existing)
                return m
            return orig(model) if callable(orig) else MagicMock()

        db.query.side_effect = q

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
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(weak_key, hashes.SHA256())
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

    def test_register_stores_supplied_hostname(self, ca_manager, executor_csr, executor_keypair):
        from core.iam.models import Executor

        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        csr_pem = executor_csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "web-server-3", "csr_pem": csr_pem, "hostname": "web-server-3.internal"},
        )
        assert resp.status_code == 201
        added = [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], Executor)]
        assert len(added) == 1
        rec = added[0]
        assert rec.id == "web-server-3"
        assert rec.hostname == "web-server-3.internal"
        assert rec.status == "active"
        assert rec.enrolled_at is not None

    def test_register_defaults_hostname_to_forwarded_address(self, ca_manager, executor_csr, executor_keypair):
        """No hostname supplied -> store the caller's forwarded (XFF) address.

        Emulates production (nginx -> 127.0.0.1:8080, trusted) by adding
        uvicorn's own trusted-proxy middleware, so request.client.host is the
        real executor address sent in X-Forwarded-For, not the loopback peer.
        """
        from core.iam.models import Executor
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

        db = _make_mock_db()
        app = self._create_app(ca_manager, db)
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="127.0.0.1, testclient")
        client = TestClient(app, base_url="http://127.0.0.1:8080")
        csr_pem = executor_csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "web-server-3", "csr_pem": csr_pem},  # no hostname
            headers={"X-Forwarded-For": "10.27.28.14"},
        )
        assert resp.status_code == 201
        added = [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], Executor)]
        assert len(added) == 1
        # The forwarded address is stored, not the loopback proxy peer.
        assert added[0].hostname == "10.27.28.14"
        assert added[0].hostname not in ("127.0.0.1", "testclient")

    def test_register_upsert_updates_existing_hostname(self, ca_manager, executor_csr, executor_keypair):
        from datetime import datetime

        from core.iam.models import Executor

        existing = Executor(id="web-server-3", hostname="old-host", status="active")
        existing.enrolled_at = datetime(2026, 1, 1, tzinfo=UTC)
        db = _make_mock_db()
        self._make_db_with_executor(db, existing)
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        csr_pem = executor_csr.public_bytes(serialization.Encoding.PEM).decode()
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "web-server-3", "csr_pem": csr_pem, "hostname": "web-server-3.internal"},
        )
        assert resp.status_code == 201
        # Re-registration updates the existing row in place, does not add a new one.
        added = [c.args[0] for c in db.add.call_args_list if c.args and isinstance(c.args[0], Executor)]
        assert added == []
        assert existing.hostname == "web-server-3.internal"
        assert existing.status == "active"


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
        from datetime import datetime, timedelta

        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(UTC) + timedelta(days=365),
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
        from datetime import datetime, timedelta

        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(UTC) + timedelta(days=1),
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
        from datetime import datetime, timedelta

        cert_record = MockExecutorCert(
            executor_id="test-exec",
            serial_number="abc123",
            not_after=datetime.now(UTC) + timedelta(days=20),
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

    def test_heartbeat_updates_last_heartbeat_when_executor_exists(self, ca_manager):
        """F3: the public heartbeat stamps last_heartbeat (drives 'online')."""
        from datetime import datetime

        from core.iam.models import Executor

        before = datetime.now(UTC)
        row = Executor(id="test-exec", hostname="test-exec.internal", status="active")
        row.last_heartbeat = None

        db = _make_mock_db()
        orig = db.query.side_effect

        def q(model):
            if model.__name__ == "Executor":
                m = MagicMock()
                m.all = list
                m.filter = lambda *a, **k: MagicMock(first=lambda: row)
                return m
            return orig(model) if callable(orig) else MagicMock()

        db.query.side_effect = q
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "test-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        assert row.last_heartbeat is not None
        assert row.last_heartbeat >= before
        assert row.status == "active"
        db.commit.assert_called()

    def test_heartbeat_no_row_is_noop(self, ca_manager):
        """F3: no Executor row -> no last_heartbeat write, no commit, still 200."""
        db = _make_mock_db()  # _make_mock_db yields None for Executor lookups
        app = self._create_app(ca_manager, db)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "ghost-exec", "cert_fingerprint": "abc"},
        )
        assert resp.status_code == 200
        db.commit.assert_not_called()
