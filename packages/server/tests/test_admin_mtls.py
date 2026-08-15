"""Tests for AdminCAManager — admin CA key/cert management.

Tests cover:
- Admin CA initialization (key + cert pair creation)
- Admin CA key encryption with passphrase
- Admin certificate signing (CN, SAN, EKU, validity)
- Admin CA key loading with/without passphrase
- Middleware mTLS validation chain (Phase 2)
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID
from starlette.testclient import TestClient

from server.ca import AdminCAManager
from server.config import CASecurityConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_ca_dir(tmp_path):
    """Create a temporary admin CA directory."""
    d = tmp_path / "admin-ca"
    d.mkdir()
    return str(d)


@pytest.fixture
def admin_ca_security():
    """Create CASecurityConfig with admin passphrase env var."""
    return CASecurityConfig(key_passphrase_env="VENYA_CA_KEY_PASSPHRASE")


@pytest.fixture(autouse=True)
def clear_passphrase_env():
    """Ensure passphrase env vars are unset before each test."""
    old = os.environ.pop("VENYA_CA_KEY_PASSPHRASE", None)
    yield
    if old is not None:
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = old


# ---------------------------------------------------------------------------
# Tests: Admin CA Initialization
# ---------------------------------------------------------------------------


class TestAdminCAInitialize:
    """Tests for AdminCAManager initialization."""

    def test_admin_ca_initialize(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager.initialize() should create key/cert pair."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        assert not manager.has_ca

        manager.initialize()

        assert manager.has_ca
        assert Path(admin_ca_dir, "admin-ca.key").exists()
        assert Path(admin_ca_dir, "admin-ca.crt").exists()

    def test_admin_ca_initialize_fails_when_exists(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager.initialize() should raise if CA already exists."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        with pytest.raises(RuntimeError, match="already exists"):
            manager.initialize()

    def test_admin_ca_key_encrypted_with_passphrase(self, admin_ca_dir, admin_ca_security):
        """Admin CA key should be encrypted when passphrase is set."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase_123"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        key_data = Path(admin_ca_dir, "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in key_data

    def test_admin_ca_key_permissions(self, admin_ca_dir, admin_ca_security):
        """Admin CA key should have 0600 permissions."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        key_path = Path(admin_ca_dir, "admin-ca.key")
        assert oct(key_path.stat().st_mode)[-3:] == "600"

    def test_admin_ca_cert_permissions(self, admin_ca_dir, admin_ca_security):
        """Admin CA cert should have 0644 permissions."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert_path = Path(admin_ca_dir, "admin-ca.crt")
        assert oct(cert_path.stat().st_mode)[-3:] == "644"

    def test_admin_ca_directory_permissions(self, admin_ca_dir, admin_ca_security):
        """Admin CA directory should have 0700 permissions."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        dir_path = Path(admin_ca_dir)
        assert oct(dir_path.stat().st_mode)[-3:] == "700"


# ---------------------------------------------------------------------------
# Tests: Admin CA Key Loading
# ---------------------------------------------------------------------------


class TestAdminCALoad:
    """Tests for AdminCAManager key loading."""

    def test_admin_ca_load_requires_passphrase(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager._load_ca_key() should load with correct passphrase."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "correct_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        key = manager._load_ca_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_admin_ca_load_fails_without_passphrase(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager._load_ca_key() should raise when passphrase not set."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "init_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Remove passphrase - key is encrypted, so loading should fail
        os.environ.pop("VENYA_CA_KEY_PASSPHRASE", None)

        with pytest.raises(RuntimeError, match="not set"):
            manager._load_ca_key()

    def test_admin_ca_load_wrong_passphrase(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager._load_ca_key() should raise on wrong passphrase."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "correct_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Set wrong passphrase
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "wrong_passphrase"

        with pytest.raises(RuntimeError, match="Failed to decrypt"):
            manager._load_ca_key()


# ---------------------------------------------------------------------------
# Tests: Admin Certificate Signing
# ---------------------------------------------------------------------------


class TestAdminSignCert:
    """Tests for AdminCAManager certificate signing."""

    def test_admin_ca_sign_cert(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager.sign_admin_cert() should produce valid signed cert."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, key_pem, cert_pem = manager.sign_admin_cert("dust@montana")

        assert cert is not None
        assert isinstance(cert, x509.Certificate)
        assert key_pem is not None
        assert cert_pem is not None

    def test_admin_cert_has_correct_cn(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have CN = admin_identity."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("admin@venya.internal")

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attrs) == 1
        assert cn_attrs[0].value == "admin@venya.internal"

    def test_admin_cert_has_correct_san(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have SAN DNS = admin_identity."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("operator@venya.internal")

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "operator@venya.internal" in dns_names

    def test_admin_cert_has_client_auth_eku(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have ExtendedKeyUsage = clientAuth."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value

    def test_admin_cert_is_not_ca(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have BasicConstraints CA=False."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc_ext.value.ca is False

    def test_admin_cert_validity_90_days(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have ~90 day validity."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        assert 89 <= validity_days <= 91

    def test_admin_cert_signed_by_admin_ca(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should verify against admin CA cert."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")
        ca_cert = x509.load_pem_x509_certificate(manager.get_admin_ca_cert_pem())

        # Verify signature
        admin_public_key = cert.public_key()
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )

    def test_admin_key_is_ecdsa_p256(self, admin_ca_dir, admin_ca_security):
        """Admin cert key should be ECDSA P-256."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, key_pem, _ = manager.sign_admin_cert("test-admin")

        # Verify key can be loaded from PEM
        loaded_key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP256R1)

    def test_admin_ca_cert_pem(self, admin_ca_dir, admin_ca_security):
        """get_admin_ca_cert_pem() should return valid PEM."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        pem = manager.get_admin_ca_cert_pem()
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")

        # Should parse as valid cert
        cert = x509.load_pem_x509_certificate(pem)
        assert cert is not None

    def test_admin_ca_subject(self, admin_ca_dir, admin_ca_security):
        """Admin CA cert should have correct subject."""
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        ca_cert = x509.load_pem_x509_certificate(manager.get_admin_ca_cert_pem())

        org = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) == 1
        assert org[0].value == "Venya"

        ou = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert len(ou) == 1
        assert ou[0].value == "Admin Certificate Authority"

        cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) == 1
        assert cn[0].value == "Venya Admin CA"


# ---------------------------------------------------------------------------
# Tests: Middleware mTLS Validation (Phase 2)
# ---------------------------------------------------------------------------


def _create_admin_mtls_app(
    admin_ca_dir: str,
    admin_identity: str = "dust@montana",
    known_admin_ids: list[str] | None = None,
    admin_mtls_enabled: bool = True,
):
    """Create a test app with admin mTLS middleware configured."""
    from fastapi import FastAPI, Request
    from starlette.requests import Request as StarletteRequest

    from server.config import AdminMTLSConfig, ServerConfig
    from server.middleware.auth import SessionMiddleware

    if known_admin_ids is None:
        known_admin_ids = [admin_identity]

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=admin_mtls_enabled,
            ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
            known_admin_ids=known_admin_ids,
        ),
    )

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config

    @app.get("/api/v1/admin/test")
    def admin_test(request: Request):
        user = getattr(request.state, "auth_user", None)
        return {"user": user, "path": "/api/v1/admin/test"}

    @app.get("/api/v1/admin/executors/list")
    def admin_executors_list(request: Request):
        return {"executors": []}

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok"}

    return app


def _sign_admin_cert_and_pem(
    admin_ca_dir: str,
    admin_identity: str,
    passphrase: str = "test_passphrase",
) -> tuple[str, str]:
    """Sign an admin cert and return PEM-encoded cert string and key PEM."""
    os.environ[passphrase] = passphrase
    from server.ca import AdminCAManager
    from server.config import CASecurityConfig

    ca_security = CASecurityConfig(key_passphrase_env=passphrase)
    manager = AdminCAManager(Path(admin_ca_dir), ca_security)
    manager.initialize()

    cert, key_pem, cert_pem = manager.sign_admin_cert(admin_identity)
    return cert_pem.decode("utf-8"), key_pem.decode("utf-8")


class TestAdminMTLSMiddleware:
    """Tests for admin mTLS middleware validation chain."""

    def test_header_injection_rejected(self, admin_ca_dir, admin_ca_security):
        """Forged X-Client-Cert without Caddy verification should be rejected."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        # Send X-Client-Cert but NOT X-Client-Verified
        resp = client.get(
            "/api/v1/admin/test",
            headers={"X-Client-Cert": cert_pem_str},
        )
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_missing_cert_on_admin_route(self, admin_ca_dir, admin_ca_security):
        """No client cert on admin route should return 403."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test")
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_valid_cert_passes(self, admin_ca_dir, admin_ca_security):
        """Valid cert + known identity should pass mTLS and continue to bearer auth."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        # mTLS passes → continues to bearer token auth → 401 (no token)
        assert resp.status_code == 401
        assert "Missing authentication token" in resp.json()["detail"]

    def test_expired_cert_rejected(self, admin_ca_dir, admin_ca_security):
        """Expired admin cert should be rejected."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Create an expired cert manually
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        ca_cert, ca_key = manager._load_ca_cert_and_key()
        now = datetime.now(timezone.utc)
        expired_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, "dust@montana"),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(expired_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=200))
            .not_valid_after(now - timedelta(days=10))  # Expired 10 days ago
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("dust@montana")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        expired_pem = expired_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": expired_pem,
                "X-Client-Verified": "true",
            },
        )
        assert resp.status_code == 403
        assert "expired" in resp.json()["detail"].lower()

    def test_unknown_identity_rejected(self, admin_ca_dir, admin_ca_security):
        """Valid cert but unknown identity should be rejected."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("rogue@attacker.internal")
        cert_pem_str = cert_pem.decode("utf-8")

        # Only dust@montana is known
        app = _create_admin_mtls_app(
            admin_ca_dir,
            "dust@montana",
            known_admin_ids=["dust@montana"],
        )

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_san_preferred_over_cn(self, admin_ca_dir, admin_ca_security):
        """SAN DNS should take precedence over CN for identity."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Create a cert with SAN DNS = "dust@montana" but CN = "different"
        ca_cert, ca_key = manager._load_ca_cert_and_key()
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        test_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        cert_with_san = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, "different@identity.internal"),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(test_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("dust@montana")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem_str = cert_with_san.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        # Should pass because SAN DNS = "dust@montana" matches known_admin_ids
        assert resp.status_code == 401  # mTLS passes → no bearer token

    def test_revoked_cert_rejected(self, admin_ca_dir, admin_ca_security):
        """Cert serial in AdminCertRevocation should be rejected."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        # We need a backend with a DB session for the revocation check.
        # Since we can't easily set up a full backend in this test,
        # we'll test with admin_mtls disabled for the backend path,
        # or mock the backend.
        from unittest.mock import MagicMock, patch

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        # Create mock backend with revoked cert
        db = MagicMock()
        from vault.iam.models import AdminCertRevocation
        revoked_entry = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = revoked_entry
        backend = MagicMock()
        backend.get_session.return_value = db

        app.state.backend = backend

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp.status_code == 403
        assert "revoked" in resp.json()["detail"].lower()

    def test_non_admin_route_unaffected(self, admin_ca_dir, admin_ca_security):
        """Non-admin routes should not require mTLS even when enabled."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_admin_mtls_disabled_allows_admin_routes(self, admin_ca_dir, admin_ca_security):
        """When admin_mtls is disabled, admin routes should work with bearer token only."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana", admin_mtls_enabled=False)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test")
        # Without mTLS, should get 401 (no bearer token), not 403
        assert resp.status_code == 401
        assert "Missing authentication token" in resp.json()["detail"]

    def test_wrong_verified_value_rejected(self, admin_ca_dir, admin_ca_security):
        """X-Client-Verified with wrong value should be rejected."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        app = _create_admin_mtls_app(admin_ca_dir, "dust@montana")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "false",  # Wrong value
            },
        )
        assert resp.status_code == 403
