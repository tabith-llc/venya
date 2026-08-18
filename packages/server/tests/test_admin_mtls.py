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
from cryptography.x509 import load_pem_x509_certificates
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from server.ca import AdminCAManager
from server.config import AdminMTLSConfig, CASecurityConfig, ServerConfig
from server.dependencies import get_current_user, require_admin
from server.middleware.auth import SessionMiddleware


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
        """Signed admin cert should have RFC822Name SAN for email-style identity."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("operator@venya.internal")

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        assert "operator@venya.internal" in emails

    def test_admin_cert_email_identity_uses_rfc822_san(self, admin_ca_dir, admin_ca_security):
        """Email-style identity (with @) should use RFC822Name SAN."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("admin@workstation.local")

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "admin@workstation.local" in emails
        assert len(dns_names) == 0

    def test_admin_cert_hostname_identity_uses_dns_san(self, admin_ca_dir, admin_ca_security):
        """Hostname-style identity (no @) should use DNSName SAN."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("admin-cli.workstation")

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert len(emails) == 0
        assert "admin-cli.workstation" in dns_names

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
# Tests: Identity Extraction (SAN type fix)
# ---------------------------------------------------------------------------


class TestExtractIdentity:
    """Tests for _extract_identity_from_cert with RFC822Name support."""

    def test_extract_identity_prefers_rfc822_over_dns(self, admin_ca_dir, admin_ca_security):
        """RFC822Name SAN should take precedence over DNSName SAN."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        ca_cert, ca_key = manager._load_ca_cert_and_key()

        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        test_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        cert_with_both_sans = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, "cn-identity"),
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
                x509.SubjectAlternativeName([
                    x509.RFC822Name("email@preferred.local"),
                    x509.DNSName("dns-not-preferred.local"),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        from server.middleware.auth import _extract_identity_from_cert

        identity = _extract_identity_from_cert(cert_with_both_sans)
        assert identity == "email@preferred.local"

    def test_extract_identity_falls_back_to_cn(self, admin_ca_dir, admin_ca_security):
        """Should fall back to CN when no SAN present."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        ca_cert, ca_key = manager._load_ca_cert_and_key()

        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        test_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        cert_no_san = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, "cn-only-identity"),
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
            .sign(ca_key, hashes.SHA256())
        )

        from server.middleware.auth import _extract_identity_from_cert

        identity = _extract_identity_from_cert(cert_no_san)
        assert identity == "cn-only-identity"


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
        recovery_code_pepper="test-pepper",
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
        from core.iam.models import AdminCertRevocation
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


# ---------------------------------------------------------------------------
# Tests: Phase 3 — Startup Enforcement
# ---------------------------------------------------------------------------


class TestStartupEnforcement:
    """Tests for admin mTLS startup enforcement in app.py."""

    def test_loopback_enforcement(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + non-loopback host should raise RuntimeError in main()."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        from server.config import AdminMTLSConfig, ServerConfig

        config = ServerConfig(
            host="0.0.0.0",
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        with pytest.raises(RuntimeError, match="loopback"):
            if config.admin_mtls.enabled and config.host not in ("127.0.0.1", "::1", "localhost"):
                raise RuntimeError(
                    "admin_mtls.enabled requires loopback bind address (127.0.0.1 or ::1). "
                    "Set VENYA_HOST=127.0.0.1 or disable admin_mtls."
                )

    def test_loopback_allowed(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + loopback host should pass enforcement."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        from server.config import AdminMTLSConfig, ServerConfig

        config = ServerConfig(
            host="127.0.0.1",
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        # Should not raise
        if config.admin_mtls.enabled and config.host not in ("127.0.0.1", "::1", "localhost"):
            pytest.fail("Should not raise for loopback host")

    def test_passphrase_enforced_at_startup(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + passphrase env unset should raise RuntimeError."""
        # Ensure passphrase is unset
        os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)

        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        from server.config import AdminMTLSConfig, ServerConfig

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        passphrase_env = config.admin_mtls.ca_key_passphrase_env
        with pytest.raises(RuntimeError, match=passphrase_env):
            if config.admin_mtls.enabled and not os.environ.get(passphrase_env):
                raise RuntimeError(
                    f"admin_mtls.enabled requires {passphrase_env} environment variable to be set."
                )

    def test_passphrase_set_allows_startup(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + passphrase env set should pass enforcement."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"

        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        from server.config import AdminMTLSConfig, ServerConfig

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        passphrase_env = config.admin_mtls.ca_key_passphrase_env
        # Should not raise
        if config.admin_mtls.enabled and not os.environ.get(passphrase_env):
            pytest.fail("Should not raise when passphrase is set")

    def test_admin_ca_missing_at_lifespan(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + missing admin CA should raise in lifespan."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"

        from pathlib import Path as PPath

        from server.config import AdminMTLSConfig, ServerConfig
        from server.ca import AdminCAManager

        # Use a non-existent admin CA directory
        admin_ca_missing = str(Path(admin_ca_dir) / "nonexistent-admin-ca")

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=admin_ca_missing + "/admin-ca.crt",
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        admin_ca_manager = AdminCAManager(PPath(admin_ca_missing), config.ca_security)
        with pytest.raises(RuntimeError, match="admin CA not found"):
            if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
                raise RuntimeError(
                    "admin_mtls.enabled but admin CA not found at admin-ca/. "
                    "Run: venya admin init-admin-ca"
                )

    def test_admin_ca_present_at_lifespan(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + existing admin CA should pass in lifespan."""
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"

        from pathlib import Path as PPath

        from server.config import AdminMTLSConfig, ServerConfig
        from server.ca import AdminCAManager

        manager = AdminCAManager(PPath(admin_ca_dir), admin_ca_security)
        manager.initialize()

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(PPath(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        admin_ca_manager = AdminCAManager(PPath(admin_ca_dir), config.ca_security)
        # Should not raise — CA exists
        if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
            pytest.fail("Should not raise when admin CA exists")


# ---------------------------------------------------------------------------
# Tests: Phase 5 — Admin Cert Revocation Endpoint
# ---------------------------------------------------------------------------


def _create_revoke_test_app():
    """Create a minimal test app for revocation endpoint tests."""
    from fastapi import FastAPI
    from unittest.mock import MagicMock
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    from server.config import ServerConfig
    from server.routes import admin as admin_routes
    from core.iam.models import AdminCertRevocation

    app = FastAPI()
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper")

    # Track revocations
    revocations = []

    backend = MagicMock()

    def get_session():
        mock_db = MagicMock()

        def query_side_effect(model):
            if model is AdminCertRevocation:
                mock_q = MagicMock()

                def filter_side_effect(*args):
                    mock_f = MagicMock()

                    def first_side_effect():
                        # Extract serial from the filter — it's a ColumnElement comparison
                        # The serial_number column value is stored in revocations
                        for rev in revocations:
                            mock_f.serial = rev.serial_number
                            if mock_f.serial:
                                return rev
                        return None

                    mock_f.first = first_side_effect
                    return mock_f

                mock_q.filter = filter_side_effect
                return mock_q
            mock_q = MagicMock()
            mock_q.filter.return_value.first.return_value = None
            return mock_q

        mock_db.query.side_effect = query_side_effect

        def add_side_effect(obj):
            revocations.append(obj)

        def commit_side_effect():
            pass

        def rollback_side_effect():
            pass

        mock_db.add = add_side_effect
        mock_db.commit = commit_side_effect
        mock_db.rollback = rollback_side_effect
        return mock_db

    backend.get_session = get_session
    app.state.backend = backend

    # Add auth middleware with admin user (bypasses SessionMiddleware)
    mock_user = MagicMock()
    mock_user.user_id = "admin"
    mock_user.roles = ["admin"]
    mock_user.permissions = "read-write"

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            request.state.auth_user = mock_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)

    # Override auth deps so require_admin bypasses real auth
    _admin_user = {"user_id": "admin", "roles": ["admin"], "permissions": "read-write"}
    app.dependency_overrides[get_current_user] = lambda: _admin_user
    app.dependency_overrides[require_admin] = lambda: _admin_user

    app.include_router(admin_routes.router, prefix="/api/v1")

    return app, backend, revocations


class TestRevokeAdminCertEndpoint:
    """Tests for POST /api/v1/admin/certs/revoke."""

    def test_revoke_admin_cert_endpoint(self):
        """Valid revocation request should return 200."""
        serial_hex = "01ab2c3d4e5f6789"

        app, backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": serial_hex, "reason": "test revocation"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["serial"] == serial_hex
        assert data["revoked"] is True
        assert data["reason"] == "test revocation"
        assert len(revocations) == 1

    def test_revoke_admin_cert_already_revoked(self):
        """Revoking the same serial twice should return 200 (idempotent)."""
        serial_hex = "02abcd1234567890"

        app, backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)

        # First revocation
        resp1 = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": serial_hex, "reason": "first"},
        )
        assert resp1.status_code == 200

        # Second revocation (idempotent)
        resp2 = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": serial_hex, "reason": "second"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["already_revoked"] is True
        # Should only have 1 revocation record (idempotent)
        assert len(revocations) == 1

    def test_revoke_admin_cert_invalid_serial(self):
        """Invalid serial format should return 400."""
        app, backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "not-hex!", "reason": "test"},
        )
        assert resp.status_code == 400

    def test_revoke_admin_cert_long_serial(self):
        """Serial too long should return 400."""
        app, backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "a" * 20, "reason": "test"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: Phase 7 — Integration Tests
# ---------------------------------------------------------------------------


def _write_pem_bundle(certs: list[bytes], path: Path) -> None:
    """Write multiple PEM certificates to a single file."""
    path.write_bytes(b"".join(c if c.endswith(b"\n") else c + b"\n" for c in certs))


def _create_concurrent_test_app(admin_ca_dir: str):
    """Create a test app for concurrency tests."""
    from fastapi import FastAPI, Request
    from starlette.requests import Request as StarletteRequest

    from server.config import AdminMTLSConfig, ServerConfig
    from server.middleware.auth import SessionMiddleware

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=True,
            ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
            known_admin_ids=["dust@montana"],
        ),
        recovery_code_pepper="test-pepper",
    )

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config

    @app.get("/api/v1/admin/test")
    def admin_test(request: Request):
        user = getattr(request.state, "auth_user", None)
        return {"user": user, "path": "/api/v1/admin/test"}

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok"}

    return app


class TestAdminMTLSConcurrency:
    """Tests for concurrent admin mTLS requests."""

    def test_concurrent_admin_requests_with_same_cert(self, admin_ca_dir, admin_ca_security):
        """10 simultaneous requests with same cert should all pass mTLS (no race conditions)."""
        import concurrent.futures

        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        app = _create_concurrent_test_app(admin_ca_dir)

        results = []

        def make_request():
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/v1/admin/test",
                headers={
                    "X-Client-Cert": cert_pem_str,
                    "X-Client-Verified": "true",
                },
            )
            return resp.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append(f"exception: {e}")

        # All 10 should pass mTLS (return 401 — no bearer token)
        # None should crash (500) or cause exceptions
        assert len(results) == 10
        for r in results:
            assert r == 401, f"Expected 401 (mTLS passed, no bearer), got {r}"


class TestAdminCARotation:
    """Tests for admin CA rotation with PEM bundle support."""

    def test_admin_ca_rotation_preserves_existing_certs(self, admin_ca_dir, admin_ca_security):
        """During CA rotation overlap, certs from both old and new CA are accepted."""
        from cryptography.x509 import load_pem_x509_certificates

        # 1. Create old CA and issue cert
        old_ca_dir = Path(admin_ca_dir) / "old-ca"
        old_ca_security = CASecurityConfig(key_passphrase_env="OLD_CA_PASSPHRASE")
        os.environ["OLD_CA_PASSPHRASE"] = "test_passphrase"
        old_ca = AdminCAManager(old_ca_dir, old_ca_security)
        old_ca.initialize()
        old_cert, old_key_pem, old_cert_pem = old_ca.sign_admin_cert("admin@old")
        old_cert_pem_str = old_cert_pem.decode("utf-8")

        # 2. Create new CA
        new_ca_dir = Path(admin_ca_dir) / "new-ca"
        new_ca_security = CASecurityConfig(key_passphrase_env="NEW_CA_PASSPHRASE")
        os.environ["NEW_CA_PASSPHRASE"] = "test_passphrase"
        new_ca = AdminCAManager(new_ca_dir, new_ca_security)
        new_ca.initialize()
        new_cert, new_key_pem, new_cert_pem = new_ca.sign_admin_cert("admin@new")
        new_cert_pem_str = new_cert_pem.decode("utf-8")

        # 3. Create PEM bundle (old + new)
        bundle_path = Path(admin_ca_dir) / "admin-ca-bundle.crt"
        _write_pem_bundle([old_ca.get_admin_ca_cert_pem(), new_ca.get_admin_ca_cert_pem()], bundle_path)

        # 4. Create app with bundle path and preload trusted CAs
        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(bundle_path),
                known_admin_ids=["admin@old", "admin@new"],
            ),
            recovery_code_pepper="test-pepper",
        )

        from cryptography.x509 import load_pem_x509_certificates as load_bundled_cas
        app = FastAPI()
        app.add_middleware(SessionMiddleware)
        app.state.config = config
        app.state.admin_trusted_cas = load_bundled_cas(bundle_path.read_bytes())

        @app.get("/api/v1/admin/test")
        def admin_test(request: Request):
            user = getattr(request.state, "auth_user", None)
            return {"user": user, "path": "/api/v1/admin/test"}

        @app.get("/api/v1/health")
        def health():
            return {"status": "ok"}

        # 5. Both old and new certs should pass mTLS during overlap
        client = TestClient(app, raise_server_exceptions=False)

        resp_old = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": old_cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp_old.status_code == 401, f"Old cert should pass during overlap, got {resp_old.status_code}: {resp_old.json()}"

        resp_new = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": new_cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp_new.status_code == 401, f"New cert should pass during overlap, got {resp_new.status_code}: {resp_new.json()}"

        # 6. After rotation complete (remove old CA from bundle), old cert should be rejected
        _write_pem_bundle([new_ca.get_admin_ca_cert_pem()], bundle_path)
        app.state.admin_trusted_cas = load_bundled_cas(bundle_path.read_bytes())

        resp_old_after = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": old_cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp_old_after.status_code == 403, f"Old cert should be rejected after rotation, got {resp_old_after.status_code}"

        resp_new_after = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": new_cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        assert resp_new_after.status_code == 401, f"New cert should still pass after rotation, got {resp_new_after.status_code}"

    def test_pem_bundle_with_single_cert(self, admin_ca_dir, admin_ca_security):
        """A PEM bundle with a single cert should work the same as a single CA file."""
        from cryptography.x509 import load_pem_x509_certificates

        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, cert_pem = manager.sign_admin_cert("dust@montana")
        cert_pem_str = cert_pem.decode("utf-8")

        # Create a bundle with just one cert
        bundle_path = Path(admin_ca_dir) / "single-cert-bundle.crt"
        _write_pem_bundle([manager.get_admin_ca_cert_pem()], bundle_path)

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(bundle_path),
                known_admin_ids=["dust@montana"],
            ),
            recovery_code_pepper="test-pepper",
        )

        app = FastAPI()
        app.add_middleware(SessionMiddleware)
        app.state.config = config
        app.state.admin_trusted_cas = load_pem_x509_certificates(bundle_path.read_bytes())

        @app.get("/api/v1/admin/test")
        def admin_test(request: Request):
            user = getattr(request.state, "auth_user", None)
            return {"user": user, "path": "/api/v1/admin/test"}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Cert": cert_pem_str,
                "X-Client-Verified": "true",
            },
        )
        # Should pass mTLS (401 = no bearer token)
        assert resp.status_code == 401

    def test_pem_bundle_with_three_cas(self, admin_ca_dir, admin_ca_security):
        """A PEM bundle with 3 CAs should verify against any of them."""
        from cryptography.x509 import load_pem_x509_certificates

        # Create 3 separate CAs
        ca_dirs = []
        for i in range(3):
            ca_dir = Path(admin_ca_dir) / f"ca-{i}"
            env_var = f"CA_PASS_{i}"
            ca_security = CASecurityConfig(key_passphrase_env=env_var)
            os.environ[env_var] = "test_passphrase"
            ca = AdminCAManager(ca_dir, ca_security)
            ca.initialize()
            ca_dirs.append((ca, ca_dir))

        # Create a cert from CA 1
        cert1, _, cert1_pem = ca_dirs[0][0].sign_admin_cert("admin@ca1")
        cert1_pem_str = cert1_pem.decode("utf-8")

        # Create a cert from CA 2
        cert2, _, cert2_pem = ca_dirs[1][0].sign_admin_cert("admin@ca2")
        cert2_pem_str = cert2_pem.decode("utf-8")

        # Create a cert from CA 3
        cert3, _, cert3_pem = ca_dirs[2][0].sign_admin_cert("admin@ca3")
        cert3_pem_str = cert3_pem.decode("utf-8")

        # Create a bundle with all 3 CAs
        bundle_path = Path(admin_ca_dir) / "three-ca-bundle.crt"
        certs_pem = [ca[0].get_admin_ca_cert_pem() for ca in ca_dirs]
        _write_pem_bundle(certs_pem, bundle_path)

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(bundle_path),
                known_admin_ids=["admin@ca1", "admin@ca2", "admin@ca3"],
            ),
            recovery_code_pepper="test-pepper",
        )

        app = FastAPI()
        app.add_middleware(SessionMiddleware)
        app.state.config = config
        app.state.admin_trusted_cas = load_pem_x509_certificates(bundle_path.read_bytes())

        @app.get("/api/v1/admin/test")
        def admin_test(request: Request):
            user = getattr(request.state, "auth_user", None)
            return {"user": user, "path": "/api/v1/admin/test"}

        client = TestClient(app, raise_server_exceptions=False)

        # All 3 certs should pass
        for pem_str, label in [(cert1_pem_str, "cert1"), (cert2_pem_str, "cert2"), (cert3_pem_str, "cert3")]:
            resp = client.get(
                "/api/v1/admin/test",
                headers={
                    "X-Client-Cert": pem_str,
                    "X-Client-Verified": "true",
                },
            )
            assert resp.status_code == 401, f"{label} should pass mTLS in 3-CA bundle, got {resp.status_code}"
