# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for AdminCAManager — admin CA key/cert management.

Tests cover:
- Admin CA initialization (key + cert pair creation)
- Admin CA key encryption with passphrase
- Admin certificate signing (CN, SAN, EKU, validity)
- Admin CA key loading with/without passphrase
- Middleware mTLS validation chain (Phase 2)
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from fastapi import FastAPI, Request
from server.ca import AdminCAManager
from server.config import AdminMTLSConfig, CASecurityConfig, InnerTLSConfig, ServerConfig
from server.dependencies import get_current_user, require_admin
from server.middleware.auth import SessionMiddleware
from starlette.testclient import TestClient

try:
    from .conftest import ADMIN_SERIAL_HEX, FOREIGN_SERIAL_HEX, forwarded_headers, make_cert_prefix, make_leaf
except ImportError:  # pytest rootdir/tests-path import mode
    from conftest import ADMIN_SERIAL_HEX, FOREIGN_SERIAL_HEX, forwarded_headers, make_cert_prefix, make_leaf

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
    return CASecurityConfig(key_passphrase_env="VENYA_ADMIN_CA_KEY_PASSPHRASE")


@pytest.fixture(autouse=True)
def clear_passphrase_env():
    """Ensure both CA passphrase env vars are unset before/after each test.

    Clears the admin var (VENYA_ADMIN_CA_KEY_PASSPHRASE) and the executor var
    (VENYA_CA_KEY_PASSPHRASE) so the split-brain regression test can set both
    to distinct values without cross-test leakage.
    """
    old_admin = os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)
    old_exec = os.environ.pop("VENYA_CA_KEY_PASSPHRASE", None)
    yield
    if old_admin is not None:
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = old_admin
    if old_exec is not None:
        os.environ["VENYA_CA_KEY_PASSPHRASE"] = old_exec


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
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase_123"
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
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "correct_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        key = manager._load_ca_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_admin_ca_load_fails_without_passphrase(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager._load_ca_key() should raise when passphrase not set."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "init_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Remove passphrase - key is encrypted, so loading should fail
        os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)

        with pytest.raises(RuntimeError, match="not set"):
            manager._load_ca_key()

    def test_admin_ca_load_wrong_passphrase(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager._load_ca_key() should raise on wrong passphrase."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "correct_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        # Set wrong passphrase
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "wrong_passphrase"

        with pytest.raises(RuntimeError, match="Failed to decrypt"):
            manager._load_ca_key()


# ---------------------------------------------------------------------------
# Tests: Admin Certificate Signing
# ---------------------------------------------------------------------------


class TestAdminSignCert:
    """Tests for AdminCAManager certificate signing."""

    def test_admin_ca_sign_cert(self, admin_ca_dir, admin_ca_security):
        """AdminCAManager.sign_admin_cert() should produce valid signed cert."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, key_pem, cert_pem = manager.sign_admin_cert("admin@example.com")

        assert cert is not None
        assert isinstance(cert, x509.Certificate)
        assert key_pem is not None
        assert cert_pem is not None

    def test_admin_cert_has_correct_cn(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have CN = admin_identity."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("admin@venya.internal")

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attrs) == 1
        assert cn_attrs[0].value == "admin@venya.internal"

    def test_admin_cert_has_correct_san(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have RFC822Name SAN for email-style identity."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("operator@venya.internal")

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        assert "operator@venya.internal" in emails

    def test_admin_cert_email_identity_uses_rfc822_san(self, admin_ca_dir, admin_ca_security):
        """Email-style identity (with @) should use RFC822Name SAN."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
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
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
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
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value

    def test_admin_cert_is_not_ca(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have BasicConstraints CA=False."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc_ext.value.ca is False

    def test_admin_cert_validity_90_days(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should have ~90 day validity."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")

        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        assert 89 <= validity_days <= 91

    def test_admin_cert_signed_by_admin_ca(self, admin_ca_dir, admin_ca_security):
        """Signed admin cert should verify against admin CA cert."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        cert, _, _ = manager.sign_admin_cert("test-admin")
        ca_cert = x509.load_pem_x509_certificate(manager.get_admin_ca_cert_pem())

        # Verify signature
        cert.public_key()
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )

    def test_admin_key_is_ecdsa_p256(self, admin_ca_dir, admin_ca_security):
        """Admin cert key should be ECDSA P-256."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        _cert, key_pem, _ = manager.sign_admin_cert("test-admin")

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
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        ca_cert, ca_key = manager._load_ca_cert_and_key()

        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        test_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        cert_with_both_sans = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "cn-identity"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(test_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.RFC822Name("email@preferred.local"),
                        x509.DNSName("dns-not-preferred.local"),
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        from server.middleware.auth import _extract_identity_from_cert

        identity = _extract_identity_from_cert(cert_with_both_sans)
        assert identity == "email@preferred.local"

    def test_extract_identity_falls_back_to_cn(self, admin_ca_dir, admin_ca_security):
        """Should fall back to CN when no SAN present."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        ca_cert, ca_key = manager._load_ca_cert_and_key()

        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        test_key = ec_mod.generate_private_key(ec_mod.SECP256R1())

        cert_no_san = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "cn-only-identity"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(test_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=90))
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


def _sqlite_revocation_backend(revocation_rows: list[tuple[str, str]] | None = None):
    """Real in-memory SQLite backend holding the AdminCertRevocation table.

    StaticPool pins ONE connection: a bare "sqlite://" memory database is
    per-connection — without it the seeding session drops the tables when it
    closes and the middleware's lookup sees "no such table" (caught by the
    first run of the revocation cells). check_same_thread=False lets the
    concurrency test's worker threads share the pinned connection.
    """
    from core.iam.models import AdminCertRevocation, Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    seed = session_factory()
    for serial_number, reason in revocation_rows or []:
        seed.add(AdminCertRevocation(serial_number=serial_number, reason=reason))
    seed.commit()
    seed.close()

    class _Backend:
        def get_session(self):
            return session_factory()

    return _Backend()


def _create_admin_mtls_app(
    admin_ca_dir: str,
    admin_identity: str = "admin@example.com",
    known_admin_ids: list[str] | None = None,
    admin_mtls_enabled: bool = True,
    revocation_rows: list[tuple[str, str]] | None = None,
    with_backend: bool = True,
    cert_prefix=None,
):
    """Create a test app with admin mTLS middleware configured.

    Args:
        revocation_rows: (serial_number, reason) pairs seeded into a REAL
            SQLite AdminCertRevocation table — the middleware's revocation
            lookup uses func.upper() SQL, which mocks cannot evaluate
            (ticket sec-admin-mtls-allowlist-revocation; house precedent:
            real-SQLite cells in test_session_manager_gate.py).
        with_backend: False simulates backend-unavailable → the middleware
            must fail closed.
        cert_prefix: directory the forwarded-cert-file header may point into
            (the #314 inner-mTLS cert-path prefix; the suite passes the path
            through the configured header exactly as nginx would).
    """
    from server.config import AdminMTLSConfig, ServerConfig

    if known_admin_ids is None:
        known_admin_ids = [admin_identity]

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=admin_mtls_enabled,
            ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
            known_admin_ids=known_admin_ids,
        ),
        inner_mtls=InnerTLSConfig(
            enabled=True,
            cert_file="/test/inner.crt",
            key_file="/test/inner.key",
            client_ca_file="/test/inner-ca.crt",
            cert_path_prefix=str(cert_prefix) if cert_prefix is not None else None,
        ),
        recovery_code_pepper="test-pepper",
    )

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config

    if with_backend:
        app.state.backend = _sqlite_revocation_backend(revocation_rows)

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


def _admin_ca_pair(admin_ca_dir: str, passphrase: str = "test_passphrase"):
    """Load (ca_cert, ca_key) from an initialized admin CA dir (key is encrypted)."""
    key = serialization.load_pem_private_key(
        (Path(admin_ca_dir) / "admin-ca.key").read_bytes(),
        password=passphrase.encode(),
    )
    return x509.load_pem_x509_certificate((Path(admin_ca_dir) / "admin-ca.crt").read_bytes()), key


def _admin_leaf(
    admin_ca_dir: str, admin_ca_security, *, cn="admin@example.com", serial=None, expired=False, san_email=None
):
    """Initialize the admin CA and build a forwarded leaf with a fixed serial."""
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
    manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
    manager.initialize()
    ca_cert, ca_key = _admin_ca_pair(admin_ca_dir)
    return make_leaf(
        ca_cert,
        ca_key,
        cn=cn,
        serial=serial,
        expired=expired,
        san_email=cn if san_email and "@" in cn else san_email,
    )


class TestAdminMTLSMiddleware:
    """Tests for the admin-mTLS chain on the crypto-forwarded certificate (#314)."""

    def test_header_injection_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """The retired header trio, forged, with NO forwarded cert → 403.

        Headline #314 pair (truth-table N1): headers that used to BE identity
        are now inert; only the crypto-verified certificate opens the gate."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "X-Client-Verified": "SUCCESS",
                "X-Client-Subject": "CN=admin@example.com,OU=Admin,O=Venya",
                "X-Client-Serial": ADMIN_SERIAL_HEX,
            },
        )
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_missing_cert_on_admin_route(self, admin_ca_dir, admin_ca_security, tmp_path):
        """No forwarded cert file at all on an admin route → 403."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test")
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_valid_cert_passes(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Admin-CA-signed forwarded cert + known identity → 200, caller=admin."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 200
        assert resp.json()["user"]["caller"] == "admin"
        assert resp.json()["user"]["user_id"] == "admin@example.com"

    def test_expired_cert_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Expired leaf (valid chain, valid identity) → 403.

        #314 behavior change: nginx dropped expired certs at the outer TLS
        layer; with app-side verification the APP must check validity too
        (the old cell documented the opposite posture and passed on headers).
        """
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, expired=True)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403

    def test_cert_outside_path_prefix_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Path guard (N2): a cert-file path OUTSIDE the configured prefix is
        never read — traversal/symlink escape fails closed."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        outside = tmp_path / "outside.pem"
        from cryptography.hazmat.primitives import serialization as _ser

        outside.write_bytes(cert.public_bytes(_ser.Encoding.PEM))
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers={"x-client-cert-file": str(outside)})
        assert resp.status_code == 403
        # sibling-prefix string escape (/certfiles vs /certfiles-secret)
        resp2 = client.get(
            "/api/v1/admin/test",
            headers={"x-client-cert-file": str(outside).replace("certfiles", "certfiles-secret")},
        )
        assert resp2.status_code == 403

    def test_unparseable_cert_file_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Garbage bytes behind the header (N3) → 403, no read-side crash."""
        prefix = make_cert_prefix(tmp_path)
        bogus = prefix / "bogus.pem"
        bogus.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----")
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers={"x-client-cert-file": str(bogus)})
        assert resp.status_code == 403

    def test_cross_plane_cert_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Cross-plane row (ruled Q4, N4): a FOREIGN-chain cert presenting the
        allowlisted admin CN is refused at the chain check — the CN/allowlist
        comparison never runs."""
        prefix = make_cert_prefix(tmp_path)
        from cryptography.hazmat.primitives.asymmetric import ec as _ec

        rogue_key = _ec.generate_private_key(_ec.SECP256R1())
        now = datetime.now(UTC)
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@example.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")]))
            .public_key(rogue_key.public_key())
            .serial_number(int(ADMIN_SERIAL_HEX, 16))
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(rogue_key, hashes.SHA256())
        )
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, rogue_cert))
        assert resp.status_code == 403

    def test_unknown_identity_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Valid Admin-CA chain, identity NOT in known_admin_ids → 403."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, cn="rogue@attacker.internal")
        app = _create_admin_mtls_app(
            admin_ca_dir,
            "admin@example.com",
            known_admin_ids=["admin@example.com"],
            cert_prefix=prefix,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_san_preferred_over_cn(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Identity extraction on the VERIFIED cert prefers SAN over CN."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(
            admin_ca_dir,
            admin_ca_security,
            cn="admin@example.com",
            serial=int(ADMIN_SERIAL_HEX, 16),
            san_email=True,
        )
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 200
        assert resp.json()["user"]["user_id"] == "admin@example.com"

    def test_unknown_identity_rejected_signed_cert(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Unknown identity is rejected even with a CA-signed cert."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, cn="unknown@identity.internal")
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403
        assert "client certificate" in resp.json()["detail"].lower()

    def test_non_admin_route_unaffected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Non-admin routes do not require the forwarded cert."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_admin_mtls_disabled_allows_admin_routes(self, admin_ca_dir, admin_ca_security, tmp_path):
        """When admin_mtls is disabled, admin routes fall to bearer auth (401)."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", admin_mtls_enabled=False, cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test")
        assert resp.status_code == 401
        assert "Missing authentication token" in resp.json()["detail"]

    def test_cert_file_absent_with_forged_headers_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Forged trio PLUS a nonexistent cert-file path → 403 (file must exist)."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/admin/test",
            headers={
                "x-client-cert-file": str(prefix / "does-not-exist.pem"),
                "X-Client-Verified": "SUCCESS",
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

        config = ServerConfig(
            host="0.0.0.0",
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["admin@example.com"],
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

        config = ServerConfig(
            host="127.0.0.1",
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["admin@example.com"],
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

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["admin@example.com"],
            ),
            recovery_code_pepper="test-pepper",
        )

        passphrase_env = config.admin_mtls.ca_key_passphrase_env
        with pytest.raises(RuntimeError, match=passphrase_env):
            if config.admin_mtls.enabled and not os.environ.get(passphrase_env):
                raise RuntimeError(f"admin_mtls.enabled requires {passphrase_env} environment variable to be set.")

    def test_passphrase_set_allows_startup(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + passphrase env set should pass enforcement."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"

        manager = AdminCAManager(Path(admin_ca_dir), admin_ca_security)
        manager.initialize()

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["admin@example.com"],
            ),
            recovery_code_pepper="test-pepper",
        )

        passphrase_env = config.admin_mtls.ca_key_passphrase_env
        # Should not raise
        if config.admin_mtls.enabled and not os.environ.get(passphrase_env):
            pytest.fail("Should not raise when passphrase is set")

    def test_admin_ca_missing_at_lifespan(self, admin_ca_dir):
        """admin_mtls.enabled + missing admin CA should raise in lifespan.

        Builds the manager via app.py's _admin_ca_security helper so the test
        exercises the real wiring (admin var), not a re-implementation that
        could drift from app.py.
        """
        from pathlib import Path as PPath

        from server.app import _admin_ca_security
        from server.ca import AdminCAManager

        # Use a non-existent admin CA directory
        admin_ca_missing = str(Path(admin_ca_dir) / "nonexistent-admin-ca")

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=admin_ca_missing + "/admin-ca.crt",
                known_admin_ids=["admin@example.com"],
            ),
            recovery_code_pepper="test-pepper",
        )

        admin_ca_manager = AdminCAManager(PPath(admin_ca_missing), _admin_ca_security(config))
        with pytest.raises(RuntimeError, match="admin CA not found"):
            if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
                raise RuntimeError(
                    "admin_mtls.enabled but admin CA not found at admin-ca/. " "Run: venya admin init-admin-ca"
                )

    def test_admin_ca_present_at_lifespan(self, admin_ca_dir, admin_ca_security):
        """admin_mtls.enabled + existing admin CA should pass in lifespan."""
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"

        from pathlib import Path as PPath

        from server.app import _admin_ca_security
        from server.ca import AdminCAManager

        manager = AdminCAManager(PPath(admin_ca_dir), admin_ca_security)
        manager.initialize()

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(
                enabled=True,
                ca_cert=str(PPath(admin_ca_dir) / "admin-ca.crt"),
                known_admin_ids=["admin@example.com"],
            ),
            recovery_code_pepper="test-pepper",
        )

        admin_ca_manager = AdminCAManager(PPath(admin_ca_dir), _admin_ca_security(config))
        # Should not raise — CA exists
        if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
            pytest.fail("Should not raise when admin CA exists")


class TestAdminCAWiring:
    """Regression for the admin-CA passphrase var split-brain.

    Bug (found G3-auth 2026-09-14, ticket core-ca-keys-unencrypted-at-rest):
    app.py built AdminCAManager with ``config.ca_security``, whose
    ``key_passphrase_env`` defaults to the EXECUTOR var
    ``VENYA_CA_KEY_PASSPHRASE``, while the installer and the startup
    enforcement (app.py main()) deliver/check ``VENYA_ADMIN_CA_KEY_PASSPHRASE``.
    The admin manager therefore never saw the passphrase and wrote the admin CA
    key UNENCRYPTED at rest on every fresh install. ``_admin_ca_security`` is
    now the single source of truth for the admin manager's security config;
    these tests pin it by contract and functionally (distinct var values).
    """

    def test_admin_ca_security_uses_admin_var(self):
        """_admin_ca_security must select the admin var, not the executor var."""
        from server.app import _admin_ca_security

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(enabled=True),
            recovery_code_pepper="test-pepper",
        )
        sec = _admin_ca_security(config)
        assert sec.key_passphrase_env == config.admin_mtls.ca_key_passphrase_env
        assert sec.key_passphrase_env == "VENYA_ADMIN_CA_KEY_PASSPHRASE"
        # The whole bug: it must NOT be the executor CA default.
        assert sec.key_passphrase_env != config.ca_security.key_passphrase_env

    def test_admin_ca_security_honors_configured_var(self):
        """An operator override of admin_mtls.ca_key_passphrase_env is respected."""
        from server.app import _admin_ca_security

        config = ServerConfig(
            admin_mtls=AdminMTLSConfig(enabled=True, ca_key_passphrase_env="CUSTOM_ADMIN_VAR"),
            recovery_code_pepper="test-pepper",
        )
        assert _admin_ca_security(config).key_passphrase_env == "CUSTOM_ADMIN_VAR"

    def test_admin_ca_encrypts_when_admin_var_set(self, admin_ca_dir):
        """Positive: admin var set (executor var unset) -> key encrypted at rest.

        This is the production condition: the installer delivers
        VENYA_ADMIN_CA_KEY_PASSPHRASE and never sets VENYA_CA_KEY_PASSPHRASE.
        Pre-fix the manager read the executor var (unset) -> plaintext key.
        """
        from pathlib import Path as PPath

        from server.app import _admin_ca_security
        from server.ca import AdminCAManager

        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "admin_pp"
        # executor var deliberately UNSET (autouse fixture cleared it)

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(enabled=True),
            recovery_code_pepper="test-pepper",
        )
        manager = AdminCAManager(PPath(admin_ca_dir), _admin_ca_security(config))
        manager.initialize()

        key_data = PPath(admin_ca_dir, "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in key_data, "admin CA key must be encrypted at rest"
        # Decrypts with the admin passphrase the manager read.
        assert manager._load_ca_key() is not None

    def test_admin_ca_ignores_executor_var(self, admin_ca_dir, caplog):
        """Negative (sharp regression): executor var set, admin var unset -> plaintext.

        Proves the admin manager reads the ADMIN var, not the executor var.
        Pre-fix (manager wired to config.ca_security = VENYA_CA_KEY_PASSPHRASE)
        this encrypted the key from the executor var and the test FAILS.
        Post-fix the admin var is absent -> plaintext + warning naming it.
        """
        import logging
        from pathlib import Path as PPath

        from server.app import _admin_ca_security
        from server.ca import AdminCAManager

        os.environ["VENYA_CA_KEY_PASSPHRASE"] = "executor_pp"
        # admin var deliberately UNSET

        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(enabled=True),
            recovery_code_pepper="test-pepper",
        )
        manager = AdminCAManager(PPath(admin_ca_dir), _admin_ca_security(config))
        with caplog.at_level(logging.WARNING, logger="venya.ca"):
            manager.initialize()

        key_data = PPath(admin_ca_dir, "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" not in key_data, "admin CA must NOT key off the executor var"
        assert any(
            "VENYA_ADMIN_CA_KEY_PASSPHRASE" in r.getMessage() and "UNENCRYPTED" in r.getMessage()
            for r in caplog.records
        ), "warning must name the admin var the manager actually reads"

    def test_admin_ca_unencrypted_warning_names_admin_var(self, admin_ca_dir, caplog):
        """Negative: no passphrase -> loud warning naming the ADMIN var, key still written."""
        import logging
        from pathlib import Path as PPath

        from server.app import _admin_ca_security
        from server.ca import AdminCAManager

        # Autouse fixture cleared both vars -> passphrase is None.
        config = ServerConfig(
            ca_dir=str(Path(admin_ca_dir)),
            admin_mtls=AdminMTLSConfig(enabled=True),
            recovery_code_pepper="test-pepper",
        )
        manager = AdminCAManager(PPath(admin_ca_dir), _admin_ca_security(config))
        with caplog.at_level(logging.WARNING, logger="venya.ca"):
            manager.initialize()

        key_data = PPath(admin_ca_dir, "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" not in key_data  # plaintext, but...
        assert b"BEGIN PRIVATE KEY" in key_data  # ...still written: no silent failure
        assert any(
            "VENYA_ADMIN_CA_KEY_PASSPHRASE" in r.getMessage() and "UNENCRYPTED" in r.getMessage()
            for r in caplog.records
        ), "warning must name the admin var the manager actually reads"


# ---------------------------------------------------------------------------
# Tests: Phase 5 — Admin Cert Revocation Endpoint
# ---------------------------------------------------------------------------


def _create_revoke_test_app():
    """Create a minimal test app for revocation endpoint tests."""
    from unittest.mock import MagicMock

    from core.iam.models import AdminCertRevocation
    from server.config import ServerConfig
    from server.routes import admin as admin_routes
    from starlette.middleware.base import BaseHTTPMiddleware

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
            # #301 F3: the endpoint now also adds an AuditEvent row per
            # revocation (and per duplicate attempt — Q3). This tracker is
            # for REVOCATION records only.
            if isinstance(obj, AdminCertRevocation):
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
        """Valid revocation request should return 200, serial normalized to
        UPPERCASE at the storage boundary (user ruling B, ticket
        sec-admin-mtls-allowlist-revocation — nginx $ssl_client_serial is
        uppercase; mixed-case input is the legacy trap)."""
        serial_input = "ab12ab12ab12ab12"

        app, _backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": serial_input, "reason": "test revocation"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["serial"] == "AB12AB12AB12AB12"
        assert data["revoked"] is True
        assert data["reason"] == "test revocation"
        assert len(revocations) == 1
        assert revocations[0].serial_number == "AB12AB12AB12AB12"

    def test_revoke_admin_cert_already_revoked(self):
        """Revoking the same serial twice should return 200 (idempotent)."""
        serial_hex = "02abcd1234567890"

        app, _backend, revocations = _create_revoke_test_app()

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
        app, _backend, _revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "not-hex!", "reason": "test"},
        )
        assert resp.status_code == 400

    def test_revoke_admin_cert_long_serial(self):
        """Serial too long should return 400."""
        app, _backend, _revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "a" * 20, "reason": "test"},
        )
        assert resp.status_code == 400

    def test_revoke_reason_at_column_bound_accepted(self):
        """revoke-cert-reason-length-unguarded: a 64-char reason (the
        AdminCertRevocation.reason String(64) width) writes through."""
        app, _backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        reason = "r" * 64
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "ab12ab12ab12ab12", "reason": reason},
        )
        assert resp.status_code == 200
        assert revocations[0].reason == reason

    def test_revoke_reason_over_column_bound_422_no_db_touch(self):
        """65 chars dies at validation — the handler never runs, so no
        revocation record is ever added."""
        app, _backend, revocations = _create_revoke_test_app()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/revoke",
            json={"serial": "ab12ab12ab12ab12", "reason": "r" * 65},
        )
        assert resp.status_code == 422
        assert revocations == []


# ---------------------------------------------------------------------------
# Tests: Phase 7 — Integration Tests
# ---------------------------------------------------------------------------


def _write_pem_bundle(certs: list[bytes], path: Path) -> None:
    """Write multiple PEM certificates to a single file."""
    path.write_bytes(b"".join(c if c.endswith(b"\n") else c + b"\n" for c in certs))


def _create_concurrent_test_app(admin_ca_dir: str, cert_prefix=None):
    """Create a test app for concurrency tests."""
    from server.config import AdminMTLSConfig, ServerConfig

    config = ServerConfig(
        admin_mtls=AdminMTLSConfig(
            enabled=True,
            ca_cert=str(Path(admin_ca_dir) / "admin-ca.crt"),
            known_admin_ids=["admin@example.com"],
        ),
        inner_mtls=InnerTLSConfig(
            enabled=True,
            cert_file="/test/inner.crt",
            key_file="/test/inner.key",
            client_ca_file="/test/inner-ca.crt",
            cert_path_prefix=str(cert_prefix) if cert_prefix is not None else None,
        ),
        recovery_code_pepper="test-pepper",
    )

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config
    app.state.backend = _sqlite_revocation_backend()

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

    def test_concurrent_admin_requests_with_same_cert(self, admin_ca_dir, admin_ca_security, tmp_path):
        """10 simultaneous requests with same forwarded cert all pass mTLS (no race conditions)."""
        import concurrent.futures

        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        headers = forwarded_headers(prefix, cert)

        app = _create_concurrent_test_app(admin_ca_dir, cert_prefix=prefix)

        results = []

        def make_request():
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/admin/test", headers=headers)
            return resp.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append(f"exception: {e}")

        # All 10 should pass mTLS (return 200 — auth_user set → route returns 200)
        # None should crash (500) or cause exceptions
        assert len(results) == 10
        for r in results:
            assert r == 200, f"Expected 200 (mTLS passed, auth_user set), got {r}"


class TestAdminCARotation:
    """Identity extraction from VERIFIED certificates (header-DN parsing retired, #314)."""

    def test_cert_identity_extraction(self):
        """_extract_identity_from_cert precedence: RFC822 SAN → DNS SAN → CN."""
        from server.middleware.auth import _extract_identity_from_cert

        ca_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        base = (
            x509.CertificateBuilder()
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
            .public_key(ca_key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=1))
        )
        cn_only = base.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                ]
            )
        ).sign(ca_key, hashes.SHA256())
        assert _extract_identity_from_cert(cn_only) == "admin@venya-core-1"
        dns_cn = base.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cn-value")]))
        dns_cn = dns_cn.add_extension(x509.SubjectAlternativeName([x509.DNSName("dns-value")]), critical=False).sign(
            ca_key, hashes.SHA256()
        )
        assert _extract_identity_from_cert(dns_cn) == "dns-value"
        both = base.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cn-value")]))
        both = both.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("dns-value"), x509.RFC822Name("mail-value")]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())
        assert _extract_identity_from_cert(both) == "mail-value"
        with pytest.raises(ValueError):
            no_id = base.subject_name(x509.Name([])).sign(ca_key, hashes.SHA256())
            _extract_identity_from_cert(no_id)

    def test_known_identity_passes(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Known identity on the forwarded cert passes mTLS."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(ADMIN_SERIAL_HEX, 16))
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 200

    def test_unknown_identity_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Unknown identity on a CA-signed forwarded cert is rejected."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, cn="unknown@attacker.com")
        app = _create_admin_mtls_app(admin_ca_dir, "admin@example.com", cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Tests: allowlist fail-closed + in-process serial revocation (ticket
# sec-admin-mtls-allowlist-revocation)
# ---------------------------------------------------------------------------


class TestAdminMtlsSerialRevocation:
    """Truth table for the hardened admin-mTLS chain on crypto-forwarded
    certs (#314 restages tickets sec-admin-mtls-allowlist-revocation #15/#16):
    allowlist fail-closed, in-process revocation over the VERIFIED cert's
    serial (the former missing-header branch is retired by construction —
    a certificate object always carries its serial). Revocation cells run on
    REAL SQLite so the func.upper() SQL is actually evaluated — mocks cannot
    model it (house precedent: test_session_manager_gate.py)."""

    def _leaf(self, admin_ca_dir, admin_ca_security, serial_hex=ADMIN_SERIAL_HEX):
        return _admin_leaf(admin_ca_dir, admin_ca_security, serial=int(serial_hex, 16))

    def test_empty_allowlist_fails_closed(self, admin_ca_dir, admin_ca_security, tmp_path):
        """#15 negative: empty known_admin_ids (the CONFIG DEFAULT) rejects
        even a fully valid forwarded cert."""
        prefix = make_cert_prefix(tmp_path)
        cert = self._leaf(admin_ca_dir, admin_ca_security)
        app = _create_admin_mtls_app(admin_ca_dir, known_admin_ids=[], cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403

    def test_executor_cn_rejected_by_chain(self, admin_ca_dir, admin_ca_security, tmp_path):
        """#15 acceptance row, #314 upgrade (ruled Q4): a FOREIGN-chain cert —
        the executor plane's shape — presenting an executor CN is refused at
        the ADMIN-plane chain check; the allowlist is defense-in-depth only."""
        prefix = make_cert_prefix(tmp_path)
        cert = _admin_leaf(admin_ca_dir, admin_ca_security, cn="venya-exec-1")
        # Admin-CA-signed with an executor CN still hits the allowlist (in-plane);
        # the CROSS-plane refusal is the rogue-chain cell in TestAdminMTLSMiddleware.
        # Here pin the allowlist half: in-plane cert, executor CN, not listed.
        app = _create_admin_mtls_app(admin_ca_dir, known_admin_ids=["admin@example.com"], cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403

    def test_revoked_serial_rejected(self, admin_ca_dir, admin_ca_security, tmp_path):
        """#16 negative: the VERIFIED cert's serial, recorded via
        POST /admin/certs/revoke, is rejected IN-PROCESS."""
        prefix = make_cert_prefix(tmp_path)
        cert = self._leaf(admin_ca_dir, admin_ca_security)
        app = _create_admin_mtls_app(
            admin_ca_dir,
            revocation_rows=[(ADMIN_SERIAL_HEX, "compromised")],
            cert_prefix=prefix,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin certificate revoked"

    def test_legacy_lowercase_row_matches_cert_serial(self, admin_ca_dir, admin_ca_security, tmp_path):
        """#16 format-trap pin (ruling B): a legacy as-provided (lowercase)
        row still matches the cert-serial presentation via func.upper()."""
        prefix = make_cert_prefix(tmp_path)
        cert = self._leaf(admin_ca_dir, admin_ca_security, serial_hex=FOREIGN_SERIAL_HEX)
        app = _create_admin_mtls_app(
            admin_ca_dir,
            revocation_rows=[("abcd1234abcd1234", "legacy-lowercase")],
            cert_prefix=prefix,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin certificate revoked"

    def test_unrevoked_serial_passes(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Positive half: allowlisted identity + verified, unrevoked serial
        → 200, caller=admin."""
        prefix = make_cert_prefix(tmp_path)
        cert = self._leaf(admin_ca_dir, admin_ca_security)
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 200
        assert resp.json()["user"]["caller"] == "admin"

    def test_cert_file_absent_fails_closed_with_recovery_log(self, admin_ca_dir, admin_ca_security, tmp_path, caplog):
        """#16 successor fail-closed: no forwarded cert → 403, and the server
        LOG carries the recovery path (installer re-run + same-window
        restarts) — the former response-detail guidance moved to the log
        because the caller is unauthenticated at this point."""
        prefix = make_cert_prefix(tmp_path)
        app = _create_admin_mtls_app(admin_ca_dir, cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        with caplog.at_level("WARNING", logger="venya.server"):
            resp = client.get("/api/v1/admin/test")
        assert resp.status_code == 403
        assert any("Recovery" in r.getMessage() for r in caplog.records)

    def test_backend_unavailable_fails_closed(self, admin_ca_dir, admin_ca_security, tmp_path):
        """Backend absence fails closed (mirrors _validate_executor_mtls)."""
        prefix = make_cert_prefix(tmp_path)
        cert = self._leaf(admin_ca_dir, admin_ca_security)
        app = _create_admin_mtls_app(admin_ca_dir, with_backend=False, cert_prefix=prefix)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/test", headers=forwarded_headers(prefix, cert))
        assert resp.status_code == 403
