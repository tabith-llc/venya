"""Tests for admin CA management CLI commands.

Tests cover:
- venya admin init-admin-ca — creates CA key/cert pair
- venya admin generate-admin-cert — signs admin client cert
"""

import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from venya_cli.commands import (
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

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
def admin_ca_initialized(admin_ca_dir):
    """Initialize an admin CA and return the directory path."""
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = "test_passphrase"
    args = type("Args", (), {"output_dir": admin_ca_dir})()
    result = cmd_admin_init_admin_ca(args)
    assert result == 0
    yield admin_ca_dir
    os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)


# ---------------------------------------------------------------------------
# Tests: init-admin-ca
# ---------------------------------------------------------------------------


class TestInitAdminCa:
    """Tests for venya admin init-admin-ca."""

    def test_init_admin_ca_creates_key_and_cert(self, admin_ca_dir):
        """init-admin-ca should create key/cert pair with correct permissions."""
        args = type("Args", (), {"output_dir": admin_ca_dir})()
        result = cmd_admin_init_admin_ca(args)

        assert result == 0
        assert Path(admin_ca_dir, "admin-ca.key").exists()
        assert Path(admin_ca_dir, "admin-ca.crt").exists()
        assert oct(Path(admin_ca_dir).stat().st_mode)[-3:] == "700"
        assert oct(Path(admin_ca_dir, "admin-ca.key").stat().st_mode)[-3:] == "600"
        assert oct(Path(admin_ca_dir, "admin-ca.crt").stat().st_mode)[-3:] == "644"

    def test_init_admin_ca_fails_when_exists(self, admin_ca_dir):
        """init-admin-ca should fail if CA already exists."""
        args1 = type("Args", (), {"output_dir": admin_ca_dir})()
        cmd_admin_init_admin_ca(args1)

        args2 = type("Args", (), {"output_dir": admin_ca_dir})()
        result = cmd_admin_init_admin_ca(args2)
        assert result == 1

    def test_init_admin_ca_key_is_ecdsa_p256(self, admin_ca_dir):
        """Admin CA key should be ECDSA P-256."""
        args = type("Args", (), {"output_dir": admin_ca_dir})()
        cmd_admin_init_admin_ca(args)

        key_data = Path(admin_ca_dir, "admin-ca.key").read_bytes()
        passphrase = os.environ.get("VENYA_ADMIN_CA_KEY_PASSPHRASE")
        key = serialization.load_pem_private_key(key_data, password=passphrase.encode() if passphrase else None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_init_admin_ca_cert_has_correct_subject(self, admin_ca_dir):
        """Admin CA cert should have correct subject."""
        args = type("Args", (), {"output_dir": admin_ca_dir})()
        cmd_admin_init_admin_ca(args)

        cert = x509.load_pem_x509_certificate(Path(admin_ca_dir, "admin-ca.crt").read_bytes())
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert len(org) == 1
        assert org[0].value == "Venya"
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert len(ou) == 1
        assert ou[0].value == "Admin Certificate Authority"
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) == 1
        assert cn[0].value == "Venya Admin CA"

    def test_init_admin_ca_cert_is_ca(self, admin_ca_dir):
        """Admin CA cert should have BasicConstraints CA=True."""
        args = type("Args", (), {"output_dir": admin_ca_dir})()
        cmd_admin_init_admin_ca(args)

        cert = x509.load_pem_x509_certificate(Path(admin_ca_dir, "admin-ca.crt").read_bytes())
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is True


# ---------------------------------------------------------------------------
# Tests: generate-admin-cert
# ---------------------------------------------------------------------------


class TestGenerateAdminCert:
    """Tests for venya admin generate-admin-cert."""

    def test_generate_admin_cert_creates_key_and_cert(self, admin_ca_initialized):
        """generate-admin-cert should produce valid signed cert."""
        output_dir = str(Path(admin_ca_initialized).parent / "admin-output")
        args = type(
            "Args",
            (),
            {
                "identity": "dust@montana",
                "ca_dir": admin_ca_initialized,
                "output_dir": output_dir,
            },
        )()
        result = cmd_admin_generate_admin_cert(args)

        assert result == 0
        assert Path(output_dir, "admin.key").exists()
        assert Path(output_dir, "admin.crt").exists()
        assert oct(Path(output_dir, "admin.key").stat().st_mode)[-3:] == "600"
        assert oct(Path(output_dir, "admin.crt").stat().st_mode)[-3:] == "644"

    def test_generate_admin_cert_correct_subject_san_eku(self, admin_ca_initialized):
        """Signed admin cert should have correct CN, SAN, EKU."""
        output_dir = str(Path(admin_ca_initialized).parent / "admin-output2")
        args = type(
            "Args",
            (),
            {
                "identity": "operator@venya.internal",
                "ca_dir": admin_ca_initialized,
                "output_dir": output_dir,
            },
        )()
        cmd_admin_generate_admin_cert(args)

        cert = x509.load_pem_x509_certificate(Path(output_dir, "admin.crt").read_bytes())

        # CN
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn) == 1
        assert cn[0].value == "operator@venya.internal"

        # SAN DNS
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "operator@venya.internal" in dns_names

        # EKU clientAuth
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

        # Not CA
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False

    def test_generate_admin_cert_signed_by_admin_ca(self, admin_ca_initialized):
        """Signed admin cert should verify against admin CA cert."""
        output_dir = str(Path(admin_ca_initialized).parent / "admin-output3")
        args = type(
            "Args",
            (),
            {
                "identity": "test-admin",
                "ca_dir": admin_ca_initialized,
                "output_dir": output_dir,
            },
        )()
        cmd_admin_generate_admin_cert(args)

        cert = x509.load_pem_x509_certificate(Path(output_dir, "admin.crt").read_bytes())
        ca_cert = x509.load_pem_x509_certificate(Path(admin_ca_initialized, "admin-ca.crt").read_bytes())

        cert.public_key()
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )

    def test_generate_admin_cert_missing_ca_key(self, tmp_path):
        """generate-admin-cert should fail if CA key not found."""
        output_dir = str(tmp_path / "output")
        args = type(
            "Args",
            (),
            {
                "identity": "test",
                "ca_dir": str(tmp_path / "nonexistent"),
                "output_dir": output_dir,
            },
        )()
        result = cmd_admin_generate_admin_cert(args)
        assert result == 1

    def test_generate_admin_cert_missing_ca_cert(self, admin_ca_initialized):
        """generate-admin-cert should fail if CA cert not found."""
        # Remove the cert file
        cert_path = Path(admin_ca_initialized, "admin-ca.crt")
        cert_path.unlink()

        output_dir = str(Path(admin_ca_initialized).parent / "output")
        args = type(
            "Args",
            (),
            {
                "identity": "test",
                "ca_dir": admin_ca_initialized,
                "output_dir": output_dir,
            },
        )()
        result = cmd_admin_generate_admin_cert(args)
        assert result == 1
