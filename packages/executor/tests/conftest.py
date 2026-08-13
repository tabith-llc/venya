"""Shared fixtures for executor integration tests.

Provides test CA, executor certificates, mTLS HTTP clients,
and a FastAPI app with real CAManager for end-to-end testing.
"""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from starlette.testclient import TestClient

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager
from server.ca import CAManager


# ---------------------------------------------------------------------------
# CA and certificate helpers
# ---------------------------------------------------------------------------


def _make_ca_pair() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an ECDSA P-256 CA keypair and self-signed certificate."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Venya Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert


def _sign_executor_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    executor_id: str,
    validity_days: int = 30,
    executor_key: ec.EllipticCurvePrivateKey | None = None,
) -> x509.Certificate:
    """Sign an executor certificate with the given CA keypair."""
    if executor_key is None:
        executor_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(executor_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(executor_id)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert


def _create_csr(private_key: ec.EllipticCurvePrivateKey, executor_id: str) -> bytes:
    """Create a PEM-encoded CSR."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_ca_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with a valid CA keypair and certificate."""
    ca_key, ca_cert = _make_ca_pair()
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_dir.chmod(0o700)
    (ca_dir / "ca.key").write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (ca_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_dir


@pytest.fixture()
def ca_key(tmp_ca_dir: Path) -> Any:
    """Load the CA private key from the test CA directory."""
    return serialization.load_pem_private_key(
        (tmp_ca_dir / "ca.key").read_bytes(),
        password=None,
    )


@pytest.fixture()
def ca_cert(tmp_ca_dir: Path) -> x509.Certificate:
    """Load the CA certificate from the test CA directory."""
    return x509.load_pem_x509_certificate((tmp_ca_dir / "ca.crt").read_bytes())


@pytest.fixture()
def ca_manager(tmp_ca_dir: Path) -> CAManager:
    """Create and initialize a CAManager pointing to the test CA directory."""
    manager = CAManager(str(tmp_ca_dir))
    # Load the pre-generated CA (don't re-initialize)
    cert = x509.load_pem_x509_certificate((tmp_ca_dir / "ca.crt").read_bytes())
    private_key = serialization.load_pem_private_key(
        (tmp_ca_dir / "ca.key").read_bytes(),
        password=None,
    )
    # Monkey-patch load_ca to return our pre-generated CA
    original_load_ca = manager.load_ca
    manager.load_ca = lambda: (cert, private_key)  # type: ignore[method-assign]
    return manager


@pytest.fixture()
def executor_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 keypair for the test executor."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
def executor_cert(ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate) -> x509.Certificate:
    """Generate a CA-signed executor certificate (30-day validity)."""
    return _sign_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)


@pytest.fixture()
def executor_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private key for the test executor."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
def executor_csr(executor_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Create a CSR for the test executor."""
    return _create_csr(executor_key, "test-executor")


@pytest.fixture()
def cert_files(tmp_path: Path, executor_key: ec.EllipticCurvePrivateKey, executor_cert: x509.Certificate):
    """Write executor cert and key to disk, returning paths."""
    cert_path = str(tmp_path / "executor.crt")
    key_path = str(tmp_path / "executor.key")

    Path(cert_path).write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)

    key_pem = executor_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(key_path).write_bytes(key_pem)
    os.chmod(key_path, 0o600)

    return cert_path, key_path


@pytest.fixture()
def tls_client(tmp_ca_dir: Path, tmp_path: Path, ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate):
    """Create an httpx2.Client with real mTLS (cert + key + CA verification).

    This validates the full TLS certificate chain between executor and server.
    Generates a matching keypair and CA-signed cert for this fixture.
    """
    import ssl
    # Generate a matching keypair for this test
    test_key = ec.generate_private_key(ec.SECP256R1())
    test_cert = _sign_executor_cert(ca_key, ca_cert, "tls-test-executor", validity_days=30, executor_key=test_key)
    
    cert_pem = test_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = test_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    # Write cert and key to temp files
    cert_file = tmp_path / "tls_executor.crt"
    key_file = tmp_path / "tls_executor.key"
    cert_file.write_text(cert_pem)
    key_file.write_text(key_pem)
    # Build SSL context with CA verification + client cert
    ssl_ctx = ssl.create_default_context(cafile=str(tmp_ca_dir / "ca.crt"))
    ssl_ctx.check_hostname = False
    ssl_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return httpx2.Client(
        base_url="https://test-server.local",
        verify=ssl_ctx,
        timeout=30.0,
    )


@pytest.fixture()
def executor_config(tmp_path: Path, tmp_ca_dir: Path) -> ExecutorConfig:
    """Create an ExecutorConfig pointing to the test CA and temp cert paths."""
    return ExecutorConfig(
        server_url="https://test-server.local",
        executor_id="test-executor",
        mtls=MtlsConfig(
            ca_cert=str(tmp_ca_dir / "ca.crt"),
            cert=str(tmp_path / "executor.crt"),
            key=str(tmp_path / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(
            rotation_days=30,
            rotate_before_days=3,
        ),
    )


@pytest.fixture()
def cert_manager(executor_config: ExecutorConfig, tls_client: httpx2.Client) -> CertificateManager:
    """Create a CertificateManager with real mTLS client."""
    return CertificateManager(executor_config, tls_client)


# ---------------------------------------------------------------------------
# Dataclasses for mock DB records
# ---------------------------------------------------------------------------


class MockExecutorCert:
    """Mock ExecutorCert DB record."""

    def __init__(self, executor_id: str, serial_number: str, not_after: datetime, not_before: datetime | None = None):
        self.executor_id = executor_id
        self.serial_number = serial_number
        self.not_after = not_after
        self.not_before = not_before


class MockExecutorCertRevocation:
    """Mock ExecutorCertRevocation DB record."""

    def __init__(self, serial_number: str):
        self.serial_number = serial_number


class MockUser:
    """Mock User DB record."""

    def __init__(self, user_id: str, auth_mode: str = "mtls"):
        self.user_id = user_id
        self.auth_mode = auth_mode
