# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shared fixtures for executor integration tests.

Provides test CA, executor certificates, mTLS HTTP clients,
and a FastAPI app with real CAManager for end-to-end testing.
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager
from executor.strategies.sbx_strategy import SECRET_TMPFS_BASE

# The executor suite must also run on an executor-only install, where the
# server package is not shipped (#466). Guard the server import so the suite
# collects there; the skip is named and attributable, never silent.
try:
    from server.ca import CAManager

    SERVER_AVAILABLE = True
except ImportError:
    CAManager = None  # type: ignore[assignment]
    SERVER_AVAILABLE = False

SERVER_ABSENT_REASON = "server package absent — executor-only install (#466)"

if not SERVER_AVAILABLE:
    # test_integration.py imports server.routes at module level; without the
    # server package it is ignored BY NAME (never a collection crash, rc=4).
    # Header + guard cells below keep the skip loud and enumerated.
    collect_ignore = ["test_integration.py"]


def pytest_report_header(config):
    """Announce the #466 server-absent state so a skip is never anonymous."""
    if not SERVER_AVAILABLE:
        return [
            f"#466: {SERVER_ABSENT_REASON}",
            "#466: not collected (server-dependent, skipped by name): tests/test_integration.py",
        ]
    return []


# ---------------------------------------------------------------------------
# #565 — the executor key is written encrypted now, so every writer cell needs
# a passphrase in the environment, exactly as a deployed unit gets one from the
# installer's EnvironmentFile. TEST value only (AGENTS.md password protocol).
#
# This is an autouse fixture rather than 60 per-cell setenvs because the
# requirement is unconditional on this plane: NO cell that registers or rotates
# can succeed without it, so a per-cell opt-in would just relocate the same
# line 60 times and invite a new cell to forget it. The refusal cells are the
# exception and they call `no_executor_key_passphrase` explicitly — the negative
# half is stated, never inherited.
# ---------------------------------------------------------------------------

#: TEST passphrase for the executor key plane (>= the #573 floor of 15 code points).
TEST_EXECUTOR_KEY_PASSPHRASE = "test-executor-key-passphrase"  # pragma: allowlist secret — TEST value, never real


@pytest.fixture(autouse=True)
def _executor_key_passphrase_env(monkeypatch):
    """Supply the executor-key passphrase the way a deployed host does (env).

    Yields nothing; the value is exposed to cells that need to OPEN a written key
    through the `executor_key_passphrase` fixture below, so no test hard-codes the
    string and no cell can drift from what the autouse half actually sets.
    """
    monkeypatch.setenv("VENYA_EXECUTOR_KEY_PASSPHRASE", TEST_EXECUTOR_KEY_PASSPHRASE)


@pytest.fixture
def executor_key_passphrase() -> str:
    """The TEST passphrase the autouse env fixture sets — for cells that read a key back."""
    return TEST_EXECUTOR_KEY_PASSPHRASE


@pytest.fixture
def no_executor_key_passphrase(monkeypatch):
    """Opt-in for the refusal cells: this host has NO passphrase configured."""
    monkeypatch.delenv("VENYA_EXECUTOR_KEY_PASSPHRASE", raising=False)


# ---------------------------------------------------------------------------
# CA and certificate helpers
# ---------------------------------------------------------------------------


def _make_ca_pair() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an ECDSA P-256 CA keypair and self-signed certificate."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Venya Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA"),
        ]
    )
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
    now = datetime.now(UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )
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
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
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
    if not SERVER_AVAILABLE:
        pytest.skip(SERVER_ABSENT_REASON)
    manager = CAManager(str(tmp_ca_dir))
    # Load the pre-generated CA (don't re-initialize)
    cert = x509.load_pem_x509_certificate((tmp_ca_dir / "ca.crt").read_bytes())
    private_key = serialization.load_pem_private_key(
        (tmp_ca_dir / "ca.key").read_bytes(),
        password=None,
    )
    # Monkey-patch load_ca to return our pre-generated CA
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
            rotate_before_days=3,
        ),
    )


@pytest.fixture()
def cert_manager(executor_config: ExecutorConfig, tls_client: httpx2.Client) -> CertificateManager:
    """Create a CertificateManager with real mTLS client."""
    cm = CertificateManager(executor_config)
    cm.client = tls_client
    return cm


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

    def __init__(self, serial_number: str, revoked_at=None):
        self.serial_number = serial_number
        # updated: the shared revocation state (executor-revocation-by-identity)
        # surfaces the row's revoked_at — mock models the full schema.
        self.revoked_at = revoked_at


class MockUser:
    """Mock User DB record."""

    def __init__(self, user_id: str, auth_mode: str = "mtls"):
        self.user_id = user_id
        self.auth_mode = auth_mode


# ---------------------------------------------------------------------------
# tmpfs fixture for sbx strategy tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _setup_tmpfs(tmp_path: Path):
    """Ensure SECRET_TMPFS_BASE directory exists for sbx strategy tests.

    Creates a temp directory and patches SECRET_TMPFS_BASE to point to it.
    This is autouse so all tests get the patch without needing explicit fixture.
    """
    original = SECRET_TMPFS_BASE
    tmpfs_parent = tmp_path / "shm"
    tmpfs_parent.mkdir(exist_ok=True)
    import executor.strategies.sbx_strategy as sbx_module

    sbx_module.SECRET_TMPFS_BASE = str(tmpfs_parent)
    try:
        yield
    finally:
        sbx_module.SECRET_TMPFS_BASE = original
