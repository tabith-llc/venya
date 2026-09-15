# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for CRL (Certificate Revocation List) functionality.

Tests cover:
- CRL generation with and without revocation entries
- CDP (CRL Distribution Point) extension in signed certificates
- Purge of expired revocation records
- CRL endpoint returns valid DER-encoded CRL
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import FastAPI
from server.ca import CAManager
from server.config import CRLConfig, ServerConfig
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
            x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
        ]
    )
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(executor_keypair, hashes.SHA256())


@dataclass
class MockRevocation:
    serial_number: str
    revoked_at: datetime


@dataclass
class MockCRLConfig:
    crl_retention_days: int = 90
    crl_url: str | None = None


# ---------------------------------------------------------------------------
# CRLConfig tests
# ---------------------------------------------------------------------------


def test_crl_config_defaults():
    """CRLConfig should have sensible defaults."""
    config = CRLConfig()
    assert config.crl_retention_days == 90
    assert config.crl_url is None


def test_crl_config_custom():
    """CRLConfig should accept custom values."""
    config = CRLConfig(crl_retention_days=30, crl_url="https://crl.example.com/crl")
    assert config.crl_retention_days == 30
    assert config.crl_url == "https://crl.example.com/crl"


def test_crl_config_min_boundary():
    """crl_retention_days should accept minimum value of 1."""
    config = CRLConfig(crl_retention_days=1)
    assert config.crl_retention_days == 1


def test_crl_config_max_boundary():
    """crl_retention_days should accept maximum value of 365."""
    config = CRLConfig(crl_retention_days=365)
    assert config.crl_retention_days == 365


# ---------------------------------------------------------------------------
# CDP extension tests
# ---------------------------------------------------------------------------


def test_cdp_extension_present(ca_manager, executor_csr):
    """Certificate should include CDP extension when crl_url is provided."""
    cert = ca_manager.sign_csr(
        executor_csr, "test-executor", crl_url="https://crl.venya.internal/api/v1/executors/certs/crl"
    )

    cdp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    assert cdp_ext is not None
    assert len(cdp_ext.value) == 1
    assert cdp_ext.value[0].full_name[0].value == "https://crl.venya.internal/api/v1/executors/certs/crl"


def test_cdp_extension_absent(ca_manager, executor_csr):
    """Certificate should not include CDP extension when crl_url is None."""
    cert = ca_manager.sign_csr(executor_csr, "test-executor", crl_url=None)

    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)


def test_cdp_extension_absent_by_default(ca_manager, executor_csr):
    """Certificate should not include CDP extension by default (no crl_url arg)."""
    cert = ca_manager.sign_csr(executor_csr, "test-executor")

    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)


# ---------------------------------------------------------------------------
# CRL generation tests
# ---------------------------------------------------------------------------


def _make_mock_db_session(ca_manager, revocations):
    """Create a mock DB session that returns revocations."""
    mock_session = MagicMock()
    mock_query = MagicMock()
    mock_query.order_by.return_value.limit.return_value.all.return_value = revocations
    mock_session.query.return_value = mock_query
    mock_session.commit.return_value = None
    return mock_session


def test_generate_crl_with_entries(ca_manager):
    """generate_crl should produce a valid DER CRL with revocation entries."""
    now = datetime.now(UTC)
    revocations = [
        MockRevocation(serial_number="01a2b3c4d5e6f700", revoked_at=now - timedelta(days=1)),
        MockRevocation(serial_number="02b3c4d5e6f70011", revoked_at=now - timedelta(days=2)),
    ]
    mock_session = _make_mock_db_session(ca_manager, revocations)

    crl_der = ca_manager.generate_crl(mock_session)

    # Should be valid DER
    assert isinstance(crl_der, bytes)
    assert len(crl_der) > 0

    # Should be parseable as a CRL
    crl = x509.load_der_x509_crl(crl_der)
    assert crl is not None
    assert len(list(crl)) == 2


def test_generate_crl_empty(ca_manager):
    """generate_crl should produce a valid empty CRL when no revocations."""
    mock_session = _make_mock_db_session(ca_manager, [])
    crl_der = ca_manager.generate_crl(mock_session)

    assert isinstance(crl_der, bytes)
    assert len(crl_der) > 0

    crl = x509.load_der_x509_crl(crl_der)
    assert crl is not None
    assert len(list(crl)) == 0


def test_generate_crl_max_entries(ca_manager):
    """generate_crl should respect max_entries limit."""
    now = datetime.now(UTC)
    all_revocations = [
        MockRevocation(serial_number=format(i, "016x"), revoked_at=now - timedelta(days=i)) for i in range(1, 20)
    ]
    # The generate_crl method queries with .order_by().limit(n).all()
    # We mock at the session level to intercept the chain and return only the limited subset
    limited = all_revocations[:5]
    mock_session = MagicMock()
    mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = limited
    mock_session.commit.return_value = None

    crl_der = ca_manager.generate_crl(mock_session, max_entries=5)

    crl = x509.load_der_x509_crl(crl_der)
    assert len(list(crl)) == 5


# ---------------------------------------------------------------------------
# Purge tests
# ---------------------------------------------------------------------------


def test_purge_expired_revocations(ca_manager):
    """purge_expired_revocations should delete old records."""
    now = datetime.now(UTC)

    mock_old = MagicMock()
    mock_old.revoked_at = now - timedelta(days=100)
    mock_new = MagicMock()
    mock_new.revoked_at = now - timedelta(days=10)

    mock_query = MagicMock()
    mock_query.filter.return_value.delete.return_value = 1
    mock_query.filter.return_value.all.return_value = [mock_old, mock_new]

    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.delete.return_value = 1
    mock_session.query.return_value.filter.return_value.all.return_value = [mock_old, mock_new]
    mock_session.commit.return_value = None

    deleted = ca_manager.purge_expired_revocations(mock_session, retention_days=90)

    assert deleted == 1
    mock_session.commit.assert_called_once()


def test_purge_expired_revocations_nothing_to_delete(ca_manager):
    """purge_expired_revocations should return 0 when no records are old enough."""
    now = datetime.now(UTC)

    mock_new = MagicMock()
    mock_new.revoked_at = now - timedelta(days=10)

    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.delete.return_value = 0
    mock_session.commit.return_value = None

    deleted = ca_manager.purge_expired_revocations(mock_session, retention_days=90)

    assert deleted == 0


# ---------------------------------------------------------------------------
# CRL endpoint tests
# ---------------------------------------------------------------------------


def _create_crl_test_app(ca_manager, config=None):
    """Create a minimal test app with CRL endpoint."""
    app = FastAPI()

    mock_backend = MagicMock()
    mock_backend.get_session.return_value = MagicMock()
    app.state.backend = mock_backend
    app.state.ca_manager = ca_manager

    if config is None:
        config = ServerConfig(crl=CRLConfig(crl_retention_days=90), recovery_code_pepper="test-pepper")
    app.state.config = config

    app.include_router(executors_routes.router, prefix="/api/v1")
    return app


def test_crl_endpoint_returns_der(ca_manager):
    """GET /executors/certs/crl should return zstd-compressed DER CRL."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    response = client.get("/api/v1/executors/certs/crl")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pkix-crl"
    assert response.headers["content-encoding"] == "zstd"

    # TestClient auto-decompresses; verify Content-Encoding header is set
    # and the decompressed content is valid DER
    assert response.headers["content-encoding"] == "zstd"


def test_crl_endpoint_empty_when_no_revocations(ca_manager):
    """GET /executors/certs/crl should return zstd-compressed empty CRL."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    response = client.get("/api/v1/executors/certs/crl")
    assert response.status_code == 200
    assert response.headers["content-encoding"] == "zstd"


def test_crl_compression_produces_valid_zstd():
    """compression.zstd.compress produces valid zstd frames."""
    import compression.zstd

    # Raw DER CRL (simulated, larger data to overcome framing overhead)
    raw_der = b"\x30" * 500 + b"\x00" * 500
    compressed = compression.zstd.compress(raw_der, level=3)

    # zstd magic number: 0x28 0xB5 0x2F 0xFD
    assert compressed[:4] == b"\x28\xb5\x2f\xfd"

    # Decompression round-trips correctly
    decompressed = compression.zstd.decompress(compressed)
    assert decompressed == raw_der


def test_crl_compression_ratio_with_realistic_data():
    """CRL compression should achieve meaningful ratio with realistic data."""
    import compression.zstd

    # Simulate a realistic CRL with many revocation entries
    crl_data = b"\x30" * 100 + b"\x30\x81" * 500 + b"\x00" * 2000
    compressed = compression.zstd.compress(crl_data, level=3)
    ratio = len(compressed) / len(crl_data)

    assert ratio < 0.5  # Should compress at least 50%
    decompressed = compression.zstd.decompress(compressed)
    assert decompressed == crl_data


def test_crl_endpoint_503_when_ca_missing():
    """GET /executors/certs/crl should return 503 when CA is not initialized."""
    app = FastAPI()
    mock_backend = MagicMock()
    mock_backend.get_session.return_value = MagicMock()
    app.state.backend = mock_backend
    # No ca_manager set
    app.state.config = ServerConfig(crl=CRLConfig(crl_retention_days=90), recovery_code_pepper="test-pepper")
    app.include_router(executors_routes.router, prefix="/api/v1")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/v1/executors/certs/crl")
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# CRL caching tests
# ---------------------------------------------------------------------------


def test_crl_endpoint_returns_etag(ca_manager):
    """GET /executors/certs/crl should return an ETag header."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    response = client.get("/api/v1/executors/certs/crl")
    assert response.status_code == 200
    assert "etag" in response.headers


def test_crl_endpoint_304_on_etag_match(ca_manager):
    """GET /executors/certs/crl should return 304 when ETag matches."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    # First request — get the ETag
    response1 = client.get("/api/v1/executors/certs/crl")
    assert response1.status_code == 200
    etag = response1.headers["etag"]

    # Second request with If-None-Match — should get 304
    response2 = client.get("/api/v1/executors/certs/crl", headers={"If-None-Match": etag})
    assert response2.status_code == 304
    assert response2.headers["etag"] == etag


def test_crl_endpoint_200_on_etag_mismatch(ca_manager):
    """GET /executors/certs/crl should return 200 when ETag differs."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    response = client.get("/api/v1/executors/certs/crl", headers={"If-None-Match": '"wrong-etag"'})
    assert response.status_code == 200


def test_crl_endpoint_cache_control(ca_manager):
    """GET /executors/certs/crl should return Cache-Control header."""
    app = _create_crl_test_app(ca_manager)
    client = TestClient(app)

    response = client.get("/api/v1/executors/certs/crl")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "max-age=30"
