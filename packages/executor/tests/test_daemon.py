# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor daemon CertificateManager.

Tests registration, rotation, revocation checking, and fingerprint
computation using real ECDSA P-256 cryptography with mocked HTTP.
"""

import hashlib
import os
import ssl
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import (
    CertificateManager,
    CertificateValidationError,
    _create_csr,
    _extract_executor_id_from_cert,
    _generate_ecdsa_p256_keypair,
    _verify_ca_signature,
    build_command_policy,
    validate_executor_certificate,
)

# --- Fixtures ---


def _make_ca_pair() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a CA keypair and self-signed certificate."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
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


def _make_executor_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    executor_id: str,
    validity_days: int = 30,
) -> x509.Certificate:
    """Sign an executor certificate with the CA."""
    key = ec.generate_private_key(ec.SECP256R1())
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
        .public_key(key.public_key())
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


@pytest.fixture()
def tmp_ca_dir(tmp_path: Path) -> Path:
    """Create a temporary CA directory with a valid CA cert."""
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
def config(tmp_path: Path, tmp_ca_dir: Path) -> ExecutorConfig:
    """Create an executor config pointing to the temporary CA."""
    return ExecutorConfig(
        server_url="https://example.com",
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
def client() -> httpx2.Client:
    """Create a temporary httpx client."""
    return httpx2.Client(base_url="https://example.com", verify=False)


@pytest.fixture()
def cert_manager(config: ExecutorConfig, client: httpx2.Client) -> CertificateManager:
    """Create a CertificateManager instance with mTLS client for rotate/check_revocation."""
    cm = CertificateManager(config)
    cm.client = client
    return cm


# --- Helper: create mock server response ---


def _make_mock_response(cert: x509.Certificate, ca_cert: x509.Certificate, serial: int) -> httpx2.Response:
    """Create a mocked httpx2.Response for a successful registration."""
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = format(serial, "016x")
    not_after = cert.not_valid_after_utc.isoformat()

    json_data = {
        "executor_id": "test-executor",
        "cert_pem": cert_pem,
        "ca_cert_pem": ca_cert_pem,
        "serial_number": serial_hex,
        "not_after": not_after,
    }

    mock_response = MagicMock(spec=httpx2.Response)
    mock_response.status_code = 201
    mock_response.json.return_value = json_data
    mock_response.raise_for_status.return_value = None
    return mock_response


# --- Tests: register ---


class TestRegister:
    """Tests for CertificateManager.register()."""

    def test_register_generates_and_stores_cert(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Registration generates keypair, CSR, gets signed cert, and saves to disk."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")

        mock_response = _make_mock_response(executor_cert, ca_cert, executor_cert.serial_number)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            cert_manager.register("test-executor")

        # Verify throwaway client was created with verify=True
        verify_arg = MockClient.call_args[1]["verify"]
        assert verify_arg is True or isinstance(verify_arg, ssl.SSLContext)
        assert MockClient.call_args[1]["timeout"] == 30.0

        # Verify files were created
        assert os.path.exists(cert_manager.cert_path)
        assert os.path.exists(cert_manager.key_path)

        # Verify file permissions (private key should be 0o600)
        key_mode = stat.S_IMODE(os.stat(cert_manager.key_path).st_mode)
        assert key_mode == 0o600

        # Verify certificate was saved correctly
        saved_cert = x509.load_pem_x509_certificate(Path(cert_manager.cert_path).read_bytes())
        assert saved_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test-executor"

        # Verify serial was stored
        assert cert_manager.serial == format(executor_cert.serial_number, "016x")

    def test_register_saves_ca_cert(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Registration saves the CA cert from the server response."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")

        mock_response = _make_mock_response(executor_cert, ca_cert, executor_cert.serial_number)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            cert_manager.register("test-executor")

        # CA cert should be saved
        assert os.path.exists(cert_manager.ca_cert_path)
        saved_ca = x509.load_pem_x509_certificate(Path(cert_manager.ca_cert_path).read_bytes())
        assert saved_ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Venya Root CA"

    def test_register_skips_when_cert_exists(self, cert_manager: CertificateManager):
        """Registration is skipped if cert and key already exist on disk."""
        # Pre-create cert and key files
        Path(cert_manager.cert_path).write_bytes(b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----")
        Path(cert_manager.key_path).write_bytes(b"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----")

        with patch("executor.daemon.httpx2.Client") as MockClient:
            cert_manager.register("test-executor")
            MockClient.assert_not_called()

        # Serial should be loaded from existing cert (even if fake, no error)
        # With a fake cert, _load_metadata will fail, but register should
        # still skip the server call


class TestRegisterErrors:
    """Error cases for CertificateManager.register()."""

    def test_register_server_error(self, cert_manager: CertificateManager):
        """Registration raises HTTPError when server returns error."""
        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "400 Bad Request",
            request=MagicMock(),
            response=MagicMock(),
        )

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            with pytest.raises(httpx2.HTTPStatusError):
                cert_manager.register("test-executor")

    def test_register_readonly_cert_dir_fails_fast(self, config: ExecutorConfig, tmp_ca_dir: Path):
        """Unwritable cert dir → actionable RuntimeError BEFORE any HTTP call (F1)."""
        cm = CertificateManager(config)
        tmp_ca_dir.chmod(0o500)
        try:
            with patch("executor.daemon.httpx2.Client") as MockClient:
                with pytest.raises(RuntimeError, match="VENYA_EXECUTOR_ENROLLMENT_TOKEN"):
                    cm.register("test-executor")
                MockClient.assert_not_called()
        finally:
            tmp_ca_dir.chmod(0o700)

    def test_register_write_failure_raises_actionable(self, cert_manager: CertificateManager):
        """OSError during cert save → actionable RuntimeError (paired: pre-check passed, write failed)."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")
        mock_response = _make_mock_response(executor_cert, ca_cert, executor_cert.serial_number)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            with patch.object(Path, "write_bytes", side_effect=OSError(30, "Read-only file system")):
                with pytest.raises(RuntimeError, match="could not be saved locally"):
                    cert_manager.register("test-executor")

    def test_register_invalid_ca_signature(self, config: ExecutorConfig):
        """Registration raises CertificateValidationError when cert is not signed by CA."""
        # Create a cert signed by a DIFFERENT CA
        _ca_key1, ca_cert1 = _make_ca_pair()
        other_ca_key, other_ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(other_ca_key, other_ca_cert, "test-executor")

        mock_response = _make_mock_response(executor_cert, ca_cert1, executor_cert.serial_number)

        mgr = CertificateManager(config)
        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
                mgr.register("test-executor")


# --- Tests: needs_rotation ---


class TestNeedsRotation:
    """Tests for CertificateManager.needs_rotation()."""

    def test_needs_rotation_no_cert(self, cert_manager: CertificateManager):
        """Returns True when no certificate exists."""
        assert cert_manager.needs_rotation() is True

    def test_needs_rotation_not_expired(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Returns False when certificate expires well in the future."""
        ca_key, ca_cert = _make_ca_pair()
        # Certificate valid for 35 days (beyond 3-day rotation threshold)
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=35)

        Path(cert_manager.cert_path).write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))

        assert cert_manager.needs_rotation() is False

    def test_needs_rotation_expiring_soon(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Returns True when certificate expires within rotate_before_days."""
        ca_key, ca_cert = _make_ca_pair()
        # Certificate valid for 2 days (within 3-day rotation threshold)
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=2)

        Path(cert_manager.cert_path).write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))

        assert cert_manager.needs_rotation() is True

    def test_needs_rotation_expired(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Returns True when certificate has already expired."""
        ca_key, ca_cert = _make_ca_pair()
        # Certificate valid for 1 day (already expired relative to threshold)
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=1)

        Path(cert_manager.cert_path).write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))

        assert cert_manager.needs_rotation() is True


# --- Tests: rotate ---


class TestRotate:
    """Tests for CertificateManager.rotate()."""

    def test_rotate_success(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Rotation generates new keypair, submits CSR, installs new cert."""
        ca_key, ca_cert = _make_ca_pair()

        # Create initial cert
        initial_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        Path(cert_manager.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Create new cert (simulating server response after rotation)
        new_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        mock_response = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)

        with patch.object(cert_manager.client, "post", return_value=mock_response):
            cert_manager.rotate()

        # Verify new cert was installed
        saved_cert = x509.load_pem_x509_certificate(Path(cert_manager.cert_path).read_bytes())
        assert saved_cert.serial_number == new_cert.serial_number

        # Verify new key was installed
        saved_key = serialization.load_pem_private_key(
            Path(cert_manager.key_path).read_bytes(),
            password=None,
        )
        assert isinstance(saved_key, ec.EllipticCurvePrivateKey)

        # Verify serial updated
        assert cert_manager.serial == format(new_cert.serial_number, "016x")

        # Verify key permissions
        key_mode = stat.S_IMODE(os.stat(cert_manager.key_path).st_mode)
        assert key_mode == 0o600

    def test_rotate_no_existing_cert(self, cert_manager: CertificateManager):
        """Rotation raises RuntimeError when no certificate exists."""
        with pytest.raises(RuntimeError, match="must register first"):
            cert_manager.rotate()


# --- Tests: get_fingerprint ---


class TestGetFingerprint:
    """Tests for CertificateManager.get_fingerprint()."""

    def test_get_fingerprint_with_cert(self, cert_manager: CertificateManager, tmp_ca_dir: Path):
        """Fingerprint matches server CAManager.compute_fingerprint for same cert."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")

        Path(cert_manager.cert_path).write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))

        fingerprint = cert_manager.get_fingerprint()

        # Verify it's a valid hex string
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # SHA-256 hex digest
        int(fingerprint, 16)  # Should not raise

        # Verify it matches direct computation
        der = executor_cert.public_bytes(serialization.Encoding.DER)
        expected = hashlib.sha256(der).hexdigest()
        assert fingerprint == expected

    def test_get_fingerprint_no_cert(self, cert_manager: CertificateManager):
        """Returns empty string when no certificate exists."""
        assert cert_manager.get_fingerprint() == ""


# --- Tests: check_revocation ---


class TestCheckRevocation:
    """Tests for CertificateManager.check_revocation()."""

    def test_check_revocation_revoked(self, cert_manager: CertificateManager):
        """Returns True when serial is in the revocation list."""
        cert_manager.serial = "0000000000000001"

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 200
        mock_response.headers = {"etag": '"abc123"'}
        mock_response.json.return_value = {"revoked_serials": ["0000000000000001", "0000000000000002"]}
        mock_response.raise_for_status.return_value = None

        with patch.object(cert_manager.client, "get", return_value=mock_response):
            assert cert_manager.check_revocation() is True

    def test_check_revocation_not_revoked(self, cert_manager: CertificateManager):
        """Returns False when serial is not in the revocation list."""
        cert_manager.serial = "0000000000000001"

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 200
        mock_response.headers = {"etag": '"def456"'}
        mock_response.json.return_value = {"revoked_serials": ["0000000000000002"]}
        mock_response.raise_for_status.return_value = None

        with patch.object(cert_manager.client, "get", return_value=mock_response):
            assert cert_manager.check_revocation() is False

    def test_check_revocation_empty_list(self, cert_manager: CertificateManager):
        """Returns False when revocation list is empty."""
        cert_manager.serial = "0000000000000001"

        mock_response = MagicMock(spec=httpx2.Response)
        mock_response.status_code = 200
        mock_response.headers = {"etag": '"empty"'}
        mock_response.json.return_value = {"revoked_serials": []}
        mock_response.raise_for_status.return_value = None

        with patch.object(cert_manager.client, "get", return_value=mock_response):
            assert cert_manager.check_revocation() is False

    def test_check_revocation_no_serial(self, cert_manager: CertificateManager):
        """Returns False when serial is not set."""
        cert_manager.serial = None

        with patch.object(cert_manager.client, "get") as mock_get:
            assert cert_manager.check_revocation() is False
            mock_get.assert_not_called()

    def test_check_revocation_server_unreachable(self, cert_manager: CertificateManager):
        """Returns False (graceful degradation) when server is unreachable."""
        cert_manager.serial = "0000000000000001"

        with patch.object(
            cert_manager.client, "get", side_effect=httpx2.RequestError("Connection refused", request=MagicMock())
        ):
            assert cert_manager.check_revocation() is False


# --- Tests: helper functions ---


class TestHelperFunctions:
    """Tests for CertificateManager helper functions."""

    def test_generate_ecdsa_p256_keypair(self):
        """Generates an ECDSA P-256 private key."""
        key = _generate_ecdsa_p256_keypair()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_create_csr(self):
        """Creates a valid CSR with the given executor_id as CN."""
        key = _generate_ecdsa_p256_keypair()
        csr_pem = _create_csr(key, "my-executor")

        csr = x509.load_pem_x509_csr(csr_pem)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "my-executor"

    def test_validate_ca_signature_valid(self):
        """Accepts a certificate signed by the given CA."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")

        # Should not raise
        _verify_ca_signature(
            executor_cert,
            ca_cert,
        )

    def test_validate_ca_signature_invalid(self):
        """Rejects a certificate signed by a different CA."""
        _ca_key1, ca_cert1 = _make_ca_pair()
        ca_key2, ca_cert2 = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key2, ca_cert2, "test-executor")

        with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
            _verify_ca_signature(
                executor_cert,
                ca_cert1,
            )


class TestValidateExecutorCertificate:
    """Tests for validate_executor_certificate()."""

    def test_valid_cert_passes(self, tmp_ca_dir: Path):
        """A properly formed cert with all correct extensions passes validation."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")

        # Should not raise
        validate_executor_certificate(
            executor_cert.public_bytes(serialization.Encoding.PEM),
            ca_cert.public_bytes(serialization.Encoding.PEM),
            "test-executor",
        )

    def test_cn_mismatch_raises(self, tmp_ca_dir: Path):
        """Rejects cert where CN does not match expected executor_id."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "other-executor")

        with pytest.raises(CertificateValidationError, match="CN mismatch"):
            validate_executor_certificate(
                executor_cert.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_expired_cert_raises(self, tmp_ca_dir: Path):
        """Rejects cert that has expired."""
        ca_key, ca_cert = _make_ca_pair()
        now = datetime.now(UTC)
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=60))
            .not_valid_after(now - timedelta(days=1))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Certificate expired"):
            validate_executor_certificate(
                expired_cert.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_not_yet_valid_raises(self, tmp_ca_dir: Path):
        """Rejects cert that is not yet valid."""
        ca_key, ca_cert = _make_ca_pair()
        now = datetime.now(UTC)
        future_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=30))
            .not_valid_after(now + timedelta(days=60))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Certificate not yet valid"):
            validate_executor_certificate(
                future_cert.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_ca_true_raises(self, tmp_ca_dir: Path):
        """Rejects cert with BasicConstraints CA=True."""
        ca_key, ca_cert = _make_ca_pair()
        ca_cert_with_ca_true = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="CA=True"):
            validate_executor_certificate(
                ca_cert_with_ca_true.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_missing_basic_constraints_raises(self, tmp_ca_dir: Path):
        """Rejects cert missing BasicConstraints extension."""
        ca_key, ca_cert = _make_ca_pair()
        cert_no_bc = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Missing BasicConstraints"):
            validate_executor_certificate(
                cert_no_bc.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_missing_key_usage_raises(self, tmp_ca_dir: Path):
        """Rejects cert missing KeyUsage extension."""
        ca_key, ca_cert = _make_ca_pair()
        cert_no_ku = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Missing KeyUsage"):
            validate_executor_certificate(
                cert_no_ku.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_missing_eku_raises(self, tmp_ca_dir: Path):
        """Rejects cert missing ExtendedKeyUsage extension."""
        ca_key, ca_cert = _make_ca_pair()
        cert_no_eku = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Missing ExtendedKeyUsage"):
            validate_executor_certificate(
                cert_no_eku.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_eku_missing_client_auth_raises(self, tmp_ca_dir: Path):
        """Rejects cert with EKU but without clientAuth."""
        ca_key, ca_cert = _make_ca_pair()
        cert_server_auth = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="EKU missing clientAuth"):
            validate_executor_certificate(
                cert_server_auth.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_bad_ca_signature_raises(self, tmp_ca_dir: Path):
        """Rejects cert signed by a different CA."""
        _ca_key1, ca_cert1 = _make_ca_pair()
        ca_key2, ca_cert2 = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key2, ca_cert2, "test-executor")

        with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
            validate_executor_certificate(
                executor_cert.public_bytes(serialization.Encoding.PEM),
                ca_cert1.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_clock_skew_tolerance_within_limit(self, tmp_ca_dir: Path):
        """Accepts cert expired within 5-minute clock skew tolerance."""
        ca_key, ca_cert = _make_ca_pair()
        now = datetime.now(UTC)
        # Expired 2 minutes ago — within 5-minute tolerance
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(minutes=2))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Should not raise — within tolerance
        validate_executor_certificate(
            cert.public_bytes(serialization.Encoding.PEM),
            ca_cert.public_bytes(serialization.Encoding.PEM),
            "test-executor",
        )

    def test_clock_skew_tolerance_beyond_limit(self, tmp_ca_dir: Path):
        """Rejects cert expired beyond 5-minute clock skew tolerance."""
        ca_key, ca_cert = _make_ca_pair()
        now = datetime.now(UTC)
        # Expired 10 minutes ago — beyond 5-minute tolerance
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "test-executor"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(minutes=10))
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
                x509.SubjectAlternativeName([x509.DNSName("test-executor")]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with pytest.raises(CertificateValidationError, match="Certificate expired"):
            validate_executor_certificate(
                cert.public_bytes(serialization.Encoding.PEM),
                ca_cert.public_bytes(serialization.Encoding.PEM),
                "test-executor",
            )

    def test_extract_executor_id_from_cert(self):
        """Extracts the CN from a certificate."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "my-special-executor")

        tmp_cert = Path("/tmp/test_extract_cert.pem")
        tmp_cert.write_bytes(executor_cert.public_bytes(serialization.Encoding.PEM))
        try:
            result = _extract_executor_id_from_cert(str(tmp_cert))
            assert result == "my-special-executor"
        finally:
            tmp_cert.unlink()

    def test_extract_executor_id_from_cert_no_cn(self):
        """Raises ValueError when certificate has no CN."""
        ca_key, ca_cert = _make_ca_pair()
        # Create cert without CN
        now = datetime.now(UTC)
        cert_no_cn = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                    ]
                )
            )
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )

        tmp_cert = Path("/tmp/test_extract_no_cn.pem")
        tmp_cert.write_bytes(cert_no_cn.public_bytes(serialization.Encoding.PEM))
        try:
            with pytest.raises(ValueError, match="no CN"):
                _extract_executor_id_from_cert(str(tmp_cert))
        finally:
            tmp_cert.unlink()


class TestBuildCommandPolicy:
    """Regression: daemon's policy construction must populate trusted_paths for balanced mode."""

    def _make_cv(self, preset: str, **kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(preset=preset, **kwargs)

    def test_balanced_gets_default_trusted_paths(self):
        from executor.command_validator import DEFAULT_TRUSTED_PATHS

        cv = self._make_cv("balanced", allowed_commands=None, dangerous_patterns=None, match_word_boundaries=True)
        policy = build_command_policy(cv)
        assert policy.trusted_paths == frozenset(DEFAULT_TRUSTED_PATHS)

    def test_strict_has_empty_trusted_paths(self):
        cv = self._make_cv(
            "strict", allowed_commands=["/usr/bin/ls"], dangerous_patterns=None, match_word_boundaries=True
        )
        policy = build_command_policy(cv)
        assert policy.trusted_paths == frozenset()
        assert policy.allowed_commands == frozenset({"/usr/bin/ls"})

    def test_permissive_has_empty_trusted_paths(self):
        cv = self._make_cv("permissive", allowed_commands=None, dangerous_patterns=None, match_word_boundaries=True)
        policy = build_command_policy(cv)
        assert policy.trusted_paths == frozenset()


class TestDeafBootRefusal:
    """Ticket relay-listener-empty-allowlist-not-observable (option B): a
    daemon that cannot bind its relay must not boot healthy-looking — it
    exits non-zero BEFORE consuming the one-shot enrollment token, so
    systemd status/journal show the failure instead of a deaf 'running'."""

    def _daemon(self, config):
        from executor.daemon import ExecutorDaemon

        d = ExecutorDaemon(config)
        d.cert_manager = MagicMock()
        d.reaper = MagicMock()
        return d

    def test_empty_allowlist_exits_before_registration(self, config):
        assert config.relay_client_ids == []  # fixture default is the broken shape
        d = self._daemon(config)
        with pytest.raises(SystemExit) as exc:
            d.start()
        assert exc.value.code == 1
        d.cert_manager.register.assert_not_called()  # one-shot token not consumed
        assert d.state.running is False

    def test_nonempty_allowlist_passes_the_guard(self, config):
        """Paired negative: the guard fires ONLY on the broken shape."""
        cfg = config.model_copy(update={"relay_client_ids": ["core-relay"]})
        d = self._daemon(cfg)
        sentinel = RuntimeError("past-the-guard")
        d.cert_manager.register.side_effect = sentinel
        with pytest.raises(RuntimeError) as exc:
            d.start()
        assert exc.value is sentinel  # reached registration ⇒ guard passed

    def test_bind_failure_also_refuses(self, config):
        """Bind/SSL deaf class: relay.start() ran but listener never bound → exit 1."""
        cfg = config.model_copy(update={"relay_client_ids": ["core-relay"]})
        d = self._daemon(cfg)
        d._create_mtls_client = MagicMock(return_value=MagicMock())
        d.relay = MagicMock()
        d.relay.active = False
        with pytest.raises(SystemExit) as exc:
            d.start()
        assert exc.value.code == 1
        assert d.state.running is False

    def test_bound_relay_proceeds(self, config):
        """Happy-path invariant (acceptance #2): bound relay → normal start."""
        cfg = config.model_copy(update={"relay_client_ids": ["core-relay"]})
        d = self._daemon(cfg)
        d._create_mtls_client = MagicMock(return_value=MagicMock())
        d.relay = MagicMock()
        d.relay.active = True
        d._main_loop = MagicMock()
        d.stop = MagicMock()
        d._write_pidfile = MagicMock()
        d.start()
        assert d.state.running is True
        d._main_loop.assert_called_once()


class TestMtlsMaterialNamedError:
    """Ticket refactor-1-config-consolidation residual (executor polish):
    missing/unusable mTLS material must produce a NAMED single-line error —
    at STARTUP it refuses boot (exit 1); at RUNTIME (rotation rebuild) it
    stays an Exception so _main_loop's tolerant handler keeps the daemon
    alive (SystemExit would bypass `except Exception` and kill it)."""

    def test_missing_mtls_files_named_runtime_error(self, config, caplog):
        import logging

        from executor.daemon import ExecutorDaemon

        d = ExecutorDaemon(config)
        # fixture config points mtls.cert/key at nonexistent tmp_path files
        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="mTLS material unusable"):
                d._create_mtls_client()
        assert "mTLS material unusable" in caplog.text
        assert config.mtls.cert in caplog.text

    def test_startup_refuses_when_client_unbuildable(self, config):
        """start() converts the named RuntimeError into SystemExit(1) —
        systemd shows failed instead of a daemon with a dead control channel."""
        from executor.daemon import ExecutorDaemon

        cfg = config.model_copy(update={"relay_client_ids": ["core-relay"]})
        d = ExecutorDaemon(cfg)
        d.cert_manager = MagicMock()
        d.reaper = MagicMock()
        d._create_mtls_client = MagicMock(side_effect=RuntimeError("mTLS material unusable: boom"))
        with pytest.raises(SystemExit) as exc:
            d.start()
        assert exc.value.code == 1
        assert d.state.running is False

    def test_runtime_rotation_failure_stays_tolerant(self, config):
        """Paired invariant: _main_loop's rotation block catches the rebuild
        failure (Exception subclass) and keeps looping — no SystemExit leak."""
        from executor.daemon import ExecutorDaemon

        d = ExecutorDaemon(config)
        d.client = MagicMock()
        d.state.running = True
        d._create_mtls_client = MagicMock(side_effect=RuntimeError("mTLS material unusable: boom"))
        loops = [0]

        def stop_after(*_a, **_k):
            loops[0] += 1
            d.state.running = False

        with patch.object(d.cert_manager, "needs_rotation", return_value=True):
            with patch.object(d.cert_manager, "rotate", side_effect=stop_after):
                with patch.object(d.cert_manager, "check_revocation", return_value=False):
                    with patch.object(d, "_send_heartbeat"):
                        with patch.object(d._shutdown_event, "wait", return_value=False):
                            d._main_loop()  # must not raise

        assert loops[0] >= 1
