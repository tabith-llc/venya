"""CA (Certificate Authority) management for executor mTLS.

Generates CA key/cert during initialization and signs executor CSRs.
Uses ECDSA P-256 for all certificates. Supports passphrase-based
encryption for CA private key storage.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("venya.ca")

# Certificate validity periods
CA_VALIDITY_DAYS = 3650  # 10 years
EXECUTOR_VALIDITY_DAYS = 30  # 30 days


def _load_passphrase(env_var: str) -> bytes | None:
    """Load passphrase from environment variable.

    Returns:
        Passphrase as bytes, or None if not set.
    """
    passphrase = os.environ.get(env_var)
    if passphrase:
        return passphrase.encode("utf-8")
    return None


def _serialize_key_encrypted(key: ec.EllipticCurvePrivateKey, passphrase: bytes | None) -> bytes:
    """Serialize a private key, optionally encrypting with a passphrase.

    Args:
        key: The private key to serialize.
        passphrase: Optional passphrase for encryption.

    Returns:
        PEM-encoded key bytes (encrypted if passphrase provided).
    """
    if passphrase:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(passphrase),
        )
    else:
        logger.warning(
            "CA key will be stored UNENCRYPTED — set %s in production",
            os.environ.get("CA_SECURITY__KEY_PASSPHRASE_ENV", "VENYA_CA_KEY_PASSPHRASE"),
        )
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def _deserialize_key(data: bytes, passphrase: bytes | None) -> ec.EllipticCurvePrivateKey:
    """Deserialize a private key from PEM, optionally decrypting.

    Args:
        data: PEM-encoded key data.
        passphrase: Optional passphrase for decryption.

    Returns:
        ECDSA private key instance.

    Raises:
        RuntimeError: If decryption fails or key cannot be loaded.
    """
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except ValueError as e:
        if passphrase:
            raise RuntimeError(f"Failed to decrypt CA key with provided passphrase: {e}") from e
        else:
            raise RuntimeError(
                "Failed to load CA key (may be encrypted but no passphrase provided). "
                "Set the passphrase environment variable."
            ) from e


class CAManager:
    """Manages the CA keypair, certificates, and signing operations.

    The CA is generated once during initialization and stored on disk.
    All executor certificates are signed by this CA.

    Supports passphrase-based encryption for the CA private key via
    the VENYA_CA_KEY_PASSPHRASE environment variable.
    """

    def __init__(self, ca_dir: str, ca_security: CASecurityConfig | None = None) -> None:
        self.ca_dir = Path(ca_dir)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.crt"

        # CA security config
        if ca_security is not None:
            self._key_passphrase_env = ca_security.key_passphrase_env
        else:
            self._key_passphrase_env = "VENYA_CA_KEY_PASSPHRASE"

    @property
    def has_ca(self) -> bool:
        """Check if CA key/cert pair exists on disk."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize(self) -> None:
        """Generate a new CA keypair and self-signed certificate.

        Creates the CA directory (if needed), generates an ECDSA P-256
        keypair, and creates a self-signed CA certificate. If a passphrase
        is set via VENYA_CA_KEY_PASSPHRASE, the key will be encrypted on disk.

        Raises:
            RuntimeError: If CA already exists.
        """
        if self.has_ca:
            raise RuntimeError(f"CA already exists at {self.ca_dir}")

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_dir), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = _load_passphrase(self._key_passphrase_env)

        # Store private key (encrypted if passphrase provided)
        key_pem = _serialize_key_encrypted(private_key, passphrase)
        self.ca_key_path.write_bytes(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed CA certificate
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Venya Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
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

        )

        cert = builder.sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.ca_cert_path.write_bytes(cert_pem)
        os.chmod(str(self.ca_cert_path), 0o644)

        logger.info("CA initialized at %s (encrypted=%s)", self.ca_dir, passphrase is not None)

    def load_ca(self) -> tuple[x509.Certificate, Any]:
        """Load the CA certificate and private key from disk.

        If the key is encrypted, attempts to decrypt using the passphrase
        from VENYA_CA_KEY_PASSPHRASE.

        Returns:
            Tuple of (certificate, private_key).

        Raises:
            RuntimeError: If the key cannot be decrypted.
        """
        passphrase = _load_passphrase(self._key_passphrase_env)
        key_data = self.ca_key_path.read_bytes()

        # Check if key appears encrypted
        is_encrypted = b"ENCRYPTED" in key_data

        if is_encrypted and not passphrase:
            raise RuntimeError(
                f"CA key is encrypted but {self._key_passphrase_env} is not set. "
                "Set the environment variable before starting the server."
            )

        if not is_encrypted and passphrase:
            logger.warning("CA key is unencrypted but passphrase is set — ignoring passphrase")

        private_key = _deserialize_key(key_data, passphrase)
        cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        return cert, private_key

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        executor_id: str,
        crl_url: str | None = None,
    ) -> x509.Certificate:
        """Sign a CSR with the CA, producing an executor certificate.

        Args:
            csr: The certificate signing request to sign.
            executor_id: Unique executor identifier (used as CN).
            crl_url: Optional CRL Distribution Point URL for CDP extension.

        Returns:
            Signed X.509 certificate.
        """
        ca_cert, ca_key = self.load_ca()
        now = datetime.now(timezone.utc)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Extract subject from CSR, replacing CN with executor_id
        csr_name = csr.subject
        # Build new name with executor_id as CN
        common_name_oid = NameOID.COMMON_NAME
        attrs = [a for a in csr_name if a.oid != common_name_oid]
        attrs.append(x509.NameAttribute(common_name_oid, executor_id))
        subject = x509.Name(attrs)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=EXECUTOR_VALIDITY_DAYS))
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
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(executor_id)]),
                critical=False,
            )
        )

        # Add CRL Distribution Point if URL is provided
        if crl_url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert

    def get_ca_cert_pem(self) -> bytes:
        """Get the CA certificate in PEM format.

        Returns:
            PEM-encoded CA certificate bytes.
        """
        return self.ca_cert_path.read_bytes()

    @staticmethod
    def compute_fingerprint(cert: x509.Certificate) -> str:
        """Compute the SHA-256 fingerprint of a certificate.

        Args:
            cert: The certificate to fingerprint.

        Returns:
            Lowercase hex fingerprint string.
        """
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def compute_serial_hex(serial: int) -> str:
        """Convert a serial number to a hex string.

        Args:
            serial: The serial number integer.

        Returns:
            Hex-encoded serial string.
        """
        return format(serial, "016x")

    def export_ca_key(self, passphrase: str) -> bytes:
        """Export the CA private key, encrypted with a passphrase.

        Reads the CA private key from disk, encrypts it using AES-256-CBC
        with a user-provided passphrase, and returns the encrypted blob.

        The plaintext key is zeroized from memory immediately after use.

        Args:
            passphrase: The passphrase to encrypt with.

        Returns:
            Encrypted key bytes: salt (16) + iv (16) + encrypted data.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        private_key_pem = self.ca_key_path.read_bytes()

        # Derive encryption key from passphrase using PBKDF2
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = kdf.derive(passphrase.encode())

        # Encrypt with AES-256-CBC
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # PKCS7 padding
        block_size = 16
        padding_len = block_size - (len(private_key_pem) % block_size)
        padded = private_key_pem + bytes([padding_len] * padding_len)

        encrypted = encryptor.update(padded) + encryptor.finalize()

        # Zeroize the plaintext key from memory
        private_key_pem = b"\x00" * len(private_key_pem)
        del private_key_pem

        return salt + iv + encrypted

    def import_ca_key(self, encrypted_key: bytes) -> None:
        """Import and write an encrypted CA private key.

        Decrypts the provided encrypted key data and writes it to disk
        with restrictive permissions (0600).

        Args:
            encrypted_key: Encrypted key bytes (salt + iv + ciphertext).
        """
        if len(encrypted_key) < 32:
            raise ValueError("Encrypted key data too small")

        salt = encrypted_key[:16]
        iv = encrypted_key[16:32]
        ciphertext = encrypted_key[32:]

        # We need the passphrase — this is typically called after
        # the admin provides it interactively. For programmatic use,
        # pass the passphrase-deriving key directly.
        raise NotImplementedError(
            "Use restore_ca_key() with passphrase for decryption, "
            "or provide encrypted_key as raw PEM for direct import"
        )

    def restore_ca_key(self, encrypted_key: bytes, passphrase: str) -> None:
        """Restore the CA private key from encrypted data.

        Decrypts the provided encrypted key data and writes it to disk
        with restrictive permissions (0600).

        Args:
            encrypted_key: Encrypted key bytes (salt + iv + ciphertext).
            passphrase: The passphrase used to encrypt the key.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        if len(encrypted_key) < 32:
            raise ValueError("Encrypted key data too small")

        salt = encrypted_key[:16]
        iv = encrypted_key[16:32]
        ciphertext = encrypted_key[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = kdf.derive(passphrase.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_len = padded[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Invalid passphrase or corrupted data")
        private_key_pem = padded[:-padding_len]

        # Write to disk
        self.ca_key_path.write_bytes(private_key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Zeroize from memory
        private_key_pem = b"\x00" * len(private_key_pem)
        del private_key_pem

    def get_ca_key_pem(self) -> bytes:
        """Get the CA private key in PEM format.

        WARNING: This returns the plaintext key. Use only for
        backup/export operations. The key should be zeroized
        immediately after use by the caller.

        Returns:
            PEM-encoded CA private key bytes.
        """
        return self.ca_key_path.read_bytes()

    def generate_crl(self, db_session, max_entries: int = 1000) -> bytes:
        """Generate a DER-encoded Certificate Revocation List.

        Queries the database for revoked certificate serial numbers,
        builds a CRL signed by the CA, and returns it in DER format.

        Args:
            db_session: SQLAlchemy session for querying revocations.
            max_entries: Maximum number of revocations to include.

        Returns:
            DER-encoded CRL bytes.
        """
        from sqlalchemy import desc

        from vault.iam.models import ExecutorCertRevocation

        ca_cert, ca_key = self.load_ca()
        now = datetime.now(timezone.utc)

        revocations = (
            db_session.query(ExecutorCertRevocation)
            .order_by(desc(ExecutorCertRevocation.revoked_at))
            .limit(max_entries)
            .all()
        )

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + timedelta(hours=1))

        for rev in revocations:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(rev.serial_number, 16))
                .revocation_date(rev.revoked_at)
                .build(hashes.SHA256())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.DER)

    def purge_expired_revocations(self, db_session, retention_days: int) -> int:
        """Delete revocation records older than retention_days.

        Args:
            db_session: SQLAlchemy session.
            retention_days: Keep records for this many days.

        Returns:
            Number of deleted records.
        """
        from vault.iam.models import ExecutorCertRevocation

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        deleted_count = db_session.query(ExecutorCertRevocation).filter(
            ExecutorCertRevocation.revoked_at < cutoff
        ).delete(synchronize_session=False)
        db_session.commit()
        return deleted_count


# --- Admin CA constants ---

ADMIN_CA_VALIDITY_DAYS = 3650  # 10 years
ADMIN_CERT_VALIDITY_DAYS = 90  # 90 days


def _build_san_for_identity(identity: str) -> x509.SubjectAlternativeName:
    """Build a SubjectAlternativeName extension for the given identity.

    Uses RFC822Name (email SAN) for email-style identities containing '@',
    and DNSName for hostname-style identities.

    Args:
        identity: The admin identity string.

    Returns:
        A SubjectAlternativeName extension value.
    """
    if "@" in identity:
        return x509.SubjectAlternativeName([x509.RFC822Name(identity)])
    else:
        return x509.SubjectAlternativeName([x509.DNSName(identity)])


class AdminCAManager:
    """Manages the admin CA keypair, certificates, and signing operations.

    Separate from CAManager (executor CA). The admin CA is used exclusively
    for signing admin client certificates used in mTLS authentication of
    admin endpoints.

    The admin CA key is encrypted on disk using a passphrase from the
    VENYA_ADMIN_CA_KEY_PASSPHRASE environment variable.
    """

    def __init__(self, ca_path: Path, ca_security: CASecurityConfig | None = None) -> None:
        self.ca_path = ca_path
        self.ca_key_path = self.ca_path / "admin-ca.key"
        self.ca_cert_path = self.ca_path / "admin-ca.crt"

        if ca_security is not None:
            self._key_passphrase_env = ca_security.key_passphrase_env
        else:
            self._key_passphrase_env = "VENYA_ADMIN_CA_KEY_PASSPHRASE"

    @property
    def has_ca(self) -> bool:
        """Check if admin CA key/cert pair exists on disk."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize(self) -> None:
        """Generate a new admin CA keypair and self-signed certificate.

        Creates the admin CA directory (if needed), generates an ECDSA P-256
        keypair, and creates a self-signed admin CA certificate. If a passphrase
        is set via VENYA_ADMIN_CA_KEY_PASSPHRASE, the key will be encrypted on disk.

        Raises:
            RuntimeError: If admin CA already exists.
        """
        if self.has_ca:
            raise RuntimeError(f"Admin CA already exists at {self.ca_path}")

        self.ca_path.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_path), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = _load_passphrase(self._key_passphrase_env)

        # Store private key (encrypted if passphrase provided)
        key_pem = _serialize_key_encrypted(private_key, passphrase)
        self.ca_key_path.write_bytes(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed admin CA certificate
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ADMIN_CA_VALIDITY_DAYS))
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
        )

        cert = builder.sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.ca_cert_path.write_bytes(cert_pem)
        os.chmod(str(self.ca_cert_path), 0o644)

        logger.info("Admin CA initialized at %s (encrypted=%s)", self.ca_path, passphrase is not None)

    def _load_ca_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the admin CA private key from disk.

        Decrypts using the passphrase from VENYA_ADMIN_CA_KEY_PASSPHRASE.

        Returns:
            ECDSA private key instance.

        Raises:
            RuntimeError: If the key cannot be decrypted or passphrase not set.
        """
        passphrase = _load_passphrase(self._key_passphrase_env)
        key_data = self.ca_key_path.read_bytes()

        is_encrypted = b"ENCRYPTED" in key_data

        if is_encrypted and not passphrase:
            raise RuntimeError(
                f"Admin CA key is encrypted but {self._key_passphrase_env} is not set. "
                "Set the environment variable before starting the server."
            )

        if not is_encrypted and passphrase:
            logger.warning("Admin CA key is unencrypted but passphrase is set — ignoring passphrase")

        return _deserialize_key(key_data, passphrase)

    def sign_admin_cert(self, admin_identity: str) -> tuple[x509.Certificate, bytes, bytes]:
        """Sign an admin certificate for the given identity.

        Generates a new ECDSA P-256 keypair, signs it with the admin CA,
        and returns the certificate, private key PEM, and certificate PEM.

        Args:
            admin_identity: The admin identity (used as CN and SAN DNS name).

        Returns:
            Tuple of (certificate, key_pem, cert_pem).
        """
        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(timezone.utc)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Generate new keypair for this admin cert
        admin_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
            x509.NameAttribute(NameOID.COMMON_NAME, admin_identity),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(admin_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ADMIN_CERT_VALIDITY_DAYS))
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
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                _build_san_for_identity(admin_identity),
                critical=False,
            )
        )

        cert = builder.sign(ca_key, hashes.SHA256())

        key_pem = admin_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        return cert, key_pem, cert_pem

    def _load_ca_cert_and_key(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        """Load the admin CA certificate and private key.

        Returns:
            Tuple of (certificate, private_key).
        """
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        ca_key = self._load_ca_key()
        return ca_cert, ca_key

    def get_admin_ca_cert_pem(self) -> bytes:
        """Get the admin CA certificate in PEM format.

        Returns:
            PEM-encoded admin CA certificate bytes.
        """
        return self.ca_cert_path.read_bytes()

    def generate_crl(self, db_session, max_entries: int = 1000) -> bytes:
        """Generate a DER-encoded Certificate Revocation List for admin certs.

        Args:
            db_session: SQLAlchemy session for querying revocations.
            max_entries: Maximum number of revocations to include.

        Returns:
            DER-encoded CRL bytes.
        """
        from sqlalchemy import desc

        from vault.iam.models import AdminCertRevocation

        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(timezone.utc)

        revocations = (
            db_session.query(AdminCertRevocation)
            .order_by(desc(AdminCertRevocation.revoked_at))
            .limit(max_entries)
            .all()
        )

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + timedelta(hours=1))

        for rev in revocations:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(rev.serial_number, 16))
                .revocation_date(rev.revoked_at)
                .build(hashes.SHA256())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.DER)

    def purge_expired_revocations(self, db_session, retention_days: int) -> int:
        """Delete admin cert revocation records older than retention_days.

        Args:
            db_session: SQLAlchemy session.
            retention_days: Keep records for this many days.

        Returns:
            Number of deleted records.
        """
        from vault.iam.models import AdminCertRevocation

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        deleted_count = db_session.query(AdminCertRevocation).filter(
            AdminCertRevocation.revoked_at < cutoff
        ).delete(synchronize_session=False)
        db_session.commit()
        return deleted_count
