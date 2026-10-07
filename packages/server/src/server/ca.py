# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CA (Certificate Authority) management for executor mTLS.

Generates CA key/cert during initialization and signs executor CSRs.
The CA keypair itself is ECDSA P-256; a submitted CSR may carry any public key
on the accepted-curve list (``accepted_csr_curve_names()`` — P-256/P-384/P-521,
refs #503 option A). Supports passphrase-based encryption for CA private key
storage.
"""

import hashlib
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import CASecurityConfig

logger = logging.getLogger("venya.ca")


class CAExistsError(RuntimeError):
    """CA keypair already exists on disk."""


# Certificate validity periods
CA_VALIDITY_DAYS = 3650  # 10 years
EXECUTOR_VALIDITY_DAYS = 30  # 30 days

# EKU for executor leaf certs. Dual-purpose: the leaf serves as a TLS client
# (registration/heartbeat toward core) AND a TLS server (relay listener :8443).
# This is the single source of truth — do not inline the OIDs elsewhere.
EXECUTOR_LEAF_EKU = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]

# Accepted CSR public-key curves. SINGLE SOURCE OF TRUTH (refs #503 option A):
# both CAManager.sign_csr (the vault) and
# routes/executors.validate_csr_key_strength (the promise the registration
# endpoint makes in its 400 text) read accepted_csr_curve_names(), so the two
# cannot drift apart. The mapping carries the human label used in the hint text.
# Read at CALL time (not snapshot into a tuple at import) so the dict below is
# the only place the list exists.
ACCEPTED_CSR_CURVE_LABELS: dict[str, str] = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}


def accepted_csr_curve_names() -> tuple[str, ...]:
    """Return the curve names a CSR public key may use."""
    return tuple(ACCEPTED_CSR_CURVE_LABELS)


def csr_curve_hint() -> str:
    """Return the actionable text naming every curve the CA accepts.

    Built from the same dict the signer checks, so the wording can never
    advertise a list that differs from the one the vault enforces.
    """
    labels = [f"{ACCEPTED_CSR_CURVE_LABELS[name]} ({name})" for name in accepted_csr_curve_names()]
    if len(labels) == 1:
        joined = labels[0]
    else:
        joined = ", ".join(labels[:-1]) + ", or " + labels[-1]
    return f"Use ECDSA {joined}."


def _load_passphrase(env_var: str) -> bytes | None:
    """Load passphrase from environment variable.

    Returns:
        Passphrase as bytes, or None if not set.
    """
    passphrase = os.environ.get(env_var)
    if passphrase:
        return passphrase.encode("utf-8")
    return None


def _serialize_key_encrypted(
    key: ec.EllipticCurvePrivateKey,
    passphrase: bytes | None,
    passphrase_env: str,
) -> bytes:
    """Serialize a private key, optionally encrypting with a passphrase.

    Args:
        key: The private key to serialize.
        passphrase: Optional passphrase for encryption.
        passphrase_env: Name of the env var that should carry the passphrase.
            Used only to make the "unencrypted" warning actionable — it names
            the var the caller actually reads (admin vs executor CA differ).

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
            passphrase_env,
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
            self._key_passphrase_env = "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

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
            raise CAExistsError(f"CA already exists at {self.ca_dir}")

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_dir), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = _load_passphrase(self._key_passphrase_env)

        # Store private key (encrypted if passphrase provided)
        key_pem = _serialize_key_encrypted(private_key, passphrase, self._key_passphrase_env)
        # #499: create-time mode via os.open(..., 0o600) — the house idiom of
        # sbx_strategy.py's env-file write. write_bytes() creates the inode at
        # 0666 & ~umask and the chmod below lands only after the full key body
        # is on disk; under a permissive umask the bytes are observable at a
        # wider mode in that window. The chmod stays as the exact final-state
        # pin (unchanged outcome: 0600).
        key_fd = os.open(str(self.ca_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Venya Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA"),
            ]
        )

        # #522: SKI + self-AKI, matching the installer's root-CA block
        # (install-venya-core.sh) and the admin CA fix (#504) — every CA in
        # this product carries them, so a root minted by the server stays
        # acceptable to strict verifiers (openssl -x509_strict, error 86).
        root_ca_ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
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
            .add_extension(root_ca_ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ca_ski),
                critical=False,
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
        try:
            key_data = self.ca_key_path.read_bytes()
        except FileNotFoundError:
            raise RuntimeError(f"CA key file not found at {self.ca_key_path}")

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
        try:
            cert_pem = self.ca_cert_path.read_bytes()
        except FileNotFoundError:
            raise RuntimeError(f"CA cert file not found at {self.ca_cert_path}")
        cert = x509.load_pem_x509_certificate(cert_pem)
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

        Raises:
            ValueError: If the CSR self-signature does not verify, or its public
                key is not an accepted ECDSA curve. Callers map ValueError to a
                client error (400) — it is bad input, not a CA fault. A
                RuntimeError from load_ca() means the CA material itself is
                unusable and stays a service fault (503).
        """
        ca_cert, ca_key = self.load_ca()
        now = datetime.now(UTC)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Validate CSR
        if not csr.is_signature_valid:
            raise ValueError("CSR signature verification failed")

        pub_key = csr.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            # ValueError, not TypeError (#503): this is caller-supplied CSR material, and
            # the registration route maps ValueError to a clean 400. A TypeError here was
            # the defect — it escaped the route's `except RuntimeError` block as a 500.
            raise ValueError(  # noqa: TRY004 — CA input validation; ValueError → 400 at caller
                f"Unsupported CSR key type: {type(pub_key).__name__}. {csr_curve_hint()}"
            )
        if pub_key.curve.name not in accepted_csr_curve_names():
            raise ValueError(f"Unsupported curve: {pub_key.curve.name}. {csr_curve_hint()}")

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
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
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
                x509.ExtendedKeyUsage(EXECUTOR_LEAF_EKU),
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
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(crl_url)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
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

        The ONE serial representation is `core.utils.cert_serial.canonical_serial`
        (ticket cert-serial-canonicalization-mismatch #481); this is the padded
        precedent that shape was named after, kept as the server-side writer so
        call sites and this method's mocks keep working unchanged.

        Args:
            serial: The serial number integer.

        Returns:
            Lowercase hex, zero-padded to a minimum of 16 digits.
        """
        return canonical_serial(serial)

    def get_ca_key_pem(self) -> bytes:
        """Get the CA private key in PEM format.

        WARNING: This returns the plaintext key. Use only for
        backup/export operations. The key should be zeroized
        immediately after use by the caller.

        Returns:
            PEM-encoded CA private key bytes.
        """
        return self.ca_key_path.read_bytes()

    def generate_crl(self, db_session, max_entries: int = 1000, revocations=None) -> bytes:
        """Generate a DER-encoded Certificate Revocation List.

        Queries the database for revoked certificate serial numbers,
        builds a CRL signed by the CA, and returns it in DER format.

        Args:
            db_session: SQLAlchemy session for querying revocations.
            max_entries: Maximum number of revocations to include.
            revocations: Pre-fetched revocation rows to embed (ticket
                crl-cap-etag-divergence #337, ruled A). The CRL endpoint fetches
                the capped rows ONCE and passes them here so the served body and
                the conditional-GET ETag describe the SAME population — a second
                internal query would re-open the snapshot gap the cap fix closes.
                None keeps the historical self-queried behavior.

        Returns:
            DER-encoded CRL bytes.
        """
        from core.iam.models import ExecutorCertRevocation
        from sqlalchemy import desc

        ca_cert, ca_key = self.load_ca()
        now = datetime.now(UTC)

        if revocations is None:
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
        from core.iam.models import ExecutorCertRevocation

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted_count = (
            db_session.query(ExecutorCertRevocation)
            .filter(ExecutorCertRevocation.revoked_at < cutoff)
            .delete(synchronize_session=False)
        )
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
            self._key_passphrase_env = "VENYA_ADMIN_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

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
        key_pem = _serialize_key_encrypted(private_key, passphrase, self._key_passphrase_env)
        # #499: create-time mode via os.open(..., 0o600) — see CAManager.initialize;
        # write_bytes() + chmod leaves the key body at 0666 & ~umask until the
        # chmod lands. The chmod stays as the exact final-state pin.
        key_fd = os.open(str(self.ca_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed admin CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
            ]
        )

        # #504: SKI + self-AKI, matching the installer's root-CA block
        # (install-venya-core.sh) — every CA in this product carries them.
        admin_ca_ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
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
            .add_extension(admin_ca_ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(admin_ca_ski),
                critical=False,
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
        now = datetime.now(UTC)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Generate new keypair for this admin cert
        admin_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, admin_identity),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(admin_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ADMIN_CERT_VALIDITY_DAYS))
            # #504: SKI + AKI referencing the admin CA — same placement and
            # from_issuer_public_key idiom as CAManager.sign_csr (executor
            # leaves), so admin leaves match the rest of the product's PKI.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(admin_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
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
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
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
        from core.iam.models import AdminCertRevocation
        from sqlalchemy import desc

        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(UTC)

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
        from core.iam.models import AdminCertRevocation

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted_count = (
            db_session.query(AdminCertRevocation)
            .filter(AdminCertRevocation.revoked_at < cutoff)
            .delete(synchronize_session=False)
        )
        db_session.commit()
        return deleted_count
