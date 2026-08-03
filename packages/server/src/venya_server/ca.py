"""CA (Certificate Authority) management for executor mTLS.

Generates CA key/cert during initialization and signs executor CSRs.
Uses ECDSA P-256 for all certificates.
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
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("venya.ca")

# Certificate validity periods
CA_VALIDITY_DAYS = 3650  # 10 years
EXECUTOR_VALIDITY_DAYS = 30  # 30 days


class CAManager:
    """Manages the CA keypair, certificates, and signing operations.

    The CA is generated once during initialization and stored on disk.
    All executor certificates are signed by this CA.
    """

    def __init__(self, ca_dir: str) -> None:
        self.ca_dir = Path(ca_dir)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.crt"

    @property
    def has_ca(self) -> bool:
        """Check if CA key/cert pair exists on disk."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize(self) -> None:
        """Generate a new CA keypair and self-signed certificate.

        Creates the CA directory (if needed), generates an ECDSA P-256
        keypair, and creates a self-signed CA certificate.

        Raises:
            RuntimeError: If CA already exists.
        """
        if self.has_ca:
            raise RuntimeError(f"CA already exists at {self.ca_dir}")

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_dir), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Store private key
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
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

        logger.info("CA initialized at %s", self.ca_dir)

    def load_ca(self) -> tuple[x509.Certificate, Any]:
        """Load the CA certificate and private key from disk.

        Returns:
            Tuple of (certificate, private_key).
        """
        cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        private_key = serialization.load_pem_private_key(
            self.ca_key_path.read_bytes(),
            password=None,
        )
        return cert, private_key

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        executor_id: str,
    ) -> x509.Certificate:
        """Sign a CSR with the CA, producing an executor certificate.

        Args:
            csr: The certificate signing request to sign.
            executor_id: Unique executor identifier (used as CN).

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
