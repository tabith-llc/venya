# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Test certificate factory for generating certs with specific properties.

Used by validation tests to construct exactly the malformed cert needed
for each test case without managing CA infrastructure manually.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def make_ca_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a CA keypair."""
    return ec.generate_private_key(ec.SECP256R1())


def make_ca_cert(ca_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Generate a self-signed CA certificate."""
    now = datetime.now(UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA"),
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
    return cert


def make_test_cert(
    executor_id: str = "test-executor",
    ca: bool = False,
    digital_signature: bool = True,
    client_auth: bool = True,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    ca_cert: x509.Certificate | None = None,
    ca_key: ec.EllipticCurvePrivateKey | None = None,
    add_san: bool = True,
) -> x509.Certificate:
    """Generate a test certificate with specific properties.

    Args:
        executor_id: CN for the certificate.
        ca: Whether BasicConstraints CA is True.
        digital_signature: Whether KeyUsage includes digitalSignature.
        client_auth: Whether ExtendedKeyUsage includes clientAuth.
        not_before: Custom notBefore. Defaults to now.
        not_after: Custom notAfter. Defaults to now + 30 days.
        ca_cert: CA certificate to sign with. If None, self-signed.
        ca_key: CA private key to sign with. Required if ca_cert provided.
        add_san: Whether to add SubjectAlternativeName extension.

    Returns:
        Signed X.509 certificate.
    """
    now = not_before or datetime.now(UTC)
    expiry = not_after or now + timedelta(days=30)

    key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH] if client_auth else []),
            critical=False,
        )
    )

    if add_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(executor_id)]),
            critical=False,
        )

    if ca_cert is not None and ca_key is not None:
        builder = builder.issuer_name(ca_cert.subject)
        cert = builder.sign(ca_key, hashes.SHA256())
    else:
        cert = builder.sign(key, hashes.SHA256())

    return cert


def save_cert_pem(cert: x509.Certificate) -> bytes:
    """Save a certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def save_key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Save a private key to PEM bytes."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_to_temp_dir(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey, tmp_path: Path) -> dict[str, str]:
    """Save cert and key to a temp directory.

    Args:
        cert: The certificate.
        key: The private key.
        tmp_path: pytest tmp_path fixture.

    Returns:
        Dict with 'cert' and 'key' paths.
    """
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(save_cert_pem(cert))
    key_path.write_bytes(save_key_pem(key))
    return {"cert": str(cert_path), "key": str(key_path)}
