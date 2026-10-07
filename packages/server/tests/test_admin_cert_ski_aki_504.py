# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#504 admin-cert-missing-ski-aki — key-identifier cells for the admin plane.

The admin CA and its leaves used to omit SubjectKeyIdentifier and
AuthorityKeyIdentifier while every other certificate in the product sets
them (installer root-CA block, CAManager.sign_csr leaves). OpenSSL with
X509_V_FLAG_X509_STRICT (CLI: -x509_strict) rejects the old chain outright
— errors 85/86, see the leg report's research cell.

AC1: admin CA carries SKI + self-AKI.          RED at HEAD.
AC2: admin leaf carries SKI + AKI -> CA's SKI. RED at HEAD.
AC3: paired negative — the root/executor plane is unchanged.
"""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from server.ca import AdminCAManager, CAManager

_ADMIN_IDENTITY = "admin@venya-test-workstation"


@pytest.fixture(autouse=True)
def _clean_passphrase_envs(monkeypatch):
    """Deterministic plaintext keys for these cells regardless of ambient env."""
    monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)


@pytest.fixture
def admin_manager(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _ski(cert: x509.Certificate) -> bytes:
    return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest


def _aki_keyid(cert: x509.Certificate):
    return cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier


def _has(cert: x509.Certificate, oid) -> bool:
    try:
        cert.extensions.get_extension_for_oid(oid)
        return True
    except x509.ExtensionNotFound:
        return False


class TestAdminCertSkiAki504:
    def test_ac1_admin_ca_carries_ski_and_self_aki(self, admin_manager):
        """AC1 (RED at HEAD): the admin CA's SKI is the digest of its own public
        key and its AKI references that same SKI (self-signed)."""
        ca_cert = x509.load_pem_x509_certificate(admin_manager.ca_cert_path.read_bytes())
        expected = x509.SubjectKeyIdentifier.from_public_key(
            serialization.load_pem_private_key(admin_manager.ca_key_path.read_bytes(), password=None).public_key()
        )
        assert _ski(ca_cert) == expected.digest, "admin CA missing SKI or wrong digest"
        assert _aki_keyid(ca_cert) == expected.digest, "admin CA missing self-AKI"

    def test_ac2_admin_leaf_carries_ski_and_aki_referencing_ca(self, admin_manager):
        """AC2 (RED at HEAD): the leaf's SKI matches its own key and its AKI
        points at the admin CA's SKI — the same construction as sign_csr leaves."""
        cert, key_pem, _cert_pem = admin_manager.sign_admin_cert(_ADMIN_IDENTITY)
        leaf_key = serialization.load_pem_private_key(key_pem, password=None)
        assert _ski(cert) == x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()).digest
        ca_cert = x509.load_pem_x509_certificate(admin_manager.ca_cert_path.read_bytes())
        assert _aki_keyid(cert) == _ski(ca_cert)
        # The pre-existing extensions must survive the addition untouched.
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is False
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        from cryptography.x509.oid import ExtendedKeyUsageOID

        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert _has(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def test_ac2_leaf_still_verifies_after_identifier_addition(self, admin_manager, tmp_path):
        """Adding the identifiers must not break chain verification — the CA
        signs the leaf and OpenSSL (default and -x509_strict) accepts it."""
        import subprocess

        _cert, key_pem, cert_pem = admin_manager.sign_admin_cert(_ADMIN_IDENTITY)
        leaf = tmp_path / "leaf.crt"
        leaf.write_bytes(cert_pem)
        ca = admin_manager.ca_cert_path
        for extra in ([], ["-x509_strict"]):
            proc = subprocess.run(
                ["openssl", "verify", *extra, "-CAfile", str(ca), str(leaf)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, f"openssl verify {extra} failed: {proc.stdout}{proc.stderr}"
        assert key_pem  # returned keypair still present

    def test_ac3_root_executor_plane_unchanged(self, tmp_path):
        """AC3 paired negative: nothing about CAManager.sign_csr (executor
        leaves) changed. The root CA now also carries SKI + self-AKI — the
        gap this test originally pinned as a separate finding landed as its
        own fix (#522, bug/root-ca-initialize-missing-ski-aki), so the pin
        was updated to the post-#522 set in the same changeset that fixed
        it (leaf identifiers and construction remain the point of this
        cell)."""
        root = CAManager(str(tmp_path / "ca"))
        root.initialize()
        root_cert = x509.load_pem_x509_certificate(root.ca_cert_path.read_bytes())
        root_oids = {e.oid for e in root_cert.extensions}
        assert root_oids == {
            ExtensionOID.BASIC_CONSTRAINTS,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        }

        exec_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exec-1")]))
            .sign(exec_key, hashes.SHA256())
        )
        leaf = root.sign_csr(csr, "exec-1")
        assert _ski(leaf) == x509.SubjectKeyIdentifier.from_public_key(exec_key.public_key()).digest
        ca_public = serialization.load_pem_private_key(root.ca_key_path.read_bytes(), password=None).public_key()
        assert _aki_keyid(leaf) == x509.SubjectKeyIdentifier.from_public_key(ca_public).digest

    def test_incumbent_admin_ca_without_ski_still_signs_valid_leaves(self, tmp_path):
        """Deployment-continuity cell: sign_admin_cert uses
        from_issuer_public_key, which does NOT require the incumbent CA to
        carry an SKI. An admin CA minted BEFORE this change can still sign
        leaves that now carry SKI + a correct AKI digest."""
        # Pre-#504 incumbent: mint a CA pair without the identifiers.
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
            ]
        )
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        incumbent_ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        ca_dir = tmp_path / "admin-ca"
        ca_dir.mkdir()
        (ca_dir / "admin-ca.crt").write_bytes(incumbent_ca.public_bytes(serialization.Encoding.PEM))
        (ca_dir / "admin-ca.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        manager = AdminCAManager(ca_dir)
        cert, _key_pem, _cert_pem = manager.sign_admin_cert(_ADMIN_IDENTITY)
        # AKI is the SHA1 digest of the issuer public key — present, and equal
        # to what the CA's SKI will be once the CA itself is re-issued.
        expected_aki = x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest
        assert _aki_keyid(cert) == expected_aki
        assert _ski(cert) == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
