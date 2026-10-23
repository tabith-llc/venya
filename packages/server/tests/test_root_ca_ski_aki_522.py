# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#522 root-ca-initialize-missing-ski-aki — key identifiers on the server-minted root.

``CAManager.initialize`` used to add only BasicConstraints + KeyUsage, while
``sign_csr`` leaves carry both key identifiers and the installer's root-CA
block (install-venya-core.sh) carries both too. A strict verifier rejects
chains rooted in the identifier-less server-minted root (openssl
-x509_strict: error 86 Missing Subject Key Identifier). The fix carries the
same SKI + self-AKI construction the #504 admin-plane fix and the installer
block use.

AC1: initialize-minted root carries SKI (digest of its own public key) and a
     self-AKI referencing it.                    RED at HEAD.
AC2: leaves signed by the re-minted root carry an AKI whose digest matches
     the root's SKI — the same pairing the admin-plane fix asserts.
AC3: paired negative — the incumbent-CA path is untouched: when ca.key and
     ca.crt already exist the CA is reused byte-for-byte (CAExistsError from
     initialize, the callers' ``has_ca`` guard skips the mint).
AC4: extension order and criticality follow the house idiom (installer root
     block / #504): BC(critical), KU(critical), SKI, self-AKI.
AC5: strict verification of a served leaf through the new root passes.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from server.ca import CAExistsError, CAManager

_PASSPHRASE = b"test_passphrase_522"


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    """Deterministic encrypted keys for these cells regardless of ambient env.

    Used to DELETE these vars so the cells minted plaintext keys; #537 made the
    write path refuse that, so the fixture now sets a test passphrase instead.
    The cells are about certificate extensions — the key envelope is incidental.
    """
    monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", _PASSPHRASE.decode())


@pytest.fixture
def root(tmp_path: Path) -> CAManager:
    manager = CAManager(str(tmp_path / "ca"))
    manager.initialize()
    return manager


def _ski(cert: x509.Certificate) -> bytes:
    return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest


def _aki_keyid(cert: x509.Certificate):
    return cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier


def _load_root_cert(manager: CAManager) -> x509.Certificate:
    return x509.load_pem_x509_certificate(manager.ca_cert_path.read_bytes())


def _make_csr(executor_id: str) -> tuple[x509.CertificateSigningRequest, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, executor_id)]))
        .sign(key, hashes.SHA256())
    )
    return csr, key


class TestRootCaSkiAki522:
    def test_ac1_minted_root_carries_ski_and_self_aki(self, root):
        """AC1 (RED at HEAD): SKI is the digest of the root's own public key
        and the AKI references that same SKI (self-signed root form)."""
        root_cert = _load_root_cert(root)
        key = serialization.load_pem_private_key(root.ca_key_path.read_bytes(), password=_PASSPHRASE)
        expected = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        assert _ski(root_cert) == expected.digest, "minted root missing SKI or wrong digest"
        assert _aki_keyid(root_cert) == expected.digest, "minted root missing self-AKI"

    def test_ac2_leaf_aki_pairs_with_new_root_ski(self, root):
        """AC2: sign_csr's from_issuer_public_key digest equals the root's own
        SKI — the chain identifiers pair, so a future refactor cannot
        silently break them. Also compares the identifier construction against
        sign_csr's own shape (same digests, root now carries both)."""
        csr, exec_key = _make_csr("exec-1")
        leaf = root.sign_csr(csr, "exec-1")
        root_cert = _load_root_cert(root)
        # The leaf's own SKI matches its key (sign_csr behaviour unchanged)...
        assert _ski(leaf) == x509.SubjectKeyIdentifier.from_public_key(exec_key.public_key()).digest
        # ...and the leaf's AKI now lands on a root that actually carries the
        # matching SKI (pre-fix: the AKI pointed at an identifier the root did
        # not publish).
        assert _aki_keyid(leaf) == _ski(root_cert)
        ca_public = serialization.load_pem_private_key(root.ca_key_path.read_bytes(), password=_PASSPHRASE).public_key()
        assert _aki_keyid(leaf) == x509.SubjectKeyIdentifier.from_public_key(ca_public).digest

    def test_ac3_incumbent_ca_reused_byte_for_byte(self, tmp_path, monkeypatch):
        """AC3 paired negative: an existing deployment's root is NOT rewritten
        by this change. With ca.key + ca.crt on disk, initialize raises
        CAExistsError and both files keep their exact bytes (the callers in
        app.py / routes/init.py guard on has_ca and skip the mint entirely)."""
        # The incumbent key is plaintext (it predates #537), so this cell runs
        # with the passphrase env UNSET — the combination the autouse fixture
        # would otherwise create (plaintext key at rest + passphrase set) is
        # #541: load_ca() now REFUSES with the approved #537 wording instead of
        # logging "ignoring passphrase" and passing it to the loader, which
        # raised TypeError. The incumbent half of this cell stays the
        # deployment-continuity case the ticket keeps working.
        monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        # Incumbent pre-#522 root: minted without the identifiers.
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA")])
        now = datetime.now(UTC)
        incumbent = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        key_bytes = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        cert_bytes = incumbent.public_bytes(serialization.Encoding.PEM)
        (ca_dir / "ca.key").write_bytes(key_bytes)
        (ca_dir / "ca.crt").write_bytes(cert_bytes)

        manager = CAManager(str(ca_dir))
        assert manager.has_ca
        with pytest.raises(CAExistsError):
            manager.initialize()
        assert (ca_dir / "ca.key").read_bytes() == key_bytes, "incumbent CA key rewritten"
        assert (ca_dir / "ca.crt").read_bytes() == cert_bytes, "incumbent CA cert rewritten — fingerprint drift"
        # The incumbent keeps signing valid leaves: sign_csr's AKI uses
        # from_issuer_public_key, which does not require the root to carry an
        # SKI. Deployment continuity without a re-mint (operator action per
        # AC5 of the ticket).
        csr, _exec_key = _make_csr("exec-9")
        leaf = manager.sign_csr(csr, "exec-9")
        assert _aki_keyid(leaf) == x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest

    def test_ac4_extension_order_and_criticality_follow_house_idiom(self, root):
        """AC4: BC(critical) -> KU(critical) -> SKI(non-critical) -> self-AKI
        (non-critical) — the exact order/criticality of the installer
        root-CA block and the #504 admin CA. Nothing else changed: serial,
        validity window, and key-usage bits keep their pre-fix shape."""
        root_cert = _load_root_cert(root)
        oids = [e.oid for e in root_cert.extensions]
        assert oids == [
            ExtensionOID.BASIC_CONSTRAINTS,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ]
        by_oid = {e.oid: e for e in root_cert.extensions}
        assert by_oid[ExtensionOID.BASIC_CONSTRAINTS].critical is True
        assert by_oid[ExtensionOID.KEY_USAGE].critical is True
        assert by_oid[ExtensionOID.SUBJECT_KEY_IDENTIFIER].critical is False
        assert by_oid[ExtensionOID.AUTHORITY_KEY_IDENTIFIER].critical is False
        ku = by_oid[ExtensionOID.KEY_USAGE].value
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True
        assert ku.digital_signature is False
        bc = by_oid[ExtensionOID.BASIC_CONSTRAINTS].value
        assert bc.ca is True
        assert bc.path_length is None
        assert root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Venya Root CA"

    def test_ac5_strict_openssl_verify_passes_through_new_root(self, root, tmp_path):
        """AC5 mechanism proof: a served executor leaf chaining to the new
        root passes ``openssl verify -x509_strict`` (the mode that errored 86
        against the identifier-less root). Default mode must pass as before."""
        import subprocess

        csr, _key = _make_csr("exec-strict")
        leaf = root.sign_csr(csr, "exec-strict")
        leaf_path = tmp_path / "leaf.crt"
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        for extra in ([], ["-x509_strict"]):
            proc = subprocess.run(
                ["openssl", "verify", *extra, "-CAfile", str(root.ca_cert_path), str(leaf_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, f"openssl verify {extra} failed: {proc.stdout}{proc.stderr}"
