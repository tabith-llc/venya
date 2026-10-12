# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 1 — the admin CSR signer (RF-6 §2.5b, §2.6, §3.2).

``AdminCAManager.sign_admin_csr(csr, identity, lifetime_seconds, crl_url=None)``
reuses the ``sign_csr`` behavior table with the two deltas the dossier names:
EKU is CLIENT_AUTH only, and the SAN comes from ``_build_san_for_identity``
(RFC822 for ``@``-bearing identities, DNS otherwise). Lifetime is the
caller's minutes-scale value. The signer returns a certificate and NO private
key — that is the whole content of ruling 3.

Every positive below carries its negative half (truth-table law): the mint is
server-described (§2.6 — the CSR subject carries no authority), the marker is
signer-written (a CSR-claimed marker is discarded), and a CA that cannot load
is never a ValueError (client input) — it stays a service fault.
"""

from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from server.ca import (
    ADMIN_SHORT_CERT_LIFETIME_SECONDS,
    PLANE_HUMAN,
    VENYA_PLANE_MARKER_OID,
    AdminCAManager,
    csr_curve_hint,
    parse_plane_marker,
)

_EMAIL_IDENTITY = "alice@example.com"
_HOST_IDENTITY = "core-1.internal"

_SHORT_LIFETIME = ADMIN_SHORT_CERT_LIFETIME_SECONDS  # 60 minutes, ruling 4a


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_admin_passphrase_rf7c1")


@pytest.fixture
def admin_manager(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _key(curve=ec.SECP256R1):
    """Generate a private key from a curve CLASS (default ec.SECP256R1) or INSTANCE."""
    instance = curve() if isinstance(curve, type) else curve
    return ec.generate_private_key(instance)


def _csr(
    private_key,
    common_name: str = "attacker-chosen-cn",
    organization: str = "EvilCorp",
    extensions=(),
) -> x509.CertificateSigningRequest:
    """A self-signed CSR with an ADVERSARIAL subject — every attribute below
    must be discarded by the mint (§2.6.1)."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(private_key, hashes.SHA256())


def _leaf_extensions(cert: x509.Certificate):
    return [(e.oid, e.critical) for e in cert.extensions]


class TestAdminCsrSignerPositive:
    def test_signed_cert_verifies_against_admin_ca(self, admin_manager):
        """Positive half: the leaf signature verifies under the admin CA key."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        ca_cert = x509.load_pem_x509_certificate(admin_manager.get_admin_ca_cert_pem())
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )

    def test_cn_is_server_supplied_identity_not_the_csr(self, admin_manager):
        """§2.6: the mint must not be self-described. The CSR claims CN + O + OU;
        all three are replaced from the server-derived identity."""
        cert = admin_manager.sign_admin_csr(
            _csr(_key(), common_name="attacker-chosen-cn", organization="EvilCorp"),
            _EMAIL_IDENTITY,
            _SHORT_LIFETIME,
        )
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert [a.value for a in cn] == [_EMAIL_IDENTITY]
        o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        assert [a.value for a in o] == ["Venya"]
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        assert [a.value for a in ou] == ["Admin"]
        # Paired negative: the CSR's own strings appear nowhere in the subject.
        subject_values = {a.value for a in cert.subject}
        assert "attacker-chosen-cn" not in subject_values
        assert "EvilCorp" not in subject_values
        assert "Root" not in subject_values

    def test_eku_is_client_auth_only(self, admin_manager):
        """§2.5 delta 1: SERVER_AUTH would let an admin leaf impersonate a
        core endpoint — it must be absent."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        # Paired negative: SERVER_AUTH is not in the set.
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku

    def test_san_is_rfc822_for_email_identity(self, admin_manager):
        """§2.5 delta 2: _build_san_for_identity routes @-bearing identities
        to RFC822Name."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        assert san.get_values_for_type(x509.RFC822Name) == [_EMAIL_IDENTITY]
        # Paired negative: no DNS leg for an email identity.
        assert san.get_values_for_type(x509.DNSName) == []

    def test_san_is_dns_for_hostname_identity(self, admin_manager):
        cert = admin_manager.sign_admin_csr(_csr(_key()), _HOST_IDENTITY, _SHORT_LIFETIME)
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        assert san.get_values_for_type(x509.DNSName) == [_HOST_IDENTITY]
        # Paired negative: no RFC822 leg for a hostname identity.
        assert san.get_values_for_type(x509.RFC822Name) == []

    def test_validity_window_equals_the_passed_lifetime(self, admin_manager):
        """Ruling 4a minutes-scale, never EXECUTOR_VALIDITY_DAYS or the 90-day
        bootstrap constant."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        window = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert window == timedelta(seconds=_SHORT_LIFETIME)
        # Paired negatives: the days-scale constants are not the window.
        assert window != timedelta(days=30)
        assert window != timedelta(days=90)

    def test_marker_extension_present_human_noncritical(self, admin_manager):
        """§3.2: CA-written plane marker, value human on this signer; the bit
        is NON-critical since s98 (#588 option A — enforcement app-side)."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is False
        assert parse_plane_marker(cert) == PLANE_HUMAN

    def test_basic_constraints_and_key_usage(self, admin_manager):
        """Carried unchanged from sign_csr: ca=False and digital_signature-only,
        both critical."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False
        assert bc.critical is True
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku = ku_ext.value
        assert ku.digital_signature is True
        assert not (
            ku.key_encipherment or ku.content_commitment or ku.data_encipherment or ku.key_cert_sign or ku.crl_sign
        )
        assert ku_ext.critical is True

    def test_ski_and_aki_per_504_placement(self, admin_manager):
        """#504 placement rule carried: SKI from the leaf public key, AKI
        from_issuer_public_key referencing the admin CA."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        ca_cert = x509.load_pem_x509_certificate(admin_manager.get_admin_ca_cert_pem())
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        assert ski.digest == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        ca_ski = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        assert aki.key_identifier == ca_ski.digest

    def test_serial_is_eight_bytes(self, admin_manager):
        """secrets.token_bytes(8) — the canonical-form revocation lookup shape
        (§2.9)."""
        cert = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        # The 8-byte ceiling is the contract; serial_number==0 is a 2**-64
        # draw (sign_csr shares the property) and not asserted away.
        assert cert.serial_number.bit_length() <= 64

    def test_cdp_optional_wiring(self, admin_manager):
        """Positive: crl_url yields a CDP with that URI. Negative (same cell,
        no url): no CDP extension at all."""
        with_cdp = admin_manager.sign_admin_csr(
            _csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME, crl_url="https://core/crl.pem"
        )
        cdp = with_cdp.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        uri = cdp[0].full_name[0].value
        assert uri == "https://core/crl.pem"

        without = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        with pytest.raises(x509.ExtensionNotFound):
            without.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)

    def test_accepted_curves_all_sign(self, admin_manager):
        """The shared accepted-curve list, not an admin-specific fork (§2.5)."""
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
            cert = admin_manager.sign_admin_csr(_csr(_key(curve)), _EMAIL_IDENTITY, _SHORT_LIFETIME)
            assert isinstance(cert, x509.Certificate)


class TestAdminCsrSignerNegative:
    def test_return_is_a_certificate_and_no_key_anywhere(self, admin_manager):
        """Ruling 3: a signing function that returns a private key must not
        survive. The result is ONE certificate object; the serialized leaf
        contains no private-key material."""
        result = admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        assert isinstance(result, x509.Certificate)
        assert not isinstance(result, tuple)
        pem = result.public_bytes(serialization.Encoding.PEM)
        # Paired negative: neither plaintext nor encrypted key blocks appear.
        assert b"PRIVATE KEY" not in pem

    def test_broken_self_signature_raises_valueerror(self, admin_manager):
        """Same error-class contract as sign_csr: bad CSR is client input."""
        der = bytearray(_csr(_key()).public_bytes(serialization.Encoding.DER))
        der[-1] ^= 0x01
        broken = x509.load_der_x509_csr(bytes(der))
        assert broken.is_signature_valid is False, "fixture must produce an unverifiable CSR"
        with pytest.raises(ValueError, match="CSR signature verification failed"):
            admin_manager.sign_admin_csr(broken, _EMAIL_IDENTITY, _SHORT_LIFETIME)

    def test_off_list_curve_refused_with_shared_hint(self, admin_manager):
        csr192 = _csr(_key(ec.SECP192R1()))
        assert csr192.is_signature_valid
        with pytest.raises(ValueError, match="Unsupported curve") as excinfo:
            admin_manager.sign_admin_csr(csr192, _EMAIL_IDENTITY, _SHORT_LIFETIME)
        # The hint text comes from the SAME dict the executor signer uses.
        assert csr_curve_hint() in str(excinfo.value)

    def test_rsa_key_refused_with_shared_hint(self, admin_manager):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa-attacker")]))
            .sign(rsa_key, hashes.SHA256())
        )
        with pytest.raises(ValueError, match="Unsupported CSR key type") as excinfo:
            admin_manager.sign_admin_csr(csr, _EMAIL_IDENTITY, _SHORT_LIFETIME)
        assert csr_curve_hint() in str(excinfo.value)

    def test_csr_claimed_marker_is_discarded(self, admin_manager):
        """§3.8 truth-table row: a marker self-signed into the CSR must never
        survive — the signer writes its own, and there is exactly one."""
        claimed = x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID, b"\x0c\x07machine")
        cert = admin_manager.sign_admin_csr(
            _csr(_key(), extensions=[(claimed, False)]), _EMAIL_IDENTITY, _SHORT_LIFETIME
        )
        oids = [oid for oid, _ in _leaf_extensions(cert)]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1, "exactly one marker — no CSR copy"
        # And the single marker says human (the signer's own value), not the
        # machine value the CSR claimed.
        assert parse_plane_marker(cert) == PLANE_HUMAN

    def test_nonpositive_lifetime_refused(self, admin_manager):
        for bad in (0, -1):
            with pytest.raises(ValueError, match="lifetime_seconds"):
                admin_manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, bad)

    def test_empty_identity_refused(self, admin_manager):
        with pytest.raises(ValueError, match="identity"):
            admin_manager.sign_admin_csr(_csr(_key()), "", _SHORT_LIFETIME)

    def test_unusable_ca_is_never_a_valueerror(self, tmp_path):
        """Error-class contract (§2.5 carried from sign_csr): a CA that cannot
        load is a service fault, never client input. At this tip the admin
        loader surfaces a missing file as FileNotFoundError and an undecryptable
        key as RuntimeError — chunk 2 maps both to 503-class faults; the cell
        pins what must NEVER happen: a ValueError (400) for a server-side fault."""
        manager = AdminCAManager(tmp_path / "no-such-ca")
        with pytest.raises((FileNotFoundError, RuntimeError)) as excinfo:
            manager.sign_admin_csr(_csr(_key()), _EMAIL_IDENTITY, _SHORT_LIFETIME)
        assert not isinstance(excinfo.value, ValueError)
