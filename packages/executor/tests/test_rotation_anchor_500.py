# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Rotation may not install its own trust anchor (#500).

``CertificateManager.rotate()`` used to read the CA out of the SAME response
body as the new leaf and write it to ``mtls.ca_cert`` — the file every later
TLS handshake is verified against. Nothing compared it with the anchor already
on disk, and ``validate_executor_certificate`` ran its six checks on the LEAF
and zero on the CA, so a caller able to answer the rotation request could swap
the trust root and have everything it presented afterwards believed.

Cells here, numbered against the ticket's acceptance criteria:

  1. AC1   a response CA that differs from the on-disk anchor and is not signed
           by it is refused, and NO file is written (RED at HEAD).
  2. AC2   three paired negatives on CA role: an expired CA, a CA with
           ``BasicConstraints ca=False``, and a CA without ``key_cert_sign`` —
           each refused (all three were accepted at HEAD).
  3. AC3   a legitimate rotation returning the SAME anchor writes through and
           still updates the in-memory identity (GREEN preserved).
  4.     the one shape in which a DIFFERENT root may be adopted at rotation:
           the incumbent anchor signed it (cross-signed rollover).
  5. AC4   order of operations: anchor resolved, leaf validated, THEN writes —
           pinned by observing the sequence on both the failure and success
           path.
  6. AC5   rotation with no anchor on disk refuses, names the re-enroll
           ceremony, and writes nothing (rotation is not a bootstrap path).
  7.       ``validate_ca_certificate`` truth table — both halves.
"""

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
    validate_ca_certificate,
)

# --- PKI helpers (self-contained: every CA role knob individually selectable) ---


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _ca(
    cn: str = "Venya Root CA",
    *,
    issuer_cn: str | None = None,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
    days: int = 3650,
    already_expired: bool = False,
    ca_flag: bool = True,
    key_cert_sign: bool = True,
    with_basic_constraints: bool = True,
    with_key_usage: bool = True,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A CA-shaped certificate with each role knob set independently.

    Pass ``signing_key`` + ``issuer_cn`` to build a CROSS-SIGNED root (someone
    else's key signs this one); the defaults build a self-signed root.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    signer = signing_key or key
    now = datetime.now(UTC)
    not_before = now - timedelta(days=365)
    not_after = now - timedelta(days=1) if already_expired else now + timedelta(days=days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if with_basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
    if with_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return key, builder.sign(signer, hashes.SHA256())


def _executor_leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str = "test-executor",
    days: int = 30,
) -> x509.Certificate:
    """A properly-shaped executor leaf signed by the given CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _response(leaf: x509.Certificate, ca_cert: x509.Certificate) -> MagicMock:
    """Mocked 201 answer from POST /api/v1/executors/register."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = 201
    mock.raise_for_status.return_value = None
    mock.json.return_value = {
        "executor_id": "test-executor",
        "cert_pem": _pem(leaf).decode(),
        "ca_cert_pem": _pem(ca_cert).decode(),
        "serial_number": format(leaf.serial_number, "016x"),
        "not_after": leaf.not_valid_after_utc.isoformat(),
    }
    return mock


@pytest.fixture()
def venue(tmp_path: Path) -> Path:
    """Writable identity dir (rotate() pre-checks it for writability)."""
    cert_dir = tmp_path / "etc-venya-executor"
    cert_dir.mkdir()
    return cert_dir


@pytest.fixture()
def manager(venue: Path) -> CertificateManager:
    """CertificateManager with cert / key / CA paths all inside the venue dir."""
    cfg = ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        dns_resolver="192.0.2.53",
        mtls=MtlsConfig(
            ca_cert=str(venue / "ca.crt"),
            cert=str(venue / "executor.crt"),
            key=str(venue / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(rotate_before_days=3),
    )
    cm = CertificateManager(cfg)
    cm.client = httpx2.Client(base_url="https://example.com", verify=False)
    return cm


def _incumbent(
    cm: CertificateManager, ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate
) -> tuple[bytes, bytes, bytes]:
    """Write the state registration leaves behind: anchor file + a leaf under it.

    Returns the on-disk snapshot for before/after comparisons.
    """
    Path(cm.ca_cert_path).write_bytes(_pem(ca_cert))
    Path(cm.cert_path).write_bytes(_pem(_executor_leaf(ca_key, ca_cert)))
    Path(cm.key_path).write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cm.serial = "incumbent-serial"
    return _snapshot(cm)


def _rotate(cm: CertificateManager, mock_response: MagicMock) -> None:
    with patch.object(cm.client, "post", return_value=mock_response):
        cm.rotate()


def _snapshot(cm: CertificateManager) -> tuple[bytes, bytes, bytes]:
    """The three files rotate() would touch, exactly as they sit on disk."""
    return (
        Path(cm.cert_path).read_bytes(),
        Path(cm.key_path).read_bytes(),
        Path(cm.ca_cert_path).read_bytes(),
    )


# --- 1. AC1: a foreign anchor is refused, and nothing is written -------------


class TestRotationCannotInstallItsOwnAnchor:
    def test_substituted_ca_refused_and_nothing_written(self, manager):
        """RED at HEAD: the response CA was the only CA consulted, so a foreign
        root arriving in the same body was adopted as the trust anchor.

        Here the leaf is legitimately signed by the FOREIGN CA — the shape an
        attacker who controls the rotation answer would present. Rejecting the
        anchor must therefore happen even though the leaf checks out, and no
        file may move."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        rogue_key, rogue = _ca("Rogue Root CA")
        leaf = _executor_leaf(rogue_key, rogue)

        with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
            _rotate(manager, _response(leaf, rogue))

        assert _snapshot(manager) == before
        assert manager.serial == "incumbent-serial"

    def test_self_signed_lookalike_leaf_refused_as_anchor(self, manager):
        """Second half of AC1: a self-signed cert with an ECDSA key and no CA
        extensions is what ``_verify_ca_signature`` alone would accept as an
        issuer. The CA-role check refuses it before continuity is even reached."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        # A leaf-shaped self-signed certificate: CA=False, no key_cert_sign.
        lookalike_key, lookalike = _ca("Lookalike", ca_flag=False, key_cert_sign=False)
        leaf = _executor_leaf(lookalike_key, lookalike)

        with pytest.raises(CertificateValidationError, match="BasicConstraints CA=False"):
            _rotate(manager, _response(leaf, lookalike))

        assert _snapshot(manager) == before


# --- 2. AC2: the three CA-role paired negatives ------------------------------


class TestCaRoleChecksOnTheArrivingAnchor:
    def test_expired_ca_refused(self, manager):
        """Expired CA: refused by the validity window. At HEAD the window was
        never checked for the CA argument, so this was adopted."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        # Same subject, still signed by the incumbent (so a continuity-only
        # fix would wave it through) but past its own not_after.
        _, stale = _ca("Venya Root CA", signing_key=incumbent_key, issuer_cn="Venya Root CA", already_expired=True)
        leaf = _executor_leaf(incumbent_key, stale)

        with pytest.raises(CertificateValidationError, match="CA certificate expired"):
            _rotate(manager, _response(leaf, stale))

        assert _snapshot(manager) == before

    def test_ca_false_refused(self, manager):
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        _, not_a_ca = _ca("Venya Root CA", signing_key=incumbent_key, issuer_cn="Venya Root CA", ca_flag=False)
        leaf = _executor_leaf(incumbent_key, not_a_ca)

        with pytest.raises(CertificateValidationError, match="BasicConstraints CA=False"):
            _rotate(manager, _response(leaf, not_a_ca))

        assert _snapshot(manager) == before

    def test_missing_key_cert_sign_refused(self, manager):
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        _, no_signing = _ca("Venya Root CA", signing_key=incumbent_key, issuer_cn="Venya Root CA", key_cert_sign=False)
        leaf = _executor_leaf(incumbent_key, no_signing)

        with pytest.raises(CertificateValidationError, match="keyCertSign"):
            _rotate(manager, _response(leaf, no_signing))

        assert _snapshot(manager) == before

    def test_extensionless_ca_rejected(self, manager):
        """A CA with no BasicConstraints at all is refused too — the missing
        extension has its own branch, not just the False branch."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        _, no_extensions = _ca(
            "Venya Root CA",
            signing_key=incumbent_key,
            issuer_cn="Venya Root CA",
            with_basic_constraints=False,
        )
        leaf = _executor_leaf(incumbent_key, no_extensions)

        with pytest.raises(CertificateValidationError, match="missing BasicConstraints"):
            _rotate(manager, _response(leaf, no_extensions))
        assert _snapshot(manager) == before


# --- 3. AC3: the legitimate same-anchor rotation stays green ------------------


class TestLegitimateRotationUnchanged:
    def test_same_anchor_writes_through(self, manager):
        """The core returns its own CA again, exactly as it did at registration:
        the rotation completes and the anchor lands unchanged."""
        ca_key, ca = _ca("Venya Root CA")
        _incumbent(manager, ca_key, ca)

        new_leaf = _executor_leaf(ca_key, ca)
        _rotate(manager, _response(new_leaf, ca))

        saved_cert = x509.load_pem_x509_certificate(Path(manager.cert_path).read_bytes())
        assert saved_cert.serial_number == new_leaf.serial_number
        assert Path(manager.ca_cert_path).read_bytes() == _pem(ca)
        assert manager.serial == format(new_leaf.serial_number, "016x")
        assert manager.not_after == new_leaf.not_valid_after_utc

    def test_rewritten_pem_same_certificate_still_accepted(self, manager):
        """Continuity is the CERTIFICATE, not the byte layout of the file: a
        re-encoded but identical CA still passes (DER comparison)."""
        ca_key, ca = _ca("Venya Root CA")
        Path(manager.ca_cert_path).write_bytes(b"\n" + _pem(ca))  # leading whitespace, same cert
        Path(manager.cert_path).write_bytes(_pem(_executor_leaf(ca_key, ca)))
        Path(manager.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )

        new_leaf = _executor_leaf(ca_key, ca)
        _rotate(manager, _response(new_leaf, ca))

        saved = x509.load_pem_x509_certificate(Path(manager.cert_path).read_bytes())
        assert saved.serial_number == new_leaf.serial_number


# --- 4. the one sanctioned way to adopt a different root ---------------------


class TestCrossSignedRollover:
    def test_incumbent_signed_new_root_adopted(self, manager):
        """A NEW root is legitimate only when the incumbent's key signed it —
        the incumbent vouches for it, which a body-supplied CA never does."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        _incumbent(manager, incumbent_key, incumbent)

        new_key, new_root = _ca("Venya Root CA 2028", signing_key=incumbent_key, issuer_cn="Venya Root CA")
        leaf = _executor_leaf(new_key, new_root)

        _rotate(manager, _response(leaf, new_root))

        assert Path(manager.ca_cert_path).read_bytes() == _pem(new_root)
        saved = x509.load_pem_x509_certificate(Path(manager.cert_path).read_bytes())
        assert saved.serial_number == leaf.serial_number

    def test_new_root_signed_by_somebody_else_still_refused(self, manager):
        """Paired negative: the same 'different root' shape, wrong signer — the
        adoption path must not degrade into 'any CA that carries a signature
        from someone'. RED at HEAD: that root is self-consistent, the leaf
        under it validates, and the anchor was swapped with no objection."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        third_key, _third = _ca("Third Party CA")
        other_key, other_signed = _ca("Venya Root CA 2028", signing_key=third_key, issuer_cn="Third Party CA")
        leaf = _executor_leaf(other_key, other_signed)

        with pytest.raises(CertificateValidationError, match="not signed by trusted CA"):
            _rotate(manager, _response(leaf, other_signed))

        assert _snapshot(manager) == before


# --- 5. AC4: order of operations ---------------------------------------------


class TestWriteOrdering:
    def test_no_write_before_the_anchor_is_resolved(self, manager):
        """The rejected path performs ZERO writes: continuity + CA role + leaf
        validation all precede the first _atomic_write."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        rogue_key, rogue = _ca("Rogue Root CA")
        leaf = _executor_leaf(rogue_key, rogue)

        with patch("executor.daemon._atomic_write") as writer:
            with pytest.raises(CertificateValidationError):
                _rotate(manager, _response(leaf, rogue))
            writer.assert_not_called()

        assert _snapshot(manager) == before

    def test_sequence_on_the_accepted_path(self, manager):
        """Success path: the writes land in the order cert -> key -> ca, so the
        trust anchor is written LAST — nothing already trusted a
        partially-installed identity, and the anchor only moves once the leaf
        and key it will be used with are durable."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        _incumbent(manager, incumbent_key, incumbent)
        new_leaf = _executor_leaf(incumbent_key, incumbent)

        events: list[str] = []
        import executor.daemon as daemon_mod

        real_write = daemon_mod._atomic_write

        def spy(path, payload, mode):
            events.append(Path(path).name)
            return real_write(path, payload, mode)

        with patch.object(daemon_mod, "_atomic_write", side_effect=spy):
            _rotate(manager, _response(new_leaf, incumbent))

        assert events == ["executor.crt", "executor.key", "ca.crt"]

    def test_leaf_signed_by_the_foreign_ca_never_reaches_validation(self, manager):
        """The substitution is caught at the ANCHOR step, not by the leaf
        checks — pinning that the guard does not depend on the leaf being bad."""
        incumbent_key, incumbent = _ca("Venya Root CA")
        before = _incumbent(manager, incumbent_key, incumbent)

        rogue_key, rogue = _ca("Rogue Root CA")
        leaf = _executor_leaf(rogue_key, rogue)  # a perfectly-shaped leaf, wrong issuer

        import executor.daemon as daemon_mod

        with (
            patch.object(
                daemon_mod, "validate_executor_certificate", wraps=daemon_mod.validate_executor_certificate
            ) as leaf_check,
            pytest.raises(CertificateValidationError),
        ):
            _rotate(manager, _response(leaf, rogue))
        leaf_check.assert_not_called()

        assert _snapshot(manager) == before


# --- 6. AC5: rotation is not a bootstrap path --------------------------------


class TestNoAnchorOnDisk:
    def test_refuses_and_names_the_reenroll_ceremony(self, manager):
        """With no anchor to compare against, rotation cannot prove continuity,
        so it refuses rather than adopting whatever arrives. The message names
        the ceremony that DOES mint an anchor."""
        ca_key, ca = _ca("Venya Root CA")
        _incumbent(manager, ca_key, ca)
        Path(manager.ca_cert_path).unlink()  # anchor gone; cert+key remain

        leaf = _executor_leaf(ca_key, ca)
        with pytest.raises(RuntimeError, match="no trust anchor on disk") as ei:
            _rotate(manager, _response(leaf, ca))

        msg = str(ei.value)
        assert "VENYA_EXECUTOR_ENROLLMENT_TOKEN" in msg
        assert "venya admin executor-enroll" in msg
        assert not Path(manager.ca_cert_path).exists()  # nothing re-created


# --- 7. validate_ca_certificate truth table (both halves) --------------------


class TestValidateCaCertificateTruthTable:
    """Positive on the left, its own negative on the right — AC2's pairs,
    checked at the unit boundary as well as through rotate()."""

    def test_valid_ca_returns_the_parsed_certificate(self):
        _key, ca = _ca("Venya Root CA")
        checked = validate_ca_certificate(_pem(ca))
        assert checked == ca  # the parsed certificate comes back, not a re-built one

    def test_expired_ca_rejected(self):
        _key, ca = _ca("Venya Root CA", already_expired=True)
        with pytest.raises(CertificateValidationError, match="CA certificate expired"):
            validate_ca_certificate(_pem(ca))

    def test_not_yet_valid_ca_rejected(self):
        """The window has two halves; only the expired one was named in the AC."""
        key, _ca_cert = _ca("Venya Root CA")
        now = datetime.now(UTC)
        future = (
            x509.CertificateBuilder()
            .subject_name(_name("Venya Root CA"))
            .issuer_name(_name("Venya Root CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
            .sign(key, hashes.SHA256())
        )
        with pytest.raises(CertificateValidationError, match="not yet valid"):
            validate_ca_certificate(_pem(future))

    def test_ca_false_rejected(self):
        _key, ca = _ca("Venya Root CA", ca_flag=False)
        with pytest.raises(CertificateValidationError, match="BasicConstraints CA=False"):
            validate_ca_certificate(_pem(ca))

    def test_missing_basic_constraints_rejected(self):
        _key, ca = _ca("Venya Root CA", with_basic_constraints=False)
        with pytest.raises(CertificateValidationError, match="missing BasicConstraints"):
            validate_ca_certificate(_pem(ca))

    def test_missing_key_cert_sign_rejected(self):
        _key, ca = _ca("Venya Root CA", key_cert_sign=False)
        with pytest.raises(CertificateValidationError, match="keyCertSign"):
            validate_ca_certificate(_pem(ca))

    def test_missing_key_usage_rejected(self):
        _key, ca = _ca("Venya Root CA", with_key_usage=False)
        with pytest.raises(CertificateValidationError, match="missing KeyUsage"):
            validate_ca_certificate(_pem(ca))

    def test_leaf_certificate_rejected_as_anchor(self):
        """The most important negative: a well-formed LEAF (CA=False,
        digitalSignature) is never an anchor, whatever key it carries."""
        _key, leaf = _ca("Venya Executor Leaf", ca_flag=False, key_cert_sign=False)
        with pytest.raises(CertificateValidationError, match="BasicConstraints CA=False"):
            validate_ca_certificate(_pem(leaf))
