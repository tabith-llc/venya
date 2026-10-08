# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 1 — the two-plane marker (RF-6 §3.2).

The plane is CA-written and explicit: a Venya private OID extension carrying
``machine`` | ``human``, critical, never taken from a CSR. This file pins the
marker from both sides:

* the writer: both mints stamp their plane at issue time — ``human`` on the
  CSR signer (see test_admin_csr_signer_rf7.py), ``machine`` on the narrowed
  bootstrap mint here;
* the parser: ``parse_plane_marker`` fails closed on every miss — missing,
  unparseable, or out-of-set. (The middleware consumption is chunk 2; the
  parser ships and is tested with the signer in chunk 1.)
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from server.ca import (
    PLANE_HUMAN,
    PLANE_MACHINE,
    VENYA_PLANE_MARKER_OID,
    AdminCAManager,
    _plane_marker_extension,
    parse_plane_marker,
)

_ADMIN_PASSPHRASE_ENV = "rf7-marker-passphrase"


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", _ADMIN_PASSPHRASE_ENV)


@pytest.fixture
def admin_manager(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _selfsigned(extra_extensions=()) -> x509.Certificate:
    """A throwaway self-signed cert carrying exactly the supplied extensions —
    the substrate for the parser's negative halves."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "marker-parser-substrate")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(key, hashes.SHA256())


def _utf8(value: str) -> x509.UnrecognizedExtension:
    body = value.encode("ascii")
    return x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID, bytes([0x0C, len(body)]) + body)


class TestPlaneMarkerOnMints:
    def test_bootstrap_mint_carries_machine_marker(self, admin_manager):
        """§6.3 item 1: the narrowed bootstrap path writes ``machine`` at mint,
        critical, and the parser reads it back."""
        cert, _key_pem, _cert_pem = admin_manager.sign_admin_cert("core-1.internal")
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is True
        assert parse_plane_marker(cert) == PLANE_MACHINE
        # Paired negative: the machine mint never yields the human value.
        assert parse_plane_marker(cert) != PLANE_HUMAN

    def test_marker_written_exactly_once_per_mint(self, admin_manager):
        cert, _key_pem, _cert_pem = admin_manager.sign_admin_cert("core-1.internal")
        oids = [e.oid for e in cert.extensions]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1

    def test_bootstrap_mint_return_shape_unchanged(self, admin_manager):
        """install-venya-core.sh:420 unpacks (cert, key_pem, cert_pem) — the
        narrowing keeps the arity byte-compatible; this cell is the pin."""
        result = admin_manager.sign_admin_cert("core-1.internal")
        cert, key_pem, cert_pem = result  # 3-tuple or TypeError
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key_pem, bytes) and b"PRIVATE KEY" in key_pem
        assert isinstance(cert_pem, bytes) and b"CERTIFICATE" in cert_pem

    def test_writer_refuses_out_of_set_plane(self):
        """Truth-table negative: the writer itself cannot stamp a third plane."""
        for bad in ("", "Human", "GHOST", "machine ", None):
            with pytest.raises(ValueError):
                _plane_marker_extension(bad)  # type: ignore[arg-type]


class TestParsePlaneMarkerFailsClosed:
    def test_absent_marker_raises(self):
        cert = _selfsigned()  # no marker at all — a pre-two-plane cert
        with pytest.raises(ValueError, match="predates the two-plane model"):
            parse_plane_marker(cert)

    def test_unparseable_payload_raises(self):
        cases = {
            "not DER at all": b"garbage",
            "wrong tag (IA5String)": bytes([0x16, 0x05]) + b"human",
            "long-form length": bytes([0x0C, 0x81, 0x05]) + b"human",
            "length mismatch": bytes([0x0C, 0x07]) + b"human",
            "trailing bytes": bytes([0x0C, 0x05]) + b"human" + b"\x00",
            "empty": b"",
        }
        for label, payload in cases.items():
            cert = _selfsigned([(x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID, payload), True)])
            try:
                parse_plane_marker(cert)
            except ValueError:
                continue
            raise AssertionError(f"{label}: unparseable marker must fail closed")

    def test_out_of_set_value_raises(self):
        for bad in ("ghost", "Human", "MACHINE", "machine\n", ""):
            cert = _selfsigned([(_utf8(bad), True)])
            try:
                got = parse_plane_marker(cert)
            except ValueError:
                continue
            raise AssertionError(f"{bad!r}: parsed as {got!r} — must refuse out-of-set value")

    def test_valid_values_parse(self):
        for plane in (PLANE_MACHINE, PLANE_HUMAN):
            cert = _selfsigned([(_utf8(plane), True)])
            assert parse_plane_marker(cert) == plane
