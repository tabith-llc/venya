# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#314 forwarded-cert CONTENT transport truth table (fleet HALT 3 remedy).

The path "extfile" the original design named ($ssl_client_certificate_path)
never existed in stock nginx; the transport is now URL-encoded PEM CONTENT
(nginx 1.13.5+ ssl_client_escaped_cert). These cells pin _forwarded_client_cert
behaviour on the CONTENT guards, with the paired negative half per the truth-
table rule: each ACCEPT has its REJECT twin (oversize, concatenation, garbage).
"""

import urllib.parse
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import NameOID

try:
    from .conftest import pem_bytes
except ImportError:
    from conftest import pem_bytes

from server.config import InnerTLSConfig, ServerConfig
from server.middleware.auth import _forwarded_client_cert

_HEADER = "x-client-cert-pem"


def _leaf() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t@e")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, SHA256())
    )


def _request(header_value, *, enabled=True, max_bytes=16384):
    """Minimal Request stand-in: .app.state.config + .headers.get only."""
    config = ServerConfig(
        recovery_code_pepper="p",
        inner_mtls=InnerTLSConfig(enabled=enabled, cert_max_bytes=max_bytes),
    )
    app = SimpleNamespace(state=SimpleNamespace(config=config))
    headers = {} if header_value is None else {_HEADER: header_value}
    return SimpleNamespace(app=app, headers=headers)


def _big_leaf() -> x509.Certificate:
    """A leaf whose PEM exceeds 512 bytes (the field minimum ceiling)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "t@e"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X" * 400),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, SHA256())
    )


def test_forwarded_cert_urlencoded_ok():
    """Positive: URL-encoded PEM content decodes and parses to an x509."""
    cert = _leaf()
    got = _forwarded_client_cert(_request(urllib.parse.quote_from_bytes(pem_bytes(cert))))
    assert isinstance(got, x509.Certificate)
    assert got.serial_number == cert.serial_number


def test_forwarded_cert_plain_pem_accepted():
    """A raw (un-encoded) PEM is still exactly one valid block — the posture
    is content-agnostic and ACCEPTS it. Not a risk: nginx only ever emits the
    URL-encoded form, and any single parseable PEM re-verifies downstream."""
    cert = _leaf()
    raw = pem_bytes(cert).decode()
    assert "\n" in raw  # a bare multi-line PEM passed verbatim as the header value
    got = _forwarded_client_cert(_request(raw))
    assert isinstance(got, x509.Certificate)


def test_forwarded_cert_over_size_ceiling_rejected():
    """Negative twin of the size guard: decoded bytes above cert_max_bytes → None."""
    cert = _big_leaf()
    encoded = urllib.parse.quote_from_bytes(pem_bytes(cert))
    # minimum legal ceiling (512) below this leaf's ~800-byte PEM
    assert _forwarded_client_cert(_request(encoded, max_bytes=512)) is None


def test_forwarded_cert_concatenation_rejected():
    """Negative: two stacked PEM blocks (BEGIN count != 1) are refused."""
    one = pem_bytes(_leaf())
    assert _forwarded_client_cert(_request(urllib.parse.quote_from_bytes(one + one))) is None


def test_forwarded_cert_garbage_rejected():
    """Negative: bytes that are not a PEM certificate → None (parse fails closed)."""
    assert _forwarded_client_cert(_request(urllib.parse.quote_from_bytes(b"not a certificate"))) is None


def test_forwarded_cert_absent_header_none():
    """Negative: no header → None (the gates fail closed, no downgrade)."""
    assert _forwarded_client_cert(_request(None)) is None


def test_forwarded_cert_disabled_surface_none():
    """Negative: inner mTLS disabled → the transport is not read at all."""
    cert = _leaf()
    encoded = urllib.parse.quote_from_bytes(pem_bytes(cert))
    assert _forwarded_client_cert(_request(encoded, enabled=False)) is None
