# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import NameOID


@pytest.fixture(autouse=True)
def _executor_ids_resolvable(monkeypatch):
    """Stub DNS for registration tests — the suite registers synthetic executor ids.

    Yields the REAL _dial_hostname_resolvable for tests that exercise actual
    resolution. Resolvability enforcement at the endpoint is covered by
    TestExecutorRegistration tests that override this stub.
    """
    from server.routes import executors as _ex

    real = _ex._dial_hostname_resolvable
    monkeypatch.setattr(_ex, "_dial_hostname_resolvable", lambda host: True)
    return real


# ---------------------------------------------------------------------------
# #314 end-to-end mTLS test helpers — forwarded-PEM plumbing shared by the
# admin-mTLS, session-middleware, and executor-identity suites.
#
# TRANSPORT = CONTENT (nginx 1.13.5+ ssl_client_escaped_cert): the verified
# client cert is URL-encoded into the header value. The old filesystem-path
# "extfile" transport never existed in stock nginx (fleet HALT 3) — there is no
# prefix, no temp file, and nothing to traverse. The `prefix`/`cert_prefix`
# args kept on these helpers are VESTIGIAL (callers still pass tmp dirs); the
# helpers ignore them and forward CONTENT.
# ---------------------------------------------------------------------------

#: Serial for the standard forwarded admin leaf (revocation-row fixtures use
#: the same hex; the middleware compares format(cert.serial_number, "x")
#: case-insensitively against AdminCertRevocation rows).
ADMIN_SERIAL_HEX = "1234123412341234"

#: Serial for foreign / non-admin leaves.
FOREIGN_SERIAL_HEX = "abcd1234abcd1234"


def pem_bytes(cert):
    """Serialize a cert to its PEM bytes (the payload nginx URL-encodes)."""
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def cert_pem_header_value(cert):
    """The header value the app expects: the cert PEM, URL-encoded.

    Mirrors nginx's ssl_client_escaped_cert so unquote_to_bytes round-trips.
    """
    import urllib.parse

    return urllib.parse.quote_from_bytes(pem_bytes(cert))


def make_cert_prefix(tmp_path):
    """Vestigial: the content transport needs no directory. Kept so callers
    that still pass tmp_path-derived prefixes keep working; returns the dir."""
    prefix = tmp_path / "certfiles"
    prefix.mkdir(parents=True, exist_ok=True)
    return prefix


def forwarded_headers(prefix, cert, header="x-client-cert-pem"):
    """Header set carrying the forwarded client cert as URL-encoded PEM content.

    The `prefix` arg is ignored (content transport); kept for call-site parity
    with the old extfile suites.
    """
    import urllib.parse

    return {header: urllib.parse.quote_from_bytes(pem_bytes(cert))}


def inner_tls_config(prefix=None):
    """InnerTLSConfig wired for unit tests (enabled + full material)."""
    from server.config import InnerTLSConfig

    return InnerTLSConfig(
        enabled=True,
        cert_file="/test/inner.crt",
        key_file="/test/inner.key",
        client_ca_file="/test/inner-ca.crt",
    )


def make_leaf(ca_cert, ca_key, *, cn, serial=None, days_valid=90, san_dns=None, san_email=None, expired=False):
    """Build a leaf signed by (ca_cert, ca_key) with a controllable serial/window."""
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    key = _ec.generate_private_key(_ec.SECP256R1())
    now = datetime.now(UTC)
    if expired:
        not_before, not_after = now - timedelta(days=30), now - timedelta(days=5)
    else:
        not_before, not_after = now - timedelta(hours=1), now + timedelta(days=days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else int.from_bytes(_uuid.uuid4().bytes[:8], "big"))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    san: list = []
    if san_email:
        san.append(x509.RFC822Name(san_email))
    if san_dns:
        san.append(x509.DNSName(san_dns))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(ca_key, SHA256())
