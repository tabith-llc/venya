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
# ---------------------------------------------------------------------------

#: Serial for the standard forwarded admin leaf (revocation-row fixtures use
#: the same hex; the middleware compares format(cert.serial_number, "x")
#: case-insensitively against AdminCertRevocation rows).
ADMIN_SERIAL_HEX = "1234123412341234"

#: Serial for foreign / non-admin leaves.
FOREIGN_SERIAL_HEX = "abcd1234abcd1234"


def make_cert_prefix(tmp_path):
    """Create a unique per-test directory the middleware may read certs from."""
    prefix = tmp_path / "certfiles"
    prefix.mkdir(parents=True, exist_ok=True)
    return prefix


def write_cert_file(prefix, cert):
    """Write a certificate PEM as a nginx-extfile-style path inside prefix.

    Randomized file name: nginx's temp names are per-connection; tests must
    not rely on (or collide across) a fixed name.
    """
    import uuid as _uuid

    from cryptography.hazmat.primitives import serialization

    path = prefix / f"cert-{_uuid.uuid4().hex}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


def forwarded_headers(prefix, cert, header="x-client-cert-file"):
    """Header set carrying the forwarded-cert path (the ONLY identity header left)."""
    return {header: write_cert_file(prefix, cert)}


def inner_tls_config(prefix):
    """InnerTLSConfig wired for unit tests (enabled + full material + prefix)."""
    from server.config import InnerTLSConfig

    return InnerTLSConfig(
        enabled=True,
        cert_file="/test/inner.crt",
        key_file="/test/inner.key",
        client_ca_file="/test/inner-ca.crt",
        cert_path_prefix=str(prefix),
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
