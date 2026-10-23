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

# --- #650: the PostgreSQL test door's pre-flight -------------------------------------------------
#
# One shared implementation, in ``scripts/pg_door_preflight.py``, wired here and in
# ``packages/core/tests/conftest.py`` — the alternative was two copies of the cause table, which is
# the split-brain shape this plane keeps booking. Added on the lead's ruling
# (`wren-650-conftest-ruling-flash1-s134`), which also set the condition this wiring is held to: it
# is ADDITIVE. It registers no fixture, shadows none, and re-orders nothing — the existing
# ``_executor_ids_resolvable`` autouse fixture below is untouched and keeps running exactly as it
# did, and the two hooks here (``pytest_report_header``, ``pytest_runtest_setup``) are the only
# thing this block contributes to collection. Core's report carries the collected-count proof that
# the same claim needed there.
#
# WHY IT BINDS HERE: a leg that sets the door variable is asking for the PostgreSQL cells to run.
# When the host cannot give them, the suite used to answer with psycopg2's "Is the server running
# on that host…" — a red product cell whose actual cause was a full tmpfs, and indistinguishable
# from a fixture nobody started. The pre-flight reads the door, names the cause, prints the number.


def _load_pg_door_preflight():
    """Load the shared pre-flight by path, the way core's baseline interlock loads its guard.

    A missing file aborts the session rather than passing quietly: a pre-flight that cannot run must
    never present as a clean run — that is the silence #650 exists to end, one layer down.
    """
    import importlib.util
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[3] / "scripts" / "pg_door_preflight.py"
    if not script.is_file():
        pytest.exit(
            f"pg-door-pre-flight CANNOT RUN: {script} is missing, so no door check is in force in "
            "this package. Restore it before trusting any PostgreSQL-gated result here.",
            returncode=1,
        )
    spec = importlib.util.spec_from_file_location("pg_door_preflight_server", script)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the module declares a @dataclass, which resolves its owning module
    # through sys.modules at class-creation time. Without this line the import dies on
    # "'NoneType' object has no attribute '__dict__'" and takes collection with it.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_pg_door_preflight = _load_pg_door_preflight()


def pytest_report_header(config) -> list[str]:
    """State what the pre-flight found, on every run — #650 AC1 wants it where it binds."""
    return [_pg_door_preflight.door_report_header(config)]


def pytest_runtest_setup(item) -> None:
    """Abort a door-gated cell loudly when the door was requested and this host cannot answer it.

    A no-op for every other cell, and a no-op for gated cells when the door is healthy or not asked
    for — that is the paired negative the row is half made of.
    """
    _pg_door_preflight.abort_unusable_door(item)


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


def make_leaf(
    ca_cert,
    ca_key,
    *,
    cn,
    serial=None,
    days_valid=90,
    san_dns=None,
    san_email=None,
    expired=False,
    plane=None,
):
    """Build a leaf signed by (ca_cert, ca_key) with a controllable serial/window.

    ``plane`` (RF-7 chunk 2) writes the CA's credential-plane marker — the
    extension every Admin-CA mint carries at this tip (``sign_admin_cert``
    writes ``machine``, ``sign_admin_csr`` writes ``human``). Pass
    ``PLANE_MACHINE`` for a double that stands in for an admin certificate; the
    middleware refuses an admin leaf with NO marker (RF-6 §3.2, fail closed),
    so an admin-plane double that omits it is a PRE-TWO-PLANE certificate and
    belongs in the cells that prove exactly that refusal.
    Left as ``None`` for root/executor-CA leaves, which carry no plane marker at
    all (the marker is an Admin-CA statement).
    """
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
    if plane is not None:
        # The CA's own signer writes this extension (server/ca.py
        # _plane_marker_extension); the double reuses that function so a test
        # leaf and a minted leaf cannot drift apart.
        from server.ca import _plane_marker_extension

        builder = builder.add_extension(_plane_marker_extension(plane), critical=True)
    return builder.sign(ca_key, SHA256())
