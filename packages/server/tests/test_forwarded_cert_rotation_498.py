# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#498 forwarded-cert-first-ca-match-rotation regression tests.

Verifies that when a CA bundle contains multiple same-subject CAs (e.g., during
CA rotation where both old and new CAs share the same subject name),
_verify_forwarded_cert evaluates each matching candidate anchor instead of
short-circuiting on the first candidate.
"""

import tempfile
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from server.config import AdminMTLSConfig, InnerTLSConfig, ServerConfig
from server.middleware.auth import SessionMiddleware, _verify_forwarded_cert
from starlette.testclient import TestClient

try:
    from .conftest import pem_bytes
except ImportError:
    from conftest import pem_bytes


def _make_ca(key, subject_name: x509.Name, serial: int = 1) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _make_leaf(
    ca_key,
    issuer_name: x509.Name,
    subject_name: x509.Name,
    serial: int = 100,
    leaf_key=None,
    not_before=None,
    not_after=None,
    plane: str | None = None,
) -> x509.Certificate:
    """Leaf double. ``plane`` writes the CA's credential-plane marker.

    RF-7 chunk 2: the admin-plane call site under test (#498's rotation bundle)
    now consumes the marker before the allowlist (RF-6 §3.2), so a leaf that
    stands in for a machine-plane admin certificate must carry what the
    bootstrap mint actually writes at this tip. Executor/root-CA leaves keep
    plane=None — the marker is an Admin-CA statement and #498's rotation
    behavior under test is unchanged by it.
    """
    now = datetime.now(UTC)
    if leaf_key is None:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before or (now - timedelta(hours=1)))
        .not_valid_after(not_after or (now + timedelta(days=30)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if plane is not None:
        from server.ca import _plane_marker_extension

        builder = builder.add_extension(_plane_marker_extension(plane), critical=True)
    return builder.sign(ca_key, hashes.SHA256())


def _request_stub():
    """Minimal Request stand-in for _verify_forwarded_cert."""
    config = ServerConfig(
        recovery_code_pepper="p",
        inner_mtls=InnerTLSConfig(enabled=True),
    )
    app = SimpleNamespace(state=SimpleNamespace(config=config))
    return SimpleNamespace(app=app)


def _sqlite_admin_backend():
    """Real SQLite backend holding an empty AdminCertRevocation table."""
    from core.iam.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    workdir = tempfile.TemporaryDirectory(prefix="venya-revocation-test-")
    db_path = Path(workdir.name) / "revocation.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    class _Backend:
        _workdir = workdir

        def get_session(self):
            return session_factory()

    return _Backend()


def test_two_ca_bundle_leaf_signed_by_second_ca_verifies():
    """AC1: bundle of two same-subject CAs, leaf signed by the SECOND -> True."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=200)

    # Bundle has ca1 first, then ca2. Leaf was signed by ca2.
    bundle = [ca1, ca2]
    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf2, bundle) is True


def test_two_ca_bundle_leaf_signed_by_first_ca_verifies():
    """Leaf signed by the FIRST CA in a rotation bundle still verifies."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    leaf1 = _make_leaf(key1, ca_subject, leaf_subject, serial=100)

    bundle = [ca1, ca2]
    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf1, bundle) is True


def test_two_ca_bundle_leaf_signed_by_untrusted_same_subject_ca_rejected():
    """AC2: paired negative - same bundle, leaf signed by a third untrusted CA -> False."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    key3_untrusted = ec.generate_private_key(ec.SECP256R1())

    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    # leaf signed by key3 (same subject name, but key not in bundle)
    leaf3 = _make_leaf(key3_untrusted, ca_subject, leaf_subject, serial=300)

    bundle = [ca1, ca2]
    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf3, bundle) is False


def test_leaf_with_no_subject_match_rejected():
    """AC3: no subject match at all -> False."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)

    foreign_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Foreign CA")])
    foreign_key = ec.generate_private_key(ec.SECP256R1())
    leaf_foreign = _make_leaf(
        foreign_key,
        foreign_subject,
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign@user")]),
        serial=400,
    )

    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf_foreign, [ca1]) is False


def test_first_match_signature_failure_does_not_short_circuit_both_attempted():
    """AC4: first-match failure must not short-circuit; assert both candidates are attempted."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=200)

    # Use mocks wrapping ca1 and ca2 that return the real public keys,
    # and assert ca.public_key() is called on BOTH candidates.
    ca1_mock = MagicMock(wraps=ca1)
    ca1_mock.subject = ca1.subject
    ca1_mock.extensions = ca1.extensions
    ca1_mock.public_key.return_value = ca1.public_key()

    ca2_mock = MagicMock(wraps=ca2)
    ca2_mock.subject = ca2.subject
    ca2_mock.extensions = ca2.extensions
    ca2_mock.public_key.return_value = ca2.public_key()

    bundle = [ca1_mock, ca2_mock]
    req = _request_stub()
    result = _verify_forwarded_cert(req, leaf2, bundle)

    assert result is True
    # Assert both were attempted: ca1 failed signature check, ca2 succeeded
    assert ca1_mock.public_key.call_count == 1
    assert ca2_mock.public_key.call_count == 1

    # Ordering swap test: reverse order [ca2, ca1] with leaf signed by ca1
    leaf1 = _make_leaf(key1, ca_subject, leaf_subject, serial=100)
    ca1_mock.public_key.reset_mock()
    ca2_mock.public_key.reset_mock()

    reverse_bundle = [ca2_mock, ca1_mock]
    swap_result = _verify_forwarded_cert(req, leaf1, reverse_bundle)
    assert swap_result is True
    assert ca2_mock.public_key.call_count == 1
    assert ca1_mock.public_key.call_count == 1


def test_non_ca_basic_constraints_candidate_skipped():
    """A matching-subject cert with ca=False in BasicConstraints is skipped in candidate loop."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    key_not_ca = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    not_ca = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(key_not_ca.public_key())
        .serial_number(50)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key_not_ca, hashes.SHA256())
    )

    key2 = ec.generate_private_key(ec.SECP256R1())
    ca2 = _make_ca(key2, ca_subject, serial=51)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=200)

    # First entry is not a CA; second is valid CA.
    bundle = [not_ca, ca2]
    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf2, bundle) is True


def test_rsa_ca_bundle_second_ca_verifies():
    """RSA-based CA bundle with rotation works with candidate loop."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya RSA CA")])
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin@venya-core-1")])
    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=200)

    bundle = [ca1, ca2]
    req = _request_stub()
    assert _verify_forwarded_cert(req, leaf2, bundle) is True


# ---------------------------------------------------------------------------
# AC5: Plane coverage — Admin plane and Executor plane call sites
# ---------------------------------------------------------------------------


def test_admin_plane_call_site_two_ca_rotation_bundle(tmp_path):
    """Admin-plane call site (auth.py:373): rotation bundle accepts leaf from second CA."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    # Write rotation bundle (both CAs in one PEM file)
    bundle_pem = pem_bytes(ca1) + b"\n" + pem_bytes(ca2)
    bundle_path = tmp_path / "admin-ca-bundle.crt"
    bundle_path.write_bytes(bundle_pem)

    leaf_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "admin@example.com"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
        ]
    )
    from server.ca import PLANE_MACHINE

    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=201, plane=PLANE_MACHINE)

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.backend = _sqlite_admin_backend()
    app.state.config = ServerConfig(
        recovery_code_pepper="p",
        admin_mtls=AdminMTLSConfig(
            enabled=True,
            ca_cert=str(bundle_path),
            known_admin_ids=["admin@example.com"],
        ),
        inner_mtls=InnerTLSConfig(enabled=True),
    )

    @app.get("/api/v1/admin/test")
    def admin_endpoint(request: Request):
        return {"status": "ok", "auth_user": getattr(request.state, "auth_user", None)}

    client = TestClient(app, raise_server_exceptions=False)

    # Pass client cert via x-client-cert-pem header (URL-encoded)
    headers = {"x-client-cert-pem": urllib.parse.quote_from_bytes(pem_bytes(leaf2))}
    resp = client.get("/api/v1/admin/test", headers=headers)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


def test_executor_plane_call_site_two_ca_rotation_bundle(tmp_path):
    """Executor-plane call site (auth.py:676): rotation bundle accepts leaf from second CA."""
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA")])
    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    ca1 = _make_ca(key1, ca_subject, serial=1)
    ca2 = _make_ca(key2, ca_subject, serial=2)

    # Write root CA rotation bundle
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    bundle_path = ca_dir / "ca.crt"
    bundle_pem = pem_bytes(ca1) + b"\n" + pem_bytes(ca2)
    bundle_path.write_bytes(bundle_pem)

    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exec-worker-1")])
    leaf2 = _make_leaf(key2, ca_subject, leaf_subject, serial=202)

    # Mock backend to resolve executor row and revocation state
    mock_db = MagicMock()

    def query_side_effect(model):
        q = MagicMock()
        name = getattr(model, "__name__", "")
        if name == "Executor":
            q.filter.return_value.first.return_value = SimpleNamespace(
                id="exec-worker-1", revoked_at=None, status="active"
            )
        elif name == "ExecutorCert":
            q.filter.return_value.first.return_value = SimpleNamespace(serial_number=f"{leaf2.serial_number:016x}")
        else:
            q.filter.return_value.first.return_value = None
        return q

    mock_db.query.side_effect = query_side_effect
    mock_backend = MagicMock()
    mock_backend.get_session.return_value = mock_db

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.backend = mock_backend
    app.state.config = ServerConfig(
        recovery_code_pepper="p",
        ca_dir=str(ca_dir),
        admin_mtls=AdminMTLSConfig(enabled=False),
        inner_mtls=InnerTLSConfig(enabled=True),
    )

    @app.post("/api/v1/sessions/{session_id}/filter")
    def filter_endpoint(request: Request):
        return {"status": "ok", "auth_user": getattr(request.state, "auth_user", None)}

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"x-client-cert-pem": urllib.parse.quote_from_bytes(pem_bytes(leaf2))}
    resp = client.post("/api/v1/sessions/test-session-1/filter", headers=headers)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
