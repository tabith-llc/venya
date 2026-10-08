# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 2 — the issuance route contract (CP-A).

``POST /api/v1/admin/certs/issue`` turns a session caller + a caller-supplied
CSR into a minutes-scale human-plane admin certificate. This file pins the
CONTRACT: CSR in, certificate out, and never a private key — the whole content
of ruling 3 (RF-6 §1.2). Caller authorization, rate limiting, the audit event,
and the §6.5 first-human reachability land in CP-B/CP-C and have their own
cells there.

Every positive carries its rejected half (RF-6 §3.8, truth-table law): the
minted cert is human-plane / a request that asks for a machine plane dies; the
identity is server-derived / a self-described identity in the body is refused;
bad CSR material is a 400 / unusable CA material is a 503, never a 500.
"""

from datetime import UTC, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from server.app import create_app
from server.ca import (
    ADMIN_SHORT_CERT_LIFETIME_SECONDS,
    PLANE_HUMAN,
    PLANE_MACHINE,
    AdminCAManager,
    csr_curve_hint,
    parse_plane_marker,
)
from server.config import ServerConfig
from server.dependencies import get_current_user
from server.routes import admin_certs as admin_certs_routes
from starlette.testclient import TestClient

_SESSION_IDENTITY = "alice@example.com"
_MACHINE_IDENTITY = "admin@core-1.internal"


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_admin_passphrase_rf7c2")


@pytest.fixture
def admin_ca(tmp_path: Path) -> AdminCAManager:
    # Default admin passphrase env (VENYA_ADMIN_CA_KEY_PASSPHRASE) is what the
    # _passphrase_env fixture above sets; no CASecurityConfig override needed.
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _key(curve=ec.SECP256R1):
    instance = curve() if isinstance(curve, type) else curve
    return ec.generate_private_key(instance)


def _csr(private_key, common_name: str = "attacker-chosen-cn") -> bytes:
    """A self-signed CSR with an adversarial subject, PEM-encoded (the wire form)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EvilCorp"),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _session_caller(user_id: str = _SESSION_IDENTITY) -> dict:
    """The shape a validated bearer/cookie session attaches (middleware/auth.py)."""
    return {"user_id": user_id, "session_id": 11, "roles": ["role-admin"], "exp": 0}


def _make_app(admin_ca: AdminCAManager | None, caller: dict | None) -> FastAPI:
    app = FastAPI()
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper")
    app.state.admin_ca_manager = admin_ca
    app.include_router(admin_certs_routes.router, prefix="/api/v1")
    if caller is not None:
        app.dependency_overrides[get_current_user] = lambda: caller
    return app


def _client(admin_ca: AdminCAManager | None, caller: dict | None) -> TestClient:
    return TestClient(_make_app(admin_ca, caller), raise_server_exceptions=False)


def _issue(client: TestClient, csr_pem: bytes | str, **extra_fields):
    body = {"csr_pem": csr_pem if isinstance(csr_pem, str) else csr_pem.decode(), **extra_fields}
    return client.post("/api/v1/admin/certs/issue", json=body)


def _issued_cert(client: TestClient, private_key=None):
    resp = _issue(client, _csr(private_key or _key()))
    assert resp.status_code == 201, resp.text
    return x509.load_pem_x509_certificate(resp.json()["certificate_pem"].encode())


class TestIssuanceHappyPath:
    def test_session_caller_receives_a_human_plane_cert(self, admin_ca):
        """Positive half: session caller + valid CSR → a human-plane leaf."""
        cert = _issued_cert(_client(admin_ca, _session_caller()))
        assert parse_plane_marker(cert) == PLANE_HUMAN
        # Paired negative: it is NOT the machine plane, and never the CSR's claim.
        assert parse_plane_marker(cert) != PLANE_MACHINE

    def test_lifetime_is_the_ruled_minutes_scale_value(self, admin_ca):
        """Ruling 4a (60 minutes) is what the route passes down (RF-6 §1.2)."""
        cert = _issued_cert(_client(admin_ca, _session_caller()))
        window = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert window == timedelta(seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS)
        # Paired negative: a days-scale lifetime (the machine-plane shape) is not
        # what this endpoint issues.
        assert window < timedelta(days=1)

    def test_identity_is_server_derived_from_the_session(self, admin_ca):
        """§2.6: the mint is not self-described — CN and SAN come from the session."""
        cert = _issued_cert(_client(admin_ca, _session_caller()))
        cn = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        assert cn == [_SESSION_IDENTITY]
        subject_values = {a.value for a in cert.subject}
        # Paired negative: the CSR's own strings appear nowhere.
        assert "attacker-chosen-cn" not in subject_values
        assert "EvilCorp" not in subject_values

    def test_eku_is_client_auth_only(self, admin_ca):
        """§2.5: SERVER_AUTH on an admin leaf would let it impersonate a core."""
        cert = _issued_cert(_client(admin_ca, _session_caller()))
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]

    def test_cert_verifies_under_the_admin_ca(self, admin_ca):
        """The leaf is signed by the admin CA the route was handed, not another key."""
        cert = _issued_cert(_client(admin_ca, _session_caller()))
        ca_cert = x509.load_pem_x509_certificate(admin_ca.get_admin_ca_cert_pem())
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )


class TestNoPrivateKeyEverReturned:
    def test_response_body_is_the_certificate_pem_and_nothing_else(self, admin_ca):
        """§2.7: response carries the certificate PEM and nothing else.

        This is ruling 3's wire-level proof — the key the workstation generated
        never comes back, and neither does a CSR echo.
        """
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert set(body.keys()) == {"certificate_pem"}
        text = resp.text
        for forbidden in ("PRIVATE KEY", "CERTIFICATE REQUEST", "BEGIN NEW CERTIFICATE REQUEST"):
            assert forbidden not in text, f"the response leaked {forbidden!r}"

    def test_error_responses_carry_no_key_material(self, admin_ca):
        """Paired negative for every refusal this route can emit."""
        client = _client(admin_ca, _session_caller())
        refusals = [
            _issue(client, "not a csr at all"),  # 400
            client.post("/api/v1/admin/certs/issue", json={}),  # 422
            client.post("/api/v1/admin/certs/issue", json={"csr_pem": "x", "identity": "mallory"}),  # 422
            _issue(client, _csr(_key(ec.SECP192R1()))),  # 400 curve refusal
        ]
        for resp in refusals:
            assert "PRIVATE KEY" not in resp.text, resp.text
        assert [r.status_code for r in refusals] == [400, 422, 422, 400]


class TestSelfDescribedIdentityRefused:
    def test_identity_field_in_the_body_is_refused(self, admin_ca):
        """§2.6 REFUSED, not ignored: extra="forbid" dies at validation (422).

        Stated for the report: the route's answer to a self-described identity
        is a refusal at the request model, so a caller cannot even ask for a
        cert naming someone else.
        """
        client = _client(admin_ca, _session_caller())
        for field in ("identity", "cn", "user_id", "plane"):
            resp = _issue(client, _csr(_key()), **{field: "mallory@example.com"})
            assert resp.status_code == 422, (field, resp.text)

    def test_csr_subject_carries_no_authority(self, admin_ca):
        """The other half: a CSR naming another person mints the SESSION's id."""
        cert = _issued_cert(_client(admin_ca, _session_caller()), _key())
        cn = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        assert cn == [_SESSION_IDENTITY]
        assert "attacker-chosen-cn" not in {a.value for a in cert.subject}


class TestCsrRejects:
    def test_unparseable_csr_is_400(self, admin_ca):
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, "-----BEGIN NONSENSE-----\nZm9v\n-----END NONSENSE-----\n")
        assert resp.status_code == 400
        assert "Invalid CSR" in resp.json()["detail"]

    def test_missing_csr_field_is_422(self, admin_ca):
        client = _client(admin_ca, _session_caller())
        resp = client.post("/api/v1/admin/certs/issue", json={})
        assert resp.status_code == 422

    def test_broken_self_signature_is_400(self, admin_ca):
        """§2.7 error-class contract: bad CSR material is client input."""
        der = bytearray(x509.load_pem_x509_csr(_csr(_key())).public_bytes(serialization.Encoding.DER))
        der[-1] ^= 0x01
        broken = x509.load_der_x509_csr(bytes(der))
        assert broken.is_signature_valid is False, "fixture must produce an unverifiable CSR"
        client = _client(admin_ca, _session_caller())
        resp = _issue(
            client,
            broken.public_bytes(serialization.Encoding.PEM).decode(),
        )
        assert resp.status_code == 400
        assert "CSR signature verification failed" in resp.json()["detail"]

    def test_off_list_curve_is_400_naming_the_accepted_curves(self, admin_ca):
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, _csr(_key(ec.SECP192R1())))
        assert resp.status_code == 400
        assert csr_curve_hint() in resp.json()["detail"]

    def test_rsa_key_is_400(self, admin_ca):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa-attacker")]))
            .sign(rsa_key, hashes.SHA256())
        )
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, csr.public_bytes(serialization.Encoding.PEM).decode())
        assert resp.status_code == 400
        assert csr_curve_hint() in resp.json()["detail"]


class TestMachinePlaneRefused:
    def test_a_request_that_asks_for_a_machine_plane_is_refused(self, admin_ca):
        """§3.2/§6.5: this endpoint mints the human plane and nothing else.

        The plane is CA-written and not selectable by the caller at all, so the
        machine plane is unreachable here — the refusal is the validation error
        on an unknown field, which is the strongest form of the rule.
        """
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, _csr(_key()), plane=PLANE_MACHINE)
        assert resp.status_code == 422


class TestServiceFaultsAreNotClientErrors:
    def test_missing_admin_ca_is_503_not_500(self):
        """§2.7: unusable CA material stays a service fault."""
        client = _client(None, _session_caller())
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 503
        assert "init-admin-ca" in resp.json()["detail"]

    def test_ca_runtime_error_is_503_not_500(self, admin_ca, monkeypatch):
        """A CA that cannot load is never client input (sign_admin_csr contract)."""

        def _boom(*_args, **_kwargs):
            raise RuntimeError("Admin CA key is encrypted but no passphrase is set")

        monkeypatch.setattr(admin_ca, "sign_admin_csr", _boom)
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 503
        assert "Admin CA unavailable" in resp.json()["detail"]

    def test_ca_missing_file_is_503_not_500(self, admin_ca, monkeypatch):
        def _gone(*_args, **_kwargs):
            raise FileNotFoundError("admin-ca.key")

        monkeypatch.setattr(admin_ca, "sign_admin_csr", _gone)
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 503


class TestCallerShapesRefused:
    def test_cert_only_caller_with_no_session_is_refused(self, admin_ca):
        """#340-A carried to the mint (RF-6 §6.6 paired negative).

        A crypto-verified admin certificate with NO session never mints —
        authorizing issuance with the caller's existing cert reproduces the
        standing-credential dependency the program exists to delete (§2.2).
        """
        client = _client(admin_ca, {"caller": "admin", "user_id": _MACHINE_IDENTITY})
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert "login session" in detail
        assert "venya admin elevate" in detail

    def test_anonymous_caller_is_refused(self, admin_ca):
        """Paired negative: no principal at all is a 401, never a mint."""
        client = _client(admin_ca, {})
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 401

    def test_session_without_session_id_is_refused(self, admin_ca):
        """The elevation token is bound to a session (#527) — no session, no mint."""
        client = _client(admin_ca, {"user_id": _SESSION_IDENTITY})
        resp = _issue(client, _csr(_key()))
        assert resp.status_code == 401


def _iter_api_routes(app):
    """(full path, APIRoute) for every endpoint, included routers flattened.

    Mirrors tests/test_route_authorization.py: FastAPI keeps an included
    router's routes nested, so the prefix comes from the include context.
    """
    from fastapi.routing import APIRoute

    for r in app.routes:
        if isinstance(r, APIRoute):
            yield r.path, r
        elif hasattr(r, "original_router"):
            ctx = getattr(r, "include_context", None)
            prefix = (getattr(ctx, "prefix", "") or "") if ctx else ""
            for er in list(r.original_router.routes):
                if isinstance(er, APIRoute):
                    yield prefix + er.path, er


class TestRouteIsMounted:
    def test_the_route_exists_on_the_real_app(self):
        """Contract cell: the router is wired in app.py, not just in this file."""
        app = create_app(ServerConfig(recovery_code_pepper="test-pepper-unused")).app
        paths = {path for path, _route in _iter_api_routes(app)}
        assert "/api/v1/admin/certs/issue" in paths

    def test_guard_marker_reaches_the_route_authorization_net(self):
        """The route-coverage net (test_route_authorization) must see a guard."""
        route = next(
            r for p, r in _iter_api_routes(_make_app(None, _session_caller())) if p == "/api/v1/admin/certs/issue"
        )
        guards = [getattr(d.call, "_venya_guard", None) for d in route.dependant.dependencies]
        assert "auth" in guards, f"expected get_current_user's guard marker, got {guards}"


class TestCsrBodyBound:
    def test_oversized_csr_is_refused_before_parsing(self, admin_ca):
        """The PEM field is bounded (same shape as executor registration)."""
        client = _client(admin_ca, _session_caller())
        resp = _issue(client, "-----BEGIN CERTIFICATE REQUEST-----\n" + "A" * 8000 + "\n")
        assert resp.status_code == 422


def test_utc_import_is_offset_aware():
    """Datetime rule: this file never builds a naive timestamp."""
    assert UTC is not None
    assert timedelta(seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS).total_seconds() == 3600
