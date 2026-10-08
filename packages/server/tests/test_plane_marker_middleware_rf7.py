# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 2 CP-C — plane-marker consumption, per-use role check, first human.

Three controls, all in `middleware/auth.py` + `dependencies.py`, none of them
reachable from the signer tests (chunk 1 shipped the marker and its parser;
the parser's docstring said the consumption was here):

1. **Plane-marker consumption (§3.2).** `_validate_admin_mtls` reads the CA's
   marker BEFORE the static allowlist, because the plane is what decides which
   policy applies. A certificate with no marker — a pre-two-plane cert — is
   refused 403 with the re-issue requirement named. Nothing defaults into a
   plane.
2. **Per-use role check (§3.3).** `require_admin`'s `caller == "admin"`
   short-circuit dies on the HUMAN plane: a person-shaped cert runs the same DB
   role lookup a session caller runs. The MACHINE plane keeps its slot-shaped
   behavior byte-for-byte (ruling 1: machines have no person) — which is why
   every pre-existing machine-plane cell in test_admin_mtls.py, test_recovery.py
   and test_forwarded_cert_rotation_498.py still passes with its assertions
   UNTOUCHED. Only the doubles gained the marker the product's own mint writes.
3. **First-human reachability (§6.5, finding F-3).** The mint path is in
   `BOOTSTRAP_PATHS` (cert OPTIONAL) and `SESSION_REQUIRED_ADMIN_PATHS` (the
   presented session is the second credential) — two existing treatments
   composed, not a third invented. A session-only caller with no certificate
   reaches the handler; a cert-only caller with no session never mints (#340-A).

Truth-table law (RF-6 §3.8): every row is a rejection that is PROVEN, with the
accepted half beside it.
"""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import count
from pathlib import Path

import pytest
from core.iam.models import Base, ElevationToken, Role, RoleMember, User
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI
from server.ca import (
    ADMIN_SHORT_CERT_LIFETIME_SECONDS,
    PLANE_HUMAN,
    PLANE_MACHINE,
    AdminCAManager,
    parse_plane_marker,
)
from server.config import AdminMTLSConfig, InnerTLSConfig, ServerConfig
from server.middleware.auth import SessionMiddleware
from server.routes import admin_certs as admin_certs_routes
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

_ADMIN_IDENTITY = "admin@example.com"  # the machine-plane slot
_HUMAN_IDENTITY = "alice@example.com"  # a person's user_id, NOT a slot
_HUMAN_ID = "alice-id"
_elev_seq = count(1)


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_passphrase")


@pytest.fixture
def admin_ca(tmp_path: Path) -> AdminCAManager:
    # The manager's own default passphrase env is what _passphrase_env sets
    # above, so no CASecurityConfig override is needed here (same shape as the
    # CP-A contract file).
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite (house pattern,
    tests/test_recovery.py:735). SQLite has no timestamptz, so
    ``SessionManager.check_expiry``'s aware-now comparison TypeErrors on
    round-tripped rows; production PostgreSQL returns aware values and the
    listener is a no-op there.
    """
    from core.iam.models import Session as SessionModel
    from sqlalchemy import event

    if getattr(SessionModel, "_rf7c2_utc_loader", False):
        return
    SessionModel._rf7c2_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


@pytest.fixture
def session():
    _sqlite_utc_loader()
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(User(user_id=_HUMAN_ID, status="active"))
    s.commit()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _admin_ca_paths(admin_ca: AdminCAManager, tmp_path: Path) -> str:
    """The middleware's anchors are the admin CA cert(s) at this path."""
    return str(admin_ca.ca_cert_path)


def _make_admin_app(admin_ca, session, *, known_ids, tmp_path):
    """The REAL SessionMiddleware with admin-mTLS ENABLED, over a real session.

    Mounts a plain admin probe guarded by the real `require_admin` (so §3.3's
    per-use check is under test, not a stand-in) AND the real mint router, so
    the same certificate can be replayed against both paths and the
    plane/allowlist difference is observable.
    """
    from server.dependencies import get_db, require_admin

    app = FastAPI()
    app.state.config = ServerConfig(
        recovery_code_pepper="p",
        admin_mtls=AdminMTLSConfig(
            enabled=True, ca_cert=_admin_ca_paths(admin_ca, tmp_path), known_admin_ids=known_ids
        ),
        inner_mtls=InnerTLSConfig(enabled=True),
    )

    class _Backend:
        """Minimal backend double: get_session hands out THIS session, so the
        middleware's revocation lookup, require_admin's role lookup and the
        mint's ceremony burn all see one transaction."""

        def get_session(self):
            return session

    app.state.backend = _Backend()
    app.state.admin_ca_manager = admin_ca

    # get_db normally resolves through get_backend; the session is shared, so
    # override it to the same object rather than opening a second connection.
    app.dependency_overrides[get_db] = lambda: session

    app.add_middleware(SessionMiddleware)

    # Route-level dependency (not a default-argument call) so the guard runs the
    # same way a real admin route runs it.
    @app.get("/api/v1/admin/probe", dependencies=[Depends(require_admin)])
    def _admin_probe():
        return {"status": "ok"}

    app.include_router(admin_certs_routes.router, prefix="/api/v1")
    return app


def _cert_headers(cert: x509.Certificate) -> dict:
    import urllib.parse

    return {"x-client-cert-pem": urllib.parse.quote_from_bytes(cert.public_bytes(serialization.Encoding.PEM))}


def _machine_cert(admin_ca: AdminCAManager) -> x509.Certificate:
    """A machine-plane admin cert, minted by the product's own bootstrap path."""
    cert, _key_pem, _pem = admin_ca.sign_admin_cert(_ADMIN_IDENTITY)
    return cert


def _human_cert(admin_ca: AdminCAManager, identity: str = _HUMAN_ID) -> x509.Certificate:
    """A human-plane cert, minted by the product's own CSR signer."""
    key = ec.generate_private_key(SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    return admin_ca.sign_admin_csr(csr, identity, ADMIN_SHORT_CERT_LIFETIME_SECONDS)


def _ca_pair(admin_ca: AdminCAManager):
    ca_cert = x509.load_pem_x509_certificate(admin_ca.ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(admin_ca.ca_key_path.read_bytes(), password=b"test_passphrase")
    return ca_cert, ca_key


def _handbuilt_admin_cert(admin_ca: AdminCAManager, cn: str, *, plane: str | None) -> x509.Certificate:
    """An admin-CA leaf built by hand, with or without the plane marker.

    `plane=None` is the pre-two-plane shape; a named plane for an identity that
    is NOT the session's is the forgery shape the paired negatives need.
    """
    from server.ca import _plane_marker_extension

    ca_cert, ca_key = _ca_pair(admin_ca)
    key = ec.generate_private_key(SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(key.public_key().public_numbers().x.to_bytes(32, "big")[:8], "big"))
        .not_valid_before(datetime.now(UTC) - timedelta(hours=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(cn)]), critical=False)
    )
    if plane is not None:
        builder = builder.add_extension(_plane_marker_extension(plane), critical=True)
    return builder.sign(ca_key, hashes.SHA256())


class TestPlaneMarkerConsumption:
    """§3.2: the middleware reads the marker and fails closed. No defaults."""

    def test_machine_plane_cert_admitted_on_admin_route(self, admin_ca, session, tmp_path):
        """Positive half — and the machine-plane no-regression proof: same slot
        check, same 200, exactly as before this change landed."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(_machine_cert(admin_ca)))
        assert resp.status_code == 200, resp.text

    def test_markerless_cert_refused_naming_the_reissue(self, admin_ca, session, tmp_path):
        """§3.8 row 5: a pre-two-plane cert is refused LOUDLY on the admin path,
        with the re-issue requirement in the text (RF-8 prints it verbatim)."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        cert = _handbuilt_admin_cert(admin_ca, _ADMIN_IDENTITY, plane=None)
        with pytest.raises(ValueError):
            parse_plane_marker(cert)  # the parser the middleware now consults
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(cert))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert "predates the two-plane model" in detail
        assert "re-issued" in detail

    def test_human_plane_cert_skips_the_allowlist_slot(self, admin_ca, session, admin_role, tmp_path):
        """§3.2: the person's user_id is NOT and must not be a config slot.

        Positive half: with the role granted, a human cert passes the admin path
        even though known_admin_ids names only the machine identity.
        """
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(_human_cert(admin_ca)))
        assert resp.status_code == 200, resp.text

    def test_human_plane_cert_still_refused_by_slot_check_if_it_were_machine(self, admin_ca, session, tmp_path):
        """Paired negative: a MACHINE-plane cert naming a non-slot identity is
        still refused by known_admin_ids — the slot check did not loosen."""
        forged_machine = _handbuilt_admin_cert(admin_ca, "stranger@example.com", plane=PLANE_MACHINE)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(forged_machine))
        assert resp.status_code == 403


class TestPerUseRoleCheck:
    """§3.3 / ruling 2: revocation is behavioral on the human plane."""

    def test_role_removed_after_mint_refuses_the_next_request(self, admin_ca, session, admin_role, tmp_path):
        """§3.8 row 1 — ruling 2's whole point, measured: the cert is still
        inside its validity window, and the NEXT request is refused."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        cert = _human_cert(admin_ca)
        assert client.get("/api/v1/admin/probe", headers=_cert_headers(cert)).status_code == 200

        # Drop the membership. Nothing touches the certificate.
        session.query(RoleMember).delete()
        session.commit()

        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(cert))
        assert resp.status_code == 403
        assert "Admin permission required" in resp.json()["detail"]
        assert parse_plane_marker(cert) == PLANE_HUMAN, "the cert itself never changed"

    def test_machine_plane_still_bypasses_the_role_table(self, admin_ca, session, tmp_path):
        """Ruling 1's corollary, kept: the loopback cert needs no role row and
        no user row, and there is no DB dependency added to that hop."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        # No Role, no RoleMember, and no User row for the machine identity.
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(_machine_cert(admin_ca)))
        assert resp.status_code == 200, resp.text

    def test_human_cert_for_a_deleted_user_refuses_403_not_500(self, admin_ca, session, admin_role, tmp_path):
        """§3.8 row 7: lookup miss is a clean 403."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        cert = _human_cert(admin_ca)
        assert client.get("/api/v1/admin/probe", headers=_cert_headers(cert)).status_code == 200
        session.query(RoleMember).delete()
        session.query(User).delete()
        session.commit()
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(cert))
        assert resp.status_code == 403
        assert resp.status_code != 500


@pytest.fixture
def admin_role(session):
    role = Role(name="admin", permissions="read-write")
    session.add(role)
    session.commit()
    session.add(RoleMember(user_id=_HUMAN_ID, role_id=role.id))
    session.commit()
    return role


class TestFirstHumanReachability:
    """§6.5 finding F-3: the mint must be reachable with NO admin certificate."""

    def _bearer(self, session, *, identity: str = _HUMAN_ID) -> str:
        """Create a real session row and return its access token."""
        from core.iam.models import Session as SessionModel

        token = f"tok-{next(_elev_seq)}"
        now = datetime.now(UTC)
        row = SessionModel(
            user_id=identity,
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            access_token=token,
            access_token_jti="jti-" + token,
            access_token_expires_at=now + timedelta(minutes=15),
        )
        session.add(row)
        session.commit()
        return token

    def _elevation(self, session, *, identity: str = _HUMAN_ID) -> str:
        token = f"elev-{next(_elev_seq)}"
        session.add(
            ElevationToken(
                token_hash=sha256(token.encode()).hexdigest(),
                user_id=identity,
                session_id=None,
                expires_at=datetime.now(UTC) + timedelta(seconds=60),
                used=False,
            )
        )
        session.commit()
        return token

    def _csr_pem(self) -> str:
        key = ec.generate_private_key(SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def test_session_only_caller_with_no_certificate_mints(self, admin_ca, session, admin_role, tmp_path):
        """THE first-human cell (§6.6 "New: first-human reachability"): bearer
        session, no client certificate at all, admin_mtls ENABLED — and the mint
        answers 201 with a human-plane cert."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        bearer = self._bearer(session)
        elev = self._elevation(session)
        resp = client.post(
            "/api/v1/admin/certs/issue",
            json={"csr_pem": self._csr_pem()},
            headers={"Authorization": f"Bearer {bearer}", "X-Elevation-Token": elev},
        )
        assert resp.status_code == 201, resp.text
        issued = x509.load_pem_x509_certificate(resp.json()["certificate_pem"].encode())
        assert parse_plane_marker(issued) == PLANE_HUMAN
        # Identity is server-derived: the session's user_id, not the (empty) CSR subject.
        cn = [a.value for a in issued.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        assert cn == [_HUMAN_ID]
        assert "PRIVATE KEY" not in resp.text

    def test_cert_only_caller_with_no_session_refused(self, admin_ca, session, admin_role, tmp_path):
        """Paired negative, §6.6 + #340-A: a valid admin CERTIFICATE and no
        session never mints — the credential the endpoint produces is not the
        credential it accepts (§2.2)."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        cert = _machine_cert(admin_ca)
        resp = client.post(
            "/api/v1/admin/certs/issue",
            json={"csr_pem": self._csr_pem()},
            headers={**_cert_headers(cert), "X-Elevation-Token": self._elevation(session)},
        )
        assert resp.status_code == 403, resp.text
        assert "login session" in resp.json()["detail"]

    def test_anonymous_caller_refused(self, admin_ca, session, admin_role, tmp_path):
        """Neither credential at all → 401, and no cert is minted."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/admin/certs/issue", json={"csr_pem": self._csr_pem()})
        assert resp.status_code == 401
        from core.iam.models import AuditEvent

        assert list(session.scalars(select(AuditEvent).where(AuditEvent.event_type == "admin_cert_issued"))) == []

    def test_bad_session_on_the_mint_path_is_401_not_a_pass(self, admin_ca, session, admin_role, tmp_path):
        """Bootstrap means a certificate is OPTIONAL, not that the session is:
        a PRESENTED but invalid session dies at the middleware."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/admin/certs/issue",
            json={"csr_pem": self._csr_pem()},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    def test_cert_plus_session_mints_as_the_session_person(self, admin_ca, session, admin_role, tmp_path):
        """The #340-A composition, stated: when a caller offers BOTH (a renewal
        shape), the session wins and the mint names the person."""
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        bearer = self._bearer(session)
        resp = client.post(
            "/api/v1/admin/certs/issue",
            json={"csr_pem": self._csr_pem()},
            headers={
                **_cert_headers(_machine_cert(admin_ca)),
                "Authorization": f"Bearer {bearer}",
                "X-Elevation-Token": self._elevation(session),
            },
        )
        assert resp.status_code == 201, resp.text
        issued = x509.load_pem_x509_certificate(resp.json()["certificate_pem"].encode())
        cn = [a.value for a in issued.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        assert cn == [_HUMAN_ID], "the certificate must name the session's person, never the offered cert"


class TestBootstrapMembershipIsDeliberate:
    """The §6.5 mechanism choice, pinned as SET MEMBERSHIP so a rename trips a
    named cell instead of a silent 403 in production."""

    def test_mint_path_is_in_both_existing_sets(self):
        assert "/api/v1/admin/certs/issue" in SessionMiddleware.BOOTSTRAP_PATHS
        assert "/api/v1/admin/certs/issue" in SessionMiddleware.SESSION_REQUIRED_ADMIN_PATHS

    def test_init_reset_bootstrap_behavior_is_untouched(self):
        """Regression half: the #450 path did not move when the mint joined."""
        assert "/api/v1/init/reset" in SessionMiddleware.BOOTSTRAP_PATHS
        assert "/api/v1/init/reset" not in SessionMiddleware.SESSION_REQUIRED_ADMIN_PATHS

    def test_recovery_reissue_treatment_is_untouched(self):
        assert "/api/v1/admin/recovery-code/reissue" in SessionMiddleware.SESSION_REQUIRED_ADMIN_PATHS
        assert "/api/v1/admin/recovery-code/reissue" not in SessionMiddleware.BOOTSTRAP_PATHS
