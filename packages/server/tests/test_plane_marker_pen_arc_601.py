# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#601 — the plane marker moves onto Tabith LLC's registered PEN arc.

Dual-arc read, single-arc write (owner-ruled HOW, verbatim: "BEFORE BETA.
It rides."). WRITE: 1.3.6.1.4.1.67159.1.1 (PEN 67159 = Tabith LLC, re-read
from the RAW IANA registry file at this landing — line 268652). READ: the
registered arc first, then the legacy 1.3.6.1.4.1.64496.1.1 for a bounded
transition window, so pre-#601 leaves keep resolving (#588's
non-retroactivity precedent). Markers on BOTH arcs at once refuse — the
named behaviour of the window, never an accident of lookup order.

Truth table (row AC4 in full):
* mint cells — exactly one marker, registered arc, critical=False
  unchanged, legacy arc ABSENT from anything this code writes;
* read cells — registered parses, legacy parses (the window is the point),
  both-at-once refuses (same-value AND contradictory-value shapes);
* fail-closed halves preserved on BOTH arcs: missing / unparseable DER /
  out-of-set / wrong extension type still raise ValueError;
* AC4(a) — a foreign cert carrying plane-shaped bytes at the legacy OID:
  the parser alone DOES resolve it (recorded, by design of the window);
  the middleware refuses it at the chain leg BEFORE the marker read
  (auth.py:403 runs before :438). Wording law observed: such a cert "would
  be parsed as our plane marker" at parser level — it is NOT claimed or
  tested as "accepted as admin", and this file proves the accept path is
  closed by the chain check, naming which 403 text fired;
* AC4(b)-in-window — a pre-change leaf (legacy arc, CRITICAL bit set, the
  exact shape old mints wrote), signed by the real admin CA, still reaches
  200 through the real middleware;
* AC4(c) — the shipped refusals cannot regress into fail-open while the
  forged case is under test: a markerless admin-CA cert still refuses 403
  naming the re-issue.

The window's exit condition is stated on the row and at the constants
(machine plane and human plane enumerated separately; removal leg carries
its own paired negative). No removal code here.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from core.iam.models import Base, User
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
    VENYA_PLANE_MARKER_OID,
    VENYA_PLANE_MARKER_OID_LEGACY,
    AdminCAManager,
    _plane_marker_extension,
    parse_plane_marker,
)
from server.config import AdminMTLSConfig, InnerTLSConfig, ServerConfig
from server.dependencies import get_db, require_admin
from server.middleware.auth import SessionMiddleware
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

_ADMIN_IDENTITY = "admin@example.com"  # the machine-plane slot
_HUMAN_ID = "alice-id"
_PASSPHRASE = b"test_passphrase"

# DER UTF8String bodies for plane-shaped value bytes (the 0x0C idiom).
_MACHINE_BYTES = b"\x0c\x07machine"
_HUMAN_BYTES = b"\x0c\x05human"


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", _PASSPHRASE.decode())
    for var in ("VENYA_ADMIN_CERT", "VENYA_ADMIN_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def admin_ca(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _selfsigned(extra_extensions=(), sn=7):
    """Parser substrate: a self-signed leaf with arbitrary marker extensions.

    Each entry is (oid, value_bytes, critical). Never written by a product
    mint — this is hand-shaped wire material for the read cells.
    """
    key = ec.generate_private_key(SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pen-arc-substrate")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(sn)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    for oid, value, critical in extra_extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=critical)
    return builder.sign(key, hashes.SHA256())


def _marker(oid, value_bytes=_MACHINE_BYTES, critical=False):
    return (oid, value_bytes, critical)


class TestWriteSiteIsRegisteredArc:
    def test_bootstrap_mint_writes_registered_arc_only(self, admin_ca):
        """Machine plane: one marker, at 67159.1.1, non-critical (#588 A
        preserved), and the legacy arc is ABSENT from anything we write."""
        cert, _key_pem, _pem = admin_ca.sign_admin_cert(_ADMIN_IDENTITY)
        oids = [e.oid for e in cert.extensions]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1
        assert VENYA_PLANE_MARKER_OID_LEGACY not in oids
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is False
        assert parse_plane_marker(cert) == PLANE_MACHINE

    def test_csr_signer_writes_registered_arc_only(self, admin_ca):
        """Human plane: same contract on the other mint path."""
        key = ec.generate_private_key(SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        cert = admin_ca.sign_admin_csr(csr, _HUMAN_ID, ADMIN_SHORT_CERT_LIFETIME_SECONDS)
        oids = [e.oid for e in cert.extensions]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1
        assert VENYA_PLANE_MARKER_OID_LEGACY not in oids
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is False
        assert parse_plane_marker(cert) == PLANE_HUMAN


class TestDualArcReadWindow:
    def test_registered_arc_parses(self):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, _HUMAN_BYTES)])
        assert parse_plane_marker(cert) == PLANE_HUMAN

    def test_legacy_arc_parses_the_window_is_the_point(self):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID_LEGACY, _MACHINE_BYTES)])
        assert parse_plane_marker(cert) == PLANE_MACHINE

    @pytest.mark.parametrize(
        "second_value",
        [_MACHINE_BYTES, _HUMAN_BYTES],
        ids=["same-plane-both-arcs", "contradictory-planes"],
    )
    def test_both_arcs_at_once_refuses_named_not_accidental(self, second_value):
        """The window never silently prefers one arc: two markers refuse,
        whether they agree (lookup-order accident bait) or contradict."""
        cert = _selfsigned(
            [_marker(VENYA_PLANE_MARKER_OID, _MACHINE_BYTES), _marker(VENYA_PLANE_MARKER_OID_LEGACY, second_value)],
            sn=8,
        )
        with pytest.raises(ValueError, match="BOTH the registered and legacy arcs"):
            parse_plane_marker(cert)

    @pytest.mark.parametrize(
        "arc",
        [VENYA_PLANE_MARKER_OID, VENYA_PLANE_MARKER_OID_LEGACY],
        ids=["registered", "legacy"],
    )
    class TestFailClosedPreservedOnBothArcs:
        """House truth table: the negatives run on BOTH readable arcs."""

        def test_unparseable_der_raises(self, arc):
            cert = _selfsigned([_marker(arc, b"\x0a\x01b")], sn=9)
            with pytest.raises(ValueError, match="unparseable plane marker"):
                parse_plane_marker(cert)

        def test_length_mismatch_raises(self, arc):
            cert = _selfsigned([_marker(arc, b"\x0c\x09mach")], sn=10)
            with pytest.raises(ValueError, match="length mismatch"):
                parse_plane_marker(cert)

        def test_out_of_set_plane_raises(self, arc):
            cert = _selfsigned([_marker(arc, b"\x0c\x05ghost")], sn=11)
            with pytest.raises(ValueError, match="outside the accepted set"):
                parse_plane_marker(cert)

        def test_criticality_is_blind_on_either_arc(self, arc):
            """Pre-#601 machine leaves ride the legacy arc WITH the critical
            bit set (the shape old mints wrote, pre-#588-A too) — the parser
            stays criticality-blind on both arcs."""
            cert = _selfsigned([_marker(arc, _MACHINE_BYTES, critical=True)])
            assert parse_plane_marker(cert) == PLANE_MACHINE

    def test_no_marker_on_either_arc_raises_reissue_text(self):
        cert = _selfsigned()
        with pytest.raises(ValueError, match="predates the two-plane model"):
            parse_plane_marker(cert)


class TestAC4aParsedButNeverAccepted:
    """Wording law binding: the claim is 'would be PARSED as our plane
    marker', and this class is the test attached to it — in BOTH directions:
    the parser alone DOES resolve plane-shaped bytes at the legacy OID (the
    window is deliberate), and the middleware still REFUSES such a foreign
    cert at the chain leg before the marker read ever runs. Nobody may
    upgrade this to 'accepted as admin' — the accept path is proven closed
    here, by naming which refusal fires."""

    def test_parser_alone_resolves_foreign_legacy_bytes(self):
        """Recorded behavior (AC4(a) first half): a cert NOT of our chain,
        carrying 0x0C-style 'machine' at the legacy OID, parses to a plane.
        parse_plane_marker has no provenance check — matching by OID only is
        the row's mechanism, stated to the limit of what is tested."""
        forged = _selfsigned([_marker(VENYA_PLANE_MARKER_OID_LEGACY, _MACHINE_BYTES)], sn=42)
        assert parse_plane_marker(forged) == PLANE_MACHINE

    def test_middleware_refuses_the_forged_leaf_at_the_chain_leg(self, admin_ca, session, tmp_path):
        """AC4(a) second half: presented through the real middleware, the
        same foreign cert is refused 403 by the chain check (auth.py:403
        runs BEFORE the marker read at :438) — the refusal text is the
        client-certificate one, NOT the plane re-issue one, which is how
        this cell proves WHICH leg closed the path.

        The forged leaf carries an allowlist-shaped identity so the only
        thing that can stop it is the chain leg.
        """
        key = ec.generate_private_key(SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _ADMIN_IDENTITY)])
        now = datetime.now(UTC)
        forged = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(44)
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(_ADMIN_IDENTITY)]), critical=False)
            .add_extension(x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID_LEGACY, _MACHINE_BYTES), critical=False)
            .sign(key, hashes.SHA256())
        )
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(forged))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail == "Admin access requires valid client certificate"
        assert "two-plane" not in detail  # refused at the chain leg, not the marker leg


class TestAC4bPreChangeLeafAdmittedAndAC4cRefusalsHold:
    def test_pre_change_legacy_critical_leaf_still_reaches_200(self, admin_ca, session, tmp_path):
        """The window's promise, at the app boundary: a leaf minted BEFORE
        this change — legacy arc, CRITICAL bit set (the exact pre-#588/pre-
        #601 wire shape), signed by the real admin CA — still resolves its
        plane and gets admitted on the machine path."""
        leaf = _admin_ca_signed_legacy_leaf(admin_ca, _ADMIN_IDENTITY, critical=True)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 200

    def test_markerless_admin_ca_cert_still_refuses_naming_reissue(self, admin_ca, session, tmp_path):
        """AC4(c): the shipped refusal cannot regress into fail-open while
        the forged case is under test — a chain-valid admin-CA cert with NO
        marker still gets the 403 that names the re-issue."""
        leaf = _admin_ca_signed_legacy_leaf(admin_ca, _ADMIN_IDENTITY, critical=True, marker=None)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 403
        assert "predates the two-plane model" in resp.json()["detail"]

    def test_both_arcs_leaf_signed_by_admin_ca_refuses_at_marker_leg(self, admin_ca, session, tmp_path):
        """The both-arcs refusal is not just parser trivia: even a cert of
        OUR chain carrying duplicate markers on both arcs refuses 403, and
        the text is the marker leg's (the chain check passes first) — no
        silent preference anywhere in the product."""
        leaf = _admin_ca_signed_legacy_leaf(admin_ca, _ADMIN_IDENTITY, critical=True, both_arcs=True)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 403
        assert "predates the two-plane model" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# middleware harness — copied shape from tests/test_plane_marker_middleware_rf7.py
# (house pattern: each file stands alone; trimmed to the probe route, the
# mint router is not exercised here).
# ---------------------------------------------------------------------------


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
    s = sessionmaker(bind=engine)()
    s.add(User(user_id=_HUMAN_ID, status="active"))
    s.commit()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _sqlite_utc_loader():
    from core.iam.models import Session as SessionModel

    if getattr(SessionModel, "_pen601_utc_loader", False):
        return
    SessionModel._pen601_utc_loader = True

    @event.listens_for(SessionModel, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _make_admin_app(admin_ca, session, *, known_ids, tmp_path):
    app = FastAPI()
    app.state.config = ServerConfig(
        recovery_code_pepper="p",
        admin_mtls=AdminMTLSConfig(enabled=True, ca_cert=str(admin_ca.ca_cert_path), known_admin_ids=known_ids),
        inner_mtls=InnerTLSConfig(enabled=True),
    )

    class _Backend:
        def get_session(self):
            return session

    app.state.backend = _Backend()
    app.state.admin_ca_manager = admin_ca
    app.dependency_overrides[get_db] = lambda: session
    app.add_middleware(SessionMiddleware)

    @app.get("/api/v1/admin/probe", dependencies=[Depends(require_admin)])
    def _admin_probe():
        return {"status": "ok"}

    return app


def _cert_headers(cert: x509.Certificate) -> dict:
    import urllib.parse

    return {"x-client-cert-pem": urllib.parse.quote_from_bytes(cert.public_bytes(serialization.Encoding.PEM))}


def _ca_pair(admin_ca: AdminCAManager):
    ca_cert = x509.load_pem_x509_certificate(admin_ca.ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(admin_ca.ca_key_path.read_bytes(), password=_PASSPHRASE)
    return ca_cert, ca_key


def _admin_ca_signed_legacy_leaf(admin_ca, cn, *, critical, marker=_MACHINE_BYTES, both_arcs=False):
    """A chain-valid leaf built BY HAND in an old or anomalous wire shape —
    the product's own mint no longer writes these, which is exactly why the
    cells need hand material signed with the real CA key."""
    ca_cert, ca_key = _ca_pair(admin_ca)
    key = ec.generate_private_key(SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(key.public_key().public_numbers().x.to_bytes(32, "big")[:8], "big"))
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(cn)]), critical=False)
    )
    if marker is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID_LEGACY, marker), critical=critical
        )
    if both_arcs:
        builder = builder.add_extension(_plane_marker_extension("machine"), critical=False)
    return builder.sign(ca_key, hashes.SHA256())
