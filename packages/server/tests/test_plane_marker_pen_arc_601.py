# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#601 — the plane marker lives on Tabith LLC's registered PEN arc, and nowhere else.

This file used to pin a DUAL-ARC READ: the registered arc, plus a bounded
transition window that also resolved an older arc belonging to a different
enterprise, so alpha-era leaves kept working. That window is CLOSED. The owner
ruled (2026-10-16, relayed via the dispatch seat, recorded on #601) that nothing
alpha-era is supported — no backwards compatibility with alpha — so there is no
old-arc credential to protect and the read branch came out with it. What this
file now pins is the paired negative the shipped source always demanded at the
moment of removal: **a marker on any arc other than ours is NOT read as ours.**

**The retired number is not in this tree, and does not need to be.** Its digits
and its holder's name live on #601. The cells below use `_FOREIGN_ARC`, a
PEN-shaped ObjectIdentifier that is not ours, because `parse_plane_marker`
consults exactly one OID (`VENYA_PLANE_MARKER_OID`): every other arc is the same
case, so pinning "not ours" pins the retired arc too — and the structural cell
`test_the_module_declares_one_plane_marker_arc` is what stops the legacy
constant coming back by another name.

Truth table (row AC4, re-shaped for the closed window):
* mint cells — exactly one marker, at the registered arc
  (1.3.6.1.4.1.67159.1.1 — PEN 67159 = Tabith LLC, re-read from the RAW IANA
  registry file at the #601 landing: the registry is BLOCK format, so the
  citation is the block at lines 268652-268653, "67159" then "Tabith LLC"),
  `critical=False` unchanged, and no other enterprise-number arc present on
  anything we write;
* read cells — the registered arc parses on both planes; the fail-closed halves
  (unparseable DER / length mismatch / out-of-set / no marker) still raise
  ValueError on that arc;
* **inverted window cells — plane-shaped bytes on a foreign arc REFUSE**, in
  every value shape, and they refuse with the missing-marker text: the parser
  never looks there, which is the whole point of closing the window;
* the combined shape (our marker plus a foreign one) resolves from OURS — the
  named behavior that replaced the old both-arcs refusal, which became
  structurally unreachable when only one arc is read (see the report; a
  certificate cannot carry two extensions with the same OID);
* fail-closed at the app boundary — a chain-valid leaf whose only marker is on
  a foreign arc now gets the 403 that names the re-issue (this cell WAS the
  window's promise of 200, and it is inverted, not deleted), a markerless
  admin-CA leaf still refuses 403, and a foreign-CA forgery is still stopped by
  the CHAIN leg before the marker leg ever runs;
* wording law kept: nothing here claims a foreign cert is "accepted as admin" —
  the accept path is proven closed by naming which 403 text fired (auth.py's
  chain leg runs before the marker read).
"""

import ast
import inspect
import textwrap
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
from server import ca as ca_module
from server.ca import (
    ADMIN_SHORT_CERT_LIFETIME_SECONDS,
    PLANE_HUMAN,
    PLANE_MACHINE,
    VENYA_PLANE_MARKER_OID,
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

# Our own registration, spelled out here (and only in prose — every assertion
# reads VENYA_PLANE_MARKER_OID) so a reader can check the arc the product is on
# without leaving the file: 1.3.6.1.4.1.67159.1.1, PEN 67159, Tabith LLC.
_REGISTERED_ARC_TEXT = "1.3.6.1.4.1.67159.1.1"

_ADMIN_IDENTITY = "admin@example.com"  # the machine-plane slot
_HUMAN_ID = "alice-id"
_PASSPHRASE = b"test_passphrase"

# DER UTF8String bodies for plane-shaped value bytes (the 0x0C idiom).
_MACHINE_BYTES = b"\x0c\x07machine"
_HUMAN_BYTES = b"\x0c\x05human"

# An enterprise-number arc that is NOT ours. The retired legacy arc's digits are
# on #601 and are deliberately not repeated here: the parser reads exactly one
# OID, so "some other arc" is the same case as "the retired arc" — and this
# stand-in keeps the tree free of a foreign registration.
_FOREIGN_ARC = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

# The iso.org.dod.internet.private.enterprise prefix, for the cell that pins
# "no other PEN arc is present on anything we mint".
_PEN_PREFIX = "1.3.6.1.4.1."

# The refusal every not-ours shape must land on: the parser never consults a
# foreign arc, so a foreign marker is indistinguishable from no marker.
_NO_MARKER = "predates the two-plane model"


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


def _pen_arc_extension(cert):
    """Every marker extension on cert whose OID is an enterprise-number arc.

    `dotted_string` is the accessor — `str()` on a cryptography
    ObjectIdentifier renders the whole repr ("<ObjectIdentifier(oid=..., name=
    Unknown OID)>"), which is exactly the kind of thing a prefix test silently
    passes or fails on depending on how it was written.
    """
    return [ext.oid for ext in cert.extensions if ext.oid.dotted_string.startswith(_PEN_PREFIX)]


class TestWriteSiteIsRegisteredArc:
    def test_bootstrap_mint_writes_registered_arc_only(self, admin_ca):
        """Machine plane: one marker, at 67159.1.1, non-critical (#588 A
        preserved), and no other enterprise-number arc on anything we write."""
        cert, _key_pem, _pem = admin_ca.sign_admin_cert(_ADMIN_IDENTITY)
        oids = [e.oid for e in cert.extensions]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1
        assert [o.dotted_string for o in _pen_arc_extension(cert)] == [VENYA_PLANE_MARKER_OID.dotted_string]
        assert _FOREIGN_ARC not in oids
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is False
        assert parse_plane_marker(cert) == PLANE_MACHINE
        assert VENYA_PLANE_MARKER_OID.dotted_string == _REGISTERED_ARC_TEXT  # 67159.1.1 is the arc, ours

    def test_csr_signer_writes_registered_arc_only(self, admin_ca):
        """Human plane: same contract on the other mint path."""
        key = ec.generate_private_key(SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        cert = admin_ca.sign_admin_csr(csr, _HUMAN_ID, ADMIN_SHORT_CERT_LIFETIME_SECONDS)
        oids = [e.oid for e in cert.extensions]
        assert oids.count(VENYA_PLANE_MARKER_OID) == 1
        assert [o.dotted_string for o in _pen_arc_extension(cert)] == [VENYA_PLANE_MARKER_OID.dotted_string]
        assert _FOREIGN_ARC not in oids
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
        assert ext.critical is False
        assert parse_plane_marker(cert) == PLANE_HUMAN

    def test_the_module_declares_one_plane_marker_arc(self):
        """Structural pin for the closed window: `server.ca` exposes exactly ONE
        plane-marker ObjectIdentifier constant, the registered one. A legacy
        constant returning under its old name, or a new second one, reddens this
        cell — which is the check the digit-grep cannot be, because the retired
        digits are not in this tree at all."""
        marker_consts = {
            name
            for name, value in vars(ca_module).items()
            if name.startswith("VENYA_PLANE_MARKER") and isinstance(value, x509.ObjectIdentifier)
        }
        assert marker_consts == {"VENYA_PLANE_MARKER_OID"}, marker_consts


class TestRegisteredArcRead:
    """The one readable arc: positive on both planes, and every shipped
    fail-closed half still raising ValueError."""

    @pytest.mark.parametrize(
        ("body", "expected"),
        [(_MACHINE_BYTES, PLANE_MACHINE), (_HUMAN_BYTES, PLANE_HUMAN)],
        ids=["machine", "human"],
    )
    def test_registered_arc_parses_on_both_planes(self, body, expected):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, body)])
        assert parse_plane_marker(cert) == expected

    def test_critical_bit_is_still_read_anyway(self):
        """#588 option A survives the window's closure: criticality-blind on the
        arc we do read."""
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, _MACHINE_BYTES, critical=True)])
        assert parse_plane_marker(cert) == PLANE_MACHINE

    def test_unparseable_der_raises(self):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, b"\x0a\x01b")], sn=9)
        with pytest.raises(ValueError, match="unparseable plane marker"):
            parse_plane_marker(cert)

    def test_length_mismatch_raises(self):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, b"\x0c\x09mach")], sn=10)
        with pytest.raises(ValueError, match="length mismatch"):
            parse_plane_marker(cert)

    def test_out_of_set_plane_raises(self):
        cert = _selfsigned([_marker(VENYA_PLANE_MARKER_OID, b"\x0c\x05ghost")], sn=11)
        with pytest.raises(ValueError, match="outside the accepted set"):
            parse_plane_marker(cert)

    def test_no_marker_raises_reissue_text(self):
        cert = _selfsigned()
        with pytest.raises(ValueError, match=_NO_MARKER):
            parse_plane_marker(cert)


class TestAnyOtherArcIsNoLongerRead:
    """THE INVERSION, and the reason this leg was allowed to land at all.

    Before #601's closure a marker on the retired arc resolved to a plane —
    that WAS the transition window. Now the parser consults one OID and nothing
    else, so a foreign-arc marker collapses into the same refusal as a
    certificate with no marker at all, whatever bytes it carries. Parametrized
    across the value shapes so the closure cannot hold only for the tidy case:
    plane-shaped, contradictory, unparseable, length-mismatched, out-of-set and
    CRITICAL-marked all refuse the same way.
    """

    @pytest.mark.parametrize(
        ("body", "critical", "case"),
        [
            (_MACHINE_BYTES, False, "plane-machine"),
            (_HUMAN_BYTES, False, "plane-human"),
            (b"\x0a\x01b", False, "unparseable-der"),
            (b"\x0c\x09mach", False, "length-mismatch"),
            (b"\x0c\x05ghost", False, "out-of-set"),
            (_MACHINE_BYTES, True, "critical-bit-set"),
        ],
        ids=["plane-machine", "plane-human", "unparseable-der", "length-mismatch", "out-of-set", "critical-set"],
    )
    def test_foreign_arc_marker_refuses_as_no_marker(self, body, critical, case):
        cert = _selfsigned([_marker(_FOREIGN_ARC, body, critical=critical)], sn=12)
        with pytest.raises(ValueError, match=_NO_MARKER) as excinfo:
            parse_plane_marker(cert)
        # Named so the shape cannot drift into a different refusal by accident:
        # the parser never looked at this arc, so this is the missing-marker path.
        assert "no Venya plane marker" in str(excinfo.value), case

    def test_our_marker_beside_a_foreign_one_resolves_from_ours(self):
        """The behavior that replaced the old both-arcs refusal, named so it is
        not an accident of lookup order.

        The duplicate refusal became structurally unreachable when only one arc
        is read (a DER extension set cannot carry the same OID twice), so the
        ruling was to remove it and keep the missing-marker refusal as the only
        no-ours path. What a foreign marker beside ours now means: ours is read,
        the foreign bytes are inert — which is how every other unrecognized
        extension already behaves.
        """
        cert = _selfsigned(
            [_marker(VENYA_PLANE_MARKER_OID, _MACHINE_BYTES), _marker(_FOREIGN_ARC, _HUMAN_BYTES)],
            sn=8,
        )
        assert parse_plane_marker(cert) == PLANE_MACHINE

    def test_the_parser_source_names_one_arc_only(self):
        """Source-level pin, because the digit-grep cannot be the check.

        The retired arc's digits are deliberately absent from this tree, so a
        cell that only tests a stand-in arc would not catch a second arc coming
        back hardcoded with the REAL retired number. This does, over the
        function's EXECUTABLE shape (via `ast`, comments and the docstring
        excluded — prose is allowed to name the arc, code is not): the parser
        must reference exactly one marker constant (`VENYA_PLANE_MARKER_OID`) and
        must carry no literal enterprise-number arc in any string constant, so
        the value has to come from the module constant, which the structural cell
        above pins to one. The two-element read tuple this row removed — our arc
        plus a second one — reddens it in both halves.
        """
        fn = ast.parse(textwrap.dedent(inspect.getsource(parse_plane_marker))).body[0]
        docstring = ast.get_docstring(fn, clean=False)
        named = {
            node.id for node in ast.walk(fn) if isinstance(node, ast.Name) and node.id.startswith("VENYA_PLANE_MARKER")
        }
        assert named == {"VENYA_PLANE_MARKER_OID"}, named
        literal_arcs = [
            node.value
            for node in ast.walk(fn)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value != docstring
            and "1.3.6.1.4.1." in node.value
        ]
        assert literal_arcs == [], literal_arcs

    def test_parser_alone_refuses_foreign_plane_bytes(self):
        """The inverted first half of the old AC4(a): parse_plane_marker has no
        provenance check and never needed one, but it now also has no path to a
        foreign arc — a forged cert carrying plane-shaped bytes at an arc that is
        not ours resolves to NOTHING, so the window's parser-level exposure
        closed with the branch. Wording law still observed: this cell is about
        the parser, and the next class is what the product actually does."""
        forged = _selfsigned([_marker(_FOREIGN_ARC, _MACHINE_BYTES)], sn=42)
        with pytest.raises(ValueError, match=_NO_MARKER):
            parse_plane_marker(forged)


class TestForeignLeafNeverAccepted:
    """The app-boundary halves. The chain leg still runs before the marker read
    (auth.py:403 before :438), so a foreign-CA forgery is stopped there whatever
    the marker says — and with the window closed, a chain-VALID leaf whose only
    marker is on a foreign arc is stopped at the marker leg instead."""

    def test_middleware_refuses_the_forged_leaf_at_the_chain_leg(self, admin_ca, session, tmp_path):
        """Unchanged by this leg: a cert NOT of our chain, carrying plane-shaped
        bytes at a foreign arc, is refused 403 by the CHAIN check, and the
        refusal text names the client certificate — not the plane re-issue —
        which is how this cell proves WHICH leg closed the path.

        The forged leaf carries an allowlist-shaped identity so the only thing
        that can stop it is the chain leg.
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
            .add_extension(x509.UnrecognizedExtension(_FOREIGN_ARC, _MACHINE_BYTES), critical=False)
            .sign(key, hashes.SHA256())
        )
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(forged))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail == "Admin access requires valid client certificate"
        assert "two-plane" not in detail  # refused at the chain leg, not the marker leg

    def test_pre_change_shape_leaf_now_refuses_naming_the_reissue(self, admin_ca, session, tmp_path):
        """THE inversion at the app boundary.

        This cell used to assert 200: a leaf minted before #601 — marker on the
        retired arc, CRITICAL bit set, the exact pre-#588/pre-#601 wire shape —
        was admitted while the window stayed open. The window is closed, so the
        same wire material is now refused, and refused by the marker leg naming
        the re-issue. Inverted, not deleted, not skipped: the shape is still
        built by hand from the real CA key because the product no longer writes
        it, which is exactly why the pin has to be here.
        """
        leaf = _admin_ca_signed_foreign_arc_leaf(admin_ca, _ADMIN_IDENTITY, critical=True)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert "predates the two-plane model" in detail, detail

    def test_markerless_admin_ca_cert_still_refuses_naming_reissue(self, admin_ca, session, tmp_path):
        """AC4(c): the shipped refusal cannot regress into fail-open while the
        forged case is under test — a chain-valid admin-CA cert with NO marker
        still gets the 403 that names the re-issue."""
        leaf = _admin_ca_signed_foreign_arc_leaf(admin_ca, _ADMIN_IDENTITY, critical=True, marker=None)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 403
        assert "predates the two-plane model" in resp.json()["detail"]

    def test_admin_ca_leaf_with_our_marker_and_a_foreign_one_is_admitted(self, admin_ca, session, tmp_path):
        """The combined shape at the app boundary, pinned rather than assumed:
        ours is read, the foreign bytes are inert, and the cert is admitted —
        the named successor to the old both-arcs 403 (see
        ``test_our_marker_beside_a_foreign_one_resolves_from_ours``)."""
        leaf = _admin_ca_signed_foreign_arc_leaf(admin_ca, _ADMIN_IDENTITY, critical=True, also_ours=True)
        app = _make_admin_app(admin_ca, session, known_ids=[_ADMIN_IDENTITY], tmp_path=tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/admin/probe", headers=_cert_headers(leaf))
        assert resp.status_code == 200


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


def _admin_ca_signed_foreign_arc_leaf(admin_ca, cn, *, critical, marker=_MACHINE_BYTES, also_ours=False):
    """A chain-valid leaf built BY HAND in a retired or anomalous wire shape —
    the product's own mint no longer writes these, which is exactly why the
    cells need hand material signed with the real CA key.

    ``marker=None`` writes no marker at all; ``also_ours=True`` adds the
    registered arc alongside the foreign one (the combined shape).
    """
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
        builder = builder.add_extension(x509.UnrecognizedExtension(_FOREIGN_ARC, marker), critical=critical)
    if also_ours:
        builder = builder.add_extension(_plane_marker_extension("machine"), critical=False)
    return builder.sign(ca_key, hashes.SHA256())
