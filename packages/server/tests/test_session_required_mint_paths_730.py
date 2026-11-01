# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#730 AC2 — the session-demanding admin paths refuse a cert-only caller on the LIVE face.

Why this file exists. ``SESSION_REQUIRED_ADMIN_PATHS`` (``middleware/auth.py``, grep the symbol) names
two mint paths: ``/api/v1/admin/recovery-code/reissue`` and ``/api/v1/admin/certs/issue``. Before this
file, no cell of the #730 surface drove either path across the shipped ``SessionMiddleware``: the set
appeared in one RF-7 file's membership assertions and in that file's single mint-path cell, and the
reissue path was never crossed with a certificate at all. #730's criterion (ii) asks for the paired
negative on the door, because criterion (i) — the roles refusal — can be satisfied by a change that
widens a prefix test, and only this half sees a widening that quietly opens a mint.

What is mounted. The shipped ``server.middleware.auth.SessionMiddleware``, ``admin_mtls`` **ENABLED**
(the posture that makes the certificate branch reachable at all), the real ``routes/admin.py`` router
(holding the reissue) and the real ``routes/admin_certs.py`` router (holding the mint), the real
``require_admin`` / ``get_current_user`` dependencies, and a real SQLite ``sessions`` / ``users`` /
``roles`` / ``elevation_tokens`` set. Identities arrive the way production delivers them: a
cryptographically verified admin certificate in the forwarded header, or a bearer token over a real
session row.

LAYER, stated per cell, in the register leg 823's file uses — who refused, and where:

  MIDDLEWARE   ``dispatch`` enters the certificate branch for these paths, crypto-verifies the offered
               certificate, sets ``request.state.admin_cert_verified`` and — because the path is in
               ``SESSION_REQUIRED_ADMIN_PATHS`` — runs any PRESENTED bearer through the same session
               validation. With no bearer presented the certificate's own identity
               (``{"caller": "admin", "user_id": <cert identity>, "plane": …}``) stays attached and the
               request goes on to the handler. The middleware does not refuse here; the refusal below is
               the handler's, and each cell says so.
  HANDLER      ``routes/admin.py::admin_reissue_recovery_code`` reads the caller SHAPE and answers 401
               ``Session authentication required to reissue a recovery code`` for a ``caller == "admin"``
               identity; ``routes/admin_certs.py::_require_human_session`` answers 403 for the same
               shape. These are the shipped second-credential guards (#340-A: cert-alone never mints).
  STATE        every refusal cell additionally reads the row the mint would have written —
               ``users.recovery_code_hash``, the ``admin_cert_issued`` audit row, and the
               ``elevation_tokens.used`` flag — because a refusal that lands nothing is the claim, and a
               guard that burns the caller's ceremony token on the way out is a different bug (#296 Q10).

RED FACE, stated as a command a stranger can copy (#730 AC2's "must fail if the guard is bypassed").
The three cells in ``TestTheRefusalIsTheShippedGuard`` are the witnesses and they run in-suite, so the
control is not a comment: each replaces exactly ONE shipped object and asserts the mint then LANDS or
the refusal moves layer. Beyond that, each single mutation below, applied to a throwaway copy of THIS
file, reddens exactly one cell and nothing else — leg 838 ran all three and logged them:

    cp packages/server/tests/test_session_required_mint_paths_730.py packages/server/tests/zz838.py
    # 1. in the reissue negative cell: _app(admin_ca, session, tmp_path) ->
    #    _app(admin_ca, session, tmp_path, bypass={"identity": {"user_id": _HUMAN_ID, "session_id": 1,
    #    "roles": [], "exp": 0}})          =>  that cell is red, the shipped 401 is not what answers
    # 2. in the mint negative cell, before the request:
    #    admin_certs_routes._require_human_session = lambda ui: ui.get("user_id") or _ADMIN_SLOT
    #    (plus a users row and an elevation token for that slot, which its FK needs)
    #                                       =>  that cell is red on a 201 — the certificate MINTED
    # 3. in the paired-positive reissue cell, before the request:
    #    SessionMiddleware.SESSION_REQUIRED_ADMIN_PATHS = frozenset()
    #                                       =>  that cell is red on a 403 — the widening is seen
    uv run -p 3.14 --directory packages/server pytest tests/zz838.py -q -k <the one cell>
    rm -f packages/server/tests/zz838.py packages/server/tests/__pycache__/zz838*.pyc

Observed at this leg's tip, cell by cell, in ``/tabith/wave44-specs-20261101/838-logs/w1_*.txt``,
``w2_*.txt`` and ``w3_*.txt``.

The one override in the shipped stack is ``get_db``, DB plumbing and not a gate: the test holds a single
session so it can read the rows the handler wrote after the response returns, and ``dependencies.get_db``
would close that session in its ``finally``. No ``dependency_overrides`` of ``require_admin``,
``require_admin_when_initialized`` or ``get_current_user`` appears anywhere in this file's real stack.

Not covered here: anything on a VM, and the owner-present physical cell (#730 AC7, do-not-run by
filing). The RF-7 file ``test_plane_marker_middleware_rf7.py`` already pins the mint's SET MEMBERSHIP and
its first-human reachability; this file does not re-pin membership, it drives the request.
"""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import count
from pathlib import Path

import pytest
from core.iam.models import AuditEvent, Base, ElevationToken, Role, RoleMember, User
from core.iam.models import Session as SessionModel
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from fastapi import Depends, FastAPI
from server import dependencies as server_deps
from server.ca import ADMIN_SHORT_CERT_LIFETIME_SECONDS, PLANE_HUMAN, AdminCAManager
from server.config import AdminMTLSConfig, InnerTLSConfig, ServerConfig
from server.middleware.auth import SessionMiddleware
from server.routes import admin as admin_routes
from server.routes import admin_certs as admin_certs_routes
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

REISSUE_PATH = "/api/v1/admin/recovery-code/reissue"
MINT_PATH = "/api/v1/admin/certs/issue"

# Exact shipped strings, read off the source at this face and never paraphrased: a reworded refusal is
# supposed to redden the cell that pins it.
REISSUE_NEEDS_SESSION = "Session authentication required to reissue a recovery code"
REISSUE_NEEDS_CERT_CHANNEL = "Certificate-verified channel required to reissue a recovery code"
MINT_NEEDS_LOGIN_SESSION = "requires a login session, not an admin certificate"

_ADMIN_SLOT = "admin@example.com"  # the machine-plane slot in known_admin_ids
_HUMAN_ID = "alice-838"  # a person's user_id: holds the admin role, has a live session
_elev_seq = count(1)

SENTINEL_HASH = "0" * 64  # a pre-existing recovery-code hash, so "unchanged" is observable


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_passphrase")


@pytest.fixture
def admin_ca(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _sqlite_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite (house pattern; kept local by convention —
    #450, #511, #718, #730's roles file and this file each carry their own, so a peer's edit cannot
    redden this cell). SQLite has no timestamptz; production PostgreSQL returns aware values and this
    listener changes nothing there.
    """
    Model838 = SessionModel
    if getattr(Model838, "_mint730_utc_loader", False):
        return
    Model838._mint730_utc_loader = True

    @event.listens_for(Model838, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "access_token_expires_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


@pytest.fixture
def session(tmp_path):
    """Real rows: one person with a live bearer session, and the two mint-path guards' inputs."""
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
    now = datetime.now(UTC)
    s.add(User(user_id=_HUMAN_ID, status="active", display_name="leg 838 person"))
    s.add(
        SessionModel(
            user_id=_HUMAN_ID,
            created_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10),
            access_token="bearer-838",
            access_token_jti="jti-838",
            access_token_expires_at=now + timedelta(minutes=5),
        )
    )
    s.commit()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


@pytest.fixture
def admin_role(session):
    role = Role(name="admin", permissions="read-write")
    session.add(role)
    session.commit()
    session.add(RoleMember(user_id=_HUMAN_ID, role_id=role.id))
    session.commit()
    return role


def _machine_cert(admin_ca: AdminCAManager) -> x509.Certificate:
    """A machine-plane admin cert for the config slot — the shape that clears the certificate branch."""
    cert, _key_pem, _pem = admin_ca.sign_admin_cert(_ADMIN_SLOT)
    return cert


def _human_cert(admin_ca: AdminCAManager) -> x509.Certificate:
    """A human-plane cert naming the session person (the renewal shape)."""
    key = ec.generate_private_key(SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    return admin_ca.sign_admin_csr(csr, _HUMAN_ID, ADMIN_SHORT_CERT_LIFETIME_SECONDS)


def _cert_headers(cert: x509.Certificate) -> dict:
    import urllib.parse

    return {"x-client-cert-pem": urllib.parse.quote_from_bytes(cert.public_bytes(serialization.Encoding.PEM))}


def _elevation(session, *, identity: str = _HUMAN_ID) -> str:
    token = f"elev-838-{next(_elev_seq)}"
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


def _csr_pem() -> str:
    key = ec.generate_private_key(SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _with_hash(session, value: str | None) -> str | None:
    """Put a known recovery-code hash on the person's row, so a change is observable."""
    user = session.query(User).filter(User.user_id == _HUMAN_ID).one()
    user.recovery_code_hash = value
    session.commit()
    return value


def _elevation_used(session) -> bool:
    """Whether the caller's single-use ceremony token has been burned — #296 Q10 says a pre-check
    refusal must NOT burn it, so every refusal cell reads this."""
    return bool(next(session.scalars(select(ElevationToken.used))))


def _reissue_state(session) -> tuple[str | None, bool, list[str]]:
    """(hash, elevation token used?, reissue audit event types) — the state half of every refusal cell."""
    user = session.query(User).filter(User.user_id == _HUMAN_ID).one()
    events = list(
        session.scalars(
            select(AuditEvent.event_type).where(
                AuditEvent.event_type.in_(["recovery_code_reissued", "recovery_code_reissue_denied"])
            )
        ).all()
    )
    return user.recovery_code_hash, _elevation_used(session), events


def _minted_count(session) -> int:
    return len(list(session.scalars(select(AuditEvent).where(AuditEvent.event_type == "admin_cert_issued")).all()))


def _app(admin_ca, session, tmp_path, *, known_ids=(_ADMIN_SLOT,), bypass: dict | None = None):
    """The real stack, or its bypass control.

    ``bypass=None`` -> the shipped ``SessionMiddleware`` with ``admin_mtls`` ENABLED, both real mint
    routers mounted, and the real guard dependencies. ``bypass=<identity dict>`` -> the middleware is
    replaced by a two-line stand-in that attaches that identity and sets the cert-channel flag (the
    ``test_roles.py`` F1 shape #730 names, plus the flag a bypassed certificate check would set). That
    form is used by exactly one cell in this file, and only to prove the refusals are the shipped guard's.
    """
    app = FastAPI()
    app.state.config = ServerConfig(
        recovery_code_pepper="838-pepper-not-a-real-one",
        admin_mtls=AdminMTLSConfig(enabled=True, ca_cert=str(admin_ca.ca_cert_path), known_admin_ids=list(known_ids)),
        inner_mtls=InnerTLSConfig(enabled=True),
    )

    class _Backend:
        """One shared session: the middleware's lookups, the guard's role read and the handler's writes
        all see the same transaction, which is what makes the state assertions below possible."""

        def get_session(self):
            return session

    app.state.backend = _Backend()
    app.state.admin_ca_manager = admin_ca
    app.dependency_overrides[server_deps.get_db] = lambda: session

    if bypass is None:
        app.add_middleware(SessionMiddleware)
    else:
        from starlette.middleware.base import BaseHTTPMiddleware

        class _Bypass(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.auth_user = bypass["identity"]
                if bypass.get("cert_channel", True):
                    request.state.admin_cert_verified = True
                return await call_next(request)

        app.add_middleware(_Bypass)

    @app.get("/api/v1/admin/probe", dependencies=[Depends(server_deps.require_admin)])
    def _probe():
        return {"status": "ok"}

    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(admin_certs_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


class TestCertOnlyCallerIsRefusedAtBothMintPaths:
    """AC2, the negatives. One credential presented — a valid, crypto-verified admin certificate — and no
    session. Each cell names the shipped layer that refuses and reads the state the mint would have
    written, so a refusal that half-lands cannot pass here.
    """

    def test_cert_only_at_the_recovery_code_reissue_is_refused_and_writes_nothing(self, admin_ca, session, tmp_path):
        client = _app(admin_ca, session, tmp_path)
        _with_hash(session, SENTINEL_HASH)
        elev = _elevation(session)

        resp = client.post(REISSUE_PATH, headers={**_cert_headers(_machine_cert(admin_ca)), "X-Elevation-Token": elev})

        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == REISSUE_NEEDS_SESSION
        # HANDLER layer, not MIDDLEWARE: this is the reissue body's own caller-shape guard, reached because
        # the middleware verified the certificate and set the channel flag for a SESSION_REQUIRED path.
        hash_now, token_used, events = _reissue_state(session)
        assert hash_now == SENTINEL_HASH, "no code was reissued"
        assert token_used is False, "the caller's ceremony token must survive a pre-check refusal (#296 Q10)"
        assert events == [], f"no reissue audit row either: {events}"

    def test_cert_only_at_the_certificate_mint_is_refused_and_mints_nothing(
        self, admin_ca, session, admin_role, tmp_path
    ):
        client = _app(admin_ca, session, tmp_path)
        elev = _elevation(session)

        resp = client.post(
            MINT_PATH,
            json={"csr_pem": _csr_pem()},
            headers={**_cert_headers(_machine_cert(admin_ca)), "X-Elevation-Token": elev},
        )

        assert resp.status_code == 403, resp.text
        assert MINT_NEEDS_LOGIN_SESSION in resp.json()["detail"]
        assert _minted_count(session) == 0, "the mint wrote an audit row while refusing"
        assert _elevation_used(session) is False, "the refusal burned the caller's ceremony token"


class TestBothCredentialsAdmitTheSameCaller:
    """The paired POSITIVES. Same certificate, same stack, one added bearer — and both mints land. A
    guard that refused every caller would pass the class above; these two cells are what makes those
    refusals mean "the second credential is missing" and not "the route is unreachable".
    """

    def test_cert_plus_session_reissues_the_code_and_writes_the_hash(self, admin_ca, session, admin_role, tmp_path):
        client = _app(admin_ca, session, tmp_path)
        _with_hash(session, SENTINEL_HASH)
        elev = _elevation(session)

        resp = client.post(
            REISSUE_PATH,
            headers={
                **_cert_headers(_human_cert(admin_ca)),
                "Authorization": "Bearer bearer-838",
                "X-Elevation-Token": elev,
            },
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["user_id"] == _HUMAN_ID
        assert len(resp.json()["recovery_code"]) >= 20
        hash_now, token_used, events = _reissue_state(session)
        assert hash_now != SENTINEL_HASH, "the reissue wrote no new hash"
        assert len(hash_now) == 64
        assert token_used is True, "the ceremony token was not burned"
        assert events == ["recovery_code_reissued"]

    def test_cert_plus_session_mints_a_human_plane_certificate(self, admin_ca, session, admin_role, tmp_path):
        client = _app(admin_ca, session, tmp_path)
        elev = _elevation(session)

        resp = client.post(
            MINT_PATH,
            json={"csr_pem": _csr_pem()},
            headers={
                **_cert_headers(_human_cert(admin_ca)),
                "Authorization": "Bearer bearer-838",
                "X-Elevation-Token": elev,
            },
        )

        assert resp.status_code == 201, resp.text
        issued = x509.load_pem_x509_certificate(resp.json()["certificate_pem"].encode())
        from server.ca import parse_plane_marker

        assert parse_plane_marker(issued) == PLANE_HUMAN
        assert _minted_count(session) == 1


class TestTheRefusalIsTheShippedGuard:
    """AC2's "the cell must fail if the guard is bypassed", run as cells rather than as comments. Each one
    replaces exactly ONE shipped object and shows the consequence, so the negatives above are known to be
    sensitive to that object and not to the fixture's shape.
    """

    def test_replacing_the_middleware_admits_a_cert_only_caller_to_the_reissue(
        self, admin_ca, session, admin_role, tmp_path
    ):
        """The #730 defect class itself: a local stand-in middleware attaching a session-shaped identity.
        The reissue then LANDS — 200 and a new hash — which is what the negative cell above would return if
        the shipped ``SessionMiddleware`` were not the thing building that caller's identity dict.
        """
        _with_hash(session, SENTINEL_HASH)
        elev = _elevation(session)
        client = _app(
            admin_ca,
            session,
            tmp_path,
            bypass={"identity": {"user_id": _HUMAN_ID, "session_id": 1, "roles": [], "exp": 0}},
        )

        # No bearer is presented at all: the stand-in hands the handler a person identity the real
        # middleware would never build for a cert-only caller.
        resp = client.post(REISSUE_PATH, headers={"X-Elevation-Token": elev})

        assert resp.status_code == 200, resp.text
        hash_now, _used, events = _reissue_state(session)
        assert hash_now != SENTINEL_HASH
        assert events == ["recovery_code_reissued"]

    def test_bypassing__require_human_session_admits_a_cert_only_caller_to_the_mint(
        self, admin_ca, session, admin_role, tmp_path, monkeypatch
    ):
        """The mint's guard is a named route function, so the control bypasses that one object: the cert-only
        request that answers 403 above then answers 201, and the audit row appears. The only other thing
        this cell changes is fixture state — a ``users`` row for the slot, which an FK on the ceremony token
        requires — and no shipped guard.
        """
        monkeypatch.setattr(
            admin_certs_routes, "_require_human_session", lambda user_info: user_info.get("user_id") or _ADMIN_SLOT
        )
        # The bypassed guard would hand the mint the CERTIFICATE's own identity, so the ceremony token this
        # control spends is bound to that slot. The slot normally has no user row (rf7 proves that); this
        # cell adds one because elevation_tokens.user_id carries a real FK, and the point of the cell is
        # that the mint LANDS when the route-level guard is gone.
        session.merge(User(user_id=_ADMIN_SLOT, status="active", display_name="838 bypass control only"))
        session.commit()
        client = _app(admin_ca, session, tmp_path)
        elev = _elevation(session, identity=_ADMIN_SLOT)

        resp = client.post(
            MINT_PATH,
            json={"csr_pem": _csr_pem()},
            headers={**_cert_headers(_machine_cert(admin_ca)), "X-Elevation-Token": elev},
        )

        assert resp.status_code == 201, resp.text
        assert _minted_count(session) == 1

    def test_narrowing_SESSION_REQUIRED_ADMIN_PATHS_moves_the_reissue_refusal_and_earns_a_403(
        self, admin_ca, session, admin_role, tmp_path, monkeypatch
    ):
        """The widening #730 AC2 is guarding against, applied to the middleware's own set: drop the reissue
        path from ``SESSION_REQUIRED_ADMIN_PATHS`` and the certificate short-circuits — the channel flag is
        never set, so the two-credential request that lands above now answers the handler's OTHER shipped
        refusal and writes no code. The outcome for a cert-only caller does not change, which is the point:
        a membership widening moves the layer, and the paired positive above is the cell that sees it.
        """
        monkeypatch.setattr(SessionMiddleware, "SESSION_REQUIRED_ADMIN_PATHS", frozenset({MINT_PATH}), raising=False)
        client = _app(admin_ca, session, tmp_path)
        _with_hash(session, SENTINEL_HASH)
        elev = _elevation(session)

        both = client.post(
            REISSUE_PATH,
            headers={
                **_cert_headers(_human_cert(admin_ca)),
                "Authorization": "Bearer bearer-838",
                "X-Elevation-Token": elev,
            },
        )
        assert both.status_code == 403, both.text
        assert both.json()["detail"] == REISSUE_NEEDS_CERT_CHANNEL
        hash_now, token_used, events = _reissue_state(session)
        assert hash_now == SENTINEL_HASH
        assert token_used is False
        assert events == []

        cert_only = client.post(
            REISSUE_PATH,
            headers={**_cert_headers(_machine_cert(admin_ca)), "X-Elevation-Token": _elevation(session)},
        )
        assert cert_only.status_code == 403, cert_only.text
        assert cert_only.json()["detail"] == REISSUE_NEEDS_CERT_CHANNEL
