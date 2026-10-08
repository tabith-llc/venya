# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 2 CP-B — mint authorization, rate limit, audit event.

The endpoint shipped in CP-A is a credential factory without the three
controls this file pins (RF-6 §2.6.3, §2.7, §2.8):

* the caller holds the admin role at MINT time — a second check, not a
  replacement (§3.3's per-USE check lives in the dependency);
* exactly one fresh FIDO2 elevation ceremony is spent per mint, consumed
  atomically so two concurrent requests cannot both spend it;
* the path is in the DB-backed rate limiter's classified set, so the cap is
  per-account across cores and survives a restart. §2.7 names the in-memory
  limiters as the WRONG choice for a mint cap: N workers enforce N×, and a
  restart clears the state.

Runs on real SQLite rows: the elevation burn is a conditional UPDATE whose
rowcount IS the control, and a mock cannot answer whether the row flipped. The
REAL ``get_db`` runs (the backend double hands out this very session), because
the rollback-on-refusal behavior those cells assert lives in that dependency.

Every cell is a truth-table pair — what must be granted, and what must be
refused with the reason named (RF-6 §2.7: all loud, none of them a 500).
"""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import count
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from core.iam.models import Base, ElevationToken, RateLimitFailure, Role, RoleMember, User
from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from server import metrics
from server.audit_lifecycle import ADMIN_CERT_ISSUED
from server.ca import AdminCAManager
from server.config import ServerConfig
from server.middleware.rate_limit import RateLimitMiddleware
from server.routes import admin_certs as routes
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

_IDENTITY = "alice@example.com"
_OTHER = "bob@example.com"
_ELEVATION_TTL = 60

# ---------------------------------------------------------------------------
# Fixtures — real SQLite, real admin CA
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _passphrase_env(monkeypatch):
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_passphrase")


@pytest.fixture
def session():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(User(user_id=_IDENTITY, status="active"))
    s.commit()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


@pytest.fixture
def admin_role(session):
    """The admin role + this user's read-write membership (require_admin's target)."""
    role = Role(name="admin", permissions="read-write")
    session.add(role)
    session.commit()
    session.add(RoleMember(user_id=_IDENTITY, role_id=role.id))
    session.commit()
    return role


@pytest.fixture
def admin_ca(tmp_path: Path) -> AdminCAManager:
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _csr_pem(private_key=None, common_name="attacker-chosen-cn") -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key or _key(), hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _mint_elevation(session, user_id: str = _IDENTITY, *, used: bool = False, ttl: int = _ELEVATION_TTL, token: str):
    """Insert a real ElevationToken row; return the plaintext token."""
    session.add(
        ElevationToken(
            token_hash=sha256(token.encode()).hexdigest(),
            user_id=user_id,
            session_id=11,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl),
            used=used,
        )
    )
    session.commit()
    return token


_elev_seq = count(1)


def _fresh_elevation(session, user_id: str = _IDENTITY) -> str:
    return _mint_elevation(session, user_id, token=f"authz-elev-{next(_elev_seq)}")


def _session_caller(user_id: str = _IDENTITY) -> dict:
    """The shape a validated bearer/cookie session attaches (middleware/auth.py)."""
    return {"user_id": user_id, "session_id": 11, "roles": [], "exp": 0}


def _app(session, admin_ca, caller: dict):
    """App running the REAL require_admin and the REAL get_db.

    The caller is attached to ``request.state.auth_user`` by a middleware
    double standing in for SessionMiddleware's own attachment
    (middleware/auth.py) — the role lookup, the ceremony burn, and the
    rollback on a later refusal are all the product's code, not a mock's.
    """
    app = FastAPI()
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper")
    app.state.admin_ca_manager = admin_ca
    backend = MagicMock()
    backend.get_session.return_value = session
    app.state.backend = backend

    class _AttachIdentity(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = caller
            return await call_next(request)

    app.add_middleware(_AttachIdentity)
    app.include_router(routes.router, prefix="/api/v1")
    return app


def _client(app):
    return TestClient(app, raise_server_exceptions=False)


def _issue(client, session=None, csr_pem=None, *, elevation="", extra_body=None):
    """POST the mint. With a session and no named token, a FRESH ceremony row is
    minted for the call (one touch, one certificate). ``elevation=None`` sends
    no header at all."""
    headers = {}
    if elevation == "" and session is not None:
        elevation = _fresh_elevation(session)
    if elevation:
        headers["X-Elevation-Token"] = elevation
    body = {"csr_pem": csr_pem or _csr_pem(), **(extra_body or {})}
    return client.post("/api/v1/admin/certs/issue", json=body, headers=headers)


def _audit_rows(session):
    from core.iam.models import AuditEvent

    return list(session.scalars(select(AuditEvent).where(AuditEvent.event_type == ADMIN_CERT_ISSUED)))


def _elevation_rows(session):
    return list(session.scalars(select(ElevationToken)))


class TestMintTimeRoleCheck:
    """§2.6.3: the mint refuses a caller with no admin role — both halves."""

    def test_admin_member_mints(self, session, admin_role, admin_ca):
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session).status_code == 201

    def test_no_admin_membership_refused_403_and_nothing_mints(self, session, admin_ca):
        """Negative half: the admin role EXISTS and this user is NOT a member →
        403 "Admin permission required".

        The role row is created on purpose: without it require_admin answers
        "Admin role not found", which is a different (deployment-shape) refusal,
        and the cell that matters here is the membership check. Proves the
        endpoint is not a general "cert for any user" factory.
        """
        role = Role(name="admin", permissions="read-write")
        session.add(role)
        session.commit()  # role exists, membership does NOT
        app = _app(session, admin_ca, _session_caller())
        resp = _issue(_client(app), session)
        assert resp.status_code == 403
        assert "Admin permission required" in resp.json()["detail"]
        assert _audit_rows(session) == []
        # The ceremony the refused request never needed stays unspent too.
        assert all(row.used is False for row in _elevation_rows(session))

    def test_unknown_user_refused_cleanly_not_500(self, session, admin_role, admin_ca):
        """§3.8 row: an identity with no user row is a lookup miss (403), never
        a 500 — the shape that would otherwise raise inside the role check."""
        app = _app(session, admin_ca, _session_caller("ghost@example.com"))
        resp = _issue(_client(app), session, elevation=_fresh_elevation(session))
        assert resp.status_code == 403, resp.text


class TestElevationCeremonyRequired:
    def test_valid_unused_unexpired_token_mints(self, session, admin_role, admin_ca):
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session).status_code == 201

    def test_missing_elevation_token_refused_403(self, session, admin_role, admin_ca):
        app = _app(session, admin_ca, _session_caller())
        resp = _issue(_client(app), session, elevation=None)
        assert resp.status_code == 403
        assert "venya admin elevate" in resp.json()["detail"]
        assert _audit_rows(session) == []

    def test_spent_token_refused_401_and_no_second_mint(self, session, admin_role, admin_ca):
        """§2.8 paired negative: an already-spent ceremony mints nothing and
        writes no ADMIN_CERT_ISSUED row."""
        token = _mint_elevation(session, token="spent-once")
        app = _app(session, admin_ca, _session_caller())
        client = _client(app)
        assert _issue(client, session, elevation=token).status_code == 201
        # Same token, second request — one touch, one certificate.
        resp2 = _issue(client, session, elevation=token)
        assert resp2.status_code == 401
        assert "Invalid or expired elevation token" in resp2.json()["detail"]
        assert len(_audit_rows(session)) == 1, "the refused mint wrote a second issuance row"

    def test_expired_token_refused_401(self, session, admin_role, admin_ca):
        token = _mint_elevation(session, token="expired", ttl=-120)
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session, elevation=token).status_code == 401

    def test_other_users_token_refused(self, session, admin_role, admin_ca):
        """Cross-account ceremony: the burn is bound to the CALLER's user_id."""
        session.add(User(user_id=_OTHER, status="active"))
        session.commit()
        token = _mint_elevation(session, _OTHER, token="mallory-ceremony")
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session, elevation=token).status_code == 401

    def test_two_requests_one_ceremony_second_refused(self, session, admin_role, admin_ca):
        """The atomic flip is the control (§2.7): one row used=True, one mint."""
        token = _mint_elevation(session, token="one-shot")
        app = _app(session, admin_ca, _session_caller())
        client = _client(app)
        codes = [
            _issue(client, session, elevation=token).status_code,
            _issue(client, session, elevation=token).status_code,
        ]
        assert sorted(codes) == [201, 401], codes
        assert len(_audit_rows(session)) == 1
        assert _elevation_rows(session)[0].used is True

    def test_role_denial_does_not_burn_the_ceremony(self, session, admin_ca):
        """Gate ORDER, stated as a test: require_admin runs before the handler,
        so a caller with no role is refused without spending a touch it could
        never use. The row stays unused and the ceremony is replayable."""
        token = _mint_elevation(session, token="replayable")
        app = _app(session, admin_ca, _session_caller())  # no admin_role
        client = _client(app)
        assert _issue(client, session, elevation=token).status_code == 403
        assert _elevation_rows(session)[0].used is False
        # Now grant the role and replay the SAME ceremony: it mints.
        role = session.scalars(select(Role)).one() if session.scalars(select(Role)).first() else None
        assert role is None, "admin_role fixture was not applied — expected no role row"
        new_role = Role(name="admin", permissions="read-write")
        session.add(new_role)
        session.commit()
        session.add(RoleMember(user_id=_IDENTITY, role_id=new_role.id))
        session.commit()
        assert _issue(client, session, elevation=token).status_code == 201


class TestIssuanceAuditEvent:
    def test_row_carries_the_ruled_field_table(self, session, admin_role, admin_ca):
        """§2.8: serial, identity, validity window, curve, requesting user, reason."""
        app = _app(session, admin_ca, _session_caller())
        resp = _issue(_client(app), session)
        assert resp.status_code == 201, resp.text

        rows = _audit_rows(session)
        assert len(rows) == 1
        row = rows[0]
        assert row.user_id == _IDENTITY, "the human user_id is the actor (ruling 2)"
        fields = json.loads(row.fields) if isinstance(row.fields, str) else row.fields
        assert set(fields) == {
            "serial_number",
            "identity",
            "not_valid_before",
            "not_valid_after",
            "curve",
            "requesting_user_id",
            "reason",
        }
        assert fields["identity"] == _IDENTITY
        assert fields["reason"] == "issue"
        assert fields["curve"] == "secp256r1"

        # The serial in the row is the issued certificate's, in the ONE
        # canonical form the revocation lookup compares (#481).
        issued = x509.load_pem_x509_certificate(resp.json()["certificate_pem"].encode())
        assert fields["serial_number"] == canonical_serial(issued.serial_number)

        # Offset-aware, per the datetime rule.
        assert datetime.fromisoformat(fields["not_valid_after"]).tzinfo is not None
        assert datetime.fromisoformat(fields["not_valid_before"]).tzinfo is not None

    def test_row_never_carries_csr_or_key_or_cert(self, session, admin_role, admin_ca):
        """§2.8 negative: non-admin auditors read this table — no
        reconstructable subject detail, no key material, no cert."""
        csr = _csr_pem()
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session, csr).status_code == 201
        row = _audit_rows(session)[0]
        fields = json.loads(row.fields) if isinstance(row.fields, str) else row.fields
        assert set(fields) == {
            "serial_number",
            "identity",
            "not_valid_before",
            "not_valid_after",
            "curve",
            "requesting_user_id",
            "reason",
        }, "an audit field was added without ruling its disclosure"
        blob = json.dumps(fields)
        for forbidden in ("PRIVATE KEY", "CERTIFICATE REQUEST", csr, "BEGIN CERTIFICATE"):
            assert forbidden not in blob, f"audit fields leaked {forbidden!r}"

    def test_metric_uses_the_existing_counter_with_an_admin_label(self, session, admin_role, admin_ca):
        """§2.8: reuse CA_SIGNED_TOTAL with a distinct label, do not invent a metric."""
        before = metrics.CA_SIGNED_TOTAL.labels(cert_type="admin")._value.get()
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session).status_code == 201
        assert metrics.CA_SIGNED_TOTAL.labels(cert_type="admin")._value.get() == before + 1

    def test_refused_mint_increments_no_metric_and_writes_no_row(self, session, admin_role, admin_ca):
        """Paired negative (§2.8): an already-spent ceremony moves nothing."""
        token = _mint_elevation(session, token="pre-spent", used=True)
        before = metrics.CA_SIGNED_TOTAL.labels(cert_type="admin")._value.get()
        app = _app(session, admin_ca, _session_caller())
        assert _issue(_client(app), session, elevation=token).status_code == 401
        assert metrics.CA_SIGNED_TOTAL.labels(cert_type="admin")._value.get() == before
        assert _audit_rows(session) == []

    def test_event_name_is_registered_in_the_single_writer(self):
        """The helper's known-set is the only place lifecycle events are born;
        an unregistered name raises (pinned behavior, #301)."""
        from server.audit_lifecycle import audit_lifecycle

        assert ADMIN_CERT_ISSUED == "admin_cert_issued"
        with pytest.raises(ValueError):
            audit_lifecycle(MagicMock(), "admin_cert_issued_typo", "someone", {})


class TestIssuanceIsClassifiedInTheDbBackedLimiter:
    """§2.7: the mint path must be in the DB-backed middleware's classified set.

    Tree honesty (s73 verification file, accepted by the lead at 09:53): an
    unclassified path does NOT ship unlimited — it falls to the generic per-IP
    tier (``config.rate_limit.ip_rate_limit``, default 1000/min). 1000 mints a
    minute is no cap on a credential, which is why this tier exists; the cells
    state the OBSERVED tier, not the dossier's wording.
    """

    def _mw(self):
        return RateLimitMiddleware(app=MagicMock(), requests_per_minute=100)

    def test_the_mint_path_is_classified(self):
        mw = self._mw()
        assert mw._is_cert_issuance_endpoint("/api/v1/admin/certs/issue") is True
        # Trailing slash normalizes (the middleware strips it before matching).
        assert mw._is_cert_issuance_endpoint("/api/v1/admin/certs/issue/") is True

    def test_neighbor_paths_are_not_classified(self):
        """Negative half: the tier is the ONE mint path, not the admin prefix."""
        mw = self._mw()
        for path in (
            "/api/v1/admin/certs/revoke",
            "/api/v1/admin/users",
            "/api/v1/auth/login/start",
            "/api/v1/recovery",
            "/api/v1/init/reset",
        ):
            assert mw._is_cert_issuance_endpoint(path) is False, path

    def test_unclassified_lands_in_the_generic_tier_not_unlimited(self):
        """States the observed fallback (lead ruling 2026-10-08)."""
        mw = self._mw()
        assert mw.requests_per_minute == 100  # this double
        default_config = ServerConfig(recovery_code_pepper="p")
        assert default_config.rate_limit.ip_rate_limit == 1000, "the generic tier is a real number"
        assert default_config.rate_limit.cert_issuance_requests_per_hour == 5, "the mint tier is single digits"

    def test_identifier_prefers_the_account_and_falls_back_to_ip(self):
        mw = self._mw()
        attached = MagicMock()
        attached.state.auth_user = {"user_id": _IDENTITY, "session_id": 11}
        assert mw._issuance_identifier(attached, "198.51.100.9") == _IDENTITY

        anonymous = MagicMock()
        anonymous.state.auth_user = None
        assert mw._issuance_identifier(anonymous, "198.51.100.9") == "198.51.100.9", "no identity never means uncapped"

        cert_shaped = MagicMock()
        cert_shaped.state.auth_user = {"caller": "admin", "user_id": "admin@core-1"}
        assert mw._issuance_identifier(cert_shaped, "198.51.100.9") == "admin@core-1"


def _limiter_config(*, issuance_per_hour: int):
    """Config double for RateLimitMiddleware (house pattern from
    test_rate_limit_middleware.MockConfig, including the post-class assignment
    so the tier value comes from the enclosing scope, not the class body)."""

    class MockConfig:
        enforce = True
        ip_rate_limit = 1000
        break_glass_requests_per_hour = 5
        auth_requests_per_minute = 20

    MockConfig.cert_issuance_requests_per_hour = issuance_per_hour
    MockConfig.clock_skew = MagicMock()
    MockConfig.clock_skew.token_tolerance_seconds = 60
    return MockConfig()


class TestIssuanceTierTrips:
    """The 429 itself, through the real middleware over a real counter table."""

    def _wired(self, session, admin_ca, caller, *, issuance_per_hour: int):
        """Limiter + identity-attaching double, in the REAL relative order.

        Starlette's ``add_middleware`` prepends, so the LAST-added layer is the
        OUTERMOST one and runs first — the attacher (the SessionMiddleware
        stand-in) is added last, exactly as SessionMiddleware sits outside
        RateLimitMiddleware in the shipped stack (proved from the real app by
        TestMiddlewareOrderingIsVerifiedNotAssumed). The counter key is then the
        account, not the client IP.
        """
        app = _app(session, admin_ca, caller)
        app.add_middleware(RateLimitMiddleware, config=_limiter_config(issuance_per_hour=issuance_per_hour))

        class _OuterIdentity(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.auth_user = caller
                return await call_next(request)

        app.add_middleware(_OuterIdentity)
        return TestClient(app, raise_server_exceptions=False)

    def test_mints_past_the_cap_trip_429_with_retry_after(self, session, admin_role, admin_ca):
        client = self._wired(session, admin_ca, _session_caller(), issuance_per_hour=2)
        codes = [_issue(client, session).status_code for _ in range(3)]
        assert codes == [201, 201, 429], codes
        resp = _issue(client, session)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert "issuance rate limited" in resp.json()["detail"]
        # The cap is a cap: no fourth certificate was minted.
        assert len(_audit_rows(session)) == 2

    def test_counter_row_is_written_under_the_account_key(self, session, admin_role, admin_ca):
        """Per-account across cores: identifier = the user_id, endpoint_type =
        this tier (the rate_limit_failures primary key)."""
        client = self._wired(session, admin_ca, _session_caller(), issuance_per_hour=5)
        assert _issue(client, session).status_code == 201
        session.commit()
        rows = list(session.scalars(select(RateLimitFailure)))
        assert [(r.identifier, r.endpoint_type) for r in rows] == [(_IDENTITY, "cert_issuance")], rows

    def test_the_cap_is_per_account_not_shared(self, session, admin_role, admin_ca):
        """Negative half of per-account keying: a second account minting through
        the same limiter is not refused by the first account's counter."""
        session.add(User(user_id=_OTHER, status="active"))
        session.commit()
        role = session.scalars(select(Role)).one()
        session.add(RoleMember(user_id=_OTHER, role_id=role.id))
        session.commit()

        client_a = self._wired(session, admin_ca, _session_caller(), issuance_per_hour=1)
        assert _issue(client_a, session).status_code == 201
        assert _issue(client_a, session).status_code == 429

        client_b = self._wired(session, admin_ca, _session_caller(_OTHER), issuance_per_hour=1)
        assert _issue(client_b, session, elevation=_fresh_elevation(session, _OTHER)).status_code == 201

    def test_no_identity_still_counts_by_ip(self, session, admin_role, admin_ca):
        """Fail-safe half: an unauthenticated flood is not uncapped."""

        class _AttachNone(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.auth_user = None
                return await call_next(request)

        caller = _session_caller()
        app = _app(session, admin_ca, caller)
        app.add_middleware(RateLimitMiddleware, config=_limiter_config(issuance_per_hour=1))
        app.add_middleware(_AttachNone)  # added last = outermost = runs first
        client = TestClient(app, raise_server_exceptions=False)

        resp = _issue(client, session)
        # The counter increments whether or not the handler later refuses.
        assert resp.status_code in (201, 401, 403)
        session.commit()
        rows = list(session.scalars(select(RateLimitFailure)))
        assert rows, "no counter row was written for an unauthenticated mint attempt"
        assert all(r.identifier != _IDENTITY for r in rows), rows

    def test_other_tiers_keep_their_ip_keying(self, session, admin_role, admin_ca):
        """Paired negative: the account keying is scoped to THIS tier — an
        auth-prefix request is still counted by IP, unchanged."""
        mw = RateLimitMiddleware(app=MagicMock(), requests_per_minute=100)
        attached = MagicMock()
        attached.state.auth_user = {"user_id": _IDENTITY}
        attached.url.path = "/api/v1/auth/login/start"
        # The dispatcher only calls _issuance_identifier for the mint tier;
        # prove the predicate does not classify an auth path.
        assert mw._is_cert_issuance_endpoint(attached.url.path) is False
        assert mw._is_auth_endpoint(attached.url.path) is True


class TestMiddlewareOrderingIsVerifiedNotAssumed:
    def test_auth_runs_before_the_limiter_on_the_real_app(self):
        """§2.7's per-account cap depends on the limiter seeing an attached
        identity. Proof by construction, not by reading app.py: the real ASGI
        stack is walked and SessionMiddleware must sit OUTSIDE RateLimitMiddleware.

        If a future change reorders them, this cell goes red and the account
        keying degrades to per-IP — loudly, not silently.
        """
        from server.app import create_app

        fastapi_app = create_app(ServerConfig(recovery_code_pepper="p")).app
        # Proof by construction: walk the stack Starlette ACTUALLY built, from
        # the outside in, rather than reading app.py and trusting the ordering.
        node = fastapi_app.build_middleware_stack()
        stack: list[str] = []
        while hasattr(node, "app"):
            stack.append(type(node).__name__)
            node = node.app
        stack.append(type(node).__name__)
        assert "SessionMiddleware" in stack, stack
        assert "RateLimitMiddleware" in stack, stack
        assert stack.index("SessionMiddleware") < stack.index(
            "RateLimitMiddleware"
        ), f"auth no longer runs before the limiter: {stack}"


class TestNoKeyMaterialOnAnyRefusalPath:
    def test_rate_limited_response_carries_no_key_or_cert(self, session, admin_role, admin_ca):
        client = TestIssuanceTierTrips()._wired(session, admin_ca, _session_caller(), issuance_per_hour=0)
        resp = _issue(client, session)
        assert resp.status_code == 429
        assert "PRIVATE KEY" not in resp.text

    def _wired_for_zero_cap(self, session, admin_role, admin_ca):
        return TestIssuanceTierTrips._wired(
            TestIssuanceTierTrips(), session, admin_ca, _session_caller(), issuance_per_hour=0
        )
