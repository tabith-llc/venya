# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""End-to-end break-glass recovery test — real init, real recovery, real auth.

Closes the loop the mock-based unit tests leave open (ticket
test-recovery-admin-enrollment-key): a recovery code produced by the REAL
init/complete path is accepted by the REAL /api/v1/recovery endpoint (same
pepper + digest wiring), the new admin gets the admin role, the code is
burned (single-use — replay rejected 401), the recovered admin can enroll a
FIDO2 key and complete a real signed assertion (session token issued), and
the CLI `venya recovery` path (cmd_recovery) drives the same flow headlessly.

Zero route mocks: real SQLite-backed Backend (engine injected per the
test_secrets.py pattern — Backend._create_engine issues PostgreSQL-only SET
pragmas), real init/recovery/auth routers, real Fido2Manager, real CA init
into a tmp dir, software ES256 authenticator (helpers adapted from
packages/server/tests/test_fido2_manager.py).

Tier limit (documented per ruling 2026-09-16): this in-process e2e does NOT
cover CA/cert issuance over the network, TLS/nginx, PostgreSQL, or physical
FIDO2 hardware interaction — those belong to the separate integration tier
(venya-test-workstation Playwright runs / physical VM acceptance).
"""

import base64
import hashlib
import json
import struct
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fido2 import cbor as fido2_cbor
from fido2.webauthn import ES256
from server.fido2.manager import Fido2Manager
from server.routes import auth as auth_routes
from server.routes import init as init_routes
from server.routes import recovery as recovery_routes
from starlette.testclient import TestClient
from venya_cli.api_client import APIClientError
from venya_cli.commands import cmd_recovery

RP_ID = "venya-core-1"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
PEPPER = "test-pepper"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _build_attestation_object(cred_id: bytes, cose_key: dict, counter: int = 0) -> bytes:
    """CBOR attestation object with attested credential data (fmt: none)."""
    aaguid = b"\x00" * 16
    cred_data = aaguid + struct.pack(">H", len(cred_id)) + cred_id + fido2_cbor.encode(cose_key)
    # Flags: UP(0x01) | UV(0x04) | AT(0x40) = 0x45
    auth_data = RP_ID_HASH + bytes([0x45]) + struct.pack(">I", counter) + cred_data
    return bytes(fido2_cbor.encode({"fmt": "none", "authData": auth_data, "attStmt": {}}))


def _browser_registration_response(cred_id: bytes, private_key) -> dict:
    """Browser-shaped registration response accepted by init/complete."""
    cose = ES256.from_cryptography_key(private_key.public_key())
    ao = _build_attestation_object(cred_id, dict(cose))
    return {
        "id": _b64url(cred_id),
        "rawId": _b64url(cred_id),
        "response": {
            "clientDataJSON": _b64url(b"{}"),
            "authenticatorAttestationResponse": {
                "attestationObject": _b64url(ao),
            },
        },
        "type": "public-key",
    }


def _cli_registration_response(cred_id: bytes, private_key) -> dict:
    """CLI-shaped registration response accepted by /auth/registration/complete."""
    cose = ES256.from_cryptography_key(private_key.public_key())
    ao = _build_attestation_object(cred_id, dict(cose))
    return {
        "id": _b64url(cred_id),
        "rawId": _b64url(cred_id),
        "response": {
            "clientDataJSON": _b64url(b"{}"),
            "attestationObject": _b64url(ao),
            "transports": [],
        },
        "type": "public-key",
    }


def _assertion_response(cred_id: bytes, private_key, raw_challenge: bytes, counter: int = 1) -> dict:
    """Signed assertion answering a login challenge."""
    flags = 0x01 | 0x04  # UP | UV
    auth_data = RP_ID_HASH + bytes([flags]) + struct.pack(">I", counter)
    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": _b64url(raw_challenge),
            "origin": f"https://{RP_ID}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data_json).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "id": _b64std(cred_id),
        "rawId": _b64std(cred_id),
        "response": {
            "clientDataJSON": _b64url(client_data_json),
            "authenticatorData": _b64url(auth_data),
            "signature": _b64url(signature),
            "userHandle": None,
        },
        "type": "public-key",
        "clientExtensionResults": {},
    }


def _build_real_app(tmp_path):
    """Real app over SQLite: init + recovery + auth routers, zero route mocks."""
    from core.engine.backend import Backend, BackendConfig
    from core.engine.encryption import KEK_SIZE
    from core.iam.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_path = tmp_path / "recovery_e2e.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    # Bypass Backend._create_engine (PostgreSQL-only SET pragmas break SQLite)
    backend._engine = engine
    backend._session_factory = session_factory

    app = FastAPI()
    app.state.backend = backend
    app.state.config = SimpleNamespace(
        recovery_code_pepper=PEPPER,
        ca_dir=str(tmp_path / "ca"),
        ca_security=None,
        session=SimpleNamespace(
            session_timeout=900,
            access_token_ttl=300,
            max_session_duration=3600,
        ),
    )
    app.state.fido2_manager = Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=backend)
    app.include_router(init_routes.router, prefix="/api/v1")
    app.include_router(recovery_routes.router, prefix="/api/v1")
    app.include_router(auth_routes.router, prefix="/api/v1")
    return app, backend


class _CliHttpShim:
    """Minimal APIClient stand-in: forwards cmd_recovery's POST to TestClient."""

    def __init__(self, http: TestClient) -> None:
        self._http = http

    def post(self, path: str, json: dict | None = None) -> dict:
        resp = self._http.post(path, json=json)
        if resp.status_code >= 400:
            raise APIClientError(f"HTTP {resp.status_code}: {resp.text}")
        return resp.json()


def test_recovery_e2e_full_loop(tmp_path):
    """init → capture code → CLI recovery → burn → replay 401 → enroll+login.

    Single sequential narrative: every step consumes the state the previous
    step created, exactly like a real lockout recovery.
    """
    from core.iam.models import Role, RoleMember, User

    app, backend = _build_real_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    # --- Step 1: real init (both halves), capture the one-shot code ---
    resp = client.post("/api/v1/init", json={"user_id": "oldadmin"})
    assert resp.status_code == 201, resp.text
    challenge_id = resp.json()["challenge_id"]

    key_a = ec.generate_private_key(ec.SECP256R1())
    resp = client.post(
        "/api/v1/init/complete",
        json={
            "user_id": "oldadmin",
            "challenge_id": challenge_id,
            "response": _browser_registration_response(b"\xaa" * 32, key_a),
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["success"] is True
    code = data["recovery_code"]
    # Format sanity: 8 groups of 6 alnum chars
    groups = code.split("-")
    assert len(groups) == 8 and all(len(g) == 6 and g.isalnum() for g in groups)

    # The two halves agree: init stored exactly sha256(pepper + code)
    db = backend.get_session()
    try:
        oldadmin = db.query(User).filter(User.user_id == "oldadmin").first()
        assert oldadmin is not None
        assert oldadmin.enrolled_at is not None
        assert oldadmin.recovery_code_hash == hashlib.sha256((PEPPER + code).encode()).hexdigest()
    finally:
        db.close()

    # --- Step 2: CLI negative — wrong code rejected, rc=1, nothing created ---
    shim = _CliHttpShim(client)
    rc = cmd_recovery(
        shim,
        SimpleNamespace(code="WRONG-CODE", new_user_id="newadmin", force=False, confirm=False),
    )
    assert rc == 1

    # --- Step 3: CLI success — real code through cmd_recovery ---
    rc = cmd_recovery(
        shim,
        SimpleNamespace(code=code, new_user_id="newadmin", force=False, confirm=False),
    )
    assert rc == 0

    # New admin exists with the admin role attached
    db = backend.get_session()
    try:
        newadmin = db.query(User).filter(User.user_id == "newadmin").first()
        assert newadmin is not None
        membership = (
            db.query(RoleMember)
            .join(Role, RoleMember.role_id == Role.id)
            .filter(RoleMember.user_id == "newadmin")
            .filter(Role.name == "admin")
            .first()
        )
        assert membership is not None
        # Burn: source admin's one-shot code is dead after use
        oldadmin = db.query(User).filter(User.user_id == "oldadmin").first()
        assert oldadmin.recovery_code_hash is None
    finally:
        db.close()

    # --- Step 4: HTTP negative — replay of the burned code is rejected ---
    resp = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "newadmin2"})
    assert resp.status_code == 401
    assert "Invalid recovery code" in resp.json()["detail"]
    db = backend.get_session()
    try:
        assert db.query(User).filter(User.user_id == "newadmin2").first() is None
    finally:
        db.close()

    # --- Step 5: recovered admin enrolls a FIDO2 key and authenticates ---
    # Enrollment goes through the real Fido2Manager (real attestation crypto)
    # plus the same WebAuthnCredential row /auth/registration/complete would
    # write. That HTTP route is bypassed deliberately: it 500s on real binary
    # credential IDs (latent bytes-vs-str response-model bug, no production
    # caller — ticket auth-registration-complete-bytes-500). The proof this
    # step owes is the assertion over real HTTP below, not the enroll route.
    from core.iam.models import WebAuthnCredential

    key_b = ec.generate_private_key(ec.SECP256R1())
    reg_challenge, _ = app.state.fido2_manager.start_registration(
        user_id="newadmin",
        username="newadmin",
    )
    cred_b = app.state.fido2_manager.finish_registration(
        reg_challenge,
        _cli_registration_response(b"\xbb" * 32, key_b),
    )
    db = backend.get_session()
    try:
        db.add(
            WebAuthnCredential(
                user_id=cred_b.user_id,
                credential_id=cred_b.credential_id,
                public_key=cred_b.public_key,
                sign_count=cred_b.sign_count,
                is_active=True,
            )
        )
        db.commit()
    finally:
        db.close()

    resp = client.post("/api/v1/auth/login/start", json={"user_id": "newadmin"})
    assert resp.status_code == 200, resp.text
    login = resp.json()
    raw_challenge = base64.b64decode(login["options"]["challenge"])

    resp = client.post(
        "/api/v1/auth/login/complete",
        json={
            "challenge_id": login["challenge_id"],
            "response": _assertion_response(b"\xbb" * 32, key_b, raw_challenge),
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["user_id"] == "newadmin"
    assert data["session_token"]
