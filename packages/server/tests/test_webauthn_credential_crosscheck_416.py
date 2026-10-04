# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""WebAuthn §7.1 step 21 credential-id crosscheck (ticket #416).

Pre-fix, finish_registration keyed its in-memory store by the
client-response id (attacker-chosen) while persisting attested key
material, so one registration could poison another user's store entry.
These cells pin the rejection half AND the unchanged-honest-ceremony
half (truth-table rule), plus the store-after-DB-write ordering.
"""

import base64
import hashlib
import json
import struct
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor as fido2_cbor
from fido2.webauthn import ES256
from server.fido2.manager import Fido2Manager, StoredCredential, WebAuthnError
from starlette.testclient import TestClient

RP_ID = "venya-core-1"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
ATTESTED_ID = b"\xaa" * 32
VICTIM_ID = b"\xbb" * 32


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_attestation_object(cred_id: bytes, cose_key: dict, counter: int = 1) -> bytes:
    """CBOR attestation object with attested credential data (UP|UV|AT flags)."""
    aaguid = b"\x00" * 16
    cred_data = aaguid + struct.pack(">H", len(cred_id)) + cred_id + fido2_cbor.encode(cose_key)
    auth_data = RP_ID_HASH + bytes([0x45]) + struct.pack(">I", counter) + cred_data
    return bytes(fido2_cbor.encode({"fmt": "none", "authData": auth_data, "attStmt": {}}))


def _reg_client_data(manager: Fido2Manager, challenge_id: str) -> str:
    """clientDataJSON answering the manager's issued challenge (reads raw challenge before pop)."""
    raw = manager.store._challenges[challenge_id].data["raw_challenge"]
    data = {
        "type": "webauthn.create",
        "challenge": _b64url(raw),
        "origin": f"https://{RP_ID}",
        "crossOrigin": False,
    }
    return _b64url(json.dumps(data, separators=(",", ":")).encode())


def _create_test_app(fido2_manager=None, backend=None, auth_user=None):
    """Minimal test app with credential routes (shape shared with test_credentials)."""
    from fastapi import FastAPI
    from starlette.middleware.base import BaseHTTPMiddleware

    app = FastAPI()
    if fido2_manager is not None:
        app.state.fido2_manager = fido2_manager
    if backend is not None:
        app.state.backend = backend
    from server.routes import credentials

    app.include_router(credentials.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if auth_user is not None:
                request.state.auth_user = auth_user
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _make_valid_elevation_db():
    """Mock DB whose conditional elevation burn consumes 1 row."""
    from types import SimpleNamespace

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(id=1)
    db.execute.return_value = SimpleNamespace(rowcount=1)
    return db


@pytest.fixture()
def cose():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return ES256.from_cryptography_key(private_key.public_key())


def _manager():
    return Fido2Manager(rp_id=RP_ID, rp_name="Venya")


def _registration_body(
    attested_id: bytes, claimed_id: bytes, cose: dict, challenge_id: str, manager: Fido2Manager
) -> dict:
    """Browser-shape registration body: attested id inside the AO, claimed id on the response envelope."""
    ao = _build_attestation_object(attested_id, cose, counter=1)
    return {
        "challenge_id": challenge_id,
        "label": "key-416",
        "response": {
            "id": _b64url(claimed_id),
            "rawId": _b64url(claimed_id),
            "response": {
                "clientDataJSON": _reg_client_data(manager, challenge_id),
                "attestationObject": _b64url(ao),
            },
            "type": "public-key",
        },
    }


class TestManagerCrosscheck:
    """(a): response.id must equal auth_data.credential_data.credential_id, rejected before any store write."""

    def test_mismatch_poison_rejected_victim_entry_unchanged(self, cose):
        manager = _manager()
        manager.store.store_credential(
            StoredCredential(user_id="victim", credential_id=VICTIM_ID, public_key=b"victim-pub", sign_count=7)
        )
        challenge_id, _ = manager.start_registration(user_id="attacker", username="attacker")

        body = _registration_body(ATTESTED_ID, VICTIM_ID, dict(cose), challenge_id, manager)
        with pytest.raises(WebAuthnError, match="Credential ID mismatch"):
            manager.finish_registration(challenge_id, body["response"])

        victim = manager.store.get_credential(VICTIM_ID)
        assert victim.user_id == "victim"
        assert victim.public_key == b"victim-pub"
        assert victim.sign_count == 7
        assert manager.store.get_credential(ATTESTED_ID) is None
        assert len(manager.store._credentials) == 1

    def test_honest_ceremony_accepted_keyed_on_attested(self, cose):
        manager = _manager()
        challenge_id, _ = manager.start_registration(user_id="u1", username="user1")

        body = _registration_body(ATTESTED_ID, ATTESTED_ID, dict(cose), challenge_id, manager)
        cred = manager.finish_registration(challenge_id, body["response"])

        assert cred.credential_id == ATTESTED_ID
        assert cred.user_id == "u1"

    def test_success_defers_store_to_handler(self, cose):
        """(b) contract: finish_registration does NOT store — the handler persists after its DB write."""
        manager = _manager()
        challenge_id, _ = manager.start_registration(user_id="u1", username="user1")

        body = _registration_body(ATTESTED_ID, ATTESTED_ID, dict(cose), challenge_id, manager)
        manager.finish_registration(challenge_id, body["response"])

        assert manager.store._credentials == {}


class TestCredentialsAddCompleteOrdering:
    """(b) at the elevated CLI-adjacent handler: store entry survives only on DB-write success."""

    def _post(self, manager: Fido2Manager, db: MagicMock, body: dict):
        backend = MagicMock()
        backend.get_session.return_value = db
        app = _create_test_app(fido2_manager=manager, backend=backend, auth_user="user1")
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/api/v1/credentials/add/browser/complete",
            json=body,
            headers={"X-Elevation-Token": "elev-token-123"},
        )

    def test_forced_db_flush_failure_leaves_no_store_entry(self, cose):
        manager = _manager()
        challenge_id, _ = manager.start_registration(user_id="user1", username="user1")
        db = _make_valid_elevation_db()
        db.flush.side_effect = RuntimeError("simulated unique violation")

        resp = self._post(manager, db, _registration_body(ATTESTED_ID, ATTESTED_ID, dict(cose), challenge_id, manager))

        assert resp.status_code == 500
        assert db.add.called
        # THE POINT: the failed DB write leaves no surviving store entry.
        assert manager.store._credentials == {}

    def test_success_stores_after_commit_and_db_row_keyed_attested(self, cose):
        manager = _manager()
        challenge_id, _ = manager.start_registration(user_id="user1", username="user1")
        db = _make_valid_elevation_db()

        resp = self._post(manager, db, _registration_body(ATTESTED_ID, ATTESTED_ID, dict(cose), challenge_id, manager))

        assert resp.status_code == 200
        assert db.commit.called
        stored = manager.store.get_credential(ATTESTED_ID)
        assert stored is not None and stored.user_id == "user1"
        added_creds = [
            c.args[0] for c in db.add.call_args_list if getattr(c.args[0], "credential_id", None) is not None
        ]
        assert [c.credential_id for c in added_creds] == [ATTESTED_ID]

    def test_mismatch_rejected_400_no_db_add_no_store(self, cose):
        manager = _manager()
        manager.store.store_credential(
            StoredCredential(user_id="victim", credential_id=VICTIM_ID, public_key=b"victim-pub", sign_count=7)
        )
        challenge_id, _ = manager.start_registration(user_id="user1", username="user1")
        db = _make_valid_elevation_db()

        resp = self._post(manager, db, _registration_body(ATTESTED_ID, VICTIM_ID, dict(cose), challenge_id, manager))

        assert resp.status_code == 400
        assert "Credential ID mismatch" in resp.json()["detail"]
        db.add.assert_not_called()
        victim = manager.store.get_credential(VICTIM_ID)
        assert victim.public_key == b"victim-pub"
        assert manager.store.get_credential(ATTESTED_ID) is None
