# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Server-side UV config knob (ticket #413, ruled shape (a)).

Pre-fix, start_authentication hardcoded user_verification "discouraged",
so the assertion-side UV branch was unreachable under any setting. These
cells pin the truth table: required + no UV -> rejected; required + UV ->
gate passes; discouraged/preferred + no UV -> accepted (default installs
see byte-identical behavior).
"""

import base64
import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor as fido2_cbor
from fido2.webauthn import ES256
from pydantic import ValidationError
from server.config import Fido2Config
from server.fido2.manager import Fido2Manager, StoredCredential, WebAuthnError

RP_ID = "venya-core-1"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture()
def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture()
def cose_key_bytes(keypair):
    _, public_key = keypair
    return fido2_cbor.encode(dict(ES256.from_cryptography_key(public_key)))


def _auth_data(counter: int, uv: bool) -> bytes:
    flags = 0x01 | (0x04 if uv else 0x00)  # UP, optional UV
    return RP_ID_HASH + bytes([flags]) + struct.pack(">I", counter)


def _assertion_response(cred_id: bytes, private_key, raw_challenge: bytes, counter: int, uv: bool) -> dict:
    auth_data = _auth_data(counter, uv)
    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": _b64url(raw_challenge),
            "origin": f"https://{RP_ID}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    message = auth_data + hashlib.sha256(client_data_json).digest()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
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


def _run_auth(manager: Fido2Manager, keypair, cose_key_bytes, uv: bool):
    private_key, _ = keypair
    cred_id = b"\xcc" * 32
    manager.store.store_credential(
        StoredCredential(user_id="u1", credential_id=cred_id, public_key=cose_key_bytes, sign_count=0)
    )
    challenge_id, options = manager.start_authentication(user_id="u1")
    raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]
    response = _assertion_response(cred_id, private_key, raw_challenge, counter=1, uv=uv)
    return challenge_id, options, response


class TestUvKnobRecording:
    def test_knob_recorded_on_challenge_and_options(self, keypair, cose_key_bytes):
        manager = Fido2Manager(rp_id=RP_ID, user_verification="required")
        challenge_id, options = manager.start_authentication(user_id="u1")
        assert manager.store._challenges[challenge_id].data["user_verification"] == "required"
        assert options["userVerification"] == "required"

    def test_default_knob_is_discouraged(self, keypair, cose_key_bytes):
        manager = Fido2Manager(rp_id=RP_ID)
        challenge_id, options = manager.start_authentication(user_id="u1")
        assert manager.store._challenges[challenge_id].data["user_verification"] == "discouraged"
        assert options["userVerification"] == "discouraged"


class TestUvAssertionTruthTable:
    def test_required_no_uv_rejected(self, keypair, cose_key_bytes):
        manager = Fido2Manager(rp_id=RP_ID, user_verification="required")
        challenge_id, _, response = _run_auth(manager, keypair, cose_key_bytes, uv=False)
        with pytest.raises(WebAuthnError, match="User verification flag not set"):
            manager.finish_authentication(challenge_id, response)

    def test_required_with_uv_passes_gate(self, keypair, cose_key_bytes):
        manager = Fido2Manager(rp_id=RP_ID, user_verification="required")
        challenge_id, _, response = _run_auth(manager, keypair, cose_key_bytes, uv=True)
        result = manager.finish_authentication(challenge_id, response)
        assert result["user_id"] == "u1"

    @pytest.mark.parametrize("knob", ["discouraged", "preferred"])
    def test_non_required_no_uv_accepted(self, knob, keypair, cose_key_bytes):
        """Regression half: exactly the pre-fix behavior — the UV gate does not fire."""
        manager = Fido2Manager(rp_id=RP_ID, user_verification=knob)
        challenge_id, _, response = _run_auth(manager, keypair, cose_key_bytes, uv=False)
        result = manager.finish_authentication(challenge_id, response)
        assert result["user_id"] == "u1"


class TestUvConfigValidation:
    def test_valid_values_accepted(self):
        for value in ("discouraged", "preferred", "required"):
            assert Fido2Config(user_verification=value).user_verification == value

    def test_default_is_discouraged(self):
        assert Fido2Config().user_verification == "discouraged"

    def test_invalid_value_fails_fast(self):
        with pytest.raises(ValidationError, match="discouraged, preferred, required"):
            Fido2Config(user_verification="sometimes")
