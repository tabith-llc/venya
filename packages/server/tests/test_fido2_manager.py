"""Tests for Fido2Manager registration and authentication verification.

Verifies the critical security path: COSE key extraction from attestation
objects and ECDSA signature verification on assertions.
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
from server.fido2.manager import Fido2Manager, StoredCredential, _b64_decode

RP_ID = "venya-core-1"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture()
def es256_keypair():
    """Generate an ES256 (P-256) key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture()
def manager(es256_keypair):
    """Fido2Manager with no backend (in-memory only)."""
    return Fido2Manager(rp_id=RP_ID, rp_name="Venya")


@pytest.fixture()
def cose_key_bytes(es256_keypair):
    """CBOR-encoded COSE key for the fixture's public key."""
    _, public_key = es256_keypair
    cose = ES256.from_cryptography_key(public_key)
    return fido2_cbor.encode(dict(cose))


def _build_attestation_object(
    cred_id: bytes,
    cose_key: dict,
    counter: int = 1,
    rp_id_hash: bytes = RP_ID_HASH,
) -> bytes:
    """Build a CBOR-encoded attestation object with attested credential data."""
    aaguid = b"\x00" * 16
    cred_data = aaguid + struct.pack(">H", len(cred_id)) + cred_id + fido2_cbor.encode(cose_key)
    # Flags: UP(0x01) | UV(0x04) | AT(0x40) = 0x45
    auth_data = rp_id_hash + bytes([0x45]) + struct.pack(">I", counter) + cred_data
    ao = fido2_cbor.encode({"fmt": "none", "authData": auth_data, "attStmt": {}})
    return bytes(ao)


def _build_auth_data(
    counter: int,
    rp_id_hash: bytes = RP_ID_HASH,
    uv: bool = True,
) -> bytes:
    """Build assertion authenticator data (no credential data)."""
    flags = 0x01  # UP
    if uv:
        flags |= 0x04  # UV
    return rp_id_hash + bytes([flags]) + struct.pack(">I", counter)


def _build_client_data_json(challenge: bytes, rp_id: str = RP_ID) -> bytes:
    """Build clientDataJSON bytes for an assertion."""
    data = {
        "type": "webauthn.get",
        "challenge": _b64url(challenge),
        "origin": f"https://{rp_id}",
        "crossOrigin": False,
    }
    return json.dumps(data, separators=(",", ":")).encode()


def _sign(private_key, auth_data: bytes, client_data_json: bytes) -> bytes:
    """Create ECDSA P-256 SHA-256 signature over authData || SHA256(clientDataJSON)."""
    message = auth_data + hashlib.sha256(client_data_json).digest()
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestFinishRegistration:
    def test_browser_shape_extracts_cose_key(self, manager, es256_keypair, cose_key_bytes):
        """Browser-shaped response: attestationObject under authenticatorAttestationResponse."""
        _, public_key = es256_keypair
        cred_id = b"\xaa" * 32
        cose = ES256.from_cryptography_key(public_key)
        ao = _build_attestation_object(cred_id, dict(cose), counter=3)

        challenge_id, _ = manager.start_registration(user_id="u1", username="user1")
        response = {
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

        cred = manager.finish_registration(challenge_id, response)
        assert cred.credential_id == cred_id
        assert cred.public_key == cose_key_bytes
        assert cred.sign_count == 3

    def test_cli_shape_extracts_cose_key(self, manager, es256_keypair, cose_key_bytes):
        """CLI-shaped response: attestationObject directly under response."""
        _, public_key = es256_keypair
        cred_id = b"\xbb" * 32
        cose = ES256.from_cryptography_key(public_key)
        ao = _build_attestation_object(cred_id, dict(cose), counter=0)

        challenge_id, _ = manager.start_registration(user_id="u2", username="user2")
        response = {
            "id": _b64url(cred_id),
            "rawId": _b64url(cred_id),
            "response": {
                "clientDataJSON": _b64url(b"{}"),
                "attestationObject": _b64url(ao),
                "transports": [],
            },
            "type": "public-key",
        }

        cred = manager.finish_registration(challenge_id, response)
        assert cred.credential_id == cred_id
        assert cred.public_key == cose_key_bytes
        assert cred.sign_count == 0

    def test_missing_attestation_object_raises(self, manager):
        """Response without attestationObject must raise ValueError."""
        challenge_id, _ = manager.start_registration(user_id="u1", username="user1")
        response = {
            "id": _b64url(b"\xcc" * 32),
            "response": {"clientDataJSON": _b64url(b"{}")},
        }
        with pytest.raises(ValueError, match="Missing attestationObject"):
            manager.finish_registration(challenge_id, response)


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------


def _store_credential(manager, user_id: str, cred_id: bytes, public_key: bytes, sign_count: int = 0):
    """Directly store a credential in the manager's in-memory store."""
    cred = StoredCredential(
        user_id=user_id,
        credential_id=cred_id,
        public_key=public_key,
        sign_count=sign_count,
    )
    manager.store.store_credential(cred)


def _build_assertion_response(
    cred_id: bytes,
    private_key,
    raw_challenge: bytes,
    counter: int,
    rp_id: str = RP_ID,
    uv: bool = True,
    tamper_signature: bool = False,
) -> dict:
    """Build a complete assertion response dict."""
    auth_data = _build_auth_data(counter, rp_id_hash=hashlib.sha256(rp_id.encode()).digest(), uv=uv)
    client_data_json = _build_client_data_json(raw_challenge, rp_id)
    signature = _sign(private_key, auth_data, client_data_json)

    if tamper_signature:
        sig_bytes = bytearray(signature)
        sig_bytes[0] ^= 0xFF
        signature = bytes(sig_bytes)

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


class TestFinishAuthentication:
    def test_valid_signature_success(self, manager, es256_keypair, cose_key_bytes):
        """Valid ES256 assertion with matching challenge → success, sign_count updated."""
        private_key, _ = es256_keypair
        cred_id = b"\xdd" * 32
        _store_credential(manager, "u1", cred_id, cose_key_bytes, sign_count=0)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]

        response = _build_assertion_response(cred_id, private_key, raw_challenge, counter=1)
        result = manager.finish_authentication(challenge_id, response)

        assert result["user_id"] == "u1"
        assert result["credential_id"] == _b64std(cred_id)

        # sign_count updated in memory
        stored_cred = manager.store.get_credential(cred_id)
        assert stored_cred is not None
        assert stored_cred.sign_count == 1

    def test_tampered_signature_rejected(self, manager, es256_keypair, cose_key_bytes):
        """Tampered signature → ValueError with 'Signature verification failed'."""
        private_key, _ = es256_keypair
        cred_id = b"\xee" * 32
        _store_credential(manager, "u1", cred_id, cose_key_bytes, sign_count=0)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]

        response = _build_assertion_response(cred_id, private_key, raw_challenge, counter=1, tamper_signature=True)
        with pytest.raises(ValueError, match="Signature verification failed"):
            manager.finish_authentication(challenge_id, response)

    def test_replayed_assertion_rejected(self, manager, es256_keypair, cose_key_bytes):
        """Challenge consumed on first use → second call with same challenge_id fails."""
        private_key, _ = es256_keypair
        cred_id = b"\xff" * 32
        _store_credential(manager, "u1", cred_id, cose_key_bytes, sign_count=0)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]

        response = _build_assertion_response(cred_id, private_key, raw_challenge, counter=1)

        # First use succeeds
        manager.finish_authentication(challenge_id, response)

        # Replay: challenge already consumed
        with pytest.raises(ValueError, match="Challenge not found or expired"):
            manager.finish_authentication(challenge_id, response)

    def test_challenge_mismatch_rejected(self, manager, es256_keypair, cose_key_bytes):
        """Assertion with wrong challenge in clientDataJSON → 'Challenge mismatch'."""
        private_key, _ = es256_keypair
        cred_id = b"\x11" * 32
        _store_credential(manager, "u1", cred_id, cose_key_bytes, sign_count=0)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        # Use a DIFFERENT challenge in the assertion
        wrong_challenge = b"\x99" * 32
        response = _build_assertion_response(cred_id, private_key, wrong_challenge, counter=1)

        with pytest.raises(ValueError, match="Challenge mismatch"):
            manager.finish_authentication(challenge_id, response)

    def test_wrong_credential_id_rejected(self, manager, es256_keypair, cose_key_bytes):
        """Assertion with unregistered credential ID → 'Credential not found'."""
        private_key, _ = es256_keypair
        _store_credential(manager, "u1", b"\x22" * 32, cose_key_bytes, sign_count=0)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]

        # Use a credential ID that doesn't exist in the store
        unknown_cred_id = b"\x33" * 32
        response = _build_assertion_response(unknown_cred_id, private_key, raw_challenge, counter=1)

        with pytest.raises(ValueError, match="Credential not found"):
            manager.finish_authentication(challenge_id, response)

    def test_counter_regression_rejected(self, manager, es256_keypair, cose_key_bytes):
        """Assertion with counter < stored counter → 'counter regression'."""
        private_key, _ = es256_keypair
        cred_id = b"\x44" * 32
        # Stored counter is 10; assertion claims counter 5 → regression
        _store_credential(manager, "u1", cred_id, cose_key_bytes, sign_count=10)

        challenge_id, _ = manager.start_authentication(user_id="u1")
        raw_challenge = manager.store._challenges[challenge_id].data["raw_challenge"]

        response = _build_assertion_response(cred_id, private_key, raw_challenge, counter=5)

        with pytest.raises(ValueError, match="Signature counter regression"):
            manager.finish_authentication(challenge_id, response)


# ---------------------------------------------------------------------------
# _b64_decode helper tests
# ---------------------------------------------------------------------------


class TestB64Decode:
    def test_standard_base64_with_padding(self):
        data = b"hello world"
        encoded = base64.b64encode(data).decode()
        assert _b64_decode(encoded) == data

    def test_base64url_without_padding(self):
        data = b"test\x00data"
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert _b64_decode(encoded) == data

    def test_empty_string(self):
        assert _b64_decode("") == b""

    def test_standard_base64_without_padding(self):
        data = b"\xfb\xff\xfe"
        encoded = base64.b64encode(data).decode()
        assert "+" in encoded and "/" in encoded
        assert _b64_decode(encoded) == data

    def test_base64url_special_chars_unpadded(self):
        """Payload whose urlsafe form contains both '-' and '_' (the dual-shape case)."""
        data = b"\xfb\xff\xfe"
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert "-" in encoded and "_" in encoded
        assert _b64_decode(encoded) == data

    def test_base64url_special_chars_padded(self):
        data = b"\xfb\xf0"
        encoded = base64.urlsafe_b64encode(data).decode()
        assert "-" in encoded and "_" in encoded
        assert _b64_decode(encoded) == data

    def test_garbage_char_raises(self):
        """Non-alphabet chars must raise, never silently drop.

        QQ!QQ is the length-favorable shape: dropping '!' leaves four valid
        chars that decode silently under validate=False. QQ!Q raises on
        length alone and is the secondary check.
        """
        with pytest.raises(ValueError):
            _b64_decode("QQ!QQ")
        with pytest.raises(ValueError):
            _b64_decode("QQ!Q")
