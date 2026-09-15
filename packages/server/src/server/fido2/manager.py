# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""WebAuthn/FIDO2 credential management.

Simplified interface — actual FIDO2 operations use python-fido2 library.
The detailed crypto handling is deferred to integration testing.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from core.utils.entropy import get_secure_token

logger = logging.getLogger(__name__)


def _b64_decode(s: str) -> bytes:
    """Decode base64 or base64url, padded or not. Alphabets are
    distinguished by charset: '-_' never appears in standard,
    '+/' never in urlsafe. Never silently discard characters."""
    if not s:
        return b""
    padded = s + "=" * (-len(s) % 4)
    if "-" in s or "_" in s:
        return base64.b64decode(padded.translate(str.maketrans("-_", "+/")), validate=True)
    return base64.b64decode(padded, validate=True)


@dataclass
class StoredChallenge:
    """A stored WebAuthn challenge."""

    user_id: str
    data: dict[str, Any]
    created_at: float


@dataclass
class StoredCredential:
    """A stored WebAuthn credential."""

    user_id: str
    credential_id: bytes
    public_key: bytes
    sign_count: int = 0
    label: str | None = None


class Fido2Store:
    """In-memory store for WebAuthn challenges and credentials.

    In production, backed by the database.
    """

    def __init__(self) -> None:
        self._challenges: dict[str, StoredChallenge] = {}
        self._credentials: dict[bytes, StoredCredential] = {}

    def store_challenge(self, challenge_id: str, user_id: str, data: dict) -> None:
        self._challenges[challenge_id] = StoredChallenge(
            user_id=user_id,
            data=data,
            created_at=time.time(),
        )

    def get_challenge(self, challenge_id: str) -> StoredChallenge | None:
        return self._challenges.pop(challenge_id, None)

    def store_credential(self, cred: StoredCredential) -> None:
        self._credentials[cred.credential_id] = cred

    def get_credential(self, credential_id: bytes) -> StoredCredential | None:
        return self._credentials.get(credential_id)

    def get_user_credentials(self, user_id: str) -> list[StoredCredential]:
        return [c for c in self._credentials.values() if c.user_id == user_id]

    def remove_credential(self, credential_id: bytes) -> bool:
        if credential_id in self._credentials:
            del self._credentials[credential_id]
            return True
        return False


class Fido2Manager:
    """Manages WebAuthn/FIDO2 registration and authentication flows.

    Provides challenge/response interfaces that the routes use.
    The actual FIDO2 library integration is wrapped here.
    """

    def __init__(
        self,
        rp_id: str = "localhost",
        rp_name: str = "Venya",
        origins: list[str] | None = None,
        backend: Any = None,
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origins = origins or ["https://localhost"]
        self.store = Fido2Store()
        self.backend = backend
        if backend is not None:
            self._load_credentials_from_db()

    def _load_credentials_from_db(self) -> None:
        """Load WebAuthn credentials from the database into the in-memory store."""
        from core.iam.models import WebAuthnCredential

        try:
            db = self.backend.get_session()
            try:
                creds = db.query(WebAuthnCredential).filter(WebAuthnCredential.is_active.is_(True)).all()
                for db_cred in creds:
                    stored = StoredCredential(
                        user_id=db_cred.user_id,
                        credential_id=db_cred.credential_id,
                        public_key=db_cred.public_key,
                        sign_count=db_cred.sign_count,
                        label=db_cred.label,
                    )
                    self.store.store_credential(stored)
            finally:
                db.close()
        except Exception:  # nosec B110 — db cleanup in finally block, outer scope handles error  # noqa: S110
            pass

    def start_registration(
        self,
        user_id: str,
        username: str,
        existing_credential_ids: list[bytes] | None = None,
    ) -> tuple[str, dict]:
        """Start a WebAuthn registration challenge.

        Args:
            user_id: Internal user ID.
            username: Human-readable username.
            existing_credential_ids: Already-registered credential IDs to exclude.

        Returns:
            Tuple of (challenge_id, options_dict).
            The options_dict contains the PublicKeyCredentialCreationOptions
            serialized to a dict for the client.
        """
        challenge_id = get_secure_token(16)
        raw_challenge = secrets.token_bytes(32)

        # Store challenge metadata
        self.store.store_challenge(
            challenge_id,
            user_id,
            {
                "username": username,
                "user_id": user_id,
                "existing_credential_ids": existing_credential_ids or [],
                "raw_challenge": raw_challenge,
            },
        )

        # Generate challenge options
        options = {
            "challenge": base64.b64encode(raw_challenge).decode("ascii"),
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {
                "id": base64.b64encode(user_id.encode()).decode("ascii"),
                "name": username,
                "displayName": username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # RS256
                {"type": "public-key", "alg": -257},  # ES256
            ],
            "timeout": 60000,
            "excludeCredentials": [
                {"type": "public-key", "id": base64.b64encode(cid).decode("ascii")}
                for cid in (existing_credential_ids or [])
            ],
            "attestation": "none",
        }

        return challenge_id, options

    def finish_registration(
        self,
        challenge_id: str,
        response: dict,
    ) -> StoredCredential:
        """Complete WebAuthn registration.

        Args:
            challenge_id: The challenge ID from start_registration.
            response: The client's registration response as a dict.

        Returns:
            Stored credential.

        Raises:
            ValueError: If registration fails.
        """
        stored = self.store.get_challenge(challenge_id)
        if stored is None:
            raise ValueError("Challenge not found or expired")

        credential_id = _b64_decode(response.get("id", ""))
        if not credential_id:
            raise ValueError("Missing credential ID in response")

        # Extract attestationObject — try browser shape first, then CLI shape
        resp = response.get("response", {})
        attestation_object_b64 = None
        if isinstance(resp, dict):
            # Browser: response.authenticatorAttestationResponse.attestationObject
            aar = resp.get("authenticatorAttestationResponse")
            if isinstance(aar, dict):
                attestation_object_b64 = aar.get("attestationObject")
            # CLI: response.attestationObject
            if attestation_object_b64 is None:
                attestation_object_b64 = resp.get("attestationObject")

        if not attestation_object_b64:
            raise ValueError("Missing attestationObject in response")

        attestation_bytes = _b64_decode(attestation_object_b64)

        from fido2 import cbor as fido2_cbor
        from fido2.webauthn import AttestationObject

        try:
            ao = AttestationObject(attestation_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse attestation object: {e}") from e

        auth_data = ao.auth_data
        if auth_data.credential_data is None:
            raise ValueError("No attested credential data in attestation")

        cose_key = auth_data.credential_data.public_key
        public_key_bytes = fido2_cbor.encode(dict(cose_key))
        sign_count = auth_data.counter

        cred = StoredCredential(
            user_id=stored.data["user_id"],
            credential_id=credential_id,
            public_key=public_key_bytes,
            sign_count=sign_count,
        )

        self.store.store_credential(cred)
        return cred

    def start_authentication(
        self,
        user_id: str | None = None,
    ) -> tuple[str, dict]:
        """Start a WebAuthn authentication challenge.

        Args:
            user_id: Optional user ID to target a specific user.

        Returns:
            Tuple of (challenge_id, options_dict).
        """
        challenge_id = get_secure_token(16)
        raw_challenge = secrets.token_bytes(32)

        allow_credentials = None
        if user_id:
            credentials = self.store.get_user_credentials(user_id)
            if credentials:
                allow_credentials = [
                    {
                        "type": "public-key",
                        "id": base64.b64encode(c.credential_id).decode("ascii"),
                    }
                    for c in credentials
                ]

        self.store.store_challenge(
            challenge_id,
            user_id or "",
            {
                "target_user_id": user_id,
                "raw_challenge": raw_challenge,
                # Server hint is "discouraged"; CLI client enforces REQUIRED itself.
                # Intentionally decoupled — do not "fix" one to match the other.
                "user_verification": "discouraged",
            },
        )

        options: dict[str, Any] = {
            "challenge": base64.b64encode(raw_challenge).decode("ascii"),
            "rpId": self.rp_id,
            "timeout": 60000,
            "userVerification": "discouraged",
        }

        if allow_credentials:
            options["allowCredentials"] = allow_credentials

        return challenge_id, options

    def finish_authentication(
        self,
        challenge_id: str,
        response: dict,
    ) -> dict:
        """Complete WebAuthn authentication.

        Args:
            challenge_id: The challenge ID from start_authentication.
            response: The client's authentication response as a dict.

        Returns:
            Dict with user_id and credential info.

        Raises:
            ValueError: If authentication fails.
        """
        # Pop-on-read: challenge is consumed on any use (success or failure).
        # This prevents replay and oracle probing.
        stored = self.store.get_challenge(challenge_id)
        if stored is None:
            raise ValueError("Challenge not found or expired")

        raw_id = _b64_decode(response.get("id", ""))
        if not raw_id:
            raise ValueError("Missing credential ID in response")

        # Find matching credential
        credential = None
        target_user_id = stored.data.get("target_user_id")
        if target_user_id:
            for c in self.store.get_user_credentials(target_user_id):
                if c.credential_id == raw_id:
                    credential = c
                    break
        else:
            for c in self.store._credentials.values():
                if c.credential_id == raw_id:
                    credential = c
                    break

        if credential is None:
            raise ValueError("Credential not found")

        # Extract assertion components
        resp = response.get("response", {})
        if not isinstance(resp, dict):
            # ValueError is the 401 contract for all callers; TypeError would 500
            raise ValueError("Malformed assertion response")  # noqa: TRY004

        client_data_json_b64 = resp.get("clientDataJSON", "")
        auth_data_b64 = resp.get("authenticatorData", "")
        signature_b64 = resp.get("signature", "")

        if not all([client_data_json_b64, auth_data_b64, signature_b64]):
            raise ValueError("Missing assertion components (clientDataJSON, authenticatorData, or signature)")

        client_data_json_bytes = _b64_decode(client_data_json_b64)
        auth_data_bytes = _b64_decode(auth_data_b64)
        signature = _b64_decode(signature_b64)

        # Challenge binding: clientDataJSON.challenge must match the issued challenge
        try:
            client_data = json.loads(client_data_json_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError("Malformed clientDataJSON") from e

        challenge_b64url = client_data.get("challenge", "")
        challenge_bytes = _b64_decode(challenge_b64url)
        stored_challenge = stored.data.get("raw_challenge", b"")
        if challenge_bytes != stored_challenge:
            raise ValueError("Challenge mismatch: assertion does not answer the issued challenge")

        # Parse authenticator data
        from fido2.webauthn import AuthenticatorData

        try:
            auth_data = AuthenticatorData(auth_data_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse authenticator data: {e}") from e

        # rpIdHash check
        expected_rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        if auth_data.rp_id_hash != expected_rp_id_hash:
            raise ValueError("RP ID hash mismatch: authenticator registered under different RP ID")

        # UP flag (user presence) — always required
        if not auth_data.is_user_present():
            raise ValueError("User presence flag not set")

        # UV flag — only enforced when the challenge negotiated "required"
        uv_required = stored.data.get("user_verification") == "required"
        if uv_required and not auth_data.is_user_verified():
            raise ValueError("User verification flag not set (required for this challenge)")

        # Signature verification: ECDSA/RSASSA over authData || SHA-256(clientDataJSON)
        from fido2 import cbor as fido2_cbor
        from fido2.webauthn import CoseKey

        try:
            cose_key = CoseKey.parse(fido2_cbor.decode(credential.public_key))
        except Exception as e:
            raise ValueError(f"Failed to parse stored public key: {e}") from e

        client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
        message = auth_data_bytes + client_data_hash

        try:
            cose_key.verify(message, signature)
        except Exception as e:
            raise ValueError("Signature verification failed") from e

        # Counter check (clone detection) — only active for keys that report non-zero counters
        if credential.sign_count > 0 and auth_data.counter < credential.sign_count:
            raise ValueError("Signature counter regression: possible credential clone")

        # Update sign count in memory
        credential.sign_count = auth_data.counter

        # Persist to DB
        if self.backend is not None:
            from datetime import UTC, datetime

            from core.iam.models import WebAuthnCredential

            try:
                db = self.backend.get_session()
                try:
                    db_cred = (
                        db.query(WebAuthnCredential)
                        .filter(WebAuthnCredential.credential_id == credential.credential_id)
                        .first()
                    )
                    if db_cred:
                        db_cred.sign_count = auth_data.counter
                        db_cred.last_used_at = datetime.now(UTC)
                        db.commit()
                finally:
                    db.close()
            except Exception:  # nosec B110
                logger.exception("sign_count persist failed; login succeeded, counter update lost")

        return {
            "user_id": credential.user_id,
            "credential_id": base64.b64encode(credential.credential_id).decode("ascii"),
        }

    def get_user_credentials(self, user_id: str) -> list[dict]:
        """Get all registered credentials for a user."""
        return [
            {
                "credential_id": base64.b64encode(c.credential_id).decode("ascii"),
                "label": c.label,
                "sign_count": c.sign_count,
            }
            for c in self.store.get_user_credentials(user_id)
        ]

    def remove_credential(self, credential_id: bytes) -> bool:
        """Remove a registered credential."""
        return self.store.remove_credential(credential_id)
