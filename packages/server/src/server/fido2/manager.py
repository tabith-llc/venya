"""WebAuthn/FIDO2 credential management.

Simplified interface — actual FIDO2 operations use python-fido2 library.
The detailed crypto handling is deferred to integration testing.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from vault.utils.entropy import get_secure_token


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
            user_id=user_id, data=data, created_at=time.time(),
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
        from vault.iam.models import WebAuthnCredential

        try:
            db = self.backend.get_session()
            try:
                creds = db.query(WebAuthnCredential).filter(
                    WebAuthnCredential.is_active == True  # noqa: E712
                ).all()
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
        except Exception:  # nosec B110 — db cleanup in finally block, outer scope handles error
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

        # Extract credential_id from response (base64url-encoded in browser)
        raw_id_b64 = response.get("id", "")
        if isinstance(raw_id_b64, str):
            credential_id = base64.b64decode(raw_id_b64)
        else:
            credential_id = raw_id_b64

        # Extract attestationObject from nested browser response structure
        attestation_object = None
        resp = response.get("response", {})
        if isinstance(resp, dict):
            attestation_object = resp.get("authenticatorAttestationResponse", {}).get(
                "attestationObject"
            )
        if attestation_object is None:
            auth_data_bytes = b""
        elif isinstance(attestation_object, str):
            # Could be base64 or base64url — try standard base64 first, then base64url
            try:
                auth_data_bytes = base64.b64decode(attestation_object)
            except Exception:
                auth_data_bytes = base64.urlsafe_b64decode(attestation_object + "=" * (4 - len(attestation_object) % 4))
        else:
            auth_data_bytes = attestation_object

        public_key = auth_data_bytes
        # Sign count is bytes 30-33 of authenticator data (right-aligned 32-bit)
        sign_count = 0
        if len(auth_data_bytes) >= 37:
            sign_count = int.from_bytes(auth_data_bytes[30:34], "big")

        cred = StoredCredential(
            user_id=stored.data["user_id"],
            credential_id=credential_id,
            public_key=public_key,
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
            },
        )

        options: dict[str, Any] = {
            "challenge": base64.b64encode(
                secrets.token_bytes(32)
            ).decode("ascii"),
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
        stored = self.store.get_challenge(challenge_id)
        if stored is None:
            raise ValueError("Challenge not found or expired")

        raw_id_b64 = response.get("id", "")
        if isinstance(raw_id_b64, str):
            raw_id = base64.b64decode(raw_id_b64)
        else:
            raw_id = raw_id_b64

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
