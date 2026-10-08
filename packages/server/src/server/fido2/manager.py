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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from core.utils.entropy import get_secure_token

from .browser_adapter import base64url_encode

logger = logging.getLogger(__name__)

# Ceremony timeout (ms) actually sent to the authenticator in both option
# builders below. Stored challenges expire with a x5 grace factor,
# mirroring the #345 elevation precedent (ELEVATION_TOKEN_TTL_SECONDS * 5);
# since #534 the window is the row's expires_at, swept at the next touch.
CHALLENGE_TIMEOUT_MS = 60_000
CHALLENGE_TTL_SECONDS = CHALLENGE_TIMEOUT_MS // 1000 * 5


class WebAuthnError(ValueError):
    """User-facing WebAuthn validation failure.

    Messages are literal, operator-authored, and safe to return verbatim in
    HTTP error detail. Routes forward ``str(WebAuthnError)`` to clients but
    must NOT forward stray ``ValueError`` from library internals — those get
    a static public message and are logged server-side instead.
    """


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


def _encode_payload(value: Any) -> Any:
    """JSON-safe encode: bytes become {"__b64__": ...}, recursively.

    A ceremony payload carries raw_challenge (bytes) and
    existing_credential_ids (a list of bytes), and the DB column is JSON
    text, so byte values are tagged rather than stringified (#534).
    """
    if isinstance(value, bytes):
        return {"__b64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {k: _encode_payload(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_payload(v) for v in value]
    return value


def _decode_payload(value: Any) -> Any:
    """Inverse of _encode_payload: tagged dicts become bytes, recursing."""
    if isinstance(value, dict):
        if set(value) == {"__b64__"}:
            return base64.b64decode(value["__b64__"])
        return {k: _decode_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_payload(v) for v in value]
    return value


def _as_utc(dt: datetime) -> datetime:
    """SQLite hands back naive datetimes; the column is UTC by house law."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


@dataclass
class StoredChallenge:
    """A claimed WebAuthn challenge, read back from the table (#534)."""

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
    """WebAuthn challenge store (database) + credential startup cache (memory).

    #534: a pending ceremony challenge lives in the fido2_challenges table,
    so a core restart or a worker hop no longer vaporises a live ceremony,
    and the claim is an atomic single-consume UPDATE (house pattern:
    elevation_challenges.state from #528). Expired rows are pruned at the
    next touch — the #408 sweep, now on the DB side. Credentials keep their
    per-process cache loaded at startup (#441); that path is unchanged (AC7).

    session_factory is a zero-arg callable returning a Session. Production
    derives it from the backend (app.py passes backend only); the explicit
    kwarg on Fido2Manager lets challenge-only tests keep the credential-side
    DB gate skipped exactly as a backend-less manager skipped it before.
    """

    def __init__(self, session_factory: Any = None) -> None:
        self._sessions = session_factory
        self._credentials: dict[bytes, StoredCredential] = {}

    def _session(self):
        if self._sessions is None:
            # Fail closed loudly: with the dict gone there is no in-process
            # place to put a ceremony, so a store without a session source
            # cannot issue or claim one. Never a silent memory fallback.
            raise RuntimeError("Fido2Store challenge operations require a database session factory (#534)")
        return self._sessions()

    def _prune_expired(self, db, now: datetime) -> None:
        """Drop rows past their TTL — the #408 sweep, moved onto the table."""
        from core.iam.models import Fido2Challenge

        db.query(Fido2Challenge).filter(Fido2Challenge.expires_at < now).delete(synchronize_session=False)

    def store_challenge(self, challenge_id: str, user_id: str, data: dict) -> None:
        from core.iam.models import Fido2Challenge

        now = datetime.now(UTC)
        db = self._session()
        try:
            # Abandoned ceremonies die on the next touch, not at restart —
            # same shape as the elevation-challenge store (#528/#345).
            self._prune_expired(db, now)
            db.add(
                Fido2Challenge(
                    challenge_id=challenge_id,
                    user_id=user_id,
                    payload=json.dumps(_encode_payload(data)),
                    state="created",
                    created_at=now,
                    expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
                )
            )
            db.commit()
        finally:
            db.close()

    def get_challenge(self, challenge_id: str) -> StoredChallenge | None:
        """Atomically claim the pending row — the consume commits before any check.

        Mirrors the #528 elevation claim: UPDATE ... WHERE state='created'
        AND expires_at > now lands first, so a denied or failed ceremony
        never re-arms the challenge (the #345 pop-on-all-paths meaning
        survives). Unknown, expired, and already-consumed all take the SAME
        branch — a uniform None, no oracle on which half failed — and the
        denial writes a value-free audit row: no challenge id, no ceremony
        material (AC2).
        """
        from core.iam.models import AuditEvent, Fido2Challenge

        now = datetime.now(UTC)
        db = self._session()
        try:
            claimed = (
                db.query(Fido2Challenge)
                .filter(
                    Fido2Challenge.challenge_id == challenge_id,
                    Fido2Challenge.state == "created",
                    Fido2Challenge.expires_at > now,
                )
                .update({"state": "consumed"}, synchronize_session=False)
            )
            # The claim commits before anything else reads the row: a claim
            # that is later refused (or a process that dies mid-ceremony)
            # must not leave the challenge live for a second attempt.
            db.commit()
            # The prune rides the same touch and commits on both branches.
            self._prune_expired(db, now)
            db.commit()
            if claimed != 1:
                try:
                    db.add(
                        AuditEvent(
                            event_type="fido2_challenge_denied",
                            user_id=None,
                            fields={
                                "outcome": "denied",
                                "reason": "challenge_not_found",
                            },
                            timestamp=datetime.now(UTC),
                        )
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    logger.exception("Audit write failed on FIDO2 challenge deny (still denying)")
                return None
            row = db.query(Fido2Challenge).filter(Fido2Challenge.challenge_id == challenge_id).one()
            return StoredChallenge(
                user_id=row.user_id,
                data=_decode_payload(json.loads(row.payload)),
                created_at=_as_utc(row.created_at).timestamp(),
            )
        finally:
            db.close()

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
    The actual FIDO2 library integration is wrapped here. Pending ceremony
    state is shared through the database (#534); the credential side stays
    a per-process cache loaded at startup (#441).
    """

    def __init__(
        self,
        rp_id: str = "localhost",
        rp_name: str = "Venya",
        origins: list[str] | None = None,
        backend: Any = None,
        user_verification: str = "discouraged",
        session_factory: Any = None,
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origins = origins or ["https://localhost"]
        # Server-side UV policy for auth ceremonies (#413): recorded on each
        # challenge and enforced by the assertion-side UV branch.
        self.user_verification = user_verification
        # Challenge storage needs a session source (#534). Production wires
        # only the backend (app.py), so the store derives its sessions from
        # it; the explicit session_factory kwarg is for DB-only ceremony
        # tests that must keep the credential-side backend gate (active-state
        # check + sign_count persist) skipped exactly as a backend-less
        # manager skipped it before this change.
        self.backend = backend
        factory = session_factory
        if factory is None and backend is not None:
            factory = getattr(backend, "get_session", None)
        self.store = Fido2Store(factory)
        if backend is not None:
            self._load_credentials_from_db()

    def _load_credentials_from_db(self) -> None:
        """Load active WebAuthn credentials from the database into the in-memory store.

        #441, recovery shape (a) — fail startup loudly: a load fault is
        logged with full exception context and re-raised. The only
        production caller is the server lifespan (app.py constructs
        ``Fido2Manager(... backend=backend)`` inside ``lifespan``), whose
        startup contract already aborts on propagated exceptions — the same
        pattern as ``_init_core`` and ``_verify_kek_sentinel``, which log
        operator-actionable errors and re-raise so uvicorn exits non-zero.
        The process must never serve with a silently-empty credential
        store; the swallow is narrowed to the session close, which cannot
        change the load verdict (a close fault warns, credentials stand).
        """
        from core.iam.models import WebAuthnCredential

        loaded = 0
        db = None
        try:
            db = self.backend.get_session()
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
                loaded += 1
            logger.info("Loaded %d active WebAuthn credential(s) into the in-memory store", loaded)
        except Exception:
            logger.exception(
                "FIDO2 credential load FAILED after %d credential(s) loaded; "
                "credentials not loaded; login/enrollment assertions will fail — "
                "aborting startup",
                loaded,
            )
            raise
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    logger.warning("Failed to close DB session after credential load", exc_info=True)

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
            "timeout": CHALLENGE_TIMEOUT_MS,
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

        The returned credential is NOT placed in the in-memory store here —
        the consuming handler persists it via ``store.store_credential`` only
        after its DB write succeeds (ticket webauthn-credential-id-crosscheck
        #416, fix-shape (b): a failed DB write must leave no store entry).
        """
        stored = self.store.get_challenge(challenge_id)
        if stored is None:
            raise WebAuthnError("Challenge not found or expired")

        credential_id = _b64_decode(response.get("id", ""))
        if not credential_id:
            raise WebAuthnError("Missing credential ID in response")

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
            raise WebAuthnError("Missing attestationObject in response")

        attestation_bytes = _b64_decode(attestation_object_b64)

        from fido2 import cbor as fido2_cbor
        from fido2.webauthn import AttestationObject

        try:
            ao = AttestationObject(attestation_bytes)
        except Exception as e:
            logger.warning("Attestation object parse failed: %s", e)
            raise WebAuthnError("Failed to parse attestation object") from e

        auth_data = ao.auth_data
        if auth_data.credential_data is None:
            raise WebAuthnError("No attested credential data in attestation")

        # WebAuthn §7.1 step 21 crosscheck (ticket webauthn-credential-id-
        # crosscheck #416): the client-response id must equal the ATTESTED
        # credential id. Pre-fix the key came from response["id"]
        # (attacker-chosen) while the persisted key material came from the
        # attested object — one registration could poison another user's
        # in-memory store entry. Reject BEFORE any store/DB write, and key
        # everything off the attested id.
        attested_credential_id = auth_data.credential_data.credential_id
        if credential_id != attested_credential_id:
            raise WebAuthnError("Credential ID mismatch: response id is not the attested credential id")

        # --- Ceremony verification (WebAuthn spec steps 5-7; ticket
        # sec-auth-elevation-authz-hardening #4). Pre-fix, finish_registration
        # never parsed clientDataJSON: ANY parseable attestationObject was
        # accepted for an issued challenge — no challenge match, no origin, no
        # type, no rpIdHash, no user-presence. finish_authentication has
        # always verified its clientData; this mirrors that structure.
        # DELIBERATE DIVERGENCE (user-ruled, documented): registration
        # enforces a STRICTER RP context than authentication — origin is
        # checked HERE; finish_authentication does not check origin.
        client_data_json_b64 = None
        if isinstance(resp, dict):
            aar = resp.get("authenticatorAttestationResponse")
            if isinstance(aar, dict):
                client_data_json_b64 = aar.get("clientDataJSON")
            if client_data_json_b64 is None:
                client_data_json_b64 = resp.get("clientDataJSON")
        if not client_data_json_b64:
            raise WebAuthnError("Missing clientDataJSON in response")

        client_data_bytes = _b64_decode(client_data_json_b64)
        try:
            client_data = json.loads(client_data_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise WebAuthnError("Malformed clientDataJSON") from e

        if client_data.get("type") != "webauthn.create":
            raise WebAuthnError("Wrong clientData type: expected webauthn.create")

        challenge_bytes = _b64_decode(client_data.get("challenge", ""))
        stored_challenge = stored.data.get("raw_challenge", b"")
        if challenge_bytes != stored_challenge:
            raise WebAuthnError("Challenge mismatch: attestation does not answer the issued challenge")

        expected_origin = f"https://{self.rp_id}"
        if client_data.get("origin") != expected_origin:
            raise WebAuthnError("Origin mismatch: clientData origin is not this RP")

        # rpIdHash + user presence (mirror of finish_authentication)
        expected_rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        if auth_data.rp_id_hash != expected_rp_id_hash:
            raise WebAuthnError("RP ID hash mismatch: authenticator registered under different RP ID")

        if not auth_data.is_user_present():
            raise WebAuthnError("User presence flag not set")

        cose_key = auth_data.credential_data.public_key
        public_key_bytes = fido2_cbor.encode(dict(cose_key))
        sign_count = auth_data.counter

        cred = StoredCredential(
            user_id=stored.data["user_id"],
            credential_id=attested_credential_id,
            public_key=public_key_bytes,
            sign_count=sign_count,
        )

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
                # Recorded from the server config knob (fido2.user_verification,
                # #413); the assertion-side branch enforces it when "required".
                # The CLI client additionally enforces REQUIRED locally —
                # intentionally decoupled, do not "fix" one to match the other.
                "user_verification": self.user_verification,
            },
        )

        options: dict[str, Any] = {
            "challenge": base64.b64encode(raw_challenge).decode("ascii"),
            "rpId": self.rp_id,
            "timeout": CHALLENGE_TIMEOUT_MS,
            "userVerification": self.user_verification,
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
            raise WebAuthnError("Challenge not found or expired")

        raw_id = _b64_decode(response.get("id", ""))
        if not raw_id:
            raise WebAuthnError("Missing credential ID in response")

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
            raise WebAuthnError("Credential not found")

        # Extract assertion components
        resp = response.get("response", {})
        if not isinstance(resp, dict):
            # ValueError is the 401 contract for all callers; TypeError would 500
            raise WebAuthnError("Malformed assertion response")

        client_data_json_b64 = resp.get("clientDataJSON", "")
        auth_data_b64 = resp.get("authenticatorData", "")
        signature_b64 = resp.get("signature", "")

        if not all([client_data_json_b64, auth_data_b64, signature_b64]):
            raise WebAuthnError("Missing assertion components (clientDataJSON, authenticatorData, or signature)")

        client_data_json_bytes = _b64_decode(client_data_json_b64)
        auth_data_bytes = _b64_decode(auth_data_b64)
        signature = _b64_decode(signature_b64)

        # Challenge binding: clientDataJSON.challenge must match the issued challenge
        try:
            client_data = json.loads(client_data_json_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise WebAuthnError("Malformed clientDataJSON") from e

        challenge_b64url = client_data.get("challenge", "")
        challenge_bytes = _b64_decode(challenge_b64url)
        stored_challenge = stored.data.get("raw_challenge", b"")
        if challenge_bytes != stored_challenge:
            raise WebAuthnError("Challenge mismatch: assertion does not answer the issued challenge")

        # Parse authenticator data
        from fido2.webauthn import AuthenticatorData

        try:
            auth_data = AuthenticatorData(auth_data_bytes)
        except Exception as e:
            logger.warning("Authenticator data parse failed: %s", e)
            raise WebAuthnError("Failed to parse authenticator data") from e

        # rpIdHash check
        expected_rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        if auth_data.rp_id_hash != expected_rp_id_hash:
            raise WebAuthnError("RP ID hash mismatch: authenticator registered under different RP ID")

        # UP flag (user presence) — always required
        if not auth_data.is_user_present():
            raise WebAuthnError("User presence flag not set")

        # UV flag — only enforced when the challenge negotiated "required"
        uv_required = stored.data.get("user_verification") == "required"
        if uv_required and not auth_data.is_user_verified():
            raise WebAuthnError("User verification flag not set (required for this challenge)")

        # Signature verification: ECDSA/RSASSA over authData || SHA-256(clientDataJSON)
        from fido2 import cbor as fido2_cbor
        from fido2.webauthn import CoseKey

        try:
            cose_key = CoseKey.parse(fido2_cbor.decode(credential.public_key))
        except Exception as e:
            logger.error(
                "Stored public key parse failed for credential %s: %s",
                credential.credential_id.hex(),
                e,
            )
            raise WebAuthnError("Failed to parse stored public key") from e

        client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
        message = auth_data_bytes + client_data_hash

        try:
            cose_key.verify(message, signature)
        except Exception as e:
            raise WebAuthnError("Signature verification failed") from e

        # Counter check (clone detection) — only active for keys that report non-zero counters
        if credential.sign_count > 0 and auth_data.counter < credential.sign_count:
            raise WebAuthnError("Signature counter regression: possible credential clone")

        # Update sign count in memory
        credential.sign_count = auth_data.counter

        # Authoritative active-state gate + sign_count persist — BOTH
        # FAIL-CLOSED. The in-memory store is a per-process startup cache; the
        # DB decides whether a credential is still active (it may have been
        # soft-deleted via DELETE /credentials/{id}, possibly on another core
        # under future HA). A removed/unknown credential must never
        # authenticate: reject if the row is missing/inactive OR if the check
        # itself cannot run. Availability tradeoff (DB outage -> auth outage)
        # is deliberate and recorded in the ticket. The sign_count WRITE is
        # fail-closed TOO (ticket fido2-counter-persist-fail-closed, ruling
        # 2026-09-21): a lost counter update silently erases a future
        # clone-detection opportunity — a quiet degradation of a security
        # control — and the read side of this same block already accepts the
        # DB-outage tradeoff, so failing open on the write was an
        # inconsistency, not a safety margin. Real-world availability cost is
        # small: the DB is local PostgreSQL (writes failing while reads work
        # is rare/transient), a full outage already denies auth at session
        # validation, and a refused login is retryable.
        if self.backend is not None:
            from datetime import UTC, datetime

            from core.iam.models import WebAuthnCredential

            db = self.backend.get_session()
            try:
                try:
                    db_cred = (
                        db.query(WebAuthnCredential)
                        .filter(WebAuthnCredential.credential_id == credential.credential_id)
                        .first()
                    )
                except Exception:
                    logger.exception("credential active-state check failed; rejecting auth (fail-closed)")
                    raise WebAuthnError("Credential not found") from None
                if db_cred is None or not db_cred.is_active:
                    raise WebAuthnError("Credential not found")
                try:
                    db_cred.sign_count = auth_data.counter
                    db_cred.last_used_at = datetime.now(UTC)
                    db.commit()
                except Exception:
                    logger.exception("sign_count persist failed; refusing login (fail-closed)")
                    raise WebAuthnError(
                        "Sign-count persistence failed; login refused — retry, and check server database health"
                    ) from None
            finally:
                db.close()

        return {
            "user_id": credential.user_id,
            "credential_id": base64url_encode(credential.credential_id),
        }

    def remove_credential(self, credential_id: bytes) -> bool:
        """Remove a registered credential."""
        return self.store.remove_credential(credential_id)
