"""Cryptographic binding for enrollment tokens.

Ties a plaintext token to the entity it was generated for (executor_id or user_id)
via HMAC-SHA256, derived from the server's recovery_code_pepper via HKDF.
"""


import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_binding_key(server_secret: str) -> bytes:
    """Derive a domain-separated key for enrollment token binding.

    Uses HKDF-SHA256 with a fixed info string to ensure the derived
    key is cryptographically distinct from any other use of the same
    server_secret (e.g., recovery code peppering).

    Args:
        server_secret: The base server secret (e.g., recovery_code_pepper).

    Returns:
        32-byte derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"venya-enrollment-token-binding-v1",
    )
    return hkdf.derive(server_secret.encode())


def compute_binding_hash(
    entity_id: str,
    plaintext_token: str,
    server_secret: str,
) -> str:
    """Compute the HMAC-SHA256 binding hash for an enrollment token.

    The binding cryptographically ties a token to the entity it was
    generated for (executor_id or user_id), so that modifying the
    ID column in the database invalidates the token even if the
    attacker knows the plaintext.

    Args:
        entity_id: The executor_id or user_id the token is bound to.
        plaintext_token: The full plaintext token string.
        server_secret: The base server secret used for key derivation.

    Returns:
        64-character hex string (SHA-256 HMAC digest).
    """
    key = derive_binding_key(server_secret)
    msg = f"{entity_id}:{plaintext_token}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_binding_hash(
    entity_id: str,
    plaintext_token: str,
    server_secret: str,
    stored_binding_hash: str | None,
) -> bool:
    """Verify a token's binding hash.

    Legacy tokens (stored_binding_hash is None or empty) are rejected
    without fallback — they must be regenerated.

    Args:
        entity_id: The executor_id or user_id from the DB record.
        plaintext_token: The plaintext token from the request.
        server_secret: The base server secret.
        stored_binding_hash: The binding_hash from the DB.

    Returns:
        True if binding matches. False if mismatch or legacy token.
    """
    if not stored_binding_hash:
        return False  # Legacy token — reject, no fallback

    expected = compute_binding_hash(entity_id, plaintext_token, server_secret)
    return hmac.compare_digest(expected, stored_binding_hash)
