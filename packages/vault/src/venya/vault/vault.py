"""Vault facade: get/put/delete/list with RBAC enforcement and rate limiting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .backend import Backend, BackendConfig
from .rate_limiter import RateLimiter


class AccessLevel(str, Enum):
    """Vault-enforced access levels."""

    MASKED = "masked"
    PLAINTEXT = "plaintext"


class Caller(str, Enum):
    """Types of callers that access the vault."""

    HUMAN = "human"
    EXECUTOR = "executor"


@dataclass
class SecretRecord:
    """Represents a stored secret."""

    id: str
    key: str
    encrypted_value: bytes
    nonce: bytes
    wrapped_dek: bytes
    key_version_id: str
    created_by: str
    created_at: datetime
    role_ids: list[str] = field(default_factory=list)


class VaultError(Exception):
    """Base vault error."""


class VaultAccessError(VaultError):
    """Access denied."""


class VaultRateLimitError(VaultError):
    """Rate limit exceeded."""


class Vault:
    """Vault facade providing get/put/delete/list with RBAC and rate limiting.

    Vault-enforced access levels:
    - Human (CLI): Returns masked value by default, plaintext after re-auth
    - Executor (mTLS): Returns plaintext by design, time-boxed and scoped
    """

    def __init__(
        self,
        backend: Backend,
        rate_limiter: RateLimiter | None = None,
        kek: bytes | None = None,
    ) -> None:
        self.backend = backend
        self.rate_limiter = rate_limiter or RateLimiter()
        self.kek = kek

    def get(
        self,
        secret_key: str,
        caller: Caller = Caller.HUMAN,
        unmask: bool = False,
        user_id: str | None = None,
        role_ids: list[str] | None = None,
    ) -> str:
        """Retrieve a secret.

        Args:
            secret_key: The secret key to retrieve.
            caller: Type of caller (human or executor).
            unmask: Whether to return plaintext (requires re-auth for humans).
            user_id: ID of the requesting user.
            role_ids: Roles to check access against.

        Returns:
            Masked value (default) or plaintext (if unmask=True for humans,
            or caller=executor).

        Raises:
            VaultAccessError: If access is denied.
            VaultRateLimitError: If rate limit exceeded.
        """
        if user_id:
            self.rate_limiter.check(user_id)

        # Check role access
        if role_ids:
            # TODO: Verify user has read access to the secret's roles
            pass

        # For executor: always plaintext
        if caller == Caller.EXECUTOR:
            return self._decrypt_secret(secret_key)

        # For human: masked by default
        if not unmask:
            return "\u2022" * 8  # ••••••••

        # Human with unmask: requires re-auth (enforced at server level)
        return self._decrypt_secret(secret_key)

    def put(
        self,
        key: str,
        value: bytes,
        user_id: str,
        role_ids: list[str],
        key_version_id: str,
    ) -> SecretRecord:
        """Store a secret.

        Args:
            key: Secret key.
            value: Secret value as bytes.
            user_id: ID of the user storing the secret.
            role_ids: Roles to scope the secret to.
            key_version_id: Key version to use for encryption.

        Returns:
            The created secret record.

        Raises:
            VaultAccessError: If user doesn't have write access.
        """
        # TODO: Verify user has write access to all specified roles
        if not role_ids:
            raise VaultAccessError("Secret must be scoped to at least one role")

        # Encrypt the secret
        if self.kek is None:
            raise VaultError("KEK not configured")

        wrapped_dek, nonce, ciphertext = self._encrypt(value)

        # TODO: Insert into database
        record = SecretRecord(
            id="",  # TODO: Get from DB
            key=key,
            encrypted_value=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            key_version_id=key_version_id,
            created_by=user_id,
            created_at=datetime.now(),
            role_ids=role_ids,
        )

        return record

    def delete(self, key: str, user_id: str) -> bool:
        """Delete a secret.

        Args:
            key: Secret key to delete.
            user_id: ID of the requesting user.

        Returns:
            True if deleted, False if not found.

        Raises:
            VaultAccessError: If user doesn't have write access.
        """
        # TODO: Verify user has write access
        # TODO: Delete from database
        return True

    def list(
        self,
        prefix: str | None = None,
        user_id: str | None = None,
        role_ids: list[str] | None = None,
    ) -> list[SecretRecord]:
        """List secrets, optionally filtered by prefix.

        Args:
            prefix: Optional key prefix to filter by.
            user_id: ID of the requesting user.
            role_ids: Roles to filter secrets by.

        Returns:
            List of secret records the user has read access to.
        """
        # TODO: Query database with role-based filtering
        return []

    def _encrypt(self, value: bytes) -> tuple[bytes, bytes, bytes]:
        """Encrypt a value using the vault's KEK."""
        from .encryption import encrypt_secret

        if self.kek is None:
            raise VaultError("KEK not configured")
        return encrypt_secret(self.kek, value)

    def _decrypt_secret(self, key: str) -> str:
        """Decrypt and return a secret value."""
        # TODO: Retrieve from database and decrypt
        # For now, raise NotImplementedError
        raise NotImplementedError("Database integration not yet implemented")
