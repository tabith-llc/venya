"""Core facade: get/put/delete/list with RBAC enforcement and rate limiting."""


from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_

from ..iam.models import Secret, SecretRole, Role, RoleMember
from .backend import Backend, BackendConfig
from .encryption import decrypt_secret as _decrypt_secret_impl
from .rate_limiter import RateLimiter


class Caller(str):
    """Types of callers that access the core."""

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
    role_names: list[str] = field(default_factory=list)


class CoreError(Exception):
    """Base core error."""


class CoreAccessError(CoreError):
    """Access denied."""


class CoreRateLimitError(CoreError):
    """Rate limit exceeded."""


class Core:
    """Core facade providing get/put/delete/list with RBAC and rate limiting.

    Core-enforced access levels:
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
        caller: str = "human",
        unmask: bool = False,
        user_id: str | None = None,
        role_names: list[str] | None = None,
    ) -> str:
        """Retrieve a secret.

        Args:
            secret_key: The secret key to retrieve.
            caller: Type of caller (human or executor).
            unmask: Whether to return plaintext (requires re-auth for humans).
            user_id: ID of the requesting user (required).
            role_names: Role names to check access against.

        Returns:
            Masked value (default) or plaintext (if unmask=True for humans,
            or caller=executor).

        Raises:
            CoreAccessError: If access is denied.
            CoreRateLimitError: If rate limit exceeded.
        """
        if user_id is None:
            raise CoreAccessError("user_id is required for secret retrieval")

        self.rate_limiter.check(user_id)

        session = self.backend.get_session()
        try:
            # Look up the secret with scoping
            if role_names:
                # Role-based join: find secret accessible via provided roles
                secret = (
                    session.query(Secret)
                    .join(SecretRole, SecretRole.secret_id == Secret.id)
                    .join(Role, Role.id == SecretRole.role_id)
                    .filter(
                        Secret.key == secret_key,
                        Role.name.in_(role_names),
                    )
                    .first()
                )
            else:
                # Ownership fallback: only the creator can retrieve
                secret = (
                    session.query(Secret)
                    .filter(
                        Secret.key == secret_key,
                        Secret.created_by == user_id,
                    )
                    .first()
                )

            if secret is None:
                raise CoreAccessError(f"Secret not found: {secret_key}")

            # Check role access if role_names provided
            if role_names:
                secret_roles = (
                    session.query(SecretRole)
                    .filter(SecretRole.secret_id == secret.id)
                    .all()
                )
                secret_role_ids = {sr.role_id for sr in secret_roles}

                # Get role IDs for the named roles
                named_roles = (
                    session.query(Role.id)
                    .filter(Role.name.in_(role_names))
                    .all()
                )
                named_role_ids = {r.id for r in named_roles}

                if not secret_role_ids.intersection(named_role_ids):
                    raise CoreAccessError(
                        "User lacks access to any of the required roles"
                    )

            # For executor: always plaintext
            if caller == Caller.EXECUTOR:
                plaintext = self._decrypt_secret(secret)
                return plaintext

            # For human: masked by default
            if not unmask:
                return "\u2022" * 8  # ••••••••

            # Human with unmask: requires re-auth (enforced at server level)
            plaintext = self._decrypt_secret(secret)
            return plaintext
        finally:
            session.close()

    def put(
        self,
        key: str,
        value: bytes,
        user_id: str,
        role_names: list[str],
        key_version_id: str,
    ) -> SecretRecord:
        """Store a secret.

        Args:
            key: Secret key.
            value: Secret value as bytes.
            user_id: ID of the user storing the secret.
            role_names: Role names to scope the secret to.
            key_version_id: Key version to use for encryption.

        Returns:
            The created secret record.

        Raises:
            CoreAccessError: If user doesn't have write access.
        """

        if not role_names:
            raise CoreAccessError("Secret must be scoped to at least one role")

        if self.kek is None:
            raise CoreError("KEK not configured")

        # Encrypt the secret
        wrapped_dek, nonce, ciphertext = self.encrypt(value)

        session = self.backend.get_session()
        try:
            # Create the secret record
            secret = Secret(
                key=key,
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                key_version_id=key_version_id,
                created_by=user_id,
                created_at=datetime.now(timezone.utc),
            )
            session.add(secret)
            session.flush()

            # Link roles
            for role_name in role_names:
                role = (
                    session.query(Role)
                    .filter(Role.name == role_name)
                    .first()
                )
                if role is None:
                    raise CoreAccessError(f"Role not found: {role_name}")
                session.add(SecretRole(secret_id=secret.id, role_id=role.id))

            session.commit()

            record = SecretRecord(
                id=str(secret.id),
                key=secret.key,
                encrypted_value=secret.encrypted_value,
                nonce=secret.nonce,
                wrapped_dek=secret.wrapped_dek,
                key_version_id=secret.key_version_id,
                created_by=secret.created_by,
                created_at=secret.created_at,
                role_names=role_names,
            )

            return record
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def delete(self, key: str, user_id: str) -> bool:
        """Delete a secret.

        Args:
            key: Secret key to delete.
            user_id: ID of the requesting user.

        Returns:
            True if deleted, False if not found.

        Raises:
            CoreAccessError: If user doesn't have write access.
        """

        session = self.backend.get_session()
        try:
            secret = (
                session.query(Secret)
                .filter(
                    Secret.key == key,
                    Secret.created_by == user_id,
                )
                .first()
            )

            if secret is None:
                return False

            # Ownership check as defense-in-depth (redundant with query scope)
            if secret.created_by != user_id:
                raise CoreAccessError("You do not own this secret")

            # Delete secret roles first (foreign key constraint)
            session.query(SecretRole).filter(
                SecretRole.secret_id == secret.id
            ).delete()

            # Delete the secret
            session.delete(secret)
            session.commit()
            return True
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def list(
        self,
        prefix: str | None = None,
        user_id: str | None = None,
        role_names: list[str] | None = None,
    ) -> list[SecretRecord]:
        """List secrets, optionally filtered by prefix.

        Args:
            prefix: Optional key prefix to filter by.
            user_id: ID of the requesting user.
            role_names: Role names to filter secrets by.

        Returns:
            List of secret records the user has read access to.
        """

        session = self.backend.get_session()
        try:
            query = session.query(Secret).join(SecretRole)

            if prefix:
                query = query.filter(Secret.key.like(f"{prefix}%"))

            if role_names:
                # Get role IDs for the named roles
                named_roles = (
                    session.query(Role.id)
                    .filter(Role.name.in_(role_names))
                    .all()
                )
                named_role_ids = {r.id for r in named_roles}
                if named_role_ids:
                    query = query.filter(
                        SecretRole.role_id.in_(named_role_ids)
                    )

            secrets = query.distinct().all()

            roles_by_secret: dict[int, list[str]] = {}
            if secrets:
                secret_ids = [s.id for s in secrets]
                role_rows = (
                    session.query(SecretRole.secret_id, Role.name)
                    .join(Role, SecretRole.role_id == Role.id)
                    .filter(SecretRole.secret_id.in_(secret_ids))
                    .all()
                )
                for sid, rname in role_rows:
                    roles_by_secret.setdefault(sid, []).append(rname)

            records = []
            for secret in secrets:
                records.append(SecretRecord(
                    id=str(secret.id),
                    key=secret.key,
                    encrypted_value=secret.encrypted_value,
                    nonce=secret.nonce,
                    wrapped_dek=secret.wrapped_dek,
                    key_version_id=secret.key_version_id,
                    created_by=secret.created_by,
                    created_at=secret.created_at,
                    role_names=roles_by_secret.get(secret.id, []),
                ))

            return records
        finally:
            session.close()

    def encrypt(self, value: bytes) -> tuple[bytes, bytes, bytes]:
        """Encrypt a value using the core's KEK.

        Returns:
            Tuple of (wrapped_dek, nonce, ciphertext).

        Raises:
            CoreError: If KEK not configured.
        """
        if self.kek is None:
            raise CoreError("KEK not configured")

        from .encryption import encrypt_secret

        return encrypt_secret(self.kek, value)

    def _decrypt_secret(self, secret: Secret) -> str:
        """Decrypt and return a secret value from a Secret ORM object."""
        if self.kek is None:
            raise CoreError("KEK not configured")

        plaintext = _decrypt_secret_impl(
            self.kek,
            secret.wrapped_dek,
            secret.nonce,
            secret.encrypted_value,
        )
        return plaintext.decode("utf-8")
