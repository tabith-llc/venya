# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Core facade: get/put/delete/list with RBAC enforcement and rate limiting."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import or_

from ..iam.models import Role, Secret, SecretRole, SessionSecret
from .backend import Backend
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
    meta: dict | None = None
    replaced: bool = False  # True when put() replaced a visible existing row


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

    def _resolve_secret_in(
        self,
        session,
        secret_key: str,
        user_id: str | None,
        role_names: list[str] | None = None,
    ) -> Secret | None:
        """Single enforcement point for secret visibility.

        A secret is visible to the caller iff any of the caller's role_names
        is in the secret's role scope, OR the caller created it. No admin
        bypass: the admin role matches only admin-scoped secrets. Returns
        None when neither holds — callers MUST treat that as "not found" so
        scoped-out keys are indistinguishable from nonexistent ones (no
        cross-role key-name enumeration).
        """
        query = session.query(Secret).filter(Secret.key == secret_key)
        if role_names:
            role_ids = session.query(Role.id).filter(Role.name.in_(role_names))
            scoped_ids = session.query(SecretRole.secret_id).filter(SecretRole.role_id.in_(role_ids))
            if user_id is not None:
                query = query.filter(or_(Secret.id.in_(scoped_ids), Secret.created_by == user_id))
            else:
                query = query.filter(Secret.id.in_(scoped_ids))
        else:
            # No roles supplied: ownership only (legacy core.get semantics)
            query = query.filter(Secret.created_by == user_id)
        return query.order_by(Secret.id).first()

    def get_for_injection(
        self, secret_key: str, user_id: str, role_names: list[str] | None = None
    ) -> tuple[int, str, dict]:
        """Resolve + decrypt a secret for session injection (server-side only).

        Returns (secret_id, plaintext, meta). Raises CoreAccessError when the
        secret is not visible to the caller (role-scoped out and not the
        creator) — routes map that to 404 "Secret not found", indistinguishable
        from a nonexistent key.
        """
        if user_id is None:
            raise CoreAccessError("user_id is required for secret injection")

        session = self.backend.get_session()
        try:
            secret = self._resolve_secret_in(session, secret_key, user_id, role_names)
            if secret is None:
                raise CoreAccessError(f"Secret not found: {secret_key}")
            return secret.id, self.decrypt_secret(secret), dict(secret.meta or {})
        finally:
            session.close()

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
            # Visibility: role-scoped match OR creator (single enforcement
            # point — _resolve_secret_in). Scoped-out and nonexistent keys are
            # indistinguishable.
            secret = self._resolve_secret_in(session, secret_key, user_id, role_names)

            if secret is None:
                raise CoreAccessError(f"Secret not found: {secret_key}")

            # For executor: always plaintext
            if caller == Caller.EXECUTOR:
                plaintext = self.decrypt_secret(secret)
                return plaintext

            # For human: masked by default
            if not unmask:
                return "\u2022" * 8  # ••••••••

            # Human with unmask: requires re-auth (enforced at server level)
            plaintext = self.decrypt_secret(secret)
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
        meta: dict | None = None,
        caller_roles: list[str] | None = None,
    ) -> SecretRecord:
        """Store a secret (upsert on a visible existing key).

        Args:
            key: Secret key.
            value: Secret value as bytes.
            user_id: ID of the user storing the secret.
            role_names: Role names to scope the secret to.
            key_version_id: Key version to use for encryption.
            meta: Structured metadata for discovery (executor, purpose, etc.).
            caller_roles: The caller's ACTUAL role names (fresh from the DB —
                NOT user_info["roles"], which carries role IDs). Used solely
                to resolve an existing row for replacement; omit for
                creator-only upsert semantics.

        Upsert semantics (ticket cli-store-force-field-ignored option-2
        ruling): if the key resolves for this caller under the SAME
        visibility primitive as get/inject/list (role in scope OR creator),
        the existing row is REPLACED in place — value re-encrypted,
        key_version_id/meta/role links overwritten, row id preserved
        (injection path /run/secrets/venya/<pk> and FK refs stay stable) and
        created_by immutable (audit lineage). A key that exists but is
        scoped-out for the caller resolves to None → a second row is
        INSERTED exactly as before: no existence leak (identical 201 shape),
        no cross-role clobber. You may replace exactly what you may see —
        replacing is never worse than deleting, which visibility already
        allows.

        Returns:
            The stored secret record; record.replaced distinguishes
            replace-in-place (True) from insert (False).

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
            existing = self._resolve_secret_in(session, key, user_id, caller_roles)

            if existing is not None:
                # Replace in place — id + created_by preserved (see docstring).
                existing.encrypted_value = ciphertext
                existing.nonce = nonce
                existing.wrapped_dek = wrapped_dek
                existing.key_version_id = key_version_id
                existing.meta = meta or {}
                session.query(SecretRole).filter(SecretRole.secret_id == existing.id).delete()
                for role_name in role_names:
                    role = session.query(Role).filter(Role.name == role_name).first()
                    if role is None:
                        raise CoreAccessError(f"Role not found: {role_name}")
                    session.add(SecretRole(secret_id=existing.id, role_id=role.id))
                session.commit()
                return SecretRecord(
                    id=str(existing.id),
                    key=existing.key,
                    encrypted_value=existing.encrypted_value,
                    nonce=existing.nonce,
                    wrapped_dek=existing.wrapped_dek,
                    key_version_id=existing.key_version_id,
                    created_by=existing.created_by,
                    created_at=existing.created_at,
                    role_names=role_names,
                    meta=existing.meta,
                    replaced=True,
                )

            # Create the secret record
            secret = Secret(
                key=key,
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                key_version_id=key_version_id,
                created_by=user_id,
                created_at=datetime.now(UTC),
                meta=meta or {},
            )
            session.add(secret)
            session.flush()

            # Link roles
            for role_name in role_names:
                role = session.query(Role).filter(Role.name == role_name).first()
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
            session.query(SecretRole).filter(SecretRole.secret_id == secret.id).delete()

            # Delete ephemeral execution-session links (foreign key
            # constraint). Expired sessions must not block secret
            # deletion/rotation (secret-delete-fk-500); audit history
            # references secret ids as data and stays intact.
            session.query(SessionSecret).filter(SessionSecret.secret_id == secret.id).delete()

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
        role_names: list[str] | None = None,
        user_id: str | None = None,
        executor: str | None = None,
        purpose: str | None = None,
        username: str | None = None,
    ) -> list[SecretRecord]:
        """List secrets visible to the caller.

        Args:
            prefix: Optional key prefix to filter by.
            role_names: Caller's role names — a secret is visible if any of
                these is in its scope.
            user_id: Caller's user ID — creator-owned secrets are always
                visible to their creator. No role_names and no user_id (the
                trusted executor/mTLS plane) lists everything.
            executor: Filter by metadata.executor.
            purpose: Filter by metadata.purpose.
            username: Filter by metadata.username.

        Returns:
            List of secret records visible to the caller.
        """

        session = self.backend.get_session()
        try:
            query = session.query(Secret).join(SecretRole)

            if prefix:
                query = query.filter(Secret.key.like(f"{prefix}%"))

            if role_names or user_id:
                visibility = []
                if role_names:
                    role_ids = session.query(Role.id).filter(Role.name.in_(role_names))
                    scoped_ids = session.query(SecretRole.secret_id).filter(SecretRole.role_id.in_(role_ids))
                    visibility.append(Secret.id.in_(scoped_ids))
                if user_id:
                    visibility.append(Secret.created_by == user_id)
                query = query.filter(or_(*visibility))

            secrets = query.distinct().all()

            # ponytail: metadata filters in Python (dialect-proof JSON access);
            # push into SQL if secret counts ever make the scan measurable.
            if executor:
                secrets = [s for s in secrets if (s.meta or {}).get("executor") == executor]
            if purpose:
                secrets = [s for s in secrets if (s.meta or {}).get("purpose") == purpose]
            if username:
                secrets = [s for s in secrets if (s.meta or {}).get("username") == username]

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
                records.append(
                    SecretRecord(
                        id=str(secret.id),
                        key=secret.key,
                        encrypted_value=secret.encrypted_value,
                        nonce=secret.nonce,
                        wrapped_dek=secret.wrapped_dek,
                        key_version_id=secret.key_version_id,
                        created_by=secret.created_by,
                        created_at=secret.created_at,
                        role_names=roles_by_secret.get(secret.id, []),
                        meta=secret.meta,
                    )
                )

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

    def decrypt_secret(self, secret: Secret) -> str:
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
