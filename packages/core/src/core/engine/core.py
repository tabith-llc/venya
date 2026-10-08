# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Core facade: get/put/delete/list with RBAC enforcement and rate limiting."""

import logging
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import or_, text

from ..iam.models import Role, Secret, SecretRole, SessionSecret
from .backend import Backend, ensure_kek_sentinel
from .encryption import DecryptionError
from .encryption import decrypt_secret as _decrypt_secret_impl
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


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


class KekHolder(Protocol):
    """The shape of the KEK cache as the facade sees it (#472).

    Declared structurally so this module keeps its distance from the
    protected-memory surface: the cache is created and owned by
    ``Backend`` alone, and the facade only ever asks it for a scoped,
    read-only view.
    """

    @property
    def is_populated(self) -> bool: ...

    def view(self) -> AbstractContextManager[memoryview]: ...


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
        kek: KekHolder | None = None,
    ) -> None:
        """Create the facade.

        Args:
            backend: The backend, which owns the KEK cache.
            rate_limiter: Optional rate limiter.
            kek: The KEK cache — a ``KekHolder``, not key bytes. Readers get a
                scoped read-only view from it; nothing here holds the key.
        """
        self.backend = backend
        self.rate_limiter = rate_limiter or RateLimiter()
        self.kek = kek

    def _require_kek(self) -> KekHolder:
        """The KEK cache when it holds a key, or the existing config error.

        Raises:
            CoreError: If no cache was given, or the cache is released or was
                never populated. Asking a released cache for key material is
                refused rather than answered with zero bytes: an all-zero KEK
                is a valid AES-256 key, so a quiet answer would keep the
                service green while writing secrets nobody can read back.
        """
        kek = self.kek
        if kek is None or not kek.is_populated:
            raise CoreError("KEK not configured")
        return kek

    #: Advisory-lock namespace for per-key secret upserts (#515). Combined with
    #: the key under ``hashtext`` so this lock cannot collide with the #339
    #: enrollment or #514 membership keys, which hash a bare user id.
    ADVISORY_LOCK_NAMESPACE = "venya:secret-key:"

    def _resolve_secret_in(
        self,
        session,
        secret_key: str,
        user_id: str | None,
        role_names: list[str] | None = None,
        for_update: bool = False,
    ) -> Secret | None:
        """Single enforcement point for secret visibility.

        A secret is visible to the caller iff any of the caller's role_names
        is in the secret's role scope, OR the caller created it. No admin
        bypass: the admin role matches only admin-scoped secrets. Returns
        None when neither holds — callers MUST treat that as "not found" so
        scoped-out keys are indistinguishable from nonexistent ones (no
        cross-role key-name enumeration).

        ``for_update`` is the write-side half of #514/#515 and is set ONLY by
        :meth:`put`: it asks the database to lock the resolved row until the
        caller's transaction ends, so "resolve the existing row, then replace
        it" is one atomic step and a concurrent put or delete cannot land
        between the read and the write. The read paths (``get``,
        ``get_for_injection``, ``list``) leave it False — a locking read on a
        hot read path would serialize every retrieval behind the row lock.
        PostgreSQL locks; SQLite, the test backend, ignores the clause.

        When duplicates exist (the shadow pair this ticket is about), the
        answer is the LOWEST id — ``order_by(Secret.id).first()`` below — so
        which value a session retrieves is decided by insertion order, which is
        why an unrepaired race is order-dependent rather than merely untidy.
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
        query = query.order_by(Secret.id)
        if for_update:
            query = query.with_for_update()
        return query.first()

    def get_for_injection(
        self, secret_key: str, user_id: str, role_names: list[str] | None = None
    ) -> tuple[int, str, dict]:
        """Resolve + decrypt a secret for session injection (server-side only).

        Returns (secret_id, plaintext, meta). Raises CoreAccessError when the
        secret is not visible to the caller (role-scoped out and not the
        creator) — routes map that to 404 "Secret not found", indistinguishable
        from a nonexistent key. Raises RateLimitExceededError when the user is
        locked out (ticket #421: this entrance gates on check() like get();
        routes map that to 429 + Retry-After).
        """
        if user_id is None:
            raise CoreAccessError("user_id is required for secret injection")

        self.rate_limiter.check(user_id)

        session = self.backend.get_session()
        try:
            try:
                secret = self._resolve_secret_in(session, secret_key, user_id, role_names)
                if secret is None:
                    raise CoreAccessError(f"Secret not found: {secret_key}")
                result = (secret.id, self.decrypt_secret(secret), dict(secret.meta or {}))
            except (CoreAccessError, DecryptionError):
                # Ticket ratelimiter-lockout-inert (refs #385): retrieval
                # failures count; the Nth raises RateLimitExceededError —
                # that IS the lockout arming, and it propagates.
                self.rate_limiter.record_failure(user_id)
                raise
            self.rate_limiter.record_success(user_id)
            return result
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
            try:
                # Visibility: role-scoped match OR creator (single enforcement
                # point — _resolve_secret_in). Scoped-out and nonexistent keys
                # are indistinguishable.
                secret = self._resolve_secret_in(session, secret_key, user_id, role_names)

                if secret is None:
                    raise CoreAccessError(f"Secret not found: {secret_key}")

                # For executor: always plaintext
                if caller == Caller.EXECUTOR:
                    result = self.decrypt_secret(secret)
                elif not unmask:
                    # For human: masked by default. A masked read is
                    # counter-NEUTRAL (ticket #421): neither clears nor
                    # records — it returns before the bookkeeping below.
                    return "\u2022" * 8  # ••••••••
                else:
                    # Human with unmask: requires re-auth (enforced at server level)
                    result = self.decrypt_secret(secret)
            except (CoreAccessError, DecryptionError):
                # Ticket ratelimiter-lockout-inert (refs #385): retrieval
                # failures count; the Nth raises RateLimitExceededError —
                # that IS the lockout arming, and it propagates.
                self.rate_limiter.record_failure(user_id)
                raise
            self.rate_limiter.record_success(user_id)
            return result
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
                NOT user_info["roles"], which carries role IDs). Two jobs:
                resolve an existing row for replacement, AND authorize the
                requested scope — every name in role_names must be one the
                caller holds (ticket secret-write-namespace-scoping #451, the
                write-side mirror of _resolve_secret_in). Omit only where no
                human caller identity exists (see the note in the body).

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

        # Write-side namespace authorization (ticket secret-write-namespace-scoping
        # #451). Reads have one door — _resolve_secret_in — and it is sound; the
        # write side had none, so holding the read-write tier in ANY group let a
        # caller store a secret into a namespace they do not belong to
        # (require_role("read-write") is a global tier test: it never asks WHICH
        # group). A caller may scope a secret only into groups they actually hold.
        # Refusal is loud — every offending name is reported and the request is
        # never silently narrowed to the caller's own subset — and it lands here,
        # before any encryption or session work, so a refused write cannot leave a
        # row, a link, or a partial commit behind. Runs ahead of the
        # "Role not found" existence check on purpose: an out-of-caller name is
        # refused whether or not it exists, so the answer leaks no group inventory.
        # caller_roles=None means "no human caller identity was supplied" — the
        # trusted/internal plane. The only production caller of put() is
        # server/routes/secrets.py::secrets_create, which always derives the real
        # roles from the DB (refs 451).
        if caller_roles is not None:
            held = set(caller_roles)
            offending = [name for name in dict.fromkeys(role_names) if name not in held]
            if offending:
                raise CoreAccessError("Role not held by caller: " + ", ".join(offending))

        if self.kek is None or not self.kek.is_populated:
            raise CoreError("KEK not configured")

        # Encrypt the secret
        wrapped_dek, nonce, ciphertext = self.encrypt(value)
        session = self.backend.get_session()
        try:
            # #515: the upsert's resolve-then-write is ONE serialized step. The
            # advisory lock is keyed on the secret KEY (a database object, so
            # it serializes every process sharing this database — separate
            # uvicorn workers and the three core VMs pointing at one
            # PostgreSQL), and it is transaction-scoped, so it releases on the
            # commit below. The FOR UPDATE on the candidate row is the belt for
            # the case where a row already exists to lock. Shape copied from
            # the two precedents this tree already ships: #339
            # ``enrollment_manager.create_enrollment_token`` and #510
            # ``routes/init.py::_lock_first_admin_bootstrap`` — including the
            # dialect guard, because pg_advisory_xact_lock/hashtext are
            # PostgreSQL-only and against SQLite the statement is a runtime "no
            # such function" error (#366). On SQLite the advisory lock is
            # SKIPPED and the FOR UPDATE clause is ignored: cross-process
            # serialization is a PostgreSQL-production property.
            #
            # What the lock does NOT change is intended multiplicity. Two
            # callers putting the same key where neither can SEE the other's
            # row (scoped out) still each resolve to None and each INSERT — the
            # lock orders the two operations, it does not make one invisible to
            # the other. Replacing is what visibility already authorizes
            # ("you may replace exactly what you may see").
            bind = session.get_bind()
            if bind.dialect.name == "postgresql":
                session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:secret_key))"),
                    {"secret_key": f"{self.ADVISORY_LOCK_NAMESPACE}{key}"},
                )
            existing = self._resolve_secret_in(session, key, user_id, caller_roles, for_update=True)

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

        Convergence point for the KEK-sentinel mint (#304): every KEK-wrapped
        envelope in the system is created here (store-secret upsert and the
        admin enrollment-token meta path), so the idempotent get-or-create
        below lands the sentinel on the first successful crypto use of every
        boot — legacy installs and fresh installs alike.

        Returns:
            Tuple of (wrapped_dek, nonce, ciphertext).

        Raises:
            CoreError: If KEK not configured.
        """
        kek_cache = self._require_kek()

        from .encryption import encrypt_secret

        with kek_cache.view() as kek:
            result = encrypt_secret(kek, value)

            # Sentinel mint after a successful wrap — best-effort: the wrap above
            # is the customer's data path and must not be lost to a belt failure.
            # The boot-time check (#304) falls back to DEK sampling if the row
            # never lands, so a mint failure degrades detection, never security.
            try:
                session = self.backend.get_session()
                try:
                    ensure_kek_sentinel(session, kek)
                finally:
                    session.close()
            except Exception:
                logger.warning(
                    "KEK sentinel mint failed; startup verification falls back to DEK sampling", exc_info=True
                )

        return result

    def decrypt_secret(self, secret: Secret) -> str:
        """Decrypt and return a secret value from a Secret ORM object."""
        kek_cache = self._require_kek()

        with kek_cache.view() as kek:
            plaintext = _decrypt_secret_impl(
                kek,
                secret.wrapped_dek,
                secret.nonce,
                secret.encrypted_value,
            )
        return plaintext.decode("utf-8")
