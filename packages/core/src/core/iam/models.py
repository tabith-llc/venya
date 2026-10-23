# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""SQLAlchemy ORM models for the core database.

21 tables covering IAM, secrets, sessions, key rotation, rate limiting,
command policies, executor certificates, elevation tokens, WebAuthn
credentials and pending ceremonies, execution relay, and the KEK
boot-sentinel.

Schema is created via Alembic migrations on install. Models are the ORM interface.
"""

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, relationship, validates


class Base(DeclarativeBase):
    """SQLAlchemy base class."""


class User(Base):
    """User accounts."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), unique=True, nullable=False)
    display_name = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="pending_enrollment")
    auth_mode = Column(String(32), nullable=False, default="security-key")
    enrolled_at = Column(DateTime(timezone=True), nullable=True)
    session_timeout = Column(Integer, default=900)
    recovery_code_hash = Column(String(64), nullable=True)

    # Relationships
    roles = relationship("RoleMember", back_populates="user")
    created_secrets = relationship("Secret", back_populates="creator")
    sessions = relationship("Session", back_populates="user")


class Role(Base):
    """Role definitions."""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    permissions = Column(String(16), nullable=False, default="read")
    description = Column(Text, nullable=True)

    # Relationships
    members = relationship("RoleMember", back_populates="role")
    scoped_secrets = relationship("SecretRole", back_populates="role")


class RoleMember(Base):
    """User-to-role membership."""

    __tablename__ = "role_members"

    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)

    # Relationships
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="members")


class Secret(Base):
    """Encrypted secrets."""

    __tablename__ = "secrets"

    __table_args__ = (UniqueConstraint("key", "created_by", name="uq_secrets_key_created_by"),)

    id = Column(Integer, primary_key=True)
    key = Column(String(512), nullable=False)
    encrypted_value = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    wrapped_dek = Column(LargeBinary, nullable=False)
    key_version_id = Column(String(64), nullable=False)
    created_by = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    meta = Column(
        "metadata",
        JSON().with_variant(postgresql.JSONB(), "postgresql"),
        nullable=True,
        server_default="{}",
        comment="Structured metadata for discovery (executor, purpose, username, description)",
    )

    # Relationships
    creator = relationship("User", back_populates="created_secrets")
    roles = relationship("SecretRole", back_populates="secret")


class SecretRole(Base):
    """Secret-to-role scoping."""

    __tablename__ = "secret_roles"

    secret_id = Column(Integer, ForeignKey("secrets.id"), primary_key=True, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True, nullable=False)

    # Relationships
    secret = relationship("Secret", back_populates="roles")
    role = relationship("Role", back_populates="scoped_secrets")


class Session(Base):
    """Active sessions."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    access_token = Column(String(128), nullable=True, unique=True)
    access_token_jti = Column(String(64), nullable=True, unique=True)
    # #342: persisted bearer-token expiry (now + access_token_ttl at issue).
    # Validated fail-closed by the middleware; NULL means "no timestamp" ->
    # rejected. Old rows pre-migration carry NULL by design.
    access_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")


class AuditEvent(Base):
    """Audit log."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(64), nullable=False)
    user_id = Column(
        String(64),
        nullable=True,
        comment=(
            "FK INTENTIONALLY absent (migration 022) — stores the auth "
            "principal verbatim regardless of mechanism (incl. mTLS CNs), "
            "preserved on user deletion"
        ),
    )
    fields = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    @validates("fields")
    def serialize_fields(self, key, value):
        if isinstance(value, dict):
            return json.dumps(value)
        return value


class EnrollmentToken(Base):
    """Enrollment tokens for user onboarding."""

    __tablename__ = "enrollment_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash = Column(String(64), unique=True, nullable=False)
    binding_hash = Column(String(64), nullable=False, default="")
    state = Column(String(16), nullable=False, default="created")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


class ExecutorEnrollmentToken(Base):
    """Enrollment tokens for executor bootstrap registration.

    Tokens are generated by admins and consumed during the one-time
    executor registration flow. Expired tokens are detected at
    validation time (state is not stored as "expired").
    """

    __tablename__ = "executor_enrollment_tokens"

    id = Column(Integer, primary_key=True)
    executor_id = Column(String(64), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    state = Column(String(16), nullable=False, default="created")
    created_by = Column(
        String(64),
        nullable=False,
        comment=(
            "FK INTENTIONALLY absent (migration 022) — stores the auth "
            "principal verbatim regardless of mechanism (incl. mTLS CNs), "
            "which have no users row"
        ),
    )
    created_by_session_id = Column(
        String(64), nullable=True, comment="Forensic trace — nullify after 90 days per retention policy"
    )
    created_from_ip = Column(
        String(45), nullable=True, comment="Forensic trace — nullify after 90 days per retention policy"
    )
    created_from_user_agent = Column(
        String(256), nullable=True, comment="Forensic trace — nullify after 90 days per retention policy"
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    used_at = Column(DateTime(timezone=True), nullable=True)
    admin_meta_wrapped_dek = Column(
        LargeBinary, nullable=True, comment="Encrypted admin metadata (ip, ua, sid) — nullify after 90 days"
    )
    admin_meta_nonce = Column(LargeBinary, nullable=True, comment="Encrypted admin metadata nonce")
    admin_meta_ciphertext = Column(LargeBinary, nullable=True, comment="Encrypted admin metadata ciphertext")


class KeyVersion(Base):
    """Key rotation versions.

    Bookkeeping labels under single-KEK alpha semantics: no per-version key
    material exists (the KEK derives from the install passphrase) and secret
    decryption never consults this table. Rotation is a synchronous label
    boundary (ticket key-rotation-worker-missing, option-2 ruling).
    """

    __tablename__ = "key_versions"
    # At most ONE row may be active — enforced by the database, not app code:
    # partial unique index over (active) WHERE active — every indexed row
    # carries the same value, so a second active row violates uniqueness.
    # Concurrent rotations cannot both commit (migration 028; PG + SQLite).
    __table_args__ = (
        Index(
            "uq_key_versions_single_active",
            "active",
            unique=True,
            postgresql_where=text("active"),
            sqlite_where=text("active"),
        ),
    )

    id = Column(Integer, primary_key=True)
    version_label = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    active = Column(Boolean, default=False, nullable=False)
    rotation_pending = Column(Boolean, default=False, nullable=False)
    encrypted_kek_hash = Column(String(64), nullable=True)


class KeyRotationJob(Base):
    """Key rotation job tracking."""

    __tablename__ = "key_rotation_jobs"

    id = Column(Integer, primary_key=True)
    created_by_user_id = Column(String(64), nullable=True)
    old_key_version_id = Column(Integer, nullable=True)
    new_key_version_id = Column(Integer, nullable=True)
    status = Column(String(16), nullable=False, default="pending")
    total_secrets = Column(Integer, default=0)
    completed_secrets = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    rolled_back_at = Column(DateTime(timezone=True), nullable=True)


class KeyRotationSecret(Base):
    """Per-secret rotation status."""

    __tablename__ = "key_rotation_secrets"

    id = Column(Integer, primary_key=True)
    rotation_job_id = Column(Integer, ForeignKey("key_rotation_jobs.id"), nullable=False)
    secret_id = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="pending")
    error_message = Column(Text, nullable=True)


class RateLimitFailure(Base):
    """Rate limit counters — fixed-window, per-IP/per-user.

    Primary key: (identifier, endpoint_type, window_start).
    identifier = IP address or user_id depending on scope.
    endpoint_type = "generic", "auth", or "break_glass".
    window_start = fixed window bucket start (1min for generic/auth, 1hr for break_glass).
    count = atomic counter incremented via UPSERT.

    Uses fixed-window buckets (not sliding window). A burst at window
    boundary allows up to 2x the limit — acceptable for this use case.
    """

    __tablename__ = "rate_limit_failures"

    identifier = Column(String(64), primary_key=True)
    endpoint_type = Column(String(16), primary_key=True)
    window_start = Column(DateTime(timezone=True), primary_key=True)
    count = Column(Integer, default=0, nullable=False)


class CommandPolicy(Base):
    """Executor command whitelist policies."""

    __tablename__ = "command_policies"

    id = Column(Integer, primary_key=True)
    policy_name = Column(String(64), unique=True, nullable=False)
    preset = Column(String(32), nullable=False)
    allowed_commands = Column(Text, nullable=True)
    dangerous_patterns = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class ExecutorCert(Base):
    """Active executor certificates."""

    __tablename__ = "executor_certs"

    id = Column(Integer, primary_key=True)
    executor_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    serial_number = Column(String(64), unique=True, nullable=False)
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)
    fingerprint = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class ExecutorCertRevocation(Base):
    """Revoked executor certificate serial numbers."""

    __tablename__ = "executor_cert_revocations"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    executor_id = Column(String(64), nullable=True)
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    reason = Column(Text, nullable=True)


class Executor(Base):
    """Registered executor status tracking.

    Tracks executor online/offline status, hostname, and enrollment state.
    Created automatically during executor registration.
    """

    __tablename__ = "executors"

    id = Column(String, primary_key=True)
    hostname = Column(String, nullable=False, comment="Executor network address for mTLS relay")
    enrolled_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, default="pending", server_default="pending")
    version = Column(
        String,
        nullable=True,
        comment=(
            "Executor dist version reported via heartbeat (additive field). "
            "NULL = daemon predates version reporting — a distinct honest "
            "signal, never backfilled; populates on the next heartbeat."
        ),
    )


class ExecutionSession(Base):
    """Execution session for command relay.

    Tracks a single command execution request from a user through
    the server to an executor. 10-minute TTL via expires_at.
    Separate from auth sessions (Session model) — collision would be catastrophic.
    """

    __tablename__ = "execution_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    executor_id = Column(String, ForeignKey("executors.id"), nullable=False)
    command = Column(
        Text,
        nullable=True,
        comment=(
            "Rendered display text of the command (shlex.join of argv). "
            "Pre-#322 rows carry the raw wire string; display readers only."
        ),
    )
    command_argv = Column(
        JSON().with_variant(postgresql.JSONB(), "postgresql"),
        nullable=True,
        comment=(
            "True argument list as submitted (ticket execution-command-wire-unstructured-string #322). "
            "NULL = pre-change row — carried the string form only, args not recoverable."
        ),
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", backref="execution_sessions")
    secrets = relationship("SessionSecret", back_populates="session")


class SessionSecret(Base):
    """Wrapped secret bundles for an execution session.

    Stores sentinel-wrapped secret values that the executor
    injects into the sandbox during command execution.
    """

    __tablename__ = "execution_session_secrets"

    session_id = Column(
        String,
        ForeignKey("execution_sessions.id"),
        primary_key=True,
    )
    secret_id = Column(
        Integer,
        ForeignKey("secrets.id"),
        primary_key=True,
    )
    wrapped_value = Column(Text, nullable=False)

    # Relationships
    session = relationship("ExecutionSession", back_populates="secrets")


class ElevationToken(Base):
    """Elevation tokens for sensitive operations (secret unmasking)."""

    __tablename__ = "elevation_tokens"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False)
    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    # #527 elevation-not-session-bound: the session that EARNED this token.
    # Nullable by ruling — pre-fix rows carry NULL and stay consumable under
    # their own user+expiry checks; new mints always bind. No DB-level FK: a
    # sessions.id reference would either block the bulk SQL sweeps (cleanup
    # deletes bypass the ORM on SQLite, where FKs are off by default) or
    # behave engine-differently — the lifecycle rule is enforced in code,
    # SessionManager.revoke_session deletes bound rows with the session.
    session_id = Column(Integer, nullable=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)


class ElevationChallenge(Base):
    """Pending elevation ceremonies, DB-backed (#528).

    The auth binding of an elevation ceremony — which user (and session)
    started it — used to live in a per-process dict, so a second worker or
    a restart lost it and the ceremony died with 'challenge not found'.
    One row per pending challenge; the claim is an atomic single-consume
    UPDATE (house pattern: enrollment_tokens.state / elevation_tokens.used).
    session_id carries no DB-level FK for the same reasons as
    ElevationToken above. Rows are short-lived (TTL x5) and pruned at the
    next challenge touch.
    """

    __tablename__ = "elevation_challenges"

    id = Column(Integer, primary_key=True)
    challenge_id = Column(String(64), unique=True, nullable=False)
    user_id = Column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    session_id = Column(Integer, nullable=True)
    # "created" -> "consumed" (vocabulary mirrors enrollment_tokens.state)
    state = Column(String(16), nullable=False, default="created")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)


class Fido2Challenge(Base):
    """Pending WebAuthn ceremony challenges, DB-backed (#534).

    The protocol half of a FIDO2 ceremony — the issued challenge bytes plus
    its ceremony metadata — used to live in a per-process dict inside
    Fido2Store, so a core restart (or, under any future multi-worker
    routing, a ceremony step landing on another process) lost it and the
    response 401'd 'Challenge not found or expired'. One row per pending
    challenge; the claim is an atomic single-consume UPDATE (house pattern:
    elevation_challenges.state from #528, enrollment_tokens.state).
    `payload` is the ceremony dict as JSON text with bytes values
    base64-tagged (raw_challenge, existing_credential_ids).

    user_id carries NO DB-level FK — deliberate. A registration challenge
    can be issued while the user row is still pending-created (init flow)
    or not present yet at all (the enrollment-token flow binds the id, the
    row lands later), and an untargeted login start carries an empty
    binding; a FK would refuse live ceremonies. The lifecycle rule is an
    application rule: rows are short-lived (CHALLENGE_TTL_SECONDS) and are
    pruned at the next challenge touch. Same ruling class as
    elevation_challenges.session_id and audit_events.user_id (022).
    """

    __tablename__ = "fido2_challenges"

    id = Column(Integer, primary_key=True)
    challenge_id = Column(String(64), unique=True, nullable=False)
    user_id = Column(String(64), nullable=False)
    payload = Column(Text, nullable=False)
    # "created" -> "consumed" (vocabulary mirrors elevation_challenges.state)
    state = Column(String(16), nullable=False, default="created")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)


class WebAuthnCredential(Base):
    """WebAuthn credentials for user authentication."""

    __tablename__ = "webauthn_credentials"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_id = Column(LargeBinary, unique=True, nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0)
    label = Column(String(64), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    # Attestation record (queue #2 leg 1: STORE only — no enforcement, no
    # chain verification in this change). Nullable because rows created
    # before migration 038 have no captured ceremony; every registration
    # from 038 forward writes all three (finish_registration already
    # requires the attestationObject). Yubico D1/D2: store the raw
    # attestation object with the credential so policy can retro-act.
    attestation_fmt = Column(String(32), nullable=True)
    aaguid = Column(String(36), nullable=True)
    attestation_object = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", backref="webauthn_credentials")


class AdminCertRevocation(Base):
    """Revoked admin certificate serial numbers."""

    __tablename__ = "admin_cert_revocations"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(64), nullable=False, index=True)
    # No server_default (Python-side lambda only): a raw-SQL INSERT that omits
    # revoked_at violates NOT NULL (physically hit in the Delta B step-4 cell —
    # ticket delta-b-run-low-bundle O6; ruled runbook-note, not migration).
    # Supported write path is the ORM (`venya admin revoke-admin-cert`); manual
    # inserts must supply revoked_at explicitly — see cert-rotation-runbook.md §4.
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    reason = Column(String(64))


class AdminCredential(Base):
    """Registry of admin certificates this core issued or holds — the population #684 lacked.

    WHY THIS TABLE EXISTS. ``admin_revoke_admin_cert`` validated the FORMAT of the
    operator's string and then blind-inserted an ``AdminCertRevocation`` row, so
    ``venya admin revoke-admin-cert --serial <any hex>`` exited 0 and wrote a revocation
    naming a serial no credential ever held, while the live admin credential kept
    transacting (#684, measured by a prior worker lane at leg 232 against the sibling relay route,
    which refuses the same string). A membership check needs something to be a member
    OF, and none existed: this was the only admin-certificate relation in the tree,
    and using ``AdminCertRevocation`` for it is circular — it is what the verb writes.

    ONE DELIBERATE DIVERGENCE FROM THE ``#597`` ``CoreRelayCredential`` SHAPE: there is
    no ``revoked_at`` column here. The admin plane already has a revocation authority
    (``AdminCertRevocation``), and ``AdminCAManager.generate_crl`` draws from it — this
    table answers exactly one question, "was this serial ever a credential this core
    vouches for", and a second revocation column would be a second source of truth for
    the same fact. Revocation stays single-writer; membership is what lives here.

    Four writers, all copying the shipped ``#597`` shape (boot ingest, mint-side write,
    explicit register) plus one observation point, so a credential that exists in the
    deployment exists here:

    * ``server/admin_registry.py`` at core startup, from the path ``VENYA_ADMIN_CERT``
      names — the machine-plane bootstrap leaf the installer mints out-of-band (mirrors
      ``relay_registry.ingest_relay_credential``: the boot covers cores installed by an
      OLDER installer, which no mint-side write ever would);
    * ``routes/admin_certs.py::admin_issue_cert`` — every human-plane mint, in the same
      transaction as its ``ADMIN_CERT_ISSUED`` audit row;
    * ``middleware/auth.py`` — every credential the admin-mTLS chain has just VERIFIED and
      admitted (``source=observed-admission``), the writer that keeps this from stranding an
      operator whose credential the boot never saw and nobody held a PEM for;
    * ``routes/admin_certs.py::admin_register_admin_cert`` — the operator's explicit remedy
      for a credential none of the above reached, reading the facts OFF the submitted
      certificate so a caller cannot enroll an arbitrary serial (same rule and same shape as
      ``admin_register_core_relay_cert``).
    """

    __tablename__ = "admin_credentials"

    id = Column(Integer, primary_key=True)
    serial_number = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Certificate serial in the ONE canonical WRITE form (lowercase hex, zero-padded to >=16) per #481",
    )
    common_name = Column(
        String(128),
        nullable=False,
        comment="Subject CN as presented — the admin identity for both planes (RF-6 SS6.3 / SS2.1)",
    )
    source = Column(
        String(32),
        nullable=False,
        comment="Which writer created the row, and so which plane it belongs to: boot-disk (the machine bootstrap leaf), issue-route (a human mint), register-route (operator-registered)",
    )
    cert_fingerprint = Column(
        String(64),
        nullable=True,
        comment="sha256 of the DER certificate, lowercase hex — identifies the credential across a re-mint",
    )
    public_key_hash = Column(
        String(64),
        nullable=True,
        comment="sha256 of the SubjectPublicKeyInfo DER — the re-mint-tied identity when the serial moves",
    )
    issued_at = Column(DateTime(timezone=True), nullable=True, comment="notBefore of the credential")
    not_after = Column(DateTime(timezone=True), nullable=True, comment="notAfter of the credential")
    registered_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        comment="When this registry row was first written",
    )


class VenyaConfig(Base):
    """Global key-material config (C-11).

    Stores deployment-wide key parameters that must be stable across process
    restarts. Currently holds the Argon2 ``kek_salt`` used to derive the KEK
    from the master passphrase: written once on first initialization, read on
    every subsequent startup so the KEK is reproducible. Without a persisted
    salt the same passphrase would derive a different KEK on each start and
    previously-stored secrets would be unrecoverable.
    """

    __tablename__ = "venya_config"

    key = Column(String(64), primary_key=True, nullable=False)
    value = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class KekSentinel(Base):
    """Boot-time proof that the encryption passphrase matches stored key material (#304).

    One logical row (fixed key ``kek_sentinel``): a fixed known plaintext
    wrapped under the KEK with the SAME AES-256-KW envelope used for secret
    DEKs (40 bytes). The server unwraps it at every startup — a wrong
    passphrase previously booted silently (lazy KEK) and could then WRAP NEW
    DEKs under an unrecoverable KEK. The wrapped envelope is the only stored
    material: no passphrase, no plaintext.
    """

    __tablename__ = "kek_sentinel"

    key = Column(String(64), primary_key=True, nullable=False)
    wrapped_sentinel = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


class CoreRelayCredential(Base):
    """Registry of the core's own relay CLIENT credential presented at executor :8443 (#597).

    Before this row the credential did not exist in the store. ``install-venya-core.sh``
    mints it with ``openssl`` straight to ``/etc/venya/relay/relay-client.crt``
    (CN ``${CORE_HOSTNAME}-relay``, ``-days 365``), and the only revocation tables in
    the tree are ``executor_cert_revocations`` and ``admin_cert_revocations`` — so a
    compromised or retired relay credential had no revocation path at all, and the CRL
    that the same CA mints could never name it (drawn from
    ``ExecutorCertRevocation`` alone, ``server/ca.py:generate_crl``). That population
    gap, not the TLS flag, is what made #586's listener door a no-op against its real
    peer; measured live in ``wave30-specs-20261017/flash5-586-listener-door-s134-report.md``.

    One row per credential, ``serial_number`` unique. Revocation is a column on the
    registry row rather than a second table, because a relay credential that is not in
    this table cannot be revoked at all: the revoke verb refuses an unregistered serial
    (``REFUSE_UNREGISTERED``, default-deny — issue 263's fail-open lesson), so there is
    never a revocation row without a registry row to hang it on. ``revoked_at`` NULL
    means live; the row itself is the registration fact.

    Written by ``server/relay_registry.py`` at core startup from the credential on
    disk, so the invariant "exists on disk => exists here" is held by the process that
    uses the credential, not by the installer step that created it. The mint step can
    pre-date the product's own database being reachable, and the installer script is
    owner-gated per change; boot-ingest covers a credential minted by an OLDER
    installer too, which an installer-only write never would.
    """

    __tablename__ = "core_relay_credentials"

    id = Column(Integer, primary_key=True)
    serial_number = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Certificate serial in the ONE canonical WRITE form (lowercase hex, zero-padded to >=16) per #481",
    )
    common_name = Column(
        String(128),
        nullable=False,
        comment="Subject CN as presented, e.g. 'core-1-relay' — matched against relay_client_ids",
    )
    hostname = Column(
        String(128),
        nullable=True,
        comment="Core host the credential belongs to (CN with the '-relay' suffix removed, when derivable)",
    )
    cert_fingerprint = Column(
        String(64),
        nullable=True,
        comment="sha256 of the DER certificate, lowercase hex — identifies the credential across a re-mint",
    )
    public_key_hash = Column(
        String(64),
        nullable=True,
        comment="sha256 of the SubjectPublicKeyInfo DER — the re-mint-tied identity when the serial moves",
    )
    signing_ca_subject = Column(
        String(255),
        nullable=True,
        comment="Issuer name of the CA that signed this credential (which CA minted it)",
    )
    signing_ca_aki = Column(
        String(64),
        nullable=True,
        comment="Authority Key Identifier hex of the signing CA, when the credential carries one",
    )
    issued_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="notBefore of the credential",
    )
    not_after = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="notAfter of the credential — 365 days at the shipped mint (install-venya-core.sh:1022)",
    )
    registered_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        comment="When this registry row was first written",
    )
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Revocation time; NULL = live. Terminal for alpha: no un-revoke, same law as Executor.revoked_at",
    )
    revoke_reason = Column(Text, nullable=True)
