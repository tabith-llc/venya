"""SQLAlchemy ORM models for the core database.

17 tables covering IAM, secrets, sessions, key rotation, rate limiting,
command policies, executor certificates, elevation tokens, and WebAuthn credentials.

Schema is created via Alembic migrations on install. Models are the ORM interface.
"""


from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """SQLAlchemy base class."""

    pass


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
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)

    # Relationships
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="members")


class Secret(Base):
    """Encrypted secrets."""

    __tablename__ = "secrets"

    __table_args__ = (
        UniqueConstraint("key", "created_by", name="uq_secrets_key_created_by"),
    )

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
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    creator = relationship("User", back_populates="created_secrets")
    roles = relationship("SecretRole", back_populates="secret")


class SecretRole(Base):
    """Secret-to-role scoping."""

    __tablename__ = "secret_roles"

    secret_id = Column(
        Integer, ForeignKey("secrets.id"), primary_key=True, nullable=False
    )
    role_id = Column(
        Integer, ForeignKey("roles.id"), primary_key=True, nullable=False
    )

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
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    access_token = Column(String(128), nullable=True, unique=True)
    access_token_jti = Column(String(64), nullable=True, unique=True)

    # Relationships
    user = relationship("User", back_populates="sessions")


class AuditEvent(Base):
    """Audit log."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(64), nullable=False)
    user_id = Column(
        String(64),
        ForeignKey("users.user_id"),
        nullable=True,
        comment="Preserved on user deletion — append-only audit trail",
    )
    fields = Column(Text, nullable=True)
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


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
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
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
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by_session_id = Column(String(64), nullable=True,
        comment="Forensic trace — nullify after 90 days per retention policy")
    created_from_ip = Column(String(45), nullable=True,
        comment="Forensic trace — nullify after 90 days per retention policy")
    created_from_user_agent = Column(String(256), nullable=True,
        comment="Forensic trace — nullify after 90 days per retention policy")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    used_at = Column(DateTime(timezone=True), nullable=True)
    admin_meta_wrapped_dek = Column(LargeBinary, nullable=True,
        comment="Encrypted admin metadata (ip, ua, sid) — nullify after 90 days")
    admin_meta_nonce = Column(LargeBinary, nullable=True,
        comment="Encrypted admin metadata nonce")
    admin_meta_ciphertext = Column(LargeBinary, nullable=True,
        comment="Encrypted admin metadata ciphertext")


class KeyVersion(Base):
    """Key rotation versions."""

    __tablename__ = "key_versions"

    id = Column(Integer, primary_key=True)
    version_label = Column(String(64), unique=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
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
    rotation_job_id = Column(
        Integer, ForeignKey("key_rotation_jobs.id"), nullable=False
    )
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
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
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
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ExecutorCertRevocation(Base):
    """Revoked executor certificate serial numbers."""

    __tablename__ = "executor_cert_revocations"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    executor_id = Column(String(64), nullable=True)
    revoked_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    reason = Column(Text, nullable=True)


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
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)


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
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", backref="webauthn_credentials")


class AdminCertRevocation(Base):
    """Revoked admin certificate serial numbers."""

    __tablename__ = "admin_cert_revocations"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(64), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reason = Column(String(64))
