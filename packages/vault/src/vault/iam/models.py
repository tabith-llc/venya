"""SQLAlchemy ORM models for the vault database.

14 tables covering IAM, secrets, sessions, key rotation, rate limiting,
command policies, and audit logging.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
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
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """SQLAlchemy base class."""

    pass


class User(Base):
    """User accounts."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), unique=True, nullable=False, index=True)
    auth_mode = Column(String(32), nullable=False, default="security-key")
    enrolled_at = Column(DateTime, nullable=True)
    session_timeout = Column(Integer, default=900)  # 15 minutes in seconds
    recovery_code_hash = Column(String(64), nullable=True)

    # Relationships
    roles = relationship("RoleMember", back_populates="user")
    created_secrets = relationship("Secret", back_populates="creator")
    sessions = relationship("Session", back_populates="user")

    __table_args__ = (
        Index("ix_users_user_id", "user_id"),
    )


class Role(Base):
    """Role definitions."""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    permissions = Column(String(16), nullable=False, default="read")  # read | read-write
    description = Column(Text, nullable=True)

    # Relationships
    members = relationship("RoleMember", back_populates="role")
    scoped_secrets = relationship("SecretRole", back_populates="role")

    __table_args__ = (
        Index("ix_roles_name", "name"),
    )


class RoleMember(Base):
    """User-to-role membership."""

    __tablename__ = "role_members"

    user_id = Column(String(64), ForeignKey("users.user_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)

    # Relationships
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="members")

    __table_args__ = (
        Index("ix_role_members_user_id", "user_id"),
        Index("ix_role_members_role_id", "role_id"),
    )


class Secret(Base):
    """Encrypted secrets."""

    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True)
    key = Column(String(512), nullable=False, index=True)
    encrypted_value = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)  # 12-byte ChaCha20 nonce
    wrapped_dek = Column(LargeBinary, nullable=False)  # 40-byte AES-256-KW wrapped DEK
    key_version_id = Column(String(64), nullable=False)
    created_by = Column(String(64), ForeignKey("users.user_id"), nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    creator = relationship("User", back_populates="created_secrets")
    roles = relationship("SecretRole", back_populates="secret")

    __table_args__ = (
        Index("ix_secrets_key", "key"),
    )


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
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    access_token_jti = Column(String(64), nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_expires_at", "expires_at"),
    )


class AuditEvent(Base):
    """Audit log."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=True)
    fields = Column(Text, nullable=True)  # JSON fields
    timestamp = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_timestamp", "timestamp"),
    )


class EnrollmentToken(Base):
    """Enrollment tokens for user onboarding."""

    __tablename__ = "enrollment_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(String(64), nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    expires_at = Column(DateTime, nullable=False)
    consumed = Column(Boolean, default=False, nullable=False)
    failed_attempts = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_enrollment_tokens_token", "token"),
        Index("ix_enrollment_tokens_expires_at", "expires_at"),
    )


class KeyVersion(Base):
    """Key rotation versions."""

    __tablename__ = "key_versions"

    id = Column(Integer, primary_key=True)
    version_label = Column(String(64), unique=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    active = Column(Boolean, default=False, nullable=False)
    rotation_pending = Column(Boolean, default=False, nullable=False)
    encrypted_kek_hash = Column(String(64), nullable=True)  # SHA-256 fingerprint


class KeyRotationJob(Base):
    """Key rotation job tracking."""

    __tablename__ = "key_rotation_jobs"

    id = Column(Integer, primary_key=True)
    created_by_user_id = Column(String(64), nullable=True)
    old_key_version_id = Column(Integer, nullable=True)
    new_key_version_id = Column(Integer, nullable=True)
    status = Column(String(16), nullable=False, default="pending")  # pending/running/completed/failed/rolled_back
    total_secrets = Column(Integer, default=0)
    completed_secrets = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)


class KeyRotationSecret(Base):
    """Per-secret rotation status."""

    __tablename__ = "key_rotation_secrets"

    id = Column(Integer, primary_key=True)
    rotation_job_id = Column(
        Integer, ForeignKey("key_rotation_jobs.id"), nullable=False
    )
    secret_id = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="pending")  # pending/rotated/failed
    error_message = Column(Text, nullable=True)


class RateLimitFailure(Base):
    """Restart-recovery for rate limiting."""

    __tablename__ = "rate_limit_failures"

    user_id = Column(String(64), primary_key=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    window_start = Column(DateTime, nullable=False)


class CommandPolicy(Base):
    """Executor command whitelist policies."""

    __tablename__ = "command_policies"

    id = Column(Integer, primary_key=True)
    policy_name = Column(String(64), unique=True, nullable=False)
    preset = Column(String(32), nullable=False)  # strict/balanced/permissive
    allowed_commands = Column(Text, nullable=True)  # JSON array
    dangerous_patterns = Column(Text, nullable=True)  # JSON array
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_command_policies_policy_name", "policy_name"),
    )


class ExecutorCert(Base):
    """Active executor certificates."""

    __tablename__ = "executor_certs"

    id = Column(Integer, primary_key=True)
    executor_id = Column(String(64), ForeignKey("users.user_id"), nullable=False)
    serial_number = Column(String(64), unique=True, nullable=False)
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    fingerprint = Column(String(64), nullable=False)  # SHA-256 fingerprint
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_executor_certs_executor_id", "executor_id"),
        Index("ix_executor_certs_serial_number", "serial_number"),
        Index("ix_executor_certs_not_after", "not_after"),
    )


class ExecutorCertRevocation(Base):
    """Revoked executor certificate serial numbers."""

    __tablename__ = "executor_cert_revocations"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    executor_id = Column(String(64), nullable=True)  # Which executor this cert belonged to
    revoked_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    reason = Column(Text, nullable=True)  # Why it was revoked

    __table_args__ = (
        Index("ix_executor_cert_revocations_serial_number", "serial_number"),
        Index("ix_executor_cert_revocations_revoked_at", "revoked_at"),
    )


class ElevationToken(Base):
    """Elevation tokens for sensitive operations (secret unmasking)."""

    __tablename__ = "elevation_tokens"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_elevation_tokens_expires_at", "expires_at"),
    )


class WebAuthnCredential(Base):
    """WebAuthn credentials for user authentication."""

    __tablename__ = "webauthn_credentials"

    id = Column(Integer, primary_key=True)
    credential_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=False, index=True)
    raw_id = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    transports = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", backref="webauthn_credentials")

    __table_args__ = (
        Index("ix_webauthn_credentials_user_id", "user_id"),
    )
