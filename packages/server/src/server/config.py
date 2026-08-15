"""Server configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("venya.server")


class DatabaseConfig(BaseModel):
    """Database configuration."""

    database_url: str | None = Field(default=None, description="PostgreSQL database URL")
    database_path: str = Field(default="venya.db", description="Path to SQLCipher database")
    passphrase: str | None = Field(default=None, description="Master passphrase for key derivation")
    wal_mode: bool = Field(default=True, description="Enable WAL mode")


class SessionConfig(BaseModel):
    """Session configuration."""

    session_timeout: int = Field(
        default=900,
        description="Idle timeout in seconds before session expires (default: 15 min)",
    )
    access_token_ttl: int = Field(
        default=300,
        description="Access token lifetime in seconds (default: 5 min)",
    )
    max_session_duration: int = Field(
        default=14400,
        description="Hard cap on session duration in seconds (default: 4 hours)",
    )


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    enforce: bool = Field(
        default=True,
        description="Whether to enforce rate limiting",
    )
    max_attempts: int = Field(
        default=5,
        description="Maximum failed attempts before lockout",
    )
    window_seconds: int = Field(
        default=300,
        description="Time window in seconds for counting failures",
    )
    ip_rate_limit: int = Field(
        default=1000,
        description="Maximum requests per IP per minute",
    )
    lockout_reinstate_minutes: int = Field(
        default=15,
        description="Minutes before a locked-out user can try again",
    )


class Fido2Config(BaseModel):
    """WebAuthn/FIDO2 configuration."""

    rp_id: str = Field(
        default="localhost",
        description="WebAuthn relying party ID",
    )
    rp_name: str = Field(
        default="Venya",
        description="WebAuthn relying party name",
    )
    origins: list[str] = Field(
        default_factory=lambda: ["https://localhost"],
        description="Allowed_origins for WebAuthn",
    )
    enrollment_token_ttl: int = Field(
        default=15,
        description="Enrollment token lifetime in minutes",
    )
    unmask_auto_hide_timeout: int = Field(
        default=30,
        description="Seconds before unmasked secret auto-masks",
    )


class CRLConfig(BaseModel):
    """Configuration for Certificate Revocation List management."""

    crl_retention_days: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Days to keep revocation records before purge",
    )
    crl_url: str | None = Field(
        default=None,
        description="CRL Distribution Point URL for CDP extension (e.g., https://crl.venya.internal/api/v1/executors/certs/crl)",
    )


class CASecurityConfig(BaseModel):
    """CA key security configuration."""

    key_passphrase_env: str = Field(
        default="VENYA_CA_KEY_PASSPHRASE",
        description="Environment variable containing the CA key passphrase.",
    )
    require_in_production: bool = Field(
        default=True,
        description="Require passphrase in production (warn if unset).",
    )


class ExecutorEnrollmentConfig(BaseModel):
    """Configuration for executor enrollment and registration."""

    # Token lifecycle
    token_ttl_seconds: int = Field(
        default=1800,
        ge=120,
        le=86400,
        description="Enrollment token lifetime in seconds (120–86400)",
    )

    # Authorization
    require_token: bool = Field(
        default=False,
        description="Reject executor registrations without a valid enrollment token",
    )

    # Rate limiting
    token_generation_per_minute: int = Field(
        default=10,
        description="Max enrollment tokens generated per admin per minute",
    )
    registration_attempts_per_minute: int = Field(
        default=5,
        description="Max registration attempts per IP/executor per minute",
    )
    registration_ip_per_minute: int = Field(
        default=20,
        description="Max registration attempts per source IP per minute (batch enrollment)",
    )

    enabled: bool = Field(
        default=True,
        description="Whether to enforce executor enrollment rate limiting",
    )

    @field_validator("token_ttl_seconds")
    @classmethod
    def warn_extended_ttl(cls, v: int) -> int:
        if v > 14400:
            logger.warning(
                "Executor enrollment token TTL is %d seconds (>4h). "
                "Consider using shorter-lived tokens for production deployments.",
                v,
            )
        return v


class CORSConfig(BaseModel):
    """Cross-Origin Resource Sharing configuration."""

    origins: list[str] = Field(
        default_factory=lambda: ["http://localhost"],
        description="Allowed CORS origins. Empty list = deny all cross-origin.",
    )
    allow_credentials: bool = True
    allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    )
    allow_headers: list[str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type"],
    )
    expose_headers: list[str] = Field(
        default_factory=lambda: ["X-Request-ID", "X-Total-Count"],
        description="Response headers exposed to browser clients",
    )
    max_age: int = Field(default=3600, ge=0, description="Preflight cache in seconds")


class ClockSkewConfig(BaseModel):
    """Clock skew tolerance configuration.

    Different environments have different clock sync realities:
    - Cloud/Kubernetes: NTP reliable, 60s is fine.
    - On-prem/edge: Physical hardware, may need 120s.
    - High-security: May tighten to 15-30s.
    """

    token_tolerance_seconds: int = Field(
        default=60,
        ge=0,
        le=300,
        description="Clock skew tolerance for token/session expiration checks (0-300s)",
    )
    cert_tolerance_seconds: int = Field(
        default=300,
        ge=0,
        le=600,
        description="Clock skew tolerance for certificate validity checks (0-600s)",
    )


class AdminMTLSConfig(BaseModel):
    """Configuration for admin mTLS authentication."""

    enabled: bool = Field(
        default=False,
        description="Require mTLS for admin endpoints",
    )
    ca_cert: str | None = Field(
        default=None,
        description="Path to admin CA certificate for verifying client certs",
    )
    ca_key_passphrase_env: str = Field(
        default="VENYA_ADMIN_CA_KEY_PASSPHRASE",
        description="Environment variable containing the admin CA key passphrase",
    )
    known_admin_ids: list[str] = Field(
        default_factory=list,
        description="Allowed admin certificate identities (SAN DNS or CN values)",
    )


class ServerConfig(BaseSettings):
    """Server configuration.

    Loaded from environment variables and/or config file.
    Environment variables are prefixed with VENYA_.
    """

    model_config = SettingsConfigDict(
        env_prefix="VENYA_",
        env_nested_delimiter="__",
        env_file="/opt/venya/.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    host: str = Field(default="127.0.0.1", description="Bind address")
    port: int = Field(default=8080, description="Bind port")
    ssl_cert: str | None = Field(default=None, description="Path to SSL certificate file")
    ssl_key: str | None = Field(default=None, description="Path to SSL private key file")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Database
    db_url: str | None = Field(default=None, description="PostgreSQL database URL (overrides db.database_path)")
    db: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Sessions
    session: SessionConfig = Field(default_factory=SessionConfig)

    # Rate limiting
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    # WebAuthn
    fido2: Fido2Config = Field(default_factory=Fido2Config)

    # mTLS (executor communication)
    mtls_ca_cert: str | None = Field(default=None, description="Path to CA certificate for mTLS (verifying executor certs)")
    mtls_ca_key: str | None = Field(default=None, description="Path to CA private key (signing executor certs)")
    mtls_cert: str | None = Field(default=None, description="Path to server mTLS certificate")
    mtls_key: str | None = Field(default=None, description="Path to server mTLS private key")
    ca_dir: str = Field(
        default="/var/lib/venya/ca",
        description="Directory for CA key/cert storage",
    )

    # CA security
    ca_security: CASecurityConfig = Field(default_factory=CASecurityConfig)

    # CRL (Certificate Revocation List)
    crl: CRLConfig = Field(default_factory=CRLConfig)

    # Executor enrollment (token TTL, auth, rate limiting)
    executor_enrollment: ExecutorEnrollmentConfig = Field(
        default_factory=ExecutorEnrollmentConfig,
    )

    # CORS
    cors: CORSConfig = Field(default_factory=CORSConfig)

    # Admin mTLS
    admin_mtls: AdminMTLSConfig = Field(default_factory=AdminMTLSConfig)

    # Clock skew tolerance
    clock_skew: ClockSkewConfig = Field(default_factory=ClockSkewConfig)

    # Audit forwarding
    audit_remote_url: str | None = Field(default=None, description="Remote syslog URL (tls://host:port)")
    audit_local_retention_days: int = Field(default=90, description="Local audit log retention days")

    # Recovery code pepper (server-side secret for hashing break-glass recovery codes)
    recovery_code_pepper: str = Field(
        default="",
        description="Secret pepper for hashing recovery codes. Must be set in production.",
    )

    @classmethod
    def from_file(cls, path: str | Path) -> ServerConfig:
        """Load configuration from a TOML file.

        Args:
            path: Path to config file.

        Returns:
            Configured ServerConfig.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]

        with open(path, "rb") as f:
            data = tomllib.load(f)

        return cls(**data)

    def save_file(self, path: str | Path) -> None:
        """Save current configuration to a TOML file.

        Args:
            path: Path to write config file.
        """
        try:
            import tomllib
        except ImportError:
            import tomli_w as tomli_w  # type: ignore[import-not-found]

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        import json

        data = json.loads(self.model_dump_json())
        with open(path, "w") as f:
            tomli_w.dump(data, f)
