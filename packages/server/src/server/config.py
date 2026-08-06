"""Server configuration."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseConfig(BaseModel):
    """Database configuration."""

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

    max_attempts: int = Field(
        default=5,
        description="Maximum failed attempts before lockout",
    )
    window_seconds: float = Field(
        default=300.0,
        description="Time window in seconds for counting failures",
    )
    ip_rate_limit: int = Field(
        default=100,
        description="Maximum requests per IP per minute",
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


class ServerConfig(BaseSettings):
    """Server configuration.

    Loaded from environment variables and/or config file.
    Environment variables are prefixed with VENYA_.
    """

    model_config = SettingsConfigDict(
        env_prefix="VENYA_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    host: str = Field(default="127.0.0.1", description="Bind address")
    port: int = Field(default=8080, description="Bind port")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Database
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

    # CORS
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost"],
        description="Allowed CORS origins",
    )

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
