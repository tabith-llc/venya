"""PostgreSQL backend for the core."""


import json
import time
from pathlib import Path
from typing import Any, ClassVar

from sqlalchemy import (
    Engine,
    create_engine,
    event,
    text,
)
from sqlalchemy.orm import Session, sessionmaker

from .encryption import KEK_SIZE, DecryptionError, derive_kek, unwrap_key


class BackendError(Exception):
    """Base backend error."""


class BackendConnectionError(BackendError):
    """Failed to connect to the database."""


class BackendConfigurationError(BackendError):
    """Invalid backend configuration."""


class BackendConfig:
    """Configuration for the PostgreSQL backend.

    Attributes:
        database_url: PostgreSQL connection URL (e.g. postgresql+psycopg2://user:pass@host/db).
        passphrase: Master passphrase for key derivation (used to derive KEK).
        kek: Optional raw 32-byte KEK. If provided, passphrase is ignored for
            key derivation but KEK is used for wrapping/unwrap.
        wal_mode: Whether to enable WAL mode (default True, PostgreSQL default).
        audit_enabled: Whether to enable audit event logging (default True).
    """

    def __init__(
        self,
        database_url: str,
        passphrase: bytes | None = None,
        kek: bytes | None = None,
        wal_mode: bool = True,
        audit_enabled: bool = True,
    ) -> None:
        if passphrase is None and kek is None:
            raise BackendConfigurationError(
                "Either passphrase or kek must be provided"
            )
        if kek is not None and len(kek) != KEK_SIZE:
            raise BackendConfigurationError(
                f"KEK must be {KEK_SIZE} bytes, got {len(kek)}"
            )

        self.database_url = database_url
        self.passphrase = passphrase
        self.kek = kek
        self.wal_mode = wal_mode
        self.audit_enabled = audit_enabled

        # Derive KEK from passphrase if not provided
        if self.kek is None and self.passphrase is not None:
            self.kek, self._salt = derive_kek(self.passphrase)
        else:
            self._salt = b""

    @property
    def engine_url(self) -> str:
        """Get the SQLAlchemy engine URL."""
        return self.database_url


class Backend:
    """PostgreSQL backend wrapper.

    Provides database engine creation, session management, and connection setup.
    """

    def __init__(self, config: BackendConfig) -> None:
        self.config = config
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None

    @property
    def engine(self) -> Engine:
        """Get the SQLAlchemy engine, creating it if necessary."""
        if self._engine is None:
            self._create_engine()
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Get the session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(bind=self.engine)
        return self._session_factory

    def get_session(self) -> Session:
        """Create a new database session."""
        return self.session_factory()

    def _create_engine(self) -> None:
        """Create the PostgreSQL engine."""
        self._engine = create_engine(
            self.config.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )

        # Set PostgreSQL PRAGMAs (connection-level settings)
        @event.listens_for(self._engine, "connect")
        def set_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                # Enable WAL (PostgreSQL default, but be explicit)
                if self.config.wal_mode:
                    cursor.execute("SET synchronous_commit = ON")

                # Set statement timeout (5 minutes)
                cursor.execute("SET statement_timeout = '300s'")

                # Enable prepared statements
                cursor.execute("SET enable_partition_pruning = ON")

                cursor.close()
            except Exception:
                cursor.close()
                raise

    def get_core(self, passphrase: str | None = None) -> Any:
        """Create and return a configured Core instance.

        Args:
            passphrase: Optional passphrase override for key derivation.

        Returns:
            Configured Core instance.
        """
        from .core import Core
        from .rate_limiter import RateLimiter

        kek = None
        # Explicit is not None check preserves empty strings (which fail derive_kek intentionally)
        if passphrase is not None:
            effective_passphrase = passphrase
        elif self.config.passphrase is not None:
            effective_passphrase = self.config.passphrase.decode("utf-8")
        else:
            effective_passphrase = None
        if effective_passphrase:
            from .encryption import derive_kek
            kek, _ = derive_kek(effective_passphrase.encode("utf-8"))
        elif kek is None and self.config.kek is not None:
            # Fallback: use backend's KEK when no passphrase provided
            # (e.g., CoreFactory.with_kek() used to create the backend)
            kek = self.config.kek

        return Core(
            backend=self,
            rate_limiter=RateLimiter(),
            kek=kek,
        )

    def dispose(self) -> None:
        """Dispose of the engine and release resources."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None

    def __enter__(self) -> Backend:
        return self

    def __exit__(self, *args: object) -> None:
        self.dispose()
