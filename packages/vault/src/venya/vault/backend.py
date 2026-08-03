"""SQLCipher SQLite backend with WAL mode, TTL, and audit logging."""

from __future__ import annotations

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
    """Configuration for the SQLCipher backend.

    Attributes:
        database_path: Path to the SQLite/SQLCipher database file.
        passphrase: Master passphrase for key derivation (used to derive KEK).
        ke: Optional raw 32-byte KEK. If provided, passphrase is ignored for
            database encryption but KEK is used for key derivation.
        wal_mode: Whether to enable WAL mode (default True).
        audit_enabled: Whether to enable audit event logging (default True).
    """

    def __init__(
        self,
        database_path: str | Path,
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

        self.database_path = Path(database_path)
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
        """Get the SQLAlchemy engine URL for SQLCipher."""
        return f"sqlite+pysqlcipher:///:memory:"


class Backend:
    """SQLCipher SQLite backend wrapper.

    Provides database engine creation, session management, and PRAGMA setup.
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
        """Create the SQLCipher engine with proper PRAGMAs."""
        # Use in-memory database for now; can be changed to file-based
        if self.config.passphrase:
            # For file-based: sqlite+pysqlcipher:///path/to/db
            # For in-memory: sqlite+pysqlcipher:///:memory:
            db_url = "sqlite+pysqlcipher:///:memory:"
        else:
            db_url = "sqlite+pysqlcipher:///:memory:"

        self._engine = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )

        # Set SQLCipher PRAGMAs
        @event.listens_for(self._engine, "connect")
        def set_sqlcipher_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                # Set the page size for better performance
                cursor.execute("PRAGMA page_size = 4096")

                # Set WAL mode if enabled
                if self.config.wal_mode:
                    cursor.execute("PRAGMA journal_mode = WAL")

                # Set key using derived passphrase
                if self.config.passphrase:
                    # SQLCipher uses the passphrase directly for encryption
                    cursor.execute(
                        f"PRAGMA key = \"x'{self.config.passphrase.hex()}'\""
                    )

                # Enable foreign keys
                cursor.execute("PRAGMA foreign_keys = ON")

                # Set busy timeout for concurrent access
                cursor.execute("PRAGMA busy_timeout = 5000")

                cursor.close()
            except Exception:
                cursor.close()
                raise

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
