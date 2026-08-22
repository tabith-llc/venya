"""PostgreSQL backend for the core."""


import json
import os
import time
from pathlib import Path
from typing import Any, ClassVar

from sqlalchemy import (
    Engine,
    create_engine,
    event,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .encryption import KEK_SIZE, DecryptionError, derive_kek, unwrap_key


class BackendError(Exception):
    """Base backend error."""


class BackendConnectionError(BackendError):
    """Failed to connect to the database."""


class BackendConfigurationError(BackendError):
    """Invalid backend configuration."""


class KekSaltMissingError(BackendError):
    """The persisted KEK salt is missing while secrets already exist.

    Unrecoverable data loss: the passphrase-derived KEK cannot be reproduced
    without the salt, so previously-stored secrets cannot be unwrapped. The
    deployment must be restored from a pre-restart backup.
    """


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
        # NOTE: for a passphrase-only config, kek stays None until
        # Backend.bootstrap_kek() resolves it from the persisted salt. Deriving
        # here with a random salt (the old behavior) produced a non-reproducible
        # KEK across restarts (C-11) and must not be done.
        self.kek = kek
        self.wal_mode = wal_mode
        self.audit_enabled = audit_enabled

    @property
    def engine_url(self) -> str:
        """Get the SQLAlchemy engine URL."""
        return self.database_url


def ensure_kek_salt(session: Session) -> bytes:
    """Return the persisted KEK salt, generating and persisting it on first boot.

    - Salt present: returned as-is (normal restart).
    - Salt absent and no secrets: first boot -> generate a random salt,
      persist it, and return it.
    - Salt absent and secrets present: raise KekSaltMissingError. Those secrets
      are wrapped under an unknown KEK and cannot be recovered.

    The concurrent first-boot race (two processes both generating a salt) is
    resolved by the ``key`` primary key: the loser re-reads the winner's salt.
    """
    from core.iam.models import Secret, VenyaConfig
    from .encryption import ARGON2_SALT_LEN

    row = session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first()
    if row is not None:
        return row.value

    existing_secret = session.query(Secret).first()
    if existing_secret is not None:
        raise KekSaltMissingError(
            "KEK salt missing from venya_config but secrets already exist. "
            "Previously stored secrets are unrecoverable with the lost salt. "
            "Restore from a pre-restart backup and retry."
        )

    salt = os.urandom(ARGON2_SALT_LEN)
    session.add(VenyaConfig(key="kek_salt", value=salt))
    try:
        session.flush()
    except IntegrityError:
        # Concurrent first boot: another process inserted a salt first.
        session.rollback()
        winner = session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first()
        if winner is None:
            raise
        return winner.value
    session.commit()
    return salt


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

    def bootstrap_kek(self, passphrase: bytes | None = None) -> bytes:
        """Resolve the KEK from the passphrase using the persisted salt (C-11).

        Reads the Argon2 salt from ``venya_config`` (generating and persisting
        it on first boot) and derives the KEK deterministically. The resolved
        KEK is cached on ``self.config.kek`` so every consumer (and, e.g., the
        filter endpoint via ``backend.config.kek``) shares a single KEK.

        Args:
            passphrase: Passphrase bytes; falls back to ``config.passphrase``.

        Returns:
            The 32-byte KEK.

        Raises:
            KekSaltMissingError: if the salt is missing but secrets exist
                (unrecoverable data loss).
            BackendConfigurationError: if no passphrase or KEK is available.
        """
        if passphrase is None:
            passphrase = self.config.passphrase
        if passphrase is None:
            if self.config.kek is not None:
                return self.config.kek
            raise BackendConfigurationError(
                "bootstrap_kek: no passphrase or KEK available"
            )

        session = self.get_session()
        try:
            salt = ensure_kek_salt(session)
            kek, _ = derive_kek(passphrase, salt)
            self.config.kek = kek
            return kek
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_core(self, passphrase: str | None = None) -> Any:
        """Create and return a configured Core instance.

        The KEK is resolved via ``bootstrap_kek()`` (persisted salt) whenever a
        passphrase is in play; an explicitly-provided raw KEK (``config.kek``)
        is used as-is when no passphrase is involved.

        Args:
            passphrase: Optional passphrase override for key derivation.

        Returns:
            Configured Core instance.
        """
        from .core import Core
        from .rate_limiter import RateLimiter

        if passphrase is not None:
            kek = self.bootstrap_kek(passphrase.encode("utf-8"))
        elif self.config.passphrase is not None:
            kek = self.bootstrap_kek()
        elif self.config.kek is not None:
            # No passphrase in play: use the raw KEK given to the backend
            # (e.g., CoreFactory.with_kek()).
            kek = self.config.kek
        else:
            kek = None

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
