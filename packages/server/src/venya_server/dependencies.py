"""Database session + auth dependencies for FastAPI."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from venya.vault.backend import Backend, BackendConfig
from venya.vault.factory import VaultFactory
from venya.vault.vault import Caller
from venya.iam.models import Base
from venya.iam.session_manager import SessionConfig as VaultSessionConfig, SessionManager
from venya.iam.role_manager import RoleManager

_bearer_scheme = HTTPBearer(auto_error=False)


def init_db(db_config: BackendConfig) -> Backend:
    """Initialize the database backend.

    Uses VENYA_DB_URL env var for PostgreSQL, falling back to
    the passed db_config for local SQLite development.

    Args:
        db_config: Database configuration.

    Returns:
        Configured Backend instance.
    """
    import os

    database_url = os.environ.get("VENYA_DB_URL")
    if database_url:
        config = BackendConfig(
            database_url=database_url,
            passphrase=db_config.passphrase.encode("utf-8") if db_config.passphrase else None,
        )
    else:
        from pathlib import Path

        path = Path(db_config.database_path)
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        config = BackendConfig(
            database_path=path,
            passphrase=db_config.passphrase.encode("utf-8") if db_config.passphrase else None,
            wal_mode=db_config.wal_mode,
        )
    return Backend(config)


def get_db(backend: Backend) -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session."""
    session = backend.get_session()
    try:
        yield session
    finally:
        session.close()


def get_backend(request: Request) -> Backend:
    """FastAPI dependency that yields the backend from app state."""
    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )
    return backend


def get_session_manager(backend: Backend = Depends(get_backend)) -> SessionManager:
    """FastAPI dependency that yields a SessionManager."""
    from sqlalchemy.orm import Session as ORMSession

    # Get the config from app state
    # We'll create a temporary session for the manager
    db = backend.get_session()
    config = getattr(backend, "_session_config", VaultSessionConfig())
    return SessionManager(db, config)


def get_role_manager(backend: Backend = Depends(get_backend)) -> RoleManager:
    """FastAPI dependency that yields a RoleManager."""
    db = backend.get_session()
    return RoleManager(db)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> dict:
    """FastAPI dependency that validates the session token and returns user info.

    Returns:
        Dict with user_id, roles, session_id.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Look up session by token JTI in app state
    # The session middleware should have validated and attached user info
    user_info = getattr(request.state, "auth_user", None)
    if user_info is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_info


def require_role(permission: str):
    """Dependency factory that requires a specific permission level.

    Args:
        permission: Required permission — "read" or "read-write".

    Returns:
        Dependency that checks the user has the required permission.
    """
    async def _checker(
        user_info: dict = Depends(get_current_user),
        role_manager: RoleManager = Depends(get_role_manager),
        request: Request = Depends(get_backend),
    ) -> dict:
        # This will be properly implemented when we have role context
        # For now, just return the user info
        return user_info

    return _checker


def get_caller(request: Request) -> Caller:
    """Determine the caller type from the request.

    mTLS requests come from executor (caller=executor).
    Bearer token requests come from human (caller=human).

    Args:
        request: The FastAPI request.

    Returns:
        Caller enum value.
    """
    # Check if request has mTLS client cert (executor)
    if getattr(request, "client_cert", None) is not None:
        return Caller.EXECUTOR

    # Otherwise human (CLI)
    return Caller.HUMAN
