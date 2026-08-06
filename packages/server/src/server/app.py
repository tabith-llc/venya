"""FastAPI app factory + lifespan."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import ServerConfig

logger = logging.getLogger("venya.server")


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create the FastAPI application.

    Args:
        config: Server configuration. If not provided, loads from defaults/env.

    Returns:
        Configured FastAPI app.
    """
    if config is None:
        config = ServerConfig()

    app = FastAPI(
        title="Venya",
        description="A secrets broker system for LLMs",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Store config on app state
    app.state.config = config  # type: ignore[attr-defined]

    # Register routes at creation time (needed for OpenAPI docs)
    from .routes import admin, audit, auth, auth_browser, enrollment, executors, filter as filter_routes, health, init as init_route, recovery, roles, secrets

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(auth_browser.router, prefix="/api/v1")
    app.include_router(init_route.router, prefix="/api/v1")
    app.include_router(executors.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")
    app.include_router(recovery.router, prefix="/api/v1")
    app.include_router(secrets.router, prefix="/api/v1")
    app.include_router(roles.router, prefix="/api/v1")
    app.include_router(enrollment.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(filter_routes.router, prefix="/api/v1")

    # Add middleware
    from .middleware import auth as auth_middleware
    from .middleware import rbac
    from .middleware import rate_limit

    app.add_middleware(rate_limit.RateLimitMiddleware, config=config.rate_limit)
    app.add_middleware(auth_middleware.SessionMiddleware)
    app.add_middleware(rbac.RBACMiddleware)

    # CORS
    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Initialize FIDO2 manager at creation time (not deferred to lifespan)
    from .fido2.manager import Fido2Manager

    app.state.fido2_manager = Fido2Manager(  # type: ignore[attr-defined]
        rp_id=config.fido2.rp_id,
        rp_name=config.fido2.rp_name,
        origins=config.fido2.origins,
    )

    # Initialize CA manager
    from .ca import CAManager

    ca_manager = CAManager(config.ca_dir)
    app.state.ca_manager = ca_manager  # type: ignore[attr-defined]

    return app


async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Lifespan context manager for FastAPI."""
    config: ServerConfig = app.state.config  # type: ignore[attr-defined]

    # Startup: initialize DB, vault, and CA (FIDO2 is already initialized)
    from .dependencies import init_db

    backend = init_db(config.db, db_url=config.db_url)
    logger.info("Database initialized: %s", config.db.database_path)
    app.state.backend = backend  # type: ignore[attr-defined]

    vault = backend.get_vault(config.db.passphrase)
    app.state.vault = vault  # type: ignore[attr-defined]

    # Initialize CA if not already done
    from .ca import CAManager

    ca_manager = CAManager(config.ca_dir)
    if not ca_manager.has_ca:
        ca_manager.initialize()
    app.state.ca_manager = ca_manager  # type: ignore[attr-defined]

    yield

    # Shutdown
    backend = getattr(app.state, "backend", None)
    if backend is not None:
        backend.dispose()
    logger.info("Server shut down")


def main() -> None:
    """Run the server."""
    import uvicorn

    config = ServerConfig()

    logging.basicConfig(
        level="debug" if config.debug else "info",
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = create_app(config)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level="debug" if config.debug else "info",
    )
