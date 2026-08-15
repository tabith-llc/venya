"""FastAPI app factory + lifespan."""

from __future__ import annotations

import asyncio
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
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

    # Store config on app state
    app.state.config = config  # type: ignore[attr-defined]

    # Register routes at creation time (needed for OpenAPI docs)
    from .routes import admin, audit, auth, auth_browser, credentials, enroll, enrollment, executors, filter as filter_routes, health, init as init_route, recovery, roles, secrets, static as static_routes

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(auth_browser.router, prefix="/api/v1")
    app.include_router(enroll.router, prefix="/api/v1")
    app.include_router(init_route.router, prefix="/api/v1")
    app.include_router(executors.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")
    app.include_router(recovery.router, prefix="/api/v1")
    app.include_router(secrets.router, prefix="/api/v1")
    app.include_router(roles.router, prefix="/api/v1")
    app.include_router(enrollment.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(credentials.router, prefix="/api/v1")
    app.include_router(filter_routes.router, prefix="/api/v1")
    app.include_router(static_routes.router)

    # Add middleware
    from .middleware import auth as auth_middleware
    from .middleware import rbac
    from .middleware import rate_limit
    from .middleware import security_headers
    from .middleware import rate_limit_headers

    app.add_middleware(security_headers.SecurityHeadersMiddleware, cors_origins=config.cors.origins)
    app.add_middleware(rate_limit_headers.RateLimitHeaderMiddleware)
    app.add_middleware(rate_limit.RateLimitMiddleware, config=config.rate_limit)
    app.add_middleware(auth_middleware.SessionMiddleware)
    app.add_middleware(rbac.RBACMiddleware)

    # CORS — always register; empty origins = deny all (Starlette behavior)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors.origins,
        allow_credentials=config.cors.allow_credentials,
        allow_methods=config.cors.allow_methods,
        allow_headers=config.cors.allow_headers,
        expose_headers=config.cors.expose_headers,
        max_age=config.cors.max_age,
    )

    # FIDO2 manager initialized in lifespan after DB is ready
    return app


async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Lifespan context manager for FastAPI."""
    config: ServerConfig = app.state.config  # type: ignore[attr-defined]

    # Warn if CORS origins are still default in non-debug environment
    if not config.debug and config.cors.origins == ["http://localhost"]:
        logger.warning(
            "CORS origins are still default (['http://localhost']) in non-debug mode. "
            "Update VENYA__CORS__ORIGINS to allow browser clients."
        )

    # Startup: initialize DB, vault, and CA (FIDO2 is already initialized)
    from .dependencies import init_db

    backend = init_db(config.db, db_url=config.db.database_url)
    logger.info("Database initialized: %s", config.db.database_path)
    app.state.backend = backend  # type: ignore[attr-defined]

    vault = backend.get_vault(config.db.passphrase)
    app.state.vault = vault  # type: ignore[attr-defined]

    # Initialize FIDO2 manager after DB is ready
    from .fido2.manager import Fido2Manager

    app.state.fido2_manager = Fido2Manager(  # type: ignore[attr-defined]
        rp_id=config.fido2.rp_id,
        rp_name=config.fido2.rp_name,
        origins=config.fido2.origins,
        backend=backend,
    )

    # Initialize CA if not already done
    from .ca import CAManager

    ca_manager = CAManager(config.ca_dir, config.ca_security)
    if not ca_manager.has_ca:
        ca_manager.initialize()
    app.state.ca_manager = ca_manager  # type: ignore[attr-defined]

    # Initialize admin CA (required if admin_mtls is enabled)
    from pathlib import Path

    from .ca import AdminCAManager

    admin_ca_dir = Path(config.ca_dir) / "admin-ca"
    admin_ca_manager = AdminCAManager(admin_ca_dir, config.ca_security)
    if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
        raise RuntimeError(
            "admin_mtls.enabled but admin CA not found at admin-ca/. "
            "Run: venya admin init-admin-ca"
        )
    app.state.admin_ca_manager = admin_ca_manager  # type: ignore[attr-defined]

    # Periodic session cleanup
    from datetime import datetime, timezone

    from sqlalchemy import text

    cleanup_task = None

    async def session_cleanup_loop():
        """Run session cleanup every 5 minutes."""
        while True:
            await asyncio.sleep(300)  # 5 minutes
            try:
                db = backend.get_session()
                try:
                    now = datetime.now(timezone.utc)
                    from vault.iam.session_manager import SessionConfig
                    config = SessionConfig()
                    hard_cap_threshold = now - (config.max_session_duration - config.session_timeout)
                    deleted = db.execute(
                        text("DELETE FROM sessions WHERE expires_at < :threshold"),
                        {"threshold": hard_cap_threshold},
                    )
                    db.commit()
                    logger.info("Session cleanup: deleted %d expired sessions", deleted.rowcount)
                except Exception:
                    db.rollback()
                    logger.exception("Session cleanup failed")
                finally:
                    db.close()
            except Exception:
                logger.exception("Session cleanup loop error")

    cleanup_task = asyncio.create_task(session_cleanup_loop())

    yield

    # Shutdown
    if cleanup_task is not None:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    backend = getattr(app.state, "backend", None)
    if backend is not None:
        backend.dispose()
    logger.info("Server shut down")


def main() -> None:
    """Run the server."""
    import logging
    import os

    import uvicorn

    config = ServerConfig()

    # Admin mTLS startup enforcement
    if config.admin_mtls.enabled and config.host not in ("127.0.0.1", "::1", "localhost"):
        raise RuntimeError(
            "admin_mtls.enabled requires loopback bind address (127.0.0.1 or ::1). "
            "Set VENYA_HOST=127.0.0.1 or disable admin_mtls."
        )

    passphrase_env = config.admin_mtls.ca_key_passphrase_env
    if config.admin_mtls.enabled and not os.environ.get(passphrase_env):
        raise RuntimeError(
            f"admin_mtls.enabled requires {passphrase_env} environment variable to be set."
        )

    from server.utils.sensitive_log_filter import SensitiveFieldFilter

    logging.basicConfig(
        level=logging.DEBUG if config.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveFieldFilter())

    app = create_app(config)

    uvicorn_kwargs = {
        "app": app,
        "host": config.host,
        "port": config.port,
        "log_level": "debug" if config.debug else "info",
    }

    if config.ssl_cert and config.ssl_key:
        uvicorn_kwargs["ssl_certfile"] = config.ssl_cert
        uvicorn_kwargs["ssl_keyfile"] = config.ssl_key
        logger.info("Starting server with HTTPS (SSL cert: %s)", config.ssl_cert)
    else:
        logger.info("Starting server with HTTP (no SSL configured)")

    uvicorn.run(**uvicorn_kwargs)
