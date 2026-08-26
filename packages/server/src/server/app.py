"""FastAPI app factory + lifespan."""

import asyncio
import logging
import time

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
        forwarded_allow_ips=config.trusted_proxies,
    )

    # Store config on app state
    app.state.config = config  # type: ignore[attr-defined]

    # Register routes at creation time (needed for OpenAPI docs)
    from .routes import (
        admin,
        audit,
        auth,
        auth_elevation,
        credentials,
        debug,
        enroll,
        enrollment,
        executors,
        health,
        recovery,
        roles,
        secrets,
    )
    from .routes import filter as filter_routes
    from .routes import init as init_route
    from .routes import static as static_routes

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(auth_elevation.router, prefix="/api/v1")
    app.include_router(enroll.router, prefix="/api/v1")
    app.include_router(init_route.router, prefix="/api/v1")
    app.include_router(executors.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")
    app.include_router(recovery.router, prefix="/api/v1")
    app.include_router(secrets.router, prefix="/api/v1")
    app.include_router(roles.router, prefix="/api/v1")
    app.include_router(enrollment.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(debug.router, prefix="/api/v1/admin")
    app.include_router(credentials.router, prefix="/api/v1")
    app.include_router(filter_routes.router, prefix="/api/v1")
    app.include_router(static_routes.router)

    # Add middleware
    from .middleware import auth as auth_middleware
    from .middleware import metrics as metrics_middleware
    from .middleware import rate_limit, rate_limit_headers, security_headers

    app.add_middleware(metrics_middleware.MetricsMiddleware)
    app.add_middleware(security_headers.SecurityHeadersMiddleware, cors_origins=config.cors.origins)
    app.add_middleware(rate_limit_headers.RateLimitHeaderMiddleware)
    app.add_middleware(rate_limit.RateLimitMiddleware, config=config.rate_limit)
    app.add_middleware(auth_middleware.SessionMiddleware)

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

    # Wrap with pure ASGI request size limit middleware — outermost layer,
    # runs before all FastAPI middleware so oversized requests are rejected
    # before auth/rate-limit/RBAC processing cost.
    from .middleware.request_size import RequestSizeLimitMiddleware

    app = RequestSizeLimitMiddleware(app, max_body_bytes=config.max_request_body_bytes)  # type: ignore[assignment]

    # FIDO2 manager initialized in lifespan after DB is ready
    return app


def _init_core(backend, passphrase):  # type: ignore[no-untyped-def]
    """Create the core from the backend.

    Logs a fatal, operator-actionable error and re-raises if the KEK salt is
    missing while secrets already exist (C-11, unrecoverable data loss). The
    caller (lifespan) propagates the error so startup aborts.
    """
    from core.engine.backend import KekSaltMissingError

    try:
        return backend.get_core(passphrase)
    except KekSaltMissingError:
        logger.critical(
            "Startup aborted: KEK salt missing from venya_config but secrets "
            "already exist. Previously stored secrets are unrecoverable. "
            "Restore from a pre-restart backup and retry."
        )
        raise


async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Lifespan context manager for FastAPI."""
    config: ServerConfig = app.state.config  # type: ignore[attr-defined]

    # CSPRNG self-test at startup
    from core.utils.entropy import csprng_self_test

    csprng_self_test()

    # Warn if CORS origins are still default in non-debug environment
    if not config.debug and config.cors.origins == ["http://localhost"]:
        logger.warning(
            "CORS origins are still default (['http://localhost']) in non-debug mode. "
            "Update VENYA__CORS__ORIGINS to allow browser clients."
        )

    # Startup: initialize DB, core, and CA (FIDO2 is already initialized)
    from .dependencies import init_db

    backend = init_db(config.db, db_url=config.db.database_url)
    from core.utils.sensitive_log import secret

    logger.info(
        "Database initialized: %s", secret(config.db.database_url) if config.db.database_url else "not configured"
    )
    app.state.backend = backend  # type: ignore[attr-defined]

    # Debug mode allows unencrypted storage for local development convenience.
    # The recovery_code_pepper check below is unconditional because rainbow table
    # attacks are viable even in dev — but local DB encryption is a lower risk.
    if not config.debug and not config.db.passphrase:
        raise RuntimeError(
            "VENYA_DB_PASSPHRASE is not set. "
            "Core secrets cannot be encrypted without a passphrase. "
            "Set the passphrase in your secrets manager and restart."
        )

    # Hard failure on missing recovery code pepper — prevents rainbow table attacks
    if not config.recovery_code_pepper:
        raise RuntimeError(
            "Recovery code pepper must be configured. Set VENYA_RECOVERY_PEPPER "
            "or config.recovery_code_pepper. Recovery codes without a server-side "
            "pepper are vulnerable to rainbow table attacks."
        )

    # Best-effort check: verify disk encryption for PostgreSQL data directory
    from .utils.disk_encryption import check_disk_encryption

    check_disk_encryption(config.db.database_url)

    core = _init_core(backend, config.db.passphrase)
    app.state.core = core  # type: ignore[attr-defined]

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

    from cryptography.x509 import load_pem_x509_certificates

    from .ca import AdminCAManager

    admin_ca_dir = Path(config.ca_dir) / "admin-ca"
    admin_ca_manager = AdminCAManager(admin_ca_dir, config.ca_security)
    if config.admin_mtls.enabled and not admin_ca_manager.has_ca:
        raise RuntimeError("admin_mtls.enabled but admin CA not found at admin-ca/. " "Run: venya admin init-admin-ca")
    app.state.admin_ca_manager = admin_ca_manager  # type: ignore[attr-defined]

    # Load admin CA PEM bundle (supports rotation — multiple certs concatenated)
    if config.admin_mtls.enabled and config.admin_mtls.ca_cert:
        try:
            admin_trusted_cas = load_pem_x509_certificates(Path(config.admin_mtls.ca_cert).read_bytes())
            app.state.admin_trusted_cas = admin_trusted_cas  # type: ignore[attr-defined]
            logger.info("Loaded %d trusted admin CA cert(s) from %s", len(admin_trusted_cas), config.admin_mtls.ca_cert)
        except Exception:
            logger.exception("Failed to load admin CA PEM bundle from %s", config.admin_mtls.ca_cert)
            raise

    # Periodic session cleanup
    from .maintenance import run_maintenance

    cleanup_task = None

    async def session_cleanup_loop():
        """Run session cleanup every 5 minutes."""
        while True:
            await asyncio.sleep(300)  # 5 minutes
            try:
                db = backend.get_session()
                try:
                    run_maintenance(db, config)
                except Exception:
                    db.rollback()
                    logger.exception("Session cleanup failed")
                finally:
                    db.close()
            except Exception:
                logger.exception("Session cleanup loop error")

    cleanup_task = asyncio.create_task(session_cleanup_loop(), name="session-cleanup")
    cleanup_task._created_at = time.monotonic()  # type: ignore[attr-defined]

    yield

    # Shutdown
    if cleanup_task is not None:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    shutdown_backend = getattr(app.state, "backend", None)
    if shutdown_backend is not None:
        shutdown_backend.dispose()
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
        raise RuntimeError(f"admin_mtls.enabled requires {passphrase_env} environment variable to be set.")

    from core.utils.sensitive_log import RedactingFormatter

    logging.basicConfig(
        level=logging.DEBUG if config.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    app = create_app(config)

    # Start Prometheus metrics HTTP server on loopback (if configured)
    metrics_port = os.environ.get("VENYA_METRICS_PORT")
    if metrics_port:
        from prometheus_client import start_http_server

        port = int(metrics_port)
        start_http_server(port, addr="127.0.0.1")
        logger.info("Prometheus metrics server started on 127.0.0.1:%d", port)

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
