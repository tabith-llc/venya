# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""FastAPI app factory + lifespan."""

import asyncio
import logging
import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import CASecurityConfig, ServerConfig

logger = logging.getLogger("venya.server")


def _admin_ca_security(config: ServerConfig) -> CASecurityConfig:
    """Build the CA security config for the *admin* CA manager.

    The admin CA key passphrase is delivered under the admin var
    (``config.admin_mtls.ca_key_passphrase_env``, default
    ``VENYA_ADMIN_CA_KEY_PASSPHRASE``) — the same var the startup enforcement
    in ``main()`` checks and the installer writes. It is NOT the executor CA
    var (``config.ca_security.key_passphrase_env``, default
    ``VENYA_CA_KEY_PASSPHRASE``).

    Wiring the admin manager to ``config.ca_security`` makes it look for the
    executor var, never find the admin passphrase, and silently write the
    admin CA key UNENCRYPTED at rest. Keep this as the single source of truth
    for the admin manager's security config so the wiring stays testable.
    """
    return CASecurityConfig(key_passphrase_env=config.admin_mtls.ca_key_passphrase_env)


def _validate_relay_mtls_config(config: ServerConfig) -> None:
    """Fail startup when the relay-client mTLS material is unset or missing.

    Without VENYA_MTLS_CERT/VENYA_MTLS_KEY the core cannot present a client
    certificate to executors: every run_command dies at REQUEST time with a
    misleading "mTLS verification failed" 503 that points at the executor's
    trust store while the actual gap is this core's own config. Refuse to boot
    instead — same fail-fast pattern as the executor deaf-boot refusal and the
    admin-CA check in lifespan (ticket refactor-1-config-consolidation
    residual, option (a) ruling 2026-09-18). Unconditional — no debug
    exemption: the relay is core function, and config-dependent exemptions
    are exactly what the structural-gate ordering rationale rejects.

    Raises:
        RuntimeError: naming the unset field or the missing file path.
    """
    from pathlib import Path

    for field_name, env_name in (("mtls_cert", "VENYA_MTLS_CERT"), ("mtls_key", "VENYA_MTLS_KEY")):
        path = getattr(config, field_name)
        if not path:
            raise RuntimeError(
                f"{env_name} is not set — the relay client cannot present mTLS to executors, "
                f"so every run_command would fail at request time. Set {env_name} to the relay "
                f"client certificate/key path (the core installer mints the pair and writes both)."
            )
        if not Path(path).expanduser().exists():
            raise RuntimeError(
                f"{env_name} points to a missing file: {path} — the relay client cannot present "
                f"mTLS to executors. Restore the file or fix {env_name}."
            )


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create the FastAPI application.

    Args:
        config: Server configuration. If not provided, loads from defaults/env.

    Returns:
        Configured FastAPI app.
    """
    if config is None:
        config = ServerConfig()

    # Single-sourced version (feature/version-surfaces condition 1): the
    # former hardcoded literal could silently disagree with the dist.
    from .routes.health import _dist_version

    app = FastAPI(
        title="Venya",
        description="A secrets broker system for LLMs",
        version=_dist_version(),
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
        auth_browser,
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
    # Bare /health alias (ticket health-probe-401-installer-diagnostics scope a):
    # LB/installer probes hitting the host root reuse the SAME handler as the
    # canonical /api/v1/health — identical payload, zero new disclosure. Hidden
    # from OpenAPI; the canonical path stays the only documented surface.
    app.add_api_route("/health", health.health_check, methods=["GET"], include_in_schema=False)
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(auth_browser.router, prefix="/api/v1")
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
    from .middleware import rate_limit, rate_limit_headers

    app.add_middleware(metrics_middleware.MetricsMiddleware)
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
            "Update VENYA_CORS__ORIGINS to allow browser clients."
        )

    # Relay-client mTLS material is functionally mandatory — validated BEFORE
    # any DB/CA work so a misconfigured core never boots "healthy but unable
    # to relay" (ticket refactor-1-config-consolidation residual, option (a)).
    _validate_relay_mtls_config(config)

    # Startup: initialize DB, core, and CA (FIDO2 is already initialized)
    from .dependencies import init_db

    backend = init_db(config.db, db_url=config.db.database_url)
    from core.utils.sensitive_log import secret

    logger.info(
        "Database initialized: %s", secret(config.db.database_url) if config.db.database_url else "not configured"
    )
    app.state.backend = backend  # type: ignore[attr-defined]

    # Unconditional: a missing passphrase is a hard failure in every mode.
    # The former `not config.debug` exemption was a dead letter — init_db
    # above constructs BackendConfig(passphrase=None), which raises
    # BackendConfigurationError before this check ever ran, so debug boots
    # never actually got unencrypted storage; the exemption only suppressed
    # the actionable error message in favor of an opaque one.
    if not config.db.passphrase:
        raise RuntimeError(
            "VENYA_DB__PASSPHRASE is not set. "
            "Core secrets cannot be encrypted without a passphrase. "
            "Set VENYA_DB__PASSPHRASE in /opt/venya/.env and restart "
            "(installer input variable: VENYA_DB_PASSPHRASE)."
        )

    # Hard failure on missing recovery code pepper — prevents rainbow table attacks
    if not config.recovery_code_pepper:
        raise RuntimeError(
            "Recovery code pepper must be configured. Set VENYA_RECOVERY_CODE_PEPPER "
            "in /opt/venya/.env (installer input variable: VENYA_RECOVERY_PEPPER) "
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
    admin_ca_manager = AdminCAManager(admin_ca_dir, _admin_ca_security(config))
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
                    run_maintenance(db, config, ca_manager)
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
        # Trust X-Forwarded-* from the configured proxies so that, behind nginx,
        # request.client.host resolves to the real caller address (not the
        # 127.0.0.1 loopback peer). nginx forwards X-Forwarded-For on every
        # proxied request; the immediate peer is 127.0.0.1, which is in the
        # trusted list by default.
        "proxy_headers": True,
        "forwarded_allow_ips": config.trusted_proxies,
    }

    if config.ssl_cert and config.ssl_key:
        uvicorn_kwargs["ssl_certfile"] = config.ssl_cert
        uvicorn_kwargs["ssl_keyfile"] = config.ssl_key
        logger.info("Starting server with HTTPS (SSL cert: %s)", config.ssl_cert)
    else:
        logger.info("Starting server with HTTP (no SSL configured)")

    uvicorn.run(**uvicorn_kwargs)
