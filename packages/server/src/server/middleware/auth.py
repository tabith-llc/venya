# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Session validation middleware.

Validates bearer tokens against active sessions and attaches
user info to request state. Supports mTLS-based admin endpoint
authentication via Nginx-layer client certificate verification.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("venya.server")


def _extract_identity_from_cert(cert: x509.Certificate) -> str:
    """Extract admin identity from a client certificate.

    Prefers SAN RFC822Name (email), then SAN DNSName, falls back to CN.

    Args:
        cert: The X.509 certificate to extract identity from.

    Returns:
        The identity string (SAN RFC822, SAN DNS, or CN value).

    Raises:
        ValueError: If certificate has neither SAN nor CN.
    """
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        if emails:
            return emails[0]
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if dns_names:
            return dns_names[0]
    except x509.ExtensionNotFound:
        pass
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    raise ValueError("Certificate has neither SAN nor CN")


def _extract_identity_from_subject(subject_dn: str) -> str:
    """Extract the CN value from a subject DN string.

    Example: 'CN=admin@venya-core-1,OU=Admin,O=Venya' -> 'admin@venya-core-1'

    Args:
        subject_dn: The subject DN string from the X-Client-Subject header.

    Returns:
        The CN value, or empty string if not found.
    """
    for field in subject_dn.split(","):
        field = field.strip()
        if field.upper().startswith("CN="):
            return field[3:]
    return ""


def _verify_cert_against_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify a certificate was signed by the admin CA.

    Args:
        cert: The certificate to verify.
        ca_cert: The admin CA certificate.

    Returns:
        True if the signature is valid.
    """
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )
    return True


class SessionMiddleware(BaseHTTPMiddleware):
    """Validates session tokens and manages token rotation.

    Accepts authentication via HttpOnly cookie (browser) or Bearer token
    (CLI). Extracts the token, looks up the session, validates it's not
    expired, and attaches user info to request.state.auth_user.
    """

    # Paths that don't require authentication
    PUBLIC_PATHS = frozenset(
        {
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/auth/login/start",
            "/api/v1/auth/login/complete",
            "/api/v1/auth/login/browser/challenge",
            "/api/v1/auth/login/browser/assert",
            "/api/v1/auth/refresh",
            "/api/v1/init",
            "/api/v1/init/complete",
            "/api/v1/init/reset",
            "/api/v1/recovery",
            "/api/v1/executors/register",
            "/api/v1/executors/certs/revocation-list",
            "/api/v1/executors/certs/crl",
            "/api/v1/enroll/browser/start",
            "/api/v1/enroll/browser/complete",
            "/api/v1/enroll/browser",
            # --- static HTML pages: no auth required ---
            "/",  # login page (public)
            "/enroll",  # user enrollment page (public)
            "/enroll-admin",  # admin enrollment page (public)
        }
    )

    # Prefixes that don't require authentication
    PUBLIC_PREFIXES = ("/static/",)  # static assets (CSS, JS, images)

    ACCESS_TOKEN_COOKIE = "venya_access_token"  # nosec B105 — cookie name, not a password

    def __init__(self, app: Any = None, max_token_age: float = 300.0) -> None:
        """
        Args:
            app: The next ASGI app.
            max_token_age: Maximum age in seconds for a bearer token before
                requiring refresh.
        """
        super().__init__(app)
        self.max_token_age = max_token_age

    def _is_admin_route(self, path: str) -> bool:
        """Check if path is an admin endpoint.

        Args:
            path: The request URL path.

        Returns:
            True if this is an admin route.
        """
        return path.startswith("/api/v1/admin/")

    async def _validate_admin_mtls(self, request: Request) -> JSONResponse | None:
        """Validate mTLS client certificate for admin routes.

        When admin_mtls is enabled and the path is an admin route, this
        performs a 3-step validation chain:
        1. Check X-Client-Verified sentinel header
        2. Extract identity from X-Client-Subject DN, check against
           known_admin_ids — an EMPTY allowlist FAILS CLOSED (ticket
           sec-admin-mtls-allowlist-revocation #15)
        3. Check X-Client-Serial against AdminCertRevocation — in-process
           revocation enforcement, fail-closed on missing serial / backend /
           lookup error (ticket sec-admin-mtls-allowlist-revocation #16)

        Nginx verifies the cert chain and expiration at the TLS layer
        (verify_if_given/require_and_verify). This middleware checks identity.

        Args:
            request: The FastAPI request.

        Returns:
            JSONResponse with 403 if validation fails, None if all checks pass.
        """
        config = getattr(request.app.state, "config", None)
        if not config or not config.admin_mtls.enabled:
            return None

        path = request.url.path.rstrip("/") if request.url.path != "/" else request.url.path
        if not self._is_admin_route(path):
            return None

        # Step 1: Check X-Client-Verified sentinel header
        verified = request.headers.get("x-client-verified")
        if verified != "SUCCESS":
            logger.warning("Admin route %s: missing or invalid X-Client-Verified header", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 2: Extract identity from X-Client-Subject header
        subject_dn = request.headers.get("x-client-subject", "")
        if not subject_dn:
            logger.warning("Admin route %s: missing X-Client-Subject header", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        identity = _extract_identity_from_subject(subject_dn)
        if not identity:
            logger.warning("Admin route %s: could not extract identity from subject DN", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Allowlist FAILS CLOSED when empty (ticket
        # sec-admin-mtls-allowlist-revocation #15): the nginx trust bundle
        # carries Root CA + Admin CA — architecturally forced, the executor
        # session path shares it — so an empty allowlist would admit ANY
        # Root-CA cert (e.g. an executor cert) as caller=admin. The 403 detail
        # stays generic here (the caller may be any cert holder); recovery
        # guidance goes to the server-side log.
        known_ids = config.admin_mtls.known_admin_ids  # type: ignore[union-attr]
        if not known_ids:
            logger.warning(
                "Admin route %s: known_admin_ids is EMPTY — failing closed. "
                "Set VENYA_ADMIN_IDENTITY (the installer writes it); ticket "
                "sec-admin-mtls-allowlist-revocation.",
                path,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )
        if identity not in known_ids:
            logger.warning("Admin route %s: identity '%s' not in known_admin_ids", path, identity)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 3: serial presentation + in-process revocation check (ticket
        # sec-admin-mtls-allowlist-revocation #16). POST /admin/certs/revoke
        # recorded AdminCertRevocation rows that nothing consulted in-process
        # (CRL generation only; nginx has no ssl_crl). Missing serial FAILS
        # CLOSED (user ruling 2026-09-20): warn-open would leave the
        # revocation bypass alive on every pre-header nginx config, silently.
        # The caller at this point is an allowlisted admin identity, so the
        # detail carries the recovery path. Serial match is case-insensitive:
        # legacy rows store the serial as-provided, nginx $ssl_client_serial
        # is uppercase; new writes normalize at the storage boundary (admin.py).
        presented_serial = (request.headers.get("x-client-serial") or "").strip()
        if not presented_serial:
            logger.warning(
                "Admin route %s: X-Client-Serial missing — failing closed. "
                "Recovery: re-run the core installer (idempotent) to regenerate "
                "the nginx site config, then `systemctl restart venya-core` in "
                "the SAME maintenance window and re-verify an admin mTLS call "
                "(installer re-runs do NOT restart a running core — ticket "
                "installer-rerun-no-service-restart).",
                path,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": "Admin mTLS misconfigured: certificate serial not presented. "
                    "Recovery: re-run the core installer to regenerate the nginx site "
                    "config, then restart venya-core and retry."
                },
            )

        backend = getattr(request.app.state, "backend", None)
        if backend is None:
            logger.warning("Admin route %s: backend unavailable — failing closed", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        db = backend.get_session()
        try:
            from core.iam.models import AdminCertRevocation
            from sqlalchemy import func

            revoked = (
                db.query(AdminCertRevocation)
                .filter(func.upper(AdminCertRevocation.serial_number) == presented_serial.upper())
                .first()
            )
        except Exception:
            logger.exception("Admin route %s: revocation lookup failed — failing closed", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )
        finally:
            db.close()

        if revoked is not None:
            logger.warning(
                "Admin route %s: certificate serial %s is revoked (reason: %s)",
                path,
                presented_serial,
                revoked.reason,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin certificate revoked"},
            )

        # All checks passed
        request.state.auth_user = {"caller": "admin", "user_id": identity}
        return None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Normalize path: strip trailing slash except for root "/"
        path = request.url.path.rstrip("/") if request.url.path != "/" else request.url.path

        # Skip auth for public paths
        if path in self.PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth for public path prefixes
        if any(path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES):
            return await call_next(request)

        # Executor session paths (filter / secrets-revoke): require a verified
        # executor mTLS identity (ticket sec-executor-session-path-no-auth —
        # the URL regex alone used to grant caller=executor with no credential
        # check, an anonymous secret-confirmation oracle + audit-forgery hole).
        if self._is_executor_session_path(request.url.path):
            executor_result = await self._validate_executor_mtls(request)
            if executor_result is not None:
                return executor_result
            # auth_user set by _validate_executor_mtls
            return await call_next(request)

        # Heartbeat: executor mTLS as well (ticket
        # sec-endpoint-ratelimit-hardening #7 — was PUBLIC: unauthenticated
        # fleet-liveness stamping + revocation/rotation oracle). Runs with
        # reject_revoked=False: the F3 ride-along ruling makes the 200
        # {revoked:true} RESPONSE the fast cooperative-stop channel — a 403
        # here would kill it (user ruling B1 2026-09-20). The route binds
        # body executor_id to the cert CN and skips the row write for
        # revoked callers.
        if request.url.path == "/api/v1/heartbeat":
            executor_result = await self._validate_executor_mtls(request, reject_revoked=False)
            if executor_result is not None:
                return executor_result
            return await call_next(request)

        # Admin mTLS validation (before bearer token auth)
        if (
            getattr(request.app.state, "config", None)
            and request.app.state.config.admin_mtls.enabled
            and self._is_admin_route(path)
        ):
            mtls_result = await self._validate_admin_mtls(request)
            if mtls_result is not None:
                return mtls_result
            # mTLS validation passed — _validate_admin_mtls already set auth_user with identity
            return await call_next(request)

        # Extract token: cookie (browser) takes priority, then bearer header (CLI)
        token = request.cookies.get(self.ACCESS_TOKEN_COOKIE)
        if not token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing authentication token"},
            )

        # Validate token via backend
        user_info = await self._validate_token(request, token)
        if user_info is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired token"},
            )

        request.state.auth_user = user_info  # type: ignore[attr-defined]
        return await call_next(request)

    async def _validate_executor_mtls(self, request: Request, reject_revoked: bool = True) -> JSONResponse | None:
        """Validate executor mTLS identity for executor session paths.

        Grants ``caller=executor`` ONLY on a verified client cert whose CN is
        a registered, non-revoked executor. Trust model mirrors
        ``_validate_admin_mtls``: nginx terminates TLS (``ssl_verify_client
        optional`` against the Root+Admin CA bundle) and OVERWRITES the
        X-Client-* headers via ``proxy_set_header``; the app binds
        loopback-only (installer ``BIND_ADDRESS=127.0.0.1``), so nginx is the
        only ingress and the headers cannot be client-spoofed. That loopback
        bind is a SHARED DEPLOYMENT INVARIANT with the admin-mTLS path —
        exposing the app port directly defeats both gates.

        Serial handling (deliberate, named decision): X-Client-Serial is
        passed through when present. When absent/empty (e.g. an nginx config
        predating the Phase-2 header addition), ``executor_revocation_state``
        falls back to the current ExecutorCert record serial per its ruled
        semantics — identity-flag and current-credential serial revocations
        still apply; only a rotated-away predecessor serial needs the
        presented header. Missing serial never fails open past those.

        Args:
            request: The FastAPI request.
            reject_revoked: True (session paths) → a revoked identity gets
                403. False (heartbeat) → revocation is NOT rejected here; the
                route returns the revoked flag in its 200 response (the F3
                ride-along cooperative-stop channel) and skips the row write.

        Returns:
            JSONResponse (401/403) on failure, None if all checks pass
            (auth_user set with caller + executor_id).
        """
        detail = "Executor mTLS authentication required"
        path = request.url.path

        # Step 1: nginx TLS-layer verification sentinel
        verified = request.headers.get("x-client-verified")
        if verified != "SUCCESS":
            logger.warning("Executor session path %s: X-Client-Verified missing or not SUCCESS", path)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": detail},
            )

        # Step 2: executor identity = CN of the verified client cert
        subject_dn = request.headers.get("x-client-subject", "")
        executor_id = _extract_identity_from_subject(subject_dn)
        if not executor_id:
            logger.warning("Executor session path %s: could not extract CN from X-Client-Subject", path)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": detail},
            )

        # Step 3+4: allowlist (registered Executor row) + revocation, routed
        # through the single revocation source (server/revocation.py contract)
        backend = getattr(request.app.state, "backend", None)
        if backend is None:
            logger.warning("Executor session path %s: backend unavailable — failing closed", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": detail},
            )

        db = backend.get_session()
        try:
            from core.iam.models import Executor

            from ..revocation import executor_revocation_state

            row = db.query(Executor).filter(Executor.id == executor_id).first()
            if row is None:
                logger.warning("Executor session path %s: CN '%s' is not a registered executor", path, executor_id)
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": detail},
                )

            presented_serial = request.headers.get("x-client-serial") or None
            rev = executor_revocation_state(db, executor_id, presented_serial=presented_serial, executor_row=row)
            if rev.revoked:
                if reject_revoked:
                    logger.warning(
                        "Executor session path %s: CN '%s' revoked (%s)",
                        path,
                        executor_id,
                        rev.reason,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": detail},
                    )
                # reject_revoked=False (heartbeat path): identity stays
                # verified; the ROUTE returns the revoked flag in its 200
                # response (F3 cooperative-stop channel, ruling B1) and skips
                # the row write for revoked callers.
                logger.info(
                    "Heartbeat from revoked executor CN '%s' (%s) — passing to route for the advisory flag",
                    executor_id,
                    rev.reason,
                )

            request.state.auth_user = {"caller": "executor", "executor_id": executor_id}  # type: ignore[attr-defined]
            return None
        finally:
            db.close()

    def _is_executor_session_path(self, path: str) -> bool:
        """Check if path is an executor session endpoint.

        These paths use mTLS auth (not bearer tokens) and should
        bypass token-based authentication.

        Args:
            path: The request URL path.

        Returns:
            True if this is an executor session path.
        """
        import re

        return bool(re.match(r"^/api/v1/sessions/[^/]+/(secrets/revoke|filter)$", path))

    async def _validate_token(self, request: Request, token: str) -> dict | None:
        """Validate a bearer token and return user info.

        Args:
            request: The FastAPI request.
            token: The bearer token string.

        Returns:
            User info dict or None if invalid.
        """
        backend = getattr(request.app.state, "backend", None)
        if backend is None:
            return None

        db = backend.get_session()
        try:
            from datetime import timedelta

            from core.iam.models import Session as SessionModel
            from core.iam.session_manager import SessionConfig as CoreSessionConfig
            from core.iam.session_manager import SessionManager, is_user_active

            sc = request.app.state.config.session
            config = CoreSessionConfig(
                session_timeout=timedelta(seconds=sc.session_timeout),
                access_token_ttl=timedelta(seconds=sc.access_token_ttl),
                max_session_duration=timedelta(seconds=sc.max_session_duration),
            )
            manager = SessionManager(db, config)

            # Find session by access token
            session = db.query(SessionModel).filter(SessionModel.access_token == token).first()

            if session is None:
                return None

            if not manager.check_expiry(session):
                return None

            # Get user info
            user = session.user

            # Surviving-session status gate (sec-auth-elevation-authz-hardening
            # #9): issuance is gated in create_session (UserNotActiveError),
            # but WITHOUT this check a disabled user's EXISTING sessions keep
            # full access until idle expiry / hard cap. Central predicate —
            # is_user_active is the single semantic source (session_manager.py).
            if not is_user_active(user):
                logger.warning("Session for user %s rejected: user is not active", session.user_id)
                return None

            user_info = {
                "user_id": user.user_id,
                "session_id": session.id,
                "roles": [],
                "exp": int(session.expires_at.timestamp()),
            }

            # Get role IDs for this user
            from core.iam.role_manager import RoleManager

            rm = RoleManager(db)
            user_roles = rm.get_user_roles(user.user_id)
            user_info["roles"] = [str(m.role_id) for m in user_roles]

            # Extend session if nearing expiry (self-debouncing: after extension,
            # expires_at resets to now + session_timeout, so the condition
            # can only re-fire >= session_timeout * 2/3 later).
            # 5-minute threshold on a 15-minute session = extend when <1/3 remains.
            now = datetime.now(UTC)
            if session.expires_at < now + timedelta(minutes=5):
                manager.extend_session(session.id)
                db.commit()

            return user_info
        finally:
            db.close()
