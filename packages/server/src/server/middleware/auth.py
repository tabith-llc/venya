"""Session validation middleware.

Validates bearer tokens against active sessions and attaches
user info to request state. Supports mTLS-based admin endpoint
authentication via Caddy-layer client certificate verification.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from ..utils.time import has_not_yet_started, is_expired

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
    PUBLIC_PATHS = frozenset({
        "/api/v1/health",
        "/api/v1/ready",
        "/api/v1/auth/registration/start",
        "/api/v1/auth/registration/complete",
        "/api/v1/auth/login/start",
        "/api/v1/auth/login/complete",
        "/api/v1/auth/refresh",
        "/api/v1/enrollment/confirm",
        "/api/v1/init",
        "/api/v1/init/complete",
        "/api/v1/init/reset",
        "/api/v1/recovery",
        "/api/v1/executors/register",
        "/api/v1/executors/certs/revocation-list",
        "/api/v1/executors/certs/crl",
        "/api/v1/heartbeat",
        "/api/v1/auth/login/browser/challenge",
        "/api/v1/auth/login/browser/assert",
        "/api/v1/auth/refresh/browser",
        "/api/v1/auth/logout/browser",
        "/api/v1/enroll/browser/start",
        "/api/v1/enroll/browser/complete",
        "/api/v1/auth/elevate/browser/challenge",
        "/api/v1/auth/elevate/browser/assert",
        "/",
        "/enroll",
        "/enroll-admin",
        "/dashboard",
        "/admin/users",
        "/admin/tokens",
        "/credentials",
        "/favicon.ico",
        "/static",
    })

    ACCESS_TOKEN_COOKIE = "venya_access_token"

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
        performs a 7-step validation chain:
        1. Check X-Client-Verified sentinel header
        2. Parse X-Client-Cert PEM header
        3. Verify cert signature against admin CA
        4. Verify cert not expired (±5min clock skew)
        5. Extract identity (SAN DNS or CN)
        6. Check identity against known_admin_ids
        7. Check revocation in AdminCertRevocation table

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
        if verified != "true":
            logger.warning("Admin route %s: missing or invalid X-Client-Verified header", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 2: Parse X-Client-Cert PEM header
        cert_pem_header = request.headers.get("x-client-cert")
        if not cert_pem_header:
            logger.warning("Admin route %s: missing X-Client-Cert header", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Decode PEM header (may have spaces/newlines removed by HTTP layer)
        cert_pem_data = cert_pem_header.encode("utf-8")
        # Reconstruct PEM format if needed
        if b"-----BEGIN CERTIFICATE-----" not in cert_pem_data:
            # Try adding PEM headers
            try:
                # The header might be base64-encoded DER or raw PEM without headers
                # Try to decode as base64 first
                import base64
                der_bytes = base64.b64decode(cert_pem_data)
                cert = x509.load_der_x509_certificate(der_bytes)
            except Exception:
                logger.warning("Admin route %s: failed to parse X-Client-Cert header", path)
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Admin access requires valid client certificate"},
                )
        else:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem_data)
            except Exception:
                logger.warning("Admin route %s: failed to parse X-Client-Cert PEM", path)
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Admin access requires valid client certificate"},
                )

        # Step 3: Verify cert signature against admin CA
        admin_ca_cert_path = config.admin_mtls.ca_cert
        if not admin_ca_cert_path:
            logger.warning("Admin route %s: admin CA cert path not configured", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        try:
            admin_ca_cert = x509.load_pem_x509_certificate(Path(admin_ca_cert_path).read_bytes())
        except Exception:
            logger.exception("Admin route %s: failed to load admin CA cert", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        try:
            _verify_cert_against_ca(cert, admin_ca_cert)
        except Exception:
            logger.warning("Admin route %s: cert signature verification failed", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 4: Verify cert not expired (config-driven clock skew tolerance)
        config = getattr(request.app.state, "config", None)
        cert_tolerance = (
            config.clock_skew.cert_tolerance_seconds
            if config and hasattr(config, "clock_skew")
            else 300
        )
        now = datetime.now(timezone.utc)
        if has_not_yet_started(cert.not_valid_before_utc, cert_tolerance):
            logger.warning("Admin route %s: cert not yet valid", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Client certificate is not yet valid"},
            )
        if is_expired(cert.not_valid_after_utc, cert_tolerance):
            logger.warning("Admin route %s: cert expired", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Client certificate has expired"},
            )

        # Step 5: Extract identity (SAN DNS preferred, CN fallback)
        try:
            identity = _extract_identity_from_cert(cert)
        except ValueError:
            logger.warning("Admin route %s: cert has no SAN or CN", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 6: Check identity against known_admin_ids
        known_ids = config.admin_mtls.known_admin_ids
        if known_ids and identity not in known_ids:
            logger.warning("Admin route %s: identity '%s' not in known_admin_ids", path, identity)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 7: Check revocation in AdminCertRevocation table
        backend = getattr(request.app.state, "backend", None)
        if backend is not None:
            db = backend.get_session()
            try:
                from vault.iam.models import AdminCertRevocation
                serial_hex = hex(cert.serial_number)[2:]  # Remove '0x' prefix
                # Pad to even length for consistent hex representation
                if len(serial_hex) % 2:
                    serial_hex = "0" + serial_hex
                serial_hex = serial_hex.lower()
                revoked = db.query(AdminCertRevocation).filter(
                    AdminCertRevocation.serial_number == serial_hex
                ).first()
                if revoked:
                    logger.warning("Admin route %s: cert serial %s is revoked", path, serial_hex)
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Client certificate has been revoked"},
                    )
            finally:
                db.close()

        return None  # All checks passed, continue to bearer token auth

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Normalize path: strip trailing slash except for root "/"
        path = request.url.path.rstrip("/") if request.url.path != "/" else request.url.path

        # Skip auth for public paths
        if path in self.PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth for static assets (any path starting with /static/)
        if path.startswith("/static/"):
            return await call_next(request)

        # Skip mTLS paths (executor)
        if self._is_mtls_request(request):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
            return await call_next(request)

        # Skip executor session paths (mTLS auth, not bearer token)
        if self._is_executor_session_path(request.url.path):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
            return await call_next(request)

        # Admin mTLS validation (before bearer token auth)
        if getattr(request.app.state, "config", None) and \
           request.app.state.config.admin_mtls.enabled and \
           self._is_admin_route(path):
            mtls_result = await self._validate_admin_mtls(request)
            if mtls_result is not None:
                return mtls_result

        # Extract token: cookie (browser) takes priority, then bearer header (CLI)
        token = request.cookies.get(self.ACCESS_TOKEN_COOKIE)
        if not token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        logger.info("AUTH DEBUG: cookies=%s, ACCESS_TOKEN_COOKIE=%s, token=%s", dict(request.cookies), self.ACCESS_TOKEN_COOKIE, token[:20] if token else "None")

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

    def _is_mtls_request(self, request: Request) -> bool:
        """Check if request was authenticated via mTLS."""
        # mTLS client cert info would be available via ASGI scope
        client_cert = request.scope.get("client_cert")
        return client_cert is not None

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

        return bool(re.match(r"^/api/v1/sessions/[^/]+/secrets/revoke$", path))

    async def _validate_token(
        self, request: Request, token: str
    ) -> dict | None:
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
            from vault.iam.session_manager import SessionManager
            from vault.iam.session_manager import SessionConfig as VaultSessionConfig
            from vault.iam.models import Session as SessionModel
            from datetime import timedelta

            config = VaultSessionConfig(
                session_timeout=timedelta(minutes=15),
                access_token_ttl=timedelta(minutes=5),
                max_session_duration=timedelta(hours=4),
            )
            manager = SessionManager(db, config)

            # Find session by access token
            session = (
                db.query(SessionModel)
                .filter(SessionModel.access_token == token)
                .first()
            )

            if session is None:
                return None

            if not manager.check_expiry(session):
                return None

            # Get user info
            user = session.user
            user_info = {
                "user_id": user.user_id,
                "session_id": session.id,
                "roles": [],
                "exp": int(session.expires_at.timestamp()),
            }

            # Get role IDs for this user
            from vault.iam.role_manager import RoleManager
            rm = RoleManager(db)
            user_roles = rm.get_user_roles(user.user_id)
            user_info["roles"] = [str(m.role_id) for m in user_roles]

            # Auto-refresh: if token is near expiry, create new token
            now = datetime.now(timezone.utc)
            if session.expires_at < now + timedelta(seconds=60):
                new_token = manager.refresh_token(token)
                if new_token:
                    user_info["session_id"] = session.id
                    # Token will be refreshed in response headers by a separate mechanism

            return user_info
        finally:
            db.close()
