"""Session validation middleware.

Validates bearer tokens against active sessions and attaches
user info to request state. Supports mTLS-based admin endpoint
authentication via Caddy-layer client certificate verification.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from core.utils.sensitive_log import token as sensitive_token
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
            "/api/v1/auth/registration/start",
            "/api/v1/auth/registration/complete",
            "/api/v1/auth/login/start",
            "/api/v1/auth/login/complete",
            "/api/v1/auth/login/browser/challenge",
            "/api/v1/auth/login/browser/assert",
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
            "/api/v1/enroll/browser/start",
            "/api/v1/enroll/browser/complete",
            "/api/v1/enroll/browser",
            # --- static HTML pages: no auth required ---
            "/",  # login page (public)
            "/enroll",  # user enrollment page (public)
            "/enroll-admin",  # admin enrollment page (public)
            "/dashboard",  # dashboard page (public)
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
        performs a 2-step validation chain:
        1. Check X-Client-Verified sentinel header
        2. Extract identity from X-Client-Subject DN, check against known_admin_ids

        Caddy verifies the cert chain and expiration at the TLS layer
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
        if verified != "true":
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

        known_ids = config.admin_mtls.known_admin_ids  # type: ignore[union-attr]
        if known_ids and identity not in known_ids:
            logger.warning("Admin route %s: identity '%s' not in known_admin_ids", path, identity)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
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

        # Skip mTLS paths (executor)
        if self._is_mtls_request(request):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
            return await call_next(request)

        # Skip executor session paths (mTLS auth, not bearer token)
        if self._is_executor_session_path(request.url.path):
            request.state.auth_user = {"caller": "executor"}  # type: ignore[attr-defined]
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

        logger.info(
            "AUTH DEBUG: cookies=%s, ACCESS_TOKEN_COOKIE=%s, token=%s",
            dict(request.cookies),
            self.ACCESS_TOKEN_COOKIE,
            sensitive_token(token, "ACCESS") if token else "None",
        )

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
            from core.iam.session_manager import SessionManager

            config = CoreSessionConfig(
                session_timeout=timedelta(minutes=15),
                access_token_ttl=timedelta(minutes=5),
                max_session_duration=timedelta(hours=4),
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
