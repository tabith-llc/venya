# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Session validation middleware.

Validates bearer tokens against active sessions and attaches
user info to request state. Admin and executor mTLS identity is
crypto-verified HERE (end-to-end-mtls-header-trust-removal #314): the
client certificate nginx forwards over the inner mTLS channel (extfile
path header) is re-verified against the CA the app holds itself. No
request header is ever identity — the X-Client-* header chain is
retired; no reads of those headers remain in this package (grep
interlock: tests/test_header_trust_interlock.py).
"""

import logging
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from core.utils.cert_serial import canonical_serial, serial_match_clause
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import load_pem_x509_certificates
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


def _inner_tls_cfg(request: Request) -> Any:
    """Return the InnerTLSConfig when fully wired for forwarded-cert reads, else None.

    An incomplete surface (no config, disabled, or no cert_pem_header) reads
    as "no certificate" everywhere — the mTLS gates then fail closed. There is
    deliberately NO header fallback (ruled Q5): a half-configured inner
    channel rejects, it does not downgrade.
    """
    config = getattr(request.app.state, "config", None)
    inner = getattr(config, "inner_mtls", None) if config is not None else None
    if inner is None or not inner.enabled or not inner.cert_pem_header:
        return None
    return inner


def _forwarded_client_cert(request: Request) -> x509.Certificate | None:
    """Read the nginx-forwarded OUTER client certificate PEM (unverified yet).

    nginx forwards the verified client cert as HEADER CONTENT: the stock
    ``ssl_client_escaped_cert`` variable (nginx >=1.13.5) emits the PEM
    URL-encoded, and the app percent-decodes it. There is NO filesystem
    read, NO path, NO prefix — the content itself is the carrier, so there
    is no traversal surface at all. Guards, each failing closed to None: the
    inner-mTLS surface must be fully wired; the header must be non-empty; the
    decoded bytes must be within the size ceiling; the payload must contain
    EXACTLY one PEM certificate block (concatenation tricks rejected); and
    the bytes must parse as a certificate.

    Why the app re-verifies the PEM even though nginx verified the chain at
    the outer TLS layer: end-to-end-mtls-header-trust-removal (#314) removes
    trust in nginx's forwarding entirely — the app's own crypto decision is
    the gate. Q6 invariant: uvicorn (0.52.1, pinned) discards the INNER peer
    certificate after verifying it, so nothing here — and nothing anywhere —
    can assert the nginx-peer identity at the app layer; the inner channel is
    an ingress seal, not an identity carrier.
    """
    inner = _inner_tls_cfg(request)
    if inner is None:
        return None
    raw = request.headers.get(inner.cert_pem_header)
    if not raw:
        return None
    data = urllib.parse.unquote_to_bytes(raw)
    if len(data) > inner.cert_max_bytes:
        logger.warning("Forwarded cert PEM exceeds size ceiling — rejected")
        return None
    if data.count(b"BEGIN CERTIFICATE") != 1:
        logger.warning("Forwarded cert PEM is not exactly one certificate block — rejected")
        return None
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return None


def _admin_ca_certs(request: Request) -> list[x509.Certificate] | None:
    """Admin-plane trust anchors: startup-loaded bundle, else the configured CA file."""
    loaded = getattr(request.app.state, "admin_trusted_cas", None)
    if loaded:
        return list(loaded)
    config = getattr(request.app.state, "config", None)
    ca_cert = getattr(getattr(config, "admin_mtls", None), "ca_cert", None)
    if not ca_cert:
        return None
    try:
        return load_pem_x509_certificates(Path(ca_cert).read_bytes())
    except Exception:
        logger.exception("Cannot load admin CA bundle from %s — admin mTLS fails closed", ca_cert)
        return None


def _executor_ca_certs(request: Request) -> list[x509.Certificate] | None:
    """Executor-plane trust anchors: the Root CA the CA manager already holds."""
    ca_manager = getattr(request.app.state, "ca_manager", None)
    if ca_manager is not None:
        try:
            return load_pem_x509_certificates(ca_manager.get_ca_cert_pem())
        except Exception:
            logger.exception("Cannot read Root CA from the CA manager — executor mTLS fails closed")
            return None
    config = getattr(request.app.state, "config", None)
    ca_dir = getattr(config, "ca_dir", None)
    if not ca_dir:
        return None
    try:
        return load_pem_x509_certificates((Path(ca_dir) / "ca.crt").read_bytes())
    except Exception:
        return None


def _cert_signature_verifies(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Check whether a leaf's signature cryptographically verifies against a CA anchor."""
    try:
        public_key = issuer.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            return True
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
    except Exception:
        return False
    return False


def _verify_forwarded_cert(request: Request, cert: x509.Certificate, ca_certs: list[x509.Certificate]) -> bool:
    """Crypto-verify a forwarded leaf against its PLANE's CA set (per-plane binding, ruled Q4).

    Checks, every miss returning False (fail-closed): the issuer is a
    presented trust anchor whose BasicConstraints says CA; the leaf's
    validity window holds (plus the configured clock-skew tolerance — nginx
    dropped expired certs at the outer TLS layer; end-to-end the app must
    check too, since app-side verification is now the gate); and the
    signature verifies against that anchor.

    cryptography 50.0.0 (the pin) exposes NO public X.509 path builder
    (``hazmat.primitives.verification`` is absent from the wheel — verified
    against the installed version), so the leaf→single-anchor check is
    explicit. Every CA we issue (root, admin, executor leaves) is one
    signature link under a CA-flagged anchor; multi-hop chains are not an
    issued shape in this product. When a transition bundle contains multiple
    anchors with the same subject name (e.g. during CA rotation), every
    candidate anchor is evaluated until one verifies or all fail closed.
    """
    config = getattr(request.app.state, "config", None)
    tolerance = getattr(getattr(config, "clock_skew", None), "cert_tolerance_seconds", 0) or 0
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc - timedelta(seconds=tolerance):
        return False
    if now > cert.not_valid_after_utc + timedelta(seconds=tolerance):
        return False
    for issuer in ca_certs:
        if issuer.subject != cert.issuer:
            continue
        try:
            if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                continue
        except x509.ExtensionNotFound:
            continue
        if _cert_signature_verifies(cert, issuer):
            return True
    return False


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
            "/health",  # bare alias of /api/v1/health (same handler, same payload)
            "/api/v1/ready",
            "/api/v1/auth/login/start",
            "/api/v1/auth/login/complete",
            "/api/v1/auth/login/browser/challenge",
            "/api/v1/auth/login/browser/assert",
            "/api/v1/auth/refresh",
            # #341: the cookie-plane refresh twin. Public BY DESIGN — the
            # handler self-gates (get_current_session returns None -> 401
            # "Invalid or expired session" in browser_refresh); an
            # idle-expired cookie session stays refreshable until the hard
            # cap, exactly like the bearer tier.
            "/api/v1/auth/refresh/browser",
            "/api/v1/init",
            "/api/v1/init/complete",
            # #450: "/api/v1/init/reset" left this set. It deletes every user,
            # credential, role and membership on the core, so it is no longer
            # reachable anonymously — see BOOTSTRAP_PATHS below for how the
            # pre-initialization bootstrap caller still reaches the handler.
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

    # Bootstrap-plane paths (#450). Authentication is OPPORTUNISTIC here: an
    # identity is attached when the caller presents one (crypto-verified admin
    # mTLS certificate, or a valid bearer/cookie session), but nothing is
    # DENIED at this layer. The handler owns the decision, because on a core
    # that has never been initialized no identity can exist yet — the CLI's
    # `venya init --installation-reset` bootstrap call posts here before any
    # admin account exists (see cli/commands.py cmd_init). The route's own
    # "is the deployment initialized?" predicate is the gate.
    BOOTSTRAP_PATHS = frozenset({"/api/v1/init/reset"})

    # Prefixes that don't require authentication
    PUBLIC_PREFIXES = ("/static/",)  # static assets (CSS, JS, images)

    # Session-demanding admin paths (ticket recovery-reissue-mtls-identity-
    # collision #340, ruled A): when admin-mTLS is enabled the cert is only
    # ONE of two credentials — these routes must ALSO authenticate the
    # presented bearer/cookie session, so the admin-mTLS branch verifies the
    # cert, marks request.state.admin_cert_verified, and falls through to
    # the session branch instead of short-circuiting. Exact strings only;
    # every other admin path keeps the cert-only short-circuit byte-for-byte.
    SESSION_REQUIRED_ADMIN_PATHS = frozenset(
        {
            "/api/v1/admin/recovery-code/reissue",
        }
    )

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

    def _extract_session_token(self, request: Request) -> str | None:
        """Session token from cookie (browser priority) or Bearer header (CLI)."""
        token = request.cookies.get(self.ACCESS_TOKEN_COOKIE)
        if token:
            return token
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def _is_admin_route(self, path: str) -> bool:
        """Check if path is an admin endpoint.

        Args:
            path: The request URL path.

        Returns:
            True if this is an admin route.
        """
        return path.startswith("/api/v1/admin/")

    async def _validate_admin_mtls(
        self,
        request: Request,
        *,
        deny_on_missing_cert: bool = True,
    ) -> JSONResponse | None:
        """Validate the crypto-forwarded client certificate for admin routes.

        When admin_mtls is enabled and the path is an admin route, this
        performs the validation chain (identity read ONLY from a
        cryptographically verified certificate — #314 retired the header
        chain; ruled Q4 binds this plane to the ADMIN CA set, so a Root-CA
        cert — e.g. an executor cert — is refused at the chain check before
        any identity comparison):
        1. Read the nginx-forwarded client-cert PEM (_forwarded_client_cert
           guards) and verify it against the admin trust anchors — missing,
           unparseable, path-escaping, expired, or foreign-chain all fail
           closed 403.
        2. Extract identity from the VERIFIED certificate (SAN RFC822 → SAN
           DNS → CN, _extract_identity_from_cert), check against
           known_admin_ids — an EMPTY allowlist FAILS CLOSED (ticket
           sec-admin-mtls-allowlist-revocation #15)
        3. Check the verified certificate's serial against
           AdminCertRevocation — in-process revocation enforcement,
           fail-closed on backend / lookup error (ticket
           sec-admin-mtls-allowlist-revocation #16; a forwarded cert always
           carries a serial, so the former missing-header branch is gone).

        Args:
            request: The FastAPI request.
            deny_on_missing_cert: True (admin routes) -> a request with no
                client certificate is denied 403, exactly as before.
                False (BOOTSTRAP_PATHS, #450) -> "no certificate presented" is
                simply "no identity": the request continues unauthenticated and
                the handler decides. A certificate that IS presented still runs
                the whole chain/allowlist/revocation check below and denies 403
                on any failure — nothing about a verified-credential comparison
                is relaxed.

        Returns:
            JSONResponse with 403 if validation fails, None if all checks pass
            (or, with deny_on_missing_cert=False, if nothing was presented).
        """
        config = getattr(request.app.state, "config", None)
        if not config or not config.admin_mtls.enabled:
            return None

        path = request.url.path.rstrip("/") if request.url.path != "/" else request.url.path
        if not (self._is_admin_route(path) or path in self.BOOTSTRAP_PATHS):
            return None

        # Step 1: crypto-verified client cert against the ADMIN-plane anchors
        cert = _forwarded_client_cert(request)
        admin_cas = _admin_ca_certs(request) if cert is not None else None
        if cert is None and not deny_on_missing_cert:
            # Bootstrap plane (#450): absence of a certificate is not a denial —
            # the pre-initialization bootstrap caller has no certificate to
            # offer. Anything that IS offered falls through to the full
            # verification below and fails closed.
            logger.debug("Bootstrap path %s: no client certificate presented", path)
            return None
        if cert is None or admin_cas is None or not _verify_forwarded_cert(request, cert, admin_cas):
            logger.warning(
                "Admin route %s: no crypto-verified client certificate — failing closed. "
                "Recovery: ensure the installer regenerated the nginx site (inner mTLS channel "
                "forwards the client cert file) and both nginx and venya-core restarted in the "
                "SAME maintenance window.",
                path,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Step 2: identity = SAN (RFC822 → DNS) or CN of the VERIFIED cert
        try:
            identity = _extract_identity_from_cert(cert)
        except ValueError:
            logger.warning("Admin route %s: verified certificate has neither SAN nor CN", path)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Admin access requires valid client certificate"},
            )

        # Allowlist FAILS CLOSED when empty (ticket
        # sec-admin-mtls-allowlist-revocation #15). Ruled-Q4 per-plane anchors
        # already refuse Root-CA certs at the chain check above, but the
        # allowlist stays a defense-in-depth layer (any Admin-CA cert must
        # still name an enumerated identity). The 403 detail stays generic
        # here (the caller may be any cert holder); recovery guidance goes to
        # the server-side log.
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

        # Step 3: in-process revocation check on the VERIFIED cert's serial
        # (ticket sec-admin-mtls-allowlist-revocation #16). POST
        # /admin/certs/revoke records AdminCertRevocation rows; nginx has no
        # ssl_crl, so this lookup is the enforcement point. The serial can no
        # longer be "absent" (it comes from the certificate object, not a
        # header) — the former missing-header fail-closed branch is retired by
        # construction; backend-absence and lookup-error still fail closed.
        # Serial match is case- AND padding-insensitive (ticket
        # cert-serial-canonicalization-mismatch #481): the serial is written in
        # the ONE canonical form, and the lookup compares match keys so legacy
        # rows stored unpadded/upper/lower still refuse the certificate they
        # name. (Before this, a 1/16-of-serials slice got a revocation that
        # recorded green and never took effect.)
        presented_serial = canonical_serial(cert.serial_number)

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

            revoked = (
                db.query(AdminCertRevocation)
                .filter(serial_match_clause(AdminCertRevocation.serial_number, presented_serial))
                .first()
            )
            if revoked is None:
                # One line at the enforcement point, naming WHICH no-match this
                # is: an empty table is a fresh install, a non-empty table that
                # missed is where a failed revocation would hide (#481).
                rows_exist = db.query(AdminCertRevocation.serial_number).first() is not None
                logger.info(
                    "Admin route %s: serial %s admitted — %s",
                    path,
                    presented_serial,
                    "no revocation row matched the rows on file" if rows_exist else "no revocation rows exist",
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

        # Audit-forwarder ingest: executor mTLS (ticket
        # audit-forwarder-server-sink #307). Runs with reject_revoked=False
        # per D2 ruling (owner 2026-10-01): a REVOKED registered executor's
        # forwarded evidence still LANDS, route-side flagged
        # fields.sender_revoked=true — pre-revocation rejections may be the
        # evidence motivating the revocation. NOTE the purpose differs from
        # the heartbeat's reject_revoked=False: there it is the advisory
        # cooperative-stop channel (ruling B1); here it is EVIDENCE
        # PRESERVATION — a 403-retry loop would end in the forwarder's
        # drop-oldest spool loss. Forged/unregistered senders still get the
        # full 401/403 refusal; the route re-checks caller == "executor".
        if request.url.path == "/api/v1/audit/ingest":
            executor_result = await self._validate_executor_mtls(request, reject_revoked=False)
            if executor_result is not None:
                return executor_result
            return await call_next(request)

        # Bootstrap plane (#450): POST /api/v1/init/reset left PUBLIC_PATHS, so
        # an anonymous caller is no longer waved through. Identity is attached
        # when one is offered — admin mTLS certificate first (the headless-core
        # CLI form), otherwise a bearer/cookie session — and the request then
        # reaches the handler either way. The handler refuses anything that did
        # not authenticate as an admin once the deployment is initialized; a
        # core with nothing to protect yet (fresh install, abandoned ceremony)
        # has no identity to require and keeps its bootstrap path.
        if path in self.BOOTSTRAP_PATHS:
            config = getattr(request.app.state, "config", None)
            if config and config.admin_mtls.enabled:
                mtls_result = await self._validate_admin_mtls(request, deny_on_missing_cert=False)
                if mtls_result is not None:
                    return mtls_result
            if getattr(request.state, "auth_user", None) is None:
                token = self._extract_session_token(request)
                if token:
                    session_user = await self._validate_token(request, token)
                    if session_user is None:
                        return JSONResponse(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            content={"detail": "Invalid or expired token"},
                        )
                    request.state.auth_user = session_user
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
            if path in self.SESSION_REQUIRED_ADMIN_PATHS:
                # #340 ruled A: the verified cert opens the CHANNEL; the
                # human session is the second credential. Mark the channel
                # and run any presented bearer/cookie token through the same
                # validation the session branch below performs, so auth_user
                # becomes the session. With NO token the cert identity stays
                # and the route's session guard denies 401 (cert-alone
                # never mints); the route additionally requires the flag
                # below, so a session-alone request never mints either.
                request.state.admin_cert_verified = True
                session_token = self._extract_session_token(request)
                if session_token:
                    session_user = await self._validate_token(request, session_token)
                    if session_user is None:
                        return JSONResponse(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            content={"detail": "Invalid or expired token"},
                        )
                    request.state.auth_user = session_user
            return await call_next(request)

        # Extract token: cookie (browser) takes priority, then bearer header (CLI)
        token = self._extract_session_token(request)

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
        response = await call_next(request)
        # #341: if this request slid the session row forward AND the credential
        # rode the browser cookie plane, re-issue the SAME-value cookie with a
        # fresh max_age = configured session_timeout. Without this the DB row
        # slides but the browser still drops the cookie at its stale expiry.
        # Bearer (CLI/MCP) requests carry no cookie and are untouched.
        if getattr(request.state, "session_extended", False) and request.cookies.get(self.ACCESS_TOKEN_COOKIE):
            session_cfg = getattr(getattr(request.app.state, "config", None), "session", None)
            if session_cfg is not None:
                response.set_cookie(
                    key=self.ACCESS_TOKEN_COOKIE,
                    value=token,
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    max_age=session_cfg.session_timeout,
                    path="/",
                )
        return response

    async def _validate_executor_mtls(self, request: Request, reject_revoked: bool = True) -> JSONResponse | None:
        """Validate executor mTLS identity for executor session paths.

        Grants ``caller=executor`` ONLY on a client certificate that the APP
        cryptographically verifies against the Root CA (ruled Q4 binds this
        plane to the executor/root anchors — an Admin-CA cert presenting an
        executor-shaped CN is refused at the chain check, the former
        CN-discriminator path). Identity and serial are read from the
        verified certificate object; the X-Client-* header chain is retired
        (#314). Forwarding rides the inner mTLS channel: the direct app-port
        connect dies at the TLS handshake (uvicorn ``ssl_cert_reqs=
        CERT_REQUIRED``), and with no inner channel the forwarded cert file
        simply never arrives — both halves fail closed, no header fallback
        (ruled Q5).

        Serial handling: the presented serial now ALWAYS comes from the
        verified certificate (never "absent"). ``executor_revocation_state``
        still defines the no-serial fallback semantics for the other callers
        (dial/heartbeat/display); this path simply cannot exercise it.

        Args:
            request: The FastAPI request.
            reject_revoked: True (session paths) → a revoked identity gets
                403. False (heartbeat) → revocation is NOT rejected here; the
                route returns the revoked flag in its 200 response (the F3
                ride-along cooperative-stop channel) and skips the row write.

        Returns:
            JSONResponse (401/403) on failure, None if all checks pass
            (auth_user set with caller, executor_id, presented_serial, revoked).
        """
        detail = "Executor mTLS authentication required"
        path = request.url.path

        # Step 1: crypto-verified client cert against the EXECUTOR-plane anchors
        cert = _forwarded_client_cert(request)
        executor_cas = _executor_ca_certs(request) if cert is not None else None
        if cert is None or executor_cas is None or not _verify_forwarded_cert(request, cert, executor_cas):
            logger.warning("Executor session path %s: no crypto-verified client certificate", path)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": detail},
            )

        # Step 2: executor identity = SAN/CN of the VERIFIED cert
        try:
            executor_id = _extract_identity_from_cert(cert)
        except ValueError:
            logger.warning("Executor session path %s: verified certificate has neither SAN nor CN", path)
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

            presented_serial = canonical_serial(cert.serial_number)
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

            request.state.auth_user = {
                "caller": "executor",
                "executor_id": executor_id,
                # Stash the admission inputs + verdict so downstream routes
                # (audit ingest) share ONE derivation by construction —
                # ticket audit-ingest-revoked-serial-flag-divergence, option (a).
                "presented_serial": presented_serial,
                "revoked": rev.revoked,
            }  # type: ignore[attr-defined]
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

            # #342: bearer-tier gate. The advertised access_token_ttl is
            # enforced here on the persisted expiry, immediately after the
            # session gates and before the user-status gate. FAIL-CLOSED:
            # NULL (pre-migration rows) or a past timestamp -> reject via
            # the existing 401 path. SQLite test rows arrive naive; PG is
            # aware — normalize to aware UTC before comparing.
            token_expiry = getattr(session, "access_token_expires_at", None)
            if token_expiry is None:
                logger.info("Bearer token for session %s rejected: no persisted token expiry", session.id)
                return None
            if token_expiry.tzinfo is None:
                token_expiry = token_expiry.replace(tzinfo=UTC)
            if token_expiry < datetime.now(UTC):
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
                # #341: dispatch re-issues the cookie plane's Set-Cookie when
                # the row was slid forward on this very request.
                request.state.session_extended = True

            return user_info
        finally:
            db.close()
