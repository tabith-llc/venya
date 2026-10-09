# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""HTTP client for server API.

Handles authentication, error handling, and retries for CLI-to-server
communication. Integrates with FIDO2 for WebAuthn-based authentication
and manages short-lived access tokens with transparent refresh.

Token model (per plan section 5.1):
    - Session: 15 min idle timeout (configurable)
    - Access token: 5 min lifetime, transparently refreshed
    - Tokens stored in memory only (no disk persistence)
"""

import logging
import os
import re
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx2

logger = logging.getLogger("venya_cli.api_client")


def default_config_dir() -> Path:
    """Platform-appropriate config directory.

    macOS convention: ~/Library/Application Support/venya.
    Windows convention: %APPDATA%/venya.
    POSIX (Linux, etc.): ~/.config/venya.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "venya"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return Path(appdata or Path.home() / "AppData" / "Roaming") / "venya"
    return Path.home() / ".config" / "venya"


# Default config file location
DEFAULT_CONFIG_DIR = default_config_dir()
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


def execution_timeout() -> float:
    """Read-timeout (seconds) for the long-running command-execute call.

    Fuse ordering (source-verified 2026-09-23, ticket
    cli-execution-timeout-cold-start-default): server→executor relay 300s
    (executors.py `AsyncClient(verify=…, timeout=300)`) < nginx
    proxy_read_timeout 330s (installer site template) < this 340s default.
    The client must be the LAST fuse so the clean upstream error (relay 503
    "Executor timed out", nginx 504) reaches the operator instead of a local
    read timeout. The former 30s client default aborted the first cold-sandbox
    run (~65s sbx template pull) client-side while the server was still
    completing it correctly — and the natural retry meant a second full
    execution.

    Override: VENYA_EXECUTION_TIMEOUT (positive integer seconds). The knob was
    previously mis-wired to the executor-register transport and did nothing
    for `venya run`.
    """
    raw = os.environ.get("VENYA_EXECUTION_TIMEOUT", "340")
    try:
        value = int(raw)
    except ValueError:
        raise APIClientError(
            f"Invalid VENYA_EXECUTION_TIMEOUT value: '{raw}'. Must be a positive integer number of seconds."
        ) from None
    if value <= 0:
        raise APIClientError(
            f"Invalid VENYA_EXECUTION_TIMEOUT value: '{raw}'. Must be a positive integer number of seconds."
        )
    return float(value)


def cli_version() -> str:
    """Single-sourced CLI version (feature/version-surfaces condition 1): dist
    metadata (pyproject) is the only truth — never a string literal. Lives here
    so commands.py can compare it against server-reported versions without a
    circular import through cli.py."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("venya-cli")
    except PackageNotFoundError:
        return "unknown"


_PRE_CANONICAL = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc"}


def version_tuple(reported: str | None) -> tuple | None:
    """Parse a PEP 440 version (``X.Y.Z`` + optional prerelease) into a
    comparable tuple; spelled-out tags (alpha/beta) canonicalize to the PEP 440
    short forms so ``alpha2`` sorts BELOW ``a13`` (the dist metadata of an
    ``0.1.0alphaNN`` pyproject reports the spelled form, heartbeat-reported
    executor versions may report either — ticket #324). Unparseable or None →
    None (callers fail closed: no version advice, never a wrong-side nudge).
    Mirrors ``server.routes.executors._version_tuple``; the CLI ships standalone
    and must not import server code."""
    if not reported:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:([a-z]+)(\d+))?$", reported.strip())
    if not m:
        return None
    pre_kind = m.group(4)
    pre_kind = _PRE_CANONICAL.get(pre_kind, pre_kind) if pre_kind else "z"
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_kind, int(m.group(5) or 0))


class APIClientError(Exception):
    """API client error."""


class APIClientAuthenticationError(APIClientError):
    """Authentication failed — requires re-auth."""


def _anchor_refusal_text(searched: str, *, transport: str = "token-bearing call") -> str:
    """The one refusal wording for a dial with no Venya trust anchor (#530).

    Kept as TEXT (not an exception) so the bearer dial and the FIDO2 ceremony
    dial (#533) raise it in their OWN error classes — one wording, two seams.
    Every path that cannot name an anchor reads the same: what was searched,
    why the host store is not the answer, and the repair. ``transport`` names
    the kind of call so the ceremony refusal says "WebAuthn ceremony".
    """
    return (
        f"Cannot dial the core: no Venya TLS trust anchor is configured — {searched}. "
        f"Venya does not fall back to the host's system trust store on a {transport}: "
        "a certificate for this hostname issued by any public CA is not proof "
        "you reached your core. Repair: run `venya setup <core>` on this workstation, "
        "or set SSL_CERT_FILE to a CA bundle you trust — a core served by a public "
        "certificate is the operator naming that bundle, never an implicit host store."
    )


def _anchor_refusal(searched: str) -> APIClientError:
    """The loud refusal for a bearer dial with no Venya trust anchor (#530).

    One wording, shared by the house builder and the resolver — see
    ``_anchor_refusal_text``.
    """
    return APIClientError(_anchor_refusal_text(searched))


def _warn_if_loose_admin_key(path: str) -> None:
    """POSIX-only mode-bit check on the admin mTLS key file: warn, never block.

    The admin key authorizes admin operations WITHOUT a security-key touch, so a
    key that group or other can read is a real exposure. This prints one line on
    stderr naming the path, the mode found, the wanted ``0600`` and that fact —
    it does NOT change the exit code, stdout, or any request the CLI makes.

    Correct modes stay silent: the trigger is the group/other READ bits
    (``mode & 0o044``), so ``0600`` and stricter (``0400``) print nothing. An
    owner-only bit above ``0600`` (e.g. the ``0700`` exec bit) is NOT flagged —
    the ruled trigger is the read-to-others class, not owner permissions.

    Windows (NTFS) has no POSIX mode bits, so the check is skipped there; we
    never print a fabricated "looks fine" — platform honesty, not a fake OK.
    """
    if os.name != "posix":
        return  # no POSIX mode bits on this platform: skip, never a fabricated OK
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return  # unstatable / raced away: the existence check at the caller owns it
    if not (mode & 0o044):
        return  # 0600-or-stricter: the correct case is silent
    print(
        f"warning: {path} is mode {mode:04o} — the admin key authorizes admin "
        "operations without a security-key touch; keep it 0600 (chmod 600), "
        "stored outside your home directory.",
        file=sys.stderr,
    )


def _build_ssl_context(cafile: str | None, certfile: str | None, keyfile: str | None) -> ssl.SSLContext:
    """Build the single TLS context for APIClient.

    Ticket cli-admin-mtls-verify-cert-conflict (option (a)): httpx2 >= 2.12
    rejects `cert=` combined with a string `verify` — the natural admin flow
    (setup-installed config CA + VENYA_ADMIN_CERT/KEY, no SSL_CERT_FILE)
    TypeErrored on every command before any request was sent. One context
    carries both directions: the Venya anchor and, when admin mTLS is
    configured, the client cert chain.

    Ticket cli-bearer-dial-falls-back-to-host-store (#530): an absent anchor is
    a REFUSAL, never ``load_default_certs()``. The old ``else`` branch trusted
    the HOST system store, so a token-bearing request to a name-confused host
    could be satisfied by any publicly-issued certificate for that name — the
    same trust-set defect #501 closed on the server relay, on the workstation
    side. Shape mirrors the landed relay builder (#501, ``_build_relay_ssl_context``):
    a bare ``PROTOCOL_TLS_CLIENT`` context (already ``CERT_REQUIRED`` +
    ``check_hostname``) loaded with ONLY the configured anchor. The repair for a
    missing anchor is ``venya setup <core>``; for a genuinely public-CA-served core
    the operator names that bundle through ``SSL_CERT_FILE`` — still an explicit
    anchor, never an implicit host store.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not cafile:
        # Defense in depth: callers resolve the anchor first and name what they
        # searched, so a blank cafile here means no anchor was ever resolved.
        raise _anchor_refusal("no CA file was resolved for this context")
    try:
        ctx.load_verify_locations(cafile=cafile)
    except (ssl.SSLError, OSError) as e:
        # Ticket 439: the refusal is correct behaviour, but the raw OpenSSL
        # text named neither the file we tried to load nor the repair.
        # Wrap — never silence — and append the original text after the
        # guidance (production mandate: loud failure, full context).
        raise APIClientError(
            f"TLS trust file {cafile!r} is present but could not be loaded as a "
            "certificate (corrupt, empty, or not PEM). Repair: run "
            "`venya setup <core>` to reinstall the core CA, or set SSL_CERT_FILE "
            f"to a valid bundle. Underlying OpenSSL error: {e}"
        ) from e
    if certfile and keyfile:
        try:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except (ssl.SSLError, OSError) as e:
            raise APIClientError(
                f"Failed to load the admin mTLS client cert/key pair " f"({certfile!r} / {keyfile!r}): {e}"
            ) from e
    return ctx


class Config:
    """CLI configuration manager.

    Reads/writes config from config.json in the platform config directory
    (see default_config_dir()). Keys: server_url, access_token
    """

    def __init__(self, config_file: Path | None = None) -> None:
        if config_file is None:
            env = os.environ.get("VENYA_CONFIG")
            if env:
                config_file = Path(env)
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        self._data: dict[str, Any] = {}
        self._transient_server_url: str | None = None
        self._load()

    def _load(self) -> None:
        """Load config from disk."""
        if self.config_file.exists():
            try:
                self._data = json.loads(self.config_file.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self) -> None:
        """Save config to disk with owner-only permissions (0o600)."""
        from .at_rest_key import ensure_secret_dir

        self.config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(self.config_file.parent)
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.config_file.parent,
                prefix=".venya-config-",
                delete=False,
            ) as fd:
                tmp_path = fd.name
                fd.write(json.dumps(self._data).encode())
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(tmp_path, self.config_file)
        except BaseException:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    @property
    def server_url(self) -> str:
        if self._transient_server_url is not None:
            return self._transient_server_url
        return self._data.get("server_url", "http://localhost:8000")

    @server_url.setter
    def server_url(self, value: str) -> None:
        self._transient_server_url = None
        self._data["server_url"] = value.rstrip("/")
        self.save()

    def set_server_url_transient(self, value: str) -> None:
        """One-shot server URL for this process only — no config.json write (#398).

        Stored outside _data (#423) so no later save() can persist it.
        """
        self._transient_server_url = value.rstrip("/")

    @property
    def access_token(self) -> str | None:
        return self._data.get("access_token")

    @access_token.setter
    def access_token(self, value: str | None) -> None:
        if value:
            self._data["access_token"] = value
        else:
            self._data.pop("access_token", None)
        self.save()

    @property
    def ca_path(self) -> Path:
        """CA certificate installed by `venya setup`, beside config.json."""
        return self.config_file.parent / "ca.crt"


# Lazy import json at module level when needed
import json


class APIClient:
    """HTTP client for the Venya server API.

    Handles:
    - Bearer token authentication
    - Automatic token refresh within active sessions
    - FIDO2 re-authentication on token expiry
    - Error handling with meaningful messages
    - Config file persistence (access_token; server_url only via the
      explicit setter — a constructor server_url is one-shot, in-memory)

    Usage:
        # Create client (reads config from ~/.config/venya/config.json)
        client = APIClient()

        # Authenticate via FIDO2
        client.authenticate(user_id="admin")

        # Make API calls (token auto-refreshed when needed)
        secrets = client.get("/api/v1/secrets")

        # Explicit refresh
        client.refresh_token()

        # Set custom server URL
        client.config.server_url = "https://core.example.com"
    """

    def __init__(
        self,
        server_url: str | None = None,
        access_token: str | None = None,
        config_file: Path | None = None,
    ) -> None:
        self.config = Config(config_file=config_file)
        if server_url:
            # #398: the constructor URL is the one-shot flag/env override —
            # in-memory for this process only; persistence belongs to the
            # explicit setter (setup / config set server_url).
            self.config.set_server_url_transient(server_url)
        if access_token:
            self.config.access_token = access_token

        cert_path = os.environ.get("VENYA_ADMIN_CERT")
        key_path = os.environ.get("VENYA_ADMIN_KEY")
        if cert_path and not key_path:
            raise APIClientError(
                "VENYA_ADMIN_CERT is set but VENYA_ADMIN_KEY is not. Both are required for admin mTLS."
            )
        if key_path and not cert_path:
            raise APIClientError(
                "VENYA_ADMIN_KEY is set but VENYA_ADMIN_CERT is not. Both are required for admin mTLS."
            )

        # True when both admin-mTLS env vars are set. The file-existence check
        # below raises if either path is invalid, so a constructed client with
        # has_admin_mtls=True always has a usable cert. run_command's headless
        # gate reads this to exempt `admin` from interactive FIDO2.
        self.has_admin_mtls = bool(cert_path and key_path)

        http_kwargs: dict[str, Any] = {
            "base_url": self.config.server_url,
            "timeout": httpx2.Timeout(30.0),
            "follow_redirects": True,
        }
        if cert_path and key_path:
            for p, var in ((cert_path, "VENYA_ADMIN_CERT"), (key_path, "VENYA_ADMIN_KEY")):
                if not os.path.isfile(p):
                    raise APIClientError(
                        f"{var} points at {p!r}, which does not exist. "
                        "Copy the admin cert/key from the core (see installer banner) and retry."
                    )
            # Existence AND, on POSIX, group/other-unreadable — one legible block.
            # The KEY authorizes admin operations without a security-key touch, so
            # its mode bits matter: warn (never block) if group or other can read it.
            # The cert is public — no mode warning there.
            _warn_if_loose_admin_key(key_path)
        # Server-TLS verification precedence: SSL_CERT_FILE env wins (the
        # full-lifecycle-test.md and cert-rotation-runbook flows drive the CLI
        # that way); then the CA installed by `venya setup` beside config.json.
        # Ticket cli-bearer-dial-falls-back-to-host-store (#530) removed the
        # third historical branch — "then system trust" — so a name with no
        # Venya anchor is never resolved here and the refusal is built from
        # `searched`, which names exactly what was looked for.
        cafile, searched = self._resolve_tls_anchor()
        self._anchor = cafile
        self._anchor_searched = searched
        # The admin client cert rides the SAME context (ticket
        # cli-admin-mtls-verify-cert-conflict, option (a)): httpx2 >= 2.12
        # rejects a string verify= combined with cert=, so both directions
        # unify into one ssl.SSLContext handed over as verify=.
        self._admin_certfile = cert_path if (cert_path and key_path) else None
        self._admin_keyfile = key_path if (cert_path and key_path) else None
        self._http_kwargs: dict[str, Any] = http_kwargs
        # #530: the transport is built on the FIRST DIAL, not here. Two reasons,
        # both load-bearing: (1) `run_command()` constructs an APIClient for
        # every command BEFORE dispatch, so an anchor check at construction would
        # make `venya setup <core>` — the very repair the refusal names —
        # unreachable on exactly the anchor-less host that needs it; (2) AC1
        # requires the refusal land "before any HTTP client is constructed", so
        # construction must not itself construct one. Tests that inject a stub
        # into `_http` still bypass the real build (the setter stores it).
        self.__http: httpx2.Client | None = None

    def _resolve_tls_anchor(self) -> tuple[str | None, str]:
        """The Venya trust anchor for this workstation, or None + what was searched.

        Order is the landed one (SSL_CERT_FILE, then the `venya setup` CA beside
        config.json). Nothing here ever consults the host trust store.
        """
        env_ca = os.environ.get("SSL_CERT_FILE")
        if env_ca:
            return env_ca, f"SSL_CERT_FILE={env_ca!r}"
        ca_path = self.config.ca_path
        if ca_path.exists():
            return str(ca_path), f"no SSL_CERT_FILE set and no config-dir CA at {ca_path}"
        return None, f"no SSL_CERT_FILE set and no config-dir CA at {ca_path}"

    @property
    def _http(self) -> httpx2.Client:
        """The dial transport, built once on first use (#530).

        Refuses with the loud anchor message BEFORE any HTTP client exists when
        this workstation has no Venya trust anchor — the token-bearing call is
        never made against the host system store.

        #521 site 1 (option C, the dial seam): the SAME seam also refuses a
        non-``https://`` core URL before any transport exists. The check lives
        HERE rather than in ``__init__`` because ``run_command()`` constructs an
        APIClient for every command before it dispatches: an eager raise at
        construction would brick ``venya setup`` — the very repair the anchor
        refusal names — on exactly the host that needs it, and would hide the
        repair hint behind a construction error. Landing at the build branch (and
        NOT in the setter) keeps the test seam that injects a stub usable.

        RF-8a (dossier §4.4): a third refusal joins the family here, on the same
        reasoning. When the admin mTLS pair is configured and the CERTIFICATE on
        disk is outside its own validity window, the CLI refuses at this seam
        before the transport exists — the operator gets the one helpful sentence
        naming `venya admin cert renew` instead of a TLS-layer rejection or a
        server 401 that says nothing about the cause. Because the guard runs
        inside the build branch, a single request attempt passes it EXACTLY once:
        there is no re-mint, no ceremony, no retry loop (§4.6's testable boundary),
        and nothing is ever put on the wire. The read is of the certificate file
        only — the private key is never opened to answer a lifetime question.
        """
        if self.__http is None:
            if not self._anchor:
                raise _anchor_refusal(self._anchor_searched)
            base_url = self._http_kwargs.get("base_url", "")
            if not (isinstance(base_url, str) and base_url.startswith("https://")):
                # Deferred import: commands.py imports this module at its top,
                # so a module-level back-import would be a cycle. Same shape the
                # landed #521 site 3 uses in fido2_client.py (`_https_refusal`).
                from .commands import _https_refusal

                raise APIClientError(
                    _https_refusal(
                        str(base_url),
                        site="the venya API request",
                        ticket="cli-dial-sites-missing-https-guard",
                        detail="this transport carries your bearer token, secrets and audit calls",
                    )
                )
            if self._admin_certfile:
                # Same deferred-import shape; only the ADMIN-pair dial is guarded,
                # because only that certificate can die inside a work session.
                from .commands import admin_cert_expiry_refusal

                refusal = admin_cert_expiry_refusal(
                    self._admin_certfile,
                    site="this admin request",
                )
                if refusal is not None:
                    raise APIClientError(refusal)
            verify = _build_ssl_context(
                cafile=self._anchor,
                certfile=self._admin_certfile,
                keyfile=self._admin_keyfile,
            )
            self.__http = httpx2.Client(**self._http_kwargs, verify=verify)
        return self.__http

    @_http.setter
    def _http(self, value: httpx2.Client | None) -> None:
        """Set the transport — test seams inject a stub here; None forces a rebuild."""
        self.__http = value

    def _get_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Get request headers including auth token."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        token = self.config.access_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the server.

        On 401, attempts automatic token refresh. If refresh fails,
        raises APIClientAuthenticationError to trigger FIDO2 re-auth.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: API path.
            json_data: Optional JSON body.
            params: Optional query parameters.
            timeout: Optional per-request timeout override (seconds); None
                keeps the client default (30s). The execute call passes
                execution_timeout() (cli-execution-timeout-cold-start-default).

        Returns:
            Parsed JSON response.

        Raises:
            APIClientError: On request failure.
            APIClientAuthenticationError: On auth failure.
        """
        headers = self._get_headers(extra_headers)
        # httpx treats an explicit timeout=None as "no timeout" — only pass the
        # override when set, so every other call keeps the client default (30s).
        request_kwargs: dict[str, Any] = {"timeout": timeout} if timeout is not None else {}

        # #530: resolved OUTSIDE the try, so the no-anchor refusal is never at
        # risk of being caught and re-worded as a connection error by the httpx
        # handlers below. No HTTP client exists yet at this line on an
        # anchor-less host — nothing has left the machine.
        http = self._http

        try:
            response = http.request(
                method,
                path,
                json=json_data,
                params=params,
                headers=headers,
                **request_kwargs,
            )
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):
                error_msg = str(e)

            if e.response.status_code == 401:
                if self.config.access_token:
                    try:
                        self.refresh_token()
                        # Retry the original request with new token
                        headers = self._get_headers(extra_headers)
                        response = http.request(
                            method,
                            path,
                            json=json_data,
                            params=params,
                            headers=headers,
                            **request_kwargs,
                        )
                        response.raise_for_status()
                        return response.json() if response.content else {}
                    except APIClientAuthenticationError:
                        pass
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            raise APIClientError(f"Connection failed: {e}")
        except httpx2.TimeoutException as e:
            raise APIClientError(f"Request timed out: {e}")

        if response.content:
            return response.json()
        return {}

    def authenticate(self, user_id: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
        """Authenticate via FIDO2 WebAuthn.

        Prompts the user to touch their security key. On success,
        stores the access token in memory for subsequent requests.

        Args:
            user_id: Optional user ID to target.
            timeout: Seconds to wait for key touch.

        Returns:
            Dict with user_id, session_token, and credential_id.

        Raises:
            APIClientAuthenticationError: If FIDO2 auth fails.
        """
        from .fido2_client import (
            Fido2Auth,
            Fido2ClientError,
            Fido2NotFoundError,
            Fido2TimeoutError,
            Fido2UserInteractionRequiredError,
        )

        # Pass the setup-installed CA so the FIDO2 ceremony endpoints are
        # verified against it too (same precedence as the client above).
        fido2 = Fido2Auth(self.config.server_url, ca_path=self.config.ca_path)

        try:
            result = fido2.authenticate(user_id=user_id, timeout=timeout)
        except Fido2NotFoundError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2TimeoutError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2UserInteractionRequiredError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2ClientError as e:
            raise APIClientAuthenticationError(str(e)) from e

        self.config.access_token = result["session_token"]
        logger.info("Authenticated as user: %s", result.get("user_id"))

        return result

    def refresh_token(self) -> str:
        """Refresh the current access token.

        Sends the current token to the server to get a new one.
        If the session is still active, the server issues a new token.

        Returns:
            The new access token.

        Raises:
            APIClientAuthenticationError: If refresh fails (session expired).
        """
        if not self.config.access_token:
            raise APIClientAuthenticationError("No token to refresh")

        try:
            result = self._post_raw("/api/v1/auth/refresh", {})
            self.config.access_token = result["access_token"]
            logger.debug("Token refreshed successfully")
            return self.config.access_token
        except APIClientError as e:
            self.config.access_token = None
            raise APIClientAuthenticationError(f"Token refresh failed: {e}") from e

    def _post_raw(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        """Make a POST request without auto-refresh (for auth endpoints)."""
        headers = self._get_headers()
        # #530: anchor refusal resolved before the try (see _request).
        http = self._http

        try:
            response = http.request(
                "POST",
                path,
                json=json_data,
                headers=headers,
            )
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):
                error_msg = str(e)
            if e.response.status_code == 401:
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            raise APIClientError(f"Connection failed: {e}")

        if response.content:
            return response.json()
        return {}

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a GET request (timeout: per-request override, seconds)."""
        return self._request("GET", path, params=params, extra_headers=extra_headers, timeout=timeout)

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a POST request (timeout: per-request override, seconds)."""
        return self._request("POST", path, json_data=json, params=params, extra_headers=extra_headers, timeout=timeout)

    def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a PUT request."""
        return self._request("PUT", path, json_data=json, params=params, extra_headers=extra_headers)

    def delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a DELETE request."""
        return self._request("DELETE", path, params=params, extra_headers=extra_headers)

    def patch(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a PATCH request."""
        return self._request("PATCH", path, json_data=json, params=params, extra_headers=extra_headers)

    def register_executor(
        self,
        executor_id: str,
        csr_pem: str,
        enrollment_token: str | None = None,
        ca_bundle: str | None = None,
        server_url: str | None = None,
    ) -> dict[str, Any]:
        """Register an executor with the core server.

        Always uses full TLS verification. To disable verification in
        development, set VENYA_TLS_VERIFY=false before running.

        This method is scoped to registration only. ``_request()`` and
        ``_post_raw()`` never fall back, and since #536 neither does this dial:
        ``register_executor()`` builds its own ``httpx2.Client`` on the shared
        anchor-or-refuse path (#530/#533), so a verification-enabled registration
        POST with no Venya trust anchor REFUSES instead of handing the CSR and
        the enrollment token to the host system trust store.

        Args:
            executor_id: Executor identifier.
            csr_pem: PEM-encoded Certificate Signing Request.
            enrollment_token: Optional enrollment token for bootstrap auth.
            ca_bundle: Optional path to CA bundle for TLS verification.

        Returns:
            Dict with cert_pem, ca_cert_pem, serial_number, not_after.

        Raises:
            APIClientError: On network failure or registration error.
        """
        # Validate executor_id format before sending to server
        from .executor_id import validate_executor_id

        try:
            executor_id = validate_executor_id(executor_id)
        except ValueError as e:
            raise APIClientError(str(e))

        payload: dict[str, Any] = {
            "executor_id": executor_id,
            "csr_pem": csr_pem,
        }
        if enrollment_token:
            payload["enrollment_token"] = enrollment_token

        url = f"{server_url or self.config.server_url}/api/v1/executors/register"

        # #545: the scheme rule lives at the dial, not only at the caller. This
        # path builds its OWN httpx2.Client below, so it never rides the gated
        # ``_http`` seam; without this check, any new caller — or the
        # ``or self.config.server_url`` fallback reaching a stored plaintext
        # value (config files written before #509/#497) — would dial http with
        # the CSR and the enrollment token aboard. Same shared wording as the
        # ``_http`` gate (#521): one rule, one wording, no hand-copied variant.
        # Deferred import: commands.py imports this module at its top, so a
        # module-level back-import would be a cycle.
        if not (isinstance(url, str) and url.startswith("https://")):
            from .commands import _https_refusal

            raise APIClientError(
                _https_refusal(
                    str(url),
                    site="the executor registration POST",
                    ticket="api-client-register-executor-raw-dial-missing-scheme-gate",
                    detail="this POST carries the CSR and the enrollment token",
                )
            )

        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env == "" or tls_verify_env.lower() == "true":
            tls_verify = True
        elif tls_verify_env.lower() == "false":
            tls_verify = False
            logger.warning("VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)")
        else:
            raise APIClientError(f"Invalid VENYA_TLS_VERIFY value: '{tls_verify_env}'. " "Must be 'true' or 'false'.")

        try:
            # Fixed 30s: registration is one fast CSR POST. The
            # VENYA_EXECUTION_TIMEOUT knob belongs to the execute path
            # (execution_timeout()) — it was mis-wired here and did nothing
            # for `venya run` (ticket cli-execution-timeout-cold-start-default).
            timeout = 30
            if tls_verify and ca_bundle:
                # An explicit bundle is already an anchor — unchanged (#395).
                verify_param: str | bool | ssl.SSLContext = str(ca_bundle)
            elif tls_verify:
                # #536: no bundle was handed to this call, so resolve this
                # workstation's Venya anchor through the SAME resolver the bearer
                # dial (#530) and the FIDO2 ceremony dial (#533) use, and refuse
                # loudly if none resolves. The branch this replaces passed the
                # bare bool ``verify=True``, which is httpx asking OpenSSL for
                # the HOST system store: on the POST that carries the CSR and
                # the enrollment token, any publicly-issued certificate for a
                # name-confused core would have been accepted. Same trust-set
                # defect #501 closed on the server relay and #530 closed on the
                # bearer dial, on the registration path. The refusal is raised
                # BEFORE the ``with httpx2.Client(...)`` below, so no transport
                # is ever constructed on an unanchored host; ``venya setup``
                # stays the repair because nothing here raises at import or at
                # APIClient construction.
                anchor, searched = self._resolve_tls_anchor()
                if not anchor:
                    # One wording for every anchor-less dial — the shared builder
                    # takes a transport name so this says what it is, the way
                    # #533 names the WebAuthn ceremony.
                    raise APIClientError(_anchor_refusal_text(searched, transport="registration POST")) from None
                # House builder, not a hand-rolled context: CERT_REQUIRED and
                # check_hostname stay on and the anchor is the ONLY trust file.
                verify_param = _build_ssl_context(cafile=anchor, certfile=None, keyfile=None)
            else:
                verify_param = tls_verify
            with httpx2.Client(verify=verify_param, timeout=timeout) as client:
                response = client.post(url, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except Exception:
                error_msg = str(e)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            # Determine if this is a TLS failure by inspecting the exception message
            # httpx2 wraps ssl.SSLError as ConnectError — check the message for TLS keywords
            err_str = str(e).lower()
            if any(t in err_str for t in ("ssl", "certificate", "tls", "verif")):
                raise APIClientError(
                    f"Registration failed: TLS verification error — {e}. " "Verify server CA is trusted."
                ) from e
            raise APIClientError(f"Connection failed: {e}")
        except httpx2.RequestError as e:
            raise APIClientError(f"Request failed: {e}")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        # #530: a client that never dialed never built a transport — nothing to close.
        if self.__http is not None:
            self.__http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
