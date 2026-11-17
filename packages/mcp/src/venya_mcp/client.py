# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Venya API client — handles auth, token refresh, and tool calls.

Uses httpx2 (the monorepo-standard httpx fork) for async HTTP.
"""

from __future__ import annotations

import logging
import os
import shlex
import warnings
from pathlib import Path

import httpx2

from .config import MCPConfig

logger = logging.getLogger("venya.mcp")


class VenyaAPIError(Exception):
    """Raised when the Venya API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Venya API error {status_code}: {detail}")


class SessionExpiredError(Exception):
    """Raised when token refresh fails — human must re-authenticate."""


def _bootstrap_tls_verify() -> bool | str:
    """Determine TLS verify setting at startup.

    Returns:
        True if VENYA_CA_CERT is set (use that path),
        False if VENYA_TLS_VERIFY=false (with warning),
        raises if CA cert is required but missing.
    """
    ca_cert = _resolve_ca_cert()
    tls_verify = os.environ.get("VENYA_TLS_VERIFY", "").lower()

    if ca_cert is not None:
        return ca_cert

    if tls_verify == "false":
        msg = (
            "TLS verification is disabled (VENYA_TLS_VERIFY=false). "
            "This is an alpha debug mode — never use in production. "
            "Set VENYA_CA_CERT to the Venya CA bundle path instead."
        )
        warnings.warn(msg, stacklevel=2)
        logger.warning(msg)
        return False

    msg = (
        "Venya CA certificate not found. "
        "Set the VENYA_CA_CERT environment variable to the path of the "
        "Venya CA bundle (e.g. /etc/venya/ca/ca-bundle.crt). "
        "TLS verification cannot be silently disabled."
    )
    raise RuntimeError(msg)


def _resolve_ca_cert() -> str | None:
    """Return VENYA_CA_CERT path if set, else None."""
    ca_cert = os.environ.get("VENYA_CA_CERT")
    if ca_cert is not None:
        path = Path(ca_cert)
        if not path.is_file():
            raise RuntimeError(f"VENYA_CA_CERT points to a file that does not exist: {ca_cert}")
        return str(path)
    return None


#: The anchored-only posture in the shipped words of ``_bootstrap_tls_verify`` below (#571). The
#: repair sentence and the posture sentence are quoted VERBATIM from that function so the
#: constructor seam and the startup resolver read the same; ``_bootstrap_tls_verify`` itself is
#: left exactly as it ships (#540's ruled False-escape path is hands-off), which is why this is a
#: quoted constant rather than a shared helper.
ANCHORED_ONLY_REFUSAL = (
    "Set the VENYA_CA_CERT environment variable to the path of the "
    "Venya CA bundle (e.g. /etc/venya/ca/ca-bundle.crt). "
    "TLS verification cannot be silently disabled."
)


#: R9 (owner ruling 2026-10-10, booked in decisions.md at 135337e): the refusal names NO
#: mechanism. "a trust store that is not the Venya CA" is true for both refused shapes at this seam —
#: ``verify=True`` lands on the machine's own store, an omitted ``verify`` lands on the transport's
#: built-in default bundle — and a reader cannot reproduce a mechanism they were never shown, so the
#: sentence states what is wrong (wrong CA) and leaves the detail to developer prose below. One
#: sentence for both shapes BY RULING: not split per shape. The repair pointer that follows it is the
#: shipped ``ANCHORED_ONLY_REFUSAL`` text, quoted once, not restated.
UNANCHORED_REFUSAL = "names a trust store that is not the Venya CA"


def _require_anchored_verify(verify: object) -> str | bool:
    """The constructor seam's anchored-or-refuse check (#571), BEFORE any transport exists.

    Same posture the CLI bearer dial and the FIDO2 ceremony dial landed in #530/#533/#536: a
    value that is not the Venya CA bundle — or the ruled alpha debug escape, exactly ``False`` —
    is refused, never defaulted. What the refusal no longer says is *which* store a bad value
    lands on: per R9 the operator-facing sentence names no mechanism (see
    ``UNANCHORED_REFUSAL``); the mechanism detail stays here, in developer prose — ``True``
    reaches httpx2's ``truststore.SSLContext`` (``_config.py`` ``create_ssl_context``, measured
    at this venue on httpx2 2.12.0) and an omitted value reaches its built-in default bundle.

    The refusal lands before ``httpx2.AsyncClient`` is constructed, so a refused call never dials.
    """
    if verify is True or verify is None:
        raise RuntimeError(
            f"VenyaClient was built with verify={verify!r}, which {UNANCHORED_REFUSAL}. "
            f"{ANCHORED_ONLY_REFUSAL} Pass False only for the ruled alpha debug escape."
        )
    if isinstance(verify, str) and verify:
        return verify
    if verify is False:
        return False
    raise RuntimeError(
        f"VenyaClient was built with verify={verify!r}, which is neither the Venya CA bundle path "
        f"nor the alpha debug escape (False). {ANCHORED_ONLY_REFUSAL}"
    )


# Last-fuse read timeout for the long-running execute call: server→executor
# relay 300s < nginx proxy_read_timeout 330s < 340s here, so a clean upstream
# error always reaches the agent before this client gives up. The former 30s
# client default abandoned cold-sandbox runs (~65s template pull) the server
# was still completing (ticket cli-execution-timeout-cold-start-default; the
# CLI twin exposes this default as VENYA_EXECUTION_TIMEOUT).
_EXECUTE_TIMEOUT_SECONDS = 340.0


class VenyaClient:
    """Async HTTP client for the Venya API.

    Token lifecycle:
    1. Read access_token from config file (written by `venya login`)
    2. Stat that file per call; when its mtime has moved, read it again, so a
       `venya login` that lands after this process started is picked up without a
       restart (#705). A stat is not a read: the hot path stays one in-memory token.
    3. On 401 → POST /api/v1/auth/refresh with current token → get new token
    4. Update config file in-place with new token (atomic write)
    5. On 401 with a refused refresh → re-read the session file once and retry once
       with any token it holds that differs from the refused one (#705)
    6. If nothing newer turned up → SessionExpiredError, naming the resolved path and
       which of the three states it found

    TLS: verified against VENYA_CA_CERT at startup. No silent downgrade. The constructor takes no
    trust default (#571): ``verify`` must name the Venya CA bundle, or be exactly ``False`` for
    the ruled alpha debug escape. ``True`` — or nothing at all — is refused before a transport
    exists, in words that name no mechanism (R9): either shape ends up trusting something that is
    not the Venya CA.
    """

    def __init__(
        self,
        config: MCPConfig,
        verify: str | bool | None = None,
    ) -> None:
        # #571: no default trust. ``None`` is the OMITTED case, not "take what the library
        # defaults to" — it refuses with the same CA-naming words a ``True`` would. The annotation
        # stays permissive (``_bootstrap_tls_verify`` returns ``bool | str`` and server.py is not
        # this leg's file); the enforcement is the guard, which runs before any transport exists.
        anchored = _require_anchored_verify(verify)
        self.config = config
        self._http = httpx2.AsyncClient(
            verify=anchored,
            timeout=httpx2.Timeout(30.0, connect=10.0),
        )
        self._access_token: str | None = config.access_token
        # One unconditional session-file re-read per request (#705); _request resets it.
        # The mtime door does not count against it — it reads only when the file moved.
        self._disk_reread = False

    async def close(self) -> None:
        await self._http.aclose()

    def _headers(self) -> dict[str, str]:
        # The mtime door: one stat per call, a read only when the file moved (#705).
        self._adopt(self.config.reload_if_changed())
        if not self._access_token:
            self._adopt(self.config.reload())
        if not self._access_token:
            raise self._session_error()
        return {"Authorization": f"Bearer {self._access_token}"}

    def _session_error(self, *, refused: bool = False) -> SessionExpiredError:
        """The expired-session sentence, naming the resolved path and the state it is in.

        Three states reach this point and the remedy differs for each, so the text says
        which one it found (#705): there is no session file at the path at all, a file is
        there but holds no ``access_token`` (the shape that made a running server answer
        "expired" when nothing had expired — an unreadable or unparseable file lands here
        too, because nothing usable could be read from it), or a token was read and the
        core refused it. The path is the one this process resolved, VENYA_CONFIG first, so
        an operator pointed at the wrong file can see that.
        """
        path = self.config.path
        if refused:
            state = f"the access_token read from {path} was refused by the core"
        elif not path.exists():
            state = f"there is no session file at {path}"
        else:
            state = f"the session file at {path} holds no access_token"
        return SessionExpiredError(
            f"Venya session expired and could not be renewed ({state}). "
            "Run the `venya` CLI (e.g. `venya list`) and approve your "
            "security key, then restart the MCP server."
        )

    def _adopt(self, disk_token: str | None) -> bool:
        """Take a token read from the session file, when it differs from the one in hand.

        The CLI writes no principal field (its config carries server_url and access_token
        only), so a swap cannot be proven to be the same operator; what it can do is say
        plainly that it happened and where, which is what the line below does — the file
        and the act are named, never the value.
        """
        if not disk_token or disk_token == self._access_token:
            return False
        self._access_token = disk_token
        logger.info("Adopted the session token on disk at %s", self.config.path)
        return True

    def _re_read_after_refusal(self) -> None:
        """Ask the session file once per request after the core refused a token (#705).

        The mtime door already covers a file that was rewritten; this is the second chance
        for the shapes it cannot see — a token that is current on disk but refused by the
        core, or a file whose mtime did not move. Bounded twice over: once per request, and
        a file still holding the refused value is not adopted, so nothing loops on it.
        """
        if self._disk_reread:
            return
        self._disk_reread = True
        if not self._adopt(self.config.reload()):
            logger.info("No newer session token to adopt at %s", self.config.path)

    async def _refresh(self) -> bool:
        """Attempt to refresh the access token.

        Sends current access token to /api/v1/auth/refresh.
        Server returns a new access_token. Updates config file in-place.
        Returns True on success, False on failure.
        """
        if not self._access_token:
            return False

        try:
            resp = await self._http.post(
                f"{self.config.server_url}/api/v1/auth/refresh",
                headers=self._headers(),
            )
            if resp.status_code != 200:
                logger.warning("Token refresh failed: %d", resp.status_code)
                return False

            data = resp.json()
            new_token = data.get("access_token")
            if not new_token:
                logger.warning("Refresh response missing access_token")
                return False

            self._access_token = new_token
            self.config.update_token(new_token)
            logger.info("Token refreshed successfully")
            return True

        except httpx2.HTTPError as e:
            logger.warning("Token refresh HTTP error: %s", e)
            return False

    async def _request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        params: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Make an authenticated request with automatic refresh on 401.

        Every Venya endpoint returns a JSON object (envelope), never a bare
        array, so this is always a dict.

        timeout: per-request override (seconds); None keeps the client default.
        Only the execute call passes one (_EXECUTE_TIMEOUT_SECONDS) — httpx
        treats an explicit None as "no timeout", so it must not be forwarded.
        """
        url = f"{self.config.server_url}{path}"
        extra: dict = {"timeout": timeout} if timeout is not None else {}
        self._disk_reread = False
        headers = self._headers()
        sent_token = self._access_token

        resp = await self._http.request(method, url, json=json_body, params=params, headers=headers, **extra)

        # 401 → try the refresh, then the session on disk, then retry once with whatever
        # newer token is in hand (#705). The retry is decided by the token, not by which
        # door moved it, so a login that lands mid-call is never thrown away.
        if resp.status_code == 401:
            logger.info("Got 401, attempting token refresh...")
            if not await self._refresh():
                self._re_read_after_refusal()
            if self._access_token != sent_token:
                resp = await self._http.request(
                    method, url, json=json_body, params=params, headers=self._headers(), **extra
                )
            else:
                raise self._session_error(refused=True)

        if resp.status_code >= 400:
            content_type = resp.headers.get("content-type", "")
            if content_type.startswith("application/json"):
                detail = resp.json().get("detail", resp.text)
            else:
                detail = resp.text
            raise VenyaAPIError(resp.status_code, str(detail))

        return resp.json()

    # --- Tool convenience methods ---

    async def list_secrets(
        self,
        executor: str | None = None,
        purpose: str | None = None,
        username: str | None = None,
    ) -> list[dict]:
        """List secrets with optional metadata filters. Never returns values."""
        params: dict[str, str] = {}
        if executor:
            params["executor"] = executor
        if purpose:
            params["purpose"] = purpose
        if username:
            params["username"] = username
        resp = await self._request("GET", "/api/v1/secrets", params=params)
        return resp["secrets"]

    async def list_executors(self) -> dict:
        """List registered executors with online status.

        Returns the full response envelope {executors: [...]}.
        """
        return await self._request("GET", "/api/v1/executors")

    async def run_command(
        self,
        executor_id: str,
        command: str,
        secret_keys: list[str],
    ) -> dict:
        """Execute a command on a remote executor with secret injection.

        Two-step internal flow (exposed as single tool to LLM):
        1. POST /executors/sessions with {executor_id, secret_keys}
           → server resolves, decrypts, wraps, stores secrets server-side
        2. POST /executors/{id}/execute with {session_id, command: argv list}
           → {exit_code, stdout, stderr, masked_count}

        The MCP server never sees secret plaintext. Output contains
        [REDACTED:<id>] markers where secret values would appear.

        If secret_keys is empty, step 1 creates a session with no secrets.
        """
        # Parse argv BEFORE the session POST (ticket mcp-session-created-before-
        # argv-parse #415): an unparseable command must not churn a secret-bound
        # session row that then waits on TTL reap. The shlex split needs no
        # session — it leads.
        # M1 boundary split (ticket execution-command-wire-unstructured-string
        # #322, owner ruling): the MCP TOOL surface stays a shell string, but
        # ExecuteRequest.command is a list[str] since #322 — argv is split
        # HERE so the wire carries structured tokens. An unparseable string
        # (unbalanced quote) becomes a ValueError, which rides the EXISTING
        # tool-error path (server.py: handler exceptions become isError=True
        # results carrying this message; no traceback reaches the agent).
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise ValueError(f"Command could not be parsed as a shell line: {exc}") from None

        # Step 1: Create session (with optional secret keys)
        session_body: dict = {"executor_id": executor_id}
        if secret_keys:
            session_body["secret_keys"] = secret_keys

        session_resp = await self._request(
            "POST",
            "/api/v1/executors/sessions",
            json_body=session_body,
        )
        session_id = session_resp["session_id"]

        # Step 2: Execute command — long-running: last-fuse timeout (ticket
        # cli-execution-timeout-cold-start-default).
        result = await self._request(
            "POST",
            f"/api/v1/executors/{executor_id}/execute",
            json_body={
                "session_id": session_id,
                "command": argv,
            },
            timeout=_EXECUTE_TIMEOUT_SECONDS,
        )

        return result

    async def get_audit(
        self,
        hours: int = 1,
        event_type: str | None = None,
        executor_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query audit log. Admin or auditor-tier callers see the full log; other read-write callers see only their own events; plain-read callers are denied (403)."""
        params: dict[str, str] = {"limit": str(limit), "hours": str(hours)}
        if event_type:
            params["event_type"] = event_type
        if executor_id:
            params["executor_id"] = executor_id
        resp = await self._request("GET", "/api/v1/audit", params=params)
        return resp["events"]
