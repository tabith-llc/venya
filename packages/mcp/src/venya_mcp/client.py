"""Venya API client — handles auth, token refresh, and tool calls.

Uses httpx2 (the monorepo-standard httpx fork) for async HTTP.
"""

from __future__ import annotations

import logging
import os
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


class VenyaClient:
    """Async HTTP client for the Venya API.

    Token lifecycle:
    1. Read access_token from config file (written by `venya auth`)
    2. On 401 → POST /api/v1/auth/refresh with current token → get new token
    3. Update config file in-place with new token (atomic write)
    4. If refresh also fails → SessionExpiredError (human must re-auth)

    TLS: verified against VENYA_CA_CERT at startup. No silent downgrade.
    """

    def __init__(
        self,
        config: MCPConfig,
        verify: bool | str = True,
    ) -> None:
        self.config = config
        self._http = httpx2.AsyncClient(
            verify=verify,
            timeout=httpx2.Timeout(30.0, connect=10.0),
        )
        self._access_token: str | None = config.access_token

    async def close(self) -> None:
        await self._http.aclose()

    def _headers(self) -> dict[str, str]:
        if not self._access_token:
            raise SessionExpiredError(
                "Venya session expired and could not be renewed. "
                "Run the `venya` CLI (e.g. `venya list`) and approve your "
                "security key, then restart the MCP server."
            )
        return {"Authorization": f"Bearer {self._access_token}"}

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
    ) -> dict:
        """Make an authenticated request with automatic refresh on 401.

        Every Venya endpoint returns a JSON object (envelope), never a bare
        array, so this is always a dict.
        """
        url = f"{self.config.server_url}{path}"

        resp = await self._http.request(method, url, json=json_body, params=params, headers=self._headers())

        # 401 → try refresh, then retry once
        if resp.status_code == 401:
            logger.info("Got 401, attempting token refresh...")
            if await self._refresh():
                resp = await self._http.request(method, url, json=json_body, params=params, headers=self._headers())
            else:
                raise SessionExpiredError(
                    "Venya session expired and could not be renewed. "
                    "Run the `venya` CLI (e.g. `venya list`) and approve your "
                    "security key, then restart the MCP server."
                )

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
        2. POST /executors/{id}/execute with {session_id, command}
           → {exit_code, stdout, stderr, masked_count}

        The MCP server never sees secret plaintext. Output contains
        [REDACTED:<id>] markers where secret values would appear.

        If secret_keys is empty, step 1 creates a session with no secrets.
        """
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

        # Step 2: Execute command
        result = await self._request(
            "POST",
            f"/api/v1/executors/{executor_id}/execute",
            json_body={
                "session_id": session_id,
                "command": command,
            },
        )

        return result

    async def get_audit(
        self,
        hours: int = 1,
        event_type: str | None = None,
        executor_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query audit log. Non-admin users see only their own events."""
        params: dict[str, str] = {"limit": str(limit), "hours": str(hours)}
        if event_type:
            params["event_type"] = event_type
        if executor_id:
            params["executor_id"] = executor_id
        resp = await self._request("GET", "/api/v1/audit", params=params)
        return resp["events"]
