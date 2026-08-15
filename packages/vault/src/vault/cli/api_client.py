"""HTTP client for server API.

Handles authentication, error handling, and retries for CLI-to-server
communication. Integrates with FIDO2 for WebAuthn-based authentication
and manages short-lived access tokens with transparent refresh.

Token model (per plan section 5.1):
    - Session: 15 min idle timeout (configurable)
    - Access token: 5 min lifetime, transparently refreshed
    - Tokens stored in memory only (no disk persistence)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import httpx2

logger = logging.getLogger("vault.cli.api_client")

# Default config file location
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "venya"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


class APIClientError(Exception):
    """API client error."""


class APIClientAuthenticationError(APIClientError):
    """Authentication failed — requires re-auth."""


class Config:
    """CLI configuration manager.

    Reads/writes config from ~/.config/venya/config.json.
    Keys: server_url, access_token
    """

    def __init__(self, config_file: Path | None = None) -> None:
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load config from disk."""
        if self.config_file.exists():
            try:
                self._data = json.loads(self.config_file.read_text())  # noqa: F821
            except (json.JSONDecodeError, OSError):  # noqa: F821
                self._data = {}

    def save(self) -> None:
        """Save config to disk."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(json.dumps(self._data))  # noqa: F821

    @property
    def server_url(self) -> str:
        return self._data.get("server_url", "http://localhost:8000")

    @server_url.setter
    def server_url(self, value: str) -> None:
        self._data["server_url"] = value.rstrip("/")
        self.save()

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


# Lazy import json at module level when needed
import json  # noqa: E402


class APIClient:
    """HTTP client for the Venya server API.

    Handles:
    - Bearer token authentication
    - Automatic token refresh within active sessions
    - FIDO2 re-authentication on token expiry
    - Error handling with meaningful messages
    - Config file persistence (server_url, access_token)

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
        client.config.server_url = "https://vault.example.com"
    """

    def __init__(
        self,
        server_url: str | None = None,
        access_token: str | None = None,
        config_file: Path | None = None,
    ) -> None:
        self.config = Config(config_file=config_file)
        if server_url:
            self.config.server_url = server_url
        if access_token:
            self.config.access_token = access_token
        self._http = httpx2.Client(
            base_url=self.config.server_url,
            timeout=httpx2.Timeout(30.0),
            follow_redirects=True,
        )

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
    ) -> dict[str, Any]:
        """Make an HTTP request to the server.

        On 401, attempts automatic token refresh. If refresh fails,
        raises APIClientAuthenticationError to trigger FIDO2 re-auth.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: API path.
            json_data: Optional JSON body.
            params: Optional query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            APIClientError: On request failure.
            APIClientAuthenticationError: On auth failure.
        """
        headers = self._get_headers(extra_headers)

        try:
            response = self._http.request(
                method,
                path,
                json=json_data,
                params=params,
                headers=headers,
            )
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):  # noqa: F841
                error_msg = str(e)

            if e.response.status_code == 401:
                if self.config.access_token:
                    try:
                        self.refresh_token()
                        # Retry the original request with new token
                        headers = self._get_headers(extra_headers)
                        response = self._http.request(
                            method,
                            path,
                            json=json_data,
                            params=params,
                            headers=headers,
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

        fido2 = Fido2Auth(self.config.server_url)

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

        try:
            response = self._http.request(
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
            except (json.JSONDecodeError, Exception):  # noqa: F841
                error_msg = str(e)
            if e.response.status_code == 401:
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            raise APIClientError(f"Connection failed: {e}")

        if response.content:
            return response.json()
        return {}

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a GET request."""
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a POST request."""
        return self._request("POST", path, json_data=json, params=params, extra_headers=extra_headers)

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

    def register_executor(
        self,
        executor_id: str,
        csr_pem: str,
        enrollment_token: str | None = None,
    ) -> dict[str, Any]:
        """Register an executor with the vault server.

        Always uses full TLS verification. To disable verification in
        development, set VENYA_TLS_VERIFY=false before running.

        This method is scoped to registration only. _request() and _post_raw()
        never fall back — prevents silent TLS bypass on authenticated calls.

        Args:
            executor_id: Executor identifier.
            csr_pem: PEM-encoded Certificate Signing Request.
            enrollment_token: Optional enrollment token for bootstrap auth.

        Returns:
            Dict with cert_pem, ca_cert_pem, serial_number, not_after.

        Raises:
            APIClientError: On network failure or registration error.
        """
        payload: dict[str, Any] = {
            "executor_id": executor_id,
            "csr_pem": csr_pem,
        }
        if enrollment_token:
            payload["enrollment_token"] = enrollment_token

        url = f"{self.config.server_url}/api/v1/executors/register"

        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env == "":
            tls_verify = True
        elif tls_verify_env.lower() == "true":
            tls_verify = True
        elif tls_verify_env.lower() == "false":
            tls_verify = False
            logger.warning("VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)")
        else:
            raise APIClientError(
                f"Invalid VENYA_TLS_VERIFY value: '{tls_verify_env}'. "
                "Must be 'true' or 'false'."
            )

        try:
            with httpx2.Client(verify=tls_verify, timeout=30.0) as client:
                response = client.post(url, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except Exception:  # noqa: BLE001
                error_msg = str(e)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            if tls_verify:
                raise APIClientError(
                    f"Registration failed. Verify server CA is trusted. "
                    "In development, export VENYA_TLS_VERIFY=false"
                ) from e
            raise APIClientError(f"Connection failed: {e}")
        except httpx2.RequestError as e:
            raise APIClientError(f"Request failed: {e}")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
