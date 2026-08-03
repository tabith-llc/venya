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

import json
import logging
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin

logger = logging.getLogger("venya.cli.api_client")


class APIClientError(Exception):
    """API client error."""


class APIClientAuthenticationError(APIClientError):
    """Authentication failed — requires re-auth."""


class APIClient:
    """HTTP client for the Venya server API.

    Handles:
    - Bearer token authentication
    - Automatic token refresh within active sessions
    - FIDO2 re-authentication on token expiry
    - Error handling with meaningful messages

    Usage:
        # Create client (no token yet)
        client = APIClient(server_url="https://vault.example.com")

        # Authenticate via FIDO2
        client.authenticate(user_id="admin")

        # Make API calls (token auto-refreshed when needed)
        secrets = client.get("/api/v1/secrets")

        # Explicit refresh
        client.refresh_token()
    """

    def __init__(
        self,
        server_url: str = "http://localhost:8000",
        access_token: str | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.access_token = access_token
        self._session_id: str | None = None

    def _get_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Get request headers including auth token."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if extra:
            headers.update(extra)
        return headers

    def _build_url(self, path: str, params: dict[str, Any] | None = None) -> str:
        """Build full URL with optional query parameters."""
        url = urljoin(self.server_url + "/", path.lstrip("/"))
        if params:
            query = urlencode(params)
            url = f"{url}?{query}"
        return url

    def _request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
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
        url = self._build_url(path, params)
        headers = self._get_headers()

        data = None
        if json_data is not None:
            data = json.dumps(json_data).encode("utf-8")

        req = request.Request(url, data=data, headers=headers, method=method)

        try:
            with request.urlopen(req) as response:
                body = response.read()
                if body:
                    return json.loads(body)
                return {}
        except HTTPError as e:
            body = e.read()
            error_msg = "Unknown error"
            if body:
                try:
                    error_data = json.loads(body)
                    error_msg = error_data.get("detail", str(e))
                except json.JSONDecodeError:
                    error_msg = str(e)

            if e.code == 401:
                # Try to refresh token before giving up
                if self.access_token:
                    try:
                        self.refresh_token()
                        # Retry the original request with new token
                        headers = self._get_headers()
                        req = request.Request(url, data=data, headers=headers, method=method)
                        with request.urlopen(req) as response:
                            body = response.read()
                            if body:
                                return json.loads(body)
                            return {}
                    except APIClientAuthenticationError:
                        pass  # Refresh failed, raise original error
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except URLError as e:
            raise APIClientError(f"Connection failed: {e.reason}")

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

        fido2 = Fido2Auth(self.server_url)

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

        self.access_token = result["session_token"]
        self._session_id = result.get("user_id")
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
        if not self.access_token:
            raise APIClientAuthenticationError("No token to refresh")

        try:
            result = self._post_raw("/api/v1/auth/refresh", {})
            self.access_token = result["access_token"]
            logger.debug("Token refreshed successfully")
            return self.access_token
        except APIClientError as e:
            self.access_token = None
            raise APIClientAuthenticationError(f"Token refresh failed: {e}") from e

    def _post_raw(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        """Make a POST request without auto-refresh (for auth endpoints)."""
        url = self._build_url(path)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        data = json.dumps(json_data).encode("utf-8")
        req = request.Request(url, data=data, headers=headers, method="POST")

        try:
            with request.urlopen(req) as response:
                body = response.read()
                if body:
                    return json.loads(body)
                return {}
        except HTTPError as e:
            body = e.read()
            error_msg = "Unknown error"
            if body:
                try:
                    error_data = json.loads(body)
                    error_msg = error_data.get("detail", str(e))
                except json.JSONDecodeError:
                    error_msg = str(e)
            if e.code == 401:
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except URLError as e:
            raise APIClientError(f"Connection failed: {e.reason}")

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a GET request."""
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a POST request."""
        return self._request("POST", path, json_data=json, params=params)

    def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a PUT request."""
        return self._request("PUT", path, json_data=json, params=params)

    def delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a DELETE request."""
        return self._request("DELETE", path, params=params)
