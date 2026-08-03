"""HTTP client for server API.

Handles authentication, error handling, and retries for CLI-to-server
communication.
"""

from __future__ import annotations

import json
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin


class APIClientError(Exception):
    """API client error."""


class APIClientAuthenticationError(APIClientError):
    """Authentication failed."""


class APIClient:
    """HTTP client for the Venya server API.

    Usage:
        client = APIClient(server_url="https://vault.example.com")
        result = client.get("/api/v1/secrets")
        client.post("/api/v1/secrets", json={"key": "foo", "value": "bar"})
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

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: API path.
            json_data: Optional JSON body.
            params: Optional query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            APIClientError: On request failure.
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
