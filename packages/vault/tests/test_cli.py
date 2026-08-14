"""Tests for CLI httpx-based API client and config management."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from vault.cli.api_client import APIClient, APIClientAuthenticationError, APIClientError, Config


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestConfig:
    """Tests for CLI config file management."""

    def test_default_server_url(self):
        """Default server URL is http://localhost:8000."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            assert config.server_url == "http://localhost:8000"
            assert config.access_token is None
        finally:
            config_file.unlink()

    def test_set_server_url(self):
        """Setting server_url persists to config file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            config.server_url = "https://vault.example.com"
            assert config.server_url == "https://vault.example.com"

            data = json.loads(config_file.read_text())
            assert data["server_url"] == "https://vault.example.com"
        finally:
            config_file.unlink()

    def test_set_server_url_strips_trailing_slash(self):
        """Server URL trailing slashes are stripped."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            config.server_url = "https://vault.example.com/"
            assert config.server_url == "https://vault.example.com"
        finally:
            config_file.unlink()

    def test_set_access_token(self):
        """Setting access_token persists to config file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            config.access_token = "test-token-123"
            assert config.access_token == "test-token-123"

            data = json.loads(config_file.read_text())
            assert data["access_token"] == "test-token-123"
        finally:
            config_file.unlink()

    def test_clear_access_token(self):
        """Setting access_token to None removes it from config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"access_token": "old-token"}')
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            assert config.access_token == "old-token"
            config.access_token = None
            assert config.access_token is None

            data = json.loads(config_file.read_text())
            assert "access_token" not in data
        finally:
            config_file.unlink()

    def test_load_existing_config(self):
        """Existing config file is loaded on initialization."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump({"server_url": "https://loaded.example.com", "access_token": "loaded-token"}, f)
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            assert config.server_url == "https://loaded.example.com"
            assert config.access_token == "loaded-token"
        finally:
            config_file.unlink()

    def test_invalid_json_falls_back_to_empty(self):
        """Invalid JSON config file falls back to empty config."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not valid json {{{")
            config_file = Path(f.name)

        try:
            config = Config(config_file=config_file)
            assert config.server_url == "http://localhost:8000"
            assert config.access_token is None
        finally:
            config_file.unlink()

    def test_config_file_created_on_save(self):
        """Config file is created if it doesn't exist."""
        config_file = Path(tempfile.mktemp(suffix=".json"))
        try:
            if config_file.exists():
                config_file.unlink()
            config = Config(config_file=config_file)
            config.server_url = "https://new.example.com"
            assert config_file.exists()
            data = json.loads(config_file.read_text())
            assert data["server_url"] == "https://new.example.com"
        finally:
            if config_file.exists():
                config_file.unlink()


# ---------------------------------------------------------------------------
# APIClient tests
# ---------------------------------------------------------------------------


def _make_mock_response(status_code=200, json_data=None, content=None):
    """Create a mock httpx.Response."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode() if content is None else content
    elif content is not None:
        mock.content = content
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


class TestAPIClient:
    """Tests for the httpx-based API client."""

    def test_init_with_server_url(self):
        """APIClient uses provided server_url."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(server_url="https://test.example.com", config_file=config_file)
            assert client.config.server_url == "https://test.example.com"
            client.close()
        finally:
            config_file.unlink()

    def test_init_with_access_token(self):
        """APIClient uses provided access_token."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(access_token="my-token", config_file=config_file)
            assert client.config.access_token == "my-token"
            client.close()
        finally:
            config_file.unlink()

    def test_get_headers_includes_token(self):
        """_get_headers includes Authorization header when token is set."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"access_token": "test-token"}')
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            headers = client._get_headers()
            assert headers["Authorization"] == "Bearer test-token"
            assert headers["Content-Type"] == "application/json"
            client.close()
        finally:
            config_file.unlink()

    def test_get_headers_no_token(self):
        """_get_headers omits Authorization when no token."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            headers = client._get_headers()
            assert "Authorization" not in headers
            client.close()
        finally:
            config_file.unlink()

    def test_get_headers_extra(self):
        """_get_headers merges extra headers."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            headers = client._get_headers({"X-Custom": "value"})
            assert headers["X-Custom"] == "value"
            client.close()
        finally:
            config_file.unlink()

    def test_request_401_triggers_refresh(self):
        """401 response triggers token refresh attempt."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"access_token": "expired-token"}')
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)

            mock_http = MagicMock()
            mock_401_response = _make_mock_response(status_code=401, json_data={"detail": "Unauthorized"})
            mock_401_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
                "unauthorized", request=MagicMock(), response=mock_401_response
            )

            mock_success_response = _make_mock_response(status_code=200, json_data={"key": "secret"})
            mock_success_response.raise_for_status.return_value = None

            mock_http.request.side_effect = [mock_401_response, mock_success_response]
            client._http = mock_http

            # Patch refresh_token to set the token directly
            original_refresh = client.refresh_token
            def mock_refresh():
                client.config.access_token = "new-token"
                return "new-token"
            with patch.object(client, "refresh_token", mock_refresh):
                result = client._request("GET", "/api/v1/secrets")
                assert result == {"key": "secret"}
                assert client.config.access_token == "new-token"
            client.close()
        finally:
            config_file.unlink()

    def test_request_401_no_token_raises_auth_error(self):
        """401 without token raises APIClientAuthenticationError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=401, json_data={"detail": "Unauthorized"})
            mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
                "unauthorized", request=MagicMock(), response=mock_response
            )
            mock_http.request.return_value = mock_response
            client._http = mock_http

            with pytest.raises(APIClientAuthenticationError):
                client._request("GET", "/api/v1/secrets")
            client.close()
        finally:
            config_file.unlink()

    def test_request_connect_error(self):
        """Connection errors are wrapped in APIClientError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()
            mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
            client._http = mock_http

            with pytest.raises(APIClientError, match="Connection failed"):
                client._request("GET", "/api/v1/secrets")
            client.close()
        finally:
            config_file.unlink()

    def test_request_timeout(self):
        """Timeout errors are wrapped in APIClientError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()
            mock_http.request.side_effect = httpx2.TimeoutException("Timeout")
            client._http = mock_http

            with pytest.raises(APIClientError, match="timed out"):
                client._request("GET", "/api/v1/secrets")
            client.close()
        finally:
            config_file.unlink()

    def test_request_other_http_error(self):
        """Non-401 HTTP errors are wrapped in APIClientError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=500, json_data={"detail": "Internal server error"})
            mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
                "server error", request=MagicMock(), response=mock_response
            )
            mock_http.request.return_value = mock_response
            client._http = mock_http

            with pytest.raises(APIClientError, match="Internal server error"):
                client._request("GET", "/api/v1/secrets")
            client.close()
        finally:
            config_file.unlink()

    def test_context_manager(self):
        """APIClient works as a context manager."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            # Replace _http with a mock to track close() calls
            mock_http = MagicMock()
            client._http = mock_http
            with client:
                assert client.config.server_url == "http://localhost:8000"
            mock_http.close.assert_called_once()
        finally:
            config_file.unlink()

    def test_post_raw(self):
        """_post_raw sends POST without auto-refresh."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"access_token": "test-token"}')
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=200, json_data={"access_token": "new-token"})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client._post_raw("/api/v1/auth/refresh", {})
            assert result == {"access_token": "new-token"}
            mock_http.request.assert_called_once()
            call_args = mock_http.request.call_args
            assert call_args[0][0] == "POST"
            assert call_args[1]["json"] == {}
            client.close()
        finally:
            config_file.unlink()

    def test_refresh_token_no_token_raises(self):
        """refresh_token without token raises APIClientAuthenticationError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            with pytest.raises(APIClientAuthenticationError, match="No token to refresh"):
                client.refresh_token()
            client.close()
        finally:
            config_file.unlink()

    def test_refresh_token_success(self):
        """refresh_token updates access_token on success."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'{"access_token": "old-token"}')
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=200, json_data={"access_token": "new-refreshed-token"})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.refresh_token()
            assert result == "new-refreshed-token"
            assert client.config.access_token == "new-refreshed-token"
            client.close()
        finally:
            config_file.unlink()

    def test_get_method(self):
        """GET method delegates to _request."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=200, json_data={"secrets": []})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.get("/api/v1/secrets", params={"prefix": "test"})
            assert result == {"secrets": []}
            mock_http.request.assert_called_once()
            call_args = mock_http.request.call_args
            assert call_args[0][0] == "GET"
            assert call_args[1]["params"] == {"prefix": "test"}
            client.close()
        finally:
            config_file.unlink()

    def test_post_method(self):
        """POST method delegates to _request."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=201, json_data={"id": 1, "key": "test"})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.post("/api/v1/secrets", json={"key": "test", "value": "secret", "roles": ["dev"]})
            assert result == {"id": 1, "key": "test"}
            mock_http.request.assert_called_once()
            call_kwargs = mock_http.request.call_args[1]
            assert call_kwargs["json"] == {"key": "test", "value": "secret", "roles": ["dev"]}
            client.close()
        finally:
            config_file.unlink()

    def test_put_method(self):
        """PUT method delegates to _request."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=200, json_data={"updated": True})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.put("/api/v1/roles/1", json={"name": "new-name"})
            assert result == {"updated": True}
            call_args = mock_http.request.call_args
            assert call_args[0][0] == "PUT"
            client.close()
        finally:
            config_file.unlink()

    def test_delete_method(self):
        """DELETE method delegates to _request."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=200, json_data={"deleted": True})
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.delete("/api/v1/secrets/test-key")
            assert result == {"deleted": True}
            call_args = mock_http.request.call_args
            assert call_args[0][0] == "DELETE"
            client.close()
        finally:
            config_file.unlink()

    def test_empty_response(self):
        """Empty response body returns empty dict."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client = APIClient(config_file=config_file)
            mock_http = MagicMock()

            mock_response = _make_mock_response(status_code=204)
            mock_response.content = b""
            mock_response.raise_for_status.return_value = None
            mock_http.request.return_value = mock_response
            client._http = mock_http

            result = client.get("/api/v1/empty-endpoint")
            assert result == {}
            client.close()
        finally:
            config_file.unlink()

    def test_config_persists_across_clients(self):
        """Config changes persist across APIClient instances."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)

        try:
            client1 = APIClient(config_file=config_file)
            client1.config.server_url = "https://persistent.example.com"
            client1.close()

            client2 = APIClient(config_file=config_file)
            assert client2.config.server_url == "https://persistent.example.com"
            client2.close()
        finally:
            config_file.unlink()
