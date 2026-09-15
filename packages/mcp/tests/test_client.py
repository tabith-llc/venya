# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the Venya API client and config management."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from venya_mcp.client import (
    SessionExpiredError,
    VenyaAPIError,
    VenyaClient,
    _bootstrap_tls_verify,
)
from venya_mcp.config import MCPConfig

# --- Config tests ---


def test_config_loads(tmp_path: Path) -> None:
    """Config file with server_url and access_token loads correctly."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1/",
                "access_token": "test-token-abc",
            }
        )
    )
    config = MCPConfig(config_file)
    assert config.server_url == "https://venya-core-1"
    assert config.access_token == "test-token-abc"


def test_config_missing_raises(tmp_path: Path) -> None:
    """Missing config file raises FileNotFoundError with actionable message."""
    config_file = tmp_path / "nonexistent.json"
    with pytest.raises(FileNotFoundError) as exc_info:
        MCPConfig(config_file)
    assert "Venya session token found" in str(exc_info.value)


def test_config_missing_token_is_none(tmp_path: Path) -> None:
    """Config file without access_token returns None."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://venya-core-1"}))
    config = MCPConfig(config_file)
    assert config.access_token is None


def test_config_update_token_preserves_keys(tmp_path: Path) -> None:
    """update_token replaces access_token, preserves server_url and unknown keys."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1",
                "access_token": "old-token",
                "unknown_key": "unknown_value",
            }
        )
    )
    config = MCPConfig(config_file)
    config.update_token("new-token")

    data = json.loads(config_file.read_text())
    assert data["access_token"] == "new-token"
    assert data["server_url"] == "https://venya-core-1"
    assert data["unknown_key"] == "unknown_value"


def test_config_update_token_atomic(tmp_path: Path) -> None:
    """update_token writes atomically — no torn file."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1",
                "access_token": "old-token",
            }
        )
    )
    config = MCPConfig(config_file)
    config.update_token("new-token")

    # File should be valid JSON (not a partial write)
    data = json.loads(config_file.read_text())
    assert data["access_token"] == "new-token"


def test_config_update_token_permissions(tmp_path: Path) -> None:
    """update_token sets 0o600 permissions."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1",
                "access_token": "old-token",
            }
        )
    )
    config = MCPConfig(config_file)
    config.update_token("new-token")
    mode = config_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_config_env_override(tmp_path: Path) -> None:
    """VENYA_CONFIG env var overrides default path."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1",
                "access_token": "env-token",
            }
        )
    )
    with patch.dict(os.environ, {"VENYA_CONFIG": str(config_file)}):
        config = MCPConfig()
        assert config.access_token == "env-token"


# --- TLS bootstrap tests ---


def test_bootstrap_tls_verify_with_ca_cert(tmp_path: Path) -> None:
    """VENYA_CA_CERT set → returns that path."""
    ca_file = tmp_path / "ca-bundle.crt"
    ca_file.write_text("fake-ca")
    with patch.dict(os.environ, {"VENYA_CA_CERT": str(ca_file)}):
        result = _bootstrap_tls_verify()
        assert result == str(ca_file)


def test_bootstrap_tls_verify_missing_ca_cert_raises() -> None:
    """No VENYA_CA_CERT → RuntimeError."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError, match="VENYA_CA_CERT"):
            _bootstrap_tls_verify()


def test_bootstrap_tls_verify_explicit_false_warns() -> None:
    """VENYA_TLS_VERIFY=false → returns False with warning."""
    with patch.dict(os.environ, {"VENYA_TLS_VERIFY": "false"}):
        result = _bootstrap_tls_verify()
        assert result is False


def test_bootstrap_tls_verify_ca_cert_not_a_file_raises(tmp_path: Path) -> None:
    """VENYA_CA_CERT points to non-existent file → RuntimeError."""
    fake_path = str(tmp_path / "does-not-exist.crt")
    with patch.dict(os.environ, {"VENYA_CA_CERT": fake_path}):
        with pytest.raises(RuntimeError, match="does not exist"):
            _bootstrap_tls_verify()


# --- Client tests ---


@pytest.fixture
def mock_config(tmp_path: Path) -> MCPConfig:
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "server_url": "https://venya-core-1",
                "access_token": "initial-token",
            }
        )
    )
    return MCPConfig(config_file)


def _make_response(status_code: int, body: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {}
    resp.text = text
    resp.headers = {}
    return resp


async def test_refresh_success(mock_config: MCPConfig) -> None:
    """401 → POST /auth/refresh 200 → retried request carries new token."""
    new_token = "refreshed-token"

    # _refresh() calls .post(), _request() calls .request()
    first_401 = _make_response(401)
    refresh_resp = _make_response(200, {"access_token": new_token})
    retry_resp = _make_response(200, {"data": "success"})

    mock_http = MagicMock()
    mock_http.post = AsyncMock(return_value=refresh_resp)
    mock_http.request = AsyncMock(side_effect=[first_401, retry_resp])

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    result = await client._request("GET", "/api/v1/test")
    assert result == {"data": "success"}
    assert client._access_token == new_token

    # Verify token was persisted to disk
    data = json.loads(mock_config.path.read_text())
    assert data["access_token"] == new_token


async def test_refresh_failure_raises_session_expired(mock_config: MCPConfig) -> None:
    """Refresh returns non-200 → SessionExpiredError."""
    first_401 = _make_response(401)
    refresh_fail = _make_response(401)

    mock_http = MagicMock()
    mock_http.post = AsyncMock(return_value=refresh_fail)
    mock_http.request = AsyncMock(side_effect=[first_401])

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    with pytest.raises(SessionExpiredError):
        await client._request("GET", "/api/v1/test")


async def test_request_sends_auth_header(mock_config: MCPConfig) -> None:
    """Normal request includes Authorization header."""
    ok_resp = _make_response(200, {"ok": True})

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=ok_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    await client._request("GET", "/api/v1/test")

    call_kwargs = mock_http.request.call_args[1]
    assert call_kwargs["headers"]["Authorization"] == "Bearer initial-token"


async def test_list_secrets_filters(mock_config: MCPConfig) -> None:
    """executor/purpose/username → params sent; omitted → no params."""
    secrets_resp = _make_response(200, {"secrets": [{"key": "mysecret", "metadata": {}}]})

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=secrets_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    result = await client.list_secrets(executor="web-3", purpose="ssh_login", username="bot")
    assert len(result) == 1

    # Check params were sent
    call_kwargs = mock_http.request.call_args[1]
    assert call_kwargs["params"]["executor"] == "web-3"
    assert call_kwargs["params"]["purpose"] == "ssh_login"
    assert call_kwargs["params"]["username"] == "bot"


async def test_list_secrets_unwraps_envelope(mock_config: MCPConfig) -> None:
    """Response envelope {secrets:[...]} → method returns the list."""
    secrets_resp = _make_response(
        200,
        {
            "secrets": [
                {"key": "k1", "metadata": {"executor": "web-3"}},
                {"key": "k2", "metadata": {}},
            ]
        },
    )

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=secrets_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    result = await client.list_secrets()
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["key"] == "k1"


async def test_run_command_two_steps(mock_config: MCPConfig) -> None:
    """Asserts call order: POST /executors/sessions → POST /executors/{id}/execute."""
    session_resp = _make_response(201, {"session_id": "sess-123", "executor_id": "exec-1"})
    execute_resp = _make_response(
        200,
        {
            "exit_code": 0,
            "stdout": "done",
            "stderr": "",
            "masked_count": 1,
        },
    )

    mock_http = MagicMock()
    mock_http.request = AsyncMock(side_effect=[session_resp, execute_resp])

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    result = await client.run_command(
        executor_id="exec-1",
        command="ls -la",
        secret_keys=["my_secret"],
    )

    assert result["exit_code"] == 0
    assert result["masked_count"] == 1

    # Verify the two calls in order
    assert mock_http.request.call_count == 2

    # First call: POST /executors/sessions
    first_call = mock_http.request.call_args_list[0]
    assert first_call.args[0] == "POST"
    assert "/executors/sessions" in first_call.args[1]
    assert first_call[1]["json"]["secret_keys"] == ["my_secret"]

    # Second call: POST /executors/{id}/execute
    second_call = mock_http.request.call_args_list[1]
    assert second_call.args[0] == "POST"
    assert "/executors/exec-1/execute" in second_call.args[1]
    assert second_call[1]["json"]["session_id"] == "sess-123"


async def test_run_command_no_secrets(mock_config: MCPConfig) -> None:
    """Skips secret_keys in session body when no keys provided."""
    session_resp = _make_response(201, {"session_id": "sess-456", "executor_id": "exec-1"})
    execute_resp = _make_response(
        200,
        {
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "masked_count": 0,
        },
    )

    mock_http = MagicMock()
    mock_http.request = AsyncMock(side_effect=[session_resp, execute_resp])

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    await client.run_command(executor_id="exec-1", command="echo hello", secret_keys=[])

    first_call = mock_http.request.call_args_list[0]
    body = first_call[1]["json"]
    assert body["executor_id"] == "exec-1"
    assert "secret_keys" not in body


async def test_get_audit_params(mock_config: MCPConfig) -> None:
    """hours/event_type/executor_id/limit → correct query params."""
    audit_resp = _make_response(200, {"events": []})

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=audit_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    await client.get_audit(hours=2, event_type="command_executed", executor_id="exec-1", limit=100)

    call_kwargs = mock_http.request.call_args[1]
    assert call_kwargs["params"]["hours"] == "2"
    assert call_kwargs["params"]["event_type"] == "command_executed"
    assert call_kwargs["params"]["executor_id"] == "exec-1"
    assert call_kwargs["params"]["limit"] == "100"


async def test_get_audit_unwraps_envelope(mock_config: MCPConfig) -> None:
    """Response envelope {events:[...]} → method returns the list."""
    audit_resp = _make_response(
        200,
        {
            "events": [
                {
                    "event_type": "command_executed",
                    "user_id": "alice",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "fields": {"executor_id": "exec-1"},
                },
            ]
        },
    )

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=audit_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    result = await client.get_audit()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["event_type"] == "command_executed"


async def test_api_error(mock_config: MCPConfig) -> None:
    """Non-401 error responses raise VenyaAPIError."""
    error_resp = _make_response(500, {"detail": "Internal server error"})
    error_resp.headers = {"content-type": "application/json"}

    mock_http = MagicMock()
    mock_http.request = AsyncMock(return_value=error_resp)

    client = VenyaClient(mock_config, verify=False)
    client._http = mock_http

    with pytest.raises(VenyaAPIError) as exc_info:
        await client._request("GET", "/api/v1/test")

    assert exc_info.value.status_code == 500
    assert "Internal server error" in str(exc_info.value)
