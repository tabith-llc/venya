"""Tests for MCP tool output formatting."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.types import TextContent
from venya_mcp.client import SessionExpiredError, VenyaAPIError, VenyaClient
from venya_mcp.server import build_client, call_tool


def _make_mock_client() -> MagicMock:
    """Create a fully mocked VenyaClient."""
    mock = MagicMock(spec=VenyaClient)
    mock.list_secrets = AsyncMock(return_value=[])
    mock.list_executors = AsyncMock(return_value={"executors": []})
    mock.run_command = AsyncMock(
        return_value={
            "exit_code": 0,
            "stdout": "output",
            "stderr": "",
            "masked_count": 0,
        }
    )
    mock.get_audit = AsyncMock(return_value=[])
    return mock


# --- list_secrets tests ---


async def test_list_secrets_empty() -> None:
    """No secrets → 'No secrets found' text."""
    mock = _make_mock_client()
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_secrets", {})
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert "No secrets found matching the criteria" in result[0].text


async def test_list_secrets_formats() -> None:
    """Secrets returned → formatted with key/executor/purpose/username."""
    mock = _make_mock_client()
    mock.list_secrets = AsyncMock(
        return_value=[
            {"key": "my_secret", "metadata": {"executor": "web-3", "purpose": "ssh_login", "username": "bot"}},
        ]
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_secrets", {})
    assert len(result) == 1
    assert "Available secrets (values not shown):" in result[0].text
    assert "key: my_secret" in result[0].text
    assert "executor: web-3" in result[0].text
    assert "purpose: ssh_login" in result[0].text
    assert "username: bot" in result[0].text


# --- list_executors tests ---


async def test_list_executors_online() -> None:
    """ONLINE/OFFLINE status rendering."""
    mock = _make_mock_client()
    mock.list_executors = AsyncMock(
        return_value={
            "executors": [
                {"id": "exec-1", "online": True, "last_heartbeat": "2026-01-01T00:00:00Z"},
                {"id": "exec-2", "online": False, "last_heartbeat": None},
            ]
        }
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_executors", {})
    assert "ONLINE" in result[0].text
    assert "OFFLINE" in result[0].text
    assert "exec-1" in result[0].text
    assert "exec-2" in result[0].text


# --- run_command tests ---


async def test_run_command_success() -> None:
    """Exit code + stdout rendered; masked count note."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(
        return_value={
            "exit_code": 0,
            "stdout": "reading packages...\nsetting up apache2",
            "stderr": "",
            "masked_count": 0,
        }
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool(
            "run_command",
            {
                "executor_id": "web-3",
                "command": "sudo apt install -y apache2",
                "secret_keys": ["bot_password_web_server_3"],
            },
        )
    assert len(result) == 1
    assert "Command exited with code 0" in result[0].text
    assert "reading packages" in result[0].text


async def test_run_command_masked_output() -> None:
    """masked_count note appears."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(
        return_value={
            "exit_code": 0,
            "stdout": "password: [REDACTED:abc12345]",
            "stderr": "",
            "masked_count": 2,
        }
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool(
            "run_command",
            {
                "executor_id": "web-3",
                "command": "cat /etc/secret",
                "secret_keys": ["db_password"],
            },
        )
    assert "2 secret(s) masked" in result[0].text


# --- get_audit tests ---


async def test_get_audit_empty() -> None:
    """No audit records → 'No audit records found' text."""
    mock = _make_mock_client()
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("get_audit", {})
    assert "No audit records found" in result[0].text


async def test_get_audit_formats() -> None:
    """Audit records formatted with timestamp/event_type/user/executor."""
    mock = _make_mock_client()
    mock.get_audit = AsyncMock(
        return_value=[
            {
                "timestamp": "2026-01-01T12:00:00Z",
                "event_type": "command_executed",
                "user_id": "alice",
                "fields": {"executor_id": "exec-1"},
            },
        ]
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("get_audit", {})
    assert "Recent audit records:" in result[0].text
    assert "command_executed" in result[0].text
    assert "user=alice" in result[0].text
    assert "executor=exec-1" in result[0].text


# --- error handling tests ---


async def test_session_expired_error() -> None:
    """SessionExpiredError propagates — SDK converts handler exceptions to isError=True."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(
        side_effect=SessionExpiredError(
            "Venya session expired and could not be renewed. "
            "Run the `venya` CLI (e.g. `venya list`) and approve your security key, "
            "then restart the MCP server."
        )
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        with pytest.raises(SessionExpiredError) as excinfo:
            await call_tool(
                "run_command",
                {
                    "executor_id": "web-3",
                    "command": "ls",
                    "secret_keys": ["key"],
                },
            )
    assert "Venya session expired" in str(excinfo.value)
    assert "venya" in str(excinfo.value).lower()


async def test_api_error() -> None:
    """VenyaAPIError propagates with exactly one 'Venya API error' prefix."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(side_effect=VenyaAPIError(503, "Service unavailable"))
    with patch("venya_mcp.server.get_client", return_value=mock):
        with pytest.raises(VenyaAPIError) as excinfo:
            await call_tool(
                "run_command",
                {
                    "executor_id": "web-3",
                    "command": "ls",
                    "secret_keys": [],
                },
            )
    text = str(excinfo.value)
    assert text.count("Venya API error") == 1
    assert "503" in text
    assert "Service unavailable" in text


async def test_unexpected_error_raises_runtime() -> None:
    """Generic exceptions surface as RuntimeError naming the tool (isError path)."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(side_effect=ValueError("boom"))
    with patch("venya_mcp.server.get_client", return_value=mock):
        with pytest.raises(RuntimeError, match=r"Unexpected error in tool run_command: boom"):
            await call_tool(
                "run_command",
                {
                    "executor_id": "web-3",
                    "command": "ls",
                    "secret_keys": [],
                },
            )


def test_build_client_wires_bootstrap_ca(tmp_path, monkeypatch) -> None:
    """build_client passes the _bootstrap_tls_verify() result as verify (F3 wiring)."""
    ca = tmp_path / "ca-bundle.crt"
    ca.write_text("fake-ca")
    monkeypatch.setenv("VENYA_CA_CERT", str(ca))
    captured: dict = {}

    class SpyClient:
        def __init__(self, config, verify=True):
            captured["verify"] = verify

    monkeypatch.setattr("venya_mcp.server.VenyaClient", SpyClient)
    build_client(MagicMock())
    assert captured["verify"] == str(ca)


def test_build_client_missing_ca_raises(monkeypatch) -> None:
    """No VENYA_CA_CERT at startup → actionable RuntimeError (paired negative)."""
    monkeypatch.delenv("VENYA_CA_CERT", raising=False)
    monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
    with pytest.raises(RuntimeError, match="VENYA_CA_CERT"):
        build_client(MagicMock())


def test_console_entry_point_is_sync() -> None:
    """venya-mcp entry point must be a sync callable (F6: async main regression guard)."""
    import inspect
    from importlib import metadata

    eps = list(metadata.entry_points(group="console_scripts", name="venya-mcp"))
    assert eps, "venya-mcp console script entry point not found in installed metadata"
    fn = eps[0].load()
    assert callable(fn)
    assert not inspect.iscoroutinefunction(fn)


async def test_unknown_tool() -> None:
    """Unknown tool name → 'Unknown tool: ...'."""
    with patch("venya_mcp.server.get_client", return_value=_make_mock_client()):
        result = await call_tool("nonexistent_tool", {})
    assert "Unknown tool: nonexistent_tool" in result[0].text


async def test_run_command_stderr_rendered() -> None:
    """stderr content appears in output."""
    mock = _make_mock_client()
    mock.run_command = AsyncMock(
        return_value={
            "exit_code": 1,
            "stdout": "",
            "stderr": "permission denied",
            "masked_count": 0,
        }
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool(
            "run_command",
            {
                "executor_id": "web-3",
                "command": "sudo rm -rf /",
                "secret_keys": [],
            },
        )
    assert "permission denied" in result[0].text
    assert "Command exited with code 1" in result[0].text
