# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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


async def test_list_secrets_renders_id_shape_and_resolved_usage() -> None:
    """Owner ruling a2 (ticket mcp-list-secrets-id-usage-not-rendered): id and
    shape are rendered, and usage arrives READY TO RUN — {secret_path} and
    {secret_id} resolved renderer-side; {host}/{user} are task-context
    placeholders and stay as authored."""
    mock = _make_mock_client()
    mock.list_secrets = AsyncMock(
        return_value=[
            {
                "id": 7,
                "key": "nas_creds",
                "metadata": {
                    "executor": "storage-01",
                    "purpose": "ssh_login",
                    "username": "nas-admin",
                    "shape": "ssh-password",
                    "usage": "sshpass -f {secret_path} ssh {user}@{host} status  # secret {secret_id}",
                },
            },
        ]
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_secrets", {})
    text = result[0].text
    assert "id: 7" in text
    assert "shape: ssh-password" in text
    assert "usage: sshpass -f /run/secrets/venya/7 ssh {user}@{host} status  # secret 7" in text
    assert "{secret_path}" not in text
    assert "{secret_id}" not in text


async def test_list_secrets_absent_shape_usage_render_no_fields() -> None:
    """Paired negative: no shape/usage stored → the fields are honestly
    omitted (no 'shape: None' garbage), while id still renders."""
    mock = _make_mock_client()
    mock.list_secrets = AsyncMock(return_value=[{"id": 3, "key": "plain_key", "metadata": {"executor": "web-3"}}])
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_secrets", {})
    text = result[0].text
    assert "id: 3" in text
    assert "shape:" not in text
    assert "usage:" not in text


async def test_list_secrets_never_renders_a_value_field() -> None:
    """Security pin (defense in depth): even if an API response ever carried
    a value field, the renderer prints only known non-value fields."""
    mock = _make_mock_client()
    mock.list_secrets = AsyncMock(
        return_value=[
            {
                "id": 9,
                "key": "k",
                "value": "ZZZ-DO-NOT-RENDER-000",
                "metadata": {"executor": "e", "purpose": "p", "username": "u", "usage": "cat {secret_path}"},
            }
        ]
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("list_secrets", {})
    text = result[0].text
    assert "ZZZ-DO-NOT-RENDER-000" not in text
    assert "usage: cat /run/secrets/venya/9" in text


def test_list_secrets_description_pins_resolved_usage() -> None:
    """a2 pin: the description must promise RESOLVED usage (agents never
    substitute {secret_path} themselves) and name the id field — the
    description/rendering drift this ticket fixed must not return."""
    import asyncio

    from venya_mcp.server import list_tools

    tools = asyncio.run(list_tools())
    by_name = {t.name: t for t in tools}
    desc = by_name["list_secrets"].description
    assert "ALREADY RESOLVED" in desc
    assert "id, executor" in desc
    assert "{secret_path}" in desc  # existing pin from secret-shape-metadata survives
    assert "/run/secrets/venya/" in desc


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


def test_tool_descriptions_teach_shape_and_file_path() -> None:
    """Pinned: the tool descriptions teach the file-path consumption pattern
    and the usage-template metadata (ticket secret-shape-metadata). The
    pre-fix run_command example ('ssh bot@web-server-3 …' with a password
    secret bound) could not consume the injected secret at all — that shape
    of misleading example must never return."""
    import asyncio

    from venya_mcp.server import list_tools

    tools = asyncio.run(list_tools())
    by_name = {t.name: t for t in tools}

    ls_desc = by_name["list_secrets"].description
    assert "usage" in ls_desc
    assert "{secret_path}" in ls_desc
    assert "/run/secrets/venya/" in ls_desc

    rc_desc = by_name["run_command"].description
    assert "sshpass -f /run/secrets/venya/" in rc_desc
    assert "'usage' template" in rc_desc
