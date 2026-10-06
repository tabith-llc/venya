# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Pins the MCP config-path resolver to the CLI resolver on every platform (#483).

packages/mcp and packages/cli resolve the location of the ONE config file
(`config.json`) independently: the mcp package does not depend on venya-cli,
so its resolver is a deliberate copy of venya_cli.api_client.default_config_dir.
These tests compare the two copies under every platform branch so they cannot
drift silently.

venya_cli is imported HERE (test code, whole workspace installed) — never in
mcp product code, which must stay installable without the CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from venya_cli import api_client as cli_api
from venya_mcp.config import MCPConfig, default_config_dir


@pytest.fixture(autouse=True)
def _no_config_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ambient VENYA_CONFIG / APPDATA out of the platform comparisons."""
    monkeypatch.delenv("VENYA_CONFIG", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)


def test_darwin_mcp_matches_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """macOS: MCP resolves the same dir/file the CLI writes."""
    monkeypatch.setattr(sys, "platform", "darwin")
    expected = Path.home() / "Library" / "Application Support" / "venya"
    assert default_config_dir() == cli_api.default_config_dir() == expected
    assert MCPConfig._resolve_path() == expected / "config.json"


def test_win32_appdata_set_mcp_matches_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Windows with %APPDATA% set: both resolvers use APPDATA\\venya."""
    monkeypatch.setattr(sys, "platform", "win32")
    appdata = tmp_path / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata))
    assert default_config_dir() == cli_api.default_config_dir() == appdata / "venya"
    assert MCPConfig._resolve_path() == appdata / "venya" / "config.json"


def test_win32_appdata_unset_both_fall_back_same_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows with %APPDATA% unset: both fall back to ~/AppData/Roaming/venya."""
    monkeypatch.setattr(sys, "platform", "win32")
    expected = Path.home() / "AppData" / "Roaming" / "venya"
    assert default_config_dir() == cli_api.default_config_dir() == expected
    assert MCPConfig._resolve_path() == expected / "config.json"


def test_linux_result_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """POSIX regression half: ~/.config/venya/config.json, as deployed today."""
    monkeypatch.setattr(sys, "platform", "linux")
    expected = Path.home() / ".config" / "venya"
    assert default_config_dir() == cli_api.default_config_dir() == expected
    assert MCPConfig._resolve_path() == expected / "config.json"


def test_venya_config_override_wins_on_any_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """VENYA_CONFIG keeps top priority on every platform, including darwin."""
    monkeypatch.setattr(sys, "platform", "darwin")
    config_file = tmp_path / "custom.json"
    config_file.write_text('{"server_url": "https://venya-core-1", "access_token": "t"}')
    monkeypatch.setenv("VENYA_CONFIG", str(config_file))
    config = MCPConfig()
    assert config.path == config_file
    assert config.access_token == "t"
