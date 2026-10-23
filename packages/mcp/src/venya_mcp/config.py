# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Reads Venya CLI config to get server URL + access token.

The config file is written by the CLI after `venya login` completes FIDO2.
It contains at minimum:
  {
    "server_url": "https://venya-core-1",
    "access_token": "eyJhbGciOi..."
  }

No refresh_token. No expires_at. Token refresh sends the current access
token to /api/v1/auth/refresh and receives a new one back.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("venya.mcp")


class InsecureServerURLError(ValueError):
    """The configured ``server_url`` is not an https:// core URL (#540).

    Subclasses ValueError so the broad handler in server.py tool dispatch
    (which catches Exception) surfaces the refusal to the agent as a tool
    error carrying the repair wording, instead of a cleartext dial.
    """


def _https_refusal(server_url: str, *, site: str, ticket: str, detail: str = "") -> str:
    """The ONE refusal wording for a non-https core URL, as a string.

    Deliberate copy of ``venya_cli.commands._https_refusal``: the mcp package
    does not depend on venya-cli (see packages/mcp/pyproject.toml), so product
    code must not import the CLI helper — the same arrangement as
    ``default_config_dir`` above. tests/test_client.py pins the two copies
    byte-for-byte for identical inputs so they cannot drift.
    """
    suffix = f" — {detail}" if detail else ""
    return (
        f"Error: server URL must be https:// — got '{server_url}'. Plaintext http is "
        f"not supported for {site}{suffix} (ticket {ticket})."
    )


def default_config_dir() -> Path:
    """Platform-appropriate config directory.

    macOS convention: ~/Library/Application Support/venya.
    Windows convention: %APPDATA%/venya.
    POSIX (Linux, etc.): ~/.config/venya.

    This resolver deliberately mirrors venya_cli.api_client.default_config_dir().
    The mcp package does not depend on venya-cli (see packages/mcp/pyproject.toml:
    mcp, httpx2, pydantic), so product code must not import the CLI helper; the
    two copies are pinned together by tests/test_config_path.py, which compares
    both resolvers under each platform branch.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "venya"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return Path(appdata or Path.home() / "AppData" / "Roaming") / "venya"
    return Path.home() / ".config" / "venya"


DEFAULT_CONFIG_DIR = default_config_dir()
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.json"


class MCPConfig:
    """Reads and writes the Venya CLI config file."""

    def __init__(self, config_path: Path | None = None) -> None:
        self.path = config_path or self._resolve_path()
        self._data: dict[str, Any] = {}
        self._load()

    @staticmethod
    def _resolve_path() -> Path:
        env = os.environ.get("VENYA_CONFIG")
        if env:
            return Path(env)
        return default_config_dir() / "config.json"

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(
                "No Venya session token found. "
                "Run the `venya` CLI (e.g. `venya list`) and approve your "
                "security key, then restart the MCP server."
            )
        self._data = json.loads(self.path.read_text())

    @property
    def server_url(self) -> str:
        """The core URL every dial composes from — https:// only (#540).

        Same rule and the same wording as the CLI dial seam
        (venya_cli.api_client.APIClient._http, ticket
        cli-dial-sites-missing-https-guard): the check lives at the point the
        URL is resolved for dialing, NOT in an ``__init__``, so loading a
        config or constructing a client for an offline repair is never
        bricked — the reasoning the CLI comment records transfers.

        The value is REFUSED, never rewritten: an automatic http -> https
        upgrade would hide a config error and can turn a working local-dial
        config into a confusing failure. The shipped default (https://localhost)
        passes the guard unchanged.
        """
        url = self._data.get("server_url", "https://localhost")
        if not (isinstance(url, str) and url.startswith("https://")):
            raise InsecureServerURLError(
                _https_refusal(
                    str(url),
                    site="the Venya MCP server dial",
                    ticket="mcp-dial-missing-https-guard",
                    detail=(
                        'set "server_url" in the Venya config file to the '
                        "https:// core URL; this transport carries your bearer "
                        "token and every tool call"
                    ),
                )
            )
        return url.rstrip("/")

    @property
    def access_token(self) -> str | None:
        return self._data.get("access_token")

    def update_token(self, new_token: str) -> None:
        """Update the access token, preserving all other keys.

        Writes atomically (temp file + os.replace) with 0o600 permissions
        so concurrent CLI reads never see a torn file.
        """
        self._data["access_token"] = new_token
        tmp_fd: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.path.parent,
                prefix=".venya-config-",
                suffix=".tmp",
                mode="w",
                delete=False,
            ) as fd:
                tmp_fd = fd.name
                fd.write(json.dumps(self._data, indent=2))
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(tmp_fd, self.path)
            tmp_fd = None
        finally:
            if tmp_fd is not None:
                try:
                    os.unlink(tmp_fd)
                except OSError:
                    pass
        logger.info("Token refreshed and persisted to %s", self.path)
