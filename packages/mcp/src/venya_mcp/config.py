# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Reads Venya CLI config to get server URL + access token.

The config file is written by the CLI after `venya auth` completes FIDO2.
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
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("venya.mcp")

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "venya" / "config.json"


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
        return DEFAULT_CONFIG_PATH

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
        url = self._data.get("server_url", "https://localhost")
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
