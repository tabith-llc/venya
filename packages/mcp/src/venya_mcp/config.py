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


#: The ONE renewing clause every session message carries (#705, #706, #776). It names the verb
#: that renews and no verb that can clear the token: `venya list` reaches the #776 clearing path,
#: and `venya run` boots a sandbox it cannot enter without a token. It lives in the module that
#: owns the session file so every site — the two refusals in the client and the startup
#: precondition below — composes the same words instead of retyping them.
RENEW_CLAUSE = "Run `venya login <USER_ID>` and approve your security key"


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
    """Reads and writes the Venya CLI config file.

    The file is the session the CLI writes, so a long-running MCP server asks it for a
    newer token when its mtime moves (#705); ``_mtime`` is what that door compares.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self.path = config_path or self._resolve_path()
        self._data: dict[str, Any] = {}
        self._mtime: int | None = None
        #: What the file's own ``server_url`` said at the last read that saw one. See the property.
        self._disk_server_url: str | None = None
        self._load()
        self._mtime = self._stat_mtime()

    @staticmethod
    def _resolve_path() -> Path:
        env = os.environ.get("VENYA_CONFIG")
        if env:
            return Path(env)
        return default_config_dir() / "config.json"

    def _load(self) -> None:
        if not self.path.exists():
            # The startup precondition, in the same shape as the running server's sentence
            # (#705, #706): it names the path this process resolved and the verb that
            # creates it, and it does not call a session that never existed an expired one.
            # Restart is still the right tail HERE, and only here: a server that never
            # started has nothing that can reload.
            raise FileNotFoundError(
                f"No Venya session token found: there is no session file at {self.path}. "
                f"{RENEW_CLAUSE} to create it, then start the MCP server again."
            )
        self._data = json.loads(self.path.read_text())
        if isinstance(self._data, dict):
            seen = self._data.get("server_url")
            self._disk_server_url = seen if isinstance(seen, str) else None

    def _stat_mtime(self) -> int | None:
        """The session file's mtime in nanoseconds, or None when it cannot be seen.

        A stat carries no file content, so a caller may ask it on every request. None is a
        value like any other here: a file that is gone stays gone until a later stat sees
        something different, and nothing is re-read in between.
        """
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def reload_if_changed(self) -> str | None:
        """Read the session file only when its mtime moved; return its token, or None.

        The cheap door a long-running server can afford on every call (#705): one stat,
        and the read of one small file only when it actually changed. The CLI writes
        atomically (temp file + ``os.replace``), so a moved mtime means a whole file. The
        observed stat is recorded whether or not the read finds a token, so a file that
        vanished or turned unreadable is read once per change, not once per call.

        One limit, stated: a rewrite landing inside the same filesystem clock tick as the
        last stat reads as unchanged (measured on this box: two writes in one tick share
        an mtime). That is a window of milliseconds, and the client asks the file again
        unconditionally whenever a token is refused, so such a session is picked up on the
        next 401 rather than lost.
        """
        now = self._stat_mtime()
        if now == self._mtime:
            return None
        return self.reload()

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

    @property
    def disk_server_url(self) -> str | None:
        """The ``server_url`` the session file held at the last read that saw one, else ``None``.

        Not the guard — the https:// refusal of #540 stays on ``server_url``, at the point the URL is
        dialled. This is only a report of what the disk says, so a caller can ask whether a token it is
        about to take belongs to the core it dials (#705: refuse a session it cannot attest). It costs
        nothing to answer, because ``reload`` already parsed the whole file to read the token. A value
        that is not a string is reported as ``None``: it names no core a caller could compare against.
        """
        return self._disk_server_url

    def reload(self) -> str | None:
        """Re-read the session file and return the ``access_token`` it holds now.

        A long-running process holds the snapshot ``_load`` took at startup, so a
        ``venya login`` that lands afterwards is invisible to it (#705). This is the read
        behind that door, and it is deliberately narrow: it takes ``access_token`` only
        and never re-points ``server_url``, so a re-read cannot move a bearer token to a
        different core mid-session (the https://-only guard of #540 keeps reading the
        startup value). What it does with the file's own ``server_url`` is report it, once,
        through ``disk_server_url``: the caller decides whether the token it is offered
        belongs to the core it dials, and refuses it when it does not (#705).

        Returns ``None`` when the file is gone, unreadable, not a JSON object, or holds no
        token, leaving ``_data`` untouched — a caller with nothing usable on disk gets its
        usual "could not be renewed" answer rather than an OSError or a decode error. The
        observed stat is recorded on every path, so ``reload_if_changed`` does not keep
        re-reading a file that has not moved since.
        """
        token: str | None = None
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            found = data.get("access_token")
            if isinstance(found, str) and found:
                token = found
                self._data["access_token"] = found
            seen_core = data.get("server_url")
            self._disk_server_url = seen_core if isinstance(seen_core, str) else None
        self._mtime = self._stat_mtime()
        return token

    def update_token(self, new_token: str) -> None:
        """Update the access token, preserving all other keys.

        "All other keys" means the keys the file holds NOW, not the snapshot this process
        took at startup. This file is shared with the CLI, and publishing a stale snapshot
        silently reverts a key another writer changed in the meantime — ``server_url`` among
        them, the one key that decides which core the client dials (#707). So the write is a
        read-modify-write: re-read the file, replace ``access_token`` only. The in-memory
        snapshot keeps its own ``server_url``; only the file follows the other writer.

        Writes atomically (temp file + os.replace) with 0o600 permissions
        so concurrent CLI reads never see a torn file.
        """
        # shortcut: the read-modify-write narrows the window to one file read, it does not
        # serialise against the CLI; a cross-plane lock on config.json is the upgrade, and it needs
        # both packages to agree on one primitive.
        try:
            merged: Any = json.loads(self.path.read_text())
        except (OSError, ValueError):
            merged = None
        if not isinstance(merged, dict):
            # An unreadable file is no reason to lose the refresh: write this process's own
            # keys and let the next writer re-read. A non-object file lands here too.
            logger.warning(
                "Session file %s gave no readable keys; writing this process's own",
                self.path,
            )
            merged = dict(self._data)
        merged["access_token"] = new_token
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
                fd.write(json.dumps(merged, indent=2))
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
        # This write is ours, so it must not look like somebody else's change on the
        # next stat — the value in _data is already the value on disk.
        self._mtime = self._stat_mtime()
