# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for run_command's server-URL resolution (flag > env > config).

Ticket cli-server-url-env-ignored: `--server-url`'s help text promises
"default: from config or VENYA_SERVER_URL" and the installer banner's
headless instruction (commands.py, `sudo VENYA_SERVER_URL=... venya admin
executor-enroll`) drives the CLI purely by env -- but run_command only ever
read the argparse flag, falling through to the config.json default
(http://localhost:8000). First physical touch on a headless core died with
Errno 111 Connection refused. Only the revoke-admin-cert handler had its own
env fallback (flag > env > config); this pins the same precedence at the
single chokepoint every command flows through.

The load-bearing negative: an explicit --server-url flag must beat the env
var, and an EMPTY env var must be treated as unset (fall through to config).
"""

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from venya_cli.commands import run_command


def _resolve(*, flag=None, env=None):
    """Drive run_command; return the server_url it passes to APIClient."""
    client = MagicMock()
    client.config.access_token = "tok"  # skip the auth gate; not under test
    client.has_admin_mtls = False
    args = SimpleNamespace(command="admin", server_url=flag, user_id=None)
    environ = {} if env is None else {"VENYA_SERVER_URL": env}
    with (
        patch("venya_cli.commands.APIClient", return_value=client) as mock_client,
        patch("venya_cli.commands.cmd_admin", return_value=0),
        patch.dict(os.environ, environ, clear=True),
    ):
        rc = run_command(args)
    assert rc == 0
    return mock_client.call_args.kwargs.get("server_url")


class TestServerUrlEnvResolution:
    def test_env_used_when_no_flag(self):
        """THE FIX: VENYA_SERVER_URL reaches APIClient when no flag is given."""
        assert _resolve(env="https://venya-core-1") == "https://venya-core-1"

    def test_flag_beats_env(self):
        """LOAD-BEARING NEGATIVE: explicit --server-url wins over the env."""
        assert _resolve(flag="https://flag.example", env="https://env.example") == "https://flag.example"

    def test_neither_passes_none(self):
        """No flag, no env -> None: APIClient falls back to config.json, unchanged."""
        assert _resolve() is None

    def test_empty_env_treated_as_unset(self):
        """VENYA_SERVER_URL='' must not become the server URL."""
        assert _resolve(env="") is None


def _resolve_exec(*, core_flag=None, env=None):
    """Drive run_command for the exec-register shape (flag dest=core_url);
    return the server_url it passes to APIClient."""
    client = MagicMock()
    client.config.access_token = "tok"  # skip the auth gate; not under test
    client.has_admin_mtls = False
    fields = {"command": "exec", "exec_command": "register"}
    if core_flag is not None:
        fields["core_url"] = core_flag
    args = SimpleNamespace(**fields)
    environ = {} if env is None else {"VENYA_SERVER_URL": env}
    with (
        patch("venya_cli.commands.APIClient", return_value=client) as mock_client,
        patch("venya_cli.commands.cmd_exec_group", return_value=0),
        patch.dict(os.environ, environ, clear=True),
    ):
        rc = run_command(args)
    assert rc == 0
    return mock_client.call_args.kwargs.get("server_url")


class TestExecRegisterCoreUrlAlias387:
    """#387: the exec-family parsers bind --core-url to dest=core_url, so the
    chokepoint must read that alias too — otherwise `exec register`'s
    post-save verify call silently targets the config default (Errno 111 on
    config-less hosts) while the CSR POST went to the flag URL."""

    def test_core_url_flag_reaches_client(self):
        """THE FIX: --core-url (dest=core_url) becomes the client base URL."""
        assert _resolve_exec(core_flag="https://venya-core-3") == "https://venya-core-3"

    def test_core_url_beats_env(self):
        """Paired negative: the explicit flag outranks VENYA_SERVER_URL."""
        assert _resolve_exec(core_flag="https://flag.example", env="https://env.example") == "https://flag.example"

    def test_no_flag_passes_none_config_path_unchanged(self):
        """Control: no --core-url anywhere -> None, APIClient falls back to
        config.json exactly as before this fix."""
        assert _resolve_exec() is None

    def test_empty_core_url_treated_as_unset(self):
        """--core-url '' must not become the server URL (empty = unset)."""
        assert _resolve_exec(core_flag="") is None
