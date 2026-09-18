# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for cmd_login — the CLI's FIDO2 auth entry point.

Ticket cli-login-no-unit-test: the command had zero coverage. Truth table per
the standing rule — success plus paired negatives (auth rejection, unexpected
error, malformed server response). The FIDO2 wire flow itself is exercised by
the API-client and e2e suites; this file pins cmd_login's own contract:
return codes, stdout/stderr split, and which identity gets printed.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from venya_cli.api_client import APIClientAuthenticationError
from venya_cli.commands import cmd_login


def _client(result=None, exc=None):
    client = MagicMock()
    if exc is not None:
        client.authenticate.side_effect = exc
    else:
        client.authenticate.return_value = result
    return client


class TestCmdLoginSuccess:
    def test_returns_zero_and_prints_identity(self, capsys):
        client = _client(result={"user_id": "ada", "access_token": "tok"})
        rc = cmd_login(client, SimpleNamespace(user_id="ada"))
        out, err = capsys.readouterr()

        assert rc == 0
        assert "Authenticated as ada." in out
        assert err == ""
        client.authenticate.assert_called_once_with(user_id="ada")

    def test_prints_server_identity_not_requested_arg(self, capsys):
        """The printed identity comes from the server's result, not the argv
        user_id — a normalization/canonicalization difference must surface."""
        client = _client(result={"user_id": "ada@venya", "access_token": "tok"})
        rc = cmd_login(client, SimpleNamespace(user_id="ada"))
        out, _ = capsys.readouterr()

        assert rc == 0
        assert "Authenticated as ada@venya." in out


class TestCmdLoginFailures:
    def test_auth_error_returns_one_on_stderr(self, capsys):
        """Paired negative: rejected assertion → rc 1, nothing on stdout."""
        client = _client(exc=APIClientAuthenticationError("key rejected by server"))
        rc = cmd_login(client, SimpleNamespace(user_id="ada"))
        out, err = capsys.readouterr()

        assert rc == 1
        assert "Login failed: key rejected by server" in err
        assert "Authenticated" not in out

    def test_unexpected_error_returns_one_on_stderr(self, capsys):
        """Paired negative: transport/local failure (no key, connection) → rc 1."""
        client = _client(exc=RuntimeError("no security key found"))
        rc = cmd_login(client, SimpleNamespace(user_id="ada"))
        out, err = capsys.readouterr()

        assert rc == 1
        assert "Login failed: no security key found" in err
        assert "Authenticated" not in out

    def test_malformed_server_response_returns_one(self, capsys):
        """Paired negative: success-shaped call but missing user_id → handled
        rc 1, not an uncaught KeyError traceback."""
        client = _client(result={"access_token": "tok"})
        rc = cmd_login(client, SimpleNamespace(user_id="ada"))
        out, err = capsys.readouterr()

        assert rc == 1
        assert "Login failed:" in err
        assert "Authenticated" not in out
