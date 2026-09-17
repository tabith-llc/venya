# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tokens print ungated (ticket cli-executor-enroll-show-sensitive-unnecessary).

--show-sensitive was removed: admin commands that mint single-use enrollment
tokens always print them (the --json paths already did). Paired negative:
the removed flag is rejected by the parser, not silently ignored.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_create_user, cmd_admin_executor_enroll


def _make_mock_response(status_code=200, json_data=None):
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode()
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


def _make_client():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)
    client = APIClient(config_file=config_file)
    return client, config_file


class TestTokensAlwaysShown:
    def test_executor_enroll_prints_token_ungated(self, capsys):
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.return_value = _make_mock_response(
                200, {"enrollment_token": "enrl_exec_TESTTOKEN123", "expires_in_seconds": 1800}
            )
            client._http = mock_http

            args = MagicMock()
            args.executor_id = "exec-test"
            args.output_dir = None

            result = cmd_admin_executor_enroll(client, args)
            out = capsys.readouterr().out
            assert result == 0
            assert "Token: enrl_exec_TESTTOKEN123" in out
            assert "[REDACTED" not in out
        finally:
            client.close()
            config_file.unlink()

    def test_create_user_prints_token_ungated(self, capsys):
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.return_value = _make_mock_response(
                200,
                {
                    "user_id": "bob",
                    "status": "pending_enrollment",
                    "enrollment_token": "enrl_user_TEST456",
                    "expires_in_seconds": 900,
                },
            )
            client._http = mock_http

            args = MagicMock()
            args.username = "bob"
            args.display_name = None
            args.roles = None
            args.json = False

            result = cmd_admin_create_user(client, args)
            out = capsys.readouterr().out
            assert result == 0
            assert "Enrollment Token: enrl_user_TEST456" in out
            assert "[REDACTED" not in out
        finally:
            client.close()
            config_file.unlink()

    def test_show_sensitive_flag_rejected(self):
        """Paired negative: the removed flag fails loudly, not silently."""
        from venya_cli.cli import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--show-sensitive", "list"])
