# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the venya store command (ticket cli-store-omits-key-version-id)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_store


def _make_mock_response(status_code=200, json_data=None):
    """Create a mock httpx.Response."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode()
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


def _make_error_response(status_code, detail):
    """Create a mock httpx.Response that fails raise_for_status."""
    resp = _make_mock_response(status_code, json_data={"detail": detail})
    resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
        f"HTTP {status_code}", request=MagicMock(), response=resp
    )
    return resp


def _make_client():
    """Create an APIClient with a temporary config file."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)
    client = APIClient(config_file=config_file)
    return client, config_file


def _make_args(**overrides):
    args = MagicMock()
    args.key = "mykey"
    args.value = "myvalue"
    args.roles = ["admin"]
    args.metadata = None
    args.key_version = None
    for k, v in overrides.items():
        setattr(args, k, v)
    return args


def _post_payload(mock_http):
    """Extract the JSON body of the POST /secrets call."""
    post_calls = [c for c in mock_http.request.call_args_list if c[0][0] == "POST"]
    assert len(post_calls) == 1, f"expected exactly one POST, got {len(post_calls)}"
    return post_calls[0][1]["json"]


class TestCmdStore:
    """venya store must send key_version_id (server requires the field)."""

    def test_store_resolves_active_key_version(self):
        """No --key-version: GET active endpoint, payload includes its id."""
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.side_effect = [
                _make_mock_response(200, {"key_version_id": "v1"}),
                _make_mock_response(201, {"id": 1, "key": "mykey", "role_names": ["admin"]}),
            ]
            client._http = mock_http

            result = cmd_store(client, _make_args())
            assert result == 0

            get_call = mock_http.request.call_args_list[0]
            assert get_call[0][0] == "GET"
            assert get_call[0][1] == "/api/v1/key-versions/active"

            payload = _post_payload(mock_http)
            assert payload["key_version_id"] == "v1"
            assert payload["key"] == "mykey"
            assert payload["value"] == "myvalue"
            assert payload["roles"] == ["admin"]
            assert (
                "force" not in payload
            )  # --force removed: server has no force field (ticket cli-store-force-field-ignored)
        finally:
            client.close()
            config_file.unlink()

    def test_store_key_version_override_skips_lookup(self):
        """--key-version is used verbatim and no active lookup is made."""
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.return_value = _make_mock_response(
                201, {"id": 2, "key": "mykey", "role_names": ["admin"]}
            )
            client._http = mock_http

            result = cmd_store(client, _make_args(key_version="v2"))
            assert result == 0

            assert mock_http.request.call_count == 1
            assert mock_http.request.call_args[0][0] == "POST"
            payload = _post_payload(mock_http)
            assert payload["key_version_id"] == "v2"
        finally:
            client.close()
            config_file.unlink()

    def test_store_active_endpoint_unavailable_fails_without_post(self):
        """503 from the active endpoint: exit 1, no POST issued (fresh install)."""
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.return_value = _make_error_response(503, "No active key version configured")
            client._http = mock_http

            result = cmd_store(client, _make_args())
            assert result == 1
            assert mock_http.request.call_count == 1
        finally:
            client.close()
            config_file.unlink()

    def test_store_post_422_still_fails(self):
        """A server 422 on POST (e.g. bad roles) is not masked: exit 1."""
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.side_effect = [
                _make_mock_response(200, {"key_version_id": "v1"}),
                _make_error_response(
                    422,
                    [
                        {
                            "type": "missing",
                            "loc": ["body", "roles"],
                            "msg": "Field required",
                        }
                    ],
                ),
            ]
            client._http = mock_http

            result = cmd_store(client, _make_args())
            assert result == 1
        finally:
            client.close()
            config_file.unlink()


class TestCmdStoreStdin:
    """Value via stdin / hidden prompt — keeps secrets out of argv
    (/proc/*/cmdline, shell history). Ticket cli-store-stdin-help-false:
    the help text always claimed stdin; option-1 ruling implemented it."""

    def _client_with_post(self):
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.return_value = _make_mock_response(201, {"id": 1, "key": "mykey", "role_names": ["admin"]})
        client._http = mock_http
        return client, config_file, mock_http

    def test_dash_positional_reads_stdin(self, monkeypatch):
        import io
        import sys

        monkeypatch.setattr(sys, "stdin", io.StringIO("piped-secret\n"))
        client, config_file, mock_http = self._client_with_post()
        try:
            assert cmd_store(client, _make_args(value="-", key_version="v1")) == 0
            assert _post_payload(mock_http)["value"] == "piped-secret"  # trailing newline stripped
        finally:
            client.close()
            config_file.unlink()

    def test_omitted_value_reads_piped_stdin(self, monkeypatch):
        import io
        import sys

        monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret\r\n"))
        client, config_file, mock_http = self._client_with_post()
        try:
            assert cmd_store(client, _make_args(value=None, key_version="v1")) == 0
            assert _post_payload(mock_http)["value"] == "s3cret"
        finally:
            client.close()
            config_file.unlink()

    def test_empty_stdin_actionable_error_no_post(self, monkeypatch, capsys):
        """Paired negative: empty input must fail loudly and send nothing."""
        import io
        import sys

        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        client, config_file, mock_http = self._client_with_post()
        try:
            assert cmd_store(client, _make_args(value="-", key_version="v1")) == 1
            assert mock_http.request.call_count == 0
            assert "stdin" in capsys.readouterr().err
        finally:
            client.close()
            config_file.unlink()

    def test_tty_prompt_uses_getpass_no_echo(self, monkeypatch):
        """Omitted value at a TTY: hidden getpass prompt, stdin never read."""
        import sys

        fake_stdin = MagicMock()
        fake_stdin.isatty.return_value = True
        monkeypatch.setattr(sys, "stdin", fake_stdin)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "hidden-val")
        client, config_file, mock_http = self._client_with_post()
        try:
            assert cmd_store(client, _make_args(value=None, key_version="v1")) == 0
            assert _post_payload(mock_http)["value"] == "hidden-val"
            fake_stdin.read.assert_not_called()
        finally:
            client.close()
            config_file.unlink()

    def test_explicit_value_ignores_stdin(self, monkeypatch):
        """Paired negative for precedence: argv value wins, stdin untouched."""
        import sys

        fake_stdin = MagicMock()
        monkeypatch.setattr(sys, "stdin", fake_stdin)
        client, config_file, mock_http = self._client_with_post()
        try:
            assert cmd_store(client, _make_args(value="plain", key_version="v1")) == 0
            assert _post_payload(mock_http)["value"] == "plain"
            fake_stdin.read.assert_not_called()
        finally:
            client.close()
            config_file.unlink()


class TestCmdStoreReplacedMessage:
    """Operator-visible replace signal (upsert option-2 ruling)."""

    def test_replaced_response_prints_replaced_message(self, capsys):
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.side_effect = [
                _make_mock_response(200, {"key_version_id": "v1"}),
                _make_mock_response(201, {"id": 7, "key": "mykey", "role_names": ["admin"], "replaced": True}),
            ]
            client._http = mock_http
            assert cmd_store(client, _make_args()) == 0
            out = capsys.readouterr().out
            assert "replaced existing" in out
            assert "id 7" in out
        finally:
            client.close()
            config_file.unlink()

    def test_fresh_store_message_unchanged(self, capsys):
        """Paired negative: replaced=False keeps the classic message."""
        client, config_file = _make_client()
        try:
            mock_http = MagicMock()
            mock_http.request.side_effect = [
                _make_mock_response(200, {"key_version_id": "v1"}),
                _make_mock_response(201, {"id": 1, "key": "mykey", "role_names": ["admin"], "replaced": False}),
            ]
            client._http = mock_http
            assert cmd_store(client, _make_args()) == 0
            out = capsys.readouterr().out
            assert "stored successfully" in out
            assert "replaced" not in out
        finally:
            client.close()
            config_file.unlink()
