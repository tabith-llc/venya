# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#616 — `admin executor-enroll --output-dir` keeps its creation promise.

The generated reference (`docs/cli-reference.md`, the `--output-dir` help row)
promises the command CREATES the bundle directory. At the base of this branch
the creation call sat AFTER the network POST, so:

- a failed POST left no directory at all (measured: rc=1, dir absent), and
- any path that could not be created reached the operator as a bare OS error
  string — `[Errno 2] No such file or directory: '/proc/self/nope'`,
  `[Errno 13] Permission denied: ...`, `[Errno 20] Not a directory: ...` —
  with the token already minted server-side.

Cells below pair the positive (creation happens, at 0700, before the round
trip) with the negatives (un-creatable paths refuse by name, carry the path,
mint nothing, and leave no partial bundle).
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_executor_enroll

TOKEN_PAYLOAD = {"enrollment_token": "enrl_exec_616_TEST", "expires_in_seconds": 900}


def _make_response(json_data):
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = 200
    mock.json.return_value = json_data
    mock.content = json.dumps(json_data).encode()
    return mock


def _make_client():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(json.dumps({"server_url": "https://test-core.example"}).encode())
        config_file = Path(f.name)
    return APIClient(config_file=config_file), config_file


def _make_args(output_dir):
    args = MagicMock()
    args.executor_id = "venya-exec-9"
    args.output_dir = str(output_dir)
    return args


class TestOutputDirCreatedBeforePost:
    """AC2 + AC5: the documented creation happens, at 0700, BEFORE the POST."""

    def test_missing_dir_created_at_0700_with_bundle(self, tmp_path, capsys, monkeypatch):
        """Positive: a non-existent (nested) DIR is created, 0700, token written, rc 0."""
        monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", tmp_path / "absent.crt")
        monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin.crt")
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(TOKEN_PAYLOAD)
            nested = tmp_path / "deep" / "nest"

            old = os.umask(0o022)
            try:
                rc = cmd_admin_executor_enroll(client, _make_args(nested))
            finally:
                os.umask(old)

            assert rc == 0
            assert nested.is_dir(), "the docs promise creation of DIR; it must exist on success"
            assert stat.S_IMODE(nested.stat().st_mode) == 0o700
            assert (nested / "token").read_bytes() == b"enrl_exec_616_TEST"
            assert stat.S_IMODE((nested / "token").stat().st_mode) == 0o600
        finally:
            client.close()
            config_file.unlink()

    def test_dir_created_even_when_post_fails(self, tmp_path, monkeypatch):
        """THE FIX (AC5 ordering): creation must not ride on the round trip.

        At the base this cell fails: rc=1 and the DIR was never created, so the
        documented "(creates …)" sentence was false on every failing mint.
        """
        monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", tmp_path / "absent.crt")
        monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin.crt")
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.side_effect = httpx2.ConnectError("boom")
            bundle = tmp_path / "bundle"

            rc = cmd_admin_executor_enroll(client, _make_args(bundle))

            assert rc == 1, "a failed mint still refuses"
            assert bundle.is_dir(), "--output-dir creation is documented, not conditional on the POST"
            assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
            # AC4: the dir is empty — no token, no half-written bundle.
            assert not (bundle / "token").exists()
            assert list(bundle.iterdir()) == [], "no partial bundle may be left behind"
        finally:
            client.close()
            config_file.unlink()

    def test_stale_token_still_removed_before_the_mint(self, tmp_path, monkeypatch):
        """AC4 no-regression: pre-mint removal survives the reordering."""
        monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", tmp_path / "absent.crt")
        monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin.crt")
        client, config_file = _make_client()
        try:
            bundle = tmp_path / "bundle"
            bundle.mkdir()
            (bundle / "token").write_text("enrl_exec_STALE_DEAD_TOKEN")
            client._http = MagicMock()
            client._http.request.side_effect = httpx2.ConnectError("boom")

            rc = cmd_admin_executor_enroll(client, _make_args(bundle))

            assert rc == 1
            assert not (bundle / "token").exists(), "failed mint must not leave a stale token"
        finally:
            client.close()
            config_file.unlink()


class TestUncreatablePathRefusesByName:
    """AC3 paired negatives: named refusal carrying the path, no OS error string,
    no request sent, nothing left on disk."""

    @pytest.mark.skipif(os.geteuid() == 0, reason="mode 0500 does not bind root")
    def test_unwritable_parent_refuses_by_name(self, tmp_path, capsys):
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        blocked.chmod(0o500)
        target = blocked / "bundle"
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(TOKEN_PAYLOAD)

            rc = cmd_admin_executor_enroll(client, _make_args(target))

            err = capsys.readouterr().err
            assert rc == 1
            assert "--output-dir" in err, err
            assert str(target) in err, f"the refusal must carry the path: {err}"
            assert "No such file" in err or "Permission denied" in err, err
            assert "[Errno" not in err, f"raw OS error string reached the operator: {err}"
            assert "Traceback" not in err, err
            assert not target.exists()
            # nothing minted: the refusal happens before the request is built
            assert client._http.request.call_count == 0, "a path that cannot hold the bundle must not mint a token"
        finally:
            blocked.chmod(0o700)
            client.close()
            config_file.unlink()

    def test_file_in_place_of_dir_refuses_by_name(self, tmp_path, capsys):
        as_file = tmp_path / "is-a-file"
        as_file.write_text("not a directory")
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(TOKEN_PAYLOAD)

            rc = cmd_admin_executor_enroll(client, _make_args(as_file))

            err = capsys.readouterr().err
            assert rc == 1
            assert "--output-dir" in err and str(as_file) in err, err
            assert "file" in err.lower(), f"should say WHY: {err}"
            assert "[Errno" not in err, f"raw OS error string reached the operator: {err}"
            assert "Traceback" not in err, err
            assert client._http.request.call_count == 0, "no token may be minted into a path that cannot hold it"
            # the pre-existing file is untouched
            assert as_file.read_text() == "not a directory"
        finally:
            client.close()
            config_file.unlink()

    def test_file_sitting_on_the_path_prefix_refuses_by_name(self, tmp_path, capsys):
        """The `[Errno 20] Not a directory` class: a FILE where a PREFIX lives."""
        as_file = tmp_path / "is-a-file"
        as_file.write_text("x")
        target = as_file / "sub"
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(TOKEN_PAYLOAD)

            rc = cmd_admin_executor_enroll(client, _make_args(target))

            err = capsys.readouterr().err
            assert rc == 1
            assert str(target) in err, err
            assert "[Errno" not in err and "Traceback" not in err, err
            assert client._http.request.call_count == 0
        finally:
            client.close()
            config_file.unlink()
