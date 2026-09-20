# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for `admin executor-enroll --output-dir` bundle output.

Ticket cli-executor-enroll-token-ux (post-reconcile scope — the redaction
defects were superseded by the 2026-09-17 --show-sensitive removal ruling;
the --output json criterion was DROPPED by user amendment 2026-09-20,
rationale voided by the same ruling). What remains, per 2026-09-14 G3-probe
evidence:

1. LOAD-BEARING NEGATIVE: a failed mint must not leave a previous run's
   stale `token` file for `test -s` freshness checks to trust — removal
   happens BEFORE the POST (removal after would resurrect the bug on a
   crash between the two).
2. Instruction snippet must use the real executor_id / configured server,
   not hardcoded `venya-exec-1` / `venya-core-1` template text.
3. CA-missing case: loud incomplete-bundle warning AND the snippet omits
   VENYA_VENYA_CA_FILE instead of referencing a nonexistent file.
4. CA-present case: the var line is included and the bundle file written.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
from venya_cli.api_client import APIClient
from venya_cli.commands import cmd_admin_executor_enroll


def _make_response(status_code=200, json_data=None):
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    mock.json.return_value = json_data if json_data is not None else {}
    mock.content = json.dumps(json_data or {}).encode()
    return mock


def _make_client(server_url="https://test-core.example"):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(json.dumps({"server_url": server_url}).encode())
        config_file = Path(f.name)
    return APIClient(config_file=config_file), config_file


def _args(tmp_path, executor_id="venya-exec-9"):
    args = MagicMock()
    args.executor_id = executor_id
    args.output_dir = str(tmp_path / "bundle")
    return args


class TestEnrollTokenBundle:
    def test_failed_mint_removes_stale_token(self, tmp_path, capsys):
        """THE FIX (load-bearing negative): stale token + failing POST ->
        token file ABSENT. Pre-POST removal; post-POST removal would leave a
        crash window that resurrects the near-reuse bug."""
        client, config_file = _make_client()
        try:
            bundle = tmp_path / "bundle"
            bundle.mkdir()
            (bundle / "token").write_text("enrl_exec_STALE_DEAD_TOKEN")
            client._http = MagicMock()
            client._http.request.side_effect = httpx2.ConnectError("boom")

            rc = cmd_admin_executor_enroll(client, _args(tmp_path))

            assert rc == 1
            assert not (bundle / "token").exists(), "failed mint must not leave a stale token"
        finally:
            client.close()
            config_file.unlink()

    def test_instructions_use_real_ids(self, tmp_path, capsys):
        """Negative+positive: snippet carries the actual executor_id and the
        configured server_url — never the hardcoded template hosts."""
        client, config_file = _make_client(server_url="https://test-core.example")
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(
                200, {"enrollment_token": "enrl_exec_TEST", "expires_in_seconds": 1800}
            )

            rc = cmd_admin_executor_enroll(client, _args(tmp_path, executor_id="venya-exec-9"))

            out = capsys.readouterr().out
            assert rc == 0
            assert "bot@venya-exec-9:" in out
            assert "VENYA_SERVER_URL=https://test-core.example" in out
            assert "bot@venya-exec-1:" not in out
            assert "venya-core-1" not in out
        finally:
            client.close()
            config_file.unlink()

    def test_ca_missing_omits_var_and_warns(self, tmp_path, monkeypatch, capsys):
        """CA absent -> loud incomplete-bundle warning AND no
        VENYA_VENYA_CA_FILE line referencing a nonexistent file."""
        monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", tmp_path / "absent-ca.crt")
        monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin-ca.crt")
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(
                200, {"enrollment_token": "enrl_exec_TEST", "expires_in_seconds": 1800}
            )

            rc = cmd_admin_executor_enroll(client, _args(tmp_path))

            out = capsys.readouterr().out
            assert rc == 0
            assert "VENYA_VENYA_CA_FILE" not in out
            assert "INCOMPLETE" in out
        finally:
            client.close()
            config_file.unlink()

    def test_ca_present_includes_var(self, tmp_path, monkeypatch, capsys):
        """CA present -> bundle file written byte-identical and the snippet
        carries the VENYA_VENYA_CA_FILE line."""
        fake_ca = tmp_path / "real-ca.crt"
        fake_ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
        monkeypatch.setattr("venya_cli.commands._BUNDLE_CORE_CA", fake_ca)
        monkeypatch.setattr("venya_cli.commands._BUNDLE_ADMIN_CA", tmp_path / "absent-admin-ca.crt")
        client, config_file = _make_client()
        try:
            client._http = MagicMock()
            client._http.request.return_value = _make_response(
                200, {"enrollment_token": "enrl_exec_TEST", "expires_in_seconds": 1800}
            )

            rc = cmd_admin_executor_enroll(client, _args(tmp_path))

            out = capsys.readouterr().out
            bundle = Path(_args(tmp_path).output_dir)
            assert rc == 0
            assert (bundle / "core-server-ca.crt").read_bytes() == fake_ca.read_bytes()
            assert f"VENYA_VENYA_CA_FILE={bundle / 'core-server-ca.crt'}" in out
        finally:
            client.close()
            config_file.unlink()
