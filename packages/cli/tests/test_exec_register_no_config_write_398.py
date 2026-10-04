# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#398: one-shot --core-url must not persist config.json.

The run_command chokepoint (commands.py) passes the flag/env URL through the
APIClient constructor, which routed it through the persisting
Config.server_url setter — so `venya exec register --core-url ...` on a
config-less host created config.json as a side effect. Pinned here: register
with --core-url over a fresh empty config dir proceeds AND leaves no config
file behind; the explicit setter (setup / config set server_url) still
persists (paired positive).
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

from venya_cli.api_client import APIClient


def _register_result():
    return {
        "cert_pem": "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
        "ca_cert_pem": "",
        "serial_number": "01:23:45",
        "not_after": "2026-09-13T00:00:00+00:00",
    }


class TestExecRegisterNoConfigWrite:
    def test_register_core_url_writes_no_config(self, tmp_path):
        """NEW (RED before fix: config.json created): register proceeds with
        the flag URL in-memory and the config dir stays empty."""
        from venya_cli.commands import executor_register

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "config.json"
        client = APIClient(server_url="https://core.example.com", config_file=config_file)
        args = SimpleNamespace(
            executor_id="test-exec",
            core_url="https://core.example.com",
            output_dir=str(tmp_path / "certs"),
            enrollment_token=None,
            ca_bundle=None,
        )

        try:
            with (
                patch.object(client, "register_executor", return_value=_register_result()),
                patch("venya_cli.commands._verify_register_auth"),
            ):
                rc = executor_register(client, args)
            assert rc == 0
            assert (tmp_path / "certs" / "executor.crt").exists()
            assert not config_file.exists()
            assert list(config_dir.iterdir()) == []
            assert client.config.server_url == "https://core.example.com"
        finally:
            client.close()

    def test_explicit_setter_still_persists(self, tmp_path):
        """Paired positive: the explicit setter (venya config set server_url /
        setup path) keeps persisting to config.json."""
        config_file = tmp_path / "config.json"
        client = APIClient(config_file=config_file)
        try:
            client.config.server_url = "https://core.example.com"
            data = json.loads(config_file.read_text())
            assert data["server_url"] == "https://core.example.com"
        finally:
            client.close()
