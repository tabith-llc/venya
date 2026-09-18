# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Relay-client mTLS startup validation (ticket refactor-1-config-consolidation
residual, option (a) ruling 2026-09-18).

Without VENYA_MTLS_CERT/VENYA_MTLS_KEY the core cannot present a client cert to
executors: every run_command dies at REQUEST time with a misleading 503 pointing
at the executor's trust store. The check must refuse startup instead, naming the
missing field — unconditional (no debug exemption), before any DB/CA work.

Truth table: unset cert / unset key / missing cert file / missing key file each
raise with the field named; both-present passes; wiring test proves lifespan
invokes it before init_db (no DB needed to observe the refusal).
"""

import pytest
from server.app import _validate_relay_mtls_config, create_app
from server.config import ServerConfig


def _config(**overrides) -> ServerConfig:
    base = {"recovery_code_pepper": "test-pepper"}
    base.update(overrides)
    return ServerConfig(**base)


class TestValidateRelayMtlsConfig:
    def test_unset_cert_fails_naming_the_field(self):
        with pytest.raises(RuntimeError, match="VENYA_MTLS_CERT is not set"):
            _validate_relay_mtls_config(_config())

    def test_unset_key_fails_naming_the_field(self, tmp_path):
        cert = tmp_path / "relay-client.crt"
        cert.write_text("x")
        with pytest.raises(RuntimeError, match="VENYA_MTLS_KEY is not set"):
            _validate_relay_mtls_config(_config(mtls_cert=str(cert)))

    def test_missing_cert_file_fails_naming_path(self, tmp_path):
        with pytest.raises(RuntimeError, match="VENYA_MTLS_CERT points to a missing file"):
            _validate_relay_mtls_config(_config(mtls_cert=str(tmp_path / "nope.crt"), mtls_key=str(tmp_path / "k")))

    def test_missing_key_file_fails_naming_path(self, tmp_path):
        cert = tmp_path / "relay-client.crt"
        cert.write_text("x")
        with pytest.raises(RuntimeError, match="VENYA_MTLS_KEY points to a missing file"):
            _validate_relay_mtls_config(_config(mtls_cert=str(cert), mtls_key=str(tmp_path / "nope.key")))

    def test_both_present_passes(self, tmp_path):
        cert = tmp_path / "relay-client.crt"
        cert.write_text("x")
        key = tmp_path / "relay-client.key"
        key.write_text("x")
        assert _validate_relay_mtls_config(_config(mtls_cert=str(cert), mtls_key=str(key))) is None


class TestLifespanWiring:
    def test_startup_refuses_before_db_init(self):
        """Wiring half: entering the lifespan raises the named error BEFORE any
        DB/CA initialization — a misconfigured core never boots healthy."""
        from fastapi.testclient import TestClient

        app = create_app(_config())
        with pytest.raises(RuntimeError, match="VENYA_MTLS_CERT is not set"):
            with TestClient(app):
                pass
