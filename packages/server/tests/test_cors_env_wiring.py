# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket cors-env-wiring-broken.

The installer wrote flat `VENYA_CORS_ORIGINS` into /opt/venya/.env — which
maps to no field (env_nested_delimiter="__", extra="ignore"), so the
operator's CORS setting was silently dropped and servers ran on the
default. Truth table: the nested name must work; the flat name must NOT
(pinning the delimiter contract that was violated).
"""

import pytest
from server.config import ServerConfig

_BASE = {
    "VENYA_DB__DATABASE_URL": "postgresql://t/t",
    "VENYA_RECOVERY_CODE_PEPPER": "p",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("VENYA_CORS__ORIGINS", "VENYA_CORS_ORIGINS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in _BASE.items():
        monkeypatch.setenv(k, v)
    # the real class reads env_file=/opt/venya/.env by default; keep the test
    # hermetic — an absent file is fine for BaseSettings
    yield


class TestCorsEnvWiring:
    def test_nested_json_list_applies(self):
        """Positive: the name the installer now writes is the name the server reads."""
        import os

        os.environ["VENYA_CORS__ORIGINS"] = '["https://core-1"]'
        try:
            config = ServerConfig()
        finally:
            del os.environ["VENYA_CORS__ORIGINS"]
        assert config.cors.origins == ["https://core-1"]

    def test_flat_form_is_ignored(self):
        """Negative: the old installer var must NOT silently satisfy CORS config."""
        import os

        os.environ["VENYA_CORS_ORIGINS"] = '["https://flat"]'
        try:
            config = ServerConfig()
        finally:
            del os.environ["VENYA_CORS_ORIGINS"]
        assert config.cors.origins == ["http://localhost"]  # default, flat ignored

    def test_installer_writes_the_nested_name(self):
        """Source interlock: the installer .env block carries the working name."""
        from pathlib import Path

        installer = (Path(__file__).resolve().parents[3] / "install-venya-core.sh").read_text()
        assert 'VENYA_CORS__ORIGINS=["https://$CORE_HOSTNAME"]' in installer
        assert "VENYA_CORS_ORIGINS=" not in installer.replace("VENYA_CORS__ORIGINS=", "")
