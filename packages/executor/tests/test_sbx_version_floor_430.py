# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the sbx version floor (ticket sbx-exec-env-file-noop, fix A).

Below 0.39.0, `sbx exec --env-file` is a silent no-op, so the executor must
refuse to boot LOUD instead of running with secrets that never land.
Negative halves of the truth table: below-floor, garbage output, missing CLI
— all three must fail loud.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from executor.daemon import ExecutorDaemon
from executor.strategies.sbx_strategy import (
    SBX_MIN_VERSION,
    SbxVersionError,
    _parse_sbx_version,
    require_supported_sbx,
)


def _completed(stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    return m


class TestRequireSupportedSbx:
    def test_supported_version_returns(self):
        with patch("executor.strategies.sbx_strategy.subprocess.run", return_value=_completed("sbx version 0.46.0\n")):
            out = require_supported_sbx()
        assert "0.46.0" in out

    def test_boundary_version_returns(self):
        """Paired positive at the floor: exactly 0.39.0 is GREEN."""
        with patch("executor.strategies.sbx_strategy.subprocess.run", return_value=_completed("0.39.0")):
            out = require_supported_sbx()
        assert SBX_MIN_VERSION == (0, 39, 0)
        assert "0.39.0" in out

    def test_below_floor_refuses_loud(self):
        with patch("executor.strategies.sbx_strategy.subprocess.run", return_value=_completed("0.38.0")):
            with pytest.raises(SbxVersionError) as exc:
                require_supported_sbx()
        msg = str(exc.value)
        assert "sbx CLI v0.38.0 is below the required 0.39.0" in msg
        assert "secret injection would be silently ignored" in msg
        assert "The site administrator should upgrade the vendor package docker-sbx" in msg
        assert "Venya does not manage vendor packages" in msg
        assert "refs ticket sbx-exec-env-file-noop" in msg

    def test_unparseable_output_refuses(self):
        with patch("executor.strategies.sbx_strategy.subprocess.run", return_value=_completed("nonsense")):
            with pytest.raises(SbxVersionError, match="cannot read sbx version from output"):
                require_supported_sbx()

    def test_missing_cli_refuses(self):
        with patch(
            "executor.strategies.sbx_strategy.subprocess.run",
            side_effect=FileNotFoundError("sbx"),
        ):
            with pytest.raises(SbxVersionError) as exc:
                require_supported_sbx()
        assert "sbx CLI not runnable" in str(exc.value)

    def test_timeout_refuses(self):
        import subprocess

        with patch(
            "executor.strategies.sbx_strategy.subprocess.run",
            side_effect=subprocess.TimeoutExpired("sbx version", 10.0),
        ):
            with pytest.raises(SbxVersionError, match="sbx CLI not runnable"):
                require_supported_sbx()


class TestParseSbxVersion:
    def test_v_prefix_and_trailing_text(self):
        assert _parse_sbx_version("sbx version v0.46.0 (build 7)") == (0, 46, 0)

    def test_garbage_raises(self):
        with pytest.raises(SbxVersionError):
            _parse_sbx_version("")


class TestDaemonStartGuardWiring:
    """daemon.start() refuses boot when the guard raises — named error line
    logged once, one-shot enrollment token never consumed (same position
    contract as TestDeafBootRefusal)."""

    def _config(self, tmp_path):
        from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig

        return ExecutorConfig(
            server_url="https://test-server.local",
            executor_id="test-executor",
            mtls=MtlsConfig(
                ca_cert=str(tmp_path / "ca.crt"),
                cert=str(tmp_path / "executor.crt"),
                key=str(tmp_path / "executor.key"),
            ),
            cert_rotation=CertificateRotationConfig(rotate_before_days=3),
            relay_client_ids=["core-relay"],
            dns_resolver="192.0.2.53",
        )

    def test_boot_refused_and_logged_once(self, tmp_path, caplog):
        refusal = SbxVersionError(
            "sbx CLI v0.38.0 is below the required 0.39.0 — secret injection would be silently ignored."
        )
        d = ExecutorDaemon(self._config(tmp_path))
        d.cert_manager = MagicMock()
        d.reaper = MagicMock()
        with (
            patch("executor.daemon.require_supported_sbx", side_effect=refusal),
            caplog.at_level(logging.ERROR, logger="venya.executor.daemon"),
        ):
            with pytest.raises(SbxVersionError):
                d.start()
        d.cert_manager.register.assert_not_called()
        assert caplog.messages.count(str(refusal)) == 1

    def test_supported_cli_proceeds_to_registration(self, tmp_path):
        """Paired positive: guard green → registration is attempted."""
        d = ExecutorDaemon(self._config(tmp_path))
        d.cert_manager = MagicMock()
        d.reaper = MagicMock()
        sentinel = RuntimeError("past-the-sbx-gate")
        d.cert_manager.register.side_effect = sentinel
        with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
            with pytest.raises(RuntimeError) as exc:
                d.start()
        assert exc.value is sentinel
