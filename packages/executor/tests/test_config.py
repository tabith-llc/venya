# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor configuration loading and serialization."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from executor.config import (
    AuditForwarderConfig,
    CertificateRotationConfig,
    CommandValidatorConfig,
    ExecutorConfig,
    MtlsConfig,
    NetworkConfig,
    OutputCaptureConfig,
    ReaperConfig,
    SessionConfig,
)


class TestMtlsConfig:
    """Tests for MtlsConfig default values."""

    def test_default_ca_cert(self):
        cfg = MtlsConfig()
        assert cfg.ca_cert == "/etc/venya/executor/ca.crt"

    def test_default_cert(self):
        cfg = MtlsConfig()
        assert cfg.cert == "/etc/venya/executor/executor.crt"

    def test_default_key(self):
        cfg = MtlsConfig()
        assert cfg.key == "/etc/venya/executor/executor.key"

    def test_custom_values(self):
        cfg = MtlsConfig(ca_cert="/custom/ca.crt", cert="/custom/cert.crt", key="/custom/key.key")
        assert cfg.ca_cert == "/custom/ca.crt"
        assert cfg.cert == "/custom/cert.crt"
        assert cfg.key == "/custom/key.key"


class TestCertificateRotationConfig:
    """Tests for CertificateRotationConfig defaults."""

    def test_default_rotation_days(self):
        cfg = CertificateRotationConfig()
        assert cfg.rotation_days == 30

    def test_default_rotate_before_days(self):
        cfg = CertificateRotationConfig()
        assert cfg.rotate_before_days == 3

    def test_default_revocation_poll_seconds(self):
        cfg = CertificateRotationConfig()
        assert cfg.revocation_poll_seconds == 60


class TestSessionConfig:
    """Tests for SessionConfig defaults."""

    def test_default_session_timeout(self):
        cfg = SessionConfig()
        assert cfg.session_timeout == 900

    def test_default_access_token_ttl(self):
        cfg = SessionConfig()
        assert cfg.access_token_ttl == 300

    def test_default_max_session_duration(self):
        cfg = SessionConfig()
        assert cfg.max_session_duration == 14400


class TestOutputCaptureConfig:
    """Tests for OutputCaptureConfig defaults."""

    def test_default_max_output_bytes(self):
        cfg = OutputCaptureConfig()
        assert cfg.max_output_bytes == 262144

    def test_default_hash_window_size(self):
        cfg = OutputCaptureConfig()
        assert cfg.hash_window_size == 20

    def test_default_min_match_length(self):
        cfg = OutputCaptureConfig()
        assert cfg.min_match_length == 8


class TestCommandValidatorConfig:
    """Tests for CommandValidatorConfig defaults."""

    def test_default_preset(self):
        cfg = CommandValidatorConfig()
        assert cfg.preset == "balanced"

    def test_default_allowed_commands(self):
        cfg = CommandValidatorConfig()
        assert cfg.allowed_commands is None

    def test_custom_allowed_commands(self):
        cfg = CommandValidatorConfig(allowed_commands=["/usr/bin/systemctl", "/usr/bin/journalctl"])
        assert cfg.allowed_commands == ["/usr/bin/systemctl", "/usr/bin/journalctl"]


class TestAuditForwarderConfig:
    """Tests for AuditForwarderConfig defaults."""

    def test_default_remote_url(self):
        cfg = AuditForwarderConfig()
        assert cfg.remote_url is None

    def test_default_max_buffer_size(self):
        cfg = AuditForwarderConfig()
        assert cfg.max_buffer_size == 10_000

    def test_default_alert_threshold(self):
        cfg = AuditForwarderConfig()
        assert cfg.alert_threshold == 0.8

    def test_default_retry_base_delay(self):
        cfg = AuditForwarderConfig()
        assert cfg.retry_base_delay == 2.0

    def test_default_retry_max_delay(self):
        cfg = AuditForwarderConfig()
        assert cfg.retry_max_delay == 300.0

    def test_default_request_timeout_seconds(self):
        cfg = AuditForwarderConfig()
        assert cfg.request_timeout_seconds == 10

    def test_custom_request_timeout_seconds(self):
        cfg = AuditForwarderConfig(request_timeout_seconds=30)
        assert cfg.request_timeout_seconds == 30

    def test_default_spool_path(self):
        cfg = AuditForwarderConfig()
        assert cfg.spool_path is None

    def test_default_local_retention_days(self):
        cfg = AuditForwarderConfig()
        assert cfg.local_retention_days == 90


class TestReaperConfig:
    """Tests for ReaperConfig defaults."""

    def test_default_check_interval(self):
        cfg = ReaperConfig()
        assert cfg.check_interval == 5.0

    def test_default_secret_ttl_seconds(self):
        cfg = ReaperConfig()
        assert cfg.secret_ttl_seconds == 300


class TestNetworkConfig:
    """Tests for NetworkConfig default values."""

    def test_default_request_timeout(self):
        cfg = NetworkConfig()
        assert cfg.request_timeout_seconds == 10

    def test_default_registration_timeout(self):
        cfg = NetworkConfig()
        assert cfg.registration_timeout_seconds == 30

    def test_custom_request_timeout(self):
        cfg = NetworkConfig(request_timeout_seconds=15)
        assert cfg.request_timeout_seconds == 15

    def test_custom_registration_timeout(self):
        cfg = NetworkConfig(registration_timeout_seconds=60)
        assert cfg.registration_timeout_seconds == 60

    def test_min_request_timeout(self):
        cfg = NetworkConfig(request_timeout_seconds=1)
        assert cfg.request_timeout_seconds == 1

    def test_min_registration_timeout(self):
        cfg = NetworkConfig(registration_timeout_seconds=5)
        assert cfg.registration_timeout_seconds == 5

    def test_max_request_timeout(self):
        cfg = NetworkConfig(request_timeout_seconds=120)
        assert cfg.request_timeout_seconds == 120

    def test_max_registration_timeout(self):
        cfg = NetworkConfig(registration_timeout_seconds=120)
        assert cfg.registration_timeout_seconds == 120

    def test_request_timeout_below_min_rejected(self):
        with pytest.raises(ValidationError):
            NetworkConfig(request_timeout_seconds=0)

    def test_registration_timeout_below_min_rejected(self):
        with pytest.raises(ValidationError):
            NetworkConfig(registration_timeout_seconds=4)

    def test_request_timeout_above_max_rejected(self):
        with pytest.raises(ValidationError):
            NetworkConfig(request_timeout_seconds=121)

    def test_registration_timeout_above_max_rejected(self):
        with pytest.raises(ValidationError):
            NetworkConfig(registration_timeout_seconds=121)


class TestExecutorConfigNetwork:
    """Tests for ExecutorConfig network config integration."""

    def test_default_network_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.network, NetworkConfig)
        assert cfg.network.request_timeout_seconds == 10
        assert cfg.network.registration_timeout_seconds == 30

    def test_env_overrides_network(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTOR_NETWORK__REQUEST_TIMEOUT_SECONDS", "45")
        monkeypatch.setenv("VENYA_EXECUTOR_NETWORK__REGISTRATION_TIMEOUT_SECONDS", "60")
        cfg = ExecutorConfig()
        assert cfg.network.request_timeout_seconds == 45
        assert cfg.network.registration_timeout_seconds == 60


class TestExecutorConfigDefaults:
    """Tests for ExecutorConfig default values."""

    def test_default_server_url(self):
        cfg = ExecutorConfig()
        assert cfg.server_url == "https://localhost:8080"

    def test_default_executor_id(self):
        cfg = ExecutorConfig()
        assert cfg.executor_id == "default"

    def test_default_log_level(self):
        cfg = ExecutorConfig()
        assert cfg.log_level == "info"

    def test_default_daemonize(self):
        cfg = ExecutorConfig()
        assert cfg.daemonize is False

    def test_default_pid_file(self):
        cfg = ExecutorConfig()
        assert cfg.pid_file == "/var/lib/venya/executor/venya-executor.pid"

    def test_default_mtls_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.mtls, MtlsConfig)

    def test_default_cert_rotation_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.cert_rotation, CertificateRotationConfig)

    def test_default_session_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.session, SessionConfig)

    def test_default_output_capture_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.output_capture, OutputCaptureConfig)

    def test_default_command_validator_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.command_validator, CommandValidatorConfig)

    def test_default_audit_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.audit, AuditForwarderConfig)

    def test_default_reaper_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.reaper, ReaperConfig)

    def test_default_network_config(self):
        cfg = ExecutorConfig()
        assert isinstance(cfg.network, NetworkConfig)


class TestExecutorConfigFromEnv:
    """Tests for environment variable loading."""

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTOR_SERVER_URL", "https://prod.example.com")
        monkeypatch.setenv("VENYA_EXECUTOR_EXECUTOR_ID", "jump-host-1")
        monkeypatch.setenv("VENYA_EXECUTOR_LOG_LEVEL", "debug")
        monkeypatch.setenv("VENYA_EXECUTOR_CERT_ROTATION__ROTATION_DAYS", "60")
        monkeypatch.setenv("VENYA_EXECUTOR_REAPER__CHECK_INTERVAL", "10.0")

    def test_env_overrides_defaults(self):
        cfg = ExecutorConfig()
        assert cfg.server_url == "https://prod.example.com"
        assert cfg.executor_id == "jump-host-1"
        assert cfg.log_level == "debug"

    def test_nested_env_vars(self):
        cfg = ExecutorConfig()
        assert cfg.cert_rotation.rotation_days == 60
        assert cfg.reaper.check_interval == 10.0

    def test_only_some_env_vars(self, monkeypatch):
        # Clear the autouse fixture's executor_id
        monkeypatch.delenv("VENYA_EXECUTOR_EXECUTOR_ID", raising=False)
        monkeypatch.delenv("VENYA_EXECUTOR_LOG_LEVEL", raising=False)
        monkeypatch.delenv("VENYA_EXECUTOR_CERT_ROTATION__ROTATION_DAYS", raising=False)
        monkeypatch.delenv("VENYA_EXECUTOR_REAPER__CHECK_INTERVAL", raising=False)
        monkeypatch.setenv("VENYA_EXECUTOR_SERVER_URL", "https://staging.example.com")
        cfg = ExecutorConfig()
        assert cfg.server_url == "https://staging.example.com"
        # Other defaults unchanged
        assert cfg.executor_id == "default"
        assert cfg.log_level == "info"


class TestExecutorConfigFromFile:
    """Tests for TOML file loading and saving."""

    def _skip_if_no_tomli_w(self):
        """Skip tests that require tomli_w for writing."""
        try:
            import tomli_w  # noqa: F401
        except ImportError:
            pytest.skip("tomli_w not installed")

    def test_from_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            ExecutorConfig.from_file(str(tmp_path / "nonexistent.toml"))

    def test_from_file_loads_values(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
server_url = "https://core.example.com"
executor_id = "executor-42"
log_level = "warning"

[cert_rotation]
rotation_days = 14
rotate_before_days = 5

[reaper]
check_interval = 1.0
secret_ttl_seconds = 60
"""
        )

        cfg = ExecutorConfig.from_file(config_file)

        assert cfg.server_url == "https://core.example.com"
        assert cfg.executor_id == "executor-42"
        assert cfg.log_level == "warning"
        assert cfg.cert_rotation.rotation_days == 14
        assert cfg.cert_rotation.rotate_before_days == 5
        assert cfg.reaper.check_interval == 1.0
        assert cfg.reaper.secret_ttl_seconds == 60

    def test_from_file_empty(self, tmp_path: Path):
        config_file = tmp_path / "empty.toml"
        config_file.write_text("")

        cfg = ExecutorConfig.from_file(config_file)
        # All defaults
        assert cfg.server_url == "https://localhost:8080"
        assert cfg.executor_id == "default"

    def test_save_and_reload(self, tmp_path: Path):
        self._skip_if_no_tomli_w()
        original = ExecutorConfig(
            server_url="https://test.com",
            executor_id="my-exec",
            log_level="error",
            cert_rotation=CertificateRotationConfig(rotation_days=45),
            reaper=ReaperConfig(check_interval=2.5, secret_ttl_seconds=120),
        )

        config_file = tmp_path / "saved.toml"
        original.save_file(config_file)

        reloaded = ExecutorConfig.from_file(config_file)
        assert reloaded.server_url == original.server_url
        assert reloaded.executor_id == original.executor_id
        assert reloaded.log_level == original.log_level
        assert reloaded.cert_rotation.rotation_days == original.cert_rotation.rotation_days
        assert reloaded.reaper.check_interval == original.reaper.check_interval
        assert reloaded.reaper.secret_ttl_seconds == original.reaper.secret_ttl_seconds

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        self._skip_if_no_tomli_w()
        config_file = tmp_path / "nested" / "deep" / "config.toml"
        cfg = ExecutorConfig()
        cfg.save_file(config_file)
        assert config_file.exists()

    def test_save_produces_valid_toml(self, tmp_path: Path):
        self._skip_if_no_tomli_w()
        config_file = tmp_path / "config.toml"
        cfg = ExecutorConfig(server_url="https://example.com")
        cfg.save_file(config_file)

        content = config_file.read_text()
        assert "server_url" in content
        assert "example.com" in content

    def test_save_serializes_nested_configs(self, tmp_path: Path):
        self._skip_if_no_tomli_w()
        config_file = tmp_path / "config.toml"
        ca_file = tmp_path / "audit-ca.crt"
        ca_file.write_text("dummy-ca")
        cfg = ExecutorConfig(
            cert_rotation=CertificateRotationConfig(rotation_days=7, rotate_before_days=1),
            audit=AuditForwarderConfig(
                remote_url="https://sink.example.com:6514",
                ca_cert_path=str(ca_file),
                max_buffer_size=5000,
            ),
        )
        cfg.save_file(config_file)

        reloaded = ExecutorConfig.from_file(config_file)
        assert reloaded.cert_rotation.rotation_days == 7
        assert reloaded.audit.remote_url == "https://sink.example.com:6514"
        assert reloaded.audit.max_buffer_size == 5000


class TestExecutorConfigModelDump:
    """Tests for configuration serialization."""

    def test_model_dump_json(self):
        cfg = ExecutorConfig(server_url="https://api.com", executor_id="test")
        data = json.loads(cfg.model_dump_json())
        assert data["server_url"] == "https://api.com"
        assert data["executor_id"] == "test"
        assert "mtls" in data
        assert "cert_rotation" in data

    def test_extra_ignored(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTOR_UNKNOWN_FIELD", "should_be_ignored")
        cfg = ExecutorConfig()
        assert not hasattr(cfg, "unknown_field")


class TestAuditForwarderValidation:
    """Fail-closed startup validation of the audit forwarder (truth table).

    Negative cases assert the daemon cannot even construct its config —
    a misconfigured audit sink must stop startup, not degrade silently
    (ticket executor-audit-forwarder-verify-false-fallback).
    """

    def test_unset_remote_url_ok(self):
        cfg = AuditForwarderConfig()
        assert cfg.remote_url is None
        assert cfg.ca_cert_path is None

    def test_https_with_existing_ca_ok(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_text("dummy")
        cfg = AuditForwarderConfig(remote_url="https://sink:6514/audit", ca_cert_path=str(ca))
        assert cfg.ca_cert_path == str(ca)

    def test_https_without_ca_rejected(self):
        with pytest.raises(ValidationError, match="ca_cert_path"):
            AuditForwarderConfig(remote_url="https://sink:6514/audit")

    def test_https_with_absent_ca_file_rejected(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="does not exist"):
            AuditForwarderConfig(remote_url="https://sink:6514/audit", ca_cert_path=str(tmp_path / "nope.crt"))

    def test_http_with_ca_rejected(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_text("dummy")
        with pytest.raises(ValidationError, match="https"):
            AuditForwarderConfig(remote_url="http://sink/audit", ca_cert_path=str(ca))

    def test_tls_scheme_rejected(self, tmp_path: Path):
        ca = tmp_path / "ca.crt"
        ca.write_text("dummy")
        with pytest.raises(ValidationError, match="https"):
            AuditForwarderConfig(remote_url="tls://sink:6514", ca_cert_path=str(ca))

    def test_from_file_rejects_misconfig(self, tmp_path: Path):
        """Startup negative through the real TOML load path."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('[audit]\nremote_url = "https://sink:6514/audit"\n')
        with pytest.raises(ValidationError, match="ca_cert_path"):
            ExecutorConfig.from_file(config_file)

    def test_env_rejects_misconfig(self, monkeypatch):
        """Startup negative through the real env load path."""
        monkeypatch.setenv("VENYA_EXECUTOR_AUDIT__REMOTE_URL", "https://sink:6514/audit")
        monkeypatch.delenv("VENYA_EXECUTOR_AUDIT__CA_CERT_PATH", raising=False)
        with pytest.raises(ValidationError, match="ca_cert_path"):
            ExecutorConfig()
