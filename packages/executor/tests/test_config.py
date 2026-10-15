# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor configuration loading and serialization."""

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from executor.config import (
    AuditForwarderConfig,
    CertificateRotationConfig,
    CommandValidatorConfig,
    ExecutorConfig,
    MtlsConfig,
    NetworkConfig,
    ReaperConfig,
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

    def test_default_rotate_before_days(self):
        cfg = CertificateRotationConfig()
        assert cfg.rotate_before_days == 3

    def test_dead_knobs_removed(self):
        """Ticket executor-dead-rotation-config: fields nobody read must not
        come back — validity is a server constant, poll cadence is the main loop."""
        cfg = CertificateRotationConfig()
        assert not hasattr(cfg, "rotation_days")
        assert not hasattr(cfg, "revocation_poll_seconds")

    def test_legacy_toml_with_removed_keys_still_loads(self, tmp_path):
        """Deployed executor.toml files may still carry the removed keys —
        they must load (ignored), not fail (negative half of the removal)."""
        from executor.config import ExecutorConfig

        toml_path = tmp_path / "executor.toml"
        toml_path.write_text(
            "[cert_rotation]\nrotation_days = 45\nrevocation_poll_seconds = 120\nrotate_before_days = 5\n"
        )
        cfg = ExecutorConfig.from_file(toml_path)
        assert cfg.cert_rotation.rotate_before_days == 5
        assert not hasattr(cfg.cert_rotation, "rotation_days")


class TestConcurrencyKnob:
    """RF-3 admission knob: `[executor] max_concurrent_commands` / env
    `VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS` — both spellings the owner pinned,
    one truth, shipped default 1.

    These cells are the pin for the resolver behaviour measured on the shipped
    interpreter (3.14.6) before writing the field: the double-underscore env
    form only lands because `ExecutorConfig.executor` carries
    `AliasChoices("executor", "VENYA_EXECUTOR")`, and the `[executor]` table only
    lands because the FIELD is named `executor` (save_file dumps field names).
    Renaming either spelling's hook silently drops the value back to 1 — which is
    the failure class these cells exist to catch, so several of them are negative
    on purpose.
    """

    ENV_PINNED = "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS"

    def test_default_is_one(self, monkeypatch):
        """Unset means today's posture: one command at a time."""
        monkeypatch.delenv(self.ENV_PINNED, raising=False)
        assert ExecutorConfig().executor.max_concurrent_commands == 1

    def test_env_spelling_resolves(self, monkeypatch):
        monkeypatch.setenv(self.ENV_PINNED, "7")
        assert ExecutorConfig().executor.max_concurrent_commands == 7

    def test_toml_section_spelling_resolves(self, tmp_path):
        """`[executor] max_concurrent_commands` — the other pinned literal —
        lands through the same field."""
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text("[executor]\nmax_concurrent_commands = 12\n")
        assert ExecutorConfig.from_file(toml_path).executor.max_concurrent_commands == 12

    def test_file_beats_env_and_that_is_the_house_precedence(self, tmp_path, monkeypatch):
        """One stated precedence, inherited not invented: from_file passes the
        TOML dict as init kwargs, and init beats env for every field on this
        model. Env still beats the default (test_env_spelling_resolves)."""
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text("[executor]\nmax_concurrent_commands = 12\n")
        monkeypatch.setenv(self.ENV_PINNED, "7")
        assert ExecutorConfig.from_file(toml_path).executor.max_concurrent_commands == 12

    def test_save_round_trip_keeps_the_section_name(self, tmp_path):
        """The knob must survive a write-back under the SAME header the owner
        pinned — this is why the field is named `executor`."""
        saved = tmp_path / "executor.toml"
        cfg = ExecutorConfig()
        cfg.executor.max_concurrent_commands = 5
        cfg.save_file(saved)
        text = saved.read_text()
        assert "[executor]" in text
        assert "max_concurrent_commands = 5" in text
        assert ExecutorConfig.from_file(saved).executor.max_concurrent_commands == 5

    def test_no_third_env_spelling_resolves(self, monkeypatch):
        """NEGATIVE half of "one knob, one truth": the two spellings the house
        convention would have produced are ignored, so no lane can configure the
        knob by accident through a form the owner did not pin."""
        monkeypatch.setenv("VENYA_EXECUTOR_MAX_CONCURRENT_COMMANDS", "8")
        assert ExecutorConfig().executor.max_concurrent_commands == 1
        monkeypatch.setenv("VENYA_EXECUTOR_EXECUTOR__MAX_CONCURRENT_COMMANDS", "8")
        assert ExecutorConfig().executor.max_concurrent_commands == 1

    def test_unrelated_section_header_is_ignored_not_read(self, tmp_path):
        """NEGATIVE half of the field-name coupling: a table named after any other
        field must not be picked up. Guards against "any nested table wins"."""
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text("[concurrency]\nmax_concurrent_commands = 9\n")
        assert ExecutorConfig.from_file(toml_path).executor.max_concurrent_commands == 1

    def test_cap_below_one_refuses_at_load(self):
        """A cap of 0 admits nothing, which is a config error, not a paused
        executor. No upper bound is asserted here: the ceiling is the RAM-derived
        RF-3 measurement, never a constant in this file."""
        with pytest.raises(ValidationError, match="at least 1"):
            ExecutorConfig(executor={"max_concurrent_commands": 0})


class TestDeadSessionAndCaptureKnobs620:
    """#620: seven executor keys that bound nothing are gone, and they must stay gone.

    Removal pins in the shape the dead rotation knobs used (`85bfa85`): an absence
    assertion for every removed name, a compat half proving a deployed `executor.toml`
    that still carries the tables loads instead of failing to boot, and the #598 half —
    the removed keys used to be ANNOUNCED as "in use", so the announcement must stop
    naming them while still naming a key that really binds. The live twin (server
    `SessionConfig` -> core `session_manager`) is asserted where it lives, so a later
    leg cannot re-add the dead copy in this package and pass.
    """

    #: Every key #620 removed, by name, whatever section it lived in.
    REMOVED_KEYS = (
        "session_timeout",
        "access_token_ttl",
        "max_session_duration",
        "max_output_bytes",
        "hash_window_size",
        "min_match_length",
        "local_retention_days",
    )

    def test_session_and_output_capture_tables_are_gone(self):
        """AC1: both containing blocks disappear, not just the fields inside them."""
        assert "session" not in ExecutorConfig.model_fields
        assert "output_capture" not in ExecutorConfig.model_fields
        cfg = ExecutorConfig()
        assert not hasattr(cfg, "session")
        assert not hasattr(cfg, "output_capture")

    def test_no_executor_model_binds_a_removed_key(self):
        """The absence pin, scoped to the whole module rather than one class: re-adding
        any of the seven names to any executor config model fails here."""
        import inspect

        import executor.config as config_module

        models = [
            obj
            for obj in vars(config_module).values()
            if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel
        ]
        bound = {name for model in models for name in model.model_fields}
        for key in self.REMOVED_KEYS:
            assert key not in bound, f"{key} is bound again by the executor config model"

    def test_the_dead_section_models_are_gone_not_merely_unhooked(self):
        import executor.config as config_module

        assert not hasattr(config_module, "SessionConfig"), "the dead executor session model is back"
        assert not hasattr(config_module, "OutputCaptureConfig"), "the dead output-capture model is back"

    def test_legacy_toml_with_removed_keys_still_loads(self, tmp_path):
        """Deployed executor.toml files may still carry the removed tables — they must
        load (ignored), not fail (negative half of the removal)."""
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text(
            "[session]\nsession_timeout = 45\naccess_token_ttl = 45\nmax_session_duration = 45\n"
            "[output_capture]\nmax_output_bytes = 45\nhash_window_size = 45\nmin_match_length = 45\n"
            "[audit]\nlocal_retention_days = 45\n"
            "[reaper]\ncheck_interval = 2.5\n"
        )
        cfg = ExecutorConfig.from_file(toml_path)
        assert cfg.reaper.check_interval == 2.5, "a live key in the same file must still land"
        assert not hasattr(cfg, "session")
        assert not hasattr(cfg, "output_capture")
        assert not hasattr(cfg.audit, "local_retention_days")

    def test_removed_session_keys_no_longer_announce_precedence(self, tmp_path, monkeypatch):
        """The false line goes away: file + env both naming a removed key must produce
        no announcement, because nothing reads either value."""
        monkeypatch.setenv("VENYA_EXECUTOR_SESSION__ACCESS_TOKEN_TTL", "45")
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text("[session]\naccess_token_ttl = 900\n")
        cfg = ExecutorConfig.from_file(toml_path)
        notes = cfg.precedence_conflict_notes()
        assert not any("session" in note for note in notes), notes

    def test_a_live_pair_still_announces_after_the_removal(self, tmp_path, monkeypatch):
        """Positive half of the pair above: removing the dead keys must not silence the
        #598 announcement for a key that actually binds."""
        monkeypatch.setenv("VENYA_EXECUTOR_LOG_LEVEL", "debug")
        toml_path = tmp_path / "executor.toml"
        toml_path.write_text('log_level = "warning"\n')
        cfg = ExecutorConfig.from_file(toml_path)
        notes = cfg.precedence_conflict_notes()
        assert len(notes) == 1, f"exactly one conflict expected, got {notes}"
        assert "log_level" in notes[0]

    def test_the_live_session_twin_still_lives_in_the_server_plane(self):
        """AC2's paired negative, stated where a reader can check it: the three session
        names belong to the server model and the core dataclass its builder feeds, and
        no executor file may declare them again. Source-shape pin, labelled as such —
        the server suite's own cells are what prove the twin binds."""
        packages_dir = Path(__file__).resolve().parents[2]
        server_config = (packages_dir / "server/src/server/config.py").read_text()
        assert "class SessionConfig(BaseModel):" in server_config
        for key in ("session_timeout", "access_token_ttl", "max_session_duration"):
            assert f"{key}: int = Field(" in server_config, f"the live twin lost {key}"
        gate = (packages_dir / "server/src/server/session_gate_config.py").read_text()
        assert "from core.iam.session_manager import SessionConfig" in gate
        executor_src = packages_dir / "executor/src/executor"
        offenders = [
            path.name
            for path in sorted(executor_src.glob("*.py"))
            if "class SessionConfig" in path.read_text() or "class OutputCaptureConfig" in path.read_text()
        ]
        assert offenders == [], f"a dead section model reappeared in {offenders}"


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


class TestExecutorConfigEgressKnobs:
    """Loadability of the dns_resolver / egress_allowlist_path knobs
    (ticket executor-dns-resolver-config-inert). Loading was never the broken
    half — the dead readers were — so these are GREEN pre-fix and pin the
    config surface the plumbing test exercises."""

    def test_from_file_loads_egress_knobs(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
dns_resolver = "198.51.100.53"
egress_allowlist_path = "/tmp/venya-t6.txt"
"""
        )

        cfg = ExecutorConfig.from_file(config_file)

        assert cfg.dns_resolver == "198.51.100.53"
        assert cfg.egress_allowlist_path == "/tmp/venya-t6.txt"

    def test_env_overrides_egress_knobs(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTOR_DNS_RESOLVER", "198.51.100.53")
        monkeypatch.setenv("VENYA_EXECUTOR_EGRESS_ALLOWLIST_PATH", "/tmp/venya-t7.txt")
        cfg = ExecutorConfig()
        assert cfg.dns_resolver == "198.51.100.53"
        assert cfg.egress_allowlist_path == "/tmp/venya-t7.txt"


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

    def test_dns_resolver_default_is_none(self):
        """Ruling D1 option (a): no built-in resolver — the daemon refuses
        to start without one (Venya never guesses your network)."""
        cfg = ExecutorConfig()
        assert cfg.dns_resolver is None


class TestExecutorConfigFromEnv:
    """Tests for environment variable loading."""

    @pytest.fixture(autouse=True)
    def env_setup(self, monkeypatch):
        monkeypatch.setenv("VENYA_EXECUTOR_SERVER_URL", "https://prod.example.com")
        monkeypatch.setenv("VENYA_EXECUTOR_EXECUTOR_ID", "jump-host-1")
        monkeypatch.setenv("VENYA_EXECUTOR_LOG_LEVEL", "debug")
        monkeypatch.setenv("VENYA_EXECUTOR_CERT_ROTATION__ROTATE_BEFORE_DAYS", "6")
        monkeypatch.setenv("VENYA_EXECUTOR_REAPER__CHECK_INTERVAL", "10.0")

    def test_env_overrides_defaults(self):
        cfg = ExecutorConfig()
        assert cfg.server_url == "https://prod.example.com"
        assert cfg.executor_id == "jump-host-1"
        assert cfg.log_level == "debug"

    def test_nested_env_vars(self):
        cfg = ExecutorConfig()
        assert cfg.cert_rotation.rotate_before_days == 6
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
            cert_rotation=CertificateRotationConfig(rotate_before_days=9),
            reaper=ReaperConfig(check_interval=2.5, secret_ttl_seconds=120),
        )

        config_file = tmp_path / "saved.toml"
        original.save_file(config_file)

        reloaded = ExecutorConfig.from_file(config_file)
        assert reloaded.server_url == original.server_url
        assert reloaded.executor_id == original.executor_id
        assert reloaded.log_level == original.log_level
        assert reloaded.cert_rotation.rotate_before_days == original.cert_rotation.rotate_before_days
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
            cert_rotation=CertificateRotationConfig(rotate_before_days=1, max_revocation_failures=7),
            audit=AuditForwarderConfig(
                remote_url="https://sink.example.com:6514",
                ca_cert_path=str(ca_file),
                max_buffer_size=5000,
            ),
        )
        cfg.save_file(config_file)

        reloaded = ExecutorConfig.from_file(config_file)
        assert reloaded.cert_rotation.max_revocation_failures == 7
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
