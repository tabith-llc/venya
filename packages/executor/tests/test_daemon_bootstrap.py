# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor daemon bootstrap registration.

Tests cover:
- BootstrapConfig loading from TOML
- Dual-location bootstrap token: canonical file (RW) + legacy toml (RO grace)
- _clear_bootstrap_token() truth table incl. read-only-config non-fatal ERROR
- TLS verification behavior in CertificateManager.register()
- VENYA_TLS_VERIFY environment variable handling
- Network error handling in CertificateManager.register()
"""

import logging
import os
import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import BootstrapConfig, ExecutorConfig


class TestBootstrapConfig:
    """Tests for BootstrapConfig model."""

    def test_defaults(self):
        """Default values are sensible."""
        config = BootstrapConfig()
        assert config.enrollment_token is None
        assert config.tls_verify is True

    def test_from_dict(self):
        """Can create from dict."""
        config = BootstrapConfig(enrollment_token="enrl_exec_abc", tls_verify=False)
        assert config.enrollment_token == "enrl_exec_abc"
        assert config.tls_verify is False

    def test_bool_parsing(self):
        """Boolean fields parse from strings via pydantic."""
        config = BootstrapConfig.model_validate({"tls_verify": "false"})
        assert config.tls_verify is False

        config = BootstrapConfig.model_validate({"tls_verify": "True"})
        assert config.tls_verify is True

        config = BootstrapConfig.model_validate({"tls_verify": "0"})
        assert config.tls_verify is False


class TestBootstrapTokenDualLocation:
    """Truth table for the dual-location bootstrap token.

    Canonical: /var/lib/venya/executor/bootstrap-token (RW under the hardened
    unit). Legacy: [bootstrap] enrollment_token in executor.toml (RO to the
    daemon — ReadOnlyPaths=/etc/venya). Ticket daemon-bootstrap-token-clear-erofs:
    the legacy clear crashed the daemon (EROFS, uncaught) → crash-loop; the
    file location makes the clear clean and the legacy clear non-fatal-loud.

    Replaces the former TestClearEnrollmentToken logic-replica tests (they
    exercised hand-copied dict surgery, never the daemon method).
    """

    TOML_WITH_TOKEN = """
server_url = "https://venya-core"
executor_id = "test-executor"

[bootstrap]
enrollment_token = "enrl_exec_toml_legacy"
"""

    def _daemon(self, tmp_path: Path, toml_text: str | None = None, toml_token: str | None = None):
        """toml_token models what ExecutorConfig.from_file parses from toml_text
        in production (main() loads the config FROM the file; the legacy
        resolver fallback reads config.bootstrap.enrollment_token)."""
        from executor.daemon import ExecutorDaemon

        config_file = tmp_path / "executor.toml"
        if toml_text is not None:
            config_file.write_text(toml_text)
        config = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            bootstrap=BootstrapConfig(enrollment_token=toml_token),
            config_path=config_file,
            relay_client_ids=["core-relay"],
        )
        daemon = ExecutorDaemon(config)
        daemon._bootstrap_token_path = tmp_path / "bootstrap-token"
        return daemon

    def test_token_file_resolves_and_clear_unlinks(self, tmp_path: Path):
        """Cell 1: canonical file present → resolved; clear unlinks it."""
        daemon = self._daemon(tmp_path)
        daemon._bootstrap_token_path.write_text("enrl_exec_file_canonical\n")

        assert daemon._resolve_bootstrap_token() == "enrl_exec_file_canonical"

        daemon._clear_bootstrap_token()
        assert not daemon._bootstrap_token_path.exists()

    def test_toml_legacy_resolves_and_clear_rewrites(self, tmp_path: Path):
        """Cell 2: legacy toml + writable → resolved; clear removes the section."""
        import tomllib

        daemon = self._daemon(tmp_path, toml_text=self.TOML_WITH_TOKEN, toml_token="enrl_exec_toml_legacy")

        assert daemon._resolve_bootstrap_token() == "enrl_exec_toml_legacy"

        daemon._clear_bootstrap_token()
        with open(tmp_path / "executor.toml", "rb") as f:
            data = tomllib.load(f)
        assert "bootstrap" not in data
        assert data["server_url"] == "https://venya-core"  # rest of config intact

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions; physical cell 2 is authoritative")
    def test_toml_readonly_clear_errors_loudly_and_proceeds(self, tmp_path: Path, caplog):
        """Cell 3 (ruling b, BOTH halves): RO toml → exact actionable ERROR logged AND no raise."""
        daemon = self._daemon(tmp_path, toml_text=self.TOML_WITH_TOKEN, toml_token="enrl_exec_toml_legacy")
        config_file = tmp_path / "executor.toml"
        config_file.chmod(0o444)
        try:
            assert daemon._resolve_bootstrap_token() == "enrl_exec_toml_legacy"

            with caplog.at_level(logging.ERROR):
                daemon._clear_bootstrap_token()  # must NOT raise (crash-loop was the harm)

            assert "remove the [bootstrap] section manually" in caplog.text
            assert "already consumed server-side" in caplog.text
            # section residue remains (documented legacy grace — spent token only)
            assert "[bootstrap]" in config_file.read_text()
        finally:
            config_file.chmod(0o644)

    def test_absent_resolves_none(self, tmp_path: Path):
        """Cell 4: neither location → None (require_token registration path unchanged)."""
        daemon = self._daemon(tmp_path, toml_text='server_url = "https://venya-core"\n')
        assert daemon._resolve_bootstrap_token() is None

    def test_both_locations_file_wins_and_both_cleared(self, tmp_path: Path):
        """Cell 5: file takes precedence; clear removes BOTH residues."""
        import tomllib

        daemon = self._daemon(tmp_path, toml_text=self.TOML_WITH_TOKEN, toml_token="enrl_exec_toml_legacy")
        daemon._bootstrap_token_path.write_text("enrl_exec_file_canonical")

        assert daemon._resolve_bootstrap_token() == "enrl_exec_file_canonical"

        daemon._clear_bootstrap_token()
        assert not daemon._bootstrap_token_path.exists()
        with open(tmp_path / "executor.toml", "rb") as f:
            assert "bootstrap" not in tomllib.load(f)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions; physical cell 2 is authoritative")
    def test_start_clears_exactly_once_with_readonly_toml(self, tmp_path: Path, caplog):
        """Ruling pin: clear runs once at registration — an RO failure never recurs per-loop."""
        daemon = self._daemon(tmp_path, toml_text=self.TOML_WITH_TOKEN, toml_token="enrl_exec_toml_legacy")
        daemon._bootstrap_token_path.write_text("enrl_exec_file_canonical")
        config_file = tmp_path / "executor.toml"
        config_file.chmod(0o444)

        daemon.cert_manager = MagicMock()
        daemon._create_mtls_client = MagicMock(return_value=MagicMock())
        daemon.reaper = MagicMock()
        daemon.relay = MagicMock()
        daemon.relay.active = True
        daemon._write_pidfile = MagicMock()
        daemon._main_loop = MagicMock()
        daemon.stop = MagicMock()

        try:
            with (
                patch("executor.daemon.sweep_workspace_base", return_value=0),
                caplog.at_level(logging.ERROR),
            ):
                daemon.start()  # must complete — no crash, loop entered

            # register got the FILE token (precedence) exactly once
            daemon.cert_manager.register.assert_called_once_with(
                "test-executor", enrollment_token="enrl_exec_file_canonical"
            )
            # legacy RO failure logged exactly once — not per-iteration, never fatal
            ro_errors = [r for r in caplog.records if "remove the [bootstrap] section manually" in r.getMessage()]
            assert len(ro_errors) == 1
            daemon._main_loop.assert_called_once()
            assert not daemon._bootstrap_token_path.exists()  # canonical half cleaned
        finally:
            config_file.chmod(0o644)


class TestDaemonRegistrationTLSVerification:
    """Tests for TLS verification in CertificateManager.register() with throwaway clients."""

    @pytest.fixture(autouse=True)
    def _writable_cert_dirs(self, monkeypatch):
        """These tests mock Path/IO wholesale; stub the register() writability pre-check."""
        monkeypatch.setattr("executor.daemon.os.access", lambda *a, **k: True)

    def test_default_is_verify_true(self, monkeypatch):
        """When VENYA_TLS_VERIFY is not set, verification is enabled."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch(
            "executor.daemon.validate_executor_certificate"
        ), patch(
            "executor.daemon.Path"
        ) as MockPath, patch(
            "executor.daemon.os.chmod"
        ):
            MockPath.return_value.write_bytes = MagicMock()
            MockPath.return_value.exists.return_value = False
            MockPath.return_value.chmod = MagicMock()
            MockPath.return_value.parent = MagicMock()
            MockPath.return_value.mkdir = MagicMock()

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = success_response

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)
            cm.register("test-1")

            MockClient.assert_called_once()
            verify_arg = MockClient.call_args[1]["verify"]
            assert verify_arg is True or isinstance(verify_arg, ssl.SSLContext)

    def test_explicit_true_is_verify_true(self, monkeypatch):
        """VENYA_TLS_VERIFY=true enables verification."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "true")

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch(
            "executor.daemon.validate_executor_certificate"
        ), patch(
            "executor.daemon.Path"
        ) as MockPath, patch(
            "executor.daemon.os.chmod"
        ):
            MockPath.return_value.write_bytes = MagicMock()
            MockPath.return_value.exists.return_value = False
            MockPath.return_value.chmod = MagicMock()
            MockPath.return_value.parent = MagicMock()
            MockPath.return_value.mkdir = MagicMock()

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = success_response

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)
            cm.register("test-1")

            verify_arg = MockClient.call_args[1]["verify"]
            assert verify_arg is True or isinstance(verify_arg, ssl.SSLContext)

    def test_false_disables_verification_with_warning(self, monkeypatch, caplog):
        """VENYA_TLS_VERIFY=false disables verification and logs a warning."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch(
            "executor.daemon.validate_executor_certificate"
        ), patch(
            "executor.daemon.Path"
        ) as MockPath, patch(
            "executor.daemon.os.chmod"
        ), caplog.at_level(
            "WARNING"
        ):
            MockPath.return_value.write_bytes = MagicMock()
            MockPath.return_value.exists.return_value = False
            MockPath.return_value.chmod = MagicMock()
            MockPath.return_value.parent = MagicMock()
            MockPath.return_value.mkdir = MagicMock()

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = success_response

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)
            cm.register("test-1")

            assert MockClient.call_args[1]["verify"] is False
            assert "TLS verification disabled" in caplog.text

    def test_invalid_value_raises_error(self, monkeypatch):
        """VENYA_TLS_VERIFY with invalid value raises RuntimeError."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "maybe")

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"):
            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)

            with pytest.raises(RuntimeError, match="Invalid VENYA_TLS_VERIFY"):
                cm.register("test-1")

            MockClient.assert_not_called()

    def test_no_fallback_on_tls_error_with_verification(self, monkeypatch):
        """Daemon fails securely on TLS error when VENYA_TLS_VERIFY=true."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "true")

        tls_error = httpx2.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch(
            "executor.daemon.validate_executor_certificate"
        ), patch(
            "executor.daemon.Path"
        ) as MockPath, patch(
            "executor.daemon.os.chmod"
        ):
            MockPath.return_value.write_bytes = MagicMock()
            MockPath.return_value.exists.return_value = False
            MockPath.return_value.chmod = MagicMock()
            MockPath.return_value.parent = MagicMock()
            MockPath.return_value.mkdir = MagicMock()

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = tls_error

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)

            with pytest.raises(RuntimeError, match="Registration failed: TLS verification error"):
                cm.register("test-1")

            assert MockClient.call_count == 1
            verify_arg = MockClient.call_args[1]["verify"]
            assert verify_arg is True or isinstance(verify_arg, ssl.SSLContext)
            assert MockClient.call_args[1]["timeout"] == 30.0

    def test_network_error_re_raises_when_verification_disabled(self, monkeypatch):
        """Daemon re-raises ConnectError when VENYA_TLS_VERIFY=false and connection fails."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")

        network_error = httpx2.ConnectError("Connection refused")

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch("executor.daemon.Path") as MockPath:
            MockPath.return_value.exists.return_value = False

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = network_error

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)

            with pytest.raises(RuntimeError, match="cannot reach server"):
                cm.register("test-1")

            verify_arg = MockClient.call_args[1]["verify"]
            assert verify_arg is False
            assert MockClient.call_args[1]["timeout"] == 30.0

    def test_uses_throwaway_not_self_client(self):
        """register() never uses self.client — always creates new httpx2.Client instances."""
        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT",
            "ca_cert_pem": "CA",
            "serial_number": "01",
            "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, patch(
            "executor.daemon._generate_ecdsa_p256_keypair"
        ), patch("executor.daemon._create_csr", return_value=b"CSR"), patch(
            "executor.daemon.validate_executor_certificate"
        ), patch(
            "executor.daemon.Path"
        ) as MockPath, patch(
            "executor.daemon.os.chmod"
        ):
            MockPath.return_value.write_bytes = MagicMock()
            MockPath.return_value.exists.return_value = False
            MockPath.return_value.chmod = MagicMock()
            MockPath.return_value.parent = MagicMock()
            MockPath.return_value.mkdir = MagicMock()

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = success_response

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)
            cm.register("test-1")

            # Verify httpx2.Client was called (throwaway client created)
            MockClient.assert_called_once()
            verify_arg = MockClient.call_args[1]["verify"]
            assert verify_arg is True or isinstance(verify_arg, ssl.SSLContext)
            assert MockClient.call_args[1]["timeout"] == 30.0
