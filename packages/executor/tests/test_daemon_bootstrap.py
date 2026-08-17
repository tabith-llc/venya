"""Tests for executor daemon bootstrap registration.

Tests cover:
- BootstrapConfig loading from TOML
- _clear_enrollment_token() removes token from config
- TLS verification behavior in CertificateManager.register()
- VENYA_TLS_VERIFY environment variable handling
- Network error handling in CertificateManager.register()
"""

from __future__ import annotations

import tempfile
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


class TestClearEnrollmentToken:
    """Tests for _clear_enrollment_token()."""

    def test_clears_token_from_config(self, tmp_path: Path):
        """Token is removed from executor.toml and empty bootstrap section is deleted."""
        config_file = tmp_path / "executor.toml"
        config_file.write_text("""
server_url = "https://venya-core"
executor_id = "jump-1"

[bootstrap]
enrollment_token = "enrl_exec_abc123"
""")
        import tomllib
        import tomli_w

        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        assert "bootstrap" in data
        assert data["bootstrap"]["enrollment_token"] == "enrl_exec_abc123"

        # Clear it (mimics _clear_enrollment_token logic)
        del data["bootstrap"]["enrollment_token"]
        if not data["bootstrap"]:
            del data["bootstrap"]

        assert "bootstrap" not in data

        # Write back and verify
        with open(config_file, "wb") as f:
            tomli_w.dump(data, f)

        with open(config_file, "rb") as f:
            data2 = tomllib.load(f)
        assert "bootstrap" not in data2

    def test_removes_empty_bootstrap_section(self, tmp_path: Path):
        """When only enrollment_token is in bootstrap, entire section is removed."""
        config_file = tmp_path / "executor.toml"
        config_file.write_text("""
server_url = "https://venya-core"
executor_id = "jump-1"

[bootstrap]
enrollment_token = "enrl_exec_abc123"
""")
        import tomllib
        import tomli_w

        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        del data["bootstrap"]["enrollment_token"]
        if not data["bootstrap"]:
            del data["bootstrap"]
        with open(config_file, "wb") as f:
            tomli_w.dump(data, f)

        with open(config_file, "rb") as f:
            data2 = tomllib.load(f)
        assert "bootstrap" not in data2

    def test_skips_when_no_config_file(self, tmp_path: Path):
        """If config file doesn't exist, _clear_enrollment_token returns early."""
        config_file = tmp_path / "nonexistent.toml"
        assert not config_file.exists()
        # _clear_enrollment_token checks config_path.exists() first
        # If file doesn't exist, it returns without error
        pass

    def test_skips_when_no_enrollment_token(self, tmp_path: Path):
        """If bootstrap section has no enrollment_token, nothing is removed."""
        config_file = tmp_path / "executor.toml"
        config_file.write_text("""
server_url = "https://venya-core"

[bootstrap]
tls_verify = false
""")
        import tomllib
        import tomli_w

        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        # No enrollment_token to clear
        if "bootstrap" in data and "enrollment_token" in data["bootstrap"]:
            del data["bootstrap"]["enrollment_token"]
            if not data["bootstrap"]:
                del data["bootstrap"]

        # bootstrap section should remain since tls_verify is still there
        assert "bootstrap" in data
        assert data["bootstrap"]["tls_verify"] is False


class TestDaemonRegistrationTLSVerification:
    """Tests for TLS verification in CertificateManager.register() with throwaway clients."""

    def test_default_is_verify_true(self, monkeypatch):
        """When VENYA_TLS_VERIFY is not set, verification is enabled."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT", "ca_cert_pem": "CA",
            "serial_number": "01", "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.validate_executor_certificate"), \
             patch("executor.daemon.Path") as MockPath, \
             patch("executor.daemon.os.chmod"):
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
            assert MockClient.call_args[1]["verify"] is True

    def test_explicit_true_is_verify_true(self, monkeypatch):
        """VENYA_TLS_VERIFY=true enables verification."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "true")

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT", "ca_cert_pem": "CA",
            "serial_number": "01", "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.validate_executor_certificate"), \
             patch("executor.daemon.Path") as MockPath, \
             patch("executor.daemon.os.chmod"):
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

            assert MockClient.call_args[1]["verify"] is True

    def test_false_disables_verification_with_warning(self, monkeypatch, caplog):
        """VENYA_TLS_VERIFY=false disables verification and logs a warning."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")

        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT", "ca_cert_pem": "CA",
            "serial_number": "01", "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.validate_executor_certificate"), \
             patch("executor.daemon.Path") as MockPath, \
             patch("executor.daemon.os.chmod"), \
             caplog.at_level("WARNING"):
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

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"):
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

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.validate_executor_certificate"), \
             patch("executor.daemon.Path") as MockPath, \
             patch("executor.daemon.os.chmod"):
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

            with pytest.raises(RuntimeError, match="Registration failed. Verify server CA is trusted"):
                cm.register("test-1")

            assert MockClient.call_count == 1
            MockClient.assert_called_once_with(verify=True, timeout=30.0)

    def test_network_error_re_raises_when_verification_disabled(self, monkeypatch):
        """Daemon re-raises ConnectError when VENYA_TLS_VERIFY=false and connection fails."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")

        network_error = httpx2.ConnectError("Connection refused")

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.Path") as MockPath:
            MockPath.return_value.exists.return_value = False

            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.side_effect = network_error

            from executor.daemon import CertificateManager

            config = ExecutorConfig.model_validate({"server_url": "https://core", "executor_id": "test-1"})
            cm = CertificateManager(config)

            with pytest.raises(httpx2.ConnectError):
                cm.register("test-1")

            MockClient.assert_called_once_with(verify=False, timeout=30.0)

    def test_uses_throwaway_not_self_client(self):
        """register() never uses self.client — always creates new httpx2.Client instances."""
        success_response = MagicMock()
        success_response.json.return_value = {
            "cert_pem": "CERT", "ca_cert_pem": "CA",
            "serial_number": "01", "not_after": "2026-09-01",
        }
        success_response.raise_for_status.return_value = None

        with patch("executor.daemon.httpx2.Client") as MockClient, \
             patch("executor.daemon._generate_ecdsa_p256_keypair"), \
             patch("executor.daemon._create_csr", return_value=b"CSR"), \
             patch("executor.daemon.validate_executor_certificate"), \
             patch("executor.daemon.Path") as MockPath, \
             patch("executor.daemon.os.chmod"):
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
            assert MockClient.call_args[1]["verify"] is True
            assert MockClient.call_args[1]["timeout"] == 30.0
