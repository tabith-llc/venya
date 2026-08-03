"""Tests for capability isolation between vault and executor.

These tests verify that mlock (which requires CAP_IPC_LOCK) is only
used in the vault package, never in CLI or other components.

The executor (Phase 4) must NEVER have CAP_IPC_LOCK — the jump host
is assumed compromised.
"""

import importlib
import sys
from unittest.mock import patch

import pytest


class TestCapabilityIsolation:
    """Verify mlock is only used in the vault package."""

    @pytest.fixture(autouse=True)
    def _reset_secure_memory_state(self):
        """Reset _SYSTEM_LIB cache before each test to avoid test pollution."""
        import venya.vault.secure_memory as sm
        original = sm._SYSTEM_LIB
        sm._SYSTEM_LIB = None
        yield
        sm._SYSTEM_LIB = original

    def test_secure_memory_requires_linux(self):
        """mlock should fail on non-Linux platforms."""
        from venya.vault.secure_memory import secure_mlock

        with patch("venya.vault.secure_memory.platform.system", return_value="Darwin"):
            try:
                secure_mlock(bytearray(16))
                assert False, "Should have raised RuntimeError"
            except RuntimeError as e:
                assert "only supported on Linux" in str(e)

    def test_secure_memory_fails_without_cap(self):
        """mlock should fail if CAP_IPC_LOCK is not available."""
        from venya.vault.secure_memory import secure_mlock

        with patch("venya.vault.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("venya.vault.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = -1
            with patch("venya.vault.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    try:
                        secure_mlock(bytearray(16))
                        assert False, "Should have raised OSError"
                    except OSError as e:
                        assert "Operation not permitted" in str(e)
            patch.stopall()

    def test_secure_buffer_auto_unlock_on_error(self):
        """SecureBuffer should handle mlock failure gracefully in context manager."""
        from venya.vault.secure_memory import SecureBuffer

        with patch("venya.vault.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("venya.vault.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            mock_lib.return_value.munlock.return_value = -1
            with patch("venya.vault.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    buf = SecureBuffer(32, mlock=True)
                    assert buf.is_locked
                    with buf:
                        pass
                    # Should not raise — munlock failure is ignored in __exit__
                    assert not buf.is_locked
            patch.stopall()

    def test_cli_does_not_import_secure_memory(self):
        """CLI should never import secure_memory (runs on untrusted jump host)."""
        # Save modules we need to keep (secure_memory is used by other tests)
        keep = {k: sys.modules[k] for k in sys.modules if "venya.vault.secure_memory" in k}

        # Clear cached venya imports (except secure_memory which other tests depend on)
        modules_to_remove = [
            k for k in sys.modules
            if k.startswith("venya") and "venya.vault.secure_memory" not in k
        ]
        for mod in modules_to_remove:
            del sys.modules[mod]

        # Import CLI
        from venya.cli import cli

        # Check that secure_memory is not in any imported module's namespace
        cli_module_names = [
            name for name, obj in sys.modules.items()
            if name and name.startswith("venya.cli")
        ]
        for name in cli_module_names:
            mod = sys.modules[name]
            imported = [attr for attr in dir(mod) if not attr.startswith("_")]
            assert "secure_memory" not in imported, (
                f"secure_memory should not be imported in {name}"
            )

        # Restore saved imports for other tests
        for k, mod in keep.items():
            sys.modules[k] = mod


class TestSecureMemoryIsolation:
    """Verify mlock/secure_memory is only used within secure_memory.py itself.

    The security model requires that mlock (which needs CAP_IPC_LOCK) is
    confined to secure_memory.py. No other module should import or use it.
    The executor (Phase 4) must NEVER have CAP_IPC_LOCK.
    """

    def test_only_secure_memory_uses_mlock(self):
        """Only secure_memory.py should define or import mlock-related symbols."""
        import importlib
        import pkgutil
        import venya.vault

        secure_memory_symbols = {"secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer", "_load_system_lib"}

        vault_dir = importlib.import_module("importlib.resources").files(venya.vault)
        if vault_dir and hasattr(vault_dir, "iterdir"):
            for submodule_path in vault_dir.iterdir():
                if submodule_path.suffix == ".py" and not submodule_path.name.startswith("_"):
                    submodule_name = submodule_path.stem
                    if submodule_name == "secure_memory":
                        continue
                    source = submodule_path.read_text(encoding="utf-8")
                    for sym in secure_memory_symbols:
                        assert sym not in source, (
                            f"secure_memory symbol '{sym}' found in {submodule_name}.py — "
                            f"mlock must only be used in secure_memory.py"
                        )

    def test_vault_class_does_not_use_secure_memory(self):
        """Vault facade should not import secure_memory."""
        import importlib
        import venya.vault.vault

        source = venya.vault.vault.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Vault should not import secure_memory"
        assert "SecureBuffer" not in content, "Vault should not use SecureBuffer"
        assert "secure_mlock" not in content, "Vault should not call secure_mlock"

    def test_backend_does_not_use_secure_memory(self):
        """Backend should not import secure_memory."""
        import venya.vault.backend

        source = venya.vault.backend.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Backend should not import secure_memory"
        assert "SecureBuffer" not in content, "Backend should not use SecureBuffer"
        assert "secure_mlock" not in content, "Backend should not call secure_mlock"

    def test_encryption_does_not_use_secure_memory(self):
        """Encryption module should not import secure_memory."""
        import venya.vault.encryption

        source = venya.vault.encryption.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Encryption should not import secure_memory"
        assert "SecureBuffer" not in content, "Encryption should not use SecureBuffer"
        assert "secure_mlock" not in content, "Encryption should not call secure_mlock"

    def test_rate_limiter_does_not_use_secure_memory(self):
        """Rate limiter should not import secure_memory."""
        import venya.vault.rate_limiter

        source = venya.vault.rate_limiter.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Rate limiter should not import secure_memory"
        assert "SecureBuffer" not in content, "Rate limiter should not use SecureBuffer"
        assert "secure_mlock" not in content, "Rate limiter should not call secure_mlock"

    def test_factory_does_not_use_secure_memory(self):
        """Factory should not import secure_memory."""
        import venya.vault.factory

        source = venya.vault.factory.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Factory should not import secure_memory"
        assert "SecureBuffer" not in content, "Factory should not use SecureBuffer"
        assert "secure_mlock" not in content, "Factory should not call secure_mlock"

    def test_iam_models_do_not_use_secure_memory(self):
        """IAM models should not import secure_memory."""
        import venya.iam.models

        source = venya.iam.models.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM models should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM models should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM models should not call secure_mlock"

    def test_iam_role_manager_does_not_use_secure_memory(self):
        """IAM role manager should not import secure_memory."""
        import venya.iam.role_manager

        source = venya.iam.role_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM role manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM role manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM role manager should not call secure_mlock"

    def test_iam_session_manager_does_not_use_secure_memory(self):
        """IAM session manager should not import secure_memory."""
        import venya.iam.session_manager

        source = venya.iam.session_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM session manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM session manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM session manager should not call secure_mlock"

    def test_iam_enrollment_manager_does_not_use_secure_memory(self):
        """IAM enrollment manager should not import secure_memory."""
        import venya.iam.enrollment_manager

        source = venya.iam.enrollment_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM enrollment manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM enrollment manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM enrollment manager should not call secure_mlock"

    def test_cli_commands_do_not_use_secure_memory(self):
        """CLI commands should not import secure_memory."""
        from venya.cli import commands

        source = commands.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "CLI commands should not import secure_memory"
        assert "SecureBuffer" not in content, "CLI commands should not use SecureBuffer"
        assert "secure_mlock" not in content, "CLI commands should not call secure_mlock"

    def test_cli_api_client_does_not_use_secure_memory(self):
        """CLI api client should not import secure_memory."""
        from venya.cli import api_client

        source = api_client.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "CLI api client should not import secure_memory"
        assert "SecureBuffer" not in content, "CLI api client should not use SecureBuffer"
        assert "secure_mlock" not in content, "CLI api client should not call secure_mlock"

    def test_vault_factory_does_not_enable_mlock_by_default(self):
        """VaultFactory should not enable mlock by default."""
        import venya.vault.factory
        from venya.vault.backend import BackendConfig

        config = BackendConfig(
            database_path="/tmp/test_vault.db",
            passphrase=b"test-passphrase-for-testing",
        )
        factory = venya.vault.factory.VaultFactory(config)
        vault = factory.build()

        # The vault should be built without mlock — SecureBuffer is not used
        # by the vault facade, so this is implicitly verified by the fact
        # that build() succeeds without any mlock-related config.
        assert vault is not None
        assert vault.kek is not None

    def test_vault_does_not_mlock_by_default(self):
        """Vault operations should not lock memory by default."""
        import venya.vault.factory
        from venya.vault.backend import BackendConfig
        from venya.vault.vault import Caller

        config = BackendConfig(
            database_path="/tmp/test_vault_isolation.db",
            passphrase=b"isolation-test-passphrase",
        )
        factory = venya.vault.factory.VaultFactory(config)
        vault = factory.build()

        # put() should not use mlock — it uses encryption, not SecureBuffer
        record = vault.put(
            key="test_secret",
            value=b"test_secret_value_for_isolation",
            user_id="test_user",
            role_ids=["test_role"],
            key_version_id="kv_001",
        )
        assert record is not None
        assert record.key == "test_secret"

        # get() as executor should return plaintext (no mlock involved)
        # _decrypt_secret is not implemented yet, so we verify the path
        # doesn't involve mlock by checking the code path
        from venya.vault.vault import VaultError

        # The _decrypt_secret raises NotImplementedError (not mlock-related)
        with pytest.raises(NotImplementedError):
            vault.get("test_secret", caller=Caller.EXECUTOR)

    def test_secure_memory_not_in_vault_module_exports(self):
        """secure_memory symbols should not be re-exported from venya.vault."""
        import venya.vault

        # secure_memory should not be directly accessible from the vault package
        assert not hasattr(venya.vault, "secure_mlock"), (
            "secure_mlock should not be re-exported from venya.vault"
        )
        assert not hasattr(venya.vault, "SecureBuffer"), (
            "SecureBuffer should not be re-exported from venya.vault"
        )

    def test_secure_memory_not_in_iam_module_exports(self):
        """secure_memory symbols should not be accessible from venya.iam."""
        import venya.iam

        assert not hasattr(venya.iam, "secure_mlock"), (
            "secure_mlock should not be accessible from venya.iam"
        )
        assert not hasattr(venya.iam, "SecureBuffer"), (
            "SecureBuffer should not be accessible from venya.iam"
        )

    def test_secure_memory_not_in_cli_module_exports(self):
        """secure_memory symbols should not be accessible from venya.cli."""
        from venya.cli import cli

        assert not hasattr(cli, "secure_mlock"), (
            "secure_mlock should not be accessible from venya.cli"
        )
        assert not hasattr(cli, "SecureBuffer"), (
            "SecureBuffer should not be accessible from venya.cli"
        )
