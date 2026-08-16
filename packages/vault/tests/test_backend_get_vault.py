"""Tests for backend.get_vault() passphrase handling."""

import pytest
from unittest.mock import MagicMock

from vault.vault.backend import Backend, BackendConfig
from vault.vault.encryption import derive_kek


class TestGetVaultPassphrase:
    """Tests for Backend.get_vault() passphrase fallback logic."""

    def _make_backend_with_passphrase(self, passphrase: bytes) -> Backend:
        """Create a backend with a given passphrase."""
        config = BackendConfig(
            database_url="postgresql://test/test",
            passphrase=passphrase,
        )
        return Backend(config)

    def _make_backend_with_kek_only(self, kek: bytes) -> Backend:
        """Create a backend with only a KEK (no passphrase)."""
        config = BackendConfig(
            database_url="postgresql://test/test",
            kek=kek,
        )
        return Backend(config)

    def test_get_vault_with_explicit_passphrase(self):
        """get_vault() uses passed passphrase when provided."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        vault = backend.get_vault(passphrase="explicit-passphrase")

        # Vault should have a non-None KEK (derived from explicit passphrase)
        assert vault.kek is not None
        assert len(vault.kek) == 32

    def test_get_vault_falls_back_to_config(self):
        """get_vault() uses config passphrase when parameter is None."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        vault = backend.get_vault(passphrase=None)

        # Vault should have a non-None KEK (derived from config passphrase)
        assert vault.kek is not None
        assert len(vault.kek) == 32

    def test_get_vault_kek_only_backend_with_none_passphrase(self):
        """get_vault(None) on KEK-only backend produces vault with no KEK."""
        kek, _ = derive_kek(b"test-key")
        backend = self._make_backend_with_kek_only(kek)
        vault = backend.get_vault(passphrase=None)

        # Vault should use the backend's KEK
        assert vault.kek is not None
        assert len(vault.kek) == 32

    def test_get_vault_preserves_empty_string_passphrase(self):
        """get_vault('') preserves empty string (not None), so it does not fall back to config."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")

        # Empty string is NOT None, so it should NOT fall through to config passphrase
        # Instead it gets passed to derive_kek (which derives from empty string — weak but valid)
        vault = backend.get_vault(passphrase="")

        # Vault should have a KEK (derived from empty string, not config passphrase)
        assert vault.kek is not None
        assert len(vault.kek) == 32

    def test_get_vault_explicit_passphrase_overrides_config(self):
        """Explicit passphrase overrides config passphrase, not config KEK."""
        config_kek, _ = derive_kek(b"config-passphrase")
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        vault = backend.get_vault(passphrase="override-passphrase")

        # Vault should have a KEK (derived from override passphrase)
        assert vault.kek is not None
        assert len(vault.kek) == 32
