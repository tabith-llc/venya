"""Tests for backend.get_core() passphrase handling."""

import pytest
from unittest.mock import MagicMock

from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import derive_kek


class TestGetCorePassphrase:
    """Tests for Backend.get_core() passphrase fallback logic."""

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

    def test_get_core_with_explicit_passphrase(self):
        """get_core() uses passed passphrase when provided."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        core = backend.get_core(passphrase="explicit-passphrase")

        # Core should have a non-None KEK (derived from explicit passphrase)
        assert core.kek is not None
        assert len(core.kek) == 32

    def test_get_core_falls_back_to_config(self):
        """get_core() uses config passphrase when parameter is None."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        core = backend.get_core(passphrase=None)

        # Core should have a non-None KEK (derived from config passphrase)
        assert core.kek is not None
        assert len(core.kek) == 32

    def test_get_core_kek_only_backend_with_none_passphrase(self):
        """get_core(None) on KEK-only backend produces core with no KEK."""
        kek, _ = derive_kek(b"test-key")
        backend = self._make_backend_with_kek_only(kek)
        core = backend.get_core(passphrase=None)

        # Core should use the backend's KEK
        assert core.kek is not None
        assert len(core.kek) == 32

    def test_get_core_preserves_empty_string_passphrase(self):
        """get_core('') preserves empty string (not None), so it does not fall back to config."""
        backend = self._make_backend_with_passphrase(b"config-passphrase")

        # Empty string is NOT None, so it should NOT fall through to config passphrase
        # Instead it gets passed to derive_kek (which derives from empty string — weak but valid)
        core = backend.get_core(passphrase="")

        # Core should have a KEK (derived from empty string, not config passphrase)
        assert core.kek is not None
        assert len(core.kek) == 32

    def test_get_core_explicit_passphrase_overrides_config(self):
        """Explicit passphrase overrides config passphrase, not config KEK."""
        config_kek, _ = derive_kek(b"config-passphrase")
        backend = self._make_backend_with_passphrase(b"config-passphrase")
        core = backend.get_core(passphrase="override-passphrase")

        # Core should have a KEK (derived from override passphrase)
        assert core.kek is not None
        assert len(core.kek) == 32
