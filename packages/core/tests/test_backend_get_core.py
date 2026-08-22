"""Tests for backend.get_core() passphrase handling.

get_core() resolves the KEK via bootstrap_kek() (persisted salt, C-11). These
tests pin the *passphrase-selection* logic (explicit overrides config, fallback
to config, empty-string passes through, raw-KEK bypass) by mocking the salt
lookup to a fixed value so derivation is deterministic. Salt persistence itself
is covered by test_kek_salt.py.
"""

from unittest.mock import MagicMock

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import derive_kek

FIXED_SALT = b"\x11" * 16


def _backend_with_mock_salt(config: BackendConfig, salt: bytes = FIXED_SALT) -> Backend:
    """Build a backend whose salt lookup returns a fixed salt (no real DB)."""
    backend = Backend(config)
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = MagicMock(value=salt)
    backend.get_session = lambda: mock_session
    return backend


class TestGetCorePassphrase:
    """Tests for Backend.get_core() passphrase selection logic."""

    def _config_with_passphrase(self, passphrase: bytes) -> BackendConfig:
        return BackendConfig(database_url="postgresql://test/test", passphrase=passphrase)

    def _config_with_kek_only(self, kek: bytes) -> BackendConfig:
        return BackendConfig(database_url="postgresql://test/test", kek=kek)

    def test_get_core_with_explicit_passphrase(self):
        """get_core() uses the passed explicit passphrase for derivation."""
        backend = _backend_with_mock_salt(self._config_with_passphrase(b"config-passphrase"))
        core = backend.get_core(passphrase="explicit-passphrase")

        expected, _ = derive_kek(b"explicit-passphrase", FIXED_SALT)
        assert core.kek == expected

    def test_get_core_falls_back_to_config(self):
        """get_core(None) derives from the config passphrase."""
        backend = _backend_with_mock_salt(self._config_with_passphrase(b"config-passphrase"))
        core = backend.get_core(passphrase=None)

        expected, _ = derive_kek(b"config-passphrase", FIXED_SALT)
        assert core.kek == expected

    def test_get_core_kek_only_backend_with_none_passphrase(self):
        """get_core(None) on a raw-KEK backend uses that KEK without touching the DB."""
        backend = Backend(self._config_with_kek_only(b"\xaa" * 32))
        backend.get_session = lambda: pytest.fail("get_session must not be called for raw-KEK backends")
        core = backend.get_core(passphrase=None)

        assert core.kek == b"\xaa" * 32

    def test_get_core_preserves_empty_string_passphrase(self):
        """get_core('') passes the empty string through to derivation (not config fallback)."""
        backend = _backend_with_mock_salt(self._config_with_passphrase(b"config-passphrase"))
        core = backend.get_core(passphrase="")

        expected, _ = derive_kek(b"", FIXED_SALT)
        assert core.kek == expected

    def test_get_core_explicit_passphrase_overrides_config(self):
        """Explicit passphrase overrides the config passphrase."""
        backend = _backend_with_mock_salt(self._config_with_passphrase(b"config-passphrase"))
        core = backend.get_core(passphrase="override-passphrase")

        expected, _ = derive_kek(b"override-passphrase", FIXED_SALT)
        config_expected, _ = derive_kek(b"config-passphrase", FIXED_SALT)
        assert core.kek == expected
        assert core.kek != config_expected
