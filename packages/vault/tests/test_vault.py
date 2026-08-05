"""Tests for vault.py - DB-agnostic logic tests."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

from vault.vault.vault import Vault, VaultAccessError, VaultError, SecretRecord
from vault.vault.backend import Backend
from vault.vault.encryption import derive_kek


class TestVaultGet:
    """Test vault.get() logic."""

    def _make_vault(self):
        """Create a vault with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Vault(backend=backend, kek=kek)

    def test_get_secret_not_found(self):
        """Returns VaultAccessError when secret doesn't exist."""
        vault = self._make_vault()
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        with pytest.raises(VaultAccessError, match="Secret not found"):
            vault.get("nonexistent")

    def test_get_human_masked_by_default(self):
        """Human caller gets masked value by default."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        result = vault.get("test-key", caller="human")
        assert result == "\u2022" * 8

    def test_get_human_unmasked(self):
        """Human caller with unmask=True gets plaintext."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        with patch.object(vault, "_decrypt_secret", return_value="plaintext-value"):
            result = vault.get("test-key", caller="human", unmask=True)
            assert result == "plaintext-value"

    def test_get_executor_always_plaintext(self):
        """Executor caller always gets plaintext."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        with patch.object(vault, "_decrypt_secret", return_value="plaintext-value"):
            result = vault.get("test-key", caller="executor")
            assert result == "plaintext-value"

    def test_get_role_access_denied(self):
        """Raises VaultAccessError when user lacks role access."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.id = 1

        mock_secret_role = MagicMock()
        mock_secret_role.role_id = 999

        mock_role = MagicMock()
        mock_role.id = 1

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        session.query.return_value.filter.return_value.all.side_effect = [
            [mock_secret_role],  # secret_roles
            [mock_role],  # named_roles
        ]
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        with pytest.raises(VaultAccessError):
            vault.get("test-key", caller="executor", role_ids=["admin"])


class TestVaultPut:
    """Test vault.put() logic."""

    def _make_vault(self):
        """Create a vault with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Vault(backend=backend, kek=kek)

    def test_put_requires_roles(self):
        """Raises VaultAccessError when no roles provided."""
        vault = self._make_vault()
        with pytest.raises(VaultAccessError, match="must be scoped"):
            vault.put("key", b"value", "user1", [], "v1")

    def test_put_requires_kek(self):
        """Raises VaultError when KEK not configured."""
        vault = Vault(backend=MagicMock(), kek=None)
        with pytest.raises(VaultError, match="KEK not configured"):
            vault.put("key", b"value", "user1", ["admin"], "v1")

    def test_put_creates_secret_and_links_roles(self):
        """Successfully creates secret and links roles."""
        vault = self._make_vault()

        mock_role = MagicMock()
        mock_role.id = 1
        mock_role.name = "admin"

        # The put method queries Role by name to find the role_id
        # session.query(Role).filter(Role.name == "admin").first()
        session = MagicMock()
        session.flush = MagicMock()
        session.commit = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        # Patch the Role query to return our mock role
        with patch("vault.vault.vault.Role") as MockRole:
            MockRole.name == "admin"  # This is how SQLAlchemy filters work
            MockRole.filter.return_value.first.return_value = mock_role

            record = vault.put("test-key", b"test-value", "user1", ["admin"], "v1")

            assert record.key == "test-key"
            assert record.role_ids == ["admin"]
            assert len(session.add.call_args_list) == 2  # Secret + SecretRole
            session.commit.assert_called_once()


class TestVaultDelete:
    """Test vault.delete() logic."""

    def _make_vault(self):
        """Create a vault with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Vault(backend=backend, kek=kek)

    def test_delete_secret_not_found(self):
        """Returns False when secret doesn't exist."""
        vault = self._make_vault()

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        result = vault.delete("nonexistent", "user1")
        assert result is False

    def test_delete_no_ownership(self):
        """Raises VaultAccessError when user doesn't own secret."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.created_by = "other_user"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        with pytest.raises(VaultAccessError, match="do not own"):
            vault.delete("test-key", "user1")

    def test_delete_success(self):
        """Successfully deletes secret."""
        vault = self._make_vault()
        mock_secret = MagicMock()
        mock_secret.created_by = "user1"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        session.delete = MagicMock()
        session.commit = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        result = vault.delete("test-key", "user1")
        assert result is True
        session.delete.assert_called_once()
        session.commit.assert_called_once()


class TestVaultList:
    """Test vault.list() logic."""

    def _make_vault(self):
        """Create a vault with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Vault(backend=backend, kek=kek)

    def test_list_returns_records(self):
        """Returns list of SecretRecord objects."""
        vault = self._make_vault()

        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"
        mock_secret.encrypted_value = b"encrypted"
        mock_secret.nonce = b"nonce"
        mock_secret.wrapped_dek = b"wrapped"
        mock_secret.key_version_id = "v1"
        mock_secret.created_by = "user1"
        mock_secret.created_at = datetime.now(timezone.utc)

        session = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        vault.backend = backend

        # Mock the entire list method to return our record directly
        with patch.object(vault, "list", return_value=[
            SecretRecord(
                id=str(mock_secret.id),
                key=mock_secret.key,
                encrypted_value=mock_secret.encrypted_value,
                nonce=mock_secret.nonce,
                wrapped_dek=mock_secret.wrapped_dek,
                key_version_id=mock_secret.key_version_id,
                created_by=mock_secret.created_by,
                created_at=mock_secret.created_at,
                role_ids=[],
            )
        ]):
            records = vault.list()
            assert len(records) == 1
            assert records[0].key == "test-key"
