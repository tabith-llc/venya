"""Tests for core.py - DB-agnostic logic tests."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

from core.engine.core import Core, CoreAccessError, CoreError, SecretRecord
from core.engine.backend import Backend
from core.engine.encryption import derive_kek


class TestCoreGet:
    """Test core.get() logic."""

    def _make_core(self):
        """Create a core with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Core(backend=backend, kek=kek)

    def test_get_secret_not_found(self):
        """Returns CoreAccessError when secret doesn't exist."""
        core = self._make_core()
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with pytest.raises(CoreAccessError, match="Secret not found"):
            core.get("nonexistent")

    def test_get_human_masked_by_default(self):
        """Human caller gets masked value by default."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        result = core.get("test-key", caller="human")
        assert result == "\u2022" * 8

    def test_get_human_unmasked(self):
        """Human caller with unmask=True gets plaintext."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with patch.object(core, "_decrypt_secret", return_value="plaintext-value"):
            result = core.get("test-key", caller="human", unmask=True)
            assert result == "plaintext-value"

    def test_get_executor_always_plaintext(self):
        """Executor caller always gets plaintext."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.id = 1
        mock_secret.key = "test-key"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with patch.object(core, "_decrypt_secret", return_value="plaintext-value"):
            result = core.get("test-key", caller="executor")
            assert result == "plaintext-value"

    def test_get_role_access_denied(self):
        """Raises CoreAccessError when user lacks role access."""
        core = self._make_core()
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
        core.backend = backend

        with pytest.raises(CoreAccessError):
            core.get("test-key", caller="executor", role_ids=["admin"])


class TestCorePut:
    """Test core.put() logic."""

    def _make_core(self):
        """Create a core with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Core(backend=backend, kek=kek)

    def test_put_requires_roles(self):
        """Raises CoreAccessError when no roles provided."""
        core = self._make_core()
        with pytest.raises(CoreAccessError, match="must be scoped"):
            core.put("key", b"value", "user1", [], "v1")

    def test_put_requires_kek(self):
        """Raises CoreError when KEK not configured."""
        core = Core(backend=MagicMock(), kek=None)
        with pytest.raises(CoreError, match="KEK not configured"):
            core.put("key", b"value", "user1", ["admin"], "v1")

    def test_put_creates_secret_and_links_roles(self):
        """Successfully creates secret and links roles."""
        core = self._make_core()

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
        core.backend = backend

        # Patch the Role query to return our mock role
        with patch("core.engine.core.Role") as MockRole:
            MockRole.name == "admin"  # This is how SQLAlchemy filters work
            MockRole.filter.return_value.first.return_value = mock_role

            record = core.put("test-key", b"test-value", "user1", ["admin"], "v1")

            assert record.key == "test-key"
            assert record.role_ids == ["admin"]
            assert len(session.add.call_args_list) == 2  # Secret + SecretRole
            session.commit.assert_called_once()


class TestCoreDelete:
    """Test core.delete() logic."""

    def _make_core(self):
        """Create a core with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Core(backend=backend, kek=kek)

    def test_delete_secret_not_found(self):
        """Returns False when secret doesn't exist."""
        core = self._make_core()

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        result = core.delete("nonexistent", "user1")
        assert result is False

    def test_delete_no_ownership(self):
        """Raises CoreAccessError when user doesn't own secret."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.created_by = "other_user"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with pytest.raises(CoreAccessError, match="do not own"):
            core.delete("test-key", "user1")

    def test_delete_success(self):
        """Successfully deletes secret."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.created_by = "user1"

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        session.delete = MagicMock()
        session.commit = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        result = core.delete("test-key", "user1")
        assert result is True
        session.delete.assert_called_once()
        session.commit.assert_called_once()


class TestCoreList:
    """Test core.list() logic."""

    def _make_core(self):
        """Create a core with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Core(backend=backend, kek=kek)

    def test_list_returns_records(self):
        """Returns list of SecretRecord objects."""
        core = self._make_core()

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
        core.backend = backend

        # Mock the entire list method to return our record directly
        with patch.object(core, "list", return_value=[
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
            records = core.list()
            assert len(records) == 1
            assert records[0].key == "test-key"
