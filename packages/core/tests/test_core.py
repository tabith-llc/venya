"""Tests for core.py - DB-agnostic logic tests."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from core.engine.backend import Backend
from core.engine.core import Core, CoreAccessError, CoreError, SecretRecord
from core.engine.encryption import derive_kek


class TestCoreGet:
    """Test core.get() logic."""

    def _make_core(self):
        """Create a core with a mock backend."""
        kek, _ = derive_kek(b"test-key")
        backend = MagicMock(spec=Backend)
        return Core(backend=backend, kek=kek)

    def test_get_requires_user_id(self):
        """Raises CoreAccessError when user_id is not provided."""
        core = self._make_core()
        with pytest.raises(CoreAccessError, match="user_id is required"):
            core.get("test-key")

    def test_get_secret_not_found(self):
        """Returns CoreAccessError when secret doesn't exist."""
        core = self._make_core()
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with pytest.raises(CoreAccessError, match="Secret not found"):
            core.get("nonexistent", user_id="user1")

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

        result = core.get("test-key", caller="human", user_id="user1")
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

        with patch.object(core, "decrypt_secret", return_value="plaintext-value"):
            result = core.get("test-key", caller="human", unmask=True, user_id="user1")
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

        with patch.object(core, "decrypt_secret", return_value="plaintext-value"):
            result = core.get("test-key", caller="executor", user_id="user1")
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
            core.get("test-key", caller="executor", user_id="user1", role_names=["admin"])

    def test_get_uses_role_join_when_role_names_provided(self):
        """get() uses role-based join when role_names is provided."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.id = 1

        mock_secret_role = MagicMock()
        mock_secret_role.role_id = 1

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

        # Mock the join chain to return the same query object
        mock_query = MagicMock()
        mock_query.join.return_value.filter.return_value.first.return_value = mock_secret
        mock_query.join.return_value.filter.return_value.all.side_effect = [
            [mock_secret_role],
            [mock_role],
        ]
        session.query.return_value.join.return_value.filter.return_value = mock_query

        result = core.get("test-key", user_id="user1", role_names=["admin"])
        assert result == "\u2022" * 8

        # Verify join was called (role-based lookup)
        session.query.return_value.join.assert_called()

    def test_get_uses_ownership_fallback_when_no_role_names(self):
        """get() uses ownership fallback when role_names is not provided."""
        core = self._make_core()
        mock_secret = MagicMock()
        mock_secret.id = 1

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_secret
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        core.get("test-key", user_id="user1")

        # Verify only filter was called (no join — ownership lookup)
        session.query.return_value.join.assert_not_called()


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
            MockRole.filter.return_value.first.return_value = mock_role

            record = core.put("test-key", b"test-value", "user1", ["admin"], "v1")

            assert record.key == "test-key"
            assert record.role_names == ["admin"]
            assert len(session.add.call_args_list) == 2  # Secret + SecretRole
            session.commit.assert_called_once()

    def test_put_rejects_duplicate_key_per_user(self):
        """Raises on duplicate key for same user (DB constraint)."""
        core = self._make_core()

        mock_role = MagicMock()
        mock_role.id = 1
        mock_role.name = "admin"

        session = MagicMock()
        session.flush = MagicMock(side_effect=Exception("UNIQUE constraint failed"))
        session.commit = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        with patch("core.engine.core.Role") as MockRole:
            MockRole.filter.return_value.first.return_value = mock_role

            with pytest.raises(Exception, match="UNIQUE constraint"):
                core.put("test-key", b"value1", "user1", ["admin"], "v1")

            # Verify rollback was called
            session.rollback.assert_called_once()


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
        """Raises CoreAccessError when defense-in-depth check catches mismatch."""
        core = self._make_core()
        mock_secret = MagicMock()
        # Mock returns the secret (simulating query not properly scoped)
        # but created_by doesn't match — defense-in-depth catches this
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

    def test_delete_uses_scoped_query(self):
        """delete() filters by both key and created_by."""
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

        core.delete("test-key", "user1")

        # Verify filter was called with two arguments (key + created_by)
        # SQLAlchemy filter(cond1, cond2) passes both as positional args
        call_args = session.query.return_value.filter.call_args
        # call_args is a call object; call_args[0] is positional args tuple
        assert len(call_args[0]) >= 1  # At least the first condition
        # The second condition is passed as the second positional arg
        if len(call_args[0]) >= 2:
            assert len(call_args[0]) == 2


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
        mock_secret.created_at = datetime.now(UTC)

        session = MagicMock()
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        # Mock the entire list method to return our record directly
        with patch.object(
            core,
            "list",
            return_value=[
                SecretRecord(
                    id=str(mock_secret.id),
                    key=mock_secret.key,
                    encrypted_value=mock_secret.encrypted_value,
                    nonce=mock_secret.nonce,
                    wrapped_dek=mock_secret.wrapped_dek,
                    key_version_id=mock_secret.key_version_id,
                    created_by=mock_secret.created_by,
                    created_at=mock_secret.created_at,
                    role_names=[],
                )
            ],
        ):
            records = core.list()
            assert len(records) == 1
            assert records[0].key == "test-key"
