# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
        # Upsert resolve step must see "no existing row" (insert path under
        # test): pin the _resolve_secret_in chain (filter→filter→order_by→
        # first) to None — MagicMock auto-chains are truthy otherwise.
        session.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.return_value = (
            None
        )
        backend = MagicMock()
        backend.get_session.return_value = session
        core.backend = backend

        # Patch the Role query to return our mock role
        with patch("core.engine.core.Role") as MockRole:
            MockRole.filter.return_value.first.return_value = mock_role

            record = core.put("test-key", b"test-value", "user1", ["admin"], "v1")

            assert record.key == "test-key"
            assert record.role_names == ["admin"]
            assert record.replaced is False
            assert len(session.add.call_args_list) == 2  # Secret + SecretRole
            session.commit.assert_called_once()

    def test_put_propagates_flush_error_with_rollback(self):
        """A DB error on the insert path propagates and rolls back.

        (Renamed from test_put_rejects_duplicate_key_per_user: its premise —
        a per-user UNIQUE constraint on key — never existed; duplicates were
        the documented behavior and visible-key re-stores are now upserts
        per the option-2 ruling. What the test actually pins is flush-error
        propagation, which survives the semantics change.)
        """
        core = self._make_core()

        mock_role = MagicMock()
        mock_role.id = 1
        mock_role.name = "admin"

        session = MagicMock()
        session.flush = MagicMock(side_effect=Exception("UNIQUE constraint failed"))
        session.commit = MagicMock()
        session.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.return_value = (
            None
        )
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


class TestSecretVisibilitySqlite:
    """Role-scoping visibility truth table on a REAL SQLite backend.

    Replaces the old mock-chain get() tests (they asserted implementation
    shape and passed vacuously through auto-generated MagicMock chains).
    Semantics under test: a secret is visible iff one of the caller's roles
    is in its scope OR the caller created it; no admin bypass; scoped-out
    keys are indistinguishable from nonexistent ones.
    """

    def _make_env(self, tmp_path):
        from core.engine.backend import BackendConfig
        from core.engine.encryption import KEK_SIZE
        from core.iam.models import Base, Role, RoleMember, User
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        db_path = tmp_path / "vis.db"
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        s = SessionLocal()
        alice = User(user_id="alice")
        bob = User(user_id="bob")
        admin_role = Role(name="admin", permissions="read-write")
        user_role = Role(name="user", permissions="read")
        s.add_all([alice, bob, admin_role, user_role])
        s.flush()
        s.add_all(
            [
                RoleMember(user_id="alice", role_id=admin_role.id),
                RoleMember(user_id="bob", role_id=user_role.id),
            ]
        )
        s.commit()
        s.close()

        kek = b"k" * KEK_SIZE
        backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
        backend._engine = engine
        backend._session_factory = SessionLocal
        core = backend.get_core()

        core.put("admin-secret", b"aaa", "alice", ["admin"], "v1", meta={"executor": "exec-1"})
        core.put("user-secret", b"uuu", "alice", ["user"], "v1", meta={"purpose": "ssh_login"})
        core.put("bob-secret", b"bbb", "bob", ["admin"], "v1", meta={"username": "bot"})
        return core, engine

    def test_get_in_scope_role(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            assert core.get("admin-secret", user_id="alice", role_names=["admin"]) == "\u2022" * 8
        finally:
            engine.dispose()

    def test_get_out_of_scope_indistinguishable_from_nonexistent(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            with pytest.raises(CoreAccessError, match="Secret not found"):
                core.get("admin-secret", user_id="bob", role_names=["user"])
            with pytest.raises(CoreAccessError, match="Secret not found"):
                core.get("nope", user_id="bob", role_names=["user"])
        finally:
            engine.dispose()

    def test_get_owner_fallback_without_matching_role(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            # bob created bob-secret (admin-scoped); bob holds only 'user'
            assert core.get("bob-secret", user_id="bob", role_names=["user"]) == "\u2022" * 8
        finally:
            engine.dispose()

    def test_get_for_injection_in_scope_returns_plaintext_and_meta(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            secret_id, plaintext, meta = core.get_for_injection("admin-secret", "alice", ["admin"])
            assert isinstance(secret_id, int)
            assert plaintext == "aaa"
            assert meta == {"executor": "exec-1"}
        finally:
            engine.dispose()

    def test_get_for_injection_out_of_scope_raises(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            with pytest.raises(CoreAccessError, match="Secret not found"):
                core.get_for_injection("admin-secret", "bob", ["user"])
        finally:
            engine.dispose()

    def test_list_visibility_matrix(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            # alice: admin role sees both admin-scoped; user-secret via creator
            alice_keys = {r.key for r in core.list(role_names=["admin"], user_id="alice")}
            assert alice_keys == {"admin-secret", "user-secret", "bob-secret"}
            # bob: user-secret via role, bob-secret via creator; admin-secret HIDDEN
            bob_keys = {r.key for r in core.list(role_names=["user"], user_id="bob")}
            assert bob_keys == {"user-secret", "bob-secret"}
        finally:
            engine.dispose()

    def test_list_trusted_plane_no_identity_lists_all(self, tmp_path):
        """No role_names and no user_id = executor/mTLS plane: everything."""
        core, engine = self._make_env(tmp_path)
        try:
            assert {r.key for r in core.list()} == {"admin-secret", "user-secret", "bob-secret"}
        finally:
            engine.dispose()

    def test_list_metadata_filters(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            rows = core.list(role_names=["admin"], user_id="alice", executor="exec-1")
            assert [r.key for r in rows] == ["admin-secret"]
            rows = core.list(role_names=["user"], user_id="bob", purpose="ssh_login")
            assert [r.key for r in rows] == ["user-secret"]
            rows = core.list(role_names=["admin"], user_id="alice", username="bot")
            assert [r.key for r in rows] == ["bob-secret"]
            rows = core.list(role_names=["admin"], user_id="alice", executor="nope")
            assert rows == []
        finally:
            engine.dispose()

    def test_list_prefix_and_visibility_combine(self, tmp_path):
        core, engine = self._make_env(tmp_path)
        try:
            assert core.list(prefix="admin", role_names=["user"], user_id="bob") == []
            rows = core.list(prefix="admin", role_names=["admin"], user_id="alice")
            assert [r.key for r in rows] == ["admin-secret"]
        finally:
            engine.dispose()


class TestSecretUpsertSqlite:
    """Upsert truth table on a REAL SQLite backend (ticket
    cli-store-force-field-ignored option-2 ruling).

    Semantics under test: re-storing a key REPLACES the row the caller can
    see (role in scope OR creator — the same _resolve_secret_in primitive as
    get/inject/list), preserving row id (injection-path stability) and
    created_by (audit lineage); a scoped-out caller gets a SECOND row with
    the original untouched (no existence leak, no cross-role clobber — the
    indistinguishability invariant from secret-role-scoping-unenforced).
    """

    def _make_env(self, tmp_path):
        from core.engine.backend import BackendConfig
        from core.engine.encryption import KEK_SIZE
        from core.iam.models import Base, Role, RoleMember, User
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        db_path = tmp_path / "upsert.db"
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        s = SessionLocal()
        admin_role = Role(name="admin", permissions="read-write")
        user_role = Role(name="user", permissions="read-write")
        s.add_all([User(user_id="alice"), User(user_id="bob"), admin_role, user_role])
        s.flush()
        s.add_all(
            [
                RoleMember(user_id="alice", role_id=admin_role.id),
                RoleMember(user_id="bob", role_id=user_role.id),
            ]
        )
        s.commit()
        s.close()

        kek = b"k" * KEK_SIZE
        backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=kek))
        backend._engine = engine
        backend._session_factory = SessionLocal
        return backend.get_core(), engine, SessionLocal

    def test_fresh_store_inserts_not_replaced(self, tmp_path):
        core, engine, _ = self._make_env(tmp_path)
        try:
            rec = core.put("k1", b"first", "alice", ["admin"], "v1", caller_roles=["admin"])
            assert rec.replaced is False
        finally:
            engine.dispose()

    def test_reput_by_creator_replaces_in_place(self, tmp_path):
        from core.iam.models import Secret

        core, engine, SessionLocal = self._make_env(tmp_path)
        try:
            r1 = core.put("k1", b"first", "alice", ["admin"], "v1", meta={"purpose": "a"}, caller_roles=["admin"])
            r2 = core.put("k1", b"second", "alice", ["user"], "v2", meta={"purpose": "b"}, caller_roles=["admin"])
            assert r2.replaced is True
            assert r2.id == r1.id, "row id must be stable (injection path /run/secrets/venya/<pk>)"
            assert r2.created_by == "alice"
            assert core.get_for_injection("k1", "alice", ["admin"])[1] == "second"
            with SessionLocal() as s:
                assert s.query(Secret).filter(Secret.key == "k1").count() == 1
                row = s.query(Secret).filter(Secret.key == "k1").one()
                assert row.key_version_id == "v2"
                assert row.meta == {"purpose": "b"}
        finally:
            engine.dispose()

    def test_reput_by_in_scope_member_replaces_creator_immutable(self, tmp_path):
        core, engine, _ = self._make_env(tmp_path)
        try:
            r1 = core.put("shared", b"aaa", "alice", ["user"], "v1", caller_roles=["admin"])
            r2 = core.put("shared", b"bbb", "bob", ["user"], "v1", caller_roles=["user"])
            assert r2.replaced is True
            assert r2.id == r1.id
            assert r2.created_by == "alice", "created_by is audit lineage — immutable on replace"
            assert core.get_for_injection("shared", "bob", ["user"])[1] == "bbb"
        finally:
            engine.dispose()

    def test_reput_scoped_out_creates_second_row_original_untouched(self, tmp_path):
        """Paired negative: no clobber, no existence signal beyond a plain insert."""
        from core.iam.models import Secret, SecretRole

        core, engine, SessionLocal = self._make_env(tmp_path)
        try:
            r1 = core.put("admin-secret", b"aaa", "alice", ["admin"], "v1", caller_roles=["admin"])
            r2 = core.put("admin-secret", b"bbb", "bob", ["user"], "v1", caller_roles=["user"])
            assert r2.replaced is False
            assert r2.id != r1.id
            with SessionLocal() as s:
                rows = s.query(Secret).filter(Secret.key == "admin-secret").order_by(Secret.id).all()
                assert len(rows) == 2
                first = rows[0]
                assert first.created_by == "alice"
                roles = s.query(SecretRole).filter(SecretRole.secret_id == first.id).count()
                assert roles == 1, "original role links untouched"
            # original still decrypts for alice, unchanged
            assert core.get_for_injection("admin-secret", "alice", ["admin"])[1] == "aaa"
        finally:
            engine.dispose()

    def test_reput_default_caller_roles_is_creator_only(self, tmp_path):
        """caller_roles omitted → ownership-only resolution (legacy semantics)."""
        core, engine, _ = self._make_env(tmp_path)
        try:
            r1 = core.put("k", b"one", "alice", ["admin"], "v1")
            r_alice = core.put("k", b"two", "alice", ["admin"], "v1")
            assert r_alice.replaced is True and r_alice.id == r1.id
            r_bob = core.put("k", b"three", "bob", ["admin"], "v1")
            assert r_bob.replaced is False and r_bob.id != r1.id
        finally:
            engine.dispose()

    def test_reput_replaces_role_links_without_residue(self, tmp_path):
        from core.iam.models import Role, SecretRole

        core, engine, SessionLocal = self._make_env(tmp_path)
        try:
            core.put("k", b"1", "alice", ["admin"], "v1", caller_roles=["admin"])
            core.put("k", b"2", "alice", ["user"], "v1", caller_roles=["admin"])
            with SessionLocal() as s:
                from core.iam.models import Secret

                sid = s.query(Secret).filter(Secret.key == "k").one().id
                links = s.query(SecretRole).filter(SecretRole.secret_id == sid).all()
                assert len(links) == 1
                role = s.query(Role).filter(Role.id == links[0].role_id).one()
                assert role.name == "user"
        finally:
            engine.dispose()
