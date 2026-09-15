# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for C-11 KEK salt persistence.

The critical property: the passphrase-derived KEK must be reproducible across
process restarts because the Argon2 salt is persisted and reused. A NO PG
instance is available in the dev env, so a real SQLite database (file-backed)
stands in: the crypto primitives + LargeBinary/Bytea already support it, and
``ensure_kek_salt`` / the metadata work identically on any SQLAlchemy backend.

A fresh engine to the same file simulates a process restart.
"""

import os
from unittest.mock import MagicMock

import pytest
from core.engine.backend import (
    Backend,
    BackendConfig,
    KekSaltMissingError,
    ensure_kek_salt,
)
from core.engine.encryption import (
    ARGON2_SALT_LEN,
    DecryptionError,
    decrypt_secret,
    derive_kek,
    encrypt_secret,
)
from core.iam.models import Base, Secret, VenyaConfig
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker


def _seed_secret(session, salt: bytes, passphrase: bytes = b"master-passphrase") -> dict:
    """Persist one secret under the KEK derived from (passphrase, salt)."""
    kek, _ = derive_kek(passphrase, salt)
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"top-secret-value")
    session.add(
        Secret(
            key="k",
            encrypted_value=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            key_version_id="v1",
            created_by="user1",
        )
    )
    session.commit()
    return {"wrapped_dek": wrapped_dek, "nonce": nonce, "ciphertext": ciphertext}


class TestEnsureKekSalt:
    """The read / generate-on-first-boot / fatal-on-missing state machine."""

    def _engine_and_factory(self, tmp_path, name="kek.db"):
        engine = create_engine(f"sqlite:///{tmp_path / name}")
        Base.metadata.create_all(engine)
        return engine, sessionmaker(bind=engine)

    def test_first_boot_generates_and_persists_salt(self, tmp_path):
        engine, factory = self._engine_and_factory(tmp_path)
        s = factory()
        salt = ensure_kek_salt(s)
        s.close()
        assert len(salt) == ARGON2_SALT_LEN
        # Persisted: a fresh session on the same DB sees the row.
        s2 = factory()
        row = s2.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first()
        s2.close()
        assert row is not None
        assert row.value == salt
        engine.dispose()

    def test_second_boot_reads_same_salt(self, tmp_path):
        engine, factory = self._engine_and_factory(tmp_path)
        s = factory()
        salt1 = ensure_kek_salt(s)
        s.close()
        # "Restart": a brand-new session (simulated new process) reads the same salt.
        s2 = factory()
        salt2 = ensure_kek_salt(s2)
        s2.close()
        assert salt2 == salt1
        engine.dispose()

    def test_missing_salt_without_secrets_is_first_boot(self, tmp_path):
        # Empty DB + no salt -> generate (already covered by test 1, but assert
        # explicitly that no exception is raised).
        engine, factory = self._engine_and_factory(tmp_path)
        s = factory()
        salt = ensure_kek_salt(s)  # must not raise
        s.close()
        assert len(salt) == ARGON2_SALT_LEN
        engine.dispose()

    def test_missing_salt_with_secrets_raises(self, tmp_path):
        engine, factory = self._engine_and_factory(tmp_path)
        # A secret exists, but the salt row was lost/corrupted.
        s = factory()
        _seed_secret(s, salt=os.urandom(ARGON2_SALT_LEN))
        s.close()
        s2 = factory()
        with pytest.raises(KekSaltMissingError):
            ensure_kek_salt(s2)
        s2.close()
        engine.dispose()

    def test_concurrent_first_boot_uses_winner_salt(self, tmp_path):
        # Simulate the race: the salt row is absent when we first look, but a
        # concurrent process inserts it before our flush -> IntegrityError path.
        engine, factory = self._engine_and_factory(tmp_path)
        s = factory()
        winner_salt = b"\x7e" * ARGON2_SALT_LEN
        # Prime a second connection holding the competing salt, uncommitted.
        s_other = factory()
        s_other.add(VenyaConfig(key="kek_salt", value=winner_salt))

        def _flush_side_effect():
            # The concurrent process wins the race just before our INSERT.
            s_other.commit()
            raise IntegrityError("INSERT INTO venya_config", {}, Exception("UNIQUE constraint"))

        # Disable query-triggered autoflush so only the explicit session.flush()
        # inside ensure_kek_salt hits the mock.
        s.autoflush = False
        s.flush = MagicMock(side_effect=_flush_side_effect)
        result = ensure_kek_salt(s)
        assert result == winner_salt
        s.close()
        s_other.close()
        engine.dispose()


class TestBootstrapKek:
    """bootstrap_kek resolves the KEK from the persisted salt and caches it."""

    def _backend_with_mock_session(self, known_salt: bytes, passphrase: bytes = b"pw"):
        config = BackendConfig(database_url="postgresql://x/x", passphrase=passphrase)
        # C-11: passphrase-only config no longer derives a random-salt KEK at init.
        assert config.kek is None
        backend = Backend(config)
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = MagicMock(value=known_salt)
        backend.get_session = lambda: mock_session
        return backend, config

    def test_bootstrap_uses_persisted_salt(self):
        known_salt = b"\x01" * ARGON2_SALT_LEN
        backend, config = self._backend_with_mock_session(known_salt)
        kek = backend.bootstrap_kek()
        expected, _ = derive_kek(b"pw", known_salt)
        assert kek == expected
        # Cached so other consumers (e.g. filter endpoint) share one KEK.
        assert config.kek == expected

    def test_get_core_core_kek_equals_config_kek(self):
        known_salt = b"\x02" * ARGON2_SALT_LEN
        backend, config = self._backend_with_mock_session(known_salt)
        core = backend.get_core(passphrase="pw")
        expected, _ = derive_kek(b"pw", known_salt)
        assert core.kek == expected
        assert core.kek == config.kek

    def test_bootstrap_kek_only_backend_no_db(self):
        # A raw-KEK backend (with_kek path) must not touch the DB for the salt.
        config = BackendConfig(database_url="postgresql://x/x", kek=b"\xab" * 32)
        backend = Backend(config)
        backend.get_session = lambda: pytest.fail("get_session must not be called")
        assert backend.bootstrap_kek() == b"\xab" * 32

    def test_get_core_kek_only_falls_back_to_config_kek(self):
        config = BackendConfig(database_url="postgresql://x/x", kek=b"\xcd" * 32)
        backend = Backend(config)
        backend.get_session = lambda: pytest.fail("get_session must not be called")
        core = backend.get_core(passphrase=None)
        assert core.kek == b"\xcd" * 32


class TestTwoProcessRoundTrip:
    """The meaningful test: the KEK is reproducible across a restart."""

    def test_kek_reproducible_and_secret_survives_restart(self, tmp_path):
        pw = b"master-passphrase"
        dbfile = tmp_path / "restart.db"
        engine1 = create_engine(f"sqlite:///{dbfile}")
        Base.metadata.create_all(engine1)
        factory1 = sessionmaker(bind=engine1)

        # --- Process 1: first boot, generate + persist salt, store a secret. ---
        s = factory1()
        salt1 = ensure_kek_salt(s)
        _seed_secret(s, salt1, passphrase=pw)
        s.close()
        engine1.dispose()

        # --- Process 2: fresh engine to the same file (simulated restart). ---
        engine2 = create_engine(f"sqlite:///{dbfile}")
        factory2 = sessionmaker(bind=engine2)
        s = factory2()
        salt2 = ensure_kek_salt(s)
        rec = s.query(Secret).filter(Secret.key == "k").first()
        s.close()

        # The salt survived the restart and the KEK is reproducible (C-11 core).
        assert salt2 == salt1
        kek1, _ = derive_kek(pw, salt1)
        kek2, _ = derive_kek(pw, salt2)
        assert kek1 == kek2

        # The previously-stored secret unwraps + decrypts after the restart.
        plaintext = decrypt_secret(kek2, rec.wrapped_dek, rec.nonce, rec.encrypted_value)
        assert plaintext == b"top-secret-value"

        engine2.dispose()

    def test_old_random_salt_behavior_does_not_reproduce(self):
        # Negative control: the pre-fix behavior (derive with salt=None) yields a
        # different KEK each call and CANNOT unwrap a previously-wrapped secret.
        pw = b"master-passphrase"
        # Old buggy derivation: random salt, discarded.
        kek_old, _ = derive_kek(pw)  # salt=None
        blob = _seed_secret_under(kek_old)

        # A "restart" that re-derives the old way gets a DIFFERENT KEK ...
        kek_restart, _ = derive_kek(pw)  # salt=None again
        assert kek_restart != kek_old
        # ... so the stored secret is unrecoverable.
        with pytest.raises(DecryptionError):
            decrypt_secret(kek_restart, blob["wrapped_dek"], blob["nonce"], blob["ciphertext"])


def _seed_secret_under(kek: bytes, value: bytes = b"top-secret-value") -> dict:
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, value)
    return {"wrapped_dek": wrapped_dek, "nonce": nonce, "ciphertext": ciphertext}
