# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""KEK sentinel (#304): boot-time proof that the passphrase matches stored key material.

A wrong passphrase used to boot silently: bootstrap_kek derives "successfully"
from passphrase + persisted salt, and the mismatch only surfaced at the first
unwrap — while the wrong KEK could WRAP NEW DEKs, making those secrets
permanently unrecoverable. The sentinel (a fixed known plaintext wrapped under
the KEK with the SAME AES-256-KW envelope as secret DEKs) proves the passphrase
before any new wrapping happens. Truth table here (core layer): sentinel match,
sentinel mismatch, legacy all-samples-fail, legacy mixed, fresh-empty, and the
idempotent get-or-create mint at the Core.encrypt convergence point. All keys
are synthetic; no value ever leaves these fixtures.
"""

from datetime import UTC, datetime

from core.engine.backend import (
    LEGACY_SAMPLE_LIMIT,
    SENTINEL_PLAINTEXT,
    Backend,
    BackendConfig,
    KekPassphraseMismatchError,
    SentinelStatus,
    ensure_kek_sentinel,
    verify_kek_sentinel,
)
from core.engine.core import Core
from core.engine.encryption import derive_kek, encrypt_secret, wrap_key
from core.iam.models import Base, KekSentinel, Secret
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _engine(tmp_path, name="sentinel.db"):
    engine = create_engine(f"sqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)


def _seed_secret(session, kek: bytes, key: str = "k") -> None:
    wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"synthetic-value")
    session.add(
        Secret(
            key=key,
            encrypted_value=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            key_version_id="v1",
            created_by="user1",
            created_at=datetime.now(UTC),
        )
    )
    session.commit()


class TestSentinelConstants:
    def test_plaintext_fits_the_dek_envelope(self):
        """The sentinel reuses wrap_key/unwrap_key — its plaintext must be a valid DEK."""
        assert len(SENTINEL_PLAINTEXT) == 32
        assert len(SENTINEL_PLAINTEXT) % 8 == 0

    def test_sample_limit_is_five(self):
        assert LEGACY_SAMPLE_LIMIT == 5


class TestSentinelCheck:
    def test_sentinel_match_verifies(self, tmp_path):
        _, factory = _engine(tmp_path)
        kek, _ = derive_kek(b"right-passphrase", b"\x01" * 16)
        s = factory()
        ensure_kek_sentinel(s, kek)
        result = verify_kek_sentinel(s, kek)
        assert result.status is SentinelStatus.MATCH
        s.close()

    def test_sentinel_mismatch_is_fatal_status(self, tmp_path):
        """Negative (the shipped silent-boot bug): wrong passphrase = MISMATCH, loud."""
        _, factory = _engine(tmp_path)
        kek, _ = derive_kek(b"right-passphrase", b"\x01" * 16)
        wrong_kek, _ = derive_kek(b"wrong-passphrase", b"\x01" * 16)
        s = factory()
        ensure_kek_sentinel(s, kek)
        result = verify_kek_sentinel(s, wrong_kek)
        assert result.status is SentinelStatus.MISMATCH
        s.close()

    def test_legacy_all_samples_fail_is_fatal_status(self, tmp_path):
        """Legacy install (no sentinel), every sampled DEK unwraps under a DIFFERENT key."""
        _, factory = _engine(tmp_path)
        right_kek, _ = derive_kek(b"right-passphrase", b"\x01" * 16)
        wrong_kek, _ = derive_kek(b"wrong-passphrase", b"\x01" * 16)
        s = factory()
        _seed_secret(s, right_kek, key="a")
        _seed_secret(s, right_kek, key="b")
        result = verify_kek_sentinel(s, wrong_kek)
        assert result.status is SentinelStatus.LEGACY_MISMATCH
        assert result.samples == 2
        assert result.failures == 2
        s.close()

    def test_legacy_mixed_boots_with_counted_failures(self, tmp_path):
        """One corrupt row must NOT brick boot: only ALL-fail is the wrong-passphrase verdict."""
        _, factory = _engine(tmp_path)
        right_kek, _ = derive_kek(b"right-passphrase", b"\x01" * 16)
        other_kek, _ = derive_kek(b"other-passphrase", b"\x02" * 16)
        s = factory()
        _seed_secret(s, other_kek, key="corrupt")  # unwrappable under the current KEK
        _seed_secret(s, right_kek, key="good")
        result = verify_kek_sentinel(s, right_kek)
        assert result.status is SentinelStatus.LEGACY_OK
        assert result.failures == 1
        s.close()

    def test_fresh_empty_install_has_nothing_to_verify(self, tmp_path):
        _, factory = _engine(tmp_path)
        kek, _ = derive_kek(b"any-passphrase", b"\x01" * 16)
        s = factory()
        result = verify_kek_sentinel(s, kek)
        assert result.status is SentinelStatus.FRESH_EMPTY
        s.close()

    def test_legacy_sampling_is_capped_at_five(self, tmp_path):
        _, factory = _engine(tmp_path)
        right_kek, _ = derive_kek(b"right-passphrase", b"\x01" * 16)
        wrong_kek, _ = derive_kek(b"wrong-passphrase", b"\x01" * 16)
        s = factory()
        for i in range(8):
            _seed_secret(s, right_kek, key=f"k{i}")
        result = verify_kek_sentinel(s, wrong_kek)
        assert result.status is SentinelStatus.LEGACY_MISMATCH
        assert result.samples == LEGACY_SAMPLE_LIMIT
        s.close()


class TestSentinelMint:
    def test_mint_is_idempotent(self, tmp_path):
        """Two mints = one row (get-or-create; no race double-mint)."""
        _, factory = _engine(tmp_path)
        kek, _ = derive_kek(b"passphrase", b"\x01" * 16)
        s = factory()
        ensure_kek_sentinel(s, kek)
        ensure_kek_sentinel(s, kek)
        assert s.query(KekSentinel).count() == 1
        s.close()

    def test_mint_stores_the_same_envelope_as_deks(self, tmp_path):
        """No new crypto format: 40-byte AES-KW envelope of the fixed plaintext."""
        _, factory = _engine(tmp_path)
        kek, _ = derive_kek(b"passphrase", b"\x01" * 16)
        s = factory()
        ensure_kek_sentinel(s, kek)
        row = s.query(KekSentinel).one()
        assert row.wrapped_sentinel == wrap_key(kek, SENTINEL_PLAINTEXT)
        assert len(row.wrapped_sentinel) == 40
        s.close()

    def test_encrypt_is_the_convergence_point_mint(self, tmp_path):
        """Core.encrypt is the single wrap site: every successful crypto use
        lands the sentinel exactly once — two stores, one row."""
        url = f"sqlite:///{tmp_path / 'conv.db'}"
        _, _ = _engine(tmp_path, "conv.db")
        kek, _ = derive_kek(b"passphrase", b"\x01" * 16)
        backend = Backend(BackendConfig(database_url=url, kek=kek))
        # the pragma connect-listener is PG-only (production dialect); inject a
        # plain engine so the SQLite test fixture can talk to the real Backend
        plain = create_engine(url)
        backend._engine = plain
        backend._session_factory = sessionmaker(bind=plain)
        core = Core(backend=backend, kek=kek)
        core.encrypt(b"value-one")
        core.encrypt(b"value-two")
        s = backend.get_session()
        assert s.query(KekSentinel).count() == 1
        # the minted sentinel proves the very passphrase/KEK it was stored under
        assert verify_kek_sentinel(s, kek).status is SentinelStatus.MATCH
        s.close()
        backend.dispose()


class TestMismatchError:
    def test_error_type_is_backend_error_family(self):
        from core.engine.backend import BackendError

        assert issubclass(KekPassphraseMismatchError, BackendError)
