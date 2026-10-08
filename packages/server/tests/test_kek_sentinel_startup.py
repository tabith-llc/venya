# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#304 startup proof: the server must NOT boot green with a wrong passphrase.

DR-drill D-6: restoring with a wrong VENYA_DB__PASSPHRASE booted silently; the
KEK is lazy-derived and the mismatch surfaced only at first crypto use — after
the wrong KEK could already wrap NEW DEKs (permanently unrecoverable secrets).
Lifespan now proves the passphrase against the stored KEK sentinel before
serving, following the _init_core admin-CA abort pattern: loud CRITICAL log +
re-raise (uvicorn exits non-zero).

Truth table here (server layer): match boots · mismatch hard-exits (raise +
CRITICAL, value-free) · legacy all-fail hard-exits · legacy mixed boots with
CRITICAL-but-not-fatal · fresh-empty boots with one WARNING · wiring pin.
Synthetic keys only; no passphrase, plaintext, or key material may reach logs.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from core.engine.backend import (
    SENTINEL_PLAINTEXT,
    Backend,
    BackendConfig,
    KekPassphraseMismatchError,
    ensure_kek_sentinel,
)
from core.engine.encryption import derive_kek, encrypt_secret
from core.iam.models import Base, KekSentinel, Secret, VenyaConfig
from server import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_RIGHT = b"right-passphrase-synthetic"
_WRONG = b"wrong-passphrase-synthetic"
_SALT = b"\x11" * 16


def _backend(tmp_path, passphrase: bytes) -> Backend:
    """Real SQLite backend with a persisted salt; KEK bootstrapped from passphrase."""
    url = f"sqlite:///{tmp_path / 'startup.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    backend = Backend(BackendConfig(database_url=url, passphrase=passphrase))
    # Backend's pragma connect-listener is PostgreSQL-only (production dialect):
    # inject the plain engine so the SQLite fixture can use the real Backend.
    backend._engine = engine
    backend._session_factory = sessionmaker(bind=engine)
    session = backend.get_session()
    if session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first() is None:
        session.add(VenyaConfig(key="kek_salt", value=_SALT, created_at=datetime.now(UTC)))
        session.commit()
    session.close()
    backend.bootstrap_kek()
    return backend


def _seed_secret(backend: Backend, kek: bytes, key: str) -> None:
    session = backend.get_session()
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
    session.close()


def _logged_text(mock_logger) -> str:
    parts = []
    for call in mock_logger.method_calls:
        for arg in call.args:
            if isinstance(arg, (str, bytes, bytearray)):
                parts.append(str(arg))
    return " | ".join(parts)


class TestSentinelStartupProof:
    def test_sentinel_match_boots(self, tmp_path):
        backend = _backend(tmp_path, _RIGHT)
        session = backend.get_session()
        with backend.kek_cache.view() as kek:
            ensure_kek_sentinel(session, kek)
        session.close()

        with patch.object(app, "logger") as mock_logger:
            app._verify_kek_sentinel(backend)  # must not raise
        mock_logger.critical.assert_not_called()
        backend.dispose()

    def test_sentinel_mismatch_hard_exits_loud_and_value_free(self, tmp_path):
        """The paired negative proving the old silent-green boot is gone."""
        backend = _backend(tmp_path, _RIGHT)
        session = backend.get_session()
        with backend.kek_cache.view() as kek:
            ensure_kek_sentinel(session, kek)
        session.close()

        wrong = _backend(tmp_path, _WRONG)
        with patch.object(app, "logger") as mock_logger, pytest.raises(KekPassphraseMismatchError):
            app._verify_kek_sentinel(wrong)

        mock_logger.critical.assert_called_once()
        text = _logged_text(mock_logger)
        assert "configured encryption passphrase does not match stored key material" in text
        # value-free doctrine: neither passphrase nor sentinel plaintext in any log line
        assert _RIGHT.decode() not in text
        assert _WRONG.decode() not in text
        assert SENTINEL_PLAINTEXT.decode() not in text
        backend.dispose()
        wrong.dispose()

    def test_legacy_all_samples_fail_hard_exits(self, tmp_path):
        backend = _backend(tmp_path, _RIGHT)
        right_kek, _ = derive_kek(_RIGHT, _SALT)
        _seed_secret(backend, right_kek, "a")
        _seed_secret(backend, right_kek, "b")

        wrong = _backend(tmp_path, _WRONG)
        with patch.object(app, "logger") as mock_logger, pytest.raises(KekPassphraseMismatchError):
            app._verify_kek_sentinel(wrong)
        mock_logger.critical.assert_called_once()
        assert "does not match stored key material" in _logged_text(mock_logger)
        backend.dispose()
        wrong.dispose()

    def test_legacy_mixed_boots_with_critical_not_fatal(self, tmp_path):
        """1 corrupt + 1 good sample: a corrupt row must not brick boot."""
        other_kek, _ = derive_kek(b"other-passphrase-synthetic", b"\x22" * 16)
        backend = _backend(tmp_path, _RIGHT)
        right_kek, _ = derive_kek(_RIGHT, _SALT)
        _seed_secret(backend, other_kek, "corrupt")
        _seed_secret(backend, right_kek, "good")

        with patch.object(app, "logger") as mock_logger:
            app._verify_kek_sentinel(backend)  # boots

        mock_logger.critical.assert_called_once()
        assert _RIGHT.decode() not in _logged_text(mock_logger)
        backend.dispose()

    def test_fresh_empty_boots_with_one_warning(self, tmp_path):
        """No sentinel, no secrets: nothing to verify, nothing to corrupt."""
        backend = _backend(tmp_path, _RIGHT)
        with patch.object(app, "logger") as mock_logger:
            app._verify_kek_sentinel(backend)  # boots
        mock_logger.critical.assert_not_called()
        mock_logger.warning.assert_called_once()
        backend.dispose()

    def test_first_crypto_use_mints_exactly_one_sentinel(self, tmp_path):
        """Fresh boot → no row; the Core.encrypt convergence point lands one row."""
        backend = _backend(tmp_path, _RIGHT)
        session = backend.get_session()
        assert session.query(KekSentinel).count() == 0
        session.close()

        core = backend.get_core()
        core.encrypt(b"first-stored-secret")
        core.encrypt(b"second-stored-secret")
        session = backend.get_session()
        assert session.query(KekSentinel).count() == 1
        session.close()
        backend.dispose()


class TestStartupWiring:
    def test_lifespan_calls_the_sentinel_proof(self):
        """Pin: the check is wired into the lifespan startup path (not dead code)."""
        from pathlib import Path

        src = (Path(__file__).resolve().parents[1] / "src" / "server" / "app.py").read_text()
        call = "\n    _verify_kek_sentinel(backend)"
        assert call in src
        # ordering pin: proof runs after the KEK is bootstrapped, before serving
        assert src.index("core = _init_core") < src.index(call)
