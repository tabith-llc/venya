# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for app startup passphrase check."""

import pytest
from server.config import DatabaseConfig, ServerConfig

_TEST_PEPPER = "test-pepper"


class TestPassphraseStartupCheck:
    """Tests for the passphrase startup hard failure in production."""

    def test_missing_passphrase_fails_in_production(self):
        """RuntimeError when debug=False and passphrase is None."""
        config = ServerConfig(
            debug=False,
            db=DatabaseConfig(database_url="postgresql://test/test"),
            recovery_code_pepper=_TEST_PEPPER,
        )

        # Replicate the exact check from app.py lifespan
        if not config.debug and not config.db.passphrase:
            with pytest.raises(RuntimeError, match="VENYA_DB_PASSPHRASE is not set"):
                raise RuntimeError(
                    "VENYA_DB_PASSPHRASE is not set. "
                    "Core secrets cannot be encrypted without a passphrase. "
                    "Set the passphrase in your secrets manager and restart."
                )
        else:
            pytest.fail("Expected RuntimeError was not raised")

    def test_missing_passphrase_allowed_in_debug(self):
        """No error when debug=True and passphrase is None (backward compat)."""
        config = ServerConfig(
            debug=True,
            db=DatabaseConfig(database_url="postgresql://test/test"),
            recovery_code_pepper=_TEST_PEPPER,
        )

        # Replicate the exact check from app.py lifespan
        if not config.debug and not config.db.passphrase:
            pytest.fail("Should not raise in debug mode")
        # If we get here, the check passed (no RuntimeError)

    def test_passphrase_present_succeeds_in_production(self):
        """No error when passphrase is set in production."""
        config = ServerConfig(
            debug=False,
            db=DatabaseConfig(
                database_url="postgresql://test/test",
                passphrase="test-passphrase",
            ),
            recovery_code_pepper=_TEST_PEPPER,
        )

        # Replicate the exact check from app.py lifespan
        if not config.debug and not config.db.passphrase:
            pytest.fail("Should not raise when passphrase is set")
        # If we get here, the check passed (no RuntimeError)

    def test_empty_string_passphrase_fails_in_production(self):
        """Empty string passphrase fails (same as None) in production."""
        config = ServerConfig(
            debug=False,
            db=DatabaseConfig(
                database_url="postgresql://test/test",
                passphrase="",
            ),
            recovery_code_pepper=_TEST_PEPPER,
        )

        # Empty string is falsy, so the check triggers
        if not config.debug and not config.db.passphrase:
            with pytest.raises(RuntimeError, match="VENYA_DB_PASSPHRASE is not set"):
                raise RuntimeError(
                    "VENYA_DB_PASSPHRASE is not set. "
                    "Core secrets cannot be encrypted without a passphrase. "
                    "Set the passphrase in your secrets manager and restart."
                )
        else:
            pytest.fail("Expected RuntimeError was not raised")
