# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for CSPRNG entropy utilities."""

import os
import secrets

import pytest
from core.utils.entropy import csprng_self_test, get_secure_token


class TestGetSecureToken:
    """Tests for get_secure_token() wrapper."""

    def test_default_length(self):
        """get_secure_token() returns a token of default length (32 bytes)."""
        token = get_secure_token()
        # secrets.token_urlsafe(32) produces ~43 chars
        assert len(token) > 0
        assert len(token) >= 30

    def test_custom_length(self):
        """get_secure_token(length=16) returns a shorter token."""
        token = get_secure_token(16)
        assert len(token) > 0
        assert len(token) < len(get_secure_token(32))

    def test_zero_length(self):
        """get_secure_token(length=0) should return empty string, not error."""
        token = get_secure_token(length=0)
        assert token == ""

    def test_urlsafe_charset(self):
        """Token contains only URL-safe characters."""
        token = get_secure_token(64)
        import re

        assert re.fullmatch(r"[A-Za-z0-9_-]+", token)

    def test_uniqueness(self):
        """Multiple calls produce different tokens."""
        tokens = {get_secure_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_entropy_compared_to_secrets(self):
        """get_secure_token delegates to secrets.token_urlsafe."""
        token = get_secure_token(32)
        expected = secrets.token_urlsafe(32)
        # Same length range (both use same underlying function)
        assert len(token) == len(expected)


class TestCsprngSelfTest:
    """Tests for csprng_self_test() startup sanity check."""

    def test_self_test_passes_normally(self):
        """csprng_self_test() succeeds on a healthy system."""
        # Should not raise on any functioning system
        csprng_self_test()

    def test_self_test_detects_all_zero_output(self, monkeypatch):
        """csprng_self_test() raises on all-zero degenerate output."""
        monkeypatch.setattr(os, "urandom", lambda n: b"\x00" * n)
        with pytest.raises(RuntimeError, match="all-zero output"):
            csprng_self_test()

    def test_self_test_detects_wrong_length(self, monkeypatch):
        """csprng_self_test() raises if os.urandom returns wrong byte count."""
        monkeypatch.setattr(os, "urandom", lambda n: b"\x01" * (n - 1))
        with pytest.raises(RuntimeError, match="returned 31 bytes"):
            csprng_self_test()

    def test_self_test_detects_os_error(self, monkeypatch):
        """csprng_self_test() raises RuntimeError on OSError from os.urandom."""
        monkeypatch.setattr(os, "urandom", lambda n: (_ for _ in ()).throw(OSError("no entropy")))
        with pytest.raises(RuntimeError, match="CSPRNG unavailable"):
            csprng_self_test()

    def test_self_test_allows_blocking_io_error(self, monkeypatch):
        """csprng_self_test() logs warning on BlockingIOError, does not raise."""
        monkeypatch.setattr(os, "urandom", lambda n: (_ for _ in ()).throw(BlockingIOError("EAGAIN")))
        # Should not raise — just logs a warning
        csprng_self_test()
