# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Unit tests for server.config.SessionConfig validation (#291 T-guard).

Truth table: an idle timeout beyond the hard cap (session_timeout >
max_session_duration) is rejected loudly at config-build time (startup
failure); timeout <= max is accepted. No server boot — the pydantic model is
validated directly.
"""

import pytest
from pydantic import ValidationError
from server.config import SessionConfig


class TestSessionConfigGuard:
    def test_timeout_exceeding_max_raises(self):
        """T-guard (negative): idle timeout beyond the hard cap is rejected."""
        with pytest.raises(ValidationError, match="must not exceed"):
            SessionConfig(session_timeout=5000, max_session_duration=1000)

    def test_timeout_within_max_ok(self):
        """T-guard (paired positive): timeout < max is accepted."""
        cfg = SessionConfig(session_timeout=1000, max_session_duration=5000)
        assert cfg.session_timeout == 1000
        assert cfg.max_session_duration == 5000

    def test_defaults_accepted(self):
        """Defaults (900 s timeout, 14400 s max) are valid."""
        cfg = SessionConfig()
        assert cfg.session_timeout == 900
        assert cfg.max_session_duration == 14400
