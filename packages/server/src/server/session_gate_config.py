# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Single builder for the core session-gate config used across the server.

Ticket ``session-config-omits-clock-skew-knob`` #459: the server built the core
``SessionConfig`` at nine sites and every one of them passed the three timeout
fields while omitting ``clock_skew_tolerance_seconds``. The dataclass default
(60 s) then silently won, so the documented operator knob
``server_config.clock_skew.token_tolerance_seconds`` never reached the session
expiry gates — tightening it to 15 s changed nothing, and raising it for an
NTP-loss deployment made the session tier disagree with the dependency tier,
which already reads the knob (``dependencies.py``).

This module is the one place a session config is assembled from server config;
sites call :func:`build_core_session_config` instead of hand-rolling the
dataclass, so a fourth field can no longer be dropped by omission.
"""

from datetime import timedelta
from typing import Any

from core.iam.session_manager import SessionConfig

# The value used when the running config carries no clock-skew section. Read
# from the core dataclass rather than restated here, so the builder and the
# dataclass cannot drift apart (same fallback order maintenance.py documents:
# configured value first, core default second).
DEFAULT_TOKEN_TOLERANCE_SECONDS: int = SessionConfig().clock_skew_tolerance_seconds


def token_tolerance_seconds(server_config: Any) -> int:
    """Return the operator's token clock-skew tolerance.

    ``server_config`` is the app-state config object — a ``ServerConfig`` in
    production, a duck-typed namespace in tests. A missing ``clock_skew``
    section, or a section without the field, falls back to the core default
    instead of raising: an install that never set the knob keeps the behaviour
    it has today.

    Args:
        server_config: The app-state config object (or ``None``).

    Returns:
        Clock-skew tolerance in seconds for token/session expiry checks.
    """
    clock_skew = getattr(server_config, "clock_skew", None)
    value = getattr(clock_skew, "token_tolerance_seconds", None)
    if value is None:
        return DEFAULT_TOKEN_TOLERANCE_SECONDS
    return int(value)


def build_core_session_config(server_config: Any) -> SessionConfig:
    """Build the core ``SessionConfig`` from the server's app-state config.

    Carries all four fields — the three timeouts AND the clock-skew tolerance —
    so the operator knob reaches every gate that consumes a session config
    (#459). The timeouts are read the same way the sites read them before this
    helper existed: ``server_config.session`` is required, and a missing
    section or field raises rather than silently defaulting.

    Args:
        server_config: The app-state config object (``request.app.state.config``).

    Returns:
        A core ``SessionConfig`` with the configured tolerance applied.
    """
    session = server_config.session
    return SessionConfig(
        session_timeout=timedelta(seconds=session.session_timeout),
        access_token_ttl=timedelta(seconds=session.access_token_ttl),
        max_session_duration=timedelta(seconds=session.max_session_duration),
        clock_skew_tolerance_seconds=token_tolerance_seconds(server_config),
    )
