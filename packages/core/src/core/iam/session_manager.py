# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Session lifecycle + token rotation.

Two-tier token system:
- Session: 15 minutes idle (sliding window), max 4 hours hard cap
- Access token: 5 minutes, transparently refreshed within active session
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from core.utils.entropy import get_secure_token

from .models import Session as SessionModel
from .models import User


class SessionError(Exception):
    """Session error."""


class UserNotActiveError(SessionError):
    """Raised when a session is requested for a user that is not 'active'.

    Single enforcement point for the login status gate (ticket
    sec-unauth-webauthn-registration-takeover): disabled / pending_enrollment /
    unknown users cannot be issued a session. Subclasses SessionError so any
    pre-existing `except SessionError` still catches it.
    """

    def __init__(self, user_id: str, status: str | None) -> None:
        self.user_id = user_id
        self.status = status
        super().__init__(f"User '{user_id}' is not active (status={status!r})")


def is_user_active(user: User | None) -> bool:
    """Central predicate: may this user hold a live session?

    Single semantic source for the 'active' status gate (pattern: central
    check, distributed callers — cf. server/revocation.py for executors).
    Consumers: ``create_session`` (issuance gate, ticket
    sec-unauth-webauthn-registration-takeover) and the server auth middleware
    ``_validate_token`` (surviving-session gate, ticket
    sec-auth-elevation-authz-hardening #9 — a disabled user's EXISTING
    sessions die on the next request, not at idle expiry). A second
    status-literal comparison anywhere is a divergence bug.
    """
    return user is not None and user.status == "active"


# Default clock skew tolerance for core-side checks
_DEFAULT_CLOCK_SKEW_SECONDS = 60


@dataclass
class SessionConfig:
    """Session configuration.

    Attributes:
        session_timeout: Idle timeout before session expires (default 15 min).
        access_token_ttl: Per-token lifetime (default 5 min).
        max_session_duration: Hard cap on any single session (default 4 hours).
        clock_skew_tolerance_seconds: Clock skew tolerance for expiration checks.
    """

    session_timeout: timedelta = field(default_factory=lambda: timedelta(minutes=15))
    access_token_ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    max_session_duration: timedelta = field(default_factory=lambda: timedelta(hours=4))
    clock_skew_tolerance_seconds: int = field(default=_DEFAULT_CLOCK_SKEW_SECONDS)


@dataclass
class AccessToken:
    """An access token for API calls.

    Attributes:
        token: The JWT-like access token string.
        user_id: The user this token is for.
        roles: The user's role IDs.
        expires_at: Token expiration time.
        jti: Token ID for tracking/revocation.
    """

    token: str
    user_id: str
    roles: list[str] = field(default_factory=list)
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    jti: str = field(default_factory=lambda: uuid.uuid4().hex)


class SessionManager:
    """Manages user sessions and access tokens.

    Session auto-extend with hard cap:
    - Idle timeout: 15 min (configurable)
    - Max duration: 4 hours (configurable, hard cap)
    - Access token TTL: 5 min (configurable)
    """

    def __init__(self, db: Session, config: SessionConfig | None = None) -> None:
        self.db = db
        self.config = config or SessionConfig()

    def create_session(self, user_id: str, roles: list[str] | None = None) -> tuple[SessionModel, AccessToken]:
        """Create a new session and access token.

        Args:
            user_id: The user ID.
            roles: Optional list of role IDs for the token payload.

        Returns:
            Tuple of (Session, AccessToken).

        Raises:
            UserNotActiveError: If the user row is missing or its status is not
                'active' — disabled / pending_enrollment users cannot be issued
                a session (ticket sec-unauth-webauthn-registration-takeover).
        """
        # Status gate: no session for a non-active user. Single choke point —
        # every login path (webauthn, browser) issues through here. The enroll
        # path sets status='active' and calls create_session in the SAME
        # transaction; SQLAlchemy autoflush makes that pending UPDATE visible
        # to this SELECT (ordering pinned by test in test_auth_status_gate.py).
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not is_user_active(user):
            raise UserNotActiveError(user_id, None if user is None else user.status)

        now = datetime.now(UTC)
        expires_at = now + self.config.session_timeout

        # Create access token first
        access_token = AccessToken(
            token=get_secure_token(32),
            user_id=user_id,
            roles=roles or [],
            expires_at=now + self.config.access_token_ttl,
        )

        session = SessionModel(
            user_id=user_id,
            expires_at=expires_at,
            access_token=access_token.token,
            access_token_jti=access_token.jti,
        )
        self.db.add(session)
        self.db.flush()

        return session, access_token

    def validate_session(self, session_id: int) -> bool:
        """Check if a session is still active.

        Returns:
            True if the session is active (not idle-expired and not exceeded max duration).
        """
        session = self.db.query(SessionModel).filter(SessionModel.id == session_id).first()
        if session is None:
            return False

        now = datetime.now(UTC)
        now_minus_tolerance = now - timedelta(seconds=self.config.clock_skew_tolerance_seconds)

        # Check hard cap using stored created_at (not derived from expires_at)
        if session.created_at + self.config.max_session_duration < now:
            return False

        # Check idle timeout
        return session.expires_at >= now_minus_tolerance

    def extend_session(self, session_id: int) -> bool:
        """Extend a session's idle timeout.

        Returns:
            True if extended, False if hard cap reached.
        """
        session = self.db.query(SessionModel).filter(SessionModel.id == session_id).first()
        if session is None:
            return False

        now = datetime.now(UTC)

        # Check hard cap using stored created_at
        if session.created_at + self.config.max_session_duration < now:
            return False

        # Extend idle timeout
        session.expires_at = now + self.config.session_timeout
        self.db.flush()
        return True

    def check_refresh_window(self, session: SessionModel) -> bool:
        """Refresh gate: HARD CAP only (mcp-refresh-path-unreachable Option A,
        user ruling 2026-09-20).

        Idle-expired sessions remain refreshable until ``created_at +
        max_session_duration``; past that, refresh dies and re-auth (FIDO2) is
        required. Deliberate ruled trade-off: revival widens the stolen-token
        renewal window from idle-timeout to hard-cap; the token rotation in
        ``refresh_token`` (old token invalidated on success) keeps a theft race
        detectable. The middleware's ``check_expiry`` (idle + hard cap) stays
        UNCHANGED — API calls from idle-expired sessions still 401, and that
        401 is what triggers the client refresh path.
        """
        return session.created_at + self.config.max_session_duration >= datetime.now(UTC)

    def refresh_token(self, access_token: str) -> AccessToken | None:
        """Refresh an access token within the hard-cap window.

        Idle-expired sessions are revived (Option A ruling 2026-09-20 — the
        former validate_session gate made every refresh of an idle-expired
        session fail: the mcp-refresh-path-unreachable dead-path root cause).

        Args:
            access_token: The current access token string.

        Returns:
            New AccessToken if successful, None if unknown token or the
            session is past max_session_duration (re-auth required).
        """
        # Find session by access token
        session = self.db.query(SessionModel).filter(SessionModel.access_token == access_token).first()
        if session is None:
            return None

        if not self.check_refresh_window(session):
            return None

        # Extend session
        self.extend_session(session.id)

        # Create new access token
        new_token = AccessToken(
            token=get_secure_token(32),
            user_id=session.user_id,
            expires_at=datetime.now(UTC) + self.config.access_token_ttl,
        )

        session.access_token = new_token.token
        session.access_token_jti = new_token.jti
        self.db.flush()

        return new_token

    def revoke_session(self, session_id: int) -> bool:
        """Revoke a session.

        Returns:
            True if revoked, False if not found.
        """
        session = self.db.query(SessionModel).filter(SessionModel.id == session_id).first()
        if session is None:
            return False

        self.db.delete(session)
        self.db.flush()
        return True

    def cleanup_expired(self) -> int:
        """Remove expired sessions.

        Deletes sessions where expires_at has passed (idle timeout expired).
        This covers both idle-expired sessions and hard-cap expired sessions
        in a single query.

        Returns:
            Number of sessions removed.
        """
        now = datetime.now(UTC)
        cleanup_threshold = now - timedelta(seconds=self.config.clock_skew_tolerance_seconds)
        expired = (
            self.db.query(SessionModel)
            .filter(
                SessionModel.expires_at < cleanup_threshold,
            )
            .delete()
        )
        self.db.flush()
        return expired

    def check_expiry(self, session: SessionModel) -> bool:
        """Check if a session has expired.

        Returns:
            False if session has expired (requires re-auth), True if still active.
        """
        now = datetime.now(UTC)
        now_minus_tolerance = now - timedelta(seconds=self.config.clock_skew_tolerance_seconds)

        # Hard cap check using stored created_at
        if session.created_at + self.config.max_session_duration < now:
            return False

        # Idle timeout check
        return session.expires_at >= now_minus_tolerance
