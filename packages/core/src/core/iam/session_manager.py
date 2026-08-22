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


class SessionError(Exception):
    """Session error."""


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
        """
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

    def refresh_token(self, access_token: str) -> AccessToken | None:
        """Refresh an access token within an active session.

        Args:
            access_token: The current access token string.

        Returns:
            New AccessToken if successful, None if session expired or max cap reached.
        """
        # Find session by access token
        session = self.db.query(SessionModel).filter(SessionModel.access_token == access_token).first()
        if session is None:
            return None

        if not self.validate_session(session.id):
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
