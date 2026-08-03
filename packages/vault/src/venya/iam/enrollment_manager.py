"""Enrollment tokens + auth setup.

Handles the enrollment flow for new users:
1. Generate enrollment token
2. User presents token + completes WebAuthn enrollment
3. Token is consumed, user account is created
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from .models import EnrollmentToken, User


class EnrollmentError(Exception):
    """Enrollment error."""


@dataclass
class EnrollmentConfig:
    """Enrollment configuration.

    Attributes:
        token_expiry: How long enrollment tokens are valid (default 24 hours).
        max_active_tokens: Maximum active (unconsumed) tokens per user (default 3).
    """

    token_expiry: timedelta = field(default_factory=lambda: timedelta(hours=24))
    max_active_tokens: int = field(default=3)


class EnrollmentManager:
    """Manages enrollment tokens and user onboarding."""

    def __init__(self, db: Session, config: EnrollmentConfig | None = None) -> None:
        self.db = db
        self.config = config or EnrollmentConfig()

    def create_enrollment_token(
        self, user_id: str, auth_mode: str = "security-key"
    ) -> EnrollmentToken:
        """Create an enrollment token for a new user.

        Args:
            user_id: The user ID to enroll.
            auth_mode: Authentication mode ("security-key" or "platform").

        Returns:
            The created EnrollmentToken.

        Raises:
            EnrollmentError: If too many active tokens exist for this user.
        """
        # Check active token count
        active_count = (
            self.db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.user_id == user_id,
                EnrollmentToken.consumed == False,  # noqa: E712
                EnrollmentToken.expires_at > datetime.now(timezone.utc),
            )
            .count()
        )
        if active_count >= self.config.max_active_tokens:
            raise EnrollmentError(
                f"User '{user_id}' already has {self.config.max_active_tokens} "
                "active enrollment tokens"
            )

        token = EnrollmentToken(
            token=secrets.token_urlsafe(32),
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + self.config.token_expiry,
            consumed=False,
        )
        self.db.add(token)
        self.db.flush()
        return token

    def get_enrollment_token(self, token_value: str) -> EnrollmentToken | None:
        """Get an enrollment token by its value.

        Returns:
            The EnrollmentToken if found and valid, None otherwise.
        """
        return (
            self.db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.token == token_value,
                EnrollmentToken.consumed == False,  # noqa: E712
                EnrollmentToken.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )

    def consume_enrollment_token(
        self, token_value: str, auth_mode: str = "security-key"
    ) -> User:
        """Consume an enrollment token and create the user.

        Args:
            token_value: The enrollment token value.
            auth_mode: Authentication mode for the new user.

        Returns:
            The created User.

        Raises:
            EnrollmentError: If token is invalid or already consumed.
        """
        token = self.get_enrollment_token(token_value)
        if token is None:
            raise EnrollmentError("Invalid or expired enrollment token")

        # Check if user already exists
        existing = (
            self.db.query(User).filter(User.user_id == token.user_id).first()
        )
        if existing:
            raise EnrollmentError(f"User '{token.user_id}' already exists")

        # Create user
        user = User(
            user_id=token.user_id,
            auth_mode=auth_mode,
            enrolled_at=datetime.now(timezone.utc),
        )
        self.db.add(user)

        # Mark token as consumed
        token.consumed = True
        self.db.flush()

        return user

    def revoke_enrollment_token(self, token_value: str) -> bool:
        """Revoke an enrollment token (mark as consumed without creating user).

        Returns:
            True if revoked, False if not found.
        """
        token = (
            self.db.query(EnrollmentToken)
            .filter(EnrollmentToken.token == token_value)
            .first()
        )
        if token is None:
            return False

        token.consumed = True
        self.db.flush()
        return True

    def cleanup_expired(self) -> int:
        """Remove expired and consumed enrollment tokens.

        Returns:
            Number of tokens removed.
        """
        now = datetime.now(timezone.utc)
        count = (
            self.db.query(EnrollmentToken)
            .filter(
                (EnrollmentToken.expires_at < now)
                | (EnrollmentToken.consumed == True),  # noqa: E712
            )
            .delete()
        )
        self.db.flush()
        return count
