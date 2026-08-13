"""Enrollment tokens for user onboarding.

Handles enrollment token lifecycle:
1. Admin creates token for a user (Phase 1)
2. User presents token to start enrollment (Phase 2)
3. Token transitions through state machine: created → in_progress → completed
4. Admin can revoke or issue new tokens (Phase 7)
5. Re-enrollment flow (Phase 6)
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .models import EnrollmentToken, User


class EnrollmentError(Exception):
    """Enrollment error."""


@dataclass
class EnrollmentConfig:
    """Enrollment configuration.

    Attributes:
        token_expiry: How long enrollment tokens are valid (default 15 minutes).
    """

    token_expiry: timedelta = field(default_factory=lambda: timedelta(minutes=15))


class EnrollmentManager:
    """Manages enrollment tokens and user onboarding."""

    def __init__(self, db: Session, config: EnrollmentConfig | None = None) -> None:
        self.db = db
        self.config = config or EnrollmentConfig()

    def _hash_token(self, plaintext: str) -> str:
        """SHA-256 hash a plaintext enrollment token."""
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    def create_enrollment_token(self, user_id: int) -> tuple[EnrollmentToken, str]:
        """Create an enrollment token for an existing user.

        Args:
            user_id: The integer ID of the user to create a token for.

        Returns:
            Tuple of (EnrollmentToken record, plaintext token string).
            The plaintext token is returned only once and never stored.
        """
        # Check for active (non-expired, non-completed, non-revoked) tokens
        active_count = (
            self.db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.user_id == user_id,
                EnrollmentToken.state.in_(["created", "in_progress"]),
                EnrollmentToken.expires_at > datetime.now(timezone.utc),
            )
            .count()
        )
        if active_count >= 3:
            raise EnrollmentError(
                f"User ID {user_id} already has 3 active enrollment tokens"
            )

        plaintext = secrets.token_urlsafe(32)
        token = EnrollmentToken(
            user_id=user_id,
            token_hash=self._hash_token(plaintext),
            state="created",
            expires_at=datetime.now(timezone.utc) + self.config.token_expiry,
        )
        self.db.add(token)
        self.db.flush()
        return token, plaintext

    def get_token_by_plaintext(self, token_value: str) -> EnrollmentToken | None:
        """Look up an enrollment token by its plaintext value.

        Returns:
            The EnrollmentToken if found, None otherwise. The token's state
            and expiry are NOT checked here — callers should validate.
        """
        token_hash = self._hash_token(token_value)
        return (
            self.db.query(EnrollmentToken)
            .filter(EnrollmentToken.token_hash == token_hash)
            .first()
        )

    def validate_token_for_start(self, token_value: str) -> EnrollmentToken:
        """Validate an enrollment token for starting the enrollment flow.

        Checks:
        - Token exists
        - State is "created"
        - Not expired
        - Linked user exists and status is "pending_enrollment"

        Args:
            token_value: The plaintext enrollment token.

        Returns:
            The validated EnrollmentToken.

        Raises:
            EnrollmentError: If validation fails.
        """
        token = self.get_token_by_plaintext(token_value)
        if token is None:
            raise EnrollmentError("Invalid enrollment token")

        if token.state not in ("created", "in_progress"):
            raise EnrollmentError(
                f"Enrollment token is not in 'created' state (current: {token.state})"
            )

        if token.expires_at <= datetime.now(timezone.utc):
            raise EnrollmentError("Enrollment token has expired")

        user = self.db.query(User).filter(User.id == token.user_id).first()
        if not user or user.status != "pending_enrollment":
            raise EnrollmentError("Linked user does not exist or is not pending enrollment")

        return token

    def mark_token_in_progress(self, token_value: str) -> EnrollmentToken:
        """Atomically transition token state from 'created' to 'in_progress'.

        Args:
            token_value: The plaintext enrollment token.

        Returns:
            The updated EnrollmentToken.

        Raises:
            EnrollmentError: If token is invalid or not in 'created' state.
        """
        token = self.get_token_by_plaintext(token_value)
        if token is None:
            raise EnrollmentError("Invalid enrollment token")
        if token.state == "in_progress":
            return token
        if token.state != "created":
            raise EnrollmentError("Invalid enrollment token or not in 'created' state")

        token.state = "in_progress"
        self.db.flush()
        return token

    def complete_enrollment(self, token_value: str) -> None:
        """Mark an enrollment token as completed.

        Args:
            token_value: The plaintext enrollment token.

        Raises:
            EnrollmentError: If token is invalid or not in 'in_progress' state.
        """
        token = self.get_token_by_plaintext(token_value)
        if token is None or token.state != "in_progress":
            raise EnrollmentError("Invalid enrollment token or not in 'in_progress' state")

        token.state = "completed"
        token.used_at = datetime.now(timezone.utc)
        self.db.flush()

    def revoke_token(self, token_id: int) -> bool:
        """Revoke an enrollment token by ID.

        Args:
            token_id: The integer ID of the enrollment token.

        Returns:
            True if revoked, False if not found.
        """
        token = (
            self.db.query(EnrollmentToken)
            .filter(EnrollmentToken.id == token_id)
            .first()
        )
        if token is None:
            return False

        if token.state in ("completed", "revoked"):
            return False

        token.state = "revoked"
        self.db.flush()
        return True

    def revoke_all_active_tokens(self, user_id: int) -> int:
        """Revoke all active enrollment tokens for a user.

        Used during re-enrollment (Phase 6).

        Args:
            user_id: The integer ID of the user.

        Returns:
            Number of tokens revoked.
        """
        count = (
            self.db.query(EnrollmentToken)
            .filter(
                EnrollmentToken.user_id == user_id,
                EnrollmentToken.state.in_(["created", "in_progress"]),
            )
            .update({"state": "revoked"}, synchronize_session="fetch")
        )
        self.db.flush()
        return count

    def get_user_tokens(self, user_id: int) -> list[EnrollmentToken]:
        """Get all enrollment tokens for a user.

        Args:
            user_id: The integer ID of the user.

        Returns:
            List of EnrollmentToken records.
        """
        return (
            self.db.query(EnrollmentToken)
            .filter(EnrollmentToken.user_id == user_id)
            .order_by(EnrollmentToken.created_at.desc())
            .all()
        )

    def cleanup_expired(self) -> int:
        """Remove expired and revoked enrollment tokens.

        Returns:
            Number of tokens removed.
        """
        now = datetime.now(timezone.utc)
        count = (
            self.db.query(EnrollmentToken)
            .filter(
                (EnrollmentToken.expires_at < now)
                | (EnrollmentToken.state == "revoked"),
            )
            .delete(synchronize_session="fetch")
        )
        self.db.flush()
        return count
