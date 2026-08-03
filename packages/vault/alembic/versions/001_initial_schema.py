"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-08-02 20:35:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("PRAGMA foreign_keys = ON")

    # --- Core IAM tables ---

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("auth_mode", sa.String(32), nullable=False, server_default="security-key"),
        sa.Column("enrolled_at", sa.DateTime(), nullable=True),
        sa.Column("session_timeout", sa.Integer(), nullable=False, server_default="900"),
        sa.UniqueConstraint("user_id", name="uq_users_user_id"),
    )
    op.create_index("ix_users_user_id", "users", ["user_id"])

    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("permissions", sa.String(16), nullable=False, server_default="read"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )
    op.create_index("ix_roles_name", "roles", ["name"])

    op.create_table(
        "role_members",
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"]),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"]),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_role_members"),
    )
    op.create_index("ix_role_members_user_id", "role_members", ["user_id"])
    op.create_index("ix_role_members_role_id", "role_members", ["role_id"])

    op.create_table(
        "key_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("version_label", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("rotation_pending", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("encrypted_kek_hash", sa.String(64), nullable=True),
        sa.UniqueConstraint("version_label", name="uq_key_versions_version_label"),
    )

    op.create_table(
        "secrets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(512), nullable=False),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("key_version_id", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.user_id"]),
    )
    op.create_index("ix_secrets_key", "secrets", ["key"])

    op.create_table(
        "secret_roles",
        sa.Column("secret_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["secret_id"], ["secrets.id"]),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"]),
        sa.PrimaryKeyConstraint("secret_id", "role_id", name="pk_secret_roles"),
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("access_token_jti", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"]),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=True),
        sa.Column("fields", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"]),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token", sa.String(128), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False, server_default="0"),
        sa.UniqueConstraint("token", name="uq_enrollment_tokens_token"),
    )
    op.create_index("ix_enrollment_tokens_token", "enrollment_tokens", ["token"])
    op.create_index("ix_enrollment_tokens_expires_at", "enrollment_tokens", ["expires_at"])

    # --- Key rotation tables ---

    op.create_table(
        "key_rotation_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_by_user_id", sa.String(64), nullable=True),
        sa.Column("old_key_version_id", sa.Integer(), nullable=True),
        sa.Column("new_key_version_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("total_secrets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed_secrets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "key_rotation_secrets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rotation_job_id", sa.Integer(), nullable=False),
        sa.Column("secret_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["rotation_job_id"], ["key_rotation_jobs.id"]),
    )

    # --- Rate limiting ---

    op.create_table(
        "rate_limit_failures",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(), nullable=False),
    )

    # --- Command policies ---

    op.create_table(
        "command_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_name", sa.String(64), nullable=False),
        sa.Column("preset", sa.String(32), nullable=False),
        sa.Column("allowed_commands", sa.Text(), nullable=True),
        sa.Column("dangerous_patterns", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("policy_name", name="uq_command_policies_policy_name"),
    )
    op.create_index("ix_command_policies_policy_name", "command_policies", ["policy_name"])

    # --- Executor certificates ---

    op.create_table(
        "executor_certs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("executor_id", sa.String(64), nullable=False),
        sa.Column("serial_number", sa.String(64), nullable=False),
        sa.Column("not_before", sa.DateTime(), nullable=False),
        sa.Column("not_after", sa.DateTime(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["executor_id"], ["users.user_id"]),
        sa.UniqueConstraint("serial_number", name="uq_executor_certs_serial_number"),
    )
    op.create_index("ix_executor_certs_executor_id", "executor_certs", ["executor_id"])
    op.create_index("ix_executor_certs_serial_number", "executor_certs", ["serial_number"])
    op.create_index("ix_executor_certs_not_after", "executor_certs", ["not_after"])


def downgrade() -> None:
    op.execute("PRAGMA foreign_keys = ON")

    op.drop_table("executor_certs")
    op.drop_table("command_policies")
    op.drop_table("rate_limit_failures")
    op.drop_table("key_rotation_secrets")
    op.drop_table("key_rotation_jobs")
    op.drop_table("enrollment_tokens")
    op.drop_table("audit_events")
    op.drop_table("sessions")
    op.drop_table("secret_roles")
    op.drop_table("secrets")
    op.drop_table("key_versions")
    op.drop_table("role_members")
    op.drop_table("roles")
    op.drop_table("users")
