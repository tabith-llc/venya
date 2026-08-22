"""Add ON DELETE CASCADE to all FKs referencing users.user_id

Revision ID: 019
Revises: 018
Create Date: 2026-08-18

M-01: Adds ON DELETE CASCADE to all foreign keys referencing users.user_id.
This makes user deletion atomic — deleting a user cascades to all child records.
AuditEvent.user_id is intentionally excluded (append-only audit trail).

Tables updated:
  role_members.user_id
  secrets.created_by
  sessions.user_id
  enrollment_tokens.user_id
  executor_enrollment_tokens.created_by
  executor_certs.executor_id
  elevation_tokens.user_id
  webauthn_credentials.user_id
"""

from alembic import op

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None

# (table, constraint_name, column, ref_table, ref_column)
CASCADE_FKS = [
    ("role_members", "role_members_user_id_fkey", "user_id", "users", "user_id"),
    ("secrets", "secrets_created_by_fkey", "created_by", "users", "user_id"),
    ("sessions", "sessions_user_id_fkey", "user_id", "users", "user_id"),
    ("enrollment_tokens", "enrollment_tokens_user_id_fkey", "user_id", "users", "user_id"),
    ("executor_enrollment_tokens", "executor_enrollment_tokens_created_by_fkey", "created_by", "users", "user_id"),
    ("executor_certs", "executor_certs_executor_id_fkey", "executor_id", "users", "user_id"),
    ("elevation_tokens", "elevation_tokens_user_id_fkey", "user_id", "users", "user_id"),
    ("webauthn_credentials", "webauthn_credentials_user_id_fkey", "user_id", "users", "user_id"),
]


def upgrade():
    for table, constraint, column, ref_table, ref_col in CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint,
            table,
            ref_table,
            [column],
            [ref_col],
            ondelete="CASCADE",
        )


def downgrade():
    for table, constraint, column, ref_table, ref_col in CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint,
            table,
            ref_table,
            [column],
            [ref_col],
        )
