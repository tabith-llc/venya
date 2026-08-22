"""Add venya_config table for global key-material config

Revision ID: 021
Revises: 020
Create Date: 2026-08-21

C-11: the passphrase-derived KEK was not reproducible across restarts.
derive_kek() generated a random salt on every call and all three call-sites
(backend.__init__, backend.get_core, factory.build) discarded the returned
salt, so the same passphrase derived a DIFFERENT KEK on each process start.
Previously-stored secrets (DEKs wrapped under the old KEK) became unrecoverable
after the first restart.

Fix: persist the KEK salt in a global config table. Written once on first
initialization, read on every subsequent startup, so the KEK is deterministic
for a given passphrase across restarts.
"""

from alembic import op
import sqlalchemy as sa

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "venya_config",
        sa.Column("key", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("value", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade():
    op.drop_table("venya_config")
