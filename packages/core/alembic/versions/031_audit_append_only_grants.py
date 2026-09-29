# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""DB-enforced append-only audit trail — grants for the venya_audit role

Revision ID: 031
Revises: 030
Create Date: 2026-09-28

The published guarantee "Append-only audit log" was a code convention, not an
enforced property: the app ran in PostgreSQL as the database OWNER role, which
holds full DML on every table, so nothing would have stopped a future code
path (or a compromised process) from UPDATE/DELETE-ing audit_events rows
silently.

This migration enforces it at the database level:

- The runtime identity is the dedicated role ``venya_audit`` (created by the
  installer BEFORE this migration runs; peer-authenticated over the local
  Unix socket, no password — see docs/deployment-config.md "Database
  identity").
- ``venya_audit`` gets full DML on all current tables and, via ALTER DEFAULT
  PRIVILEGES, on every table/sequence a FUTURE migration creates — no
  per-migration grant discipline required.
- ``REVOKE UPDATE, DELETE ON audit_events`` runs LAST so it wins over the
  blanket grants: audit rows are INSERT/SELECT-able by the app, never
  modifiable. The owner role ``venya`` (ops + migrations) keeps full rights.

PostgreSQL-only DCL — this migration executes on the installer path (Postgres)
only; SQLite dev/test databases use model create_all and never run it.
All statements are idempotent (re-runs are no-ops); the role guard is the
single fail-loud gate.
"""

from alembic import op

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None

# Plain string literals (no f-string construction): the role/DB names are
# deployment constants, and literal SQL keeps this file clear of bandit B608
# (hardcoded-SQL-expression) findings without a suppression. The constants
# below exist so the interlock test can assert every statement names the right
# roles — a rename in one place without the other red-gates the merge.
APP_ROLE = "venya_audit"
OWNER_ROLE = "venya"
DATABASE_NAME = "venya"

# Fail loud if the installer did not create the runtime role first: a silent
# GRANT to a missing role would error obscurely mid-transaction and leave the
# install half-configured with no actionable message.
ROLE_GUARD_SQL = (
    "DO $$ BEGIN "
    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'venya_audit') THEN "
    "RAISE EXCEPTION 'role venya_audit is missing — the installer must create it before migrations (peer-auth runtime role, no password)'; "
    "END IF; "
    "END $$"
)

GRANT_CONNECT_SQL = "GRANT CONNECT ON DATABASE venya TO venya_audit"
GRANT_SCHEMA_SQL = "GRANT USAGE ON SCHEMA public TO venya_audit"
# REFERENCES is required, not decorative: the schema is dense with FKs
# (sessions->users, session_secrets->execution_sessions/secrets, ...), and
# PostgreSQL checks REFERENCES on the REFERENCED table when the app INSERTs
# into a referencing table. Without it, ordinary INSERTs fail with
# "permission denied".
GRANT_TABLES_SQL = "GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON ALL TABLES IN SCHEMA public TO venya_audit"
GRANT_SEQUENCES_SQL = "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO venya_audit"

# Future migrations run as the owner role; default privileges make every
# object they create reachable by the runtime role automatically.
DEFAULT_PRIVS_TABLES_SQL = (
    "ALTER DEFAULT PRIVILEGES FOR ROLE venya IN SCHEMA public "
    "GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES TO venya_audit"
)
DEFAULT_PRIVS_SEQUENCES_SQL = (
    "ALTER DEFAULT PRIVILEGES FOR ROLE venya IN SCHEMA public " "GRANT USAGE, SELECT ON SEQUENCES TO venya_audit"
)

# MUST stay the final statement of upgrade(): it narrows the blanket table
# grant. Audit rows are append-only for the runtime role: the app can INSERT
# (logging) and SELECT (audit API) but never UPDATE or DELETE.
REVOKE_AUDIT_SQL = "REVOKE UPDATE, DELETE ON audit_events FROM venya_audit"


def upgrade() -> None:
    op.execute(ROLE_GUARD_SQL)
    op.execute(GRANT_CONNECT_SQL)
    op.execute(GRANT_SCHEMA_SQL)
    op.execute(GRANT_TABLES_SQL)
    op.execute(GRANT_SEQUENCES_SQL)
    op.execute(DEFAULT_PRIVS_TABLES_SQL)
    op.execute(DEFAULT_PRIVS_SEQUENCES_SQL)
    op.execute(REVOKE_AUDIT_SQL)


def downgrade() -> None:
    # Honest full reversal: the role held no privileges before this
    # migration, so remove everything it was given (including the default
    # privileges), restoring the exact pre-migration grant state.
    op.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE venya IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES FROM venya_audit"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE venya IN SCHEMA public " "REVOKE USAGE, SELECT ON SEQUENCES FROM venya_audit"
    )
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM venya_audit")
    op.execute("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM venya_audit")
    op.execute("REVOKE USAGE ON SCHEMA public FROM venya_audit")
    op.execute("REVOKE CONNECT ON DATABASE venya FROM venya_audit")
