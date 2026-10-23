# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Revision 043 — the revocation epoch counter (PB-597T2).

WHAT THIS ADDS. One one-row table (``revocation_epoch``) and the PostgreSQL trigger set that keeps it
moving. Revocation state is spread over four relations, not one:

===============================  =========================================  ==========================
relation                         how a revocation is expressed              trigger class added here
===============================  =========================================  ==========================
``executor_cert_revocations``    a row IS the revocation                    row + TRUNCATE
``admin_cert_revocations``       a row IS the revocation                    row + TRUNCATE
``executors``                    the ``revoked_at`` column flips            guarded row + DELETE
``core_relay_credentials``       the ``revoked_at`` column flips            guarded row + DELETE
===============================  =========================================  ==========================

WHY A COUNTER AND NOT A WRITER AUDIT. #597 closed on the admission that "raw SQL or out-of-band
revocations were not exhaustively searched". An enumeration of writers can never be finished, so it can
never be trusted. A counter asks a question that CAN be answered: has any of this changed since my last
read. This is the floor PB-367's admission check stands on; the read path, the caching and the check
itself are PB-367's work and are deliberately absent here.

MECHANISM, AND WHY IT IS NEW IN THIS MIGRATION SET. ``031_audit_append_only_grants.py`` is the
nearest-looking precedent and it is NOT one: its append-only guarantee is made of GRANTS, with
``REVOKE UPDATE, DELETE ON audit_events`` running last so it wins over the blanket grants. There is no
``CREATE TRIGGER`` anywhere in ``packages/core/alembic/versions/`` — a tree-wide grep for
``create[[:space:]]+trigger`` at ``9f18afcb`` returned zero files — so privileges are the house
instrument for a structural DB guard and **a trigger is new instrumentation here.** It is chosen anyway,
and the reason is the difference between the two problems. Privileges bind WHO may write: to be
enforced they would have to be revoked from ``venya_audit``, which forbids the very product writes this
counter must count, and they cannot bind the owner role or a human at ``psql`` at all — and a human at
``psql`` is exactly the out-of-band writer #597 could not enumerate. A trigger does not care who the
authorized writer is: it runs on every write whatever the writer's identity, which is the property an
epoch needs. So the register row's "inherit the migration-031 pattern" is answered honestly: 031's
pattern is privileges, this leg does not inherit it, and the departure is reported rather than papered.

FAIL-LOUD IS THE POSTURE, NOT A DEFECT, AND THE WORDS ARE MEASURED. The bump targets ``id = 1`` and
raises when the UPDATE matches nothing, so if that row is deleted — or the whole table is emptied by a
``TRUNCATE`` — every revocation write ABORTS: an operator cannot revoke a credential without the change
being counted, and cannot silently un-count it either. An early build of this function carried no such
clause, and with the seed row deleted a real revocation ``INSERT`` answered ``INSERT 0 1`` while the
counter never moved: the #597 hole reopened by the thing meant to close it. That history is now pinned by
a cell (``test_the_seed_row_absence_refuses_a_revocation_write``) rather than by a paragraph. Restore the
row; never make the trigger tolerant.

THE RESIDUAL THIS REVISION CANNOT CLOSE. Triggers are ordinary catalog objects — a DBA holding the
owner role can ``DROP TRIGGER`` and revocation writes then succeed uncounted, with nothing in the
schema to read back. Stated here and in ``docs/revocation-table-operations-runbook.md`` §9; the honest
sentence is that the mechanism bounds the writer CLASSES it names, not the operator who removes the
mechanism.

LOCK DISCIPLINE — READ BEFORE RUNNING THIS ON A LIVE CORE. ``CREATE TRIGGER`` takes ACCESS EXCLUSIVE on
its target table. ``executor_cert_revocations`` is read on the executor request path (heartbeat, the
per-request mTLS check, the two dial gates, the public CRL route), so this revision is the FIRST
migration to take that lock class on that table — runbook §4 recorded "No migration currently takes
ACCESS EXCLUSIVE on this table", and after this revision that sentence is a dated fact. It is bounded
the way §3 step 2 prescribes: ``SET LOCAL lock_timeout``/``statement_timeout`` ahead of every DDL, so a
blocked revision gives up on the DDL side instead of starving the fleet behind a queued lock. When it
times out the upgrade ABORTS and the DDL did not run; re-run in a maintenance window or with the daemons
halted (§5, §7). ``SET LOCAL`` dies with this transaction, so the settings leak into no session.

IDEMPOTENT-SAFE. Every ``CREATE TRIGGER`` is preceded by ``DROP TRIGGER IF EXISTS`` on the same
relation, and the seed row is a guarded ``INSERT ... WHERE NOT EXISTS``, so a re-run after a partial
failure lands the same way a first run does. ``CREATE OR REPLACE FUNCTION`` needs no guard.

DIALECT. PostgreSQL-only DDL, guarded on the bind dialect (the ``029`` precedent). SQLite — every
dev/test venue, and ``create_all`` — gets the table and its seed row from ``upgrade()`` and never the
triggers. That is why the statement surface is pinned statically (the ``031``/``041`` split) and the
BEHAVIORAL half is proven behind the PG door (``VENYA_TEST_PG_URL``).

GRANTS. No grant statement here, on purpose. ``031`` installs ``ALTER DEFAULT PRIVILEGES FOR ROLE venya
IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES TO venya_audit``, so a table
a later revision creates is reachable by the runtime role automatically — and the trigger's ``UPDATE
revocation_epoch`` runs as the writing role, which holds that privilege. Do not "helpfully" add a GRANT:
it would duplicate 031's default-privilege rule, and 031's own interlock forbids ``TRUNCATE``/``CREATE``
ever reaching the runtime role.
"""

from typing import NamedTuple

import sqlalchemy as sa
from alembic import op

revision = "043"
down_revision = "042"
branch_labels = None
depends_on = None

TABLE_NAME = "revocation_epoch"
FUNCTION_NAME = "venya_revocation_epoch_bump"

#: The single row every trigger targets. Named so this file and the interlock cannot disagree.
EPOCH_ROW_ID = 1

TABLE_COMMENT = (
    "One-row write counter for revocation state (PB-597T2); +1 per revocation write across the four "
    "relations this migration names. A value that stops moving is the signal, not a failure."
)

#: Bounded so a blocked revision fails on the DDL side instead of joining a lock convoy on the
#: liveness plane (runbook §3 step 2). These are the runbook's own worked-example values.
LOCK_BOUND_SQL = "SET LOCAL lock_timeout = '5s'"
STATEMENT_BOUND_SQL = "SET LOCAL statement_timeout = '30s'"

BUMP_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {FUNCTION_NAME}() RETURNS trigger
LANGUAGE plpgsql AS $trg$
DECLARE
    counted INTEGER;
BEGIN
    -- Reads no argument: the bump is the same whatever the write class was. RETURN NULL is the
    -- correct body for AFTER row and AFTER statement triggers alike.
    UPDATE {TABLE_NAME}
       SET epoch = epoch + 1, updated_at = CURRENT_TIMESTAMP
     WHERE id = {EPOCH_ROW_ID};
    GET DIAGNOSTICS counted = ROW_COUNT;
    IF counted = 0 THEN
        -- Fail CLOSED, and that is a measured decision rather than an assumption. Without this
        -- clause the UPDATE above matches nothing and raises NOTHING: with the seed row deleted, a real
        -- revocation INSERT answered "INSERT 0 1" — a revocation recorded while the counter stood
        -- still, which is the exact silent hole #597 conceded. A counter that can be emptied by a DELETE
        -- is not a floor. The cost is symmetrical and stated in §9 of
        -- docs/revocation-table-operations-runbook.md: with the row gone, revocation writes are REFUSED
        -- until it is restored, and the restore is the one INSERT named below.
        RAISE EXCEPTION
            'revocation_epoch row {EPOCH_ROW_ID} is missing — revocation state cannot be counted, so this write is refused. Restore it: INSERT INTO {TABLE_NAME} (id, epoch, updated_at) VALUES ({EPOCH_ROW_ID}, 0, CURRENT_TIMESTAMP)'
            USING HINT = 'This is deliberate fail-closure (PB-597T2). Do not soften the trigger to let the write through.';
    END IF;
    RETURN NULL;
END
$trg$
"""


class Trigger(NamedTuple):
    """One trigger: its name, the relation it hangs on, and the DDL that creates it."""

    name: str
    relation: str
    sql: str


# --- a row IS the revocation: fire on every write, and on the statement that erases them all.

EXECUTOR_CERT_REV_TRIGGER = Trigger(
    "trg_revocation_epoch_exec_cert_rev",
    "executor_cert_revocations",
    """
CREATE TRIGGER trg_revocation_epoch_exec_cert_rev
AFTER INSERT OR UPDATE OR DELETE ON executor_cert_revocations
FOR EACH ROW EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

EXECUTOR_CERT_REV_TRUNCATE_TRIGGER = Trigger(
    "trg_revocation_epoch_exec_cert_rev_truncate",
    "executor_cert_revocations",
    """
CREATE TRIGGER trg_revocation_epoch_exec_cert_rev_truncate
AFTER TRUNCATE ON executor_cert_revocations
FOR EACH STATEMENT EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

ADMIN_CERT_REV_TRIGGER = Trigger(
    "trg_revocation_epoch_admin_cert_rev",
    "admin_cert_revocations",
    """
CREATE TRIGGER trg_revocation_epoch_admin_cert_rev
AFTER INSERT OR UPDATE OR DELETE ON admin_cert_revocations
FOR EACH ROW EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

ADMIN_CERT_REV_TRUNCATE_TRIGGER = Trigger(
    "trg_revocation_epoch_admin_cert_rev_truncate",
    "admin_cert_revocations",
    """
CREATE TRIGGER trg_revocation_epoch_admin_cert_rev_truncate
AFTER TRUNCATE ON admin_cert_revocations
FOR EACH STATEMENT EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

# --- a COLUMN FLIP is the revocation: the WHEN guard is load-bearing, not an optimization.
# ``executors`` is the heartbeat table — an UPDATE lands on it on every beat, fleet-wide. A trigger
# without the guard would advance the epoch on TRAFFIC rather than on revocations, and a reader asking
# "did revocation state change?" would be told "yes" continuously and uselessly. DELETE is unguarded on
# purpose: a row that disappears takes its revocation state with it, which is a change to see.

EXECUTORS_REVOKE_TRIGGER = Trigger(
    "trg_revocation_epoch_executors_revoke",
    "executors",
    """
CREATE TRIGGER trg_revocation_epoch_executors_revoke
AFTER UPDATE OF revoked_at ON executors
FOR EACH ROW
WHEN (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

EXECUTORS_DELETE_TRIGGER = Trigger(
    "trg_revocation_epoch_executors_delete",
    "executors",
    """
CREATE TRIGGER trg_revocation_epoch_executors_delete
AFTER DELETE ON executors
FOR EACH ROW EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

CORE_RELAY_REVOKE_TRIGGER = Trigger(
    "trg_revocation_epoch_core_relay_revoke",
    "core_relay_credentials",
    """
CREATE TRIGGER trg_revocation_epoch_core_relay_revoke
AFTER UPDATE OF revoked_at ON core_relay_credentials
FOR EACH ROW
WHEN (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

CORE_RELAY_DELETE_TRIGGER = Trigger(
    "trg_revocation_epoch_core_relay_delete",
    "core_relay_credentials",
    """
CREATE TRIGGER trg_revocation_epoch_core_relay_delete
AFTER DELETE ON core_relay_credentials
FOR EACH ROW EXECUTE FUNCTION venya_revocation_epoch_bump()
""",
)

TRIGGERS = (
    EXECUTOR_CERT_REV_TRIGGER,
    EXECUTOR_CERT_REV_TRUNCATE_TRIGGER,
    ADMIN_CERT_REV_TRIGGER,
    ADMIN_CERT_REV_TRUNCATE_TRIGGER,
    EXECUTORS_REVOKE_TRIGGER,
    EXECUTORS_DELETE_TRIGGER,
    CORE_RELAY_REVOKE_TRIGGER,
    CORE_RELAY_DELETE_TRIGGER,
)

#: The relations whose writes this counter claims to cover. The interlock test asserts this set
#: against the ORM census, so a FIFTH revocation surface added later red-gates instead of quietly
#: narrowing the guarantee — that is the only way "the counter covers revocation state" stays true.
WATCHED_RELATIONS = ("executor_cert_revocations", "admin_cert_revocations", "executors", "core_relay_credentials")


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        TABLE_NAME,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="chk_revocation_epoch_single_row"),
        comment=TABLE_COMMENT,
    )

    # The row the triggers bump. Guarded so a re-run after a partial failure cannot create a second
    # row (the CHECK would refuse it anyway) and cannot leave the single row missing — which would
    # make every revocation write abort before it counted anything.
    op.execute(
        f"INSERT INTO {TABLE_NAME} (id, epoch, updated_at) "
        f"SELECT {EPOCH_ROW_ID}, 0, CURRENT_TIMESTAMP "
        f"WHERE NOT EXISTS (SELECT 1 FROM {TABLE_NAME} WHERE id = {EPOCH_ROW_ID})"
    )

    if not _is_postgresql():
        # SQLite dev/test venues: table and seed row only. The trigger DDL is PG syntax, and the
        # behavioral half of this revision is proven behind the PG door rather than here.
        return

    op.execute(LOCK_BOUND_SQL)
    op.execute(STATEMENT_BOUND_SQL)
    op.execute(BUMP_FUNCTION_SQL)
    for trigger in TRIGGERS:
        op.execute(f"DROP TRIGGER IF EXISTS {trigger.name} ON {trigger.relation}")
        op.execute(trigger.sql)


def downgrade() -> None:
    if _is_postgresql():
        op.execute(LOCK_BOUND_SQL)
        op.execute(STATEMENT_BOUND_SQL)
        for trigger in TRIGGERS:
            op.execute(f"DROP TRIGGER IF EXISTS {trigger.name} ON {trigger.relation}")
        op.execute(f"DROP FUNCTION IF EXISTS {FUNCTION_NAME}()")

    op.drop_table(TABLE_NAME)
