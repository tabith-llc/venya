# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""PB-597T2 — the revocation epoch counter (migration 043).

Two halves, and the split is the house split for PostgreSQL-only DDL (the ``031``/``041`` shape):

* **Statement surface** — always runs, needs no server. Pins what the DDL must say: which relations
  are watched, that the ``WHEN`` guard is on the heartbeat-bearing ones, that ``TRUNCATE`` has its own
  statement-level trigger, that the function fails CLOSED when the seed row is gone, that the lock
  bound runs before the DDL, that ``downgrade`` reverses exactly what ``upgrade`` did, and that the
  watched set equals the revocation-bearing set the ORM actually declares. That last sweep is the one
  that keeps the guarantee from narrowing in silence.
* **Behaviour** — the ``*Postgresql`` class, gated on the door variable. Applies the real ``upgrade()``
  on the real engine and then drives every write class the counter claims to cover, including the two
  negatives: a heartbeat ``UPDATE`` that must NOT advance it, and a revocation write that must be
  REFUSED once the seed row is gone.

**Why a trigger and not privileges.** ``031`` is the nearest precedent and is not one: its append-only
guarantee is made of GRANTS and a ``REVOKE UPDATE, DELETE`` that runs last. Privileges bind WHO may
write — enforceable here only by revoking the very product writes the counter must count, and powerless
against the owner role or a human at ``psql``, which is precisely the out-of-band writer #597 could not
enumerate. A trigger does not care who the authorized writer is. There is no ``CREATE TRIGGER`` anywhere
in ``packages/core/alembic/versions/`` before this revision, so this is new instrumentation in this
migration set and the claim is tested, not asserted: ``test_trigger_is_new_instrumentation_here``.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "043_revocation_epoch_597t2.py"

_PG_URL_ENV = "VENYA_TEST_PG_URL"
# One deadline, one name, shared by every PostgreSQL-gated cell (the #614 R1 posture).
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}

#: The four relations whose writes the counter must cover, as the ORM names them. Kept here as the
#: expectation and cross-checked against the migration's own WATCHED_RELATIONS, so the two lists
#: cannot drift without a red.
_EXPECTED_WATCHED = {
    "executor_cert_revocations",
    "admin_cert_revocations",
    "executors",
    "core_relay_credentials",
}


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_043", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sqlite_engine():
    """An in-memory SQLite engine with FK enforcement switched ON at connect (#634).

    043's own table has no foreign keys, so the pragma changes nothing here — but a file that builds a
    SQLite engine without it joins the blind set the #634 ratchet counts, and a blind engine is how a
    cell passes on rows no real database would accept. Cost: four lines. Benefit: this file never
    becomes the exception somebody has to reason about later.
    """
    import sqlalchemy.event as sa_event

    engine = create_engine("sqlite://")

    @sa_event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return engine


def _upgrade_source() -> str:
    return inspect.getsource(_load_migration().upgrade)


# --------------------------------------------------------------------------------
# A. THE PREMISE THE REGISTER ROW CARRIED — checked, not inherited
# --------------------------------------------------------------------------------


def test_trigger_is_new_instrumentation_here():
    """No ``CREATE TRIGGER`` exists anywhere in this migration set.

    The register row told this leg to inherit "the migration-031 pattern". It does not, and this cell
    is the proof of the departure rather than a paragraph arguing it: if a later revision adds a
    trigger and this count stops being zero, the house pattern has become triggers and the row needs
    re-reading — which is the outcome this cell exists to make loud.
    """
    versions = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    others = sorted(p for p in versions.glob("[0-9]*.py") if p.name != _MIGRATION_PATH.name)
    hits = [p.name for p in others if "create trigger" in p.read_text().lower()]
    assert hits == [_MIGRATION_PATH.name] or hits == [], f"unexpected trigger files: {hits}"
    for p in others:
        assert "create trigger" not in p.read_text().lower(), f"{p.name} carries a trigger; this cell's premise moved"


def test_031_precedent_is_privileges_not_a_trigger():
    """The named precedent's mechanism, asserted off its own file.

    So that "inherit the 031 pattern" can never again be read as "write a trigger like 031 did":
    031 never wrote one, and its guarantee is a REVOKE that runs last.
    """
    text = (_MIGRATION_PATH.parent / "031_audit_append_only_grants.py").read_text()
    assert "REVOKE UPDATE, DELETE ON audit_events" in text
    assert "ALTER DEFAULT PRIVILEGES" in text
    assert "create trigger" not in text.lower()


def test_migration_chains_to_the_head_it_found():
    mod = _load_migration()
    assert mod.revision == "043"
    assert mod.down_revision == "042"
    # Single head: exactly one revision file may claim 042 as its parent.
    versions = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    children = [p.name for p in versions.glob("[0-9]*.py") if f'down_revision = "{mod.down_revision}"' in p.read_text()]
    assert children == [_MIGRATION_PATH.name], f"{mod.down_revision} has more than one child: {children}"


# --------------------------------------------------------------------------------
# B. THE WATCHED SET — the guarantee, and the way it narrows in silence
# --------------------------------------------------------------------------------


def test_watched_relations_are_the_four_the_spec_named():
    mod = _load_migration()
    assert set(mod.WATCHED_RELATIONS) == _EXPECTED_WATCHED
    assert len(mod.WATCHED_RELATIONS) == 4


def test_watched_set_matches_the_orm_revocation_census():
    """The sweep that keeps "the counter covers revocation state" true.

    Derived from the models, not from this file's expectation: a relation is revocation-bearing if it
    carries a ``revoked_at`` column or its name ends in ``_revocations``. A FIFTH such surface added
    later — a new registry, a renamed table — fails here and forces the author to either watch it or
    say out loud why the counter does not. Without this cell the guarantee narrows silently, which is
    the same failure class as #597's uneumerable writers.
    """
    from core.iam.models import Base

    census = set()
    for table in Base.metadata.tables.values():
        if "revoked_at" in table.columns or table.name.endswith("_revocations"):
            census.add(table.name)
    mod = _load_migration()
    assert census == set(mod.WATCHED_RELATIONS), (
        f"the ORM declares revocation state on {sorted(census)} but the counter watches "
        f"{sorted(mod.WATCHED_RELATIONS)} — add the trigger, or record why not"
    )


def test_every_watched_relation_has_a_trigger_and_a_named_function():
    mod = _load_migration()
    by_relation: dict[str, list[str]] = {}
    for trigger in mod.TRIGGERS:
        assert trigger.relation in mod.WATCHED_RELATIONS, f"{trigger.name} hangs on an unwatched relation"
        assert "venya_revocation_epoch_bump()" in trigger.sql, f"{trigger.name} does not call the bump function"
        by_relation.setdefault(trigger.relation, []).append(trigger.name)
    assert set(by_relation) == set(mod.WATCHED_RELATIONS), f"unwatched: {set(mod.WATCHED_RELATIONS) - set(by_relation)}"
    assert len(mod.TRIGGERS) == 8


def test_truncate_is_covered_on_the_row_tables():
    """AC2's middle negative, pinned in DDL: a TRUNCATE fires NO row trigger.

    ``executor_cert_revocations`` is the table an operator can ``TRUNCATE`` (runbook §5 calls it
    "Never", and says so because it erases revocation history). If that statement erased the history
    and left the epoch where it was, the counter would be a floor with a hole exactly where the
    hazard is biggest. So the pair is explicit, not implied.
    """
    mod = _load_migration()
    truncate_triggers = [t for t in mod.TRIGGERS if "AFTER TRUNCATE" in t.sql]
    assert {t.relation for t in truncate_triggers} == {"executor_cert_revocations", "admin_cert_revocations"}
    for t in truncate_triggers:
        assert "FOR EACH STATEMENT" in t.sql, "TRUNCATE triggers must be statement-level or PG refuses the DDL"


def test_heartbeat_bearing_tables_guard_on_the_revocation_column():
    """The paired negative that keeps the epoch a revocation signal and not a traffic meter.

    ``executors`` is the heartbeat table — a fleet of daemons writes ``last_heartbeat`` to it every
    beat. An unguarded trigger there would advance the epoch continuously and make "has revocation
    state changed?" permanently true, which is worse than useless: PB-367 would either re-read
    constantly or learn to ignore the counter.
    """
    mod = _load_migration()
    for t in mod.TRIGGERS:
        if t.relation in ("executors", "core_relay_credentials") and "AFTER UPDATE" in t.sql:
            assert "UPDATE OF revoked_at" in t.sql, f"{t.name} fires on any column, including a heartbeat"
            assert "IS DISTINCT FROM" in t.sql, f"{t.name} has no value test, so a re-write of the same value counts"
    # And the reverse half: the row-tables must NOT be guarded, or a revocation row that never touched
    # a revoked_at column is invisible.
    for t in mod.TRIGGERS:
        if t.relation.endswith("_revocations") and "AFTER INSERT" in t.sql:
            assert "WHEN (" not in t.sql, f"{t.name} guards INSERT, which would hide revocation rows"


def test_the_row_table_triggers_fire_on_all_three_verbs():
    mod = _load_migration()
    for t in mod.TRIGGERS:
        if t.relation.endswith("_revocations") and "AFTER TRUNCATE" not in t.sql:
            assert "INSERT OR UPDATE OR DELETE" in t.sql


# --------------------------------------------------------------------------------
# C. THE MECHANISM'S OWN POSTURE — fail closed, bounded, reversible
# --------------------------------------------------------------------------------


def test_function_fails_closed_when_the_seed_row_is_gone():
    """``UPDATE ... WHERE id = 1`` matching zero rows is SILENT by default.

    Measured, not theorised: the first version of this function had no guard, and with the seed row
    deleted a real revocation INSERT answered ``INSERT 0 1`` while the counter never moved — the #597
    hole reopened by the fix for it. So the body must check ROW_COUNT and raise. This cell pins the
    clause and the recovery text, because a fail-closed path that does not tell the operator how to
    unblock it is an outage with extra steps.
    """
    mod = _load_migration()
    body = mod.BUMP_FUNCTION_SQL
    assert "GET DIAGNOSTICS" in body and "ROW_COUNT" in body
    assert "RAISE EXCEPTION" in body
    assert "is missing" in body
    assert "INSERT INTO revocation_epoch" in body, "the raise must name the restore, or the operator guesses"
    assert "Do not soften the trigger" in body, "the HINT is the guard against a future lane widening this to pass"
    assert "RETURN NULL" in body


def test_lock_bound_precedes_every_trigger_ddl_in_upgrade():
    """``CREATE TRIGGER`` takes ACCESS EXCLUSIVE — including on the liveness plane's hot table.

    Runbook §4 recorded that no migration took that lock class on ``executor_cert_revocations``; this
    revision is the first, so §3 step 2's bound is mandatory and ordering is the whole claim: a
    ``SET LOCAL`` that lands AFTER the DDL bounds nothing.
    """
    mod = _load_migration()
    src = _upgrade_source()
    assert src.index("LOCK_BOUND_SQL") < src.index("BUMP_FUNCTION_SQL")
    assert src.index("STATEMENT_BOUND_SQL") < src.index("BUMP_FUNCTION_SQL")
    assert mod.LOCK_BOUND_SQL.startswith("SET LOCAL lock_timeout")
    assert mod.STATEMENT_BOUND_SQL.startswith("SET LOCAL statement_timeout")
    # And the same discipline on the way down, which takes the same lock class.
    assert "LOCK_BOUND_SQL" in inspect.getsource(mod.downgrade)


def test_seed_insert_is_guarded_and_create_trigger_is_preceded_by_a_drop():
    src = _upgrade_source()
    assert "WHERE NOT EXISTS" in src, "an unguarded seed INSERT makes a re-run abort on the CHECK"
    assert "DROP TRIGGER IF EXISTS" in src, "a re-run after a partial failure must not die on an existing trigger"


def test_downgrade_reverses_exactly_what_upgrade_created():
    """One list, walked both ways — the walk is the contract, not a second copy of the names.

    A downgrade that names its own eight triggers can lose one to a rename while upgrade keeps
    creating it, and the orphan survives every test that only checks the table is gone.
    """
    mod = _load_migration()
    down_src = inspect.getsource(mod.downgrade)
    assert "TRIGGERS" in down_src, "downgrade must iterate the same TRIGGERS list upgrade iterates"
    assert "DROP TRIGGER IF EXISTS" in down_src and "trigger.relation" in down_src
    assert (
        "DROP FUNCTION IF EXISTS" in down_src and "FUNCTION_NAME" in down_src
    ), "downgrade must drop the function by the same name upgrade creates it"
    assert "op.drop_table(TABLE_NAME)" in down_src, "downgrade must drop the table by the shared constant"
    for name in {t.name for t in mod.TRIGGERS}:
        assert name not in down_src, f"{name} is spelled into downgrade — a second copy that can drift"


def test_model_and_migration_declare_the_same_columns():
    """Model first, migration to match — the project rule, asserted rather than promised."""
    from core.iam.models import RevocationEpoch

    mod = _load_migration()
    engine = _sqlite_engine()
    op_obj = None
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx) as operations:
            op_obj = operations
            mod.upgrade()
    cols = {c.name for c in RevocationEpoch.__table__.columns}
    assert cols == {"id", "epoch", "updated_at"}
    live = sa.inspect(engine)
    assert "revocation_epoch" in live.get_table_names()
    assert {"id", "epoch", "updated_at"} <= {c["name"] for c in live.get_columns("revocation_epoch")}
    assert op_obj is not None


def test_upgrade_on_sqlite_creates_the_table_and_never_attempts_trigger_ddl():
    """The dialect guard is load-bearing: SQLite is every dev/test venue.

    Positive control inside the cell: the same statement text is proven to be the PG-only syntax that
    would fail here, so the guard's absence would red this run rather than silently skip the DDL.
    """
    import sqlite3

    mod = _load_migration()
    engine = _sqlite_engine()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
    live = sa.inspect(engine)
    assert "revocation_epoch" in live.get_table_names()
    with engine.connect() as conn:
        rows = conn.exec_driver_sql("select id, epoch from revocation_epoch").all()
    assert rows == [(1, 0)], "the seed row the PG triggers target must exist on SQLite too"
    # The positive control: PG trigger DDL is not acceptable SQLite syntax.
    with sqlite3.connect(":memory:") as raw, pytest.raises(sqlite3.OperationalError):
        raw.execute(mod.TRIGGERS[0].sql)


def test_sqlite_downgrade_drops_the_table():
    mod = _load_migration()
    engine = _sqlite_engine()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
            mod.downgrade()
    assert "revocation_epoch" not in sa.inspect(engine).get_table_names()


def test_no_grant_statement_in_this_revision():
    """031 owns privileges, including for tables later revisions create.

    A GRANT added here would duplicate 031's default-privilege rule, and 031's own interlock forbids
    TRUNCATE/CREATE ever reaching the runtime role — so a lane "helpfully" widening it here would
    break the audit guarantee while fixing nothing.
    """
    mod = _load_migration()
    # Only DDL the database will actually execute: the Python CONSTANT NAMES contain the word
    # REVOKE (EXECUTORS_DELETE_TRIGGER sits next to trg_revocation_epoch_executors_revoke), and a
    # substring sweep over the file's text reads that as a DCL statement — a check that fires on its
    # own vocabulary is not a check.
    statements = [t.sql.strip() for t in mod.TRIGGERS] + [mod.BUMP_FUNCTION_SQL.strip()]
    for stmt in statements:
        head = stmt.splitlines()[0].upper()
        assert not head.startswith(("GRANT ", "REVOKE ")), f"DCL in a DDL revision: {head}"
        assert " GRANT " not in f" {stmt.upper()} " or "DEFAULT PRIVILEGES" in stmt.upper()
    assert all("GRANT" not in t.sql.upper().replace("EXECUTORS_REVOKE", "") for t in mod.TRIGGERS)


# --------------------------------------------------------------------------------
# D. BEHAVIOUR, ON THE ENGINE THAT RUNS THE TRIGGERS
# --------------------------------------------------------------------------------


def _watched_tables_present(conn):
    """Build the four watched relations from the ORM, so the cell runs against real columns."""
    from core.iam.models import Base

    for name in sorted(_EXPECTED_WATCHED):
        Base.metadata.tables[name].create(conn, checkfirst=True)


@pytest.mark.skipif(
    not os.environ.get(_PG_URL_ENV),
    reason=f"needs a scratch PostgreSQL in {_PG_URL_ENV} (not available on this venue)",
)
class TestRevocationEpoch043Postgresql:
    """The PG half — the engine the trigger set is written for.

    Class-named per the #614 R1 interlock: every file naming VENYA_TEST_PG_URL declares a
    *Postgresql class, because that is what the scan walks. Every engine below carries
    ``_PG_DEADLINE``, because a gated cell that opens an unbounded read transaction can pin the DDL
    this class is running.
    """

    def _scratch(self, engine, schema):
        with engine.begin() as conn:
            conn.exec_driver_sql(f"CREATE SCHEMA {schema}")
            conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
            _watched_tables_present(conn)
            ctx = MigrationContext.configure(conn)
            with Operations.context(ctx):
                _load_migration().upgrade()

    def _epoch(self, conn):
        return conn.exec_driver_sql("select epoch from revocation_epoch where id = 1").scalar()

    def test_real_upgrade_installs_eight_triggers_and_a_function(self):
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.connect() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                assert (
                    conn.exec_driver_sql(
                        "select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace "
                        "where n.nspname=current_schema() and p.proname='venya_revocation_epoch_bump'"
                    ).scalar()
                    == 1
                ), "the function did not land in the scratch schema"
                n = conn.exec_driver_sql(
                    "select count(*) from pg_trigger t join pg_class c on c.oid=t.tgrelid "
                    "join pg_namespace gn on gn.oid=c.relnamespace "
                    "where gn.nspname=current_schema() and t.tgname like %s and not t.tgisinternal",
                    ("trg_revocation_epoch%",),
                ).scalar()
                assert n == 8, f"expected 8 triggers, found {n}"
                assert self._epoch(conn) == 0
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    def test_every_write_class_advances_it_and_a_read_does_not(self):
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.begin() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                base = self._epoch(conn)

                # --- the paired NEGATIVE first: reads are not writes.
                conn.exec_driver_sql("select count(*) from executor_cert_revocations")
                conn.exec_driver_sql("select serial_number from admin_cert_revocations")
                conn.exec_driver_sql("select id, revoked_at from executors")
                assert self._epoch(conn) == base, "a SELECT advanced the epoch"

                # --- AC1 / AC2(i): out-of-band SQL, no ORM anywhere near it.
                conn.exec_driver_sql(
                    "insert into executor_cert_revocations (serial_number, revoked_at, reason) "
                    "values ('aa01', current_timestamp, 'pg cell: raw insert')"
                )
                assert self._epoch(conn) == base + 1
                conn.exec_driver_sql(
                    "insert into admin_cert_revocations (serial_number, revoked_at, reason) "
                    "values ('bb02', current_timestamp, 'pg cell: raw insert')"
                )
                assert self._epoch(conn) == base + 2

                # --- a column flip IS the revocation.
                conn.exec_driver_sql(
                    "insert into executors (id, hostname, enrolled_at) values ('e1','h1', current_timestamp)"
                )
                flip = self._epoch(conn)
                conn.exec_driver_sql("update executors set revoked_at = current_timestamp where id = 'e1'")
                assert self._epoch(conn) == flip + 1, "a revocation written to executors.revoked_at went uncounted"

                # --- the paired NEGATIVE that matters most: a heartbeat must NOT count.
                quiet = self._epoch(conn)
                conn.exec_driver_sql("update executors set last_heartbeat = current_timestamp where id = 'e1'")
                conn.exec_driver_sql("update executors set hostname = 'h2' where id = 'e1'")
                assert self._epoch(conn) == quiet, (
                    "a non-revocation UPDATE on the heartbeat table advanced the epoch — the WHEN guard "
                    "is gone or the trigger widened, and the counter is now a traffic meter"
                )

                # --- un-revoke is still a change; DELETE on a watched relation is a change.
                conn.exec_driver_sql("update executors set revoked_at = null where id = 'e1'")
                assert self._epoch(conn) == quiet + 1
                conn.exec_driver_sql("delete from executors where id = 'e1'")
                assert self._epoch(conn) == quiet + 2
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    def test_truncate_advances_it_though_no_row_trigger_fires(self):
        """AC2(ii) — the one maintenance statement that erases all revocation history."""
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.begin() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                before = self._epoch(conn)
                conn.exec_driver_sql("truncate executor_cert_revocations")
                after_trunc = self._epoch(conn)
                assert after_trunc == before + 1, (
                    "TRUNCATE did not advance the epoch — the statement-level trigger is missing or PG "
                    "rejected it; record the residual, do not paper the gap"
                )
                conn.exec_driver_sql("truncate admin_cert_revocations")
                assert self._epoch(conn) == after_trunc + 1
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    def test_the_seed_row_absence_refuses_a_revocation_write(self):
        """AC2's fail-closure, and the class the FIRST version of this function got wrong.

        With no guard, this same sequence answered ``INSERT 0 1`` and left the counter where it was —
        a revocation recorded and uncounted. The cell asserts the refusal AND that no row landed,
        because "it raised" alone would still let a partial write through.
        """
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.begin() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                conn.exec_driver_sql("delete from revocation_epoch where id = 1")
            with pytest.raises(sa.exc.DBAPIError) as excinfo:
                with engine.begin() as conn:
                    conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                    conn.exec_driver_sql(
                        "insert into executor_cert_revocations (serial_number, revoked_at, reason) "
                        "values ('refuse1', current_timestamp, 'pg cell: must be refused')"
                    )
            message = str(excinfo.value)
            assert "row 1 is missing" in message, message
            with engine.connect() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                assert (
                    conn.exec_driver_sql(
                        "select count(*) from executor_cert_revocations where serial_number='refuse1'"
                    ).scalar()
                    == 0
                ), "the write was refused but the row is there — the abort did not roll back"
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    def test_dropping_the_trigger_is_the_residual_and_it_is_silent(self):
        """AC2(iii) — demonstrate the residual, do not claim it away.

        A DBA who drops a trigger does NOT break revocation writes and gets no error: the write
        succeeds and the counter simply stops seeing that class. This cell PINS that silence as
        behaviour, so no later lane can describe the epoch as an absolute guarantee without tripping
        over a test that says otherwise. The function, by contrast, cannot be dropped quietly —
        ``DROP FUNCTION`` without CASCADE is refused by PG because the triggers depend on it, which the
        second half of this cell measures.
        """
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.begin() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                before = self._epoch(conn)
                conn.exec_driver_sql("drop trigger trg_revocation_epoch_exec_cert_rev on executor_cert_revocations")
                conn.exec_driver_sql(
                    "insert into executor_cert_revocations (serial_number, revoked_at, reason) "
                    "values ('dropped1', current_timestamp, 'pg cell: written with the guard removed')"
                )
                assert self._epoch(conn) == before, (
                    "the epoch moved on a write whose trigger was dropped — if this ever goes red, the "
                    "mechanism got stronger than the residual claims; correct §9 of the runbook as well"
                )
                assert (
                    conn.exec_driver_sql(
                        "select count(*) from executor_cert_revocations where serial_number='dropped1'"
                    ).scalar()
                    == 1
                ), "the uncounted write did not land, which would mean the residual is not silent after all"

            # The half that IS protected: PG refuses to drop the function out from under its triggers.
            with pytest.raises(sa.exc.DBAPIError) as excinfo:
                with engine.begin() as conn:
                    conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                    conn.exec_driver_sql("drop function venya_revocation_epoch_bump()")
            assert "cannot drop function" in str(excinfo.value)
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    def test_downgrade_removes_everything_upgrade_added(self):
        """AC3's other half, on the real engine: the reverse path leaves no orphan."""
        url = os.environ[_PG_URL_ENV]
        engine = create_engine(url, connect_args=_PG_DEADLINE, poolclass=NullPool)
        schema = f"t597t2_{uuid.uuid4().hex[:10]}"
        try:
            self._scratch(engine, schema)
            with engine.begin() as conn:
                conn.exec_driver_sql("select set_config('search_path', %s, false)", (schema,))
                ctx = MigrationContext.configure(conn)
                with Operations.context(ctx):
                    _load_migration().downgrade()
                assert conn.exec_driver_sql("select to_regclass('revocation_epoch')").scalar() is None
                assert (
                    conn.exec_driver_sql(
                        "select count(*) from pg_trigger t join pg_class c on c.oid=t.tgrelid "
                        "join pg_namespace gn on gn.oid=c.relnamespace "
                        "where gn.nspname=current_schema() and t.tgname like %s",
                        ("trg_revocation_epoch%",),
                    ).scalar()
                    == 0
                )
                assert (
                    conn.exec_driver_sql(
                        "select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace "
                        "where n.nspname=current_schema() and p.proname='venya_revocation_epoch_bump'"
                    ).scalar()
                    == 0
                )
                # And the watched tables survive their own guard's removal — downgrade must not touch data.
                for name in sorted(_EXPECTED_WATCHED):
                    assert conn.exec_driver_sql(f"select to_regclass('{name}')").scalar() is not None
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
