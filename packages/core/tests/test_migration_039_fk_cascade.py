# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 039 — the declared ON DELETE CASCADEs become real.

#591: ``models.py`` declared ``ondelete="CASCADE"`` on ``execution_sessions.user_id``
and ``role_members.role_id`` while the schema carried a plain FK. The clause-parity
half of that class is pinned by ``test_dropped_fk_model_drift.py``; this file pins
the revision itself:

1. the chain shape (039 hangs off 038, one head),
2. the constraint names it pins — read from the 001/025 creations, not assumed,
3. the actual PostgreSQL DDL, rendered offline through the postgresql dialect
   (``as_sql``). No database, real or scratch, is touched: what is proved here is
   the statement the migration sends,
4. the behaviour a trusting path depends on: a real FK-enforcing engine deletes the
   parent and the children go, with no admin route and no ORM cascade involved,
   plus the paired negative where the same delete is refused when the clause is
   absent.

The scratch DDL in part 4 is filled from the migrations' own ``CASCADE_FKS`` tables
(019 + 039), not from hand-written clauses, so the cell cannot quietly drift away
from the revision it is meant to prove.
"""

import importlib.util
import io
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError

_CORE_DIR = Path(__file__).resolve().parents[1]
_VERSIONS_DIR = _CORE_DIR / "alembic" / "versions"

#: The two FKs this revision repairs, as (table, column).
_REVISION_TARGETS = {("execution_sessions", "user_id"), ("role_members", "role_id")}


def _load(name: str):
    path = _VERSIONS_DIR / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _upgrade_ddl(mod) -> str:
    """Render upgrade() as PostgreSQL DDL — offline, no engine, no database."""
    buf = io.StringIO()
    ctx = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buf})
    with Operations.context(ctx):
        mod.upgrade()
    return buf.getvalue()


def _downgrade_ddl(mod) -> str:
    buf = io.StringIO()
    ctx = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buf})
    with Operations.context(ctx):
        mod.downgrade()
    return buf.getvalue()


def test_revision_039_chains_to_038():
    mod = _load("039_add_missing_fk_cascades.py")
    assert mod.revision == "039"
    assert mod.down_revision == "038"


def test_revision_targets_exactly_the_two_drifted_fks():
    mod = _load("039_add_missing_fk_cascades.py")
    targets = {(table, column) for table, _constraint, column, _ref, _ref_col in mod.CASCADE_FKS}
    assert (
        targets == _REVISION_TARGETS
    ), f"039 must carry exactly the two declared-cascade gaps #591 counted, got {sorted(targets)}"
    # refs: the clause is worthless if it points somewhere else than the model does.
    refs = {(table, column): (ref_table, ref_col) for table, _c, column, ref_table, ref_col in mod.CASCADE_FKS}
    assert refs[("execution_sessions", "user_id")] == ("users", "user_id")
    assert refs[("role_members", "role_id")] == ("roles", "id")


def test_pinned_constraint_names_are_the_inherited_ones():
    """Names read from the 001/025 definitions, not worked out by assumption.

    Both FKs were created UNNAMED — ``role_members.role_id`` as a bare
    ``sa.ForeignKeyConstraint`` at 001:57, ``execution_sessions.user_id`` as an
    inline ``sa.ForeignKey`` at 025:28 — so PostgreSQL assigned the standard
    ``{table}_{column}_fkey``. The sibling ``role_members_user_id_fkey`` created
    the same way at 001:56 is what migration 019 drops on every install today;
    018 and 022 rely on the same rule for the same two construction shapes. If
    the assumption were wrong, 019 would already have failed.
    """
    mod = _load("039_add_missing_fk_cascades.py")
    for table, constraint, column, _ref_table, _ref_col in mod.CASCADE_FKS:
        assert constraint == f"{table}_{column}_fkey", (
            f"039 pins {constraint!r} for {table}.{column}; the unnamed creations in "
            "001/025 leave PostgreSQL naming it "
            f"{table}_{column}_fkey"
        )


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_postgres_ddl_is_the_019_idiom(direction):
    """Both directions emit a drop + re-create per target, named identically.

    This is the check that the revision really sends ON DELETE CASCADE (and that
    downgrade symmetrically restores the plain form) — rendered against the
    PostgreSQL dialect, so nothing is executed anywhere.
    """
    mod = _load("039_add_missing_fk_cascades.py")
    ddl = _upgrade_ddl(mod) if direction == "upgrade" else _downgrade_ddl(mod)
    want_cascade = direction == "upgrade"

    for table, constraint, column, ref_table, ref_col in mod.CASCADE_FKS:
        drop = f"ALTER TABLE {table} DROP CONSTRAINT {constraint};"
        add_prefix = (
            f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
            f"FOREIGN KEY({column}) REFERENCES {ref_table} ({ref_col})"
        )
        assert drop in ddl, f"{direction} must drop {constraint} on {table}"
        line = next((ln for ln in ddl.splitlines() if ln.startswith(add_prefix)), None)
        assert line is not None, f"{direction} did not re-create {constraint} as rendered:\n{ddl}"
        if want_cascade:
            assert "ON DELETE CASCADE" in line, f"upgrade must carry the clause: {line}"
        else:
            assert "ON DELETE" not in line, f"downgrade must restore the plain FK: {line}"

    # exactly the two targets move — no collateral ALTERs in this revision
    assert ddl.count("DROP CONSTRAINT") == 2
    assert ddl.count("ADD CONSTRAINT") == 2


# ---------------------------------------------------------------------------
# Behaviour cell: does the clause the revision adds actually cascade?
#
# SQLite with PRAGMA foreign_keys=ON is the FK-enforcing engine here (the same
# harness test_secret_delete_fk.py uses for the opposite truth-table half). It
# is not PostgreSQL, and it is not claimed to be: what this cell proves is that
# a schema whose FK carries ON DELETE CASCADE lets a plain parent DELETE
# through, and one whose FK does not carry the clause refuses it. The PostgreSQL
# fresh-chain apply rides the installer cell, as every migration here assumes.
# ---------------------------------------------------------------------------

_PARENT_DDL = (
    "CREATE TABLE users (user_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active')",
    "CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
)

#: Slot names are "{table}.{column}" — filled from the migrations below, never
#: typed here (see _cascade_map).
_CHILD_DDL = {
    "execution_sessions": (
        "CREATE TABLE execution_sessions ("
        " id TEXT PRIMARY KEY,"
        " executor_id TEXT NOT NULL,"
        " user_id TEXT NOT NULL REFERENCES users(user_id){execution_sessions.user_id})"
    ),
    "role_members": (
        "CREATE TABLE role_members ("
        " user_id TEXT NOT NULL REFERENCES users(user_id){role_members.user_id},"
        " role_id INTEGER NOT NULL REFERENCES roles(id){role_members.role_id},"
        " PRIMARY KEY (user_id, role_id))"
    ),
}

#: Every slot the child DDL asks for, keyed "{table}.{column}".
_CHILD_SLOTS = (
    "execution_sessions.user_id",
    "role_members.user_id",
    "role_members.role_id",
)

#: The two slots migration 039 establishes — plain before it, CASCADE after.
_039_SLOTS = frozenset({"execution_sessions.user_id", "role_members.role_id"})


def _cascade_map(*, through_039: bool) -> dict[str, str]:
    """The clause each child column carries, read from the migrations themselves.

    Nothing here types a clause by hand: 019 supplies what it established, 039
    supplies its two when ``through_039`` is set, and with the flag off those two
    come out as plain FKs — the pre-039 shape. A slot no revision established is
    an assertion failure, not a silent plain FK.
    """
    revisions = ["019_add_user_fk_cascade.py"]
    if through_039:
        revisions.append("039_add_missing_fk_cascades.py")
    clauses: dict[str, str] = {}
    for name in revisions:
        mod = _load(name)
        for table, _constraint, column, _ref_table, _ref_col in mod.CASCADE_FKS:
            clauses[f"{table}.{column}"] = " ON DELETE CASCADE"

    unestablished = {slot for slot in _CHILD_SLOTS if slot not in clauses}
    expected = set() if through_039 else set(_039_SLOTS)
    assert unestablished == expected, (
        f"slots with no clause from the chain ({sorted(unestablished)}) do not match "
        f"what this shape expects ({sorted(expected)}) — the cell is not proving the schema"
    )
    clauses.update(dict.fromkeys(unestablished, ""))
    return clauses


def _fill(ddl: str, clauses: dict[str, str]) -> str:
    """Substitute every ``{table.column}`` slot with its clause.

    Handled by replace rather than str.format because the slot names contain a
    dot, which format reads as attribute access. A surviving ``{`` means a slot
    went unfilled — that fails loudly instead of shipping a silent plain FK.
    """
    for slot, clause in clauses.items():
        ddl = ddl.replace("{" + slot + "}", clause)
    if "{" in ddl:
        msg = f"scratch DDL left an unfilled FK slot: {ddl}"
        raise AssertionError(msg)
    return ddl


def _create_schema(conn, *, through_039: bool):
    clauses = _cascade_map(through_039=through_039)
    for ddl in _PARENT_DDL:
        conn.exec_driver_sql(ddl)
    for slot in _CHILD_SLOTS:
        assert slot in clauses, f"no clause established for {slot}"
    for ddl in _CHILD_DDL.values():
        conn.exec_driver_sql(_fill(ddl, clauses))
    conn.commit()


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://")

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    yield eng
    eng.dispose()


def _seed(engine):
    """One user, one role, and a child row under each of the two FKs 039 repairs."""
    with engine.connect() as conn:
        conn.exec_driver_sql("INSERT INTO users (user_id) VALUES ('u1')")
        conn.exec_driver_sql("INSERT INTO roles (id, name) VALUES (7, 'admin')")
        conn.exec_driver_sql("INSERT INTO role_members (user_id, role_id) VALUES ('u1', 7)")
        conn.exec_driver_sql("INSERT INTO execution_sessions (id, executor_id, user_id) VALUES ('s1', 'exec-1', 'u1')")
        conn.commit()


def _counts(engine):
    with engine.connect() as conn:
        return {
            "users": conn.exec_driver_sql("SELECT COUNT(*) FROM users").one()[0],
            "roles": conn.exec_driver_sql("SELECT COUNT(*) FROM roles").one()[0],
            "role_members": conn.exec_driver_sql("SELECT COUNT(*) FROM role_members").one()[0],
            "execution_sessions": conn.exec_driver_sql("SELECT COUNT(*) FROM execution_sessions").one()[0],
        }


def test_user_delete_cascades_to_execution_session_without_the_route(engine):
    """The #591 exposure: a path that TRUSTS the declared cascade, not the route.

    Plain SQL, no admin route, no ORM, no hand-ordered child deletes. Before 039
    this statement raised an FK violation for any user who had ever run a command.
    """
    with engine.connect() as conn:
        _create_schema(conn, through_039=True)
    _seed(engine)

    with engine.connect() as conn:
        conn.exec_driver_sql("DELETE FROM users WHERE user_id = 'u1'")
        conn.commit()

    assert _counts(engine) == {
        "users": 0,
        "roles": 1,  # the role itself is not the user's child — untouched
        "role_members": 0,  # goes via 019's user_id cascade
        "execution_sessions": 0,  # goes via 039's clause
    }


def test_role_delete_cascades_to_role_members(engine):
    """The second 039 target: deleting a ROLE drops its membership rows.

    ``RoleManager.delete_role`` refuses a non-empty role, so this is not the
    product path either — it is the offboarding-script path that reads the
    declaration and expects the schema to honour it.
    """
    with engine.connect() as conn:
        _create_schema(conn, through_039=True)
    _seed(engine)

    with engine.connect() as conn:
        conn.exec_driver_sql("DELETE FROM roles WHERE id = 7")
        conn.commit()

    assert _counts(engine)["role_members"] == 0
    assert _counts(engine)["execution_sessions"] == 1  # the session is the user's child, not the role's


@pytest.mark.parametrize(
    ("parent_sql", "child_table"),
    [
        ("DELETE FROM users WHERE user_id = 'u1'", "execution_sessions"),
        ("DELETE FROM roles WHERE id = 7", "role_members"),
    ],
)
def test_without_the_clause_the_same_delete_is_refused(engine, parent_sql, child_table):
    """NEGATIVE half (and harness guard): pre-039, FK enforcement really bites.

    Same engine, same seed, same statement — the only difference is that the
    clause is not there. If this ever passes silently, foreign keys are not being
    enforced and the two positive cells above prove nothing.
    """
    with engine.connect() as conn:
        _create_schema(conn, through_039=False)
    _seed(engine)

    with pytest.raises(IntegrityError):
        with engine.connect() as conn:
            conn.exec_driver_sql(parent_sql)
            conn.commit()

    assert _counts(engine)[child_table] == 1
