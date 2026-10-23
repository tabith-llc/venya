# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Migration 022 phantom-FK drift class pins.

Migration 022 dropped the FKs on executor_enrollment_tokens.created_by and
audit_events.user_id on purpose (mTLS admin identities are cert CNs with no
users row; both columns store the auth principal verbatim regardless of
mechanism). The models previously still declared those FKs — model-vs-
migration drift that makes a future autogenerate/migration diff hallucinate
re-adding a dropped-by-ruling constraint.

Two halves:

1. A pin per 022 column: the model column carries zero foreign keys.
2. A whole-class sweep: replay every ``op.drop_constraint(...,
   type_="foreignkey")`` in ``alembic/versions`` against the ``op.
   create_foreign_key`` calls that follow it, and assert no column left
   FK-free by that history is model-declared as a foreign key again. A
   future migration that drops an FK and a future model edit that re-declares
   it both fail here, loudly, without another whack-a-mole ticket.
3. Clause parity (#591): the sweep also tracks the ``ondelete`` clause of
   every foreign key the chain leaves in place — including the ones created
   inline by ``op.create_table`` — and compares it against what the model
   declares. Presence-only is how this class hid: ``execution_sessions.user_id``
   and ``role_members.role_id`` were model-declared ``CASCADE`` for months while
   the schema carried a plain FK. A future ``models.py`` edit that declares a
   clause no migration builds, or a migration that drops one the model still
   claims, fails here.
"""

import ast
import re
from pathlib import Path

import pytest
from core.iam.models import Base, ExecutorEnrollmentToken

#: packages/core — tests/ and alembic/ are siblings of it.
_CORE_DIR = Path(__file__).resolve().parents[1]
_VERSIONS_DIR = _CORE_DIR / "alembic" / "versions"


def test_executor_created_by_has_no_fk_per_migration_022():
    col = ExecutorEnrollmentToken.__table__.columns["created_by"]
    assert len(col.foreign_keys) == 0


def _revision_key(path: Path) -> tuple[int, str]:
    match = re.match(r"(\d+)", path.stem)
    return (int(match.group(1)) if match else 1 << 30, path.stem)


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _string_list(node) -> tuple[str, ...] | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [_const(elt) for elt in node.elts]
        if all(isinstance(value, str) for value in values):
            return tuple(values)
    return None


def _clause_of(node: ast.Call):
    """The literal ``ondelete`` of an FK call, or NO_CLAUSE when it carries none."""
    for keyword in node.keywords:
        if keyword.arg != "ondelete":
            continue
        value = _const(keyword.value)
        if isinstance(value, str):
            return value
        msg = (
            f"{getattr(node.func, 'attr', node.func)}: its ondelete is not a literal string, "
            "so this sweep cannot judge it — extend the parser rather than let the "
            "clause go unpinned"
        )
        raise AssertionError(msg)
    return NO_CLAUSE


def _inline_table_fks(node: ast.Call):
    """Foreign keys declared inside an ``op.create_table`` call.

    Yields ("create", columns, name, clause). Covers both house shapes:
    ``sa.ForeignKeyConstraint([...], [...], name=..., ondelete=...)`` as a
    table argument, and ``sa.Column("col", ..., sa.ForeignKey("t.c"))`` inline
    on the column. These are the creations the presence-only sweep never saw,
    which is exactly where the #591 clause drift hid.
    """
    for arg in node.args[1:]:
        if not isinstance(arg, ast.Call) or not isinstance(arg.func, ast.Attribute):
            continue
        keywords = {kw.arg: kw.value for kw in arg.keywords if kw.arg}
        if arg.func.attr == "ForeignKeyConstraint":
            columns = _string_list(arg.args[0]) if arg.args else None
            if columns is None:
                columns = _string_list(keywords.get("constrained_columns"))
            if not columns:
                continue
            name = keywords.get("name")
            yield ("create", columns, _const(name) if name is not None else None, _clause_of(arg))
        elif arg.func.attr == "Column":
            column = _const(arg.args[0]) if arg.args else None
            if not isinstance(column, str):
                continue
            for sub in arg.args[1:]:
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "ForeignKey":
                    yield ("create", (column,), None, _clause_of(sub))


def _constraint_name(node: ast.Call) -> str | None:
    if node.args:
        value = _const(node.args[0])
        if isinstance(value, str):
            return value
    for keyword in node.keywords:
        if keyword.arg == "constraint_name":
            value = _const(keyword.value)
            if isinstance(value, str):
                return value
    return None


#: An FK event carries no literal ondelete clause.
NO_CLAUSE = object()


def _fk_events(node: ast.AST, namespace: dict[str, object]):
    """Yield (kind, table, columns, constraint, clause) for one op call or for-loop.

    ``clause`` is the literal ``ondelete`` value for a ``create`` event, ``NO_CLAUSE``
    when the create carries none, and ``None`` for a drop (a drop removes whatever
    clause the column had).
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "drop_constraint":
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            if _const(keywords.get("type_")) != "foreignkey":
                return
            table = _const(node.args[1]) if len(node.args) > 1 else None
            columns = None
            if "columns" in keywords:
                columns = _string_list(keywords["columns"])
            elif len(node.args) > 2:
                one = _const(node.args[2])
                columns = (one,) if isinstance(one, str) else _string_list(node.args[2])
            yield ("drop", table, columns, _constraint_name(node), None)
            return
        if node.func.attr == "create_foreign_key":
            table = _const(node.args[1]) if len(node.args) > 1 else None
            columns = _string_list(node.args[3]) if len(node.args) > 3 else None
            if columns is None:
                for keyword in node.keywords:
                    if keyword.arg == "constrained_columns":
                        columns = _string_list(keyword.value)
            yield ("create", table, columns, _constraint_name(node), _clause_of(node))
            return
        if node.func.attr == "create_table":
            table = _const(node.args[0]) if node.args else None
            if not isinstance(table, str):
                return
            for kind, columns, name, clause in _inline_table_fks(node):
                yield (kind, table, columns, name, clause)
            return

    if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple):
        iter_name = node.iter.id if isinstance(node.iter, ast.Name) else None
        rows = namespace.get(iter_name or "")
        if not isinstance(rows, list):
            return
        # The loop body's own create clause applies to every row it creates
        # (019/039 pass ondelete="CASCADE" in the call, not in the row tuple).
        # Two different literals in one loop is not a shape this sweep can
        # attribute per-row, so it fails instead of guessing.
        loop_clauses = {
            _clause_of(child)
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "create_foreign_key"
        }
        if len(loop_clauses) > 1:
            msg = "a row loop creating more than one distinct ondelete clause — extend the parser"
            raise AssertionError(msg)
        loop_clause: object = next(iter(loop_clauses), None)
        targets = [
            # A loop target is a Name (``for table, constraint, column in ...``),
            # never a Constant — reading it through _const() made every row of
            # 019/039 invisible to this sweep.
            target.id if isinstance(target, ast.Name) else _const(target)
            for target in node.target.elts
        ]
        table_index = next((i for i, t in enumerate(targets) if t in ("table", "table_name")), None)
        column_index = next((i for i, t in enumerate(targets) if t == "column"), None)
        name_index = next(
            (i for i, t in enumerate(targets) if t in ("constraint", "constraint_name")),
            None,
        )
        if table_index is None or column_index is None:
            return
        calls = {
            call.func.attr
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        kinds = [
            kind
            for kind in ("drop", "create")
            if f"{kind}_constraint" in calls or (kind == "create" and "create_foreign_key" in calls)
        ]
        for row in rows:
            if not isinstance(row, (list, tuple)):
                continue
            table = row[table_index] if table_index < len(row) else None
            column = row[column_index] if column_index < len(row) else None
            name = row[name_index] if name_index is not None and name_index < len(row) else None
            if not isinstance(table, str) or not isinstance(column, str):
                continue
            for kind in kinds:
                clause = loop_clause if kind == "create" else None
                yield (kind, table, (column,), name if isinstance(name, str) else None, clause)


def _namespaces() -> dict[str, dict[str, object]]:
    """Module-level list constants (the loop-driven migrations) per file."""
    namespaces: dict[str, dict[str, object]] = {}
    for path in _VERSIONS_DIR.glob("*.py"):
        assignments: dict[str, object] = {}
        for node in ast.parse(path.read_text(), filename=str(path)).body:
            targets: list[str] = []
            value = None
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
                value = node.value
            if value is None or not targets:
                continue
            try:
                assignments[targets[0]] = ast.literal_eval(value)
            except (ValueError, TypeError):
                continue
        namespaces[path.name] = assignments
    return namespaces


def _resolve_columns(
    *,
    file_name: str,
    table: str,
    constraint: str | None,
    columns: tuple[str, ...] | None,
    declared: dict[str, tuple[str, tuple[str, ...]]],
) -> tuple[str, ...]:
    if columns:
        return columns
    if constraint and constraint in declared:
        declared_table, declared_columns = declared[constraint]
        if declared_table == table:
            return declared_columns
    # PostgreSQL names an inline column FK "{table}_{column}_fkey".
    if constraint and constraint.endswith("_fkey"):
        prefix = f"{table}_"
        if constraint.startswith(prefix):
            column = constraint[len(prefix) : -len("_fkey")]
            if column:
                return (column,)
    msg = (
        f"{file_name}: cannot resolve the columns of dropped foreign key "
        f"{constraint!r} on {table!r} — extend the sweep parser, do not "
        "let a dropped FK slip past the model drift check unpinned"
    )
    raise AssertionError(msg)


def _migration_fk_history() -> dict[tuple[str, str], tuple[str, object]]:
    """Per (table, column): ('dropped', None) or ('created', ondelete clause).

    Latest upgrade() wins, oldest revision replayed first. ``clause`` is the
    literal ``ondelete`` string or ``NO_CLAUSE`` when the FK is created plain —
    the half that presence-only checking could not see (#591).
    """
    namespaces = _namespaces()
    declared: dict[str, tuple[str, tuple[str, ...]]] = {}
    history: dict[tuple[str, str], tuple[str, object]] = {}
    files = sorted(_VERSIONS_DIR.glob("*.py"), key=_revision_key)

    # Pass 1: every named FK this schema ever creates, so a drop that names
    # its constraint but not its columns can still be resolved.
    for path in files:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            for kind, table, columns, name, _clause in _fk_events(node, namespaces[path.name]):
                if kind != "create" or not name or not isinstance(table, str):
                    continue
                if columns:
                    declared.setdefault(name, (table, columns))

    # Pass 2: replay upgrade() bodies oldest revision first.
    for path in files:
        tree = ast.parse(path.read_text(), filename=str(path))
        namespace = namespaces[path.name]
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name != "upgrade":
                continue
            for child in ast.walk(node):
                for kind, table, columns, name, clause in _fk_events(child, namespace):
                    if not isinstance(table, str):
                        continue
                    resolved = _resolve_columns(
                        file_name=path.name,
                        table=table,
                        constraint=name,
                        columns=columns,
                        declared=declared,
                    )
                    state = ("dropped", None) if kind == "drop" else ("created", clause)
                    for column in resolved:
                        history[(table, column)] = state
    return history


def _dropped_fk_targets() -> list[tuple[str, str]]:
    history = _migration_fk_history()
    pairs = sorted(pair for pair, (state, _clause) in history.items() if state == "dropped")
    if not pairs:
        msg = (
            "the migration sweep found no foreign key ever dropped by an "
            "upgrade — the parser or the versions directory is broken"
        )
        raise AssertionError(msg)
    return pairs


#: Columns migration history left FK-free: (table, column).
DROPPED_FK_TARGETS = _dropped_fk_targets()

_BASE_TABLES = Base.metadata.tables


@pytest.mark.parametrize(("table", "column"), DROPPED_FK_TARGETS)
def test_dropped_fk_is_absent_from_models(table: str, column: str) -> None:
    """No column migration history dropped its FK from may declare one again."""
    model_table = _BASE_TABLES[table]
    assert len(model_table.columns[column].foreign_keys) == 0


#: What the whole chain leaves in the schema per (table, column):
#: (state, ondelete clause | NO_CLAUSE). Presence alone was not enough (#591).
FK_HISTORY = _migration_fk_history()

#: Every foreign key the ORM declares, as (table, column, declared ondelete).
MODEL_FK_CLAUSES = sorted(
    (
        table.name,
        column.name,
        next(iter(column.foreign_keys)).ondelete,
    )
    for table in _BASE_TABLES.values()
    for column in table.columns
    if column.foreign_keys
)


def test_sweep_sees_every_model_foreign_key() -> None:
    """The sweep must cover the model's whole FK population, not a subset.

    A model FK the replay never produced is a parser gap: the clause check
    below would silently compare nothing for it, which is how a declared
    cascade can go unbuilt again.
    """
    unseen = [(table, column) for table, column, _clause in MODEL_FK_CLAUSES if (table, column) not in FK_HISTORY]
    assert not unseen, f"migration sweep produced no FK for model columns: {unseen}"


@pytest.mark.parametrize(("table", "column", "model_ondelete"), MODEL_FK_CLAUSES)
def test_model_declared_ondelete_clause_is_built_by_the_chain(
    table: str, column: str, model_ondelete: str | None
) -> None:
    """Clause parity: what models.py declares, the schema must actually carry.

    Both drift directions fail here — a model that declares ``CASCADE`` no
    migration ever built (the #591 case: execution_sessions.user_id and
    role_members.role_id), and a migration that leaves a clause in place the
    model no longer claims. A plain FK and a cascading one are not the same
    constraint; asserting only that a FK exists let the first sit undiscovered.
    """
    state, clause = FK_HISTORY[(table, column)]
    assert state == "created", f"{table}.{column}: model declares an FK the chain drops"
    schema_ondelete = None if clause is NO_CLAUSE else clause
    assert schema_ondelete == model_ondelete, (
        f"{table}.{column}: models.py declares ondelete={model_ondelete!r} but the "
        f"migration chain leaves {schema_ondelete!r} — the schema disagrees with the "
        "ORM, so any path that trusts the declaration (ops clear, offboarding "
        "script, customer SQL, the next seat that reads models.py) gets an FK "
        "violation instead of a cascade"
    )
