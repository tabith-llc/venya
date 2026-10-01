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


def _fk_events(node: ast.AST, namespace: dict[str, object]):
    """Yield (kind, table, columns, constraint) for one op call or for-loop."""
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
            yield ("drop", table, columns, _constraint_name(node))
            return
        if node.func.attr == "create_foreign_key":
            table = _const(node.args[1]) if len(node.args) > 1 else None
            columns = _string_list(node.args[3]) if len(node.args) > 3 else None
            if columns is None:
                for keyword in node.keywords:
                    if keyword.arg == "constrained_columns":
                        columns = _string_list(keyword.value)
            yield ("create", table, columns, _constraint_name(node))
            return

    if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple):
        iter_name = node.iter.id if isinstance(node.iter, ast.Name) else None
        rows = namespace.get(iter_name or "")
        if not isinstance(rows, list):
            return
        targets = [
            _const(target) if isinstance(target, ast.Name) else None
            for target in node.target.elts
        ]
        table_index = next(
            (i for i, t in enumerate(targets) if t in ("table", "table_name")), None
        )
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
        kinds = [kind for kind in ("drop", "create") if f"{kind}_constraint" in calls or
                 (kind == "create" and "create_foreign_key" in calls)]
        for row in rows:
            if not isinstance(row, (list, tuple)):
                continue
            table = row[table_index] if table_index < len(row) else None
            column = row[column_index] if column_index < len(row) else None
            name = row[name_index] if name_index is not None and name_index < len(row) else None
            if not isinstance(table, str) or not isinstance(column, str):
                continue
            for kind in kinds:
                yield (kind, table, (column,), name if isinstance(name, str) else None)


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


def _migration_fk_history() -> dict[tuple[str, str], str]:
    """Per (table, column): 'dropped' or 'created', latest upgrade wins."""
    namespaces = _namespaces()
    declared: dict[str, tuple[str, tuple[str, ...]]] = {}
    history: dict[tuple[str, str], str] = {}
    files = sorted(_VERSIONS_DIR.glob("*.py"), key=_revision_key)

    # Pass 1: every named FK this schema ever creates, so a drop that names
    # its constraint but not its columns can still be resolved.
    for path in files:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            for kind, table, columns, name in _fk_events(node, namespaces[path.name]):
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
                for kind, table, columns, name in _fk_events(child, namespace):
                    if not isinstance(table, str):
                        continue
                    resolved = _resolve_columns(
                        file_name=path.name,
                        table=table,
                        constraint=name,
                        columns=columns,
                        declared=declared,
                    )
                    for column in resolved:
                        history[(table, column)] = "dropped" if kind == "drop" else "created"
    return history


def _dropped_fk_targets() -> list[tuple[str, str]]:
    history = _migration_fk_history()
    pairs = sorted(pair for pair, state in history.items() if state == "dropped")
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
