"""R1 (#614) interlock — every PostgreSQL-gated test cell carries a bounded timeout.

**Why this file exists.** The eight `*Postgresql` classes in this repo had never run on the
shipping engine (no venue sets ``VENYA_TEST_PG_URL``), and when one finally did run (#607,
s105) it hung: a read transaction left open holds an ``AccessShareLock`` on the table, the
next cell's ``DROP TABLE``/``drop_all`` asks for ``AccessExclusiveLock`` on the same table,
and with no deadline PostgreSQL waits forever. Both backends were the test process's own two
connections, so nothing external could clear it.

**What this file pins (three claims, one cell each).**

1. ``test_pg_gated_file_declares_an_inspected_class`` — every file naming the env var
   declares a ``*Postgresql`` class. Without this, the scan below could be silently blind to
   a new gated file written in some other shape.
2. ``test_every_pg_engine_in_a_gated_class_has_a_bounded_timeout`` — the deadline is in the
   source, on every PG connection the gated classes make.
3. ``test_the_timeout_option_reaches_the_driver`` — the deadline is *transmitted*: SQLAlchemy
   hands the option string to the DBAPI ``connect()`` verbatim, with a positive number behind
   it. Runs against a spy module, so it needs no server.

**What this file does NOT pin (stated so nobody over-reads it).** It proves the knob is
present and sent, not that a live server *fired* it. The firing proof needs a scratch database
and is a different instrument: seed a table, hold a conflicting ``ACCESS EXCLUSIVE`` lock from
a second connection, run the cell, and expect ``psycopg2.errors.LockNotAvailable`` ("canceling
statement due to lock timeout") in roughly ``lock_timeout`` ms instead of a hang. The #614
report records that half as NOT RUN wherever no venue existed — do not read green here as a
firing proof there.
"""

import ast
from pathlib import Path

import pytest
from sqlalchemy import create_engine

PG_ENV_VAR = "VENYA_TEST_PG_URL"
DEADLINE_NAME = "_PG_DEADLINE"

# Packages that carry PG-gated cells. executor/mcp/cli/venya-contract carry none — measured
# at the dev tip, not assumed; if one appears elsewhere, this list grows by walking the tree.
_TEST_ROOTS = ("packages/core/tests", "packages/server/tests")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _pg_gated_files() -> list[Path]:
    here = Path(__file__).resolve()
    out: list[Path] = []
    for rel in _TEST_ROOTS:
        for path in sorted((_repo_root() / rel).glob("*.py")):
            # This file names the env var in its own text and carries no PG cell: scanner,
            # not scan target.
            if path.resolve() == here:
                continue
            if PG_ENV_VAR in path.read_text(encoding="utf-8"):
                out.append(path)
    return out


def _scan_id(path: Path) -> str:
    return str(path.relative_to(_repo_root()))


def _pg_class_nodes(tree: ast.Module) -> list[ast.ClassDef]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name.endswith("Postgresql")]


def _create_engine_calls(node: ast.AST) -> list[ast.Call]:
    return [
        call
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and getattr(call.func, "id", getattr(call.func, "attr", None)) == "create_engine"
    ]


def _module_constants(tree: ast.Module) -> dict[str, object]:
    """Module-level ``NAME = <literal>`` values, so a shared option dict resolves."""
    out: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        out[target.id] = ast.literal_eval(node.value)
                    except ValueError:
                        pass
    return out


def _connect_args_value(call: ast.Call, constants: dict[str, object]) -> object:
    """The ``connect_args`` payload as a Python value, literal or named constant."""
    for kw in call.keywords:
        if kw.arg != "connect_args":
            continue
        if isinstance(kw.value, ast.Name):
            assert kw.value.id in constants, f"line {call.lineno}: connect_args={kw.value.id} is not a module literal"
            return constants[kw.value.id]
        return ast.literal_eval(kw.value)
    raise AssertionError(f"create_engine at line {call.lineno} has no connect_args")


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_pg_gated_file_declares_an_inspected_class(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert _pg_class_nodes(tree), (
        f"{path}: names {PG_ENV_VAR} but declares no *Postgresql class — this scan walks "
        "those classes, so a gated file in any other shape would be scanned and missed"
    )


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_every_pg_engine_in_a_gated_class_has_a_bounded_timeout(path: Path) -> None:
    """R1: no PG-gated cell may open an unbounded connection.

    Engines OUTSIDE the ``*Postgresql`` classes are deliberately not asserted — those are the
    SQLite harness stacks, and demanding a PostgreSQL GUC of a SQLite URL would be a wrong
    test, not a stronger one.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constants = _module_constants(tree)
    for cls in _pg_class_nodes(tree):
        for call in _create_engine_calls(cls):
            options = _connect_args_value(call, constants).get("options", "")
            assert "lock_timeout" in options, (
                f"{path}:{call.lineno} {cls.name}: no lock_timeout on a PG connection — an "
                "open read transaction pins the next cell's DDL forever (the #607 s105 hang)"
            )


def _spy_dbapi(sink: list) -> object:
    """Fake DBAPI module: records the kwargs SQLAlchemy would hand a real driver.

    ``connect`` raises ``SystemExit`` on purpose — nothing here opens a socket, and the raise
    stops SQLAlchemy before it asks a nonexistent server for anything.
    """
    import types

    def connect(**kwargs):
        sink.append(kwargs)
        raise SystemExit("spy: no connection made")

    mod = types.ModuleType("spy_pg_dbapi")
    mod.paramstyle = "pyformat"
    mod.Error = Exception
    mod.OperationalError = type("OperationalError", (Exception,), {})
    mod.DatabaseError = type("DatabaseError", (Exception,), {})
    mod.connect = connect
    return mod


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_the_timeout_option_reaches_the_driver(path: Path) -> None:
    """Wiring proof, no server needed: each gated class's options string reaches ``connect()``
    verbatim, with a real number behind the deadline."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constants = _module_constants(tree)
    for cls in _pg_class_nodes(tree):
        for call in _create_engine_calls(cls):
            connect_args = _connect_args_value(call, constants)
            options = connect_args["options"]
            for token in options.split("-c")[1:]:
                name, _, value = token.strip().partition("=")
                assert int(value.rstrip("ms").strip()) > 0, f"{path}:{call.lineno}: {name} has no real deadline"

            sink: list = []
            engine = create_engine(
                "postgresql+psycopg2://u:p@127.0.0.1:1/scratch",  # never dialled — the spy aborts
                module=_spy_dbapi(sink),
                connect_args=connect_args,
            )
            with pytest.raises(SystemExit):
                engine.connect()
            assert sink, f"{path}:{call.lineno} {cls.name}: the driver was never called"
            assert sink[0].get("options") == options, (
                f"{path}:{call.lineno} {cls.name}: driver saw {sink[0].get('options')!r}, " f"expected {options!r}"
            )


def test_the_shared_deadline_is_the_only_one():
    """One name, one value: a cell that invents its own deadline is a cell that will drift."""
    values: set[str] = set()
    for path in _pg_gated_files():
        constants = _module_constants(ast.parse(path.read_text(encoding="utf-8")))
        assert DEADLINE_NAME in constants, f"{path}: missing {DEADLINE_NAME}"
        values.add(str(constants[DEADLINE_NAME]))
    assert len(values) == 1, f"{DEADLINE_NAME} differs across files: {sorted(values)}"
