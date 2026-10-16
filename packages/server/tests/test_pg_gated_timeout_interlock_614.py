"""R1 (#614, #630) interlock — every PostgreSQL-gated test cell carries a bounded timeout.

**Why this file exists.** The eight `*Postgresql` classes in this repo had never run on the
shipping engine (no venue sets ``VENYA_TEST_PG_URL``), and when one finally did run (#607,
s105) it hung: a read transaction left open holds an ``AccessShareLock`` on the table, the
next cell's ``DROP TABLE``/``drop_all`` asks for ``AccessExclusiveLock`` on the same table,
and with no deadline PostgreSQL waits forever. Both backends were the test process's own two
connections, so nothing external could clear it.

**What this file pins (seven claims).**

1. ``test_pg_gated_file_declares_an_inspected_class`` — every file naming the env var
   declares a ``*Postgresql`` class. Without this, the scan below could be silently blind to
   a new gated file written in some other shape.
2. ``test_every_pg_engine_in_a_gated_class_has_a_bounded_timeout`` — the deadline is in the
   source, on every PG connection the gated classes make.
3. ``test_the_timeout_option_reaches_the_driver`` — the deadline is *transmitted*: SQLAlchemy
   hands the option string to the DBAPI ``connect()`` verbatim, with a positive number behind
   it. Runs against a spy module, so it needs no server.
4. ``test_the_shared_deadline_is_the_only_one`` — one deadline name and value across files.
5. ``test_no_pg_engine_reached_through_a_helper_is_unbounded`` (#630, blind spot C) — claims 2
   and 3 walk the CLASS SUBTREE, so an engine opened in a module-level helper the gated class
   calls was invisible: right file, right class name, right gate, house ``_PG_DEADLINE``
   present, and the walk saw no ``create_engine`` node at all — control C passed 28/28 at s121.
   This claim walks the helper CLOSURE instead (same-file module defs, plus defs imported from
   inside the test tree) and asserts the deadline on every engine in it whose URL is PG or
   unresolvable. It FAILS CLOSED: a bare-name call the walk cannot bind at all is itself a
   finding, because "cannot see it" must never look like "saw nothing".
6. ``test_every_barrier_a_gated_cell_reaches_is_bounded`` (#630, blind spot D) — the barrier
   bounding ``82b1eb5`` added to the three core race cells was pinned by NO claim, so
   ``threading.Barrier(2)`` plus a bare ``barrier.wait()`` (an unbounded rendezvous) passed the
   interlock. Two bounding shapes are accepted because both ARE bounded and the tree ships
   both: a constructor ``timeout=`` (five files), or a ``timeout=`` on every ``.wait()`` of the
   bound name (files 510 and 511). Dropping either form now turns red.
7. ``test_the_scan_roots_are_not_blind_to_a_subdirectory`` (#630 discovered-extra) —
   ``_pg_gated_files()`` globs ``*.py``, which is NON-RECURSIVE, so a gated file dropped into a
   subdirectory of either root would be read by nothing and still report a clean tree. The claim
   compares the glob against a recursive walk.

Claims 2 and 3 are byte-untouched: #630 is a guard STRENGTHENING, and the class-body walk was
not relaxed to accommodate the gap — it was joined by a second walker. Non-vacuity of 5 and 6 is
pinned IN-TREE by ``test_control_c_fixture_is_caught_by_the_helper_walk``,
``test_control_c_unbound_helper_fails_closed`` and
``test_control_d_fixture_is_caught_by_the_barrier_walk``: controls C and D are the shapes
``flash5`` measured GREEN at s121, committed here as source text and fed to the same detector
functions the shipped claims run. Revert the helper walk or the barrier claim and those cells
fail loudly instead of quietly agreeing with the tree.

**Counts, re-derived at dev ``59cf8ef`` on 2026-10-15 (#630 AC4 — counts rot, so re-run this):**
``git grep -ln 'VENYA_TEST_PG_URL' -- 'packages/*/tests/*'`` → 9 files, minus this scanner = 8
scan targets (a whole-tree grep returns the same 9, and ``rglob`` over the two roots finds no
extra — which is what claim 7 now enforces); 8 ``*Postgresql`` classes; 12 gated cells inside
them; 18 ``create_engine`` calls across the 8 files — 8 PG (one per gated class, every one of
them inside a class body today) and 10 SQLite, so claim 5 has no work to do on the current tree
and is proven by its fixtures and by the live control C run (see the #630 report);
7 ``threading.Barrier`` constructions and 8 ``.wait()`` calls, all inside gated classes; 19
helper defs the closure binds across the 8 files, the ``MIN_BOUND_HELPERS`` floor. This file
collects 47 cells at that tip (8 files x 5 parametrised claims + the shared-deadline cell + 1
subdirectory cell + 5 non-parametrised cells).

**What this file does NOT pin (stated so nobody over-reads it).**

1. It proves the knob is present and sent, not that a live server *fired* it. The firing proof
   needs a scratch database and is a different instrument: seed a table, hold a conflicting
   ``ACCESS EXCLUSIVE`` lock from a second connection, run the cell, and expect
   ``psycopg2.errors.LockNotAvailable`` ("canceling statement due to lock timeout") in roughly
   ``lock_timeout`` ms instead of a hang. The #614 report records that half as NOT RUN wherever
   no venue existed — do not read green here as a firing proof there.
2. PRODUCT imports are NOT walked. A gated cell that reaches its engine through product code
   (``Backend(BackendConfig(database_url=...))``, which 512 and 513 also do alongside their own
   bounded engine) arrives at a connection this guard cannot read. That is the shape #630 leaves
   open, named here rather than papered over; a helper inside the TEST tree IS walked (claim 5).
3. A barrier bound to something other than a plain name (``self.barrier =
   threading.Barrier(2)`` with a bare ``wait()``) is reported as unprovable rather than
   skipped — but a ``.wait()`` reached through an alias this walk does not follow is not.
4. SQLite engines are exempt BY VALUE wherever they sit, including inside a helper: demanding a
   PostgreSQL GUC of a SQLite URL would be a wrong test, not a stronger one. That exemption is
   exercised by ``test_control_sqlite_helper_stays_exempt`` so it cannot be quietly widened.
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


# -------------------------------------------------------------------------------------
# #630 — the class-body subtree is not the only place a gated cell can get an engine, and
# a Barrier is not an engine but hangs the very same way. The two functions below are the
# detectors claims 5 and 6 run; they take SOURCE TEXT, not a path, so the committed control
# fixtures at the bottom of this file feed them the exact shapes that were green at s121
# (control C: engine behind a module-level helper; control D: `Barrier(2)` + bare `wait()`).
# Revert either detector and those cells go red — that is the #630 AC1 requirement.
# Claims 2 and 3 above are byte-untouched.
# -------------------------------------------------------------------------------------

#: `threading.Barrier(parties, action=None, timeout=None)` — timeout is the 3rd positional.
_BARRIER_TIMEOUT_ARG = 2
#: `Barrier.wait(timeout=None)` — timeout is the 1st positional.
_WAIT_TIMEOUT_ARG = 0

_IMPORT_STASH: dict[Path, ast.Module | None] = {}


def _parse_cached(path: Path) -> ast.Module | None:
    if path not in _IMPORT_STASH:
        try:
            _IMPORT_STASH[path] = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            _IMPORT_STASH[path] = None
    return _IMPORT_STASH[path]


def _url_expr(call: ast.Call) -> ast.expr | None:
    """The URL argument of a ``create_engine`` call, positional or ``url=``."""
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _file_assigns(tree: ast.Module) -> dict[str, ast.expr]:
    """Every ``NAME = <expr>`` in the file, so a ``db_url`` alias resolves to its URL."""
    out: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.setdefault(target.id, node.value)
    return out


def _names_the_env_var(expr: ast.expr, constants: dict[str, object]) -> bool:
    """True when ``expr`` names the PostgreSQL URL env var, directly or as a module constant."""
    name: object
    if isinstance(expr, ast.Name):
        name = expr.id
    elif isinstance(expr, ast.Constant):
        name = expr.value
    else:
        return False
    return isinstance(name, str) and (name == PG_ENV_VAR or constants.get(name) == PG_ENV_VAR)


def _url_kind(
    expr: ast.expr | None, constants: dict[str, object], assigns: dict[str, ast.expr], depth: int = 0
) -> tuple[str, str]:
    """Classify an engine URL as ``("pg"|"sqlite", why)``.

    UNRESOLVABLE IS ANSWERED "pg", NOT SKIPPED. An unbounded PG connection is the whole
    failure this guard exists to prevent, and "probably it is the SQLite harness" is exactly
    the guess that left control C green at s121. Only a URL that resolves to a ``sqlite://``
    literal or f-string prefix is exempt — and that exemption is what keeps claim 5 from
    demanding a PostgreSQL GUC of a SQLite stack, which would be a wrong test, not a strong one.
    """
    if expr is None:
        return "pg", "create_engine with no URL argument"
    if depth > 6:
        return "pg", "URL chain too deep to resolve"
    if isinstance(expr, ast.Name):
        target = assigns.get(expr.id)
        if target is None:
            return "pg", f"{expr.id} is not assigned in this file"
        return _url_kind(target, constants, assigns, depth + 1)
    if isinstance(expr, ast.Subscript):
        if _names_the_env_var(expr.slice, constants):
            return "pg", f"os.environ[{PG_ENV_VAR}]"
        return "pg", "os.environ of a key this walk cannot resolve"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "get" and expr.args:
        if _names_the_env_var(expr.args[0], constants):
            return "pg", f"os.environ.get({PG_ENV_VAR})"
        return "pg", "os.environ.get() of a key this walk cannot resolve"
    head: object = None
    if isinstance(expr, ast.Constant):
        head = expr.value
    elif isinstance(expr, ast.JoinedStr) and expr.values:
        first = expr.values[0]
        head = first.value if isinstance(first, ast.Constant) else None
    if not isinstance(head, str):
        return "pg", f"unresolvable URL expression {ast.unparse(expr)!r}"
    if head.startswith("postgres"):
        return "pg", head
    if head.startswith("sqlite"):
        return "sqlite", head
    return "pg", f"URL {head!r} names neither postgres nor sqlite"


def _timeout_resolves_positive(call: ast.Call, constants: dict[str, object], positional_index: int) -> bool:
    """True when ``call`` carries a ``timeout=`` (or its positional form) that resolves > 0."""
    value: ast.expr | None = None
    for kw in call.keywords:
        if kw.arg == "timeout":
            value = kw.value
    if value is None and len(call.args) > positional_index:
        value = call.args[positional_index]
    if value is None:
        return False
    resolved: object = None
    if isinstance(value, ast.Constant):
        resolved = value.value
    elif isinstance(value, ast.Name):
        resolved = constants.get(value.id)
    return isinstance(resolved, (int, float)) and not isinstance(resolved, bool) and resolved > 0


def _module_defs(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
    """Module-level functions and classes by name — the helpers a gated class can call."""
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def _import_map(tree: ast.Module) -> dict[str, tuple[str | None, str, int]]:
    """Local name -> (module, imported attribute, import level), for test-tree resolution."""
    out: dict[str, tuple[str | None, str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                out[a.asname or a.name] = (node.module, a.name, node.level)
        elif isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = (a.name, "", 0)
    return out


def _bound_names(scope: ast.AST) -> set[str]:
    """Names ``scope`` binds itself: params, assignments, nested defs, imports, handlers."""
    out: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                out.add(a.arg)
            if node.args.vararg:
                out.add(node.args.vararg.arg)
            if node.args.kwarg:
                out.add(node.args.kwarg.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            out.add(node.id)
        elif isinstance(node, ast.alias):
            out.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
    return out


def _test_tree_target(module: str | None, attr: str, level: int, base_dir: Path | None) -> Path | None:
    """The file a ``tests``-tree import points at, or None when the import leaves the roots.

    Product and third-party imports are NOT walked (limitation 2 in the module docstring): a
    gated cell that reaches its engine through ``core``/``server`` is the shape #630 leaves
    open, and naming it here beats pretending the walk sees it.
    """
    if base_dir is None:
        return None
    parts = module.split(".") if module else []
    while parts and parts[0] == "":
        parts = parts[1:]
    if level:
        base = base_dir
        for _ in range(level - 1):
            base = base.parent
        tail = parts
    elif parts and parts[0] == "tests" and len(parts) > 1:
        tail = parts[1:]
        base = base_dir
    else:
        return None
    if not tail and attr:
        tail = [attr]
    if not tail:
        return None
    for probe in (base.joinpath(*tail).with_suffix(".py"), base.joinpath(*tail) / "__init__.py"):
        if probe.is_file():
            return probe
    return None


def _gated_helper_closure(
    text: str, label: str, base_dir: Path | None = None
) -> tuple[list[tuple[str, ast.AST, str, ast.Module]], list[str]]:
    """(resolved helper nodes, unresolvable-call findings) reachable from ``*Postgresql`` classes.

    Breadth-first from every gated class in this source, following bare-name calls into
    module-level defs of the same file and into defs of modules the import resolves to INSIDE
    the test tree. Visited-set bounded, so a mutual recursion cannot loop. A bare-name call
    that binds to nothing at all — not a module def, not an import, not a local name, not a
    builtin — is a FINDING, not a skip: that is the fail-closed half of #630 AC2.
    """
    tree = ast.parse(text)
    builtins_names = set(dir(__import__("builtins")))
    parsed: dict[str, ast.Module] = {label: tree}
    resolved: list[tuple[str, ast.AST, str, ast.Module]] = []
    findings: list[str] = []
    seen: set[tuple[str, str]] = set()
    queue: list[tuple[str, ast.AST, Path | None, str]] = [
        (label, cls, base_dir, f"{cls.name} class body") for cls in _pg_class_nodes(tree)
    ]
    while queue:
        cur_label, node, cur_base, why = queue.pop(0)
        cur_tree = parsed.get(cur_label) or tree
        defs = _module_defs(cur_tree)
        imports = _import_map(cur_tree)
        local = _bound_names(node)
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            name = call.func.id
            if name in defs:
                if (cur_label, name) not in seen:
                    seen.add((cur_label, name))
                    resolved.append((cur_label, defs[name], f"{why} -> {name}()", cur_tree))
                    queue.append((cur_label, defs[name], cur_base, f"{why} -> {name}()"))
                continue
            if name in imports:
                # Imports are tried BEFORE the local-name skip: an import statement inside a
                # class body binds the name locally too (511 does exactly this), and answering
                # "local" there would be the silent pass this claim exists to close.
                module, attr, level = imports[name]
                target = _test_tree_target(module, attr, level, cur_base)
                if target is None:
                    continue  # product / third-party import: not walked (limitation 2)
                ttree = _parse_cached(target)
                tlabel = str(target.relative_to(_repo_root())) if target.is_relative_to(_repo_root()) else str(target)
                if ttree is None:
                    findings.append(
                        f"{cur_label}:{call.lineno}: {name} resolves to {target}, which this walk cannot parse "
                        f"— fail-closed, not silent-pass ({why})"
                    )
                    continue
                parsed.setdefault(tlabel, ttree)
                tdef = _module_defs(ttree).get(attr)
                if tdef is None:
                    findings.append(
                        f"{cur_label}:{call.lineno}: {name} ({module}.{attr}) is not a module-level def of "
                        f"{tlabel}, so its engines are invisible to this walk ({why})"
                    )
                    continue
                if (tlabel, attr) not in seen:
                    seen.add((tlabel, attr))
                    resolved.append((tlabel, tdef, f"{why} -> import {name} from {tlabel}", ttree))
                    queue.append((tlabel, tdef, target.parent, f"{why} -> import {name} from {tlabel}"))
                continue
            if name in local or name in builtins_names:
                continue
            findings.append(
                f"{cur_label}:{call.lineno}: call to {name}() binds to nothing this walk can follow — it may "
                f"open a PG engine and claim 5 cannot see it ({why})"
            )
    return resolved, findings


def _helper_engine_findings(text: str, label: str, base_dir: Path | None = None) -> list[str]:
    """Every unbounded PG engine reached from a gated class through a HELPER, plus complaints.

    Engines whose node sits inside a ``*Postgresql`` class body are claims 2/3's business and
    are skipped here, so the same call is never reported under two different messages.
    """
    tree = ast.parse(text)
    constants = _module_constants(tree)
    assigns = _file_assigns(tree)
    class_calls = {id(c) for cls in _pg_class_nodes(tree) for c in _create_engine_calls(cls)}
    out: list[str] = []
    resolved, unresolved = _gated_helper_closure(text, label, base_dir)
    out.extend(unresolved)
    for hlabel, node, why, htree in resolved:
        hconsts = constants if hlabel == label else _module_constants(htree)
        hassigns = assigns if hlabel == label else _file_assigns(htree)
        for call in _create_engine_calls(node):
            if id(call) in class_calls:
                continue
            kind, reason = _url_kind(_url_expr(call), hconsts, hassigns)
            if kind == "sqlite":
                continue
            try:
                options = _connect_args_value(call, hconsts).get("options", "")
            except (AssertionError, AttributeError, TypeError, ValueError) as exc:
                out.append(
                    f"{hlabel}:{call.lineno} [{why}]: the engine this helper hands a gated cell has no "
                    f"readable connect_args ({exc}) — {reason}"
                )
                continue
            if "lock_timeout" not in options:
                out.append(
                    f"{hlabel}:{call.lineno} [{why}]: no lock_timeout on a PG connection reached from a gated "
                    f"class through a helper ({reason}) — the #607 s105 hang shape, invisible to the "
                    f"class-body walk"
                )
    return out


def _barrier_findings(text: str, label: str, base_dir: Path | None = None) -> list[str]:
    """Every ``threading.Barrier`` a gated class (or a helper it calls) constructs unbounded.

    Two shapes are accepted because both are bounded, and the shipped tree uses both: the
    constructor carries ``timeout=`` (five files), or every ``.wait()`` on the bound name does
    (files 510 and 511). A drop of EITHER form turns this red, which is the point — control D
    at s121 passed with neither.
    """
    tree = ast.parse(text)
    constants = _module_constants(tree)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    scopes: list[tuple[str, ast.AST, str, dict[str, object]]] = [
        (label, cls, cls.name, constants) for cls in _pg_class_nodes(tree)
    ]
    resolved, _unresolved = _gated_helper_closure(text, label, base_dir)
    for hlabel, node, why, htree in resolved:
        scopes.append((hlabel, node, f"helper {why}", _module_constants(htree)))
    out: list[str] = []
    for scope_label, scope, where, consts in scopes:
        for call in ast.walk(scope):
            if not isinstance(call, ast.Call):
                continue
            fname = getattr(call.func, "attr", None) or (call.func.id if isinstance(call.func, ast.Name) else None)
            if fname != "Barrier":
                continue
            if _timeout_resolves_positive(call, consts, _BARRIER_TIMEOUT_ARG):
                continue
            parent = parents.get(call)
            target = parent.targets[0] if isinstance(parent, ast.Assign) and parent.targets else None
            name = target.id if isinstance(target, ast.Name) else None
            waits = [
                w
                for w in ast.walk(scope)
                if isinstance(w, ast.Call)
                and isinstance(w.func, ast.Attribute)
                and w.func.attr == "wait"
                and isinstance(w.func.value, ast.Name)
                and name is not None
                and w.func.value.id == name
            ]
            if name is None:
                out.append(
                    f"{scope_label}:{call.lineno} {where}: a Barrier with no constructor timeout is not bound to "
                    "a plain name, so no bounded .wait() can be traced to it — unbounded as far as this walk can "
                    "prove (control D)"
                )
            elif not waits:
                out.append(
                    f"{scope_label}:{call.lineno} {where}: Barrier({name}) has no constructor timeout and no "
                    f".wait() bound to it in this scope — an unbounded rendezvous is a hang (control D)"
                )
            for w in waits:
                if not _timeout_resolves_positive(w, consts, _WAIT_TIMEOUT_ARG):
                    out.append(
                        f"{scope_label}:{w.lineno} {where}: {name}.wait() has no bounded timeout and the Barrier "
                        f"at :{call.lineno} carries none — a peer that dies before the release hangs this cell "
                        "forever (control D)"
                    )
    return out


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


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_no_pg_engine_reached_through_a_helper_is_unbounded(path: Path) -> None:
    """#630 blind spot C (control C): the engine may not sit in a helper the walk skips.

    Claims 2 and 3 walk the CLASS SUBTREE, so an unbounded PG connection opened by a
    module-level helper the gated class calls was invisible — 28/28 green at s121 with the
    engine one stack frame away from the class that runs it. This claim walks the helper
    CLOSURE instead, and it FAILS CLOSED: a bare-name call the walk cannot bind at all is a
    finding, because "cannot see it" and "saw nothing" must never look the same to a guard.

    SQLite URLs are exempt by value, not by location — see ``_url_kind``.
    """
    findings = _helper_engine_findings(path.read_text(encoding="utf-8"), _scan_id(path), path.parent)
    assert not findings, "a gated cell reaches an unbounded PG engine through a helper:\n" + "\n".join(findings)


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_every_barrier_a_gated_cell_reaches_is_bounded(path: Path) -> None:
    """#630 blind spot D (control D): the barrier bounding 82b1eb5 added is now pinned.

    ``threading.Barrier(2)`` with a bare ``barrier.wait()`` has no deadline anywhere: a peer
    that dies before the release hangs the cell forever, exactly the #607 shape but on the
    thread side instead of the lock side. At s121 that file passed the interlock 28/28,
    because no claim looked at barriers at all.
    """
    findings = _barrier_findings(path.read_text(encoding="utf-8"), _scan_id(path), path.parent)
    assert not findings, "a gated cell reaches an unbounded Barrier:\n" + "\n".join(findings)


# -------------------------------------------------------------------------------------
# The paired negatives AC1 asks for. Controls C and D are the shapes flash5 measured GREEN
# at s121 (28/28) — they are reproduced here as committed source, fed to the same detector
# functions the two claims above run, and required to be caught. Revert the helper walk or
# the barrier claim and these cells fail loudly rather than quietly agreeing with the tree.
# -------------------------------------------------------------------------------------

#: Control C verbatim in shape: right file, right class name, right gate, house
#: ``_PG_DEADLINE`` present — and the engine opened one frame away, in a module-level helper.
CONTROL_C_SOURCE = '''
"""Throwaway gated file, control C shape (#630)."""
import os
from sqlalchemy import create_engine

PG_URL_ENV = "VENYA_TEST_PG_URL"
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


def _pg_engine():
    return create_engine(os.environ[PG_URL_ENV], connect_args={"options": "-c statement_timeout=60000"})


class TestControlCPostgresql:
    def test_one(self):
        assert _pg_engine() is not None
'''

#: The same file with the deadline on the helper's engine — the compliant half of control C.
CONTROL_C_COMPLIANT = CONTROL_C_SOURCE.replace(
    'connect_args={"options": "-c statement_timeout=60000"}',
    "connect_args=_PG_DEADLINE",
)

#: Control D verbatim in shape: compliant on every prior claim, with an unbounded rendezvous.
CONTROL_D_SOURCE = '''
"""Throwaway gated file, control D shape (#630)."""
import threading

PG_URL_ENV = "VENYA_TEST_PG_URL"
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


class TestControlDPostgresql:
    def test_one(self):
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()

        run()
'''

#: Control D bounded the way five shipped files do it — the constructor carries the timeout.
CONTROL_D_CTOR_BOUNDED = CONTROL_D_SOURCE.replace("threading.Barrier(2)", "threading.Barrier(2, timeout=10)")

#: Control D bounded the way files 510 and 511 do it — each wait carries the timeout.
CONTROL_D_WAIT_BOUNDED = CONTROL_D_SOURCE.replace("barrier.wait()", "barrier.wait(timeout=10)")

#: A gated class that reaches an engine through a name bound nowhere: the fail-closed half.
#: Only the CALL site is renamed — renaming the def too would leave the call resolvable and
#: the cell would prove nothing.
CONTROL_UNBOUND_SOURCE = CONTROL_C_SOURCE.replace(
    "assert _pg_engine() is not None", "assert _not_defined_anywhere() is not None"
)

#: Floor on the helper defs the closure must bind across the gated files. A drop here means the
#: closure stopped FOLLOWING calls, and claim 5 would then pass by seeing nothing (#630 AC4).
#: Measured at dev ``59cf8ef``: 19 across the 8 gated files.
MIN_BOUND_HELPERS = 19


def test_the_scan_roots_are_not_blind_to_a_subdirectory() -> None:
    """#630 discovered-extra: ``_pg_gated_files()`` globs ``*.py``, which is NON-RECURSIVE.

    A gated file dropped into a subdirectory of either root would name the env var, be missed
    by every claim, and read exactly like a clean tree — the same silent-pass family this row
    was filed for, found while re-deriving the counts AC4 asked for. The recursive walk is the
    check; today the two agree at 8 files, and there is no subdirectory under either root
    (``packages/executor/tests/helpers/`` is the only tests subdir in the repo and executor
    carries no PG-gated cell).
    """
    flat = {p.resolve() for p in _pg_gated_files()}
    deep: set[Path] = set()
    for rel in _TEST_ROOTS:
        for path in sorted((_repo_root() / rel).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            if PG_ENV_VAR in path.read_text(encoding="utf-8"):
                deep.add(path.resolve())
    assert deep == flat, (
        f"the scan globs {sorted(str(x.relative_to(_repo_root())) for x in flat)} but the recursive walk finds "
        f"{sorted(str(x.relative_to(_repo_root())) for x in deep)} — a gated file the claims never read"
    )


def test_the_helper_walk_is_not_vacuous_on_the_shipped_tree() -> None:
    """The negative half of claim 5 proven on the real tree, not only on a fixture.

    Counts BOUND HELPER NODES, not findings: zero findings over a closure that resolved
    nothing is the green-that-proves-nothing case this row was filed to prevent.
    """
    bound = 0
    for path in _pg_gated_files():
        text = path.read_text(encoding="utf-8")
        resolved, unresolved = _gated_helper_closure(text, _scan_id(path), path.parent)
        assert not unresolved, f"{path}: the closure could not bind: {unresolved}"
        bound += len(resolved)
    assert bound >= MIN_BOUND_HELPERS, (
        f"the helper closure bound {bound} defs across {_pg_gated_files()} gated files; the walk "
        f"that binds nothing reports nothing and claim 5 becomes decoration"
    )


def test_control_c_fixture_is_caught_by_the_helper_walk() -> None:
    """#630 AC1: the control C shape, green at s121, is now a named failure — and its
    compliant twin is not, so the detector is not simply reporting every engine it sees."""
    offenders = _helper_engine_findings(CONTROL_C_SOURCE, "control_c.py")
    assert len(offenders) == 1, f"control C must be caught once, got {offenders}"
    assert "lock_timeout" in offenders[0] and "_pg_engine" in offenders[0], offenders[0]
    assert _helper_engine_findings(CONTROL_C_COMPLIANT, "control_c_ok.py") == [], "compliant helper flagged"


def test_control_c_unbound_helper_fails_closed() -> None:
    """The 'or' half of AC2: a call the walk cannot bind is a FINDING, never a silent pass."""
    offenders = _helper_engine_findings(CONTROL_UNBOUND_SOURCE, "control_unbound.py")
    assert any("binds to nothing this walk can follow" in o for o in offenders), offenders


def test_control_d_fixture_is_caught_by_the_barrier_walk() -> None:
    """#630 AC1: the control D shape, green at s121, is now a named failure — and BOTH
    bounding forms the shipped tree uses stay clean, so 510/511 do not go red for style."""
    offenders = _barrier_findings(CONTROL_D_SOURCE, "control_d.py")
    assert len(offenders) == 1, f"control D must be caught once, got {offenders}"
    assert "barrier.wait()" in offenders[0] or "wait() has no bounded timeout" in offenders[0], offenders[0]
    assert _barrier_findings(CONTROL_D_CTOR_BOUNDED, "control_d_ctor.py") == [], "constructor form flagged"
    assert _barrier_findings(CONTROL_D_WAIT_BOUNDED, "control_d_wait.py") == [], "per-wait form flagged"


def test_control_sqlite_helper_stays_exempt() -> None:
    """The exemption is by VALUE, not by location: a helper handing a gated cell a SQLite
    engine is not this guard's business, and the claim must not pretend otherwise."""
    src = CONTROL_C_SOURCE.replace(
        'os.environ[PG_URL_ENV], connect_args={"options": "-c statement_timeout=60000"}',
        '"sqlite://"',
    )
    offenders = _helper_engine_findings(src, "control_sqlite.py")
    assert offenders == [], f"a SQLite helper engine was demanded a PG GUC: {offenders}"
