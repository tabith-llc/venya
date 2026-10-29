"""R1 (#614, #630) interlock — every PostgreSQL-gated test cell carries a bounded timeout.

**Why this file exists.** The eight `*Postgresql` classes in this repo were written before any
venue could run them on the shipping engine, and the first one that did run (#607, s105) hung:
a read transaction left open holds an ``AccessShareLock`` on the table, the next cell's ``DROP
TABLE``/``drop_all`` asks for ``AccessExclusiveLock`` on the same table, and with no deadline
PostgreSQL waits forever. Both backends were the test process's own two connections, so
nothing external could clear it.

**The gate is an opt-in URL, not a closed door.** Every class here skips on one condition:
``VENYA_TEST_PG_URL`` is unset. That is a property of the host, not of the cell — a machine
with no reachable PostgreSQL has nothing to point the variable at, so the skip is the honest
report. A venue that DOES have a reachable scratch database can and should set it and run the
cells; that is the intended state, not an exception to be apologised for. This interlock exists
to catch a gated cell that skips *silently* — one whose engine carries no deadline, or a new
file whose class the scan cannot see — and it must never be read as a claim that the door can
only ever stay shut.

**What this file pins (eight claims).**

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
8. ``test_every_pg_engine_in_a_gated_file_is_bounded_whatever_its_class_name`` (#649, blind spot
   5) — claims 1/2/5 key on the class NAME, so a PG engine written in a gated FILE from a class
   named otherwise sat outside every one of them. This claim keys on the FILE: it walks every
   ``create_engine`` in the source, exempts SQLite BY VALUE exactly as claim 4 rules, and demands
   ``lock_timeout`` of everything else — including an engine with no ``connect_args`` at all,
   which is reported as a finding rather than raised through. The site #649 names (613's
   ``TestVenueGateHonesty``, unreachable-URL cells) is now COVERED, not exempted.

Claims 2 and 3 are byte-untouched: #630 is a guard STRENGTHENING, and the class-body walk was
not relaxed to accommodate the gap — it was joined by a second walker. #649 follows the same
rule: claim 1/2/5's class-name predicate is byte-unchanged, and ``_file_engine_findings`` is a
THIRD walker over the whole module, which is why
``test_control_e_shape_is_invisible_to_the_class_name_claims`` exists — it proves the older
claims still miss the shape, so the new claim adds reach and is not a duplicate of what was
already there. Non-vacuity of 5 and 6 is
pinned IN-TREE by ``test_control_c_fixture_is_caught_by_the_helper_walk``,
``test_control_c_unbound_helper_fails_closed`` and
``test_control_d_fixture_is_caught_by_the_barrier_walk``: controls C and D are the shapes
A prior worker lane measured GREEN at s121, committed here as source text and fed to the same detector
functions the shipped claims run. Revert the helper walk or the barrier claim and those cells
fail loudly instead of quietly agreeing with the tree.

**Counts, re-derived at dev ``70e0755`` on 2026-10-17 (#630 AC4 — counts rot, so re-run this;**
``git grep -ln 'VENYA_TEST_PG_URL' -- 'packages/*/tests/*' | wc -l`` **and the scan-target count
below, then the AST tallies this file's own helpers print):** ``git grep -ln 'VENYA_TEST_PG_URL'
-- 'packages/*/tests/*'`` → 11 files, minus this scanner = 10 scan targets (a whole-tree grep
returns the same 11, and ``rglob`` over the two roots finds no extra — which is what claim 7 now
enforces); 10 ``*Postgresql`` classes; 24 gated cells inside them; **24 ``create_engine`` calls
across the 10 files — 12 PG and 12 SQLite.** All 12 PG engines sit inside a gated class body or
inside a gated FILE that the #649 file walk now reads, and every one of them is bounded — so
claims 1/2/5/8 have no work to do on the current tree and are proven by their fixtures and by the
live control C run (see the #630 report); 8 ``threading.Barrier`` constructions and 9 ``.wait()``
calls, all inside gated classes; 24 helper defs the closure binds across the 10 files, the
``MIN_BOUND_HELPERS`` floor (23) sitting one below it. This file collects 71 cells at that tip
(10 files x 6 parametrised claims + the shared-deadline cell + 1 subdirectory cell + the
non-parametrised claim, control-fixture and vacuity cells). The same
figures at the pre-re-anchor base ``59cf8ef`` were 9 files / 8 targets / 8 classes / 12 cells /
18 engines (8 PG, 10 SQLite) / 19 helper defs / 47 cells; the move is #613's gated file joining
the tree, not a count that was ever wrong.

**What this file does NOT pin (stated so nobody over-reads it).**

1. It proves the knob is present and sent, not that a live server *fired* it. The firing proof
   needs a reachable scratch database — the same opt-in URL above, pointed at it — and is a
   different instrument: seed a table, hold a conflicting ``ACCESS EXCLUSIVE`` lock from a second
   connection, run the cell, and expect ``psycopg2.errors.LockNotAvailable`` ("canceling
   statement due to lock timeout") in roughly ``lock_timeout`` ms instead of a hang. Where no
   such database was reachable the #614 report recorded that half as NOT RUN; setting the URL on
   a venue that has one is how this cell's result stops being a hypothesis — do not read green
   HERE as a firing proof there.
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
5. CLOSED at #649, was: an engine in a gated FILE whose enclosing class is NOT named
   ``*Postgresql`` read by no claim. Found re-deriving these counts at ``04eb349``: 613:299
   (``TestVenueGateHonesty``, the unreachable-URL cells) opens a real PG engine outside every
   gated class body and outside any helper a gated class reaches. It DID carry
   ``connect_args=_PG_DEADLINE`` — read at that tip, not inferred — so the tree was correct,
   but claim 2 could not see it and claim 5 did not reach it: dropping that deadline passed
   every cell in this file. **#649 closed it by COVERING the site, not by exempting it** —
   ``_file_engine_findings`` walks every ``create_engine`` in a gated file and keys on the FILE,
   not the class name, asserted by
   ``test_every_pg_engine_in_a_gated_file_is_bounded_whatever_its_class_name``. The mutation was
   run, not asserted: dropping the deadline at 613:299 (M1) and keeping ``connect_args`` but
   losing ``lock_timeout`` (M2) each redden that one cell with DISTINCT text, and
   ``test_control_e_shape_is_invisible_to_the_class_name_claims`` proves the pre-existing claims
   still cannot see this shape, so the file walk is load-bearing and not redundant.
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
# The paired negatives AC1 asks for. Controls C and D are the shapes a prior worker lane measured GREEN
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
#: Measured at dev ``04eb349``: 23 across the 9 gated files (19 across 8 at the pre-re-anchor
#: base ``59cf8ef``) — re-run ``test_the_helper_walk_is_not_vacuous_on_the_shipped_tree``.
#: Floor on the PG engines the FILE walk must classify on the shipped tree (#649 AC2 pairing).
#: Measured at dev ``70e0755``: 12 PG + 12 SQLite = 24 ``create_engine`` calls across the 10
#: gated files, every PG one already bounded — so this floor is set BELOW the measured 12 to
#: catch a classifier that starts answering "sqlite" to everything, which would report zero
#: findings and look exactly like a clean tree. Re-derive with ``test_the_file_walk_is_not_
#: vacuous_on_the_shipped_tree``.
MIN_FILE_WALK_PG_ENGINES = 8

#: Control E: the #649 escape shape — a PG engine in a gated file, in a class whose name does
#: not end in ``*Postgresql``, with the deadline dropped. Invisible to claims 1/2/5 by name.
CONTROL_E_SOURCE = '''
"""Throwaway gated file, control E shape (#649)."""
import os
from sqlalchemy import create_engine

PG_URL_ENV = "VENYA_TEST_PG_URL"
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}


class TestVenueHonestyPlainName:
    def test_one(self):
        assert create_engine(os.environ[PG_URL_ENV]) is not None
'''

#: The same file with the deadline restored — the compliant half, which must stay clean.
CONTROL_E_COMPLIANT = CONTROL_E_SOURCE.replace(
    "create_engine(os.environ[PG_URL_ENV])",
    "create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)",
)

MIN_BOUND_HELPERS = 23


def _enclosing_class(tree: ast.Module, lineno: int) -> str:
    """Innermost class holding ``lineno``, or ``"<module>"``. Names the scope in a finding so a
    reader can tell an escape (a non-``*Postgresql`` class) from an ordinary class body."""
    best = "<module>"
    best_span: tuple[int, int] = (0, 1 << 30)
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        lo = min((n.lineno for n in ast.walk(cls) if hasattr(n, "lineno")), default=cls.lineno)
        hi = max((n.lineno for n in ast.walk(cls) if hasattr(n, "lineno")), default=cls.lineno)
        if lo <= lineno <= hi and (hi - lo) < (best_span[1] - best_span[0]):
            best, best_span = cls.name, (lo, hi)
    return best


def _file_engine_findings(text: str, label: str) -> list[str]:
    """Every PG engine constructed ANYWHERE in this source that carries no ``lock_timeout``.

    #649: claims 1/2 scope the walk to ``*Postgresql`` CLASS BODIES and claim 5 follows helpers
    out of those bodies. A PG engine in a gated FILE whose enclosing class is named anything
    else is inside neither set, and the shipped tree has exactly one: 613's
    ``TestVenueGateHonesty`` opens a real PG engine per ``UNREACHABLE`` parameterisation from a
    class name the predicate never matches. Dropping that deadline was invisible to every cell
    in this guard — the escape this row names, measured at ``70e0755``: the bound removed at
    613:299 left all 57 cells green.

    This walk keys on the FILE, so it closes the hole by COVERING the site rather than by
    exempting it. Three properties it must not lose: SQLite engines stay exempt BY VALUE exactly
    as claim 4 rules (demanding a PG GUC of a SQLite URL is a wrong test); an URL the walk
    cannot resolve is answered PG by ``_url_kind``, so a name that binds nothing becomes a
    FINDING rather than a silent pass; and an engine with NO ``connect_args`` at all is the
    unbounded shape this guard exists to catch, so it is reported, not raised through —
    ``_connect_args_value`` asserts the keyword exists, which is right for the class-body claim
    (those engines all carry it today) and wrong for a walk whose whole job is to find the ones
    that do not.
    """
    tree = ast.parse(text)
    constants = _module_constants(tree)
    assigns = _file_assigns(tree)
    findings: list[str] = []
    for call in _create_engine_calls(tree):
        kind, why = _url_kind(_url_expr(call), constants, assigns)
        if kind == "sqlite":
            continue
        scope = _enclosing_class(tree, call.lineno)
        if not any(kw.arg == "connect_args" for kw in call.keywords):
            findings.append(
                f"{label}:{call.lineno} opens a PG engine ({why}) in {scope} with NO connect_args "
                f"at all (so no lock_timeout and no statement_timeout) — the #607 s105 hang "
                "shape, missed by the class-name claims"
            )
            continue
        options = _connect_args_value(call, constants).get("options", "")
        if "lock_timeout" not in options:
            findings.append(
                f"{label}:{call.lineno} opens a PG engine ({why}) in {scope} with no lock_timeout "
                f"in connect_args — the #607 s105 hang shape, missed by the class-name claims "
                "because this engine sits outside every *Postgresql body"
            )
    return findings


@pytest.mark.parametrize("path", _pg_gated_files(), ids=_scan_id)
def test_every_pg_engine_in_a_gated_file_is_bounded_whatever_its_class_name(path: Path) -> None:
    """#649 AC1: the net covers every PG engine in a gated file, not only the ones sitting in
    a class whose name ends in ``Postgresql``.

    Claim 1 bounded engines inside gated CLASS BODIES; claim 5 widened that to helpers those
    bodies call. Both still key on the class NAME, so a PG engine written in a gated file from
    a class named otherwise was unclaimed — and the code under that hole was correct, which is
    why nothing noticed. Pairing: ``test_control_e_fixture_is_caught_by_the_file_walk`` proves
    this walk can see the shape, and ``test_the_file_walk_is_not_vacuous_on_the_shipped_tree``
    proves it is not passing by inspecting nothing.
    """
    findings = _file_engine_findings(path.read_text(encoding="utf-8"), _scan_id(path))
    assert findings == [], "a PG engine in a gated file is unbounded and no class-name claim reads it:\n" + "\n".join(
        findings
    )


def test_control_e_fixture_is_caught_by_the_file_walk() -> None:
    """#649 AC2's mutation, run as a fixture so it is re-runnable rather than history.

    Control E is the 613 shape: a PG engine inside a gated file, in a class whose name does NOT
    end in ``*Postgresql``, with no deadline. It must be caught exactly once, and its compliant
    twin — the same file with ``connect_args=_PG_DEADLINE`` restored — must stay clean, so the
    walk is not simply reporting every engine it sees.
    """
    offenders = _file_engine_findings(CONTROL_E_SOURCE, "control_e.py")
    assert len(offenders) == 1, f"control E must be caught once, got {offenders}"
    assert "lock_timeout" in offenders[0] and "TestVenueHonestyPlainName" in offenders[0], offenders[0]
    assert _file_engine_findings(CONTROL_E_COMPLIANT, "control_e_ok.py") == [], "compliant control E flagged"


def test_control_e_shape_is_invisible_to_the_class_name_claims() -> None:
    """Why #649 was a real hole and not a paperwork one: the SAME source that control E reddens
    passes every pre-existing claim, because none of them enters a non-``*Postgresql`` class.

    If a future edit widens claim 1 or claim 5 until this cell reddens, that is the pair
    tightening correctly and this row's premise retiring — update this cell to say so rather
    than deleting it, because it is the proof that the file walk is not redundant.
    """
    tree = ast.parse(CONTROL_E_SOURCE)
    constants = _module_constants(tree)
    gated_classes = _pg_class_nodes(tree)
    assert gated_classes == [], "control E must carry no *Postgresql class, or it is not the escape shape"
    for cls in gated_classes:
        for call in _create_engine_calls(cls):
            if "lock_timeout" not in _connect_args_value(call, constants).get("options", ""):
                raise AssertionError("control E became visible to the class-body claim")
    resolved, unresolved = _gated_helper_closure(CONTROL_E_SOURCE, "control_e.py", None)
    assert (
        resolved == [] and unresolved == []
    ), f"control E must be outside the helper walk too, or claim 5 already covered it: {resolved, unresolved}"
    assert _file_engine_findings(
        CONTROL_E_SOURCE, "control_e.py"
    ), "the file walk is the ONLY claim that sees this shape, so it must find it"


def test_the_file_walk_is_not_vacuous_on_the_shipped_tree() -> None:
    """The green-that-proves-nothing guard, in the shape #630 AC4 already established.

    Counting FILES is not enough: a walk that classified every engine as SQLite would report
    zero findings and look identical to a healthy tree. This asserts the walk actually resolves
    PG engines on the shipped tree, at a floor, so a future classifier that starts answering
    "sqlite" to everything reddens here instead of hiding behind claim 1's green.
    """
    pg_seen = 0
    for path in _pg_gated_files():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        constants = _module_constants(tree)
        assigns = _file_assigns(tree)
        for call in _create_engine_calls(tree):
            kind, _ = _url_kind(_url_expr(call), constants, assigns)
            if kind == "pg":
                pg_seen += 1
    assert pg_seen >= MIN_FILE_WALK_PG_ENGINES, (
        f"the file walk classified only {pg_seen} PG engines across the gated files; below the "
        f"floor of {MIN_FILE_WALK_PG_ENGINES} it is reporting nothing because it sees nothing"
    )


def test_the_exemption_list_is_sqlite_by_value_and_nothing_else() -> None:
    """#649 AC3: the exemption is ASSERTED, not implied by whichever cells happen to pass.

    Two halves. (a) Every engine the file walk skips on the shipped tree skips because its URL
    resolves to a ``sqlite`` head — there is no name-based, class-based or location-based pass.
    (b) 613's ``TestVenueGateHonesty`` unreachable-URL cells are PG-dialect engines that fail at
    connect, NOT SQLite engines, and they are now inside the bound requirement rather than
    outside it: this cell names them so nobody re-exempts them by their failing behaviour.
    """
    exempt: list[str] = []
    for path in _pg_gated_files():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        constants = _module_constants(tree)
        assigns = _file_assigns(tree)
        for call in _create_engine_calls(tree):
            kind, why = _url_kind(_url_expr(call), constants, assigns)
            if kind == "sqlite":
                exempt.append(why if isinstance(why, str) else str(why))
    assert exempt, "no SQLite engine found anywhere: the exemption list is asserted against nothing"
    assert all(
        str(h).startswith("sqlite") for h in exempt
    ), f"an engine was exempt for a reason that is not a SQLite URL: {exempt}"

    site = _repo_root() / "packages" / "server" / "tests" / "test_audit_executor_id_filter_613.py"
    venue = _file_site_kinds(site)
    assert venue, f"{site}: found no engine in TestVenueGateHonesty — the site this row names is gone, update #649"
    assert all(
        k == "pg" for k, in venue
    ), f"the 613 venue-honesty cells must classify as PG-dialect engines, got {venue}"


def _file_site_kinds(path: Path) -> list[tuple[str]]:
    """The URL class of every ``create_engine`` inside ``TestVenueGateHonesty`` by name."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constants = _module_constants(tree)
    assigns = _file_assigns(tree)
    out: list[tuple[str]] = []
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "TestVenueGateHonesty"):
        for call in _create_engine_calls(cls):
            kind, _why = _url_kind(_url_expr(call), constants, assigns)
            out.append((kind,))
    return out


def test_the_scan_roots_are_not_blind_to_a_subdirectory() -> None:
    """#630 discovered-extra: ``_pg_gated_files()`` globs ``*.py``, which is NON-RECURSIVE.

    A gated file dropped into a subdirectory of either root would name the env var, be missed
    by every claim, and read exactly like a clean tree — the same silent-pass family this row
    was filed for, found while re-deriving the counts AC4 asked for. The recursive walk is the
    check; today the two agree at 9 files, and there is no subdirectory under either root
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
