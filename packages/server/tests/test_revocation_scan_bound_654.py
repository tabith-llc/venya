# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#654 / #656 — the SCAN half of the bounded revocation read, both halves of the truth table.

#603 AC1 bounded the LOCK WAIT. This file judges the row shape A did not cover: a revocation read
that is merely SLOW. ``lock_timeout`` says nothing about how long a statement may run once it HOLDS
the lock, so the only ceiling on a read's execution time was the session-wide
``SET statement_timeout = '300s'`` the engine's connect listener installs — five hundred times the
read's own budget, and the fault it hides raises nothing at all.

THE FOURTH STATE, named, because it is the reason no counter can ever find it. A 12 s revocation read
SUCCEEDS. There is no exception to classify, so nothing refuses, nothing counts and nothing logs —
and the executor that polls the route has already gone: its bound is
``NetworkConfig.request_timeout_seconds`` = 10 s, so the caller records a FAILURE while the core
records a 200. ``crl.revocation_read_scan_timeout_ms`` (2 000 ms default, ceiling 10 s = that same
caller patience) makes that state UNREACHABLE above the bound — the read is cancelled and refused in
the named class — and the duration histogram makes anything that still answers under the bound an
OBSERVATION rather than an absence.

What the cells pin, in order:

* THE BOUND EXISTS AND BITES — both deadline statements inside the one savepoint, captured in the
  right order, and cells that go RED the moment either ``SET LOCAL`` is removed from the seam.
* THE REVERT TARGET — the trap this leg was written to avoid. Reverting ``statement_timeout`` the way
  the seam reverts ``lock_timeout`` (to ``'0'``) does not clear a narrowing, it REMOVES the bound for
  the rest of the caller's transaction: PostgreSQL's default here is 0 while our session value is
  300 s. The seam captures the session value with ``SHOW`` and restores THAT, and the cells tell the
  two revert forms apart instead of merely preferring one.
* NEVER WIDEN — a session bound tighter than ours is left exactly where the operator put it.
* THE THIRD OUTCOME — 57014 gets its own class, series, latch and message; 55P03 keeps all four. An
  unrelated fault still moves nothing and is still not converted into a revocation-plane refusal.
* THE TWO SITES #656 FILES — the dial CRL mint and the public poll's no-publisher fallback, both now
  inside the SAME seam, and both STILL ANSWERING: the paired negatives are what keep a freeze fix
  from becoming a fail-open or a fleet-wide starvation.
* ONE RULEBOOK — the shared refusal sentence, the one central arm, and a closed site vocabulary.
* THE VOCABULARY CHECK CAN SEE A LABEL IN EVERY SHAPE IT IS WRITTEN IN — literal, module or class
  constant, ``for_site(Name)``, a local bound to a resolvable value, an f-string chunk — and reports
  every site it cannot resolve by name instead of skipping it (``_UNRESOLVED_SITE_BASELINE``). #662
  found the hole: the closed set was only ever as wide as a literal-only reader could notice.

The doubles offer no method the real object lacks: the savepoint double has ``commit``/``rollback``
and no ``release()``, because that asymmetry is how the #603 first draft stayed green in units and
died on a live core. The PostgreSQL class at the end runs the three claims no double can make — that
57014 actually fires, that the session bound survives the read, and that a held ``ACCESS EXCLUSIVE``
on the newly bounded poll read now REFUSES instead of hanging.
"""

from __future__ import annotations

import ast
import inspect
import logging
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from prometheus_client import REGISTRY
from server import revocation_read, revocation_snapshot
from server.config import CRLConfig, ServerConfig
from server.revocation_read import (
    REVOCATION_UNAVAILABLE_DETAIL,
    RevocationReadScanTimeout,
    RevocationReadUnavailable,
    bounded_read,
)
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

PG_URL_ENV = "VENYA_TEST_PG_URL"
_PG_DEADLINE = {"options": "-c lock_timeout=5000 -c statement_timeout=60000"}

#: What the shipped connect listener sets on every pooled connection (``core/engine/backend.py``) and
#: the value the seam must hand back. A copy of this number in PRODUCT code is the drift class; here it
#: is only what a double pretends the server said.
_SESSION_SCAN_BOUND = "300s"

#: The closed vocabulary that may appear on a revocation-plane refusal series (#656 AC4: no second
#: rulebook, and never an attacker-shaped path on a Prometheus label — ``middleware/auth.py``'s own
#: docstring says why). Re-derived against the MERGED tip, not against this leg's own base: #657
#: landed ``poll/revocation-list`` (the STALE arm, a counter label, never a seam label — it is applied
#: at the raise, not by ``bounded_read``) and #658 landed ``admin-mtls`` (the admin plane's seam
#: label) while this branch was open. Some of these are module constants rather than inline
#: ``site="…"`` literals, which is why ``_seam_site_labels_from_source`` resolves names through
#: module/class constants, a local bound to a resolvable value, and an f-string chunk — #662 proved
#: that a literal-only ``for_site`` arm reports a smaller vocabulary than the seam actually holds.
#: This leg's own fallback label was ``revocation-poll`` at the first cut; with
#: ``poll/revocation-list`` now on the SAME series from the SAME route, two near-identical strings
#: would tell an operator nothing about which arm refused, so it is ``poll/fallback-read``.
#:
#: THE FOUR ``admin/*`` ROWS BELOW ARE WIDENED AHEAD OF THEIR MERGE, and each carries the proof the
#: guard's owner demanded — an entry enters only on a shipped call site in
#: ``packages/server/src/**``, never from a test double. All four are #662's, read at
#: ``7e64d5d21d41`` (branch ``bug/662-admin-sites-bounded-flash4-s133``, which is NOT an ancestor of
#: ``origin/dev`` at this base), each a module constant that is then passed at a real call site in
#: ``packages/server/src/server/routes/admin.py`` (symbol, not line, is the durable half):
#:   ``admin/certs-revoke``      ``ADMIN_CERT_REVOKE_SITE``     → ``bounded_read(db, site=…)`` in ``admin_revoke_admin_cert``
#:   ``admin/executor-revoke``   ``ADMIN_EXECUTOR_REVOKE_SITE`` → ``bounded_read(db, site=…)`` AND ``for_site(…)`` in ``admin_revoke_executor``
#:   ``admin/remove-executor``   ``ADMIN_REMOVE_EXECUTOR_SITE`` → ``for_site(…)`` in ``admin_remove_executor``
#:   ``admin/executors-certs``   ``ADMIN_EXECUTORS_CERTS_SITE`` → ``for_site(…)`` in ``admin_list_executors``
#: Two of those four were INVISIBLE to this check before the leg that adds them (they arrive only as
#: ``for_site(Name)``, and that arm read literals) — the blind spot act 2 of this leg closes.
#: If #662 is reworked or never lands, these four entries are dead vocabulary and the next
#: re-derivation must prune them: widening ahead of a merge is stated here, not hidden.
_SHIPPED_SITE_LABELS = frozenset(
    {
        "revocation-plane",
        "heartbeat",
        "audit-ingest",
        "executor-session",
        "executor-mtls",
        "crl",
        "register/incumbent-exemption",
        "register/terminal-check",
        "register/rotation-prior-serial",
        "admin/list-executors",
        "dial/create-session",
        "dial/execute",
        # landed on dev while this branch was open (#657 stale arm, #658 admin plane)
        "poll/revocation-list",
        "admin-mtls",
        # the two this leg adds, one per #656 site
        "dial/crl-mint",
        "poll/fallback-read",
        # #662's four admin-plane sites: provenanced above, UNMERGED at this base (7e64d5d)
        "admin/certs-revoke",
        "admin/executor-revoke",
        "admin/remove-executor",
        "admin/executors-certs",
    }
)

#: The same four, named again so a PARTIAL landing cannot pass quietly. See the guard in
#: ``test_every_site_label_the_seam_can_receive_is_in_the_closed_vocabulary``.
_ADMIN_662_LABELS = frozenset(
    {
        "admin/certs-revoke",
        "admin/executor-revoke",
        "admin/remove-executor",
        "admin/executors-certs",
    }
)


def _resolve_site_expr(node: ast.AST | None, scopes: list[dict[str, str]]) -> str | None:
    """The string a site argument evaluates to, or ``None`` when it genuinely cannot be known here.

    Resolves the forms a static reader can honour — a literal, a name bound to a resolvable value in
    scope (module constant, class constant, a local assigned earlier in this same function), a
    concatenation of those, and an f-string whose chunks all resolve. Deliberately does NOT guess at
    an attribute (``self.CONST``), a call, a subscript or a format spec: those are run-time values,
    and a guard that invents a label it cannot see is worse than one that reports the site as
    unresolved.
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        for scope in reversed(scopes):
            if node.id in scope:
                return scope[node.id]
        return None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                if not isinstance(value.value, str):
                    return None
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                if value.format_spec is not None:
                    return None
                chunk = _resolve_site_expr(value.value, scopes)
                if chunk is None:
                    return None
                parts.append(chunk)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_site_expr(node.left, scopes)
        right = _resolve_site_expr(node.right, scopes)
        if left is None or right is None:
            return None
        return left + right
    return None


def _seam_site_labels_from_source(source: str, relname: str = "<source>") -> tuple[set[str], list[str]]:
    """The seam's site labels in ONE file: ``(resolved, unresolved-descriptors)``.

    Two arms, unchanged in shape from the cell that first shipped them: a ``for_site`` name argument,
    and a ``site=`` keyword on any call — the second also covers the ``labels(site=…)`` emission
    points, because a narrower arm would stop counting the places a label really does reach a
    Prometheus series. #662 exposed the asymmetry this function used to carry: ``site=NAME`` resolved
    a module constant while ``for_site(NAME)`` resolved nothing, so two of four shipped labels sat
    outside the closed vocabulary unnoticed and the check still read green.

    A site whose label cannot be resolved statically is reported as ``"<file> <callee>(<source>)
    [n sites]"`` and pinned by ``_UNRESOLVED_SITE_BASELINE``. Silently skipping is the lie; counting
    is the #634 two-bucket shape.
    """
    tree = ast.parse(source)
    found: set[str] = set()
    counted: dict[tuple[str, str], int] = {}

    def take(callee: str, arg: ast.expr, scopes: list[dict[str, str]], *, keyword: str | None = None) -> None:
        label = _resolve_site_expr(arg, scopes)
        if label is not None:
            found.add(label)
            return
        shown = f"{keyword}={ast.unparse(arg)}" if keyword else ast.unparse(arg)
        key = (callee, shown)
        counted[key] = counted.get(key, 0) + 1

    def scan_expr(node: ast.AST, scopes: list[dict[str, str]]) -> None:
        if isinstance(node, ast.Call):
            callee = getattr(node.func, "id", None) or getattr(node.func, "attr", None) or "<expr>"
            if callee == "for_site" and node.args:
                take(callee, node.args[0], scopes)
            for kw in node.keywords:
                if kw.arg == "site":
                    take(callee, kw.value, scopes, keyword="site")
        for child in ast.iter_child_nodes(node):
            # A nested def inside an expression is read in the ENCLOSING scope, so a constant bound
            # only inside it can surface as unresolved here. Conservative and named, never dropped.
            scan_expr(child, scopes)

    def scan_body(body: list[ast.stmt], scopes: list[dict[str, str]]) -> None:
        for stmt in body:
            scan_stmt(stmt, scopes)

    def bind(stmt: ast.stmt, scopes: list[dict[str, str]]) -> None:
        target_nodes = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        value = _resolve_site_expr(stmt.value, scopes)
        if value is None:
            return
        for target in target_nodes:
            if isinstance(target, ast.Name):
                scopes[-1][target.id] = value

    def scan_stmt(stmt: ast.stmt, scopes: list[dict[str, str]]) -> None:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            scan_body(stmt.body, scopes + [{}])
            return
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            if stmt.value is not None:
                scan_expr(stmt.value, scopes)
                bind(stmt, scopes)
            return
        if isinstance(stmt, ast.With | ast.AsyncWith):
            for item in stmt.items:
                scan_expr(item.context_expr, scopes)
            scan_body(stmt.body, scopes)
            return
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
            return
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                scan_stmt(child, scopes)
            elif isinstance(child, ast.excepthandler):
                scan_body(child.body, scopes)
            else:
                scan_expr(child, scopes)

    module_scope: dict[str, str] = {}
    # Pre-pass: hoist module- and class-level string constants so a function may name a constant
    # declared below it (legal Python, and legal here — the scan is not an execution).
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_scope: dict[str, str] = {}
            for inner in node.body:
                if isinstance(inner, (ast.Assign, ast.AnnAssign)) and inner.value is not None:
                    resolved = _resolve_site_expr(inner.value, [module_scope, class_scope])
                    if resolved is not None:
                        for target in inner.targets if isinstance(inner, ast.Assign) else [inner.target]:
                            if isinstance(target, ast.Name):
                                class_scope[target.id] = resolved
                                module_scope.setdefault(target.id, resolved)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            resolved = _resolve_site_expr(node.value, [module_scope])
            if resolved is not None:
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Name):
                        module_scope[target.id] = resolved

    scan_body(tree.body, [module_scope])

    unresolved = [
        f"{relname} {callee}({arg_src}) [{count} site{'s' if count != 1 else ''}]"
        for (callee, arg_src), count in sorted(counted.items())
    ]
    return found, unresolved


def _seam_site_labels_in_root(src_root: Path) -> tuple[set[str], list[str]]:
    """Every seam site label under ``src_root``, and every site whose label could not be resolved."""
    found: set[str] = set()
    unresolved: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        file_found, file_unresolved = _seam_site_labels_from_source(
            path.read_text(encoding="utf-8"), str(path.relative_to(src_root))
        )
        found |= file_found
        unresolved += file_unresolved
    return found, unresolved


#: Every site in the shipped tree whose label this collector cannot resolve statically, by name.
#: Three of these are the seam's own metric emission points (``labels(site=site)`` — the value is a
#: function parameter, chosen by the caller at run time), and one is the middleware's computed
#: executor-path label, whose four possible outputs are pinned by the cell beside the baseline.
#: A NEW entry means a new way to hand the seam a label, and it must be added here with that reason,
#: or written as a literal/constant instead. Removing one silently is not an option either.
_UNRESOLVED_SITE_BASELINE = (
    "middleware/auth.py for_site(self._revocation_site(path)) [1 site]",
    "revocation_read.py labels(site=site) [3 sites]",
    "revocation_snapshot.py labels(site=site) [1 site]",
)


def _canceled_fault() -> DBAPIError:
    """A DBAPIError carrying PostgreSQL 57014 — psycopg's ``query_canceled``, the shape a
    ``statement_timeout`` cancellation arrives in."""
    orig = SimpleNamespace(pgcode="57014", args=(), sqlstate="57014")
    return DBAPIError("SELECT … FROM executor_cert_revocations", {}, orig)


def _lock_timeout_fault() -> DBAPIError:
    orig = SimpleNamespace(pgcode=revocation_read.LOCK_TIMEOUT_SQLSTATE, args=(), sqlstate="55P03")
    return DBAPIError("SELECT … FROM executor_cert_revocations", {}, orig)


def _unrelated_fault() -> RuntimeError:
    return RuntimeError("some other backend fault")


# --- metric reads through the registry, not through driver internals ----------------


def _sample(name: str, **labels) -> float:
    """One sample value from the live registry, 0.0 when that child has never been seen.

    Every caller asserts a DELTA: the registry is process-global, so an absolute figure here would be
    a number that depends on which cell ran last.
    """
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if sample.name == name and all(sample.labels.get(k) == v for k, v in labels.items()):
                return float(sample.value)
    return 0.0


def _scan_refusals(site: str) -> float:
    return _sample("venya_revocation_read_scan_refusals_total", site=site)


def _lock_refusals(site: str) -> float:
    return _sample("venya_revocation_read_refusals_total", site=site)


def _hist_count(site: str) -> float:
    return _sample("venya_revocation_read_duration_seconds_count", site=site)


def _hist_bucket(le: str, site: str) -> float:
    return _sample("venya_revocation_read_duration_seconds_bucket", le=le, site=site)


class _RecordingSavepoint:
    def __init__(self, owner) -> None:
        self.owner = owner

    def rollback(self):
        self.owner.events.append("savepoint-rollback")

    def commit(self):
        # A nested commit IS RELEASE SAVEPOINT. No release() method: SessionTransaction has none, and
        # a double that offers one keeps units green while every live read dies with AttributeError.
        self.owner.events.append("savepoint-release")


class _ScanSession:
    """A postgresql-bind session double that answers ``SHOW statement_timeout`` the way a server does.

    ``session_scan_bound`` is what the server reports for its own session bound — the value the seam
    must capture BEFORE narrowing and restore AFTER. ``None`` and junk strings model the unreadable
    state, which has its own cells because its honest answer is "no scan deadline for this read".
    """

    def __init__(
        self,
        *,
        session_scan_bound: object = _SESSION_SCAN_BOUND,
        raise_on_read=None,
        fail_read=None,
        rows=None,
        fail_on_restore=False,
    ) -> None:
        self.events: list[str] = []
        self.statements: list[str] = []
        self._session_bound = session_scan_bound
        self._raise = raise_on_read
        self._fail_read = fail_read
        self._rows = rows if rows is not None else [("row",)]
        self._fail_on_restore = fail_on_restore
        self.read_attempts = 0

    # --- dialect gate ---------------------------------------------------------------
    def get_bind(self):
        return SimpleNamespace(dialect=postgresql.dialect())

    # --- session surface the seam uses ----------------------------------------------
    def flush(self):
        self.events.append("flush")

    def begin_nested(self):
        self.events.append("savepoint-begin")
        return _RecordingSavepoint(self)

    def execute(self, statement, params=None):
        sql = str(statement)
        self.events.append(f"execute:{sql.split()[0].upper() if sql.split() else '?'}")
        self.statements.append(sql)
        if sql.startswith("SHOW statement_timeout"):
            return SimpleNamespace(scalar=lambda: self._session_bound, fetchall=list)
        if self._fail_on_restore and sql.startswith("SET LOCAL statement_timeout") and len(self.scan_bounds()) > 1:
            raise _unrelated_fault()
        if "timeout" not in sql and self._raise is not None:
            raise self._raise
        return SimpleNamespace(scalar=lambda: 1, fetchall=lambda: self._rows)

    def query(self, *a, **kw):
        """The ORM surface the two #656 sites actually read through — ``generate_crl`` and
        ``revocation_populations`` both use ``db.query(...)``, so the fault a mint cell injects has to
        come out of HERE, not out of ``execute``."""
        self.read_attempts += 1
        if self._fail_read is not None:
            raise self._fail_read
        q = MagicMock(name="query")
        q.count.return_value = 0
        q.all.return_value = []
        return q

    # --- readback helpers -----------------------------------------------------------
    def _like(self, token: str) -> list[str]:
        return [s for s in self.statements if token in s]

    def lock_bounds(self) -> list[str]:
        return self._like("SET LOCAL lock_timeout")

    def scan_bounds(self) -> list[str]:
        """Narrowing AND restore — both say ``SET LOCAL statement_timeout``, and the cells that count
        narrowing must not read the revert as a second bound."""
        return self._like("SET LOCAL statement_timeout")

    def narrowed_scan(self) -> str | None:
        sets = self.scan_bounds()
        return sets[0] if sets else None

    def shows(self) -> list[str]:
        return self._like("SHOW statement_timeout")


class _NonPGSession(_ScanSession):
    def get_bind(self):
        return SimpleNamespace(dialect=MagicMock(name="sqlite3"))


@pytest.fixture(autouse=True)
def _reset_state():
    revocation_read.reset_read_deadline_state()
    revocation_snapshot.reset_snapshot_state()
    yield
    revocation_read.reset_read_deadline_state()
    revocation_snapshot.reset_snapshot_state()


def _server_src_root() -> Path:
    return Path(revocation_read.__file__).resolve().parent


class TestScanBoundExists:
    """The bound is installed, in the right place, from a validated number."""

    def test_seam_sets_both_deadlines_inside_one_savepoint(self):
        db = _ScanSession()
        with bounded_read(db, site="heartbeat"):
            db.execute("SELECT 1 FROM executor_cert_revocations")
        assert db.shows() == ["SHOW statement_timeout"], "the session bound must be read first"
        assert db.events.index("savepoint-begin") < db.events.index("execute:SHOW")
        assert "'300ms'" in db.lock_bounds()[0]
        assert f"'{revocation_read.current_scan_timeout_ms()}ms'" in db.narrowed_scan(), (
            "the seam installs no statement deadline, so a slow scan is bounded only by the 300 s "
            "session GUC — this is the RED-if-the-bound-is-removed half of #654"
        )
        # Order is load-bearing: capture must precede narrowing, or the value the seam restores is the
        # value it just installed.
        assert db.statements.index("SHOW statement_timeout") < db.statements.index(db.narrowed_scan())
        assert db.statements.index(db.narrowed_scan()) < db.statements.index("SELECT 1 FROM executor_cert_revocations")

    def test_scan_deadline_statement_interpolates_a_validated_int_only(self):
        assert "'250ms'" in str(revocation_read.scan_deadline_statement(250))
        with pytest.raises((ValueError, TypeError)):
            revocation_read.scan_deadline_statement("250ms'; DROP TABLE executors; --")

    def test_configure_scan_timeout_keeps_the_default_rather_than_disabling(self):
        """Same posture as the lock knob: disabling is not a supported posture on this plane."""
        revocation_read.configure_scan_timeout(None)
        assert revocation_read.current_scan_timeout_ms() == revocation_read.DEFAULT_SCAN_TIMEOUT_MS
        revocation_read.configure_scan_timeout(0)
        assert revocation_read.current_scan_timeout_ms() == revocation_read.DEFAULT_SCAN_TIMEOUT_MS
        revocation_read.configure_scan_timeout(1500)
        assert revocation_read.current_scan_timeout_ms() == 1500
        db = _ScanSession()
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        assert "'1500ms'" in db.narrowed_scan()

    def test_seam_is_still_a_noop_on_non_postgres(self):
        """SQLite unit suites have no such GUC — and the SHOW must not be attempted there either, or
        the no-op branch stops being a no-op and every existing suite changes shape under this leg."""
        db = _NonPGSession()
        with bounded_read(db, site="heartbeat"):
            db.execute("SELECT 1")
        assert db.statements == ["SELECT 1"], db.statements
        assert db.events == ["execute:SELECT"], db.events


class TestRevertTarget:
    """The §4a trap as cells. These must tell the two revert forms APART — a cell that passes on
    either one proves nothing."""

    def test_success_restores_the_captured_session_value_not_zero(self):
        db = _ScanSession()
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        scans = db.scan_bounds()
        assert len(scans) == 2, f"expected one narrowing and one restore, saw {scans}"
        assert f"'{_SESSION_SCAN_BOUND}'" in scans[1], scans
        assert not any("statement_timeout = '0'" in s for s in scans), (
            "the seam reverted statement_timeout to PostgreSQL's default, which for OUR session is a "
            "widening to NO bound for the rest of the caller's transaction"
        )
        # The lock revert keeps its own shipped form, so the two are visibly different on purpose.
        assert any("lock_timeout = '0'" in s for s in db.lock_bounds())
        assert "savepoint-release" in db.events

    def test_refusal_path_issues_no_restore_because_rollback_is_the_revert(self):
        db = _ScanSession(raise_on_read=_canceled_fault())
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(db, site="heartbeat"):
                db.execute("SELECT 1")
        assert len(db.scan_bounds()) == 1, "ROLLBACK TO SAVEPOINT reverts the GUC; no second SET"
        assert db.events.count("savepoint-rollback") == 1

    def test_zero_session_bound_is_restored_to_zero_because_that_is_what_was_found(self):
        """The asymmetry stated the right way round: restoring ``'0'`` is CORRECT when the session said
        ``'0'``. The defect is assuming it, so the value comes from the capture either way."""
        db = _ScanSession(session_scan_bound="0")
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        assert "2000ms" in db.narrowed_scan()
        assert "= '0'" in db.scan_bounds()[1]

    def test_a_teardown_fault_on_the_restore_does_not_cost_the_answer_or_the_release(self):
        """Row I. The read already happened; a failing revert must return the population and leave the
        savepoint released, exactly as the shipped lock revert does — and it must SAY so."""
        db = _ScanSession(session_scan_bound="0", fail_on_restore=True)
        with bounded_read(db, site="crl"):
            rows = db.execute("SELECT 1").fetchall()
        assert rows == [("row",)], "a teardown fault replaced the answer already read"
        assert "savepoint-release" in db.events


class TestNeverWidens:
    """Installing our number over a tighter session bound would LOOSEN the operator's own limit."""

    def test_a_tighter_session_deadline_is_left_alone(self):
        db = _ScanSession(session_scan_bound="500ms")
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        assert db.narrowed_scan() is None, "the seam widened a 500 ms session bound to 2 000 ms"
        assert db.scan_bounds() == []
        assert db.lock_bounds(), "the lock deadline still applies — this rule is about the scan GUC"

    def test_an_equal_session_deadline_is_left_alone(self):
        db = _ScanSession(session_scan_bound="2000ms")
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        assert db.narrowed_scan() is None

    def test_a_looser_session_deadline_is_narrowed(self):
        """The positive half beside the two negatives above: the rule is a comparison, and a
        comparison pinned on one side only is the half-table this project refuses."""
        db = _ScanSession(session_scan_bound="10min")
        with bounded_read(db, site="crl"):
            db.execute("SELECT 1")
        assert "2000ms" in db.narrowed_scan()


class TestUnreadableSessionBound:
    """The state in which the seam cannot know what to restore, and what it must NOT do about it."""

    @pytest.mark.parametrize("unreadable", [None, 1, True, "", "5 fortnights", "'; DROP TABLE executors; --"])
    def test_unreadable_value_installs_nothing_and_says_so_once(self, caplog, unreadable):
        db = _ScanSession(session_scan_bound=unreadable)
        with caplog.at_level(logging.WARNING):
            with bounded_read(db, site="crl"):
                db.execute("SELECT 1")
        assert db.narrowed_scan() is None, "an unrestorable value must never be narrowed"
        assert db.scan_bounds() == []
        assert "NO scan deadline" in caplog.text, caplog.text
        assert not any("DROP TABLE" in s for s in db.statements), (
            "a server-returned string must not reach SQL text it was never meant to be: the shape "
            "guard is the only path from a SHOW answer into a statement"
        )

    def test_restore_statement_refuses_a_value_that_is_not_a_time(self):
        assert revocation_read.scan_restore_statement("5min") is not None
        assert revocation_read.scan_restore_statement("0") is not None
        assert revocation_read.scan_restore_statement("5min; DROP TABLE executors") is None
        assert revocation_read.scan_restore_statement("'300s'") is None
        assert revocation_read.scan_restore_statement("") is None

    @pytest.mark.parametrize(
        ("raw", "want"),
        [("0", 0.0), ("500ms", 500.0), ("2000ms", 2000.0), ("5min", 300_000.0), ("1s", 1000.0), ("1h", 3_600_000.0)],
    )
    def test_session_values_are_read_in_milliseconds(self, raw, want):
        assert revocation_read.scan_deadline_ms(raw) == want

    @pytest.mark.parametrize("raw", [None, 1, True, "abc", "5 fortnights", "-1", ""])
    def test_anything_else_reads_as_unusable(self, raw):
        assert revocation_read.scan_deadline_ms(raw) is None


class TestThirdOutcome:
    """57014 gets a name. 55P03 keeps the one it already had."""

    def test_scan_overrun_raises_its_own_class_and_names_the_site_and_its_number(self):
        db = _ScanSession(raise_on_read=_canceled_fault())
        with pytest.raises(RevocationReadScanTimeout) as got:
            with bounded_read(db, site="dial/crl-mint"):
                db.execute("SELECT 1")
        assert "dial/crl-mint" in str(got.value)
        assert str(revocation_read.current_scan_timeout_ms()) in str(got.value)
        assert "57014" in str(got.value)
        assert "lock deadline" not in str(got.value), "the scan refusal must not wear the lock wording"

    def test_the_scan_class_is_caught_by_the_shipped_refusal_arms(self):
        """Subclass, not sibling — which is what lets the one central arm and the shipped site arms
        answer the new fault without a single new ``except`` anywhere."""
        db = _ScanSession(raise_on_read=_canceled_fault())
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(db, site="poll/fallback-read"):
                db.execute("SELECT 1")

    def test_query_canceled_is_still_not_the_lock_class(self):
        """AC1 criterion 1, unchanged by this leg: the two classes do not read each other."""
        assert revocation_read.is_lock_timeout(_canceled_fault()) is False
        assert revocation_read.is_query_canceled(_lock_timeout_fault()) is False
        assert revocation_read.is_query_canceled(_canceled_fault()) is True
        assert revocation_read.is_lock_timeout(_lock_timeout_fault()) is True

    def test_scan_class_walks_a_wrapped_cause(self):
        wrapped = _unrelated_fault()
        wrapped.__cause__ = _canceled_fault()
        assert revocation_read.is_query_canceled(wrapped) is True

    def test_lock_refusal_is_still_refused_in_its_own_class_untouched(self):
        db = _ScanSession(raise_on_read=_lock_timeout_fault())
        with pytest.raises(RevocationReadUnavailable) as got:
            with bounded_read(db, site="heartbeat"):
                db.execute("SELECT 1")
        assert not isinstance(got.value, RevocationReadScanTimeout), "the lock class was renamed"
        assert "lock deadline" in str(got.value) and "55P03" in str(got.value)


class TestSeriesAreSeparate:
    """New series, new names. The #603 series is not folded into, not re-labelled, not re-scoped."""

    def test_scan_refusal_counts_only_its_own_series(self):
        site = "dial/crl-mint"
        scan_before, lock_before = _scan_refusals(site), _lock_refusals(site)
        for _ in range(2):
            with pytest.raises(RevocationReadUnavailable):
                with bounded_read(_ScanSession(raise_on_read=_canceled_fault()), site=site):
                    raise _canceled_fault()
        assert _scan_refusals(site) == scan_before + 2
        assert (
            _lock_refusals(site) == lock_before
        ), "a slow scan moved the LOCK counter — ops would chase a convoy that never happened"

    def test_lock_refusal_counts_only_the_lock_series(self):
        site = "poll/fallback-read"
        lock_before, scan_before = _lock_refusals(site), _scan_refusals(site)
        with pytest.raises(RevocationReadUnavailable):
            with bounded_read(_ScanSession(raise_on_read=_lock_timeout_fault()), site=site):
                raise _lock_timeout_fault()
        assert _lock_refusals(site) == lock_before + 1
        assert _scan_refusals(site) == scan_before

    def test_unrelated_fault_moves_neither_series_and_is_not_converted(self):
        site = "crl"
        scan_before, lock_before = _scan_refusals(site), _lock_refusals(site)
        with pytest.raises(RuntimeError, match="some other backend fault"):
            with bounded_read(_ScanSession(raise_on_read=_unrelated_fault()), site=site):
                raise _unrelated_fault()
        assert _scan_refusals(site) == scan_before
        assert _lock_refusals(site) == lock_before

    @pytest.mark.parametrize(
        ("sqlstate", "why"),
        [("40P01", "deadlock_detected, row H"), ("08006", "connection_good, row G's class")],
    )
    def test_a_backend_fault_that_is_neither_lock_nor_scan_stays_unnamed(self, sqlstate, why):
        """Rows G and H, stated as what they still are. This leg bounds a lock wait and a slow scan;
        a deadlock victim and a connection fault are NOT converted into either named class, because
        naming them would be exactly the folding AC1 forbids. The paired negative of the two new
        classes is that everything else still escapes untouched — and counted nowhere."""
        site = "heartbeat"
        orig = SimpleNamespace(pgcode=sqlstate, args=(), sqlstate=sqlstate)
        fault = DBAPIError("SELECT 1", {}, orig)
        scan_before, lock_before = _scan_refusals(site), _lock_refusals(site)
        with pytest.raises(DBAPIError):
            with bounded_read(_ScanSession(raise_on_read=fault), site=site):
                raise fault
        assert _scan_refusals(site) == scan_before, f"{why} was folded into the scan class"
        assert _lock_refusals(site) == lock_before, f"{why} was folded into the lock class"

    def test_no_existing_series_gained_a_label(self):
        """A label added to a shipped series re-splits every operator query built on it. The #603
        counter is still labelled by site and nothing else, whatever this leg added beside it."""
        from server import metrics

        assert list(metrics.REVOCATION_READ_REFUSALS_TOTAL._labelnames) == ["site"]
        assert list(metrics.REVOCATION_READ_SCAN_REFUSALS_TOTAL._labelnames) == ["site"]
        assert list(metrics.REVOCATION_READ_DURATION_SECONDS._labelnames) == ["site"]


class TestLatchesAreIndependent:
    """Each state gets its own once-per-process line, and each line points at ITS OWN counter."""

    def test_scan_line_fires_once_and_its_counter_keeps_counting(self, caplog):
        site = "heartbeat"
        before = _scan_refusals(site)
        with caplog.at_level(logging.WARNING):
            for _ in range(2):
                with pytest.raises(RevocationReadUnavailable):
                    with bounded_read(_ScanSession(raise_on_read=_canceled_fault()), site=site):
                        raise _canceled_fault()
        assert caplog.text.count("CANCELLED by its own") == 1
        assert "venya_revocation_read_scan_refusals_total" in caplog.text
        assert "not a revocation" in caplog.text.lower()
        assert _scan_refusals(site) == before + 2

    def test_a_lock_line_does_not_use_up_the_scan_line(self, caplog):
        """The failure this separation exists for: one latch shared by two faults, and whichever
        arrives second is journalled nowhere."""
        with caplog.at_level(logging.WARNING):
            with pytest.raises(RevocationReadUnavailable):
                with bounded_read(_ScanSession(raise_on_read=_lock_timeout_fault()), site="crl"):
                    raise _lock_timeout_fault()
            assert revocation_read.is_refusal_warned() is True
            assert revocation_read.is_scan_refusal_warned() is False
            with pytest.raises(RevocationReadUnavailable):
                with bounded_read(_ScanSession(raise_on_read=_canceled_fault()), site="crl"):
                    raise _canceled_fault()
        assert revocation_read.is_scan_refusal_warned() is True
        assert "CANCELLED by its own" in caplog.text

    def test_reset_clears_both_latches_and_both_defaults(self):
        revocation_read.configure_scan_timeout(1234)
        revocation_read.reset_read_deadline_state()
        assert revocation_read.current_scan_timeout_ms() == revocation_read.DEFAULT_SCAN_TIMEOUT_MS
        assert revocation_read.current_lock_timeout_ms() == revocation_read.DEFAULT_LOCK_TIMEOUT_MS
        assert revocation_read.is_scan_refusal_warned() is False
        assert revocation_read.is_refusal_warned() is False


class TestTheFourthStateIsObservable:
    """A read that succeeds slowly raises nothing, so it can only ever be an observation."""

    def test_the_seam_observes_its_own_site(self):
        site = "poll/fallback-read"
        before = _hist_count(site)
        with bounded_read(_ScanSession(), site=site):
            pass
        assert _hist_count(site) == before + 1

    def test_the_buckets_reach_the_bound_that_actually_governs_the_read(self):
        """The hiding mechanism in metric form: REQUEST_DURATION's top bucket is 10 s while the bound
        was 300 s, so a 12 s read and a 300 s read were one ``+Inf`` observation."""
        from math import inf

        from server import metrics

        def finite_bounds(metric) -> list[float]:
            # ``_upper_bounds`` carries prometheus's implicit +Inf tail; the assertion is about the
            # highest BOUNDED bucket, which is the one that has to reach the governing GUC.
            return [b for b in metric._upper_bounds if b != inf]

        assert max(finite_bounds(metrics.REVOCATION_READ_DURATION_SECONDS)) == 300.0
        assert max(finite_bounds(metrics.REQUEST_DURATION)) == 10.0

    def test_a_twelve_second_read_is_not_the_same_observation_as_a_fast_one(self):
        """Row C against row A, asserted on bucket counts rather than on prose."""
        late, quick = "dial/execute", "admin/list-executors"
        base_late, base_quick = _hist_bucket("10.0", late), _hist_bucket("0.05", quick)
        revocation_read.note_read_duration(late, 12.0)
        revocation_read.note_read_duration(quick, 0.03)
        assert _hist_bucket("10.0", late) == base_late, "a 12 s read must NOT land inside 10 s"
        assert _hist_bucket("30.0", late) == base_late + 1
        assert _hist_bucket("0.05", quick) == base_quick + 1

    def test_a_negative_elapsed_reading_cannot_poison_every_bucket_above_it(self):
        """Buckets are cumulative, so a nonsense observation corrupts the whole series. The seam
        computes a difference, therefore the clamp belongs at the observe call — and gets a cell."""
        site = "heartbeat"
        base = _hist_bucket("0.025", site)
        revocation_read.note_read_duration(site, -5.0)
        assert _hist_bucket("0.025", site) == base + 1

    def test_a_read_refused_by_the_bound_never_answers(self):
        """The impossibility half. Before this leg a slow read returned 200 at t=12 s; the same fault
        now raises, so the caller-left / core-answered-200 disagreement cannot recur above the bound."""
        db = _ScanSession(raise_on_read=_canceled_fault())
        with pytest.raises(RevocationReadScanTimeout):
            with bounded_read(db, site="crl"):
                db.execute("SELECT 1")
        assert revocation_read.is_scan_refusal_warned() is True

    def test_a_read_inside_the_budget_still_answers_and_counts_nothing(self):
        """Row A: no lock, no delay, serves, UNCOUNTED. Without this half the new counters would be a
        story about every read rather than about the ones that failed."""
        site = "audit-ingest"
        scan_before, lock_before = _scan_refusals(site), _lock_refusals(site)
        db = _ScanSession()
        with bounded_read(db, site=site):
            rows = db.execute("SELECT 1").fetchall()
        assert rows == [("row",)]
        assert _scan_refusals(site) == scan_before
        assert _lock_refusals(site) == lock_before


class TestNoSecondRulebook:
    """#656 AC4: one seam, one sentence, one arm, one closed label vocabulary."""

    def test_the_refusal_sentence_is_declared_exactly_once_in_the_package(self):
        src_root = _server_src_root()
        owners = [
            str(p.relative_to(src_root))
            for p in src_root.rglob("*.py")
            if 'REVOCATION_UNAVAILABLE_DETAIL = "' in p.read_text(encoding="utf-8")
        ]
        assert owners == ["revocation_read.py"], f"a second implementation of the sentence: {owners}"

    def test_the_poll_route_still_aliases_the_same_constant(self):
        from server.routes import executors as ex

        assert ex._STALE_LIST_DETAIL is REVOCATION_UNAVAILABLE_DETAIL

    @staticmethod
    def _bounded_with_nodes(func: ast.FunctionDef) -> list[ast.withitem]:
        """Every ``with`` whose context expression calls ``bounded_read`` — shape off the AST, so
        prose that merely names the seam cannot satisfy it and a rename cannot pass silently."""
        out: list[ast.withitem] = []
        for node in ast.walk(func):
            if isinstance(node, ast.With):
                for item in node.items:
                    if "bounded_read" in ast.dump(item.context_expr):
                        out.append(item)
        return out

    def _func(self, module_name: str, qualname: str, func_name: str) -> ast.FunctionDef:
        path = _server_src_root() / module_name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if qualname:
            cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == qualname)
            return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == func_name)
        return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == func_name)

    def test_the_poll_fallback_enters_the_seam_exactly_once(self):
        func = self._func("revocation_snapshot.py", "", "read_populations")
        assert len(self._bounded_with_nodes(func)) == 1, (
            "the no-publisher fallback is either back outside the seam (#656 site 2 reopened) or "
            "wrapped twice, which is a second rulebook of its own"
        )

    def test_the_dial_mint_read_enters_the_seam_and_the_admin_mint_does_not(self):
        """Site 1 bounded, and the boundary stated where it still stands. #658 landed while this branch
        was open and bounded the admin plane's mTLS revocation LOOKUP (`middleware/auth.py`, label
        ``admin-mtls``) — it did NOT touch the admin CRL mint, and this leg does not either, so the
        mint half of the admin plane is still #658's row's own business and stays out of this diff."""
        executor = self._func("ca.py", "CAManager", "generate_crl")
        assert self._bounded_with_nodes(executor), "CAManager.generate_crl queries its population outside the seam"
        admin = self._func("ca.py", "AdminCAManager", "generate_crl")
        assert not self._bounded_with_nodes(admin), "the admin CRL mint was swept into this leg (that is #658's plane)"

    def test_the_admin_plane_lookup_is_bounded_by_its_own_row(self):
        """Re-derived at the merged tip rather than inherited: #658 put the seam on the admin mTLS
        read. Pinned here so this leg's boundary claim cannot rot into a stale description of dev."""
        src = (_server_src_root() / "middleware" / "auth.py").read_text(encoding="utf-8")
        assert "bounded_read(db, site=ADMIN_MTLS_REVOCATION_SITE)" in src

    def test_the_publisher_read_stays_outside_the_seam_by_ruling(self):
        """The asymmetry is a decision, so it gets pinned. ``publish_snapshot`` reads on a worker
        thread off the loop, where AC2's 45 s ceiling is the ruled answer; bounding it would turn one
        slow publish into a fleet-wide refusal, and this cell makes that a deliberate edit."""
        func = self._func("revocation_snapshot.py", "", "publish_snapshot")
        assert not self._bounded_with_nodes(func)

    def test_every_site_label_the_seam_can_receive_is_in_the_closed_vocabulary(self):
        """A Prometheus label must never be reachable from a request path. Every label the seam can
        take is enumerated from the AST here, resolving module constants the way the #614 interlock
        does — and counting, not dropping, whatever it cannot resolve (see
        ``_seam_site_labels_from_source``)."""
        found, unresolved = _seam_site_labels_in_root(_server_src_root())
        assert found <= _SHIPPED_SITE_LABELS, f"labels outside the vocabulary: {sorted(found - _SHIPPED_SITE_LABELS)}"
        assert sorted(unresolved) == list(_UNRESOLVED_SITE_BASELINE), (
            "the seam's label set moved in a way this check cannot read. An unresolved site is not "
            "a free pass: add it to the baseline with the file, the callee and the reason, or (if it "
            "can be written as a literal or a constant) fix the call site instead."
        )
        assert {"dial/crl-mint", "poll/fallback-read"} <= found, "a #656 site lost its label"
        # #662 is unmerged at this base, so none of its four labels is in the tree yet. The moment it
        # lands, ALL FOUR must appear: one missing means a call site lost its label while the
        # vocabulary still permits it, which is a silent narrowing of an operator's alert surface.
        # The empty half of this test is TODAY's face, and it is stated rather than assumed.
        seen_662 = frozenset(_ADMIN_662_LABELS & found)
        assert seen_662 in (frozenset(), _ADMIN_662_LABELS), (
            f"partial #662 label set at this face: {sorted(seen_662)} — either #662 is unmerged "
            "(expect none of the four) or it landed with a call site missing (expect all four)"
        )
        assert "admin-mtls" in found, (
            "#658's admin-plane label is no longer reachable from the seam — either it moved under "
            "this branch or this cell stopped reading the plane, and both need saying out loud"
        )
        assert not any(label.startswith("/api") for label in found), "a raw path reached a metric label"

    def test_the_two_poll_labels_name_different_arms_of_one_route(self):
        """#657 counts the STALE arm of the poll; this leg bounds the READ arm of the same route. Two
        strings, two arms, one series — and an operator must be able to tell them apart, which is the
        reason this leg's label is ``poll/fallback-read`` and not something that reads like #657's.

        It also pins the half that the seam-vocabulary cell cannot see: ``POLL_REFUSAL_SITE`` reaches
        the counter at the raise, never through ``bounded_read``, so a scan of seam labels alone would
        report a smaller vocabulary than the series actually holds.
        """
        from server.revocation_snapshot import POLL_REFUSAL_SITE

        assert POLL_REFUSAL_SITE == "poll/revocation-list"
        assert POLL_REFUSAL_SITE in _SHIPPED_SITE_LABELS
        assert "poll/fallback-read" != POLL_REFUSAL_SITE

    def test_the_matcher_still_wraps_its_own_reads_in_the_seam(self):
        """Neighbour guard: this leg added statements INSIDE bounded_read and must not have moved the
        shipped seam off the single matcher."""
        func = self._func("revocation.py", "", "executor_revocation_state")
        assert len(self._bounded_with_nodes(func)) == 1


class TestCollectorBlindSpot654:
    """The blind spot INSIDE this guard, proven before it is closed (s137 act 2).

    The closed vocabulary is only as honest as the scanner that feeds it. The shipped scanner read
    literal arguments and module-level constants on the ``site=`` arm only, so a label reaching the
    seam through a local variable, or through ``for_site(SOME_CONST)``, was never counted — it was
    silently skipped, which is the failure the #634 interlock names: a guard whose coverage depends
    on how the call site was written is a guard that can be defeated by a variable.

    These cells drive the collector on SYNTHETIC source, not on the shipped tree, so the control
    measures the instrument rather than the code it happens to be pointed at today.
    """

    #: mirrors #662's real shapes: a label assigned to a local, then handed to both arms.
    _LOCAL_VAR_SOURCE = """
from server.revocation_read import bounded_read, for_site


async def admin_revoke_thing(db, body):
    label = "control/local-var"
    with for_site(label):
        with bounded_read(db, site=label):
            pass
"""

    _MODULE_CONST_SOURCE = """
from server.revocation_read import for_site

CONTROL_CONST = "control/module-const"


def read_it(db):
    with for_site(CONTROL_CONST):
        pass
"""

    _FSTRING_SOURCE = """
from server.revocation_read import bounded_read

PLANE = "control"


def read_it(db):
    with bounded_read(db, site=f"{PLANE}/computed-chunk"):
        pass
"""

    _COMPUTED_SOURCE = """
from server.revocation_read import for_site


class Middleware:
    def _revocation_site(self, path):
        return path

    def dispatch(self, db, path):
        with for_site(self._revocation_site(path)):
            pass
"""

    def test_positive_control__a_label_routed_through_a_local_variable_is_seen(self):
        """THE CONTROL. This cell is the evidence, and it must go RED before the collector changes.

        If it ever passes without the collector resolving locals, the control is measuring nothing
        and the fix it justifies is not a fix.
        """
        found, unresolved = _seam_site_labels_from_source(self._LOCAL_VAR_SOURCE, "<control-local>")
        assert (
            "control/local-var" in found
        ), f"the collector read {sorted(found)} and skipped the local; unresolved={unresolved}"
        assert unresolved == [], f"a resolvable site was left in the unresolved bucket: {unresolved}"

    def test_positive_control__for_site_taking_a_module_constant_is_seen(self):
        """The exact 2-of-4 gap #662 exposed: ``for_site(NAME)`` resolved nothing on the positional
        arm while ``site=NAME`` resolved the module constant on the keyword arm."""
        found, unresolved = _seam_site_labels_from_source(self._MODULE_CONST_SOURCE, "<control-const>")
        assert "control/module-const" in found, f"for_site(Name) was invisible: found={sorted(found)}"
        assert unresolved == [], f"a resolvable site was left in the unresolved bucket: {unresolved}"

    def test_positive_control__an_f_string_chunk_built_from_a_constant_is_seen(self):
        found, unresolved = _seam_site_labels_from_source(self._FSTRING_SOURCE, "<control-fstring>")
        assert "control/computed-chunk" in found, f"f-string chunk was invisible: found={sorted(found)}"
        assert unresolved == [], f"a resolvable site was left in the unresolved bucket: {unresolved}"

    def test_paired_negative__a_computed_label_is_counted_not_dropped(self):
        """The other half of the same rule, and the half that keeps the fix from being a quiet
        over-claim. A label produced by a function call at run time CANNOT be resolved statically —
        the shipped ``middleware/auth.py`` does exactly this — so it must arrive in the unresolved
        bucket by name instead of vanishing from the check."""
        found, unresolved = _seam_site_labels_from_source(self._COMPUTED_SOURCE, "<control-computed>")
        assert found == set(), f"a computed label was guessed at: {sorted(found)}"
        assert unresolved == [
            "<control-computed> for_site(self._revocation_site(path)) [1 site]"
        ], f"unresolved descriptor wrong or missing: {unresolved}"

    def test_the_four_662_entries_are_justified_by_a_seam_that_can_actually_see_them(self):
        """The paired negative on this leg's OWN act 1, and the half that makes the widening a claim
        rather than a courtesy to the lane that benefits from it.

        A closed vocabulary can be widened for two very different reasons: because the seam can now
        reach four more labels and the check must count them (true), or because the scanner still
        cannot see the shape they arrive in and someone made the red go away by moving the goalposts
        (the fail-loudly violation class). The way to tell those apart is to drive the instrument on
        the bytes it will meet AFTER the merge, not on the tree it stands in, so this cell does not
        care which side of #662's merge its base sits on:

        1. the collector resolves all four labels in BOTH shapes #662 uses — ``site=NAME`` and
           ``for_site(NAME)`` — which is precisely what the literal-only arm could not do;
        2. the same four are then permitted by the closed set (an entry the seam can reach must be
           in the vocabulary, or the merged face reads red); and
        3. whatever the tree under test actually contains, the check cannot be quiet about a partial
           set — the guard beside this cell covers that, and it is the reason this cell is written
           against synthetic bytes instead of a checkout of a branch this venue must not build on.
        """
        merged_face = """
from server.revocation_read import bounded_read, for_site

ADMIN_CERT_REVOKE_SITE = "admin/certs-revoke"
ADMIN_EXECUTOR_REVOKE_SITE = "admin/executor-revoke"
ADMIN_REMOVE_EXECUTOR_SITE = "admin/remove-executor"
ADMIN_EXECUTORS_CERTS_SITE = "admin/executors-certs"


async def admin_revoke_admin_cert(db):
    with bounded_read(db, site=ADMIN_CERT_REVOKE_SITE):
        pass


async def admin_revoke_executor(db):
    with bounded_read(db, site=ADMIN_EXECUTOR_REVOKE_SITE):
        pass
    with for_site(ADMIN_EXECUTOR_REVOKE_SITE):
        pass


async def admin_remove_executor(db):
    with for_site(ADMIN_REMOVE_EXECUTOR_SITE):
        pass


async def admin_list_executors(db):
    with for_site(ADMIN_EXECUTORS_CERTS_SITE):
        pass
"""
        found, unresolved = _seam_site_labels_from_source(merged_face, "<merged-662-face>")
        assert found == _ADMIN_662_LABELS, f"the merged face read {sorted(found)}"
        assert unresolved == [], f"a #662 site the collector cannot read: {unresolved}"
        assert found <= _SHIPPED_SITE_LABELS, (
            f"the seam can reach {sorted(found - _SHIPPED_SITE_LABELS)} and the closed set does not "
            "permit them — the merged face would read red, which is the outcome a widening is "
            "supposed to prevent"
        )

    def test_the_one_computed_seam_site_still_has_a_closed_vocabulary(self):
        """The unresolved bucket is a NAME, not an excuse. ``middleware/auth.py`` hands the seam
        ``self._revocation_site(path)``, which no static reader can evaluate — so the closed set must
        be justified against what that function can actually RETURN, read off its own AST.

        This is the paired negative the baseline would otherwise lack: a new ``return`` in the
        matcher, or a ``path`` value reaching a label without collapsing to a fixed name, reddens
        here instead of slipping past a check that admitted it could not see the site.
        """
        src = (_server_src_root() / "middleware" / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        func = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_revocation_site"
        )
        returned = {
            n.value.value
            for n in ast.walk(func)
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
        }
        assert returned == {"heartbeat", "audit-ingest", "executor-session", "executor-mtls"}, (
            f"the computed executor-path label vocabulary changed: {sorted(returned)} — a name that "
            "reaches a Prometheus series from a request path must be reviewed, not just recorded"
        )
        assert returned <= _SHIPPED_SITE_LABELS, f"outside the closed set: {sorted(returned - _SHIPPED_SITE_LABELS)}"
        # The site the baseline claims is still the site that exists — a renamed argument or a moved
        # call must update the baseline in the same change, not delete this guard.
        found, unresolved = _seam_site_labels_from_source(src, "middleware/auth.py")
        assert (
            "middleware/auth.py for_site(self._revocation_site(path)) [1 site]" in unresolved
        ), f"the computed site changed shape and this cell did not notice: {unresolved}"
        assert "self._revocation_site(path)" not in found, "a computed label was guessed at"

    def test_the_shipped_tree_has_no_second_rulebook_after_the_fix(self):
        """The scanner's own truth table against real product bytes: the labels it resolves are a
        subset of the closed vocabulary, and every site it cannot resolve is one of the named,
        counted shapes in ``_UNRESOLVED_SITE_BASELINE`` — not zero, and not silent."""
        found, unresolved = _seam_site_labels_in_root(_server_src_root())
        assert found <= _SHIPPED_SITE_LABELS, f"{sorted(found - _SHIPPED_SITE_LABELS)}"
        assert set(unresolved) == set(
            _UNRESOLVED_SITE_BASELINE
        ), f"unresolved set moved: {sorted(set(unresolved) ^ set(_UNRESOLVED_SITE_BASELINE))}"
        assert sorted(unresolved) == sorted(_UNRESOLVED_SITE_BASELINE), (
            "an unresolved shape appeared twice in one file and was counted as one — the site count "
            "is part of the claim, not decoration"
        )


class TestSite2PollFallback:
    """The public poll's no-publisher read: bounded, and STILL ANSWERING."""

    def test_the_fallback_read_itself_is_bounded(self):
        """Called through ``read_populations``, not wrapped by hand — the cell must prove the WRAP
        lives in the function, which is what #656 AC2 asks for."""
        revocation_snapshot.disarm_publisher()
        db = _ScanSession()
        revocation_snapshot.read_populations(db)
        assert db.narrowed_scan() is not None, "the fallback is back outside the seam"
        assert db.lock_bounds()
        assert db.read_attempts >= 1, "vacuous: the fallback read never ran"

    def test_a_locked_fallback_refuses_in_the_shipped_stale_class(self):
        """A held lock on the poll now costs a refusal in the sentence ops already read — not a parked
        loop, not a 403, and never 'nothing revoked'."""
        revocation_snapshot.disarm_publisher()
        with pytest.raises(RevocationReadUnavailable) as got:
            with bounded_read(_ScanSession(raise_on_read=_lock_timeout_fault()), site="poll/fallback-read"):
                raise _lock_timeout_fault()
        assert "poll/fallback-read" in str(got.value)
        assert got.value.__class__ is RevocationReadUnavailable
        assert "no revocation asserted" in REVOCATION_UNAVAILABLE_DETAIL.lower()

    def test_the_fallback_still_answers_the_current_population(self):
        """#656 AC2's paired negative. Refusing every poll until a publisher came back would starve
        the fleet on one dead task (the #626 shape), so bounding must not have become abstaining."""
        from core.iam.models import Base, Executor, ExecutorCertRevocation
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine, tables=[Executor.__table__, ExecutorCertRevocation.__table__])
        db = sessionmaker(bind=engine)()
        now = _utcnow()
        db.add(Executor(id="venya-exec-1", hostname="e1.test", enrolled_at=now, revoked_at=now))
        db.add(ExecutorCertRevocation(serial_number="00aa", executor_id="venya-exec-2", reason="manual"))
        db.commit()
        revocation_snapshot.disarm_publisher()
        serials, identities = revocation_snapshot.read_populations(db)
        assert serials == ["00aa"]
        assert identities == ["venya-exec-1"]
        db.close()

    def test_an_armed_publisher_answers_from_memory_with_no_read_at_all(self):
        """The other paired negative #656 names: the wrap must not have moved the read onto the
        healthy path. Zero statements IS the proof."""
        revocation_snapshot.arm_publisher()
        revocation_snapshot.publish_populations(["ff"], [], published_mono=time.monotonic())
        db = _ScanSession()
        assert revocation_snapshot.read_populations(db) == (["ff"], [])
        assert db.statements == [] and db.events == []


class TestSite1DialMint:
    """The dial mints its CRL from the same population, now inside the same seam."""

    @pytest.fixture()
    def ca_manager(self, tmp_path, monkeypatch):
        """A real CA on disk — the mint must actually sign, or the cell proves nothing about the read."""
        from server.ca import CAManager

        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "test_passphrase_654")
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        return manager

    def test_the_self_queried_mint_runs_inside_the_seam(self, ca_manager):
        db = _ScanSession()
        der = ca_manager.generate_crl(db)
        assert isinstance(der, bytes) and der, "the mint did not actually mint"
        assert db.narrowed_scan() is not None, "the dial's own read is outside the seam — #656 site 1 reopened"
        assert db.lock_bounds()
        assert db.read_attempts == 1, "exactly one population read, inside the one seam"

    def test_the_mint_passed_rows_from_the_bounded_route_issues_no_second_seam(self, ca_manager):
        """The CRL route reads inside ``bounded_read(db, site="crl")`` and passes the rows in; the mint
        must not wrap a second time around a read that already happened."""
        db = _ScanSession()
        ca_manager.generate_crl(db, revocations=[])
        assert db.statements == [], db.statements

    def test_a_locked_mint_refuses_rather_than_parking_the_loop(self, ca_manager):
        with pytest.raises(RevocationReadUnavailable):
            ca_manager.generate_crl(_ScanSession(fail_read=_lock_timeout_fault()))

    def test_a_scan_overrun_on_the_mint_refuses_in_the_scan_class(self, ca_manager):
        with pytest.raises(RevocationReadScanTimeout):
            ca_manager.generate_crl(_ScanSession(fail_read=_canceled_fault()))

    def test_the_dial_labels_its_mint_for_the_counter(self, tmp_path):
        """The label travels in the ``for_site`` scope exactly as the matcher's does, so the refusal
        says the DIAL minted nothing instead of naming the anonymous plane default."""
        from server.routes.executors import _ensure_dial_crl_store

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.crt").write_bytes(b"a stand-in the store only fingerprints")
        seen: list[str] = []

        class _Mint:
            def generate_crl(self, db):
                seen.append(revocation_read.current_site())
                return b"not-real-der"

        request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    config=SimpleNamespace(ca_dir=str(ca_dir)),
                    ca_manager=_Mint(),
                )
            )
        )
        with pytest.raises(ValueError):  # the store parses the DER it was handed and cannot
            _ensure_dial_crl_store(request, MagicMock())
        assert seen == ["dial/crl-mint"]


class TestConfigSurface:
    def test_the_knob_exists_with_a_named_default_and_stated_bounds(self):
        field = CRLConfig.model_fields["revocation_read_scan_timeout_ms"]
        assert field.default == 2000
        cfg = ServerConfig(recovery_code_pepper="p", crl={"revocation_read_scan_timeout_ms": 1500})
        assert cfg.crl.revocation_read_scan_timeout_ms == 1500
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_scan_timeout_ms=0)
        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_scan_timeout_ms=60_000)

    def test_the_env_name_is_on_the_field_description_the_operator_reads(self):
        assert "VENYA_CRL__REVOCATION_READ_SCAN_TIMEOUT_MS" in (
            CRLConfig.model_fields["revocation_read_scan_timeout_ms"].description or ""
        )

    def test_a_scan_bound_at_or_below_the_lock_bound_is_refused(self):
        """Not tidiness. ``statement_timeout`` counts lock waits too, so a scan bound under the lock
        bound answers every convoy with 57014 and leaves the #603 series empty — the exact vocabulary
        AC1 won. Startup fails loudly instead, which is also how ``validate_snapshot_windows`` works.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_scan_timeout_ms=300)
        with pytest.raises(ValidationError):
            CRLConfig(revocation_read_scan_timeout_ms=100, revocation_read_lock_timeout_ms=300)
        # And the shipped defaults satisfy it, so nothing that boots today stops booting.
        assert CRLConfig().revocation_read_scan_timeout_ms > CRLConfig().revocation_read_lock_timeout_ms

    def test_the_lifespan_installs_the_scan_deadline_beside_the_lock_one(self):
        import server.app as app_module

        src = inspect.getsource(app_module)
        assert "configure_scan_timeout(getattr(config.crl, " in src
        assert "revocation_read_scan_timeout_ms" in src


class TestOperatorSurfaceIsDocumented:
    """A knob and two series that exist only in code are a trap for the next seat on this box.

    Same discipline #653 applied to the scrape endpoint: a runbook that names a counter but not the
    path that reads it, or a deadline but not the number that sets it, is the defect in text form.
    """

    _RUNBOOK = Path(__file__).resolve().parents[3] / "docs" / "revocation-table-operations-runbook.md"

    def test_the_runbook_names_the_scan_knob_and_both_new_series(self):
        text_src = self._RUNBOOK.read_text(encoding="utf-8")
        assert "crl.revocation_read_scan_timeout_ms" in text_src
        assert "VENYA_CRL__REVOCATION_READ_SCAN_TIMEOUT_MS" in text_src
        assert "venya_revocation_read_scan_refusals_total" in text_src
        assert "venya_revocation_read_duration_seconds" in text_src

    def test_the_runbook_no_longer_claims_statement_timeout_is_untouchable(self):
        """The stale sentence this leg had to correct, pinned so it cannot come back.

        It read ``statement_timeout stays as it ships and is a different failure with a different
        name`` while the seam was installing a per-read one — half true, and the half that was false
        is the half an operator would act on.
        """
        text_src = self._RUNBOOK.read_text(encoding="utf-8")
        assert "stays as it ships and is a different failure" not in text_src

    def test_the_shipped_lock_knob_is_still_documented_where_it_was(self):
        """Neighbour guard: correcting a stale sentence is not a licence to drop the row beside it."""
        text_src = self._RUNBOOK.read_text(encoding="utf-8")
        assert "crl.revocation_read_lock_timeout_ms" in text_src
        assert "venya_revocation_read_refusals_total" in text_src


def _utcnow():
    return datetime.now(UTC)


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"these three claims need a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestScanBoundPostgresql:
    """The three claims a double cannot make. Point the env var at a SCRATCH database only.

    1. ``statement_timeout`` FIRES on the shipping engine — the interlock proves the knob is sent,
       never that it cancelled anything.
    2. The session bound SURVIVES a bounded read, and the shipped lock revert form ('0') visibly does
       not produce the same face — so the §4a cell can tell the two revert targets apart.
    3. A held ``ACCESS EXCLUSIVE`` on the population the poll's fallback reads now ends in a REFUSAL
       in the shipped stale class. Before #656's fix this read was outside the seam entirely, and the
       tree's own comment on the sibling route records what that cost: the loop froze.
    """

    @staticmethod
    def _engine():
        from sqlalchemy import create_engine

        return create_engine(os.environ[PG_URL_ENV], connect_args=_PG_DEADLINE)

    @staticmethod
    def _session():
        from sqlalchemy.orm import sessionmaker

        return sessionmaker(bind=TestScanBoundPostgresql._engine())()

    def test_the_statement_deadline_really_cancels_a_slow_read(self):
        """57014 FIRES on the shipping engine — the interlock proves the knob is SENT, never that it
        cancelled anything, and no double can prove the cancellation is a real PostgreSQL fault."""
        revocation_read.configure_scan_timeout(200)
        db = self._session()
        try:
            with pytest.raises(RevocationReadScanTimeout):
                with bounded_read(db, site="heartbeat"):
                    db.execute(text("SELECT pg_sleep(3)"))
        finally:
            db.rollback()
            db.close()

    def test_a_read_inside_the_budget_answers_on_the_real_engine(self):
        """The paired half of the cell above: the bound must refuse the LONG read, not every read —
        a bound that refuses everything is a denial of service with a metric attached."""
        revocation_read.configure_scan_timeout(2000)
        db = self._session()
        try:
            with bounded_read(db, site="crl"):
                assert db.execute(text("SELECT 1")).scalar() == 1
        finally:
            db.rollback()
            db.close()

    def test_the_session_bound_survives_the_read_and_the_trap_form_does_not(self):
        """The §4a proof, both directions, in one transaction.

        Positive: after a successful bounded read the session's own bound is back — so the caller's
        NEXT statement, usually a legitimate write, runs under neither a deadline it never asked for
        nor no bound at all. The 0.3 s sleep is the test: it exceeds the 200 ms budget the seam just
        held and sits inside the session's, so a leaked narrowing refuses it and a leaked ``'0'``
        would not have been distinguishable from correct behaviour by any other means here.

        Negative: the WRONG revert is performed on purpose and reads differently. If this ever agrees
        with the positive half, the cell has stopped telling the forms apart and proves nothing.
        """
        revocation_read.configure_scan_timeout(200)
        db = self._session()
        try:
            session_before = db.execute(text("SHOW statement_timeout")).scalar()
            with bounded_read(db, site="crl"):
                assert db.execute(text("SELECT 1")).scalar() == 1
            after = db.execute(text("SHOW statement_timeout")).scalar()
            assert after == session_before, f"the seam left the session at {after!r}, found {session_before!r}"
            assert db.execute(text("SELECT pg_sleep(0.3)")).scalar() is not None, (
                "the narrowed scan deadline LEAKED past the read — the caller's next statement is now "
                "under a bound it was never meant to carry"
            )

            db.execute(text("SAVEPOINT trap"))
            db.execute(text("SET LOCAL statement_timeout = '200ms'"))
            db.execute(text("SET LOCAL statement_timeout = '0'"))
            db.execute(text("RELEASE SAVEPOINT trap"))
            assert db.execute(text("SHOW statement_timeout")).scalar() == "0", (
                "a revert to '0' is supposed to REMOVE the bound; if it reads like the session value "
                "this cell no longer distinguishes the two forms and its positive half proves nothing"
            )
        finally:
            db.rollback()
            db.close()

    def test_the_scan_deadline_is_gone_after_the_savepoint_exits(self):
        """The door-ON half of the §4a claim, read off the server rather than off a double.

        The seam's success path reverts both GUCs explicitly because ``RELEASE SAVEPOINT`` does not
        undo ``SET LOCAL`` — measured on PostgreSQL 16.15 for the lock half and recorded in the seam's
        own module docstring, and asserted in the unit suite only against a double that agrees. This
        asks the engine what it actually holds after the read, and the answer is what matters twice
        over: a leftover narrowing would put the caller's NEXT statement under a deadline it never
        asked for, and a leftover ``'0'`` on the scan GUC would remove a bound the product believes it
        installed. Both readings come from ``current_setting``, not from the seam's own statements.
        """
        revocation_read.configure_scan_timeout(200)
        db = self._session()
        try:
            lock_before = db.execute(text("SHOW lock_timeout")).scalar()
            scan_before = db.execute(text("SHOW statement_timeout")).scalar()
            with bounded_read(db, site="crl"):
                assert db.execute(text("SELECT 1")).scalar() == 1
            lock_after = db.execute(text("SHOW lock_timeout")).scalar()
            scan_after = db.execute(text("SHOW statement_timeout")).scalar()
            # Inside the savepoint the seam holds 300 ms / 200 ms; outside it, both are back to what
            # the session says. Pinned against the captured values rather than literals, because the
            # fixture's session numbers are the harness's choice, not the product's.
            assert scan_after == scan_before, f"scan bound leaked: {scan_before!r} -> {scan_after!r}"
            assert (
                lock_after == lock_before or lock_after == "0"
            ), f"lock deadline after the read is {lock_after!r}, session said {lock_before!r}"
            # The narrowing must have been real while it lasted: a sleep past the 200 ms budget but
            # inside the session's own bound answers now, and refused inside the seam.
            assert db.execute(text("SELECT pg_sleep(0.3)")).scalar() is not None
        finally:
            db.rollback()
            db.close()

    def test_the_shipped_lock_revert_restores_zero_not_the_session_value(self):
        """A fact about the shipped half, pinned because it is easy to mistake for a defect and
        easy to break while 'fixing' it symmetrically.

        ``_CLEAR_DEADLINE`` sets ``lock_timeout = '0'``, which is parity on EVERY shipping face because
        the product sets no session ``lock_timeout`` at all — only ``statement_timeout = '300s'``,
        ``synchronous_commit`` and ``enable_partition_pruning`` on the connect listener. This test
        engine is different by construction: the house ``_PG_DEADLINE`` that the #614/#630 interlock
        REQUIRES on every gated cell passes ``-c lock_timeout=5000``, so on the harness the revert to
        ``'0'`` drops that guard for the rest of the transaction. That is a harness property, not a
        product one, and it is the reason the scan half may not copy the lock revert: on the product
        ``statement_timeout``'s session value is 300 s, so a ``'0'`` there would remove a real bound.
        If a later seat 'tidies' the lock revert into a capture-and-restore, this cell fires and they
        make the choice deliberately, on both faces.
        """
        db = self._session()
        try:
            session_lock = db.execute(text("SHOW lock_timeout")).scalar()
            assert session_lock not in ("0",), (
                f"this fixture's session lock_timeout is {session_lock!r}; the cell below describes a "
                "harness that DOES set one (the required _PG_DEADLINE), so re-read it before editing"
            )
            with bounded_read(db, site="crl"):
                inside = db.execute(text("SHOW lock_timeout")).scalar()
                assert inside == "300ms", f"the seam did not hold its own deadline, saw {inside!r}"
            assert db.execute(text("SHOW lock_timeout")).scalar() == "0"
            # And the scan GUC on the SAME connection after the SAME read is back to the session value,
            # which is the whole asymmetry this leg exists to get right.
            assert db.execute(text("SHOW statement_timeout")).scalar() != "0"
        finally:
            db.rollback()
            db.close()

    def test_a_held_access_exclusive_on_the_poll_population_now_refuses(self):
        """#656 site 2, physical, both halves.

        The holder bounds ITSELF with the same deadline pair and releases in a ``finally``: a cell
        that hangs is a cell that failed, and that is the #607 shape this repo's own interlock exists
        for. The victim is the population read the poll's fallback performs.
        """
        from core.iam.models import Base, ExecutorCertRevocation

        engine = self._engine()
        Base.metadata.create_all(engine, tables=[ExecutorCertRevocation.__table__])
        db = sessionmaker(bind=engine)()
        holder = engine.connect()
        try:
            holder.execute(text("LOCK TABLE executor_cert_revocations IN ACCESS EXCLUSIVE MODE"))
            revocation_read.configure_lock_timeout(100)
            revocation_read.configure_scan_timeout(2000)
            with pytest.raises(RevocationReadUnavailable) as got:
                with bounded_read(db, site="poll/fallback-read"):
                    db.query(ExecutorCertRevocation).all()
            assert revocation_read.is_lock_timeout(got.value), "a convoy must still read as a convoy"
            assert not isinstance(got.value, RevocationReadScanTimeout)
        finally:
            holder.rollback()
            holder.close()
            db.rollback()
            db.close()
            Base.metadata.drop_all(engine, tables=[ExecutorCertRevocation.__table__])

    def test_a_held_access_exclusive_on_the_mint_population_now_refuses(self, tmp_path, monkeypatch):
        """#656 site 1, physical: the dial's self-queried mint read. Same shape as the cell above on a
        different call path — AC1's paired-site requirement is that neither site can close without the
        other, so neither gets proved by the other's cell."""
        from core.iam.models import Base, ExecutorCertRevocation
        from server.ca import CAManager

        engine = self._engine()
        Base.metadata.create_all(engine, tables=[ExecutorCertRevocation.__table__])
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "test_passphrase_654_pg")
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        db = sessionmaker(bind=engine)()
        holder = engine.connect()
        try:
            holder.execute(text("LOCK TABLE executor_cert_revocations IN ACCESS EXCLUSIVE MODE"))
            revocation_read.configure_lock_timeout(100)
            revocation_read.configure_scan_timeout(2000)
            with pytest.raises(RevocationReadUnavailable) as got:
                manager.generate_crl(db)
            assert "revocation-plane" in str(got.value) or "crl-mint" in str(got.value)
        finally:
            holder.rollback()
            holder.close()
            db.rollback()
            db.close()
            Base.metadata.drop_all(engine, tables=[ExecutorCertRevocation.__table__])
