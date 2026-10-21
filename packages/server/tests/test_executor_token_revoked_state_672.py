"""#672 — the ``revoked`` state on the EXECUTOR token plane is a dead state.

``routes/executors.py::register_executor`` READS ``ExecutorEnrollmentToken.state == "revoked"`` at
two sites, but no shipped verb ever WRITES that value on this plane. This module enforces the
disclosure attached to those reads: the guard cells below fail if a writer is ever introduced, so
the comment cannot rot into a lie, and they fail if someone deletes the read branches to make the
claim true by removal (which the ruling forbids).

Scope of the claim (measured at the tip this leg was cut from):
  - executor-plane writers: ``routes/admin.py::admin_enroll_executor`` mints ``state="created"``
    (the model default is also ``"created"``) and ``routes/executors.py::register_executor``
    consumes with a raw ``UPDATE ... SET state = 'consumed'``. That is the complete set.
  - ``revoked`` IS written for real on the USER plane, by
    ``core/iam/enrollment_manager.py::EnrollmentManager.revoke_token`` and
    ``EnrollmentManager.revoke_all_active_tokens``, both on ``EnrollmentToken``.
  - ``maintenance.py::purge_admin_identity_metadata`` writes no ``state`` at all, and expiry is
    computed (``is_expired``), never stored as ``"expired"``.

Zero behavior change is the acceptance test: the refusal branches are asserted to behave exactly
as they do today, not improved.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# House pattern (see test_admin_revocation_read_bound_658.py): tests/ is a package, so the sibling
# helpers import relatively under the rootdir run and flat under the per-package tests-path run.
try:  # pragma: no cover - import-mode detail
    from .test_executor_enrollment import _create_test_app, _generate_test_csr, _make_mock_ca
except ImportError:  # pytest rootdir/tests-path import mode
    from test_executor_enrollment import _create_test_app, _generate_test_csr, _make_mock_ca

REPO_ROOT = Path(__file__).resolve().parents[3]

# ---------------------------------------------------------------- scan plumbing

EXECUTOR_RE = re.compile(r"\bExecutorEnrollmentToken\b|executor_enrollment_tokens")
USER_RE = re.compile(r"\bEnrollmentToken\b|\benrollment_tokens\b")
# raw SQL writes: UPDATE <table> SET state = 'x'
SQL_STATE_WRITE_RE = re.compile(r"\bSET\s+state\s*=\s*'([A-Za-z_]+)'", re.IGNORECASE)

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _source_and_tree(path: Path) -> tuple[str, ast.Module]:
    src = path.read_text(encoding="utf-8")
    return src, ast.parse(src, filename=str(path))


def _state_writes(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Every shipped ``state`` STRING write in one module: (lineno, value, kind)."""
    out: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        # obj.state = "value"
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = getattr(node, "value", None)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                for tgt in targets:
                    if isinstance(tgt, ast.Attribute) and tgt.attr == "state":
                        out.append((tgt.lineno, value.value, "orm-attr"))
        # Model(state="value") / .update(state="value")
        if (
            isinstance(node, ast.keyword)
            and node.arg == "state"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            out.append((node.value.lineno, node.value.value, "kwarg"))
        # {"state": "value"} — the .update(dict) form
        if isinstance(node, ast.Dict):
            for key, val in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "state"
                    and isinstance(val, ast.Constant)
                    and isinstance(val.value, str)
                ):
                    out.append((val.lineno, val.value, "dict"))
        # raw SQL: SET state = 'value'
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for match in SQL_STATE_WRITE_RE.finditer(node.value):
                out.append((node.lineno, match.group(1), "sql"))
    return out


def _shipped_sources() -> list[Path]:
    """All product source under packages/*/src (tests and migrations are not shipped verbs)."""
    return sorted(p for p in REPO_ROOT.glob("packages/*/src/**/*.py") if p.is_file())


def _plane_writes() -> list[dict]:
    """(file, function, value, kind) for every state write, tagged with the plane its function acts on."""
    rows = []
    for path in _shipped_sources():
        src, tree = _source_and_tree(path)
        for lineno, value, kind in _state_writes(tree):
            holder = next(
                (
                    n
                    for n in ast.walk(tree)
                    if isinstance(n, FUNCTION_NODES) and n.lineno <= lineno <= (n.end_lineno or n.lineno)
                ),
                None,
            )
            seg = ast.get_source_segment(src, holder) if holder else ""
            seg = seg or ""
            if EXECUTOR_RE.search(seg):
                plane = "executor"
            elif USER_RE.search(seg):
                plane = "user"
            else:
                plane = "unknown"
            rows.append(
                {
                    "file": str(path.relative_to(REPO_ROOT)),
                    "function": holder.name if holder else "<module>",
                    "value": value,
                    "kind": kind,
                    "plane": plane,
                }
            )
    return rows


def _fmt(rows: list[dict]) -> str:
    return (
        "\n".join(f"  {r['file']}::{r['function']} -> state={r['value']!r} ({r['kind']}, {r['plane']})" for r in rows)
        or "  (none)"
    )


# ---------------------------------------------------------------- the guards


def test_no_shipped_writer_sets_revoked_on_the_executor_token_plane():
    """The #672 claim. A writer here turns this red by name instead of making the code comment false."""
    offenders = [r for r in _plane_writes() if r["plane"] == "executor" and r["value"] == "revoked"]
    assert not offenders, (
        "a shipped verb now writes state='revoked' on the EXECUTOR plane (ExecutorEnrollmentToken).\n"
        "Either the revoke capability was built (then update the disclosure comments in "
        "routes/executors.py::register_executor and the two other cells in this file) or this is "
        "unintended.\nWriters that appeared:\n" + _fmt(offenders)
    )


def test_executor_plane_writer_value_set_is_exactly_created_and_consumed():
    """The mint and the consume are the WHOLE state machine on this plane.

    Any other value written here — revoked, expired, or a new one — means the plane grew without
    this row, which is the silent-rot case the disclosure exists to prevent.
    """
    values = {r["value"] for r in _plane_writes() if r["plane"] == "executor"}
    assert values == {"created", "consumed"}, f"executor-plane state writers changed: {sorted(values)!r}"
    # expiry is COMPUTED (is_expired), never stored, so "expired" must stay absent from that set.


def test_revoked_writers_exist_on_the_user_plane_and_are_named():
    """Positive control for the scan AND the paired negative: the OTHER plane keeps its real revoke.

    If the scanner ever stops seeing writes at all (pattern drift, bad glob), this goes red first
    instead of letting the two guard cells above pass vacuously.
    """
    revoked = {
        (r["function"])
        for r in _plane_writes()
        if r["plane"] == "user" and r["value"] == "revoked" and r["file"].endswith("core/iam/enrollment_manager.py")
    }
    assert revoked == {"revoke_token", "revoke_all_active_tokens"}, (
        f"user-plane revoke writers changed: {sorted(revoked)!r} — the executor-plane assertion is "
        "only meaningful while the scanner still sees the real revocation path"
    )


def test_no_file_that_touches_the_executor_plane_writes_a_revoked_state():
    """Scope-level classification can be dodged by a helper that takes a row; this one cannot.

    Any source file that references the executor token model or table at all is held to writing no
    ``revoked`` state anywhere in itself. Today that is routes/executors.py, routes/admin.py,
    maintenance.py and core/iam/models.py, and none of them do.
    """
    offenders = []
    for path in _shipped_sources():
        src, tree = _source_and_tree(path)
        if not EXECUTOR_RE.search(src):
            continue
        for _lineno, value, kind in _state_writes(tree):
            if value == "revoked":
                offenders.append(f"{path.relative_to(REPO_ROOT)} ({kind})")
    assert not offenders, f"executor-plane-touching file writes state='revoked': {offenders}"


def test_the_two_read_branches_are_still_there():
    """The ruling says do not DELETE the dead reads; passing #672 by removing them is not allowed.

    Exactly two ``token.state == "revoked"`` readers exist on the executor plane, both inside
    register_executor (the pre-check and the lost-race re-read).
    """
    src, _tree = _source_and_tree(REPO_ROOT / "packages/server/src/server/routes/executors.py")
    readers = re.findall(r'token\.state\s*==\s*"revoked"', src)
    assert len(readers) == 2, f"expected the two #672 read sites, found {len(readers)} — do not delete them"
    assert "#672" in src, "the dead-state disclosure comment must stay attached to those reads"


# ---------------------------------------------------------------- behavior: unchanged


@pytest.fixture
def _reset_rate_limiter():
    """Same isolation the existing enrollment suite uses (shared _LIMITERS cache)."""
    from server import rate_limit as _rl

    saved = dict(_rl._LIMITERS)
    _rl._LIMITERS.clear()
    yield
    _rl._LIMITERS.clear()
    _rl._LIMITERS.update(saved)


def _mock_token(executor_id: str, plaintext: str, state: str, *, expires_at: datetime | None = None):
    from unittest.mock import MagicMock

    token = MagicMock()
    token.id = 42
    token.executor_id = executor_id
    token.state = state
    token.token_hash = hmac.new(b"test-pepper-12345", plaintext.encode(), hashlib.sha256).hexdigest()
    token.expires_at = expires_at or (datetime.now(UTC) + timedelta(minutes=10))
    return token


def _client_for_token(mock_token):
    """Drive POST /api/v1/executors/register with a token row whose state is mock_token.state."""
    from unittest.mock import MagicMock

    db = MagicMock()
    backend = MagicMock()
    backend.get_session.return_value = db
    app = _create_test_app(backend=backend, ca_manager=_make_mock_ca())
    query = MagicMock()
    query.filter.return_value.first.return_value = mock_token
    db.query.side_effect = lambda model: query
    # UPDATE ... SET state='consumed' -> rowcount 0, i.e. the token was NOT consumed by this call
    db.execute.return_value = MagicMock(rowcount=0)
    return TestClient(app, raise_server_exceptions=False), db, _generate_test_csr()


def test_unreachable_revoked_branch_still_refuses_with_401(_reset_rate_limiter):
    """The dead state, driven by hand: the branch is correct, it is only never reachable in production."""
    client, db, csr = _client_for_token(_mock_token("t672-exec", "enrl_672_revoked", "revoked"))
    resp = client.post(
        "/api/v1/executors/register",
        json={"executor_id": "t672-exec", "csr_pem": csr, "enrollment_token": "enrl_672_revoked"},
    )
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"]
    assert not db.execute.called, "a refused token must not reach the consumption UPDATE"


def test_garbage_state_is_not_waved_past_and_still_refuses(_reset_rate_limiter):
    """Paired negative: an unknown state value is refused today; this cell states that, it does not improve it."""
    client, _db, csr = _client_for_token(_mock_token("t672-exec", "enrl_672_garbage", "banana"))
    resp = client.post(
        "/api/v1/executors/register",
        json={"executor_id": "t672-exec", "csr_pem": csr, "enrollment_token": "enrl_672_garbage"},
    )
    assert resp.status_code == 401, "a state no shipped verb can write must not authenticate a registration"
    assert "invalid or expired" in resp.json()["detail"]


def test_expired_created_token_refuses_without_any_state_write(_reset_rate_limiter):
    """TTL is the real lifecycle on this plane: expiry is computed, never stored as state='expired'."""
    token = _mock_token("t672-exec", "enrl_672_expired", "created", expires_at=datetime.now(UTC) - timedelta(minutes=5))
    client, db, csr = _client_for_token(token)
    resp = client.post(
        "/api/v1/executors/register",
        json={"executor_id": "t672-exec", "csr_pem": csr, "enrollment_token": "enrl_672_expired"},
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"]
    assert not db.execute.called, "expiry must be computed at validation time, not written back to state"
    assert token.state == "created", "the refusal must not mutate the stored state"


def test_user_plane_revoke_still_writes_revoked_in_the_db(tmp_path):
    """The other half of the paired negative, run for real: breaking the user plane is not how this row passes."""
    from core.iam.enrollment_manager import EnrollmentManager
    from core.iam.models import Base, EnrollmentToken, User
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'mint672.db'}")

    # #634: a sqlite engine without this listener declares every FK and enforces none, and the
    # core interlock reddens any new blind engine file. House shape is test_secret_delete_fk.py.
    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as s:
        s.add(User(user_id="u672", status="pending_enrollment"))
        s.commit()
        manager = EnrollmentManager(s)
        token, _plaintext = manager.create_enrollment_token("u672")
        token_id = token.id
        s.commit()

        assert manager.revoke_token(token_id) is True
        s.commit()
        stored = s.query(EnrollmentToken).filter_by(id=token_id).one()
        assert stored.state == "revoked", "EnrollmentManager.revoke_token is the REAL revoke path — it must stay real"
        # and it is the USER plane: the executor table got nothing from that call
        assert s.query(EnrollmentToken).count() == 1
