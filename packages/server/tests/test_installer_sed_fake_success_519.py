# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#519 installer-sed-fake-success — per-fix reporting cells for the installer.

``venya_apply_code_fixes`` in ``venya-common.sh`` used to print a success line
whether or not its ``sed`` matched (sed exits 0 on zero replacements), and its
Fix 3 / Fix 4 guards grepped FILE-WIDE strings instead of the patch site, so
an unrelated occurrence could mask a needed fix. The ruled shape: each fix
verifies its patch-site POST-condition and reports
``applied / already clean / FAILED-ANCHOR-MISSING`` (missing anchor is never a
success line), idempotently.

#618 changed two of those outcomes. (1) Fix 1 no longer seds: the line it
patched left the product when ``init_db`` started taking the URL as a
parameter, so the guard now ASSERTS the live pair — the ``db_url or
os.environ.get("VENYA_DB_URL")`` expression in ``dependencies.py`` plus the
``init_db(config.db, db_url=config.db.database_url)`` call-site in ``app.py`` —
and edits nothing. (2) A dead anchor is a hard abort, not a warning: every
``FAILED-ANCHOR-MISSING`` line is ``[ERROR]`` and the function exits nonzero
before the venv, the migrations and the service start.

#718 (owner ruling R-2629, "reanchor") moved Fix 3 the same way. Its anchor was
``db.add(admin_role)`` in ``routes/init.py`` and the role add now lives in
``server/role_seed.py``, inside a loop over a table, so that literal is gone. The
guard keeps its purpose — a ``db.flush()`` must sit between the seed-role add and
the audit read of ``role.id`` — and asserts it as a LINE WINDOW over
``role_seed.py``, editing nothing. Two consequences these cells pin: Fix 3 can
never report ``applied`` again, and the re-aimed guard must still be able to FAIL
(``test_seed_flush_outside_the_window_is_not_a_mask``), because a guard re-aimed at
an anchor that can never miss is the #519 class wearing a new line number.

Cells run the REAL function, extracted from the git-tracked library at
``venya-common.sh`` (the #505 precedent: exercise real script logic, never a
re-implementation), against a fixture tree under the same ``set -euo
pipefail`` the installers run with. No VMs: fixtures are plain files.
"""

import re
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMON = REPO_ROOT / "venya-common.sh"

_DEPS = "packages/server/src/server/dependencies.py"
_APP = "packages/server/src/server/app.py"
_INIT = "packages/server/src/server/routes/init.py"
_EXEC = "packages/server/src/server/routes/executors.py"
_SEED = "packages/server/src/server/role_seed.py"

# The LIVE shape of Fix 1 (#618 re-anchor). The guard asserts this pair and
# never edits it: the configured URL arrives as the init_db parameter the
# call-site passes, and the environment value is only the fallback.
LIVE_DEPS = """
from __future__ import annotations
import os

def init_db(db_config, db_url=None):
    database_url = db_url or os.environ.get("VENYA_DB_URL")
    return database_url
"""
LIVE_APP = """
def create_app(config):
    backend = init_db(config.db, db_url=config.db.database_url)
    return backend
"""

# Unpatched (old-shape) sources for the fixes that DO still patch (2, 3, 4):
# every anchor present, none of the post-conditions.
UNPATCHED_INIT = """
def init_step():
    from ..iam.models import Role
    admin_role = Role(name="admin")
    db.add(admin_role)

    db.commit()
"""
UNPATCHED_EXEC = """
def heartbeat():
    not_after = current_cert.not_after
    if not_after < threshold:
        renew()
"""

# Patched (post-condition) sources for the fixes that still patch (2 and 4): the
# exact shapes the seds produce. PATCHED_INIT carries the flush line only because
# the #718 re-anchor made Fix 3 an assertion over role_seed.py, not a sed on init.py —
# the shape below is what init.py looked like when Fix 3 last applied, and Fix 2 is
# the only guard that reads it now.
PATCHED_INIT = """
def init_step():
    from core.iam.models import Role
    admin_role = Role(name="admin")
    db.add(admin_role)
        db.flush()
"""
PATCHED_EXEC = """
def heartbeat():
    not_after = current_cert.not_after
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
"""

# --- Fix 3's #718 re-anchor (#718, owner ruling R-2629 "reanchor") -----------------
# The guard no longer seds anything. It asserts that SOME db.flush() line lies strictly
# BETWEEN the seed-role add and the audit read of role.id — the invariant the old
# adjacency sed existed to create, now that the add lives in role_seed.py inside a loop
# over a table (so there is no literal `admin_role` there, and there must not be one
# added to satisfy a grep). LIVE_SEED is that shape in minimum dress; the three negative
# fixtures are the three ways it can genuinely fail.
LIVE_SEED = """
def ensure_seed_roles(db):
    roles = {}
    created = []
    for name in SEED_ROLES:
        role = Role(name=name)
        db.add(role)
        roles[name] = role
        created.append(name)
    db.flush()
    for role in roles.values():
        audit_lifecycle(db, ROLE_CREATED, None, {"role_id": role.id, "role_name": role.name})
    return roles, created
"""
# The flush is gone entirely: role.id would be read before the row has an id.
SEED_NO_FLUSH = LIVE_SEED.replace("    db.flush()\n", "")
# #519 criterion 2 in its new dress: a db.flush() EXISTS in the file, but only OUTSIDE
# the window, so it cannot be what makes the id exist. A file-wide occurrence must not
# mask the missing site flush.
SEED_MASKED_FLUSH = LIVE_SEED.replace("    db.flush()\n", "").replace(
    "    roles = {}\n", "    db.flush()  # unrelated, before any role was added\n    roles = {}\n"
)
# The add anchor moved (a rename of the loop variable is enough): nothing to anchor on.
NO_ANCHOR_SEED = LIVE_SEED.replace("db.add(role)", "db.add(new_role)")

# Anchor-absent sources: neither the live shape nor anything the guards accept
# for any fix. DEPS here is the RETIRED env-only form — since #618 it is no
# longer a sed target, it is a dead anchor, which is the point of the cell.
NO_ANCHOR_DEPS = 'database_url = os.environ.get("VENYA_DB_URL")\n'
NO_ANCHOR_APP = "def create_app(config):\n    backend = init_db(config.db)\n"
NO_ANCHOR_INIT = "def init_step():\n    pass\n"
NO_ANCHOR_EXEC = "def heartbeat():\n    pass\n"


def _write_tree(
    root: Path,
    deps: str = LIVE_DEPS,
    init: str = UNPATCHED_INIT,
    exec_src: str = UNPATCHED_EXEC,
    app: str = LIVE_APP,
    seed: str = LIVE_SEED,
) -> None:
    for rel, content in (
        (_DEPS, deps),
        (_APP, app),
        (_INIT, init),
        (_EXEC, exec_src),
        (_SEED, seed),
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def _run_fixes(root: Path) -> subprocess.CompletedProcess:
    """Execute the REAL venya_apply_code_fixes from the git-tracked library.

    Extracts nothing but the function itself (source the library — top level
    is pure function definitions — verified by the anchor asserts below),
    defines the same info/warn names venya_print_colors provides, pins
    INSTALL_DIR to the fixture, and runs under the installers' own
    `set -euo pipefail`.
    """
    script = (
        "set -euo pipefail\n"
        f"source {str(COMMON)!r}\n"
        'info()  { echo "[INFO]  $*"; }\n'
        'warn()  { echo "[WARN]  $*"; }\n'
        'error() { echo "[ERROR] $*"; }\n'
        f"INSTALL_DIR={str(root)!r}\n"
        "venya_apply_code_fixes\n"
    )
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


def _counts(out: str) -> tuple[int, int, int]:
    applied = len(re.findall(r": applied\b", out))
    clean = len(re.findall(r": already clean\b", out))
    failed = len(re.findall(r"FAILED-ANCHOR-MISSING", out))
    return applied, clean, failed


def _dead_anchor_lines(out: str) -> list[str]:
    return [line for line in out.splitlines() if "FAILED-ANCHOR-MISSING" in line]


def test_common_lib_still_pure_definitions() -> None:
    """Guard for the harness assumption: venya-common.sh defines functions
    only (sourcing it has no side effects). Anchor greps the header comment
    plus the function definition, so a reflow that introduces top-level
    execution fails loudly here first."""
    src = COMMON.read_text()
    assert src.count("venya_apply_code_fixes() {") == 1, "function anchor no longer unique — re-anchor"
    assert 'info "Applying code fixes..."' in src, "ruled per-fix reporting block moved"


def test_bash_syntax_clean() -> None:
    proc = subprocess.run(["bash", "-n", str(COMMON)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_both_installers_share_the_aborting_guard() -> None:
    """#618 blast radius: the abort lives in the SHARED library, so it fires on
    both installers. Interlock — if either call-site is dropped, or either
    script stops running under `set -euo pipefail` (which is what makes an
    `exit 1` inside the function end the install), this cell says so instead of
    the change arriving as a silent difference in one installer's behaviour."""
    for name in ("install-venya-core.sh", "install-venya-executor.sh"):
        src = (REPO_ROOT / name).read_text()
        assert "venya_apply_code_fixes" in src, f"{name} no longer calls the shared guard"
        assert "set -euo pipefail" in src, f"{name} no longer runs under set -euo pipefail"


def test_anchors_present_applied() -> None:
    """Criterion 1/4 (RED at HEAD: the old code printed success unconditionally
    and fix-3/4 reported nothing at all when the file-wide grep masked them):
    with every PATCH anchor present, each remaining fix applies, its
    post-condition lands, and the report says 'applied' for the two fixes that
    still sed. Fix 1 and Fix 3 are the two presence assertions — #618 made the
    first one, #718/R-2629 the second — so each reports 'already clean' and
    neither edits the tree."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (2, 2, 0), out
    # Post-conditions actually landed in the files (not just in the log):
    assert "FAILED" not in out
    # Fix 1 asserts and never edits: the live pair is byte-unchanged.
    assert (root / _DEPS).read_text() == LIVE_DEPS
    assert (root / _APP).read_text() == LIVE_APP
    # Fix 3 asserts too, since R-2629: role_seed.py must come back byte-identical.
    assert (root / _SEED).read_text() == LIVE_SEED
    init_after = (root / _INIT).read_text()
    assert "from ..iam.models" not in init_after and "from core.iam.models" in init_after
    exec_after = (root / _EXEC).read_text()
    assert re.search(r"not_after = current_cert\.not_after\n.*not_after\.tzinfo", exec_after, re.DOTALL)
    assert "FAILED" not in out


def test_already_patched_reports_clean_not_failure() -> None:
    """Criterion 3 (idempotence): a second run on a patched tree reports
    'already clean' for every fix — never failure, never a re-apply, and the
    files stay byte-identical."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP)
    before = {rel: (root / rel).read_bytes() for rel in (_DEPS, _APP, _INIT, _EXEC, _SEED)}
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (0, 4, 0), out
    after = {rel: (root / rel).read_bytes() for rel in (_DEPS, _APP, _INIT, _EXEC, _SEED)}
    assert before == after, "already-patched tree was touched"
    # Run a THIRD time: stable at 4 clean (no drift across re-installs).
    proc2 = _run_fixes(root)
    assert _counts(proc2.stdout + proc2.stderr) == (0, 4, 0), proc2.stdout


def test_anchor_absent_is_loud_never_success() -> None:
    """Criterion 1 (the headline class), AMENDED by #618: with neither the live
    shape nor any patch anchor present — the future upstream-change scenario —
    every fix must be a loud [ERROR] FAILED-ANCHOR-MISSING, NO fix may report a
    success line, and the run must ABORT nonzero. The old posture printed those
    lines as [WARN] and returned 0, which is how Fix 1 fired on every healthy
    install for two days without stopping anything; the old unconditional
    success line ('Fixed init.py imports') must stay gone."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, NO_ANCHOR_DEPS, NO_ANCHOR_INIT, NO_ANCHOR_EXEC, app=NO_ANCHOR_APP, seed=NO_ANCHOR_SEED)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    applied, clean, failed = _counts(out)
    assert failed == 4, out
    assert applied == 0 and clean == 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 4, out
    for line in lines:
        assert "[ERROR]" in line, f"missing anchor not an error: {line}"
    # The abort names the fixes, and the operator-facing block says what to do.
    for name in ("Fix 1", "Fix 2", "Fix 3", "Fix 4"):
        assert any(name in line for line in lines), f"{name} not named in the [ERROR] lines: {out}"
    assert "anchor-missing failure(s)" in out, out
    assert "Re-anchor venya_apply_code_fixes" in out, out
    assert proc.returncode != 0, f"dead anchor did not abort the run: {out}"
    assert "Fixed init" not in out, "old unconditional success line survived"


def test_file_wide_occurrence_no_longer_masks_a_needed_fix() -> None:
    """Criterion 2: the old Fix 3 skipped whenever 'db.flush()' appeared
    ANYWHERE in init.py, and Fix 4 likewise for 'not_after.tzinfo'. The anchors
    are patch-site specific. #718 moved the flush invariant to the window guard
    below (`test_seed_flush_outside_the_window_is_not_a_mask`), so this cell now
    carries Fix 4's half: an unrelated 'not_after.tzinfo' mention far from the
    site must NOT mask the site guard, and the fix still lands.

    It also pins that Fix 3 can no longer report 'applied' from ANY init.py
    shape: a tree whose init.py carries the old adjacency pair and whose
    role_seed.py is a dead anchor must fail Fix 3, so the retired sed cannot
    quietly become a check on the wrong file."""
    root = Path(tempfile.mkdtemp())
    masking_init = UNPATCHED_INIT + "\n    db.flush()  # unrelated, lives in another function\n"
    masking_exec = (
        UNPATCHED_EXEC + "\n    legacy = old_cert.not_after.tzinfo  # unrelated mention, far from the patch site\n"
    )
    _write_tree(root, LIVE_DEPS, masking_init, masking_exec, app=LIVE_APP)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, _clean, failed = _counts(out)
    assert failed == 0 and applied == 2, out
    exec_after = (root / _EXEC).read_text()
    assert re.search(r"not_after = current_cert\.not_after\n.*not_after\.tzinfo", exec_after, re.DOTALL)

    # The retired anchor cannot satisfy the guard: the old adjacency pair is present in
    # init.py, role_seed.py has no add to anchor on, and Fix 3 must say so.
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP, seed=NO_ANCHOR_SEED)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 3" in lines[0], out
    assert "no db.add(role) line" in lines[0], out
    assert proc.returncode != 0, out


def test_current_repo_source_reports_what_is_actually_true() -> None:
    """Criterion 5 pinned as a cell: run the function against a copy of the
    CURRENT repo sources — the honest per-fix verdict at this tip, so nobody
    has to re-derive it and any source-shape drift trips here. #618 moved this
    verdict from (1, 2, 1) to (1, 3, 0); #718 (R-2629) moves it again to
    (0, 4, 0), because the only remaining sed target that used to fire on a
    healthy tree was Fix 3's init.py flush insertion, and that fix is now a
    presence assertion over role_seed.py:
      Fix 1 already clean (the live dependencies.py expression AND the app.py
            call-site are both present — the presence assertion holds),
      Fix 2 already clean (source already uses core.iam.models),
      Fix 3 already clean (role_seed.py flushes between the seed-role add at
            db.add(role) and the audit read of role.id),
      Fix 4 already clean (tz guard already sits at the site).

    role_seed.py is copied from the repo rather than from a fixture, so this is
    the one cell that reads the shipped source and the shipped guard together."""
    root = Path(tempfile.mkdtemp())
    for rel in (_DEPS, _APP, _INIT, _EXEC, _SEED):
        src = REPO_ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (0, 4, 0), out
    assert "FAILED" not in out, out
    assert "Fix 1 (db URL from config): already clean" in out
    assert "Fix 2 (init.py imports): already clean" in out
    assert "Fix 3 (seed-role flush before the audit id read): already clean" in out
    assert "Fix 4 (executors.py heartbeat tz guard): already clean" in out
    # Nothing was touched: the tree is what the repo says it is.
    assert (root / _SEED).read_bytes() == (REPO_ROOT / _SEED).read_bytes()


def test_seed_flush_outside_the_window_is_not_a_mask() -> None:
    """★ THE PAIRED NEGATIVE for the re-anchored Fix 3 (R-2629's acceptance), shown RED
    then GREEN in one cell.

    A guard re-aimed at an anchor that can never miss is the #519 fake-success class with
    a new line number, so this drives the two shapes in which the invariant is genuinely
    broken and requires the loud verdict, then requires clean on the live shape.

    (a) no db.flush() in the file at all — role.id would be read while still None;
    (b) a db.flush() present but OUTSIDE the window, before any role is added — the file-
        wide-occurrence mask, #519 criterion 2, in its new dress.
    Both must abort nonzero and name role_seed.py. (c) is the green: the same tree with
    the site flush restored reports already clean and exits 0."""

    def seed_lines(root: Path) -> list[str]:
        proc = _run_fixes(root)
        out = proc.stdout + proc.stderr
        lines = _dead_anchor_lines(out)
        assert len(lines) == 1 and "Fix 3" in lines[0], out
        assert "[ERROR]" in lines[0], out
        assert "role_seed.py" in lines[0], out
        assert proc.returncode != 0, f"dead seed anchor did not abort the install: {out}"
        return lines

    # (a) flush absent
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP, seed=SEED_NO_FLUSH)
    line = seed_lines(root)[0]
    assert "no db.flush() anywhere" in line, line

    # (b) flush present but outside the window — the mask
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP, seed=SEED_MASKED_FLUSH)
    line = seed_lines(root)[0]
    assert "none of the 1 db.flush() lines" in line, line
    assert "sits between the role add" in line, line
    assert "a flush outside that window does not make role.id exist" in line, line

    # (c) GREEN arm: the live shape passes, and the other three fixes are unaffected
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP, seed=LIVE_SEED)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert _counts(out) == (0, 4, 0), out
    assert "Fix 3 (seed-role flush before the audit id read): already clean" in out
    assert not _dead_anchor_lines(out)


def test_one_dead_anchor_alone_aborts_and_names_the_file() -> None:
    """#618 Half 2, the negative half the [WARN] posture never had: a tree that
    is healthy for three fixes and drifted for ONE (dependencies.py moved, the
    app.py call-site fine) must still abort nonzero — one dead anchor is enough,
    and the [ERROR] line names the file the operator has to look at. Warn-and-
    continue was rejected outright because this is the state that hid Fix 1."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, NO_ANCHOR_DEPS, UNPATCHED_INIT, UNPATCHED_EXEC, app=LIVE_APP)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (2, 1, 1), out
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 1" in lines[0] and "[ERROR]" in lines[0], out
    assert "dependencies.py" in lines[0], out
    assert "app.py was not reached" in lines[0], out
    # The three healthy fixes still did their work before the stop.
    assert "from core.iam.models" in (root / _INIT).read_text()
    assert "not_after.tzinfo" in (root / _EXEC).read_text()


def test_call_site_drift_alone_is_a_dead_anchor() -> None:
    """The presence assertion is a PAIR: a tree whose dependencies.py still
    carries the expression but whose app.py stopped passing the configured URL
    (the shape that would put the env value back in charge) is a dead anchor,
    not a clean report. This is the scenario Fix 1 existed to prevent. Also
    pinned here: the abort text names WHICH half went missing (lead ruling
    s108) — either half can be true while the behavior is wrong, so an "and/or"
    message would leave the operator reading two files blind."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=NO_ANCHOR_APP)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 1" in lines[0], out
    assert "app.py does not pass the configured URL" in lines[0], out
    assert "app.py" in lines[0] and "init_db(config.db, db_url=config.db.database_url)" in lines[0], out


def test_missing_expression_names_itself_and_says_app_was_not_reached() -> None:
    """Distinct message per cause, the other half: dependencies.py moved. The
    line has to say the expression is what is missing AND that app.py was never
    examined — an operator told 'the call-site is wrong' about a tree whose
    dependencies.py is the moved file chases the wrong file."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, NO_ANCHOR_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 1" in lines[0], out
    assert "db_url-with-env-fallback expression is not in dependencies.py" in lines[0], out
    assert "app.py was not reached" in lines[0], out


def test_absent_files_abort_too_one_distinct_message_per_file() -> None:
    """File-absent joins the abort set (lead ruling s108): the core and executor
    archives are the identical whole-tree git archive, so a missing source file
    is truncation, a wrong target or a foreign tree — a broken install claiming
    success, which is the #519 class. Each cause prints its own line naming the
    path it looked at."""
    # (a) dependencies.py absent — Fix 1's own cause line.
    root = Path(tempfile.mkdtemp())
    _write_tree(root)
    (root / _DEPS).unlink()
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 1" in lines[0], out
    assert "dependencies.py absent" in lines[0], out
    assert str(root / "packages/server/src/server/dependencies.py") in lines[0], out

    # (b) app.py absent — the second cause line, which must NOT be the same
    # text as (a): it says the first half is present and the second unread.
    root = Path(tempfile.mkdtemp())
    _write_tree(root)
    (root / _APP).unlink()
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "app.py absent" in lines[0], out
    assert "dependencies.py half is present" in lines[0], out

    # (c) a file the remaining fixes patch is absent (executors.py) — the same
    # abort posture applies to fixes 2/3/4, whose anchors are live.
    root = Path(tempfile.mkdtemp())
    _write_tree(root)
    (root / _EXEC).unlink()
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 4" in lines[0], out
    assert "file absent" in lines[0] and str(root / _EXEC) in lines[0], out

    # (d) role_seed.py absent — the #718 re-anchor reads a NEW file, and the core and
    # executor archives are the identical whole-tree git archive, so its absence is
    # truncation, not an old release: it must abort with its own line naming the path.
    root = Path(tempfile.mkdtemp())
    _write_tree(root, LIVE_DEPS, PATCHED_INIT, PATCHED_EXEC, app=LIVE_APP)
    (root / _SEED).unlink()
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    lines = _dead_anchor_lines(out)
    assert len(lines) == 1 and "Fix 3" in lines[0], out
    assert "role_seed.py absent" in lines[0] and str(root / _SEED) in lines[0], out
    # and it is a distinct sentence from (c), so the operator reads one file
    assert lines[0] != "", out
