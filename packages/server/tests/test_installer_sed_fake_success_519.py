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
``applied / already clean / FAILED-ANCHOR-MISSING`` (missing anchor is a loud
warn, never a success line), idempotently.

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
_INIT = "packages/server/src/server/routes/init.py"
_EXEC = "packages/server/src/server/routes/executors.py"

# Unpatched (old-shape) sources: every fix anchor present, none of the
# post-conditions.
UNPATCHED_DEPS = """
from __future__ import annotations
import os

def init_db():
    database_url = os.environ.get("VENYA_DB_URL")
    return database_url
"""
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

# Patched (post-condition) sources: the exact shapes the seds produce.
PATCHED_DEPS = """
import os

def init_db():
    database_url = db_config.database_url or os.environ.get("VENYA_DB_URL")
    return database_url
"""
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

# Anchor-absent sources: neither the pre- nor the post-condition for any fix.
NO_ANCHOR_DEPS = 'database_url = db_url or os.environ.get("VENYA_DB_URL")\n'
NO_ANCHOR_INIT = "def init_step():\n    pass\n"
NO_ANCHOR_EXEC = "def heartbeat():\n    pass\n"


def _write_tree(root: Path, deps: str, init: str, exec_src: str) -> None:
    for rel, content in ((_DEPS, deps), (_INIT, init), (_EXEC, exec_src)):
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


def test_anchors_present_applied() -> None:
    """Criterion 1/4 (RED at HEAD: the old code printed success unconditionally
    and fix-3/4 reported nothing at all when the file-wide grep masked them):
    with every patch anchor present, each fix applies, post-conditions land,
    and the report says 'applied' exactly four times."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, UNPATCHED_DEPS, UNPATCHED_INIT, UNPATCHED_EXEC)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (4, 0, 0), out
    # Post-conditions actually landed in the files (not just in the log):
    assert "database_url = db_config.database_url or os.environ" in (root / _DEPS).read_text()
    init_after = (root / _INIT).read_text()
    assert "from ..iam.models" not in init_after and "from core.iam.models" in init_after
    assert re.search(r"db\.add\(admin_role\)\n\s*db\.flush\(\)", init_after), init_after
    exec_after = (root / _EXEC).read_text()
    assert re.search(r"not_after = current_cert\.not_after\n.*not_after\.tzinfo", exec_after, re.DOTALL)
    assert "FAILED" not in out


def test_already_patched_reports_clean_not_failure() -> None:
    """Criterion 3 (idempotence): a second run on a patched tree reports
    'already clean' for every fix — never failure, never a re-apply, and the
    files stay byte-identical."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, PATCHED_DEPS, PATCHED_INIT, PATCHED_EXEC)
    before = {rel: (root / rel).read_bytes() for rel in (_DEPS, _INIT, _EXEC)}
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (0, 4, 0), out
    after = {rel: (root / rel).read_bytes() for rel in (_DEPS, _INIT, _EXEC)}
    assert before == after, "already-patched tree was touched"
    # Run a THIRD time: stable at 4 clean (no drift across re-installs).
    proc2 = _run_fixes(root)
    assert _counts(proc2.stdout + proc2.stderr) == (0, 4, 0), proc2.stdout


def test_anchor_absent_is_loud_never_success() -> None:
    """Criterion 1 (the headline class): with neither the pre- nor the
    post-condition present — the future upstream-change scenario — every fix
    must be a loud [WARN] FAILED-ANCHOR-MISSING and NO fix may report a
    success line. The old code's fake success (Fix 2 always printing
    'Fixed init.py imports' while sed matched nothing) must be gone."""
    root = Path(tempfile.mkdtemp())
    _write_tree(root, NO_ANCHOR_DEPS, NO_ANCHOR_INIT, NO_ANCHOR_EXEC)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    applied, clean, failed = _counts(out)
    assert failed == 4, out
    assert applied == 0 and clean == 0, out
    for line in out.splitlines():
        if "FAILED-ANCHOR-MISSING" in line:
            assert "[WARN]" in line, f"missing anchor not loud: {line}"
    assert "Fixed init" not in out, "old unconditional success line survived"


def test_file_wide_occurrence_no_longer_masks_a_needed_fix() -> None:
    """Criterion 2: the old Fix 3 skipped whenever 'db.flush()' appeared
    ANYWHERE in init.py, and Fix 4 likewise for 'not_after.tzinfo'. Now the
    anchors are patch-site specific: a file-wide occurrence away from the
    site must NOT mask the site fix (both fixes land)."""
    root = Path(tempfile.mkdtemp())
    masking_init = UNPATCHED_INIT + "\n    db.flush()  # unrelated, lives in another function\n"
    masking_exec = (
        UNPATCHED_EXEC + "\n    legacy = old_cert.not_after.tzinfo  # unrelated mention, far from the patch site\n"
    )
    _write_tree(root, UNPATCHED_DEPS, masking_init, masking_exec)
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, _clean, failed = _counts(out)
    assert failed == 0 and applied == 4, out
    init_after = (root / _INIT).read_text()
    assert re.search(r"db\.add\(admin_role\)\n\s*db\.flush\(\)", init_after), init_after


def test_current_repo_source_reports_what_is_actually_true() -> None:
    """Criterion 5 pinned as a cell: run the function against a copy of the
    CURRENT repo sources — the honest per-fix verdict at this tip, so nobody
    has to re-derive it and any source-shape drift trips here:
      Fix 1 FAILED-ANCHOR-MISSING (dependencies.py was restructured upstream —
            the line this fix patches no longer exists; removal proposed as a
            separate item in the leg report),
      Fix 2 already clean (source already uses core.iam.models),
      Fix 3 applied (flush is batched later in the block, not at the site —
            the inserted flush is redundant-but-harmless; see report),
      Fix 4 already clean (tz guard already sits at the site)."""
    root = Path(tempfile.mkdtemp())
    for rel in (_DEPS, _INIT, _EXEC):
        src = REPO_ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    proc = _run_fixes(root)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    applied, clean, failed = _counts(out)
    assert (applied, clean, failed) == (1, 2, 1), out
    assert "Fix 1 (dependencies.py db_config): FAILED-ANCHOR-MISSING" in out
    assert "Fix 2 (init.py imports): already clean" in out
    assert "Fix 3 (init.py admin_role flush): applied" in out
    assert "Fix 4 (executors.py heartbeat tz guard): already clean" in out
