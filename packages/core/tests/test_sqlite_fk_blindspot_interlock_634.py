# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#634 AC4 — the interlock that stops the sqlite-FK blind spot from re-accumulating.

Why a guard at all. SQLite does not enforce foreign keys unless the connection asks it to, so a test
engine built without ``PRAGMA foreign_keys=ON`` runs with every constraint DECLARED and NOT ACTIVE.
#634 measured that face and found it large: enforcement forced ON turns **116 cells red across 21
files**. Without an interlock, the next test file that opens a sqlite engine inherits the blindness
silently and nobody re-counts for another year.

Why this guard is AST and not grep — and this is the row's own lesson applied to itself. The original
measurement instrument was::

    git grep -lE "create_engine\\(\\s*[\"']sqlite"

That pattern requires a quote immediately after the open paren, so it is blind to
``create_engine(f"sqlite:///{db_path}")``, ``create_engine(url)`` where ``url`` was assigned two lines
above, and ``create_engine(\\n    "sqlite://",\\n)``. Measured on the same tree with the same file set:
the grep sees **23 engine-builder files / 15 blind**; the AST scan here sees **80 files / 66 blind**. And
grep over-counts as well as under-counts — it matches inside string literals, so this file's own
parametrised source samples read to grep as engines that build nothing. A grep-based
interlock would therefore green-light every f-string engine forever — the exact blind-spot-within-a-
check that #640, #649 and #650 are all about, and the same class as a bare-directory pathspec returning
a confident zero. **The instrument is the finding, and it is wrong in both directions.**

Design: a RATCHET, not a promise. ``BASELINE`` below is the frozen set of files that build a sqlite
engine and do not install enforcement, at ``dev 492fe4e``. The guard does not demand an empty baseline
(that would be 66 files in one leg, the thing the lead ruled into tranches); it demands **no growth** —
a new blind site reddens, and so does a silently-disappearing one, because a file that stopped being an
engine-builder while still listed means the scanner changed under us.

Named exemptions (``EXEMPT``) are honest, declared, and reasoned — never inferred from a string match.
``test_sqlite_engine_factory_policy.py`` is the AC3 case: its cells deliberately exercise the blind
engine, because that file's whole subject is proving the blindness exists.

Every negative half mutates an in-memory source string only. No file on disk is written by this suite.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

#: Repo root, resolved from this file so the guard works from any package's pytest run.
#: This file lives at <root>/packages/core/tests/, so the root is FOUR parents up. Getting this wrong
#: is self-demonstrating: from ``packages/`` the pathspec ``packages/*/tests/*.py`` matches nothing and
#: the scan returns a confident zero — the same false-zero this whole row is about. The
#: ``test_positive_control_…`` cell below is what catches it.
ROOT = Path(__file__).resolve().parents[3]

#: Files that build a sqlite engine and do NOT install ``PRAGMA foreign_keys=ON``, **generated from the
#: scanner at ``dev 492fe4e`` BEFORE tranche 1 (66 entries) — not hand-typed** (the first draft of this list
#: was hand-written and the guard immediately caught three wrong paths and two files that do install
#: enforcement, which is the argument for generating it). Shrinks one file per tranche;
#: must never grow.
#:
#: # shortcut: 66 grandfathered blind engine-builders remain, upgrade one per tranche; tranches after
#: tranche 1 are gated on flash1/#645, ultra/#612-594 and flash3/#649 clearing the shared test surface,
#: per the lead's s134 ruling (wave30-specs-20261017/wren-634-ruling-flash2-s134.md §1).
#: Re-derive with: ``uv run -p 3.14 python -c "import importlib.util; ..."`` — see §Regenerating this
#: baseline in this file's module docstring.
BASELINE: frozenset[str] = frozenset(
    {
        "packages/cli/tests/test_recovery_e2e.py",
        "packages/core/tests/test_capability_isolation.py",
        "packages/core/tests/test_cert_serial_canonical.py",
        "packages/core/tests/test_core.py",
        "packages/core/tests/test_db_kek_passphrase_length_floor_573.py",
        "packages/core/tests/test_enrollment_cap_advisory_lock.py",
        "packages/core/tests/test_kek_salt.py",
        "packages/core/tests/test_kek_sentinel.py",
        "packages/core/tests/test_migration_027_bootstrap.py",
        "packages/core/tests/test_migration_028_single_active.py",
        "packages/core/tests/test_migration_032_kek_sentinel.py",
        "packages/core/tests/test_migration_033_command_argv.py",
        "packages/core/tests/test_migration_034_access_token_expiry.py",
        "packages/core/tests/test_migration_035_elevation_session.py",
        "packages/core/tests/test_migration_036_elevation_challenges.py",
        "packages/core/tests/test_migration_037_fido2_challenges.py",
        "packages/core/tests/test_migration_038_attestation_columns.py",
        "packages/core/tests/test_role_manager_admin_lockout_443.py",
        "packages/core/tests/test_role_manager_auditor.py",
        "packages/core/tests/test_role_manager_sod_race_514.py",
        "packages/core/tests/test_secret_put_upsert_515.py",
        "packages/core/tests/test_session_cleanup_hard_cap_529.py",
        "packages/core/tests/test_session_manager_gate.py",
        "packages/core/tests/test_session_revoke_elevation_527.py",
        "packages/server/tests/fido2_db.py",
        "packages/server/tests/test_admin_cert_issue_authz_rf7.py",
        "packages/server/tests/test_admin_cert_issue_rf7.py",
        "packages/server/tests/test_admin_display_name_width_520.py",
        "packages/server/tests/test_admin_executor_removal_391.py",
        "packages/server/tests/test_admin_mtls.py",
        "packages/server/tests/test_admin_role_lockout_guards_443.py",
        "packages/server/tests/test_admin_session_timeout_dead_write_625.py",
        "packages/server/tests/test_admin_string_validation.py",
        "packages/server/tests/test_audit.py",
        "packages/server/tests/test_audit_executor_id_filter_613.py",
        "packages/server/tests/test_audit_ingest_zstd_bound_473.py",
        "packages/server/tests/test_audit_key_filter_607.py",
        "packages/server/tests/test_credentials.py",
        "packages/server/tests/test_elevation_challenge_db_state_528.py",
        "packages/server/tests/test_enroll_label_width_518.py",
        "packages/server/tests/test_enrollment_used_at_462.py",
        "packages/server/tests/test_execute_session_replay_513.py",
        "packages/server/tests/test_executor_revocation_identity.py",
        "packages/server/tests/test_fail_open_elevation_442.py",
        "packages/server/tests/test_fido2_attestation_store_leg1.py",
        "packages/server/tests/test_fido2_manager.py",
        "packages/server/tests/test_forwarded_cert_rotation_498.py",
        "packages/server/tests/test_init.py",
        "packages/server/tests/test_init_concurrent_admin_510.py",
        "packages/server/tests/test_kek_sentinel_startup.py",
        "packages/server/tests/test_key_rotation.py",
        "packages/server/tests/test_lifecycle_audit_events.py",
        "packages/server/tests/test_maintenance.py",
        "packages/server/tests/test_orderby_tiebreaker_463.py",
        "packages/server/tests/test_publisher_resurrection_626.py",
        "packages/server/tests/test_rate_limit_middleware.py",
        "packages/server/tests/test_recovery.py",
        "packages/server/tests/test_recovery_double_spend_512.py",
        "packages/server/tests/test_revocation_read_bound_603.py",
        "packages/server/tests/test_revocation_scan_bound_654.py",
        "packages/server/tests/test_revocation_snapshot_603.py",
        "packages/server/tests/test_secret_session_scoping_440.py",
        "packages/server/tests/test_secrets.py",
        "packages/server/tests/test_session_secrets_revoke_real_411.py",
        "packages/server/tests/test_sod_admin_create_user.py",
        "packages/server/tests/test_stale_arm_refusal_count_657.py",
    }
)

#: Declared, reasoned exemptions. A file here is NOT counted against the ratchet.
EXEMPT: dict[str, str] = {
    # AC3 named exemption, per the lead's s134 ruling. This file's subject IS the blind engine: its
    # cells prove the shipped factory cannot answer PRAGMA foreign_keys at all, and that the
    # injection route accepts an orphan row. Enforcing FKs here would destroy the proof, not fix it.
    "packages/core/tests/test_sqlite_engine_factory_policy.py": (
        "#634 AC3 — deliberately exercises the BLIND engine; the file's cells prove blindness exists. "
        "Do not install enforcement here. Ruling: wave30-specs-20261017/wren-634-ruling-flash2-s134.md §4."
    ),
}


def _tracked_test_files() -> list[Path]:
    """Every tracked ``*.py`` under ``packages/*/tests`` — enumerated from git, never hand-listed."""
    out = subprocess.run(
        ["git", "ls-files", "--", "packages/*/tests/*.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / line for line in out.splitlines() if line]


def _strings_in(node: ast.AST) -> list[str]:
    """Every string literal reachable from a node, including f-string static chunks."""
    found: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.append(child.value)
    return found


def _is_sqlite_arg(node: ast.AST, local_sqlite_names: frozenset[str]) -> bool:
    return any("sqlite" in s.lower() for s in _strings_in(node)) or any(
        isinstance(x, ast.Name) and x.id in local_sqlite_names for x in ast.walk(node)
    )


def _engine_sites(tree: ast.Module) -> tuple[int, int]:
    """Return (sqlite engine sites, sites whose URL cannot be resolved statically).

    Unresolvable = the first argument is a bare Name that is neither a local sqlite assignment nor a
    literal containing "sqlite" — e.g. a URL supplied by a pytest fixture. Those are COUNTED and must
    be either exempt or in the baseline, so the scanner cannot be quietly defeated by moving the URL
    into a fixture.
    """
    local_sqlite: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any("sqlite" in s.lower() for s in _strings_in(n.value)):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    local_sqlite.add(t.id)

    sqlite_sites = 0
    unresolved_sites = 0
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if name != "create_engine" or not n.args:
            continue
        arg = n.args[0]
        if _is_sqlite_arg(arg, frozenset(local_sqlite)):
            sqlite_sites += 1
        elif isinstance(arg, ast.Name):
            unresolved_sites += 1
    return sqlite_sites, unresolved_sites


def _installs_enforcement(tree: ast.Module) -> bool:
    """True iff some call executes ``PRAGMA foreign_keys = ON``.

    Deliberately AST-only, and this is the second instrument lie the row tells: ``git grep -l
    'PRAGMA foreign_keys'`` matches COMMENTS and DOCSTRINGS. Measured at 492fe4e, grep says 15 files
    mention the pragma and only 14 execute it — and one of those 15 is a file whose only mention is
    prose saying it does NOT set it. A comment is not enforcement.
    """
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if name not in ("execute", "exec_driver_sql", "exec_driver_sql_async"):
            continue
        for s in _strings_in(n.args[0]) if n.args else []:
            compact = s.lower().replace(" ", "")
            if "foreign_keys=on" in compact:
                return True
    return False


def _scan() -> dict[str, tuple[int, int, bool]]:
    """path -> (sqlite sites, unresolved sites, installs enforcement)."""
    results: dict[str, tuple[int, int, bool]] = {}
    for path in _tracked_test_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        sqlite_sites, unresolved = _engine_sites(tree)
        if not sqlite_sites and not unresolved:
            continue
        results[str(path.relative_to(ROOT))] = (sqlite_sites, unresolved, _installs_enforcement(tree))
    return results


@pytest.fixture(scope="module")
def scan() -> dict[str, tuple[int, int, bool]]:
    return _scan()


def _blind_of(scan: dict) -> set[str]:
    return {p for p, (_s, _u, installs) in scan.items() if not installs and p not in EXEMPT}


# ---------------------------------------------------------------- the ratchet


def test_positive_control_the_scanner_sees_engine_builders(scan):
    """Prove the instrument can return hits before trusting any zero it returns.

    This is the fleet's own rule for a counting check: a count that came from a pattern matching
    nothing looks identical to a count that came from a tree with nothing in it.
    """
    assert scan, "the scanner found zero sqlite engine sites — the instrument is broken, not the tree"
    total = sum(s for s, _u, _i in scan.values())
    assert total > 50, f"only {total} engine sites found; the scan surface has shrunk unexpectedly"


def test_blind_set_matches_the_frozen_baseline_with_no_growth(scan):
    """AC4: a NEW blind sqlite engine-builder reddens the suite. No silent fourth row, no silent new file."""
    blind = _blind_of(scan)
    new = blind - set(BASELINE)
    assert not new, (
        f"new sqlite engine file(s) without PRAGMA foreign_keys=ON and without a declared exemption: "
        f"{sorted(new)}. Add the connect-listener (shape: test_secret_delete_fk.py) or, if blindness is "
        f"the subject of the file, add a reasoned entry to EXEMPT in this file. #634."
    )


def test_baseline_entries_are_all_still_blind_or_gone(scan):
    """The ratchet is two-sided: a listed file that STARTED enforcing must be removed from BASELINE.

    Without this half, a completed tranche would leave a stale name in the list and the next reader
    could not tell 'still owed' from 'already fixed' — the same adjectives-not-measurements failure the
    #603 ruling names.
    """
    blind = _blind_of(scan)
    stale = set(BASELINE) - blind
    assert not stale, (
        f"BASELINE lists file(s) that no longer count as blind: {sorted(stale)}. Either the tranche "
        f"landed (delete the row from BASELINE in the same changeset) or the scanner's view changed — "
        f"investigate before editing."
    )


def test_exempt_files_are_reasoned_and_real(scan):
    """An exemption must name a file that actually builds an engine, and carry a reason.

    The paired negative for the exemption list itself: a typo'd path would silently shrink the ratchet.
    """
    assert EXEMPT, "exemption table empty while the baseline is not — check this file is current"
    for path, reason in EXEMPT.items():
        assert reason.strip(), f"exemption for {path} carries no reason"
        assert "#634" in reason, f"exemption for {path} must cite the row it answers (#634)"
        assert Path(ROOT / path).exists(), f"exemption names a file that does not exist: {path}"
        assert path in scan, f"exemption names {path} but the scanner sees no engine site there"


def test_grep_is_wrong_in_both_directions_and_ast_is_the_authority(scan):
    """The measurement that justifies this file existing: the row's grep instrument is wrong TWICE over.

    UNDER-counts: ``create_engine(f"sqlite:///{db_path}")``, ``create_engine(url)`` and a call split
    across lines carry no quote right after the open paren, so the row's own pattern never sees them.
    Measured on this tree with this file set: grep names 23 engine-builder files, the AST scan names 80.

    OVER-counts: grep matches inside a STRING LITERAL, so a file that merely quotes the statement —
    including this guard's own parametrised source samples — reads to grep as an engine-builder that
    builds nothing. That half was found by this cell failing on its own file, which is the strongest
    possible demonstration that a grep interlock would have been wrong in both directions at once.

    The AST is the authority because it separates a call node from a string. The two claims below are
    therefore different: a grep hit with no AST call must be string-only (proven by re-parsing that
    file), and the AST must still see strictly more real engine-builders than grep does.
    """
    ast_files = set(scan)
    grep_out = subprocess.run(
        ["git", "grep", "-l", "-E", r"""create_engine\(\s*["']sqlite""", "--", "packages"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        # check=False on purpose: git grep exits 1 on zero matches, and a zero-match grep is exactly
        # the confident-nothing result this row was measured with. The assertions below judge the run.
        check=False,
    ).stdout
    grep_files = {line.split(":", 1)[-1] for line in grep_out.splitlines() if line}
    assert grep_files, "the grep control matched nothing at all — the control itself is broken"

    # 1. Every grep hit the AST does not count must carry NO create_engine call node. If one ever
    #    does, the scanner has a hole and the row's blind spot is back.
    for path in sorted(grep_files - ast_files):
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")) == "create_engine"
        ]
        assert not calls, f"grep found a real engine-builder the AST scan missed: {path}"

    # 2. The disagreement must be non-empty and in the direction that justifies the AST.
    assert grep_files - ast_files, (
        "grep and AST now agree exactly — either every f-string engine was fixed (re-grade this cell) "
        "or the scanner regressed into the blind spot this file exists to close"
    )
    assert len(ast_files) > len(grep_files), (
        f"AST sees {len(ast_files)} engine-builder files vs grep's {len(grep_files)}; the instrument "
        f"that produced #634's original face must not be reused"
    )


@pytest.mark.parametrize(
    "source,expect_blind",
    [
        # A plain literal engine with no listener: blind.
        ('engine = create_engine("sqlite://")\n', True),
        # The exact form the grep instrument cannot see: an f-string URL. Blind, and AST finds it.
        ('engine = create_engine(f"sqlite:///{p}")\n', True),
        # URL assembled into a variable first — also invisible to grep's quoted-adjacent pattern.
        ('url = f"sqlite:///{p}"\nengine = create_engine(url)\n', True),
        # Multi-line call.
        ('engine = create_engine(\n    "sqlite://",\n    echo=False,\n)\n', True),
        # Same engine WITH the listener: not blind.
        (
            (
                'engine = create_engine("sqlite://")\n'
                "@event.listens_for(engine, 'connect')\n"
                "def _fk(dbapi_conn, rec):\n"
                "    cur = dbapi_conn.cursor()\n"
                "    cur.execute('PRAGMA foreign_keys=ON')\n"
                "    cur.close()\n"
            ),
            False,
        ),
        # A COMMENT naming the pragma is not enforcement — the instrument-lie case, in miniature.
        (
            (
                'engine = create_engine("sqlite://")\n'
                "# this file's SQLite stack does not set PRAGMA foreign_keys=ON here\n"
            ),
            True,
        ),
        # A non-sqlite engine is out of scope entirely.
        ('engine = create_engine("postgresql+psycopg2://u@h/db")\n', None),
        # URL supplied by a fixture: unresolvable, therefore COUNTED (never silently skipped).
        ("engine = create_engine(sqlite_url)\n", True),
    ],
    ids=["literal", "fstring", "variable", "multiline", "with-listener", "comment-only", "postgres", "fixture-url"],
)
def test_scanner_classifies_each_engine_form(scan, source, expect_blind):
    """Per-form coverage of the scanner itself, on in-memory source only — no file is written.

    ``expect_blind=None`` means "must not be counted as an engine site at all".
    """
    tree = ast.parse(source)
    sqlite_sites, unresolved = _engine_sites(tree)
    installs = _installs_enforcement(tree)

    if expect_blind is None:
        assert sqlite_sites == 0 and unresolved == 0, "a postgres engine was counted as sqlite"
        return

    counted = sqlite_sites + unresolved > 0
    assert counted, "the scanner did not see this engine site at all"
    assert not installs or expect_blind is False, "an engine with a listener read as blind"
    assert (not installs) is expect_blind, f"expected blind={expect_blind}, scanner said blind={not installs}"


def test_the_scanner_never_rewrites_what_it_audits():
    """A guard that edits the tree it measures is not a guard.

    The first draft of this cell asserted ``git status --porcelain -- packages`` was empty. That was
    wrong on its face and it went red immediately: the worktree is legitimately dirty for every lane
    that is mid-run, and a repo-wide cleanliness assertion in a test suite is a trap for other seats,
    not a property of this one. What the cell can honestly claim is local and self-contained: running
    the scan leaves the bytes it read exactly as it found them.
    """
    targets = _tracked_test_files()[:40]
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in targets if p.exists()}
    _scan()  # the audited operation
    after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in targets if p.exists()}

    assert before == after, "the scan changed or touched a file it reads — an interlock must not mutate its own input"


def test_the_baseline_is_derived_not_remembered():
    """Every BASELINE entry is a real tracked file the scanner currently sees as blind.

    This is the half that keeps the frozen list honest as the tree moves: a hand-typed entry that is
    a wrong path, a file that already installs enforcement, or a deleted file reddens here instead of
    quietly narrowing the ratchet. (It earned its place: the first hand-typed version of BASELINE had
    three of those, and this guard's own sibling cell caught them.)
    """
    scan = _scan()
    for entry in sorted(BASELINE):
        path = ROOT / entry
        assert path.exists(), f"BASELINE names a file that does not exist: {entry}"
        assert entry in scan, f"BASELINE names {entry} but the scanner sees no sqlite engine there"
        assert not scan[entry][2], f"BASELINE names {entry} but that file DOES install enforcement"
    for entry in sorted(EXEMPT):
        assert (ROOT / entry).exists(), f"EXEMPT names a file that does not exist: {entry}"
