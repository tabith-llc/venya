# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed in that file, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral cells: #587 — stop-before-migrate, and a freshness proof that binds.

The owner ruled LAND on two halves (courier-52): "fix the ordering (stop before
migration) and make the freshness proof binding, before beta." These cells
exercise exactly that shipped text, and nothing else:

  Half 1 (1A) `install-venya-core.sh` stops a LIVE venya-core before it runs
      migrations, so the schema never moves under a process still holding the
      previous build's imports. With no unit (first install) the guard is false
      and the stop must neither fire nor abort.
  Half 3 (3a/3b) `venya_service_freshness` returns THREE outcomes — 0 FRESH,
      1 STALE, 2 UNDECIDABLE — and `venya_verify_install` consumes them: FRESH
      claims success, STALE refuses the claim and exits non-zero, UNDECIDABLE
      withholds the claim and still exits 0. 1 and 2 never collapse together.

House pattern (`test_installer_nginx_start_proof_454`, `_mode_preservation_381`):
run the REAL text lifted out of the git-tracked scripts, or the REAL library
functions sourced from it, against shell-function stubs for `systemctl`/`stat`,
under the same `set -euo pipefail` the installers run with. No VMs, no services,
no installs — nothing here touches a real unit or a real database.

Truth table (every check has its rejection half):
  T1   bash -n on all three touched scripts (repo rule; pre-commit may not cover .sh).
  T2   positive  live unit -> stop announced AND issued, migrations still reached.
  T3   negative  no unit -> stop never attempted, install continues (AC-2).
  T4   negative  stop fails -> run aborts, migrations never run.
  T5   ordering  backup < stop < _run_migrations < sync, guard before all of it.
  T6   proof    FRESH -> rc 0 (strictly-after and equal-boundary both fresh).
  T7   proof    STALE -> rc 1, names both timestamps, never says UNDECIDABLE.
  T8   proof    unreadable start / unreadable stamp -> rc 2, never says FAILED.
  T9   claim    rc 0 -> "Installation verified successfully" prints (AC-4).
  T10  claim    rc 1 -> no claim, non-zero exit, flow stops, service named.
  T11  claim    rc 2 -> no claim, ZERO exit, own wording, no staleness accusation.
  T12  negative proof never ran -> claim behaves exactly as before the change.
  T13  wiring   BOTH installers capture the rc and name their own unit (AC-6).
  T14  scope    Half 2 was NOT ruled: no state-report function, no new trap.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "install-venya-core.sh"
EXEC = REPO_ROOT / "install-venya-executor.sh"
COMMON = REPO_ROOT / "venya-common.sh"

# Symbols are read from the shipped library so a rename in the source fails the
# cell loudly rather than testing a name that no longer exists.
_COMMON_SRC = COMMON.read_text(encoding="utf-8")


def _func_name(src: str, suffix: str) -> str:
    """Return the shipped function name ending in `suffix`, or fail the module."""
    for line in src.splitlines():
        if line.startswith("ven") and line.rstrip().endswith(f"{suffix}() {{"):
            return line.split("(")[0]
    raise AssertionError(f"no function matching {suffix!r} found in venya-common.sh — the cell names are stale")


FN_PROOF = _func_name(_COMMON_SRC, "_service_freshness")
FN_CLAIM = _func_name(_COMMON_SRC, "_verify_install")


def _freshness_rc_var(src: str) -> str:
    """The environment variable the claim reads, taken from the shipped text."""
    import re

    m = re.search(r"\$\{([A-Z_]*FRESHNESS_RC)(:-0)?\}", src)
    assert m, "the success claim does not read a freshness rc variable — Half 3 is not wired"
    return m.group(1)


def _service_name_var(src: str) -> str:
    import re

    m = re.search(r"\$\{([A-Z_]*FRESHNESS_SERVICE)", src)
    assert m, "the refusal text does not name the service — the claim cannot say what is stale"
    return m.group(1)


RC_ENV = _freshness_rc_var(_COMMON_SRC)
SVC_ENV = _service_name_var(_COMMON_SRC)

# The installers' own capture clause, derived from the shipped call site.
_CORE_SRC_AT_START = CORE.read_text(encoding="utf-8")
CAPTURE_CLAUSE = "|| " + RC_ENV + "=$?"

# --- lift markers for the Half-1 block -----------------------------------------------
STOP_BEGIN = "# --- Run database migrations (core-specific) ---"
STOP_END = 'info "Running database migrations..."'

PRELUDE = (
    "set -euo pipefail\n"
    'info()  { echo "[INFO]  $*"; }\n'
    'warn()  { echo "[WARN]  $*"; }\n'
    'error() { echo "[ERROR] $*"; }\n'
    # `return`, never `exit`: these are shell FUNCTIONS and an `exit` inside one
    # would end the whole cell script at the first stubbed call.
    "systemctl() {\n"
    '    echo "systemctl $*"\n'
    '    case "$1" in\n'
    '        is-active) [ "${UNIT_ACTIVE:-yes}" = yes ] && return 0; return 3 ;;\n'
    '        stop)      return "${RC_STOP:-0}" ;;\n'
    "    esac\n"
    "    return 0\n"
    "}\n"
)


def _clean_env(extra: dict | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIT_", "RC_", "STAMP_EPOCH", RC_ENV, SVC_ENV))}
    if extra:
        env.update(extra)
    return env


def _run(text: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "cell.sh"
        script.write_text(PRELUDE + text + 'echo "CELL-REACHED-AFTER\n"', encoding="utf-8")
        return subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=_clean_env(env_extra),
            check=False,
        )


def _stop_block() -> str:
    src = CORE.read_text(encoding="utf-8")
    return src[src.index(STOP_BEGIN) : src.index(STOP_END, src.index(STOP_BEGIN))]


# --- a fake install tree so the claim function can be run for real -------------------


def _fake_install(tmp: Path) -> Path:
    root = tmp / "install"
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / ".venv" / "bin" / "venya").write_text("", encoding="utf-8")
    (root / "present-file").write_text("", encoding="utf-8")
    return root


def _claim_script(root: Path, trailing: str) -> str:
    """Source the REAL library, define the colour helpers the claim uses, then call it."""
    return (
        "set -euo pipefail\n"
        f'INSTALL_DIR="{root}"\n'
        f'source "{COMMON}"\n'
        "venya_print_colors\n"
        f'{FN_CLAIM} "{root}/present-file"\n' + trailing
    )


def _run_claim(freshness_rc: str | None, trailing: str = 'echo "CLAIM_REACHED_AFTER"\n') -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = _fake_install(Path(tmp))
        script = Path(tmp) / "claim.sh"
        script.write_text(_claim_script(root, trailing), encoding="utf-8")
        env = _clean_env({SVC_ENV: "venya-core"})
        if freshness_rc is not None:
            env[RC_ENV] = freshness_rc
        proc = subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            check=False,
        )
        return proc.returncode, proc.stdout.decode(errors="replace")


STAMP_EPOCH = "1791972000"  # a fixed deploy-stamp instant: 2026-10-14 10:00:00Z


def _run_proof(start_raw: str, *, stamp_readable: bool = True, show_ok: bool = True) -> tuple[int, str]:
    """Drive the REAL proof function with `systemctl show` and `stat` stubbed."""
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "proof.sh"
        script.write_text(
            "set -euo pipefail\n"
            f'STAMP_EPOCH="{STAMP_EPOCH}"\n'
            "systemctl() {\n"
            '    if [ "$1" = show ]; then\n'
            f'        [ "{show_ok}" = True ] && echo "{start_raw}" && return 0\n'
            "        return 1\n"
            "    fi\n"
            "    return 0\n"
            "}\n"
            "stat() {\n"
            '    if [ "$1" = -c ]; then\n'
            f'        [ "{stamp_readable}" = True ] && echo "$STAMP_EPOCH" && return 0\n'
            "        return 1\n"
            "    fi\n"
            '    /usr/bin/stat "$@"\n'
            "}\n"
            f'source "{COMMON}"\n'
            "venya_print_colors\n"
            f'{FN_PROOF} venya-core /tmp/587-stamp-that-need-not-exist && echo "PROOF_RC=0" '
            '|| echo "PROOF_RC=$?"\n',
            encoding="utf-8",
        )
        proc = subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_clean_env(),
            check=False,
        )
        return proc.returncode, proc.stdout.decode(errors="replace")


# --------------------------------------------------------------------------------------
# T1 — every touched script parses (repo rule).
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("script", [CORE, EXEC, COMMON], ids=["core", "executor", "common"])
def test_t1_bash_n_clean(script: Path):
    proc = subprocess.run(["bash", "-n", str(script)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    assert proc.returncode == 0, proc.stdout.decode(errors="replace")


# --------------------------------------------------------------------------------------
# Half 1 — stop before migrate.
# --------------------------------------------------------------------------------------


def test_t2_positive_live_unit_is_stopped_before_migrations():
    """A re-run over a live core: the stop is announced, issued, and the install
    still reaches its migrations. The outage is deliberate and SAID — #587's
    accepted cost, and the owner's ruling is that it happens out loud."""
    proc = _run(_stop_block())
    out = proc.stdout.decode(errors="replace")
    assert proc.returncode == 0, out
    assert "CELL-REACHED-AFTER" in out, "the stop must not end the install"
    assert "stopping venya-core.service BEFORE database migrations" in out, out
    assert "will not answer requests" in out, "the outage must be named, not silent"
    assert "systemctl stop venya-core.service" in out
    assert out.index("NOTICE: stopping") < out.index("systemctl stop venya-core.service")


def test_t3_paired_negative_first_install_never_stops_and_never_aborts():
    """AC-2: no running unit (a day-one install, or a core already down) must
    neither attempt the stop — `stop` on an unloaded unit is a non-zero command
    under set -e — nor lose its migrations."""
    proc = _run(_stop_block(), {"UNIT_ACTIVE": "no"})
    out = proc.stdout.decode(errors="replace")
    assert proc.returncode == 0, out
    assert "systemctl stop" not in out, "no stop may be attempted when nothing is running"
    assert "NOTICE: stopping venya-core.service" not in out
    assert "CELL-REACHED-AFTER" in out, "a fresh install must still reach its migrations"


def test_t4_paired_negative_a_failing_stop_is_not_swallowed():
    """If the stop itself fails the run must NOT proceed into the migrations
    believing the process is down. Half 2 (naming the leftover state) is out of
    this ruling, so the honest shipped behaviour is a bare non-zero abort."""
    proc = _run(_stop_block(), {"UNIT_ACTIVE": "yes", "RC_STOP": "1"})
    out = proc.stdout.decode(errors="replace")
    assert proc.returncode != 0, out
    assert "CELL-REACHED-AFTER" not in out, "a half-stopped core must not be migrated"


def test_t5_ordering_backup_then_stop_then_migrations_then_sync():
    """Sequence pin on the real file: the pre-upgrade backup stays strictly first
    (AC-7 — no shape may migrate without it), the stop lands between the backup
    and `_run_migrations`, and the restart remains the last act. Guards against a
    later hunk sliding the stop below the migration call, which would restore the
    window silently while every marker above still matched."""
    src = CORE.read_text(encoding="utf-8")
    backup = src.index("sudo -u postgres pg_dump")
    stop = src.index("systemctl stop venya-core.service")
    migrations = src.index("_run_migrations")
    sync = src.index("venya_service_sync venya-core")
    assert backup < stop < migrations < sync, (backup, stop, migrations, sync)
    assert src.index("Refusing to downgrade") < backup, "the version guard still precedes all mutation"


# --------------------------------------------------------------------------------------
# Half 3a — the proof returns three distinct outcomes.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start_raw", "stamp_readable", "show_ok", "expect_rc", "expect_line", "forbid"),
    [
        # T6 FRESH: strictly after the stamp, and equal to it (the shipped test is >=).
        ("Thu Oct 15 2026 10:00:00", True, True, 0, "PROOF-OF-FRESH-BYTES:", ("FAILED", "UNDECIDABLE")),
        ("Wed Oct 14 2026 10:00:00", True, True, 0, "PROOF-OF-FRESH-BYTES:", ("FAILED", "UNDECIDABLE")),
        # T7 STALE: provably predates the deployed bytes.
        ("Tue Oct 13 2026 09:00:00", True, True, 1, "PROOF-OF-FRESH-BYTES FAILED", ("UNDECIDABLE",)),
        # T8 UNDECIDABLE: systemd unreadable, or the stamp unreadable. Never STALE.
        ("n/a", True, True, 2, "PROOF-OF-FRESH-BYTES UNDECIDABLE", ("FAILED",)),
        ("Thu Oct 15 2026 10:00:00", False, True, 2, "PROOF-OF-FRESH-BYTES UNDECIDABLE", ("FAILED",)),
    ],
    ids=["t6_fresh_after", "t6b_fresh_equal", "t7_stale", "t8a_undecidable_start", "t8b_undecidable_stamp"],
)
def test_t6_to_t8_proof_three_outcomes(start_raw, stamp_readable, show_ok, expect_rc, expect_line, forbid):
    _, out = _run_proof(start_raw, stamp_readable=stamp_readable, show_ok=show_ok)
    assert expect_line in out, out
    assert f"PROOF_RC={expect_rc}" in out, out
    for word in forbid:
        assert word not in out, f"outcomes must never alias; {word!r} appeared in an rc={expect_rc} run:\n{out}"


# --------------------------------------------------------------------------------------
# Half 3b — the success claim consumes the outcome.
# --------------------------------------------------------------------------------------


def test_t9_positive_fresh_proof_still_claims_success():
    """AC-4: binding the proof must not become a blanket failure — a proven-fresh
    run claims success exactly as before."""
    rc, out = _run_claim("0")
    assert rc == 0, out
    assert "Installation verified successfully" in out, out
    assert "VERIFICATION NOT CLAIMED" not in out
    assert "CLAIM_REACHED_AFTER" in out


def test_t10_stale_refuses_the_claim_and_ends_the_run():
    """The whole point of binding: a provably stale process may NOT be followed by
    a success claim, and the run does not sail past the refusal."""
    rc, out = _run_claim("1")
    assert rc != 0, out
    assert "Installation verified successfully" not in out, out
    assert "CLAIM_REACHED_AFTER" not in out, "the refusal must end the run, not warn past it"
    assert "VERIFICATION NOT CLAIMED" in out
    assert "venya-core" in out, "the refusal names which service was not proven"
    assert "predates" in out, "and says why"


def test_t11_undecidable_withholds_the_claim_without_failing_the_install():
    """The hazard carried out of the proposal, kept as its own outcome: a host
    whose timestamps we cannot read must not be reported as PROVEN (rc 0 claim)
    and must not be reported as BROKEN (rc 1 refusal). Collapsing 2 into 1 would
    fail a good install; collapsing it into 0 would claim a proof never made."""
    rc, out = _run_claim("2")
    assert rc == 0, out
    assert "CLAIM_REACHED_AFTER" in out, "undecidable must not end the install"
    assert "Installation verified successfully" not in out, out
    assert "VERIFICATION NOT CLAIMED" in out
    assert "UNDECIDABLE" in out, "it carries its own wording"
    assert "predates" not in out, "and never accuses the process of being stale"


def test_t12_paired_negative_an_unwired_caller_behaves_as_before():
    """A caller that never ran the proof leaves the variable unset. Under the
    installers' own `set -u` that must neither crash nor fail: the gate binds only
    where it is wired, so this is not an ambient behaviour change."""
    rc, out = _run_claim(None)
    assert rc == 0, out
    assert "Installation verified successfully" in out, out
    assert "unbound variable" not in out, out


# --------------------------------------------------------------------------------------
# T13 — wiring exists in BOTH installers (AC-6: no core-only fix).
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "unit"),
    [(CORE, "venya-core"), (EXEC, "venya-executor")],
    ids=["core", "executor"],
)
def test_t13_both_installers_capture_the_proof_rc(script: Path, unit: str):
    src = script.read_text(encoding="utf-8")
    calls = [ln for ln in src.splitlines() if ln.strip().startswith(f"{FN_PROOF} {unit} ")]
    assert len(calls) == 1, calls
    assert CAPTURE_CLAUSE in calls[0], calls[0]
    svc_line = f"{SVC_ENV}={unit}"
    assert svc_line in src, "the refusal cannot name the service"
    assert src.index(svc_line) < src.index(calls[0].strip()), "the identity is set before the proof runs"


# --------------------------------------------------------------------------------------
# T14 — scope guard for the lead's ruling: Half 2 was NOT ruled out into code.
# --------------------------------------------------------------------------------------


def test_t14_ruled_scope_only_half2_and_the_dead_shapes_are_absent():
    """Half 2 (an abort naming the state it left) is explicitly OUT of this
    ruling, 2A (ERR trap) measured blind to the 15 explicit exits and rejects
    itself, and 1B (migrations-after-sync) was ranked last and left unapplied.
    This cell fails if any of them is smuggled in later — a paired negative on
    the SCOPE, not just the code."""
    for script in (CORE, EXEC, COMMON):
        src = script.read_text(encoding="utf-8")
        assert "venya_report_abort_state" not in src, f"{script.name}: Half 2 crept in"
        assert "venya_install_state_on_exit" not in src, f"{script.name}: Half 2 crept in"
        assert "VENYA_BYTES_SWAPPED" not in src, f"{script.name}: Half 2 state flags crept in"
        assert "optional_no_ca" not in src, f"{script.name}: the #588 option B shape does not belong here"
    # the two shipped traps survive and NOTHING new was added
    core_src = CORE.read_text(encoding="utf-8")
    assert "trap 'cleanup_install_temps' EXIT" in core_src
    assert "trap 'rm -rf \"$FETCH_DIR\"' EXIT" in core_src
    assert core_src.count("trap '") == 2, core_src.count("trap'")
    # 1B not applied: the migration call is still ABOVE the service sync (T5 pins it)
    assert CORE.read_text().index("_run_migrations") < CORE.read_text().index("venya_service_sync venya-core")
    # 1C moot: no name-the-window NOTICE at the extract point (the ruling was LAND)
    core = CORE.read_text(encoding="utf-8")
    assert "STALE_WINDOW_START_EPOCH" not in core
