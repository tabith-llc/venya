# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#496 pg-cluster-head-selects-inactive — active-cluster resolution cells.

``install-venya-core.sh`` used to pick the PostgreSQL config dir with
``ls -d /etc/postgresql/*/main | head -n1``. Sort order means the LOWEST
installed major wins, so on a multi-version host the ``venya_map`` peer map
was written into a cluster the server does not run: ``venya-core`` died at
startup on peer authentication while the installer reported the step done.

Ruled shape (s77-ruling-496-recon R1-R4): resolve the ONLINE cluster from
``pg_lsclusters --no-header`` (primary), fall back to the running server's own
``SHOW config_file`` when that tool is absent (non-Debian packaging), ABORT
with the candidate list when resolution is not exactly one cluster, then strip
stray markers from the NON-active clusters (best-effort, warn-only).

Cells run the REAL extracted code: the two helpers and the caller block are
lifted verbatim out of ``install-venya-core.sh``, the ``/etc/postgresql``
literal is rewritten to a fixture tree, and the resolution tools are PATH
stubs (the #491/#505/#396 precedent — exercise real script logic, never a
re-implementation). No VMs, no sudo, nothing outside the tmpdir.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "install-venya-core.sh"

_PG_ROOT_LITERAL = "/etc/postgresql"
_RESOLVE_ANCHOR = "venya_resolve_pg_cluster() {"
_STRIP_ANCHOR = "venya_strip_inactive_pg_markers() {"
_BLOCK_START = 'PG_MAIN_DIR=$(venya_resolve_pg_cluster) || PG_MAIN_DIR=""'
_BLOCK_END = 'venya_strip_inactive_pg_markers "$PG_MAIN_DIR"'
_OLD_SELECTION = "PG_MAIN_DIR=$(ls -d /etc/postgresql/*/main 2>/dev/null | head -n1)"

OFFLINE_VER = "14"  # lowest sort order: what head -n1 used to pick
ONLINE_VER = "16"  # the cluster the server actually runs

EXISTING_ABORT = "PostgreSQL main config dir not found — cannot install the venya_audit peer map."

_STUB_PG_LSC = """#!/bin/bash
cat "$PG_LSC_FILE"
"""

_STUB_SUDO = """#!/bin/bash
if [ "$1" = "-u" ]; then shift 2; fi
exec "$@"
"""

_STUB_PSQL = """#!/bin/bash
sql="${@: -1}"
case "$sql" in
    *"SHOW config_file"*) cat "$PG_CFG_FILE"; exit 0 ;;
esac
exit 1
"""

# Presence of pg_lsclusters is emulated both ways: the fleet's core VMs really
# do carry it in /usr/bin, so a cell that needs it ABSENT must not depend on
# the ambient PATH. The shadow only intercepts the one probe the helper makes.
_COMMAND_SHADOW_ABSENT = """command() {
    if [ "${1:-}" = "-v" ] && [ "${2:-}" = "pg_lsclusters" ]; then return 1; fi
    builtin command "$@"
}
"""

_STUBS = (("pg_lsclusters", _STUB_PG_LSC), ("sudo", _STUB_SUDO), ("psql", _STUB_PSQL))


def _core() -> str:
    return CORE.read_text(encoding="utf-8")


def _region(text: str, start: str, end_marker: str) -> str:
    """Lift a real region out of the installer between two anchors."""
    assert start in text, f"anchor missing from install-venya-core.sh: {start!r}"
    i = text.index(start)
    j = text.index(end_marker, i) + len(end_marker)
    return text[i:j]


def _resolve_func() -> str:
    src = _core()
    assert src.count(_RESOLVE_ANCHOR) == 1, "resolver anchor no longer unique — re-anchor"
    return _region(src, _RESOLVE_ANCHOR, "\n}\n")


def _strip_func() -> str:
    src = _core()
    assert src.count(_STRIP_ANCHOR) == 1, "hygiene anchor no longer unique — re-anchor"
    return _region(src, _STRIP_ANCHOR, "\n}\n")


def _caller_block() -> str:
    src = _core()
    assert src.count(_BLOCK_START) == 1, "caller-block anchor no longer unique — re-anchor"
    return _region(src, _BLOCK_START, _BLOCK_END)


class _Harness:
    """Fixture tree + PATH stubs around the real extracted installer code."""

    def __init__(self, tmp_path: Path, root_name: str = "pgetc") -> None:
        self.tmp = tmp_path
        self.etc = tmp_path / root_name
        self.stub = tmp_path / "bin"
        self.stub.mkdir(parents=True, exist_ok=True)
        for name, body in _STUBS:
            p = self.stub / name
            p.write_text(body, encoding="utf-8")
            p.chmod(0o755)
        self.lsc_file = tmp_path / "lsc.txt"
        self.lsc_file.write_text("", encoding="utf-8")
        self.cfg_file = tmp_path / "cfg.txt"
        self.cfg_file.write_text("", encoding="utf-8")
        self.make_root()

    def make_root(self) -> None:
        try:
            self.etc.mkdir(parents=True, exist_ok=True)
        except FileExistsError:  # pragma: no cover - path already exists
            pass

    def cluster(self, ver: str, *, marker: bool = False) -> Path:
        """A fake /etc/postgresql/<ver>/main carrying the two marker files."""
        d = self.etc / ver / "main"
        d.mkdir(parents=True, exist_ok=True)
        ident = "venya_map venya venya_audit\n" if marker else "# pg_ident placeholders\n"
        hba = (
            "local   venya           venya_audit                         peer map=venya_map\n"
            "local   all             all                                     peer\n"
            if marker
            else "local   all             all                                     peer\n"
        )
        (d / "pg_ident.conf").write_text(ident, encoding="utf-8")
        (d / "pg_hba.conf").write_text(hba, encoding="utf-8")
        return d

    def rows(self, *specs: tuple[str, str]) -> None:
        """Write pg_lsclusters --no-header rows: (ver, status) pairs."""
        lines = [
            f"{ver}  main  5432  {status}  postgres  /var/lib/postgresql/{ver}/main  /var/log/x"
            for ver, status in specs
        ]
        self.lsc_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def probe_answer(self, path: str) -> None:
        """What `sudo -u postgres psql -tAc 'SHOW config_file'` prints."""
        self.cfg_file.write_text(path + "\n" if path else "", encoding="utf-8")

    def _script(self, body: str, lsc_present: bool) -> Path:
        shadow = "" if lsc_present else _COMMAND_SHADOW_ABSENT
        script = (
            "set -euo pipefail\n"
            # error()/warn() mirror venya-common.sh: they print on STDOUT, the
            # same stream a command substitution captures. The helpers under
            # test must therefore keep diagnostics off it.
            'error() { echo "[ERROR] $*"; }\n'
            'warn()  { echo "[WARN] $*"; }\n'
            'info()  { echo "[INFO] $*"; }\n'
            f"{shadow}"
            f"{body}\n"
            'echo "RESULT=[$PG_MAIN_DIR]"\n'
        )
        p = self.tmp / "run.sh"
        p.write_text(script, encoding="utf-8")
        return p

    def _env(self) -> dict[str, str]:
        return {
            "PATH": f"{self.stub}:/usr/bin:/bin",
            "PG_LSC_FILE": str(self.lsc_file),
            "PG_CFG_FILE": str(self.cfg_file),
            "HOME": str(self.tmp),
        }

    def run(self, *, lsc_present: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess:
        """Run resolver + hygiene + the real caller block (rebased)."""
        body = (_resolve_func() + _strip_func() + _caller_block()).replace(_PG_ROOT_LITERAL, str(self.etc))
        return subprocess.run(
            ["/bin/bash", str(self._script(body, lsc_present))],
            cwd=str(cwd) if cwd else str(self.tmp),
            env=self._env(),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def run_resolve_only(self, *, lsc_present: bool = True) -> subprocess.CompletedProcess:
        """The resolver alone, streams kept apart: proves stdout is one field."""
        body = _resolve_func().replace(_PG_ROOT_LITERAL, str(self.etc))
        shadow = "" if lsc_present else _COMMAND_SHADOW_ABSENT
        script = (
            "set -euo pipefail\n"
            'error() { echo "[ERROR] $*"; }\n'
            'warn()  { echo "[WARN] $*"; }\n'
            f"{shadow}"
            f"{body}\n"
            'PG_MAIN_DIR=$(venya_resolve_pg_cluster) || PG_MAIN_DIR=""\n'
            'printf "CAPTURED=[%s]\\n" "$PG_MAIN_DIR"\n'
            '[ -n "$PG_MAIN_DIR" ] || exit 1\n'
        )
        p = self.tmp / "resolve_only.sh"
        p.write_text(script, encoding="utf-8")
        return subprocess.run(
            ["/bin/bash", str(p)],
            cwd=str(self.tmp),
            env=self._env(),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def out(self, proc: subprocess.CompletedProcess) -> str:
        return proc.stdout + proc.stderr

    def chosen(self, proc: subprocess.CompletedProcess) -> str:
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT="):
                return line[len("RESULT=") :].strip("[]")
        return ""

    def markers(self, d: Path) -> str:
        return (d / "pg_ident.conf").read_text(encoding="utf-8") + (d / "pg_hba.conf").read_text(encoding="utf-8")


# --- source pins: the tripwire pair (behaviour cells below are the proof) ---


def _code_lines(src: str) -> str:
    """The script with comment lines dropped — a pin must not be satisfiable
    by prose (the explanatory comment quotes the old form on purpose)."""
    return "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))


def test_head_selects_inactive_form_is_gone() -> None:
    """AC2: no `ls` parsing survives in the cluster-selection path."""
    code = _code_lines(_core())
    assert _OLD_SELECTION not in code, "the head -n1 selection form is back"
    assert "ls -d /etc/postgresql" not in code
    assert "head -n1" not in _resolve_func(), "head -n1 crept back into the resolver"
    assert "ls -d" not in _resolve_func(), "ls parsing crept back into the resolver"


def test_ruled_helper_shapes_present() -> None:
    """R1/R4: the ruled names exist once and carry both mechanisms."""
    src = _core()
    assert src.count(_RESOLVE_ANCHOR) == 1
    assert src.count(_STRIP_ANCHOR) == 1
    resolver = _resolve_func()
    assert "pg_lsclusters --no-header" in resolver
    assert "psql -tAc 'SHOW config_file'" in resolver
    # R5: a swallowed resolution error is the defect class this ticket kills.
    assert "2>/dev/null" not in resolver


# --- the defect, quoted (RED against the OLD form, run as a fixture) ---


def test_old_head_form_selected_the_inactive_cluster(tmp_path: Path) -> None:
    """Documents WHY the fix matters, and pins the paired rejection: the old
    command, run against the same two-cluster fixture, names the OFFLINE
    cluster. The new resolver must name the ONLINE one instead."""
    h = _Harness(tmp_path)
    offline = h.cluster(OFFLINE_VER)
    online = h.cluster(ONLINE_VER)
    old = subprocess.run(
        ["/bin/bash", "-c", f'echo "$(/bin/ls -d {tmp_path}/pgetc/*/main 2>/dev/null | head -n1)"'],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert old.stdout.strip() == str(offline), f"fixture lost its ordering: {old.stdout!r}"
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    proc = h.run()
    assert h.chosen(proc) != str(offline), "the resolver picked the inactive cluster"
    assert h.chosen(proc) == str(online)


# --- positive: the ONLINE cluster wins ---


def test_online_cluster_wins_over_lower_version(tmp_path: Path) -> None:
    """14 offline + 16 online → 16/main is the write target. RED at the parent
    commit, where head -n1 answered 14/main."""
    h = _Harness(tmp_path)
    offline = h.cluster(OFFLINE_VER)
    online = h.cluster(ONLINE_VER)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    proc = h.run()
    assert proc.returncode == 0, h.out(proc)
    assert h.chosen(proc) == str(online), h.out(proc)
    assert str(offline) not in h.chosen(proc)


def test_probe_fallback_resolves_the_same_dir(tmp_path: Path) -> None:
    """R1 fallback: with pg_lsclusters absent the answer comes from the
    running server's own `SHOW config_file`, main dir = that file's dir."""
    h = _Harness(tmp_path)
    online = h.cluster(ONLINE_VER)
    h.cluster(OFFLINE_VER)
    h.probe_answer(f"{online}/postgresql.conf")
    proc = h.run(lsc_present=False)
    assert proc.returncode == 0, h.out(proc)
    assert h.chosen(proc) == str(online), h.out(proc)


def test_path_with_whitespace_survives_assignment(tmp_path: Path) -> None:
    """AC3's other half: a config root containing a space must not break the
    assignment (the old form word-split `ls` output)."""
    h = _Harness(tmp_path, root_name="pg etc")
    online = h.cluster(ONLINE_VER)
    h.cluster(OFFLINE_VER)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    proc = h.run()
    assert proc.returncode == 0, h.out(proc)
    assert h.chosen(proc) == str(online), h.out(proc)


# --- negative halves (truth-table law: what must be REJECTED) ---


def test_two_online_clusters_abort_naming_both_writing_nothing(tmp_path: Path) -> None:
    """AC1 / R2: more than one online cluster is fatal, never guessed. Both
    candidates are named and NEITHER cluster's marker files are touched."""
    h = _Harness(tmp_path)
    a = h.cluster("15")
    b = h.cluster("16")
    h.rows(("15", "online"), ("16", "online"))
    proc = h.run()
    out = h.out(proc)
    assert proc.returncode != 0, "an ambiguous cluster state was accepted"
    assert "RESULT=" not in proc.stdout, f"the installer continued past ambiguity: {out}"
    assert "[ERROR]" in out
    assert str(a) in out and str(b) in out, f"both candidates must be listed: {out}"
    assert "venya_map" not in h.markers(a) + h.markers(b)


def test_no_cluster_at_all_keeps_the_existing_abort_text(tmp_path: Path) -> None:
    """The existing loud abort still fires: nothing online, nothing probed,
    non-zero exit, the peer-map error quoted verbatim."""
    h = _Harness(tmp_path)
    h.rows()
    h.probe_answer("")
    proc = h.run(lsc_present=False)
    out = h.out(proc)
    assert proc.returncode != 0, "an unresolvable cluster state exited 0"
    assert EXISTING_ABORT in out
    assert "RESULT=" not in proc.stdout


def test_offline_only_state_is_rejected(tmp_path: Path) -> None:
    """Paired negative for the primary mechanism: every cluster offline is NOT
    a success — the resolver answers nothing and the caller aborts."""
    h = _Harness(tmp_path)
    h.cluster(OFFLINE_VER)
    h.cluster(ONLINE_VER)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "down"))
    proc = h.run()
    assert proc.returncode != 0, h.out(proc)
    assert h.chosen(proc) == "", h.out(proc)
    assert EXISTING_ABORT in h.out(proc)


def test_probe_failure_is_visible_not_swallowed(tmp_path: Path) -> None:
    """The defect class this ticket exists to kill: when the probe cannot
    answer, the run says so loudly instead of quietly picking a directory."""
    h = _Harness(tmp_path)
    h.cluster(ONLINE_VER)
    h.probe_answer("")
    proc = h.run_resolve_only(lsc_present=False)
    assert proc.returncode != 0
    assert "CAPTURED=[]" in proc.stdout, proc.stdout


# --- hygiene (R3) ---


def test_stray_marker_stripped_from_inactive_cluster(tmp_path: Path) -> None:
    """R3: after selecting, a leftover marker in the NON-active cluster goes
    and the ACTIVE cluster's marker survives untouched."""
    h = _Harness(tmp_path)
    inactive = h.cluster(OFFLINE_VER, marker=True)
    active = h.cluster(ONLINE_VER, marker=True)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    proc = h.run()
    assert proc.returncode == 0, h.out(proc)
    assert h.chosen(proc) == str(active)
    assert "venya_map" not in h.markers(inactive), h.markers(inactive)
    assert "venya_map venya venya_audit" in (active / "pg_ident.conf").read_text(encoding="utf-8")
    assert "peer map=venya_map" in (active / "pg_hba.conf").read_text(encoding="utf-8")


def test_hygiene_is_warn_only_when_cleanup_fails(tmp_path: Path) -> None:
    """R3 best-effort: a cleanup failure warns and the install still proceeds
    with the right target — hygiene never aborts a run."""
    h = _Harness(tmp_path)
    inactive = h.cluster(OFFLINE_VER, marker=True)
    active = h.cluster(ONLINE_VER, marker=True)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    inactive_dir = inactive  # the dir itself becomes unwritable
    inactive_dir.chmod(0o555)
    try:
        proc = h.run()
    finally:
        inactive_dir.chmod(0o755)
    assert proc.returncode == 0, h.out(proc)
    assert h.chosen(proc) == str(active)
    assert "[WARN]" in h.out(proc), f"cleanup failure was silent: {h.out(proc)}"


# --- CWD independence + single-field stdout (#491 lesson) ---


def test_resolution_is_cwd_independent(tmp_path: Path) -> None:
    """Run the caller from a directory holding a file named `main`: the chosen
    cluster must not depend on the working directory (#491's glob class)."""
    hostile = tmp_path / "hostile-cwd"
    hostile.mkdir()
    (hostile / "main").write_text("", encoding="utf-8")
    (hostile / "16").write_text("", encoding="utf-8")
    h = _Harness(tmp_path)
    h.cluster(OFFLINE_VER)
    online = h.cluster(ONLINE_VER)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    plain = h.run()
    from_hostile = h.run(cwd=hostile)
    assert plain.returncode == 0, h.out(plain)
    assert from_hostile.returncode == 0, h.out(from_hostile)
    assert h.chosen(plain) == h.chosen(from_hostile) == str(online)


def test_helper_stdout_carries_only_the_chosen_dir(tmp_path: Path) -> None:
    """Captured through a command substitution, the resolver's stdout is
    exactly one field — the chosen path; its diagnostics stay on stderr.
    `[ERROR]` lines reaching stdout would land inside PG_MAIN_DIR."""
    h = _Harness(tmp_path)
    online = h.cluster(ONLINE_VER)
    h.cluster(OFFLINE_VER)
    h.rows((OFFLINE_VER, "offline"), (ONLINE_VER, "online"))
    proc = h.run_resolve_only()
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [f"CAPTURED=[{online}]"], proc.stdout

    h2 = _Harness(tmp_path / "none")
    h2.rows()
    proc2 = h2.run_resolve_only()
    assert proc2.returncode != 0
    assert "CAPTURED=[]" in proc2.stdout, proc2.stdout
    assert "[ERROR]" not in proc2.stdout, f"diagnostics leaked into PG_MAIN_DIR: {proc2.stdout!r}"


def test_bash_n_clean() -> None:
    """Commit-policy hard rule: the installer parses."""
    proc = subprocess.run(["bash", "-n", str(CORE)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("name", ["resolve", "strip"])
def test_extracted_regions_are_complete_definitions(tmp_path: Path, name: str) -> None:
    """Guard on the extraction anchors: what the cells lift out must be a
    brace-balanced, self-contained function definition — otherwise every
    behavioural cell above would be testing a truncated body."""
    func = _resolve_func() if name == "resolve" else _strip_func()
    anchor = _RESOLVE_ANCHOR if name == "resolve" else _STRIP_ANCHOR
    assert func.startswith(anchor)
    assert func.rstrip().endswith("}")
    assert func.count("{") == func.count("}"), f"{name}: braces do not balance"
    p = tmp_path / f"{name}_shape.sh"
    p.write_text(
        'error() { echo "[ERROR] $*"; }\nwarn() { echo "[WARN] $*"; }\n' + func.replace(_PG_ROOT_LITERAL, "/nope"),
        encoding="utf-8",
    )
    proc = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
