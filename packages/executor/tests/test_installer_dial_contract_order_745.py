# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#745 — the executor installer tests its own dial contract before it pays for a build.

``install-venya-executor.sh`` states the contract at its own header: ``VENYA_EXECUTOR_ID``
"is the relay dial hostname + client-cert SAN — it MUST be resolvable from every core".
Two things made that statement unenforceable:

* the only place the claim was evaluated sat at line 602 of 1,081, after rustup, uv,
  Python 3.14, the tarball, the venv and ``cargo build --release`` — the operator paid for
  a toolchain and a Rust build before learning the name cannot resolve, and the first hard
  stop was registration;
* the default was ``venya-exec-1``, the one value guaranteed to violate the contract on a
  host with no matching entry, chosen in silence. The core copy already defaults its own
  name to the machine (``CORE_HOSTNAME="${CORE_HOSTNAME:-$(hostname)}"``); the executor copy
  had no own-name idiom at all (re-run the predicate:
  ``grep -nE 'hostname -|uname -n|\\$\\(\\s*hostname' install-venya-executor.sh`` → zero lines).

The NON-FATAL posture is ruled and these cells hold it: local ``getent`` is a weak proxy,
authoritative resolvability is core-side, an Ubuntu ``127.0.1.1 <hostname>`` entry makes an
ID equal to the own-hostname pass trivially, and a core-side-only ``/etc/hosts`` entry is a
valid strategy — so a check that aborted on the local proxy would false-positive a working
install. That reasoning is about *whether* to look fatally; it never said *when*.

Order pins are the house pattern (``test_installer_docker_gate_order.py``,
``test_installer_no_private_literals``): marker-index comparison over the installer source.
The two executed cells lift the REAL code out of the script and run it against PATH stubs,
the ``test_installer_pg_cluster_resolve_496.py`` precedent — no VM, no sudo, no install,
nothing outside a tmpdir.
"""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

# --- markers: what must sit where ---
DIAL_HEADER = "# --- Executor-id dial contract: checked while the install is still cheap (#745) ---"
CONFIRM_HEADER = "# --- Confirm a defaulted executor ID (#745) ---"
DIAL_LOOK = 'if getent hosts "$EXECUTOR_ID" > /dev/null 2>&1; then'
# The remedy line, up to the point where the ID is expanded — the executed cell runs the
# real block, so the variable is substituted there and cannot be matched literally.
REMEDY_LINE = "Remedy — on EACH core host: add one '<executor-ip> "
CONTRACT_LINE = "CONTRACT: the ID is the relay dial hostname + client-cert SAN"
OWN_TRAP_LINE = "local resolution does not prove core-side resolution (127.0.1.1 own-hostname trap)"
REGISTER_MARKER = "# --- Register mTLS certificate"

# The steps an operator used to pay for first, in the order the script runs them.
# Each is a command line, pinned to occur once, so a comment mentioning a step cannot
# stand in for the step itself.
EXPENSIVE_STEPS = (
    "venya_install_system_pkgs curl sudo build-essential sshpass",
    "venya_install_uv_user",
    "venya_install_python314",
    "venya_download_tarball executor",
    "venya_apply_code_fixes",
    'venya_create_venv "venya-executor-requirements.txt"',
    "&& cargo build --release",
)
# The first thing the script writes to the host at all — the look must precede even this.
FIRST_WRITE = "# --- Create venya service account (no password, nologin, locked) ---"
# The remedy the registration-failure branch prints, worded differently from the moved
# block's — which is why it is pinned by its own text and not by a shared prefix.
REGISTER_REMEDY = "address first, name as the SECOND field (#490 shape) — or a DNS record"

# --- the real code, extracted by unique anchors ---
DEFAULT_ANCHOR = 'EXECUTOR_ID="${VENYA_EXECUTOR_ID:-$(hostname)}"'
DEFAULT_TAIL = '    EXECUTOR_ID="venya-exec-1"\nfi'


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _region(text: str, start: str, end: str) -> str:
    """Lift a real region out of the installer between two anchors, refusing ambiguity."""
    assert text.count(start) == 1, f"start anchor not unique in install-venya-executor.sh: {start!r}"
    assert end in text[text.index(start) :], f"end anchor not found after the start: {end!r}"
    i = text.index(start)
    j = text.index(end, i) + len(end)
    return text[i:j]


def _dial_block() -> str:
    """The moved contract block: header through the closing ``fi``."""
    return _region(_source(), DIAL_HEADER, "\nfi\n")


def _default_block() -> str:
    """The default assignment plus its empty-name fallback."""
    return _region(_source(), DEFAULT_ANCHOR, DEFAULT_TAIL)


def _run(script: str, tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    path = tmp_path / "run.sh"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        ["/bin/bash", str(path)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _getent_stub(tmp_path: Path, *, resolves: bool) -> Path:
    """A PATH dir whose getent answers the way a host with (no) entry would."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "getent"
    stub.write_text(f"#!/bin/bash\nexit {0 if resolves else 1}\n", encoding="utf-8")
    stub.chmod(0o755)
    return bin_dir


class TestTheLookPrecedesTheBuild:
    """AC1 and AC3: order, pinned against the source the operator actually runs."""

    def test_dial_contract_block_moved_into_the_parameter_region(self):
        src = _source()
        look = src.index(DIAL_LOOK)
        assert src.index(DIAL_HEADER) < look, "the moved block lost its own header"
        assert look < src.index(REGISTER_MARKER), "the contract look still sits at the registration foot"

    def test_no_expensive_step_runs_before_the_contract_look(self):
        """The discriminating pin: on the pre-fix file every one of these is earlier."""
        src = _source()
        look = src.index(DIAL_LOOK)
        for step in EXPENSIVE_STEPS:
            assert src.count(step) == 1, f"step marker no longer unique: {step!r}"
            assert look < src.index(
                step
            ), f"the operator still pays for {step!r} before learning the name cannot resolve (#745)"

    def test_the_look_precedes_the_first_write_to_the_host(self):
        """AC4's re-install shape: a name that stopped resolving is caught before anything
        is written, so the catch costs the operator nothing."""
        src = _source()
        assert src.count(FIRST_WRITE) == 1, "the first-write marker is no longer unique"
        assert src.index(DIAL_LOOK) < src.index(FIRST_WRITE), "the contract look must precede the first system write"

    def test_the_block_was_moved_not_duplicated(self):
        src = _source()
        assert src.count('getent hosts "$EXECUTOR_ID"') == 1, "two contract looks means two messages and two opinions"
        assert src.count(DIAL_HEADER) == 1, "the moved block header appears more than once"

    def test_the_registration_foot_still_points_at_the_same_guidance(self):
        """The 400 branch keeps its remedy; the move must not strand a reader who gets there."""
        src = _source()
        register = src.index(REGISTER_MARKER)
        assert src.count(REGISTER_REMEDY) == 1, "the registration-side remedy text changed shape"
        assert register < src.index(
            REGISTER_REMEDY
        ), "the registration failure path no longer prints its remedy after the header"


class TestTheRulingStillHolds:
    """AC1/AC3 paired negative: non-fatal, exactly as ruled — executed, not just positioned."""

    def test_the_moved_block_cannot_abort_the_install(self, tmp_path):
        """An ID that resolves only core-side must not be fatal, and that is unchanged.

        Runs the REAL lifted block with a getent stub that refuses, the shape of a host
        carrying no local entry: the guidance must print and the segment must exit 0.
        """
        script = (
            "set -uo pipefail\n"
            'info()  { echo "[INFO] $*"; }\n'
            'warn()  { echo "[WARN] $*"; }\n'
            'error() { echo "[ERROR] $*"; }\n'
            f'EXECUTOR_ID="venya-exec-9"\n'
            f"{_dial_block()}\n"
            'echo "REACHED_END=1"\n'
        )
        bin_dir = _getent_stub(tmp_path, resolves=False)
        proc = _run(script, tmp_path, {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)})
        assert (
            proc.returncode == 0
        ), f"the contract block aborted the install: rc={proc.returncode} {proc.stdout}{proc.stderr}"
        assert "REACHED_END=1" in proc.stdout, "the block exited before its end — the abort ruling was broken"
        assert "does NOT resolve locally" in proc.stdout, proc.stdout
        assert CONTRACT_LINE.split(" —")[0] in proc.stdout, proc.stdout
        assert REMEDY_LINE in proc.stdout, proc.stdout

    def test_the_resolving_branch_still_warns_about_its_own_weakness(self, tmp_path):
        """A locally-resolving ID is told the truth too: local is not core-side proof."""
        script = (
            "set -uo pipefail\n"
            'info()  { echo "[INFO] $*"; }\n'
            'warn()  { echo "[WARN] $*"; }\n'
            'error() { echo "[ERROR] $*"; }\n'
            'EXECUTOR_ID="venya-exec-9"\n'
            f"{_dial_block()}\n"
        )
        bin_dir = _getent_stub(tmp_path, resolves=True)
        proc = _run(script, tmp_path, {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "resolves locally" in proc.stdout, proc.stdout
        assert OWN_TRAP_LINE in proc.stdout, proc.stdout

    def test_no_exit_line_inside_the_block(self):
        src = _source()
        block = _dial_block()
        assert "exit " not in block, f"the non-fatal ruling is broken by an exit in the block: {block!r}"
        assert src.count(DIAL_LOOK) == 1


class TestTheDefaultAgreesWithTheContract:
    """AC2: the chosen shape — derive from the host, confirm in a TTY, explain when not one.

    Why this shape and not "require the ID to be named": the fleet names its guests after
    what ``hostname`` answers (``venya-exec-1`` is a host name, not an invention), the core
    installer already defaults its own identity to the machine, and an unset variable is the
    one place a silent wrong value can hide. Requiring the name would abort a re-run that is
    otherwise fine, and this leg was not given licence to add an abort. An explicit
    ``VENYA_EXECUTOR_ID`` still wins untouched.
    """

    def test_default_is_the_host_own_name(self):
        src = _source()
        assert DEFAULT_ANCHOR in src, "the executor ID no longer defaults to the host's own name"
        assert 'EXECUTOR_ID="${VENYA_EXECUTOR_ID:-venya-exec-1}"' not in src, "the silent literal default is back"

    def test_extracted_default_answers_the_host_name_and_the_operator_wins(self, tmp_path):
        """Executed: derived from the host, an explicit value untouched, a name query that
        answers nothing falls back to the old literal."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "hostname").write_text('#!/bin/bash\nprintf "exec-a\\n"\n', encoding="utf-8")
        (bin_dir / "hostname").chmod(0o755)
        block = _default_block()
        script = f"set -uo pipefail\n{block}\nprintf 'ID=[%s]\\n' \"$EXECUTOR_ID\"\n"

        proc = _run(script, tmp_path, {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)})
        assert "ID=[exec-a]" in proc.stdout, proc.stdout + proc.stderr

        proc = _run(
            script,
            tmp_path,
            {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "VENYA_EXECUTOR_ID": "named-by-operator"},
        )
        assert "ID=[named-by-operator]" in proc.stdout, proc.stdout + proc.stderr

        empty_bin = tmp_path / "emptybin"
        empty_bin.mkdir()
        proc = _run(script, tmp_path, {"PATH": str(empty_bin), "HOME": str(tmp_path)})
        assert (
            "ID=[venya-exec-1]" in proc.stdout
        ), f"a host whose name query answers nothing must still get a value: {proc.stdout}{proc.stderr}"

    def test_a_defaulted_id_is_confirmed_in_a_tty_only(self):
        """The confirm is TTY-gated: a piped install carries the rest of the script on stdin,
        so an unguarded read would consume installer lines rather than an answer."""
        src = _source()
        assert src.count(CONFIRM_HEADER) == 1, "the confirm block is missing or duplicated"
        confirm = src[src.index(CONFIRM_HEADER) :]
        window = confirm[: confirm.index("\nvenya_guard_injection")]
        assert 'if [ -z "${VENYA_EXECUTOR_ID:-}" ]' in window, "a named ID must not be re-asked"
        assert "[ -t 0 ]" in window, "the read is not TTY-gated"
        assert "VENYA_SKIP_PROMPT:-}" in window, "the documented skip-prompt knob is not honoured"
        assert "Unattended install" in window, "the non-TTY branch must say what it chose and why"

    def test_the_injection_gate_still_runs_on_the_final_value(self):
        """Whatever the confirm accepted is guarded before it reaches config files."""
        src = _source()
        assert src.index(CONFIRM_HEADER) < src.index(
            'venya_guard_injection "EXECUTOR_ID"'
        ), "the confirm can now hand an unguarded value to the config writer"

    def test_the_header_table_names_the_new_default(self):
        """Docs that went stale in this change are corrected in it."""
        src = _source()
        header = src[: src.index(DIAL_LOOK)]
        assert "default: this host's own name" in header, "the in-file parameter table still promises venya-exec-1"
        readme = (REPO_ROOT / "install-scripts-README.md").read_text(encoding="utf-8")
        row = [line for line in readme.splitlines() if line.startswith("| `VENYA_EXECUTOR_ID`")]
        assert row and "this host" in row[0], f"install-scripts-README.md still documents the old default: {row}"
