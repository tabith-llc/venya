# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""venya-common.sh confirm path: prompt gate before question print (ticket #389).

The question text used to be emitted BEFORE the VENYA_SKIP_PROMPT check, so a
SKIP=yes unattended run printed prompts nobody answers, and a non-TTY run
without the flag silently consumed EOF defaults. The gate now runs first:
SKIP=yes -> documented default, zero question lines; non-TTY without the flag
-> loud exit with guidance and zero writes; TTY path byte-identical. The
#203/EXEC co-location hard stop is a different function and must keep
refusing even with VENYA_SKIP_PROMPT=yes.

Harness cells execute the real fragments extracted from the source (house
pattern: test_installer_docker_gate_order / test_installer_token_failfast_28).
Truth-table rule: every accept has its paired reject.
"""

import os
import pty
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMON = REPO_ROOT / "venya-common.sh"

GATE_BEGIN = "venya_prompt_gate() {"
GATE_END = "# --- 4b. Co-location guard"
COLOC_BEGIN = "venya_check_no_colocation() {"
COLOC_END = "# --- 5. Create venya user ---"

PRELUDE = (
    "set -euo pipefail\n"
    'error() { echo "[ERROR] $*"; }\n'
    'warn() { echo "[WARN] $*"; }\n'
    'info() { echo "[INFO] $*"; }\n'
    "systemctl() { return 1; }\n"
)


def _common_source() -> str:
    return COMMON.read_text(encoding="utf-8")


def _confirm_fragment() -> str:
    src = _common_source()
    # Base-lenient start: at pre-#389 bytes the gate does not exist yet, so
    # cells still execute the OLD confirm path (behavioral RED evidence, and
    # the TTY parity cell PASSes at both refs).
    begin = src.index(GATE_BEGIN) if GATE_BEGIN in src else src.index("venya_determine_install_dir() {")
    return src[begin : src.index(GATE_END)]


def _colocation_fragment() -> str:
    src = _common_source()
    return src[src.index(COLOC_BEGIN) : src.index(COLOC_END)]


def _run_confirm(script_dir: Path, skip: bool, tty: bool = False, answers: bytes = b"") -> tuple[int, str]:
    """Run the confirm path (determine_install_dir + check_existing)."""
    body = (
        PRELUDE + _confirm_fragment() + 'venya_determine_install_dir "$1"\n'
        "venya_check_existing\n"
        'echo "CELL-REACHED-AFTER $INSTALL_DIR"\n'
    )
    script = script_dir / "confirm_cell.sh"
    script.write_text(body, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ("VENYA_SKIP_PROMPT", "VENYA_INSTALL_DIR")}
    if skip:
        env["VENYA_SKIP_PROMPT"] = "yes"
    cmd = ["bash", str(script), str(script_dir / "default-dir")]
    if tty:
        master, slave = pty.openpty()
        proc = subprocess.Popen(cmd, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        os.close(slave)
        os.write(master, answers)
        out = proc.stdout.read().decode(errors="replace")
        proc.wait()
        os.close(master)
        return proc.returncode, out
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env, check=False
    )
    return proc.returncode, proc.stdout.decode(errors="replace")


class TestSkipYesPrintsZeroQuestions:
    def test_fresh_dir_default_quiet(self, tmp_path):
        """SKIP=yes, no incumbent: default taken, zero question lines."""
        rc, out = _run_confirm(tmp_path, skip=True)
        assert rc == 0
        assert "Install to" not in out
        assert "Reinstall?" not in out
        assert f"CELL-REACHED-AFTER {tmp_path / 'default-dir'}" in out

    def test_existing_reinstall_default_quiet(self, tmp_path):
        """SKIP=yes over an incumbent install: proceeds, zero question lines."""
        incumbent = tmp_path / "incumbent"
        incumbent.mkdir()
        (incumbent / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        body = (
            PRELUDE + _confirm_fragment() + f'INSTALL_DIR="{incumbent}"\n'
            "venya_check_existing\n"
            'echo "CELL-REACHED-AFTER"\n'
        )
        script = tmp_path / "reinstall_cell.sh"
        script.write_text(body, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k not in ("VENYA_SKIP_PROMPT", "VENYA_INSTALL_DIR")}
        env["VENYA_SKIP_PROMPT"] = "yes"
        proc = subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            check=False,
        )
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode == 0
        assert "Reinstall?" not in out
        assert "Aborted." not in out
        assert "CELL-REACHED-AFTER" in out


class TestNonTtyNoSkipFailsLoud:
    def test_fresh_dir_gate_exits(self, tmp_path):
        """Paired reject: non-TTY without the flag -> rc=1, guidance, no
        question ever printed, flow stops before any downstream step."""
        rc, out = _run_confirm(tmp_path, skip=False)
        assert rc == 1
        assert "VENYA_SKIP_PROMPT" in out
        assert "refusing to answer" in out
        assert "default-dir? [Y/n] " not in out, "bare echo -n prompt must not print"
        assert "CELL-REACHED-AFTER" not in out

    def test_reinstall_gate_exits_zero_writes(self, tmp_path):
        """Non-TTY without the flag at the reinstall site: loud exit and the
        only write-marker in the cell body is never reached."""
        incumbent = tmp_path / "incumbent"
        incumbent.mkdir()
        (incumbent / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        marker = tmp_path / "downstream-write"
        body = (
            PRELUDE + _confirm_fragment() + f'INSTALL_DIR="{incumbent}"\n'
            "venya_check_existing\n"
            f'echo written > "{marker}"\n'
        )
        script = tmp_path / "reinstall_loud_cell.sh"
        script.write_text(body, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k not in ("VENYA_SKIP_PROMPT", "VENYA_INSTALL_DIR")}
        proc = subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            check=False,
        )
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode == 1
        assert "Reinstall? [y/N] " not in out, "bare echo -n prompt must not print"
        assert "refusing to answer 'Reinstall? [y/N]'" in out
        assert "VENYA_SKIP_PROMPT" in out
        assert not marker.exists(), "gate must stop the flow before any write"


class TestTtyPathUnchanged:
    def test_questions_printed_and_read(self, tmp_path):
        """TTY: both questions print and answers are read exactly as before
        (y -> default dir, n -> documented Aborted exit 0)."""
        incumbent_default = tmp_path / "default-dir"
        incumbent_default.mkdir()
        (incumbent_default / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        rc, out = _run_confirm(tmp_path, skip=False, tty=True, answers=b"y\nn\n")
        assert rc == 0
        assert "Install to" in out
        assert "Reinstall?" in out
        assert "Aborted." in out
        assert "CELL-REACHED-AFTER" not in out


class TestColocationHardStopPreserved:
    def _run_colocation(self, tmp_path: Path, skip: bool, core_exists: bool):
        core_unit = tmp_path / "venya-core.service"
        exec_unit = tmp_path / "venya-executor.service"
        exec_toml = tmp_path / "executor.toml"
        if core_exists:
            core_unit.write_text("[Unit]\n", encoding="utf-8")
        body = (
            PRELUDE
            + _colocation_fragment()
            .replace("/etc/systemd/system/venya-core.service", f'"{core_unit}"')
            .replace("/etc/systemd/system/venya-executor.service", f'"{exec_unit}"')
            .replace("/etc/venya/executor.toml", f'"{exec_toml}"')
            + "venya_check_no_colocation executor\n"
            'echo "CELL-COLOCATION-PASSED"\n'
        )
        script = tmp_path / "colocation_cell.sh"
        script.write_text(body, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k not in ("VENYA_SKIP_PROMPT", "VENYA_INSTALL_DIR")}
        if skip:
            env["VENYA_SKIP_PROMPT"] = "yes"
        proc = subprocess.run(
            ["bash", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            check=False,
        )
        return proc.returncode, proc.stdout.decode(errors="replace")

    def test_hard_stop_refuses_despite_skip(self, tmp_path):
        """#203/EXEC semantics UNCHANGED: a core incumbent still hard-stops
        an executor install even with VENYA_SKIP_PROMPT=yes."""
        rc, out = self._run_colocation(tmp_path, skip=True, core_exists=True)
        assert rc == 1
        assert "REFUSING TO INSTALL" in out
        assert "CELL-COLOCATION-PASSED" not in out

    def test_no_collision_passes(self, tmp_path):
        """Paired positive: no other-component incumbent -> guard passes."""
        rc, out = self._run_colocation(tmp_path, skip=True, core_exists=False)
        assert rc == 0
        assert "CELL-COLOCATION-PASSED" in out


class TestSourceOrderPins:
    def test_gate_precedes_question_print_at_both_sites(self):
        src = _common_source()
        for call, echo in (
            ('venya_prompt_gate "Install to', 'echo -n "Install to'),
            ('venya_prompt_gate "Reinstall?', 'echo -n "Reinstall?'),
        ):
            assert src.index(call) < src.index(echo), f"{echo!r} must sit after the gate call"

    def test_old_print_before_check_shape_gone(self):
        src = _common_source()
        assert 'echo -n "Install to $default_dir? [Y/n] "\n        if [ "${VENYA_SKIP_PROMPT' not in src
        assert 'echo ""\n            reply="y"' not in src, "the echo-empty skip shape must be retired"

    def test_colocation_guard_never_calls_the_gate(self):
        body = _colocation_fragment()
        assert "venya_prompt_gate" not in body
        assert "VENYA_SKIP_PROMPT" not in body.split("venya_check_no_colocation() {")[1]
