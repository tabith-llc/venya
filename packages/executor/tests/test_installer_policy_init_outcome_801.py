# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor installer #801: the deny-all policy answer is read, not discarded.

Incumbent shape (``install-venya-executor.sh``, global-policy block)::

    if sudo -H -u venya sbx policy init deny-all < /dev/null > /dev/null 2>&1; then
        info "sbx global network policy initialized (deny-all)"
    else
        warn "sbx policy init deny-all failed or policy already initialized — verify manually ..."
    fi

stdout AND stderr were thrown away, so one sentence covered two opposite
outcomes: a re-run over a policy that is already in place (harmless) and a host
with no policy at all (every ``sbx create`` fails). Measured on a sandbox test
guest at sbx v0.46.0, ``policy init deny-all`` returns the SAME status 1 for both and
names the benign one in its own sentence, so the sentence -- not the status --
is what the branch reads.

Cells run the REAL block, extracted between its section comments, under the
installer's own ``set -euo pipefail`` with the ``info``/``warn``/``error`` names
``venya_print_colors`` provides, behind PATH stubs for ``sudo`` and ``sbx``
(house pattern: #457 runs an extracted block behind a PATH stub; #28 extracts a
between-anchors fragment). No VM, no root, no install is involved; the guest
measurement behind the three faces is in the leg-1428 report.

The three faces are the ones measured on the guest and recorded in the leg
report: init succeeds (fresh state), init returns 1 saying "already
initialized" (a re-run), init returns non-zero saying anything else (the guest
cannot sandbox). Each accept carries its paired reject.
"""

import os
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

BEGIN = "# --- sbx global network policy (required before any sandbox create) ---"
STOP = "# --- sbx agent-template warm"
DONE_SENTINEL = "POLICY-BLOCK-COMPLETED"

# The discarded-answer shape this leg removes, verbatim from the pre-fix tip.
OLD_DISCARD = "sbx policy init deny-all < /dev/null > /dev/null 2>&1"
OLD_SENTENCE = "failed or policy already initialized"

# Vendor answers, copied from the guest measurement.
ANSWER_FRESH = 'Global network policy initialized to "deny-all".\n'
ANSWER_ALREADY = (
    "error: global network policy is already initialized; reset it first to change it\n" "  try: sbx policy reset\n"
)
ANSWER_BROKEN = "error: sandboxd is not running\n"


def _installer_source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _block() -> str:
    """The real policy block, from its section comment to the next one."""
    src = _installer_source()
    assert BEGIN in src, "policy block start anchor moved -- re-anchor this cell"
    assert STOP in src, "next-section anchor moved -- re-anchor this cell"
    start = src.index(BEGIN)
    assert start < src.index(STOP, start), "policy block no longer precedes the warm section"
    return src[start : src.index(STOP, start)]


def _stub_bin(tmp_path: Path, *, rc: int, answer: str) -> tuple[Path, Path]:
    """PATH stubs. ``sudo`` drops the privilege prefix and runs the rest, so the
    installer's own command line is the thing under test; ``sbx`` replays one
    face and records every verb it was called with.

    Returns (bin_dir, calls_file).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)

    sudo = bin_dir / "sudo"
    sudo.write_text(
        "#!/bin/sh\n" '[ "$1" = "-H" ] && shift\n' '[ "$1" = "-u" ] && shift 2\n' 'exec "$@"\n',
        encoding="utf-8",
    )

    answer_file = bin_dir / "answer.txt"
    answer_file.write_text(answer, encoding="utf-8")
    calls_file = tmp_path / "sbx-calls.txt"
    calls_file.write_text("", encoding="utf-8")  # truncate: one run, one log
    sbx = bin_dir / "sbx"
    sbx.write_text(
        "#!/bin/sh\n" 'printf \'%s\\n\' "$*" >> "$SBX_CALLS"\n' 'cat "$SBX_ANSWER"\n' f"exit {rc}\n",
        encoding="utf-8",
    )
    for stub in (sudo, sbx):
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir, calls_file


def _run_block(tmp_path: Path, *, rc: int, answer: str) -> subprocess.CompletedProcess:
    bin_dir, calls_file = _stub_bin(tmp_path, rc=rc, answer=answer)
    script = tmp_path / "policy_block.sh"
    script.write_text(
        "set -euo pipefail\n"
        'info()  { echo "[INFO]  $*"; }\n'
        'warn()  { echo "[WARN]  $*"; }\n'
        'error() { echo "[ERROR] $*"; }\n'
        f"{_block()}\n"
        f'echo "{DONE_SENTINEL}"\n',
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["SBX_ANSWER"] = str(bin_dir / "answer.txt")
    env["SBX_CALLS"] = str(calls_file)
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False, env=env)
    proc.sbx_calls = calls_file.read_text(encoding="utf-8")  # type: ignore[attr-defined]
    return proc


class TestInstallerPolicyInitOutcome:
    # ------------------------------------------------------------------ source
    def test_bash_syntax_clean(self) -> None:
        proc = subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_incumbent_discard_shape_is_gone(self) -> None:
        """The answer is captured, so neither the discard nor the
        one-sentence-covering-both warning can survive in the tracked root copy."""
        src = _installer_source()
        assert OLD_DISCARD not in src, "policy init still discards stdout+stderr"
        assert OLD_SENTENCE not in src, "the two-outcomes-in-one-sentence warning survived"
        assert "verify manually" not in _block(), "an instruction with no command is not a remedy"

    def test_the_real_verb_is_still_the_one_issued(self) -> None:
        """test_installer_template_warm.py keys the warm's prerequisite order on
        this string; a rewrite that dropped the verb would silently retarget it."""
        assert "sbx policy init deny-all" in _block()

    # ------------------------------------------------------------------ faces
    def test_fresh_init_reports_initialized(self, tmp_path: Path) -> None:
        """Accept: rc 0 is the one outcome that says the policy was put in place."""
        proc = _run_block(tmp_path, rc=0, answer=ANSWER_FRESH)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "[INFO]  sbx global network policy initialized (deny-all)" in proc.stdout
        assert "[ERROR]" not in proc.stdout
        assert "[WARN]" not in proc.stdout

    def test_already_initialized_is_info_not_error(self, tmp_path: Path) -> None:
        """The benign re-run: same rc 1 the broken face gives, its own sentence,
        and no error channel at all."""
        proc = _run_block(tmp_path, rc=1, answer=ANSWER_ALREADY)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "[INFO]  sbx global network policy already initialized" in proc.stdout
        assert "[ERROR]" not in proc.stdout, "a re-run was reported as a failure"

    def test_other_failure_names_the_captured_answer(self, tmp_path: Path) -> None:
        """Reject: any other non-zero answer is an error that carries the status,
        the vendor's own words, what breaks, and the two commands to act on."""
        proc = _run_block(tmp_path, rc=127, answer=ANSWER_BROKEN)
        assert "[ERROR]" in proc.stdout
        assert "not initialized" in proc.stdout
        assert "global network policy has not been initialized" in proc.stdout, "what breaks is unnamed"
        assert "exited 127" in proc.stdout, "the status is not named"
        assert ANSWER_BROKEN.strip() in proc.stderr, "the captured reason did not reach the operator"
        assert "sbx policy init deny-all" in proc.stdout, "the repair command is missing"
        assert "sbx policy ls" in proc.stdout, "the read command is missing"

    def test_failure_is_loud_but_does_not_stop_the_install(self, tmp_path: Path) -> None:
        """Paired negative on the behaviour change the report names: this case is
        error-level, NOT fatal, so the block still falls through."""
        proc = _run_block(tmp_path, rc=1, answer=ANSWER_BROKEN)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert DONE_SENTINEL in proc.stdout
        assert "[WARN]  The install continues" in proc.stdout

    def test_policy_ls_is_the_operator_read_not_the_branch_test(self, tmp_path: Path) -> None:
        """`sbx policy ls` was measured to answer by the reading user's session,
        not by policy state, so the branch must issue exactly one verb -- the init."""
        for rc, answer in ((0, ANSWER_FRESH), (1, ANSWER_ALREADY), (1, ANSWER_BROKEN)):
            # Each face rewrites its own stub answer and call log under tmp_path.
            proc = _run_block(tmp_path, rc=rc, answer=answer)
            assert proc.sbx_calls.strip() == "policy init deny-all", (rc, proc.sbx_calls)
