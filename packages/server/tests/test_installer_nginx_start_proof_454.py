# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral cells: the core installer PROVES nginx is up before it claims
the reverse proxy is running (ticket #454 / installer-nginx-restart-discarded-announces-success).

``install-venya-core.sh`` ran ``systemctl restart nginx`` with the result
discarded and printed ``info "Nginx enabled and started"`` on the next line,
so a core install could announce a dead or misconfigured proxy. The ruled
shape (ticket AC-1/AC-2): capture the restart rc, assert
``systemctl is-active --quiet nginx.service``, and on failure print the
``nginx -t`` output and exit non-zero — the success line only prints when the
proof succeeded.

Cells run the REAL block lifted out of the git-tracked script between the
``# Start Nginx`` marker and the next section marker (house pattern:
test_installer_skip_prompt_389 / test_installer_sed_fake_success_519 —
exercise real script logic, never a re-implementation), under the same
``set -euo pipefail`` the installers run with, against shell-function stubs
for ``systemctl`` and ``nginx``. No VMs, no installs: nothing touches a real
service manager.

Truth table, both halves: restart-rc-0 + unit active -> rc 0 + the success
claim, no [ERROR], no config test run. Each failure half (restart rc!=0;
restart rc 0 but unit NOT active) -> rc != 0 + config-test output surfaced +
NO success claim. Paired negative on the incumbent behavior: a failing
``systemctl enable`` stays fatal and never reaches the restart (T4).
"""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "install-venya-core.sh"

BEGIN = "# Start Nginx\n"
END = "# --- Pre-upgrade database backup"

PRELUDE = (
    "set -euo pipefail\n"
    'info()  { echo "[INFO]  $*"; }\n'
    'warn()  { echo "[WARN]  $*"; }\n'
    'error() { echo "[ERROR] $*"; }\n'
    # systemctl/nginx stubs, driven by the RC_* env vars each cell sets.
    # `return`, never `exit`: these are shell FUNCTIONS, and an `exit` inside
    # one terminates the whole cell script at the first call.
    "systemctl() {\n"
    '    echo "systemctl $*" >> "$STUB_LOG"\n'
    '    case "$1" in\n'
    '        enable)    return "${RC_ENABLE:-0}" ;;\n'
    '        restart)   return "${RC_RESTART:-0}" ;;\n'
    '        is-active) [ "${UNIT_ACTIVE:-yes}" = yes ] && return 0; return 3 ;;\n'
    "    esac\n"
    "    return 0\n"
    "}\n"
    "nginx() {\n"
    '    echo "nginx $*" >> "$STUB_LOG"\n'
    '    echo "nginx: configuration file /etc/nginx/nginx.conf test failed" >&2\n'
    '    return "${RC_NGX_T:-1}"\n'
    "}\n"
)


def _nginx_block() -> str:
    src = CORE.read_text(encoding="utf-8")
    begin = src.index(BEGIN)
    end = src.index(END, begin)
    return src[begin:end]


def _run_cell(tmp_path: Path, env_overrides: dict) -> tuple[int, str]:
    script = tmp_path / "nginx_block_cell.sh"
    script.write_text(PRELUDE + _nginx_block() + 'echo "CELL-REACHED-AFTER\n"', encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("RC_") and k != "UNIT_ACTIVE"}
    env["STUB_LOG"] = str(tmp_path / "stub-calls.log")
    env.update(env_overrides)
    proc = subprocess.run(
        ["bash", str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
        check=False,
    )
    out = proc.stdout.decode(errors="replace")
    log = Path(env["STUB_LOG"]).read_text(encoding="utf-8") if Path(env["STUB_LOG"]).exists() else ""
    return proc.returncode, out + "\n--- stub calls ---\n" + log


class TestNginxStartProof454:
    def test_t1_bash_n_clean(self):
        """AC-3: the git-tracked root copy parses."""
        proc = subprocess.run(["bash", "-n", str(CORE)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        assert proc.returncode == 0, proc.stdout.decode(errors="replace")
        assert CORE == REPO_ROOT / "install-venya-core.sh"

    def test_t2_positive_active_prints_the_claim_and_exits_zero(self, tmp_path):
        """Restart clean + unit active: the success line is honest, rc 0, no
        [ERROR], and the config test is never invoked on the happy path."""
        rc, out = _run_cell(tmp_path, {"RC_RESTART": "0", "UNIT_ACTIVE": "yes"})
        assert rc == 0, out
        assert "Nginx enabled and started" in out
        assert "[ERROR]" not in out
        assert "CELL-REACHED-AFTER" in out
        assert "nginx -t" not in out, "config test must not run when the unit is active"
        assert "systemctl restart nginx" in out
        assert "systemctl is-active --quiet nginx.service" in out

    def test_t3a_paired_negative_restart_fails_loud_no_claim(self, tmp_path):
        """restart rc != 0: non-zero exit, config-test output surfaced, NO
        success line, flow stops before the rest of the installer."""
        rc, out = _run_cell(tmp_path, {"RC_RESTART": "1", "UNIT_ACTIVE": "yes", "RC_NGX_T": "1"})
        assert rc != 0, out
        assert "Nginx enabled and started" not in out
        assert "CELL-REACHED-AFTER" not in out
        assert "[ERROR]" in out
        assert "configuration file /etc/nginx/nginx.conf test failed" in out, "AC-2: config-test output shown"

    def test_t3b_paired_negative_unit_inactive_no_claim(self, tmp_path):
        """The subtler half: the restart returns 0 but the unit is NOT active
        (a systemd no-op / activating-then-dead unit). Still a refusal, still
        no success line — this is exactly the discarded-result class."""
        rc, out = _run_cell(tmp_path, {"RC_RESTART": "0", "UNIT_ACTIVE": "no", "RC_NGX_T": "1"})
        assert rc != 0, out
        assert "Nginx enabled and started" not in out
        assert "CELL-REACHED-AFTER" not in out
        assert "configuration file /etc/nginx/nginx.conf test failed" in out

    def test_t4_enable_stays_fatal_and_pre_restart_behavior_unchanged(self, tmp_path):
        """The pre-existing enable-fatal behavior is unchanged: a failing
        ``systemctl enable`` aborts the script under set -e before the
        restart line is ever reached (no restart call in the stub log)."""
        rc, out = _run_cell(tmp_path, {"RC_ENABLE": "1", "RC_RESTART": "0", "UNIT_ACTIVE": "yes"})
        assert rc != 0, out
        assert "CELL-REACHED-AFTER" not in out
        assert "Nginx enabled and started" not in out
        assert "systemctl restart nginx" not in out, "enable must stay fatal ahead of the restart"

    def test_t5_no_discarded_result_on_the_nginx_path(self):
        """The fix must not re-introduce a swallowed result: no ``|| true``
        anywhere in the block, and the restart rc is captured."""
        block = _nginx_block()
        assert "|| true" not in block, block
        assert "NGINX_RESTART_RC=0" in block
        assert "systemctl restart nginx || NGINX_RESTART_RC=$?" in block
        assert "systemctl is-active --quiet nginx.service" in block
        # success line sits AFTER the proof, never before it
        assert block.index('if [ "$NGINX_RESTART_RC" -ne 0 ]') < block.index('"Nginx enabled and started"')
