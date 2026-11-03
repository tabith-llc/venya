# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Login-shell verification cells for install-venya-cli.sh (ticket #744).

The installer exports ~/.local/bin into its OWN PATH, then ran `command -v
venya` in that same process: the check passed by construction and the remedy
line below it was unreachable. Observed on the estate workstation: shims
present, operator's next command answered "venya: command not found".

Behavioral cells execute the real verify fragment extracted from the script
(house pattern: test_installer_skip_prompt_389.py), against a fake HOME whose
shell startup file either does or does not put ~/.local/bin on PATH.

Truth table: positive = a wired login shell is reported as proven, no remedy
noise. Negative (the tvw shape, and the reason this file exists) = shim present
+ login PATH without ~/.local/bin => the installer must NOT print an unqualified
"installed", must name the remedy, and must say it before the day-one commands.
The negative cell is RED at a788ece3 (pre-fix bytes) — see the leg report.
"""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "install-venya-cli.sh"

BEGIN = "venya_login_shell_path() {"
VERIFY_BEGIN = "# --- Verify ---"
END = "# --- FIDO2 access check"

PRELUDE = (
    "set -euo pipefail\n"
    'error() { echo "[ERROR] $*"; }\n'
    'warn() { echo "[WARN] $*"; }\n'
    'info() { echo "[INFO] $*"; }\n'
    # `uv tool dir` only: the fragment never installs.
    'uv() { echo "$FAKE_TOOLS_DIR"; }\n'
)

# login-file shapes: wired (Ubuntu default profile) and NOT wired (tvw)
PROFILE_WIRED = 'export PATH="$HOME/.local/bin:$PATH"\n'
PROFILE_UNWIRED = 'export PATH="/usr/bin:/bin"\n'


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _fragment(src: str) -> str:
    """Helpers + verify block, base-lenient so the pre-fix bytes also run.

    At a788ece3 the helper does not exist yet, so the slice starts at the
    verify marker — which is exactly what lets the negative cell be RED there.
    """
    begin = src.index(BEGIN) if BEGIN in src else src.index(VERIFY_BEGIN)
    return src[begin : src.index(END)]


def _home(tmp_path: Path, profile: str) -> Path:
    """Fake operator home: shims installed, tools dir present, given startup file."""
    home = tmp_path / "home"
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True)
    tools = home / ".local" / "share" / "uv" / "tools"
    (tools / "venya-mcp" / "bin").mkdir(parents=True)
    shim = "#!/bin/sh\nexit 0\n"
    (bindir / "venya").write_text(shim, encoding="utf-8")
    (bindir / "venya-mcp").write_text(shim, encoding="utf-8")
    python = tools / "venya-mcp" / "bin" / "python"
    python.write_text(shim, encoding="utf-8")
    for f in (bindir / "venya", bindir / "venya-mcp", python):
        f.chmod(0o755)
    (home / ".profile").write_text(profile, encoding="utf-8")
    return home


def _run_verify(tmp_path: Path, profile: str) -> tuple[int, str]:
    """Execute the extracted verify fragment as the installer would run it."""
    home = _home(tmp_path, profile)
    script = tmp_path / "verify_cell.sh"
    script.write_text(PRELUDE + _fragment(_src()), encoding="utf-8")
    local_bin = str(home / ".local" / "bin")
    env = {
        "HOME": str(home),
        "PATH": f"{local_bin}:/usr/bin:/bin",  # the installer's OWN exported PATH
        # what a fresh terminal starts from, before any login file is read
        "VENYA_PATH_INHERITED": "/usr/bin:/bin",
        "INSTALL_MCP": "yes",
        "FAKE_TOOLS_DIR": str(home / ".local" / "share" / "uv" / "tools"),
    }
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, timeout=120, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def test_login_shell_without_the_shim_dir_does_not_claim_installed(tmp_path: Path) -> None:
    """The tvw shape: shim on the installer PATH, login PATH lacks it."""
    rc, out = _run_verify(tmp_path, PROFILE_UNWIRED)
    assert rc == 0, out
    assert "does NOT resolve" in out, out
    # the unqualified claim is what the ticket calls the defect
    assert "venya CLI installed:" not in out, out
    assert "venya-mcp installed:" not in out, out
    assert "shim installed at" in out, out


def test_unresolved_shim_prints_a_reachable_remedy(tmp_path: Path) -> None:
    """AC2: the remedy must sit on a branch the PATH export cannot mask."""
    _, out = _run_verify(tmp_path, PROFILE_UNWIRED)
    assert 'export PATH="$HOME/.local/bin:$PATH"' in out, out
    assert "uv tool update-shell" in out, out
    # names what is missing, so the operator knows which shell to fix
    assert "does not resolve" in out, out


def test_wired_login_shell_is_reported_as_proven(tmp_path: Path) -> None:
    """Positive half: a login shell that resolves the name is stated as proven."""
    rc, out = _run_verify(tmp_path, PROFILE_WIRED)
    assert rc == 0, out
    assert "venya CLI installed:" in out, out
    assert "proven in a login shell" in out, out
    assert "venya-mcp installed:" in out, out
    assert "does NOT resolve" not in out, out
    assert "update-shell" not in out, out


def test_probe_asks_with_the_inherited_path_not_the_exported_one() -> None:
    """The control must guarantee its own input: it may inherit nothing from the
    export it is auditing (#744 root cause)."""
    src = _src()
    assert 'VENYA_PATH_INHERITED="$PATH"' in src
    assert src.index('VENYA_PATH_INHERITED="$PATH"') < src.index('export PATH="$HOME/.local/bin:$PATH"')
    assert 'PATH="$VENYA_PATH_INHERITED" bash -lc' in src


def test_day_one_banner_is_warned_before_the_commands_are_printed() -> None:
    """AC3: the operator hears the caveat before being told to type the name."""
    src = _src()
    gate = src.index('if [ -n "$LOGIN_UNRESOLVED" ]; then\n    # Stated before')
    assert gate < src.index('echo "Day-one commands:"')


def test_mcp_shim_failure_branch_carries_a_remedy() -> None:
    """AC4: venya-mcp's own failure branch used to name no remedy at all."""
    src = _src()
    branch = src[src.index('error "venya-mcp shim not found') :]
    branch = branch[: branch.index("exit 1")]
    assert "update-shell" in branch, branch
