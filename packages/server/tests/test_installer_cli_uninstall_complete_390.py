# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Behavioral cells: CLI uninstaller removes writer sites and fails loud (#390).

Root cause (uv 0.12 probe, montana scratch HOME): uv's tool-env + shim removal
is receipt-driven (uv-receipt.toml). For a de-registered or de-contented tool
env `uv tool uninstall <pkg>` exits non-zero with "is not installed" and
removes NOTHING, while ~/.local/bin shims and the tools dir survive — `venya`
then resolves to a broken launcher. The uninstaller must remove the installer
writer sites itself and exit non-zero if anything still resolves.

Harness idiom (per test_installer_origin_pin_posture.py): exec the REAL
uninstall-venya-cli.sh with HOME pointed at a tmpdir and a stub `uv` bin whose
per-tool exit codes are marker-file driven — the decision logic runs while all
filesystem effects stay inside the tmpdir.

Truth table, both halves: clean uninstall rc=0 + zero resolving venya;
de-registered leftover (uv rc=2) still ends with no shims/tool dirs and rc=0;
a binary that still resolves elsewhere on PATH hits the [ERROR] path with
rc!=0 (RED-at-base shows the leftover half failing).
"""

import os
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "uninstall-venya-cli.sh"

_UV_STUB = """#!/bin/bash
echo "uv $*" >> "$STUB_LOG"
if [ "$1 $2" = "tool dir" ]; then echo "$TOOLS_DIR"; exit 0; fi
if [ "$1 $2" = "tool uninstall" ]; then
    name="$3"
    rc=0
    if [ -f "$RC_DIR/rc-$name" ]; then rc="$(cat "$RC_DIR/rc-$name")"; fi
    if [ "$rc" = "0" ]; then
        # uv's success half is receipt-driven: it removes the tool env AND
        # the shims it registered.
        rm -rf "$TOOLS_DIR/$name"
        if [ "$name" = "venya-cli" ]; then rm -f "$HOME/.local/bin/venya"; fi
        if [ "$name" = "venya-mcp" ]; then rm -f "$HOME/.local/bin/venya-mcp"; fi
    fi
    exit "$rc"
fi
exit 0
"""


class _Harness:
    def __init__(self, tmp: str) -> None:
        self.tmp = Path(tmp)
        self.home = self.tmp / "home"
        self.bindir = self.home / ".local" / "bin"
        self.tools = self.home / ".local" / "share" / "uv" / "tools"
        self.stub = self.tmp / "stubbin"
        self.rc_dir = self.tmp / "rc"
        self.log = self.tmp / "uv-calls.log"
        for d in (self.bindir, self.tools, self.stub, self.rc_dir):
            d.mkdir(parents=True)
        p = self.stub / "uv"
        p.write_text(_UV_STUB, encoding="utf-8")
        p.chmod(0o755)
        self.log.write_text("", encoding="utf-8")

    def install_tree(self) -> None:
        """Create the writer-site artifacts install-venya-cli.sh leaves behind."""
        for tool in ("venya-cli", "venya-mcp"):
            env = self.tools / tool
            (env / "bin").mkdir(parents=True)
            (env / "uv-receipt.toml").write_text("[tool]\n", encoding="utf-8")
        (self.bindir / "venya").write_text("#!/bin/sh\necho venya\n", encoding="utf-8")
        (self.bindir / "venya-mcp").write_text("#!/bin/sh\necho mcp\n", encoding="utf-8")

    def set_uv_rc(self, tool: str, rc: int) -> None:
        (self.rc_dir / f"rc-{tool}").write_text(str(rc), encoding="utf-8")

    def run(self, extra_path: str | None = None) -> subprocess.CompletedProcess:
        path = f"{self.stub}:{os.defpath}:/usr/bin:/bin"
        if extra_path:
            path = f"{self.stub}:{extra_path}:{os.defpath}:/usr/bin:/bin"
        env = {
            "HOME": str(self.home),
            "PATH": path,
            "STUB_LOG": str(self.log),
            "TOOLS_DIR": str(self.tools),
            "RC_DIR": str(self.rc_dir),
            "VENYA_SKIP_PROMPT": "yes",
            "VENYA_PURGE_CONFIG": "no",
        }
        return subprocess.run(
            ["/bin/bash", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )


def test_clean_uninstall_leaves_zero_resolving_venya_and_exits_0() -> None:
    """AC-1 positive: installed tree, uv succeeds -> rc 0, no writer sites."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp)
        h.install_tree()
        r = h.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "[ERROR]" not in r.stdout
        assert not (h.bindir / "venya").exists()
        assert not (h.bindir / "venya-mcp").exists()
        assert not (h.tools / "venya-cli").exists()
        assert not (h.tools / "venya-mcp").exists()


def test_de_registered_leftover_is_removed_by_the_script_itself() -> None:
    """#390 core cell: uv reports "not installed" (rc 2) for a de-contented
    env — the script must still clear the shims + tool dirs and exit 0.
    RED-at-base: the shims survived and verify exited 1."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp)
        h.install_tree()
        for tool in ("venya-cli", "venya-mcp"):
            h.set_uv_rc(tool, 2)
        r = h.run()
        assert "reported nothing to remove" in r.stdout, r.stdout
        assert not (h.bindir / "venya").exists(), "broken venya shim left on PATH"
        assert not (h.bindir / "venya-mcp").exists(), "broken venya-mcp shim left"
        assert not (h.tools / "venya-cli").exists(), "tool env dir left"
        assert not (h.tools / "venya-mcp").exists(), "tool env dir left"
        assert "uv tool uninstall venya-cli" in h.log.read_text(encoding="utf-8")
        assert r.returncode == 0, r.stdout + r.stderr


def test_still_resolving_binary_exits_nonzero_after_error() -> None:
    """AC-1 negative half: a venya the script does not own still on PATH ->
    [ERROR] line AND rc!=0 (fail-loudly pin)."""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp)
        h.install_tree()
        rogue = Path(tmp) / "roguebin"
        rogue.mkdir()
        (rogue / "venya").write_text("#!/bin/sh\necho rogue\n", encoding="utf-8")
        (rogue / "venya").chmod(0o755)
        r = h.run(extra_path=str(rogue))
        assert r.returncode != 0
        assert "venya still resolves at" in r.stdout


def test_uninstaller_script_without_uv_still_clears_writer_sites() -> None:
    """Origin-down/air-gapped half: no uv on PATH -> manual removal at the
    same writer sites must leave nothing resolving. (Base already cleared
    this path; pinned so the #390 refactor cannot regress it.)"""
    with tempfile.TemporaryDirectory() as tmp:
        h = _Harness(tmp)
        h.install_tree()
        env_home = h.home
        path = f"{os.defpath}:/usr/bin:/bin"
        env = {
            "HOME": str(env_home),
            "PATH": path,
            "VENYA_SKIP_PROMPT": "yes",
            "VENYA_PURGE_CONFIG": "no",
        }
        r = subprocess.run(
            ["/bin/bash", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (h.bindir / "venya").exists()
        assert not (h.tools / "venya-cli").exists()
