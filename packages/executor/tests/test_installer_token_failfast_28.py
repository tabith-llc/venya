# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor installer: fresh-install enrollment-token fail-fast (ticket #28).

An empty/missing VENYA_EXECUTOR_ENROLLMENT_TOKEN on a fresh install used to
ride through every system write (apt, venv, toml) and only surface later as
a daemon boot failure. The guard now mirrors the VENYA_SERVER_URL Require
block: exit 1 BEFORE any write, naming the knob and the mint command.
Re-runs with an existing certificate keep working without a token.

Harness cells run the REAL guard fragment extracted from the installer
source (house pattern: test_installer_docker_gate_order pins source order;
here we additionally execute the fragment with the cert path redirected to
a tmp dir). Truth-table rule: every accept has its paired reject.
"""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

GUARD_BEGIN = "# --- Require VENYA_EXECUTOR_ENROLLMENT_TOKEN on a fresh install"
GUARD_END = "# --- Fail-closed config-injection gate"
CERT_SENTINEL = "/etc/venya/executor/executor.crt"


def _installer_source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _run_guard(tmp_path: Path, token, cert_bytes) -> subprocess.CompletedProcess:
    """Execute the extracted guard fragment against a faked cert state.

    token=None means the variable is unset; b"" means set-but-empty.
    cert_bytes=None means no cert file; b"..." means an existing cert.
    """
    src = _installer_source()
    fragment = src[src.index(GUARD_BEGIN) : src.index(GUARD_END)]
    assert CERT_SENTINEL in fragment, "guard must reference the incumbent cert path"
    cert_path = tmp_path / "executor.crt"
    if cert_bytes is not None:
        cert_path.write_bytes(cert_bytes)
    script = tmp_path / "guard_cell.sh"
    body = (
        "set -euo pipefail\n"
        "EXECUTOR_ID=venya-exec-cell\n"
        "error() { echo \"[ERROR] $*\"; }\n"
        + fragment.replace(CERT_SENTINEL, f'"{cert_path}"')
    )
    script.write_text(body, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "VENYA_EXECUTOR_ENROLLMENT_TOKEN"}
    if token is not None:
        env["VENYA_EXECUTOR_ENROLLMENT_TOKEN"] = token
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class TestFreshInstallFailFast:
    def test_unset_token_aborts_with_named_knob(self, tmp_path):
        """Fresh + unset token -> rc=1, message names the knob (negative half)."""
        proc = _run_guard(tmp_path, None, None)
        assert proc.returncode == 1
        assert "VENYA_EXECUTOR_ENROLLMENT_TOKEN is required" in proc.stdout
        assert "venya admin executor-enroll" in proc.stdout

    def test_empty_token_aborts(self, tmp_path):
        """Fresh + set-but-empty token (the $(cat /missing/path) class) -> rc=1."""
        proc = _run_guard(tmp_path, "", None)
        assert proc.returncode == 1
        assert "VENYA_EXECUTOR_ENROLLMENT_TOKEN is required" in proc.stdout

    def test_zero_byte_cert_still_counts_fresh(self, tmp_path):
        """Empty incumbent file is not a certificate (-s guard, paired negative)."""
        proc = _run_guard(tmp_path, "", b"")
        assert proc.returncode == 1

    def test_valid_token_proceeds(self, tmp_path):
        """Fresh + set token -> rc=0, no error output (positive half)."""
        proc = _run_guard(tmp_path, "tok-abc", None)
        assert proc.returncode == 0
        assert "[ERROR]" not in proc.stdout


class TestRerunPathUnchanged:
    def test_existing_cert_no_token_proceeds(self, tmp_path):
        """Re-run with incumbent cert and no token -> guard passes (AC 3)."""
        proc = _run_guard(tmp_path, None, b"stub-cert")
        assert proc.returncode == 0
        assert "[ERROR]" not in proc.stdout


class TestSourceOrderPins:
    def test_guard_precedes_every_system_write(self):
        """The guard sits with the SERVER_URL Require block — before apt,
        venv creation, and executor.toml writes."""
        src = _installer_source()
        guard = src.index(GUARD_BEGIN)
        for write_marker in ("venya_apt install", "} > /etc/venya/executor.toml"):
            assert guard < src.index(write_marker), f"guard must precede {write_marker!r}"

    def test_rerun_message_names_the_incumbent_cert(self):
        """Paired positive: the register section explains the tokenless
        re-run instead of warning about a doomed daemon."""
        src = _installer_source()
        assert "Existing executor certificate found" in src
