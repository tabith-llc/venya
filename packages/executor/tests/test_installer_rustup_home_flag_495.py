# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Home-flag pin: the executor installer's rustup bootstrap runs with -H.

Regression guard for ticket #495 (`rustup-sudo-missing-home-flag`): the
cargo-missing guard bootstraps Rust via `sudo -u venya` with no `-H`, so
rustup installed into the invoking user's home and the guard's own check
(`SU_CARGO=/home/venya/.cargo/bin/cargo`) could never see it. The fix adds `-H`
so HOME resolves to /home/venya and the install lands where the guard looks.

House precedent for the flag is already in-tree: venya-common.sh:280
(`venya_install_uv_user`) and install-venya-executor.sh (the uv step) both use
`sudo -H -u venya`.

Static source pins (house pattern: test_installer_docker_gate_order):
  POSITIVE:  the rustup bootstrap invocation carries `sudo -H -u venya`;
  NEGATIVE:  no `sudo -u venya … rustup …` form WITHOUT `-H` remains.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

RUSTUP_INVOCATION = "sudo -H -u venya bash -c \"curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_rustup_bootstrap_carries_home_flag():
    """POSITIVE: the cargo-missing guard invokes rustup as venya WITH -H."""
    src = _source()
    assert RUSTUP_INVOCATION in src, (
        "rustup bootstrap must run `sudo -H -u venya` so the install lands in " "/home/venya/.cargo (#495)"
    )


def test_no_rustup_bootstrap_without_home_flag():
    """PAIRED NEGATIVE: no rustup bootstrap invoking venya WITHOUT -H remains.

    A bare `sudo -u venya` leaves HOME on the invoking user, so rustup would
    write into the wrong home again — exactly the #495 defect.
    """
    src = _source()
    # Any sudo targeting venya that reaches a rustup.rs bootstrap on the same
    # line, where the sudo form is NOT `sudo -H -u venya`.
    bad = re.search(
        r"sudo(?!\s+-H)\s+-u\s+venya[^\n]*sh\.rustup\.rs",
        src,
    )
    assert bad is None, f"rustup bootstrap without -H remains (#495): {bad.group(0)!r}"
