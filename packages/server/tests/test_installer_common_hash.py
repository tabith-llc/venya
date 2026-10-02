# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: piped installs VERIFY venya-common.sh before sourcing it (#360).

ticket installer-common-self-fetch-unhashed (ruled A 2026-10-02): every fetch-
and-source of the shared library must check a sha256 — the serve-time embedded
placeholder (sed-filled by create-tarball-and-serve.sh), the operator pin
VENYA_COMMON_SHA256, or the origin sidecar — and FAIL CLOSED when none is
obtainable. Root-sourcing an unverified script is the self-attestation class
the tarball path already closed (venya-common.sh guard).

Static source pins (house pattern: test_installer_dir_pins / docker gate order):
each install script must (a) carry the placeholder, (b) abort on mismatch,
(c) abort when no expectation is resolvable, and (d) perform ALL of it before
the `source` of the fetched file.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLERS = (
    "install-venya-core.sh",
    "install-venya-executor.sh",
    "install-venya-cli.sh",
)

PLACEHOLDER = "__VENYA_COMMON_SHA256__"


def _fetch_region(name: str) -> str:
    src = (REPO_ROOT / name).read_text(encoding="utf-8")
    m = re.search(r"Fetching shared installer library.*?source \"\$FETCH_DIR/venya-common\.sh\"", src, re.DOTALL)
    assert m, f"{name}: fetch-and-source block not found"
    return m.group(0)


def test_every_installer_carries_the_embed_placeholder() -> None:
    for name in INSTALLERS:
        assert PLACEHOLDER in (REPO_ROOT / name).read_text(encoding="utf-8"), name


def test_verification_precedes_source_in_every_installer() -> None:
    for name in INSTALLERS:
        region = _fetch_region(name)
        assert "sha256sum" in region, f"{name}: no sha256 computation before source"
        assert "MISMATCH" in region, f"{name}: no mismatch abort before source"
        assert "VENYA_COMMON_SHA256" in region, f"{name}: operator pin not honored"
        assert region.index("sha256sum") < region.index('source "$FETCH_DIR/venya-common.sh"')


def test_fail_closed_without_any_expectation() -> None:
    """Negative half: no embedded hash AND no sidecar reachable -> abort, never
    source (mirror of the tarball guard's fail-closed semantics)."""
    for name in INSTALLERS:
        region = _fetch_region(name)
        assert "refusing to source" in region.lower(), f"{name}: not fail-closed on missing expectation"
