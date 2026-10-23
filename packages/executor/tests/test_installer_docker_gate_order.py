# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Ordering interlock: the executor installer enrolls BEFORE the Docker gate.

Regression guard for ticket executor-docker-gate-before-enrollment (#337-family
findings train, ruled A 2026-10-02): the Docker-auth abort used to fire before
the CSR/enrollment step, so an operator without Docker Hub creds could not even
land a certificate/identity — the (unconsumed) token sat until its 1800 s TTL
expired. Now the whole Docker chain (auth gate, sandboxd, network policy,
template warm) runs AFTER the register section, so cert/identity lands first
and a docker-degraded abort only costs the optional runtime.

Static source-order pins (house pattern: test_installer_no_private_literals):
  1. the "Docker credentials are required" abort appears AFTER the
     "Register mTLS certificate" section header;
  2. sandboxd/policy/warm headers likewise appear after the register header;
  3. the documented degraded knob still names itself in the same block.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = REPO_ROOT / "install-venya-executor.sh"

REGISTER_MARKER = "# --- Register mTLS certificate"
DOCKER_ABORT_MARKER = "Docker credentials are required for sandbox execution."
SANDBOXD_MARKER = "# --- sandboxd daemon"
POLICY_MARKER = "# --- sbx global network policy"
WARM_MARKER = "# --- sbx agent-template warm"
SKIP_KNOB_MARKER = "VENYA_SKIP_DOCKER_LOGIN=yes"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_docker_abort_now_follows_enrollment():
    src = _source()
    reg = src.index(REGISTER_MARKER)
    abort = src.index(DOCKER_ABORT_MARKER)
    assert abort > reg, "Docker-auth abort must be sequenced after the enrollment section (#363)"


def test_docker_runtime_chain_follows_enrollment():
    src = _source()
    reg = src.index(REGISTER_MARKER)
    for marker in (SANDBOXD_MARKER, POLICY_MARKER, WARM_MARKER):
        assert src.index(marker) > reg, f"{marker!r} must run after enrollment (#363)"


def test_degraded_knob_still_named_at_the_gate():
    """Paired negative: the skip knob keeps its documented degraded contract
    (moved with the block, wording reachable in the same section)."""
    src = _source()
    abort = src.index(DOCKER_ABORT_MARKER)
    assert SKIP_KNOB_MARKER in src[abort : abort + 1200]


HARDEN_MARKER = "# --- Harden executor credentials"


def test_harden_precedes_docker_gate():
    """#370: credential hardening must run BEFORE the Docker-auth gate — an
    abort at the creds gate has already registered + created
    /etc/venya/executor; if hardening followed, the keys stay root-owned and
    the daemon crash-loops until a completing re-run."""
    src = _source()
    harden = src.index(HARDEN_MARKER)
    abort = src.index(DOCKER_ABORT_MARKER)
    assert harden < abort, "harden block must precede the Docker-creds gate (#370)"
    # ...and still after enrollment, so the certs exist when it runs (#363 holds)
    assert harden > src.index(REGISTER_MARKER), "harden must run after registration (#363)"
