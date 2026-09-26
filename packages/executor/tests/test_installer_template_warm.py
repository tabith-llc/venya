# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: the executor installer warms the sbx agent template at install time.

Ticket sbx-cold-start-prepull (owner order 2026-09-26): the first relayed
command on a fresh executor must not carry the multi-GiB template pull
(cold 60-90 s vs warm ~5 s). Pins the warm block's load-bearing properties:
throwaway create+rm pair (the executor's own sbx surface), the degraded-install
skip gate, non-fatal warn-and-continue, and the F7 prerequisite ORDER (warm
strictly after the deny-all policy init, which is after Docker auth).
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = (REPO_ROOT / "install-venya-executor.sh").read_text()


def test_installer_warms_agent_template() -> None:
    # Throwaway create+rm pair on the executor's own sbx surface.
    assert 'WARM_SANDBOX="venya-install-warm"' in INSTALLER
    assert 'sbx create --name "$WARM_SANDBOX" shell "$WARM_WS"' in INSTALLER
    assert 'sbx rm --force "$WARM_SANDBOX"' in INSTALLER
    # The workspace must pre-exist (sbx create prompts on a missing dir and
    # dies on non-TTY EOF) — pin the mktemp-into-workspaces-base pattern.
    assert "mktemp -d /home/venya/.venya-workspaces/warm." in INSTALLER


def test_installer_template_warm_is_gated_and_nonfatal() -> None:
    # Paired negative: the degraded no-auth install must NOT attempt the pull.
    assert "Skipping agent-template warm (VENYA_SKIP_DOCKER_LOGIN=yes" in INSTALLER
    # Failure warns and continues — never `error`+exit for the warm itself.
    assert "Agent-template warm FAILED" in INSTALLER


def test_installer_template_warm_runs_after_policy_init() -> None:
    # F7 prerequisite order: Docker auth -> sandboxd -> deny-all policy -> warm.
    assert INSTALLER.index("sbx policy init deny-all") < INSTALLER.index("WARM_SANDBOX=")
    # And inside the sbx-prereq region (before the network/hostname section).
    assert INSTALLER.index("WARM_SANDBOX=") < INSTALLER.index("Resolve Core Hostname")
