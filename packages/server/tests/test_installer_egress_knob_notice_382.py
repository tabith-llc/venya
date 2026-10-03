# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Source-pin: #382 core egress-knob ignored-knob notice (warn-only, shape (a)).

VENYA_EGRESS_ALLOW seeds the EXECUTOR installer's egress allowlist; the core
installer consumed it silently (dropped it with zero feedback). The fix is a
one-line warn in the core env-validation cluster before the first mutation.
Truth-table halves: the warn must exist and sit in the right place (P1-P3);
core must NEVER call venya_write_egress_allowlist (if it ever grows a call the
notice becomes a lie and this suite fails LOUD — N1) and the executor seed
path stays exactly one call with no core-style warn (N2).
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]

_MARKER = "VENYA_EGRESS_ALLOW applies to the executor installer only — " "ignoring on core."
_GUARD = 'if [ -n "${VENYA_EGRESS_ALLOW:-}" ]; then'
_LAST_GUARD = 'venya_guard_injection "VENYA_RECOVERY_PEPPER"'
_FIRST_MUTATION = "venya_create_user"
_WRITE_FN = "venya_write_egress_allowlist"


class TestInstallerEgressKnobNotice382:
    def test_p1_marker_present_once(self):
        core = (_ROOT / "install-venya-core.sh").read_text()
        assert core.count(_MARKER) == 1

    def test_p2_placement_in_env_cluster_before_first_mutation(self):
        core = (_ROOT / "install-venya-core.sh").read_text()
        assert core.index(_LAST_GUARD) < core.index(_MARKER) < core.index(_FIRST_MUTATION)

    def test_p3_guard_form_is_unset_safe(self):
        core = (_ROOT / "install-venya-core.sh").read_text()
        assert _GUARD in core

    def test_n1_core_never_consumes_egress_writer(self):
        core = (_ROOT / "install-venya-core.sh").read_text()
        calls = [line for line in core.splitlines() if _WRITE_FN in line and not line.lstrip().startswith("#")]
        assert calls == []

    def test_n2_executor_seed_path_untouched(self):
        executor = (_ROOT / "install-venya-executor.sh").read_text()
        assert executor.count(_WRITE_FN) == 1
        assert executor.count(_MARKER) == 0
