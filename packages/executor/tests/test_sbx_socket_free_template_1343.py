# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#312 — both `sbx create` sites name the same sandbox template, by image name.

The vendor resolves a bare agent name to a flavour of its choosing, and the flavour it
chooses for `shell` mounts a container-runtime socket that the boot probe then refuses.
Naming the template at the create sites takes that choice back. The property that makes
this a control rather than a green light is that BOTH sites read ONE declaration: the
sandbox the guard measures has to be the sandbox a workload gets, or a passing probe
describes a shape that nothing on the machine ever runs.

These cells hold that pairing. Nothing here creates a sandbox: every `sbx` verb is a
patched `subprocess.run` in this process, per `R-2911`.
"""

from unittest.mock import MagicMock, patch

import pytest

from executor.strategies import sbx_strategy as sbx

TEMPLATE = "docker.io/docker/sandbox-templates:shell"


def _run_recorder(calls: list, probe_stdout: str) -> callable:
    def run(cmd, **kwargs):
        calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        res.stdout = probe_stdout
        res.stderr = ""
        return res

    return run


def _template_token(argv: list[str]) -> str | None:
    """The image reference this create argv asks for, or None if it asks for none."""
    if "-t" not in argv:
        return None
    return argv[argv.index("-t") + 1]


class TestBothSitesNameTheTemplate:
    def test_probe_site_names_the_declared_template(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(calls, "agent\n")):
            sbx.require_runtime_isolated_sandbox(memory_mb=512)
        create = next(c for c in calls if c[1] == "create")
        assert _template_token(create) == TEMPLATE, f"the probe created {create!r}"

    def test_workload_site_names_the_declared_template(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        strategy = sbx.SbxStrategy(sandbox_memory_mb=512)
        with patch.object(sbx.subprocess, "run", _run_recorder(calls, "")):
            strategy.create_sandbox("venya-1343", "/workspace")
        create = next(c for c in calls if c[1] == "create")
        assert _template_token(create) == TEMPLATE, f"the workload created {create!r}"

    def test_declaration_is_the_single_source_at_both_sites(self, tmp_path, monkeypatch):
        """The pairing, asserted as ONE value: whatever the module declares is what BOTH
        argvs carry, so a future edit to the declaration moves the probe and the workload
        together and cannot move one alone."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        assert sbx.SANDBOX_TEMPLATE == TEMPLATE
        probe_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(probe_calls, "agent\n")):
            sbx.require_runtime_isolated_sandbox(memory_mb=512)
        probe_argv = next(c for c in probe_calls if c[1] == "create")

        work_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(work_calls, "")):
            sbx.SbxStrategy(sandbox_memory_mb=512).create_sandbox("venya-1343", "/workspace")
        work_argv = next(c for c in work_calls if c[1] == "create")

        assert _template_token(probe_argv) == _template_token(work_argv) == sbx.SANDBOX_TEMPLATE

    def test_drift_cell_the_pairing_fails_when_one_site_moves(self, tmp_path, monkeypatch):
        """PAIRED NEGATIVE, and the reason this file exists: if a later edit re-points one
        site and not the other, the guard would go green on a shape production never
        creates. This cell asserts the two sites agree, so a split is red here first.

        Proven red at the pen by hard-coding the workload site to the socket-mounting
        flavour and watching exactly this cell fail, then reverting it in the same act.
        """
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        probe_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(probe_calls, "agent\n")):
            sbx.require_runtime_isolated_sandbox(memory_mb=512)
        work_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(work_calls, "")):
            sbx.SbxStrategy(sandbox_memory_mb=512).create_sandbox("venya-1343", "/workspace")

        probe_t = _template_token(next(c for c in probe_calls if c[1] == "create"))
        work_t = _template_token(next(c for c in work_calls if c[1] == "create"))
        assert probe_t is not None and work_t is not None, "a create site names no template"
        assert probe_t == work_t, (
            f"the probe measures {probe_t!r} but the workload runs {work_t!r}; a passing "
            "boot guard would be describing a sandbox this executor never creates"
        )

    def test_image_is_named_not_pinned(self):
        """`R-2927` cl.1: the shape is verified at runtime by the probe, not asserted by a
        digest this code cannot check. A digest form in the declaration is out of posture."""
        assert "@" not in sbx.SANDBOX_TEMPLATE, "a digest pin appeared where a name belongs"
        assert sbx.SANDBOX_TEMPLATE.startswith("docker.io/"), "the name lost its registry"


class TestGuardUntouched:
    """The criterion did not move while the template did: same probe, same answer, same raise."""

    def test_probe_question_still_asks_every_socket_path(self):
        joined = " ".join(sbx.rt_probe_argv())
        for path in sbx.RUNTIME_SOCKET_PATHS:
            assert path in joined, f"{path} is no longer asked about"

    def test_a_writable_socket_still_refuses_at_this_template(self, tmp_path, monkeypatch):
        exposed = "agent sudo docker\nVENYA_RT W /var/run/docker.sock\n"
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(calls, exposed)):
            with pytest.raises(sbx.SbxRuntimeExposureError):
                sbx.require_runtime_isolated_sandbox(memory_mb=512)

    def test_a_socket_free_face_still_passes_and_says_so(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(calls, "agent\n")):
            face = sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "no writable runtime socket" in face
        assert [c[1] for c in calls] == ["create", "exec", "rm"]
