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

import re
from pathlib import Path
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


class TestAllFourSitesAgree:
    """The pairing, at the width the release line actually has.

    Four creates name a sandbox on this product: the boot probe and the workload create in
    this module, the install-time shape record's probe in ``sandbox_shape``, and the
    installer's template warm in ``install-venya-executor.sh``. Reusing the INNER probe argv
    does not make two different outer creates the same face, so this class compares all four
    against the one declaration. The installer is read as text on purpose: a shell script
    cannot import a Python constant, so its side of the invariant is a named variable and the
    only instrument that can hold it is a cell that parses it.
    """

    INSTALLER = Path(__file__).resolve().parents[3] / "install-venya-executor.sh"

    def _create_argv_from_shape_record(self, monkeypatch, tmp_path) -> list[str]:
        from executor import sandbox_shape as ss

        seen: list[list[str]] = []

        def fake_run(argv, timeout=None):
            seen.append(list(argv))
            if argv[1] == "create":
                return 0, "", ""
            return 0, "agent\n", ""

        # WORKSPACE_BASE is imported by name inside the function, so the module that owns it
        # is the one to patch — patching sandbox_shape would leave the real path in play.
        monkeypatch.setattr(ss, "run_instrument", fake_run)
        from executor.strategies import sbx_strategy as st

        monkeypatch.setattr(st, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        ss._sandbox_view(512)
        return next(a for a in seen if a[1] == "create")

    def test_shape_record_site_names_the_declaration(self, monkeypatch, tmp_path):
        argv = self._create_argv_from_shape_record(monkeypatch, tmp_path)
        assert _template_token(argv) == sbx.SANDBOX_TEMPLATE, f"the shape record created {argv!r}"

    def test_installer_warm_site_names_the_declaration(self):
        """The fourth site, parsed rather than trusted. Regex is on the assignment, so a
        renamed or deleted variable reddens this cell instead of quietly diverging."""
        text = self.INSTALLER.read_text(encoding="utf-8")
        found = re.findall(r'^\s*SBX_SANDBOX_TEMPLATE="([^"]+)"', text, re.MULTILINE)
        assert len(found) == 1, f"expected exactly one SBX_SANDBOX_TEMPLATE assignment, found {found!r}"
        assert found[0] == sbx.SANDBOX_TEMPLATE, (
            f"the installer warms {found[0]!r} but the executor creates {sbx.SANDBOX_TEMPLATE!r}; "
            "the record and the guard would then describe different sandboxes"
        )

    def test_installer_warm_create_actually_uses_the_variable(self):
        text = self.INSTALLER.read_text(encoding="utf-8")
        warm = [ln for ln in text.splitlines() if 'sbx create --name "$WARM_SANDBOX"' in ln]
        assert len(warm) == 1, f"expected one warm create, found {len(warm)}"
        assert '-t "$SBX_SANDBOX_TEMPLATE"' in warm[0], warm[0]

    def test_every_installer_create_line_reads_the_variable(self):
        """BOTH reads, and the COUNT, so this cannot rot quietly.

        The installer declares the template once and reads it twice: the warm it executes, and
        the `Manual warm:` remedy it PRINTS for an operator to copy after the automated warm has
        already failed — the moment a wrong flavour costs a cold pull inside the timeout chain.
        Selecting installer lines by the executed form's own substring cannot see the printed
        one, so a deleted token there stayed green (measured at leg 1351). Select by shape
        instead, then pin how many shapes exist: a third create line cannot be silently
        un-listed and a deleted read cannot be silently un-paired.

        The quote forms differ and that is the trap: the printed line lives inside a
        double-quoted `warn` string, so in the file bytes its quotes are escaped
        (`-t \"$SBX_SANDBOX_TEMPLATE\"`), while the executed line carries plain quotes. A naive
        `'-t "$SBX_SANDBOX_TEMPLATE"' in ln` reads False on the good printed line, which would make
        this cell red on correct bytes, so the selector matches the flag and the variable name and
        lets whatever quote characters sit between them be whatever they are.
        """
        text = self.INSTALLER.read_text(encoding="utf-8")
        creates = [
            ln for ln in text.splitlines() if re.search(r"\bsbx\s+create\b", ln) and not ln.lstrip().startswith("#")
        ]
        assert len(creates) == 2, (
            f"expected exactly 2 installer create lines (the executed warm and the printed "
            f"remedy), found {len(creates)}: {[ln.strip()[:70] for ln in creates]}"
        )
        # The character class allows the quote forms both sites use: the executed line has plain
        # quotes, and the printed remedy sits inside a double-quoted `warn` string, so in the file
        # bytes its quotes are escaped. A naive '-t "$SBX_SANDBOX_TEMPLATE"' substring reads False
        # on those correct bytes, which would make this cell red on a healthy installer.
        reads_it = re.compile(r"-t\s+[\"\\']*\$SBX_SANDBOX_TEMPLATE")
        unpaired = [ln.strip()[:90] for ln in creates if not reads_it.search(ln)]
        assert not unpaired, (
            f"installer create lines that do not read the declaration: {unpaired} — one declaration, "
            "every create reads it, including the line an operator copies by hand"
        )

    def test_all_four_sites_are_one_value(self, monkeypatch, tmp_path):
        """THE PAIRING CELL. If any one of the four sites moves alone, this is red — which is
        the failure mode that survived a two-site PASS on leg 1343."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        probe_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(probe_calls, "agent\n")):
            sbx.require_runtime_isolated_sandbox(memory_mb=512)
        work_calls: list = []
        with patch.object(sbx.subprocess, "run", _run_recorder(work_calls, "")):
            sbx.SbxStrategy(sandbox_memory_mb=512).create_sandbox("venya-1350", "/workspace")
        shape_argv = self._create_argv_from_shape_record(monkeypatch, tmp_path)
        installer_text = self.INSTALLER.read_text(encoding="utf-8")
        installer_ref = re.findall(r'^\s*SBX_SANDBOX_TEMPLATE="([^"]+)"', installer_text, re.MULTILINE)

        faces = {
            "boot probe": _template_token(next(c for c in probe_calls if c[1] == "create")),
            "workload create": _template_token(next(c for c in work_calls if c[1] == "create")),
            "shape record": _template_token(shape_argv),
            "installer warm": installer_ref[0] if installer_ref else None,
        }
        assert all(v is not None for v in faces.values()), f"a site names no template: {faces}"
        assert set(faces.values()) == {sbx.SANDBOX_TEMPLATE}, (
            f"the four creates disagree: {faces} — a boot that passes would be describing a "
            "sandbox some other site never creates"
        )
