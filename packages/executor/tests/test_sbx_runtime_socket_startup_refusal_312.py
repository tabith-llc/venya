# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#312 item 3a — the executor refuses to boot a sandbox that can reach a
container runtime.

The face this pins is the estate's, measured 2026-11-12 and reported in
`reports/312`: inside a sandbox this executor creates, `id -Gn` answers
`agent sudo docker` and `/var/run/docker.sock` is present, group-writable, and
owned `root docker`. `create_sandbox` passes no group, user, socket or capability
flag, so venya neither adds the exposure nor can remove it — what it can do is
stop asserting isolation it has not checked. These cells are that refusal: what
the probe asks, what a yes costs, what cleanup still runs, and that a boot that
refuses never reaches registration.

No cell here touches a real sandbox, a real guest, or an estate box: every sbx
call is a patched `subprocess.run` in this process, per `R-2911`.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import ExecutorDaemon
from executor.strategies import sbx_strategy as sbx


@pytest.fixture
def config(tmp_path: Path) -> ExecutorConfig:
    return ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        dns_resolver="192.0.2.53",
        relay_client_ids=["core-relay"],
        mtls=MtlsConfig(
            ca_cert=str(tmp_path / "ca.crt"),
            cert=str(tmp_path / "executor.crt"),
            key=str(tmp_path / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(rotate_before_days=3),
    )


def _daemon(config) -> ExecutorDaemon:
    d = ExecutorDaemon(config)
    d.cert_manager = MagicMock()
    d.reaper = MagicMock()
    return d


EXPOSED_STDOUT = "agent sudo docker\nVENYA_RT W /var/run/docker.sock\n"
SOCKET_PRESENT_NOT_WRITABLE = "agent\nVENYA_RT P /var/run/docker.sock\n"
CLEAN_STDOUT = "agent\n"
CREATED = "docker: created"


def fake_sbx(
    calls: list,
    *,
    probe_stdout: str | None = CLEAN_STDOUT,
    create_rc: int = 0,
    create_stderr: str = "",
    exec_exc: Exception | None = None,
) -> callable:
    """A stand-in `subprocess.run` for the three sbx verbs the probe uses."""

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        res.stdout = ""
        res.stderr = ""
        verb = cmd[1] if len(cmd) > 1 else ""
        if verb == "create":
            res.returncode = create_rc
            res.stderr = create_stderr
        elif verb == "exec":
            if exec_exc is not None:
                raise exec_exc
            if probe_stdout is None:
                raise AssertionError("exec ran although create failed")
            res.stdout = probe_stdout
        return res

    return run


class TestProbeCommand:
    """What the guard asks the sandbox. The question is legible on purpose."""

    def test_probe_asks_about_every_runtime_socket_path(self):
        joined = " ".join(sbx.rt_probe_argv())
        for path in sbx.RUNTIME_SOCKET_PATHS:
            assert path in joined, f"{path} is not asked about"
        assert "id -Gn" in joined  # the group face, for the wording of a refusal
        assert sbx._RT_TAG in joined

    def test_probe_is_read_only_by_construction(self):
        """`sh -c` over `id` and four file tests — no write, no network, and
        nothing that could consume an enrollment or alter sandbox state."""
        argv = sbx.rt_probe_argv()
        assert argv[0] == "sh" and argv[1] == "-c"
        body = argv[2]
        for forbidden in ("rm ", "mkdir", "curl", "wget", "echo >", "docker "):
            assert forbidden not in body, f"probe body contains {forbidden!r}"
        assert body.count("id -Gn") == 1

    def test_probe_timeout_default_and_env_override(self, monkeypatch):
        monkeypatch.delenv("VENYA_SBX_RT_PROBE_TIMEOUT", raising=False)
        assert sbx.rt_probe_timeout() == sbx.SBX_RT_PROBE_TIMEOUT
        monkeypatch.setenv("VENYA_SBX_RT_PROBE_TIMEOUT", "5")
        assert sbx.rt_probe_timeout() == 5.0
        # A typo or a zero must never read as "skip the check".
        for bad in ("0", "-3", "banana", ""):
            monkeypatch.setenv("VENYA_SBX_RT_PROBE_TIMEOUT", bad)
            assert sbx.rt_probe_timeout() == sbx.SBX_RT_PROBE_TIMEOUT


class TestProbeParsing:
    def test_writable_socket_is_exposure(self):
        parsed = sbx.parse_runtime_probe(EXPOSED_STDOUT)
        assert parsed.exposed is True
        assert parsed.writable == ["/var/run/docker.sock"]
        assert parsed.groups == ["agent", "sudo", "docker"]

    def test_socket_present_but_not_writable_is_not_exposure(self):
        parsed = sbx.parse_runtime_probe(SOCKET_PRESENT_NOT_WRITABLE)
        assert parsed.exposed is False
        assert parsed.present == ["/var/run/docker.sock"]
        assert parsed.writable == []

    def test_clean_sandbox_parses_clean(self):
        parsed = sbx.parse_runtime_probe(CLEAN_STDOUT)
        assert parsed.exposed is False
        assert parsed.writable == [] and parsed.present == []
        assert parsed.groups == ["agent"]

    def test_numeric_gid_line_is_parseable_and_still_not_the_test(self):
        """An image with no /etc/group names prints numbers. GIDs are
        site-specific (this estate's docker group is 1001, most images carry
        999), so the criterion stays `-w` inside the sandbox, never a number."""
        parsed = sbx.parse_runtime_probe("1000 27 1001\n")
        assert parsed.exposed is False
        assert parsed.groups == ["1000", "27", "1001"]

    def test_silence_is_not_proof_of_isolation(self):
        with pytest.raises(sbx.SbxRuntimeExposureError):
            sbx.parse_runtime_probe("")

    def test_unexpected_output_is_a_refusal_not_a_pass(self):
        with pytest.raises(sbx.SbxRuntimeExposureError):
            sbx.parse_runtime_probe("agent\nsomething else entirely $$\nVENYA_RT W /x\n")


class TestRequireRuntimeIsolatedSandbox:
    def test_refuses_and_names_the_socket_and_the_owner_of_the_fix(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", fake_sbx(calls, probe_stdout=EXPOSED_STDOUT)):
            with pytest.raises(sbx.SbxRuntimeExposureError) as exc:
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        msg = str(exc.value)
        assert "/var/run/docker.sock" in msg
        assert "docker-sbx" in msg  # who has to change, named
        assert "refs #312" in msg
        # Honest claim boundary: a reachable runtime is the finding; a proven
        # host escape is not, and the guard must not assert one.
        assert "escape" not in msg.lower()
        assert "another container" in msg

    def test_probe_sandbox_is_removed_after_a_refusal(self, tmp_path, monkeypatch):
        """A refusal must not leave a live sandbox holding the probe's workspace."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", fake_sbx(calls, probe_stdout=EXPOSED_STDOUT)):
            with pytest.raises(sbx.SbxRuntimeExposureError):
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        removed = [c for c in calls if c[:2] == ["sbx", "rm"]]
        assert removed, f"no sbx rm among {calls}"
        assert removed[0][:3] == ["sbx", "rm", "--force"]
        assert removed[0][3].startswith("venya-rt-probe-")
        assert list((tmp_path / "wsbase").iterdir()) == []  # workspace collected too

    def test_passes_when_the_socket_is_not_writable(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(sbx.subprocess, "run", fake_sbx(calls, probe_stdout=SOCKET_PRESENT_NOT_WRITABLE)):
            face = sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "not writable" in face
        assert [c[1] for c in calls] == ["create", "exec", "rm"]

    def test_failed_create_refuses_without_execing(self, tmp_path, monkeypatch):
        """An unanswerable question is not an answer: no create, no exec, no rm
        of a sandbox that never existed."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(
            sbx.subprocess,
            "run",
            fake_sbx(calls, create_rc=125, create_stderr="no such image: shell"),
        ):
            with pytest.raises(sbx.SbxRuntimeExposureError) as exc:
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "rc=125" in str(exc.value)
        assert [c[1] for c in calls] == ["create"]
        assert list((tmp_path / "wsbase").iterdir()) == []

    def test_create_timeout_refuses_and_names_the_knob(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            raise subprocess.TimeoutExpired(cmd, 60)

        with patch.object(sbx.subprocess, "run", run):
            with pytest.raises(sbx.SbxRuntimeExposureError) as exc:
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "VENYA_SBX_RT_PROBE_TIMEOUT" in str(exc.value)

    def test_missing_sbx_cli_refuses_rather_than_passes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            raise OSError("no sbx")

        with patch.object(sbx.subprocess, "run", run):
            with pytest.raises(sbx.SbxRuntimeExposureError) as exc:
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "docker-sbx" in str(exc.value)
        assert [c[1] for c in calls] == ["create"]  # one attempt, and no exec after it

    def test_exec_timeout_refuses_after_creating(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        with patch.object(
            sbx.subprocess,
            "run",
            fake_sbx(calls, exec_exc=subprocess.TimeoutExpired(["sbx", "exec"], 60)),
        ):
            with pytest.raises(sbx.SbxRuntimeExposureError):
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert [c[1] for c in calls] == ["create", "exec", "rm"]


class TestBootRefusalBeforeRegistration:
    """The guard is a BOOT guard: same position as the empty-allowlist and
    missing-resolver refusals, so a doomed executor never consumes the one-shot
    enrollment token (R-2910's own reasoning for the shape)."""

    def test_exposure_exits_one_before_registration(self, config):
        d = _daemon(config)
        with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
            with patch(
                "executor.daemon.require_runtime_isolated_sandbox",
                side_effect=sbx.SbxRuntimeExposureError("the sandbox can reach a runtime"),
            ):
                with pytest.raises(SystemExit) as exc:
                    d.start()
        assert exc.value.code == 1
        d.cert_manager.register.assert_not_called()  # one-shot token not consumed
        assert d.state.running is False

    def test_clean_probe_passes_the_guard(self, config):
        """Paired negative: the refusal fires on the exposed answer and ONLY on
        it — a clean probe walks on to registration."""
        d = _daemon(config)
        sentinel = RuntimeError("past-the-guard")
        d.cert_manager.register.side_effect = sentinel
        with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
            with patch(
                "executor.daemon.require_runtime_isolated_sandbox",
                return_value="no writable runtime socket in the sandbox view",
            ) as guard:
                with pytest.raises(RuntimeError) as exc:
                    d.start()
        assert exc.value is sentinel  # reached registration ⇒ guard passed
        assert guard.call_args.kwargs["memory_mb"] == config.sandbox_memory_mb

    def test_guard_runs_after_the_orphan_reap(self, config):
        """Ordering is load-bearing: the boot reap collects every `venya-*`
        sandbox as residue, so a probe sandbox created BEFORE that pass would be
        removed out from under the probe. Assert the observed call order."""
        d = _daemon(config)
        order: list = []
        sentinel = RuntimeError("past-the-guard")
        d.cert_manager.register.side_effect = sentinel
        with (
            patch("executor.daemon.require_supported_sbx", return_value="0.46.0"),
            patch(
                "executor.daemon.require_runtime_isolated_sandbox",
                side_effect=lambda **kw: order.append("probe") or "clean",
            ),
            patch("executor.daemon.reap_orphan_sandboxes", side_effect=lambda **kw: order.append("reap") or 0),
            patch("executor.daemon.sweep_workspace_base", side_effect=lambda **kw: order.append("sweep") or 0),
        ):
            with pytest.raises(RuntimeError):
                d.start()
        assert order == ["sweep", "reap", "probe"], order
