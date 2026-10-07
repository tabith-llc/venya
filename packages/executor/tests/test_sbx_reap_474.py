# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket sandbox-residue-unreaped-after-teardown-failure (#474).

Pre-fix: the ruled #417 teardown swallow logged a failed ``sbx rm`` and moved
on, and the daemon's boot sweep (``sweep_workspace_base``) reclaimed
DIRECTORIES only — so a secrets-bearing microVM whose teardown failed (or that
outlived a killed daemon) was visible to no reaper at all, for the life of the
host.

Fix pinned here (static leg — the physical ``sbx`` cells are DO-NOT-RUN in this
venue, which carries no sandbox CLI; the design is in the leg report):
1. a reap pass for LIVE SANDBOXES exists — enumerate ``venya-*`` sandboxes and
   remove the ones with no live owning session;
2. it runs at daemon boot (before the relay listener can accept a command, so
   nothing a previous run left can be mistaken for live) and on the
   failed-teardown path;
3. OWNERSHIP KEY: sandbox name -> owning execution session, claimed in
   ``create_sandbox`` and released only by a successful ``sbx rm``
   (``sbx ls``/``sbx rm`` are the vendor CLI, timeout-bounded);
4. #417's swallow-and-log behavior is preserved verbatim — the reaper is armed
   INSIDE the except branch, so the origin exception still surfaces.

Paired negatives: a sandbox belonging to a live session is never reaped (the
ownership check is proven, not assumed), a successful teardown collects
nothing, and an unavailable/failing/fresh CLI never aborts a boot.
"""

import logging
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import Executor
from executor.strategies import sbx_strategy as sbx
from executor.strategies.sbx_strategy import SbxStrategy

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_ORIGIN = "venya-6f6c6f72-6574776f-ab12cd34ef56-0000aa"  # a live session's VM
_RESIDUE = "venya-6f6c6f72-6574776f-ffffffff0000-112233"  # left by a dead run


def _completed(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["sbx"], returncode=rc, stdout=stdout, stderr=stderr)


def _ls_rm_run(live=_RESIDUE, rm_rc=0):
    """subprocess.run double: `sbx ls` lists ``live``, `sbx rm` returns ``rm_rc``."""

    def _run(cmd, *a, **kw):
        if cmd[:2] == ["sbx", "ls"]:
            return _completed(stdout=f"{live}\n")
        if cmd[:3] == ["sbx", "rm", "--force"]:
            return _completed(rc=rm_rc, stderr="" if rm_rc == 0 else "sandboxd said no")
        raise AssertionError(f"unexpected command in reap test: {cmd!r}")

    return _run


@pytest.fixture(autouse=True)
def _clean_registry():
    """The ownership registry is process-global (one daemon per host); keep
    each cell hermetic."""
    sbx.clear_live_sandboxes()
    yield
    sbx.clear_live_sandboxes()


# ---------------------------------------------------------------------------
# AC1 — the reap pass exists: enumerate, keep the owned, collect the rest
# ---------------------------------------------------------------------------


class TestReapPass:
    def test_reap_removes_unowned_and_keeps_owned(self, caplog):
        """Positive: residue with no owning session is collected."""
        sbx.register_live_sandbox(_ORIGIN, "session-live")
        with patch.object(sbx.subprocess, "run", side_effect=_ls_rm_run()):
            with caplog.at_level(logging.INFO, logger="venya.executor.strategies.sbx"):
                collected = sbx.reap_orphan_sandboxes()

        assert collected == 1
        assert f"collected residue {_RESIDUE}" in caplog.text

    def test_paired_negative_live_session_sandbox_never_reaped(self):
        """AC3: ownership is PROVEN, not assumed — an owned name is skipped."""
        sbx.register_live_sandbox(_RESIDUE, "session-live")
        calls = []

        def _run(cmd, *a, **kw):
            calls.append(cmd)
            if cmd[:2] == ["sbx", "ls"]:
                return _completed(stdout=f"{_RESIDUE}\n")
            raise AssertionError("reap must not issue `sbx rm` for an owned sandbox")

        with patch.object(sbx.subprocess, "run", side_effect=_run):
            collected = sbx.reap_orphan_sandboxes()

        assert collected == 0
        assert [c[:2] for c in calls] == [["sbx", "ls"]]

    def test_reap_ignores_foreign_names(self):
        """Scope: only the `venya-` prefix is ever considered."""
        with patch.object(sbx.subprocess, "run", side_effect=_ls_rm_run(live="someone-elses-vm")):
            collected = sbx.reap_orphan_sandboxes()
        assert collected == 0

    def test_reap_passes_when_names_supplied_without_listing(self):
        """The failed-teardown arm reaps with the enumeration it is handed."""
        with patch.object(sbx.subprocess, "run", side_effect=_ls_rm_run()) as run:
            collected = sbx.reap_orphan_sandboxes(names=[_RESIDUE])
        assert collected == 1
        assert all(c.args[0][:2] == ["sbx", "rm"] for c in run.call_args_list)

    def test_reap_survives_rm_failure(self, caplog):
        """A removal that keeps failing is logged, never raised, never counted."""
        with patch.object(sbx.subprocess, "run", side_effect=_ls_rm_run(rm_rc=1)):
            with caplog.at_level(logging.WARNING, logger="venya.executor.strategies.sbx"):
                collected = sbx.reap_orphan_sandboxes()
        assert collected == 0
        assert "sbx rm" in caplog.text


class TestEnumerate:
    def test_parses_prefixed_tokens_across_layouts(self):
        """Layout-independent parse: whitespace tokens, `venya-` prefix only."""
        out = "NAME            STATE    IMAGE\nvenya-s-1-aaaa  running  shell\nno-sbx-here\n"
        with patch.object(sbx.subprocess, "run", return_value=_completed(stdout=out)):
            assert sbx.list_sandbox_names() == ["venya-s-1-aaaa"]

    def test_no_sandboxes_found_is_empty(self):
        with patch.object(sbx.subprocess, "run", return_value=_completed(stdout="No sandboxes found.\n")):
            assert sbx.list_sandbox_names() == []

    @pytest.mark.parametrize(
        "exc,label",
        [(FileNotFoundError("sbx"), "unavailable"), (subprocess.TimeoutExpired(["sbx", "ls"], 30), "timed out")],
    )
    def test_cli_problems_degrade_to_empty(self, exc, label, caplog):
        """A boot must not die over debris it came to clean."""
        with patch.object(sbx.subprocess, "run", side_effect=exc):
            with caplog.at_level(logging.WARNING, logger="venya.executor.strategies.sbx"):
                assert sbx.list_sandbox_names() == []
        assert "sandbox reap pass skipped" in caplog.text

    def test_nonzero_listing_exit_degrades_to_empty(self, caplog):
        with patch.object(
            sbx.subprocess, "run", return_value=_completed(rc=1, stderr="ERROR: Not authenticated to Docker")
        ):
            assert sbx.list_sandbox_names() == []
        assert "exited 1" in caplog.text


# ---------------------------------------------------------------------------
# Ownership key: claim at create, release only on a real removal
# ---------------------------------------------------------------------------


class TestOwnershipRegistry:
    def test_create_sandbox_claims_ownership(self):
        strategy = SbxStrategy()
        with patch.object(sbx.subprocess, "run", return_value=_completed(stdout="")), patch.object(
            strategy, "_copy_sshpass"
        ):
            strategy.create_sandbox(_ORIGIN, "/workspace", session_id="session-live")
        assert sbx.live_sandbox_names() == {_ORIGIN}

    def test_successful_removal_releases_the_claim(self):
        strategy = SbxStrategy()
        strategy._sandbox_name = _ORIGIN
        sbx.register_live_sandbox(_ORIGIN, "session-live")
        with patch.object(sbx.subprocess, "run", return_value=_completed(rc=0)):
            rc = strategy.remove_sandbox()
        assert rc == 0
        assert sbx.live_sandbox_names() == set()

    def test_failed_removal_keeps_the_claim_and_reports_rc(self, caplog):
        """The residue stays attributed to its live session; rc tells the
        caller the VM is still there."""
        strategy = SbxStrategy()
        strategy._sandbox_name = _ORIGIN
        sbx.register_live_sandbox(_ORIGIN, "session-live")
        with patch.object(sbx.subprocess, "run", return_value=_completed(rc=1, stderr="sandboxd down")):
            with caplog.at_level(logging.WARNING, logger="venya.executor.strategies.sbx"):
                rc = strategy.remove_sandbox()
        assert rc == 1
        assert sbx.live_sandbox_names() == {_ORIGIN}
        assert "Failed to remove sandbox" in caplog.text


# ---------------------------------------------------------------------------
# AC2 — failed teardown: the reaper is invoked and the residue is collected
# ---------------------------------------------------------------------------


class TestFailedTeardownArmsReaper:
    """AC2: a failed teardown is handed to the reaper instead of being lost."""

    def _executor(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        ex = Executor(command_validator=MagicMock(), session_id="s-474", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        return ex, strategy

    def _run(self, ex):
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            return ex._run_command_sbx("cmd", [], None, None)

    def test_teardown_raise_arms_reaper_and_preserves_origin(self, caplog):
        """AC2 + AC4: the reaper runs AND the origin exception still surfaces."""
        ex, strategy = self._executor()
        boom = ValueError("guest exec blew up")
        strategy.execute_command.side_effect = boom
        strategy.remove_sandbox.side_effect = TimeoutError("sbx rm hung")

        with patch("executor.executor.reap_orphan_sandboxes", return_value=1) as reap:
            with caplog.at_level(logging.WARNING, logger="venya.executor"):
                with pytest.raises(ValueError) as ei:
                    self._run(ex)

        assert ei.value is boom  # #417 verbatim: the swallow never masks the origin
        assert "Sandbox teardown failed" in caplog.text
        reap.assert_called_once()

    def test_teardown_raise_on_a_clean_run_still_arms_the_reaper(self):
        """Success path + failed teardown: the run still succeeds (#417), and
        the residue is handed to the reaper — pre-fix nothing was."""
        ex, strategy = self._executor()
        strategy.remove_sandbox.side_effect = TimeoutError("sbx rm hung")
        with patch("executor.executor.reap_orphan_sandboxes") as reap:
            result = self._run(ex)  # the swallow must not turn a clean run into a failure
        assert result.stdout == b"ok"
        reap.assert_called_once()

    def test_teardown_nonzero_rc_calls_the_reaper(self):
        """The CLI reports a failed removal WITHOUT raising — same arm."""
        ex, strategy = self._executor()
        strategy.remove_sandbox.return_value = 1
        with patch("executor.executor.reap_orphan_sandboxes") as reap:
            self._run(ex)
        reap.assert_called_once()

    def test_paired_negative_clean_teardown_collects_nothing(self):
        ex, strategy = self._executor()
        strategy.remove_sandbox.return_value = 0
        with patch("executor.executor.reap_orphan_sandboxes") as reap:
            self._run(ex)
        reap.assert_not_called()

    def test_session_id_reaches_the_ownership_claim(self):
        """The executor hands its session id down so the claim is attributable."""
        ex, strategy = self._executor()
        strategy.remove_sandbox.return_value = 0
        with patch("executor.executor.reap_orphan_sandboxes"):
            self._run(ex)
        assert strategy.create_sandbox.call_args.kwargs["session_id"] == "s-474"


# ---------------------------------------------------------------------------
# AC1/AC2 — the pass runs at boot, BEFORE anything can execute
# ---------------------------------------------------------------------------


class TestBootReap:
    def _daemon(self, tmp_path):
        from executor.config import BootstrapConfig, ExecutorConfig
        from executor.daemon import ExecutorDaemon

        config = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            bootstrap=BootstrapConfig(),
            config_path=tmp_path / "executor.toml",
            relay_client_ids=["core-relay"],
            dns_resolver="192.0.2.53",
        )
        daemon = ExecutorDaemon(config)
        daemon._bootstrap_token_path = tmp_path / "bootstrap-token"
        return daemon

    def test_boot_runs_the_reap_pass_before_the_listener_starts(self, tmp_path):
        """Ordering is the safety property: at boot the ownership registry is
        empty, so every `venya-*` sandbox is residue — but only while nothing
        can execute yet. The reap must therefore precede relay.start()."""
        import executor.daemon as daemon_mod

        daemon = self._daemon(tmp_path)
        calls = []
        daemon.cert_manager = MagicMock()
        daemon._create_mtls_client = MagicMock(return_value=MagicMock())
        daemon.reaper = MagicMock()
        daemon.relay = MagicMock()
        daemon.relay.active = True
        daemon._write_pidfile = MagicMock()
        daemon._main_loop = MagicMock()
        daemon.stop = MagicMock()
        daemon.relay.start.side_effect = lambda: calls.append("relay")

        with (
            patch.object(daemon_mod, "require_supported_sbx", return_value="0.46.0"),
            patch.object(daemon_mod, "sweep_workspace_base", return_value=0),
            patch.object(daemon_mod, "reap_orphan_sandboxes", side_effect=lambda: calls.append("reap") or 0),
            patch.object(daemon_mod, "sweep_stale_tmp_files", return_value=0),
        ):
            daemon.start()

        assert calls.index("reap") < calls.index("relay")

    def test_paired_negative_the_reap_pass_never_gates_the_relay_bind(self, tmp_path, caplog):
        """The boot order holds: relay binds and the loop runs after the pass.

        ``reap_orphan_sandboxes`` is best-effort internally (see
        TestEnumerate/TestReapPass), so this cell pins the BOOT-SIDE property
        — the pass sits before ``relay.start()`` and nothing about it can keep
        the listener from binding.
        """
        import executor.daemon as daemon_mod

        daemon = self._daemon(tmp_path)
        daemon.cert_manager = MagicMock()
        daemon._create_mtls_client = MagicMock(return_value=MagicMock())
        daemon.reaper = MagicMock()
        daemon.relay = MagicMock()
        daemon.relay.active = True
        daemon._write_pidfile = MagicMock()
        daemon._main_loop = MagicMock()
        daemon.stop = MagicMock()

        with (
            patch.object(daemon_mod, "require_supported_sbx", return_value="0.46.0"),
            patch.object(daemon_mod, "sweep_workspace_base", return_value=0),
            patch.object(daemon_mod, "sweep_stale_tmp_files", return_value=0),
            patch.object(daemon_mod, "reap_orphan_sandboxes", return_value=1),
            caplog.at_level(logging.INFO),
        ):
            daemon.start()

        daemon.relay.start.assert_called_once()
        daemon._main_loop.assert_called_once()
        assert "Collected 1 orphaned sandbox(es)" in caplog.text
