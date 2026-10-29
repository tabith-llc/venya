# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#696 family (R-2614, Road B) — the egress-policy child gets a bound, and the class gets a gate.

THE DEFECT, as re-derived at this base (``74dc19ee``): ``apply_network_policy`` ran
``subprocess.run([\"sbx\", \"policy\", \"allow\", \"network\", ...], check=False)`` with NO ``timeout=``
at all. It was the only unbounded ``subprocess`` child in ``packages/*/src``. The call sits inside
``_run_command_sbx``, which the relay handler runs while it holds the executor's admission permit
(``max_concurrent_commands`` defaults to **1**), so one wedged sandboxd response did not slow a
command down — it parked the executor. Every later client queued behind a wait that had no end, and
the failure produced no log line and no outcome, because nothing was ever broken on its face.

WHAT THESE CELLS PIN, in the owner's three parts:

1. **the bound** — the call carries ``timeout=``, its value comes from ``VENYA_SBX_POLICY_TIMEOUT``
   read AT CALL TIME (default ``SBX_POLICY_TIMEOUT``), and the resolution idiom matches its two
   siblings: absent/empty -> default, non-numeric -> warning naming value and default, floor 0.0.
2. **fail-closed** — on ``TimeoutExpired`` the command is NOT executed and the executor returns to
   idle: no ``execute_command``, the sandbox is still torn down once, the permit comes back, and the
   operator's sentence names the egress stage rather than pretending a command hung.
3. **cleanup** — no stranded sandbox survives the timeout (see the residue argument in
   ``test_timeout_teardown_removes_the_sandbox_it_was_configuring``).

Paired negatives throughout: the healthy path is unchanged (rules registered, command runs, ONE
removal), a non-zero registration exit still raises as before, and the census is proven to FIRE
before its clean read is believed — on a planted site, on a stale exemption, on a scope that
resolved to nothing, and on an exemption list that outgrew its ceiling.

WHAT IS NOT PINNABLE ON THIS VENUE, stated rather than smoothed over: ``sbx`` is a guest binary, so
the wall-clock figure in ``SBX_POLICY_TIMEOUT``'s comment is a physical capture on
``venya-exec-3``, not a cell. These cells fake ONE boundary — ``subprocess.run`` inside the strategy
— exactly as ``test_sbx_create_outcome_639.py`` does, and the shipped code (argv build, timeout
resolution, the caller's lane, the teardown ``finally``) runs for real against that fake.
"""

import ast
import contextlib
import importlib.util
import io
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import Executor
from executor.strategies.sbx_strategy import (
    SBX_POLICY_TIMEOUT,
    SBX_POLICY_TIMEOUT_ENV,
    SbxPolicyTimeoutError,
    SbxStrategy,
    sbx_policy_timeout,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
_CENSUS_SCRIPT = REPO_ROOT / "scripts" / "check_subprocess_timeout_census.py"

# Tree door: load the shared census. A missing or renamed script is a loud ERROR here, never a
# skip — a skip would reopen the exact hole this file exists to close (same idiom as
# packages/cli/tests/test_httpx2_upper_bound_447.py, which is the house shape for two doors).
_spec = importlib.util.spec_from_file_location("subprocess_timeout_census", _CENSUS_SCRIPT)
assert (
    _spec is not None and _spec.loader is not None
), f"the shared census must live at {_CENSUS_SCRIPT} (R-2614 requirement 4)"
census = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(census)


def _pid_gone(pid: int) -> bool:
    """True when no process answers to ``pid``. Our own children are reaped by ``run``'s wait."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _policy_hosts(*hosts: str) -> MagicMock:
    """An EgressFilter stand-in returning exactly these hosts."""
    egress = MagicMock()
    egress.get_allowed_hosts.return_value = list(hosts)
    return egress


def _strategy() -> SbxStrategy:
    strategy = SbxStrategy(dns_resolver="192.0.2.53")
    strategy._sandbox_name = "venya-test123"
    return strategy


class TestEgressPolicyBound:
    """Requirement 1 — the call is bounded, and the bound is a knob, not a magic number."""

    def test_policy_call_carries_a_timeout(self, tmp_path: Path):
        """The defect's face: before this row the kwargs had no `timeout` key at all."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("198.51.100.50")):
                strategy.apply_network_policy("venya-test123")
            assert mock_run.call_count == 1
            kwargs = mock_run.call_args.kwargs
            assert "timeout" in kwargs, "the egress-policy child is unbounded — that is the defect"
            assert kwargs["timeout"] == sbx_policy_timeout()

    def test_knob_resolves_at_call_time(self, monkeypatch):
        """The env spelling bites, and it is read at CALL time, not import time — so a unit cell
        (and a deployment) shortens the bound without touching the command budget."""
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "7")
        assert sbx_policy_timeout() == 7.0
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("198.51.100.50")):
                strategy.apply_network_policy("venya-test123")
            assert mock_run.call_args.kwargs["timeout"] == 7.0

    def test_default_when_unset_or_empty(self, monkeypatch):
        """Absent and empty both land on the shipped default — the sibling idiom exactly."""
        monkeypatch.delenv(SBX_POLICY_TIMEOUT_ENV, raising=False)
        assert sbx_policy_timeout() == float(SBX_POLICY_TIMEOUT)
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "")
        assert sbx_policy_timeout() == float(SBX_POLICY_TIMEOUT)

    def test_non_numeric_warns_and_falls_back(self, monkeypatch, caplog):
        """A typo is a warning naming BOTH the value and the default, never a crash and never a
        silent zero — a policy path that fell back to 0 seconds would refuse every command."""
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "soon")
        with caplog.at_level(logging.WARNING, logger="venya.executor.strategies.sbx"):
            assert sbx_policy_timeout() == float(SBX_POLICY_TIMEOUT)
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "soon" in text and str(SBX_POLICY_TIMEOUT) in text, caplog.text

    def test_negative_floors_at_zero(self, monkeypatch):
        """Same floor as `_direct_path_timeout()` — a negative bound is 0.0, not an exception."""
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "-5")
        assert sbx_policy_timeout() == 0.0

    def test_bound_is_named_consistently_with_its_family(self):
        """The owner's naming requirement, pinned structurally: one ``*_ENV`` constant plus a
        read-at-call-time helper, as ``DIRECT_PATH_TIMEOUT_ENV`` / ``VENYA_SBX_CREATE_TIMEOUT`` do.
        A bare literal in the call would be the magic number he ruled out."""
        assert SBX_POLICY_TIMEOUT_ENV == "VENYA_SBX_POLICY_TIMEOUT"
        assert callable(sbx_policy_timeout)
        sites = [
            node
            for node in ast.walk(ast.parse(Path(SbxStrategy.apply_network_policy.__code__.co_filename).read_text()))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and getattr(node.func.value, "id", None) == "subprocess"
        ]
        wired = [
            k
            for node in sites
            for k in node.keywords
            if k.arg == "timeout"
            and isinstance(k.value, ast.Call)
            and getattr(k.value.func, "id", None) == "sbx_policy_timeout"
        ]
        assert wired, "the egress-policy call does not read its bound from the helper"

    def test_knob_is_documented(self):
        """A knob no operator can find is a dead surface with a different name. The comfort-door
        row in ``docs/ease-of-use.md`` is the deployment's only view of it, so it is pinned here
        the same way the shipped default is."""
        doc = REPO_ROOT / "docs" / "ease-of-use.md"
        text = doc.read_text()
        assert SBX_POLICY_TIMEOUT_ENV in text, f"{SBX_POLICY_TIMEOUT_ENV} is undocumented"


class TestEgressPolicyTimeoutFailsClosed:
    """Requirement 2 — on timeout: no command, teardown runs, permit returns, honest sentence."""

    def _executor(self, strategy):
        ex = Executor(command_validator=MagicMock(), session_id="s-policy", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        return ex

    def test_timeout_does_not_execute_the_command(self):
        """The command must not run with an egress policy that never finished. This is the
        fail-closed half: a sandbox under partial deny-all is NOT a sandbox to exec into."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.apply_network_policy.side_effect = SbxPolicyTimeoutError(
            ["sbx", "policy", "allow", "network", "h"], 30
        )
        ex = self._executor(strategy)
        result = ex._run_command_sbx("cmd", [], None, None)
        strategy.execute_command.assert_not_called()
        assert result.exit_code == -1

    def test_timeout_reports_the_egress_stage_not_a_hung_command(self, caplog):
        """#639's lesson applied one stage earlier: the shared TimeoutExpired lane used to say
        "Sandbox command timed out" for anything in the guarded region. A policy timeout is not a
        command timeout, and it says so — with the bound that actually fired."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.apply_network_policy.side_effect = SbxPolicyTimeoutError(
            ["sbx", "policy", "allow", "network", "h"], 30
        )
        ex = self._executor(strategy)
        with caplog.at_level(logging.ERROR, logger="venya.executor"):
            result = ex._run_command_sbx("cmd", [], None, None)
        assert b"egress policy apply timed out after 30" in result.stderr, result.stderr
        assert "command was not executed" in result.stderr.decode(), result.stderr
        journal = " ".join(r.getMessage() for r in caplog.records)
        assert "EGRESS POLICY apply timed out" in journal

    def test_timeout_sentence_is_not_the_generic_relay_error(self):
        """#697's rule in this direction: the executor's refusal must not collapse into the core's
        substituted literal, or the one component that knew what happened says nothing. Checked
        against the shipped constant, imported rather than retyped so a rename trips here."""
        from server.routes.executors import GENERIC_RELAY_ERROR_DETAIL

        strategy = MagicMock(spec=SbxStrategy)
        strategy.apply_network_policy.side_effect = SbxPolicyTimeoutError(["sbx", "policy"], 30)
        ex = self._executor(strategy)
        result = ex._run_command_sbx("cmd", [], None, None)
        text = result.stderr.decode()
        assert text and GENERIC_RELAY_ERROR_DETAIL not in text

    def test_permit_returns_after_a_policy_timeout(self, tmp_path):
        """THE OUTAGE CELL. The permit is the executor's availability: at cap=1 the relay handler
        holds it around the engine call and releases it in a ``finally``. A policy timeout that
        escaped as an exception, or hung, would wedge the listener shut — so a SECOND client must
        get through. Nothing here runs a sandbox or ``sbx``: the engine is the injected stub at the
        ``executor_factory`` seam, and the stub returns exactly what the shipped engine returns on
        this lane — a completed refusal, ``exit_code -1`` (see the two cells above), NOT a raised
        exception and NOT a 503. The relay status for a timed-out policy is therefore unchanged by
        this row; what changes is that it arrives in 30 seconds instead of never.
        """
        from tests.test_relay_listener import ALLOWED, _client, _start, _url
        from tests.test_relay_threading_rf3 import _payload, _pk

        state = {"n": 0}

        def _apply(_name):
            # ONE counter for the whole cell: the relay handler builds an engine per session, so a
            # counter inside the factory would reset and hang BOTH clients. First arrival hangs the
            # policy child, second behaves normally — which is what proves a LATER client gets
            # through rather than merely re-proving the refusal itself.
            if state["n"] == 1:
                raise SbxPolicyTimeoutError(
                    ["sbx", "policy", "allow", "network", "a.example", "--sandbox", "venya-x"],
                    float(SBX_POLICY_TIMEOUT),
                )

        def _factory(_sid):
            """The SHIPPED engine on the policy-timeout lane, not a hand-written refusal.

            A stand-in strategy whose ``apply_network_policy`` raises exactly what the bounded
            call site raises, wired into a real ``Executor``: so ``execute()`` ->
            ``_run_command_sbx`` -> the TimeoutExpired lane -> the teardown ``finally`` all run for
            real, and what the relay handler sees is the object the product would produce.
            """
            strategy = MagicMock(spec=SbxStrategy)
            strategy.apply_network_policy.side_effect = _apply
            strategy.execute_command.return_value = subprocess.CompletedProcess([], 0, stdout=b"ran", stderr=b"")
            strategy.remove_sandbox.return_value = 0
            engine = Executor(command_validator=MagicMock(), session_id="s-relay", injection_strategy=strategy)
            engine.http_client = None
            engine._injection_result = None

            class _Engine:
                def __init__(self) -> None:
                    self.strategy = strategy

                def execute(self, command, secrets, env_vars=None, askpass_helper=False):
                    state["n"] += 1
                    return engine._run_command_sbx(command, [], None, None)

            return _Engine()

        pk = _pk(tmp_path)
        assert pk.config.executor.max_concurrent_commands == 1, "cap=1 is the shipped posture"
        listener = _start(pk.config, _factory, [ALLOWED])
        try:
            with _client(pk.ca, pk.c_ok) as client:
                first = client.post(_url(listener), json=_payload("s1", "boom"))
                second = client.post(_url(listener), json=_payload("s2", "after"))
            assert first.status_code == 200 and first.json()["exit_code"] == -1, first.text
            assert "egress policy apply timed out" in first.json()["stderr"], first.text
            assert second.status_code == 200, f"the admission permit never returned: {second.status_code}"
            assert second.json()["exit_code"] == 0, second.text
            assert state["n"] == 2
        finally:
            listener.stop()

    def test_no_rule_is_registered_after_the_timeout(self):
        """The owner's exact ask: "the hung case returns the executor to idle WITHOUT the allow rule
        ever being applied". One host, the CLI hangs -> the rule for that host was never confirmed,
        so no success is claimed and no later host in the list is attempted."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(["sbx", "policy", "allow", "network", "a"], 30)
            with patch(
                "executor.egress_filter.EgressFilter", return_value=_policy_hosts("198.51.100.50", "198.51.100.100")
            ):
                with pytest.raises(SbxPolicyTimeoutError):
                    strategy.apply_network_policy("venya-test123")
            assert mock_run.call_count == 1, "the loop continued past a rule that never completed"


class TestEgressPolicyCleanup:
    """Requirement 3 — the residue question, answered with the mechanism."""

    def test_timeout_teardown_removes_the_sandbox_it_was_configuring(self):
        """The sandbox EXISTS by the time the policy site runs (create precedes it), so a policy
        timeout must route through the same teardown as any other setup raise (#406). ONE removal,
        and the guarded region starts before create — that ordering is what makes this safe."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.apply_network_policy.side_effect = SbxPolicyTimeoutError(["sbx", "policy"], 30)
        ex = Executor(command_validator=MagicMock(), session_id="s-clean", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        ex._run_command_sbx("cmd", [], None, None)
        assert strategy.remove_sandbox.call_count == 1

    def test_teardown_returning_nonzero_arms_the_reaper(self):
        """A failed ``sbx rm`` means a secrets-bearing microVM is still live (#474), so the reaper
        pass runs behind it. Paired negative against the cell above: the cleanup claim is not
        "removal always succeeds", it is "removal is attempted and its failure is collected"."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.apply_network_policy.side_effect = SbxPolicyTimeoutError(["sbx", "policy"], 30)
        strategy.remove_sandbox.return_value = 1
        ex = Executor(command_validator=MagicMock(), session_id="s-reap", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        with patch("executor.executor.reap_orphan_sandboxes") as reap:
            ex._run_command_sbx("cmd", [], None, None)
        reap.assert_called_once()

    def test_grandchild_survival_is_named_not_papered_over(self):
        """``subprocess.run(timeout=...)`` kills the DIRECT child only. Anything the ``sbx`` CLI
        forked can outlive it, and this cell's job is to pin that the code says so at the site
        rather than implying a full kill.

        Why the residue is harmless, as mechanism (requirement 3 option (b)), and the part option
        (a) cannot carry alone:
          * ``sbx policy allow network --sandbox <name>`` is a CLIENT call into the long-lived
            ``sandboxd`` daemon. Killing the client mid-RPC does not orphan a process tree that
            holds policy state — the daemon owns the state, and it is the same daemon before and
            after, so there is no half-spawned sandboxd to reap.
          * What CAN be left behind is a policy rule keyed to a sandbox name that no longer exists.
            The rule grants nothing to nobody: the sandbox is removed by the teardown above, and a
            rule for a dead name cannot admit traffic because no traffic carries that name.
          * The name is never reused. Sandboxes are ``venya-<session>-<uuid12>``
            (``_run_command_sbx``), so a stale rule can never be inherited by a later sandbox.
          * The existing teardown is what bounds the real residue: ``remove_sandbox`` runs
            ``sbx rm --force`` with its OWN 30 s bound and, on any failure, the caller's ``finally``
            arms ``reap_orphan_sandboxes()``, which sweeps unowned ``venya-*`` names.
        The residual class that is NOT pinnable from this seat: the vendor's own GC of rules for
        dead sandboxes. The site's existing ``shortcut:`` comment says a sweep is needed if
        ``sbx policy ls`` grows unbounded — that question is unchanged by this row and remains open.
        """
        source = Path(SbxStrategy.apply_network_policy.__code__.co_filename).read_text()
        window = source[source.index("def apply_network_policy") :]
        site = window[: window.index("def execute_command")]
        assert "kills THIS child" in site or "not reaped here" in site, "the site must name the caveat"
        # And the removal path the argument relies on is bounded, not hopeful.
        removal = source[source.index("def remove_sandbox") :]
        assert re.search(r"timeout=\d+", removal[: removal.index("if self._workspace_dir")]), removal[:900]


class TestEgressPolicyRealHungChild:
    """The bound biting a REAL hung child — no mock of ``subprocess.run`` anywhere.

    The other cells fake the call boundary because ``sbx`` is a guest binary. This class does not
    need to: a stand-in ``sbx`` earlier on ``PATH`` that never returns is enough to drive the
    shipped code end to end — real ``subprocess.run``, real ``timeout=`` read from the real knob,
    real kill of a real child, real named re-raise. It is the class that says the bound is not
    decorative, and the class that measured what the bound does NOT reach.
    """

    def test_a_hanging_policy_child_is_killed_at_the_bound(self, tmp_path, monkeypatch):
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        pidfile = tmp_path / "child.pid"
        script = bindir / "sbx"
        script.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nsleep 30\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "1")
        strategy = _strategy()
        with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("a.example")):
            started = time.monotonic()
            with pytest.raises(SbxPolicyTimeoutError) as ei:
                strategy.apply_network_policy("venya-test123")
            elapsed = time.monotonic() - started
        assert float(ei.value.timeout) == 1.0
        assert elapsed < 5, f"waited {elapsed:.1f}s for a 1 s bound — the bound did not fire"
        assert _pid_gone(int(pidfile.read_text().strip())), "the direct child survived its own bound"

    def test_a_forked_grandchild_survives_and_the_bound_still_returns_promptly(self, tmp_path, monkeypatch):
        """REQUIREMENT 3, MEASURED — and the measurement overturned the premise written down first.

        The owner's caveat is that ``subprocess.run(timeout=...)`` kills the DIRECT child only.
        That half is REAL and is pinned here: a grandchild the stand-in CLI forked was still alive
        after the refusal (measured by pid, before this cell killed it — it is the cell's own
        process, so nothing is left behind).

        What is NOT true, on this interpreter, is the worry that follows it — that a surviving
        grandchild holding the capture pipes would keep ``communicate()`` open and defeat the
        bound. Measured twice at ``timeout=1`` with a grandchild that inherits stdout and never
        exits: ``run`` returned at 1.00 s. ``communicate(timeout=...)`` carries its own deadline, so
        it raises at the bound, and the POSIX path then waits on the KILLED direct child only. So
        the outage property survives a grandchild; the residue is a stray process and a possible
        partial rule, not an indefinite hang. If that ever changes, this cell reddens and the
        argument beside the call site has to be re-read — it is not a licence to delete the bound.
        """
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        selfpid = tmp_path / "child.pid"
        grandpid = tmp_path / "grand.pid"
        script = bindir / "sbx"
        # Unredirected grandchild: it inherits the capture pipes, which is the worst case.
        script.write_text(f"#!/bin/sh\necho $$ > {selfpid}\nsleep 20 &\necho $! > {grandpid}\nwait\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv(SBX_POLICY_TIMEOUT_ENV, "1")
        strategy = _strategy()
        with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("a.example")):
            started = time.monotonic()
            with pytest.raises(SbxPolicyTimeoutError):
                strategy.apply_network_policy("venya-test123")
            elapsed = time.monotonic() - started
        direct = int(selfpid.read_text().strip())
        grand = int(grandpid.read_text().strip())
        try:
            assert elapsed < 5, f"the bound did not return promptly: {elapsed:.1f}s"
            assert _pid_gone(direct), "the direct child survived its own bound"
            assert not _pid_gone(grand), (
                "the grandchild was reaped after all — the caveat at the call site and in this "
                "docstring is now wrong, re-derive it rather than deleting the assertion"
            )
        finally:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(grand, 9)


class TestEgressPolicyHealthyPathUnchanged:
    """Paired negatives on the shipped behavior: the bound changed nothing else."""

    def test_rules_still_registered_one_per_host(self):
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("a.example", "b.example")):
                strategy.apply_network_policy("venya-test123")
            assert mock_run.call_count == 2
            assert [c.args[0][4] for c in mock_run.call_args_list] == ["a.example", "b.example"]

    def test_nonzero_exit_still_raises_runtimeerror(self):
        """The fail-loud row (F11) is byte-unchanged: a REFUSED registration is still a
        RuntimeError, and must not be relabelled as a timeout by the new except clause."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="unknown flag", stdout="")
            with patch("executor.egress_filter.EgressFilter", return_value=_policy_hosts("a.example")):
                with pytest.raises(RuntimeError, match="Failed to register egress allow a.example"):
                    strategy.apply_network_policy("venya-test123")

    def test_happy_path_still_executes_and_removes_once(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        ex = Executor(command_validator=MagicMock(), session_id="s-happy", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        result = ex._run_command_sbx("cmd", [], None, None)
        assert result.stdout == b"ok"
        strategy.execute_command.assert_called_once()
        assert strategy.remove_sandbox.call_count == 1


class TestSubprocessTimeoutCensus:
    """Requirement 4 — the gate itself, with the census proven able to fire."""

    def test_shipped_tree_is_clean(self, capsys):
        """The zero. Believable only because every cell below shows the instrument can bite."""
        rc = census.census(REPO_ROOT)
        assert rc == 0, capsys.readouterr().out

    def test_scanned_count_is_above_the_floor(self, capsys):
        """The floor is a tripwire, not a claim: assert the number the census prints for THIS
        tree, so a glob that narrows reddens here instead of silently widening what is "clean"."""
        census.census(REPO_ROOT)
        out = capsys.readouterr().out
        n = int(re.search(r"scanned (\d+) files", out).group(1))
        assert n >= census.MIN_SCANNED_FILES, out
        assert n >= 104, f"packages/*/src shrank to {n} files — re-derive the predicate, do not lower the floor"

    def test_instrument_can_fire_on_its_own_control(self, capsys):
        """The positive control, run as the script's own ``--self-test``: an unbounded planted site
        reads 1, a bounded one reads 0. This is the guarantee that guarantees its own input — it
        builds its own fixture tree and its own EMPTY exemption table, so it inherits nothing from
        the shipped tree or from this caller."""
        assert census.self_test() == 0, capsys.readouterr().out

    def test_planted_unbounded_site_in_a_real_src_file_is_red(self, tmp_path, monkeypatch):
        """THE PAIRED NEGATIVE the owner asked for, on the shipped predicate: a scratch package
        under a scratch repo root with a ``subprocess.run`` that has no bound must FAIL the census,
        and the same file with a bound must pass it. Written as a real layout, not a mock, because
        a mock of the walker would test the mock."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        # Pad past the floor so the file-count tripwire is not what answers this question.
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "wedger.py").write_text("import subprocess\n\nsubprocess.run(['true'], check=False)\n")
        assert census.census(root, exemptions={}) == 1
        (src / "wedger.py").write_text("import subprocess\n\nsubprocess.run(['true'], timeout=1, check=False)\n")
        assert census.census(root, exemptions={}) == 0

    def test_a_second_unbounded_site_in_an_exempted_file_is_still_red(self, tmp_path):
        """Why the exemption is scoped to ``path::function`` and not to the path: a file-level
        waiver is a hole with a name on it. Same file, a different function, no bound -> red.

        The exemption table here is the fixture's own — the census is driven with an explicit
        table so the shipped entries cannot answer a question about a scratch tree."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "w.py").write_text(
            "import subprocess\n\n"
            "def _run_command_direct():\n    subprocess.run(['true'], check=False)\n\n"
            "def _some_new_path():\n    subprocess.run(['true'], check=False)\n"
        )
        table = {"packages/widget/src/widget/w.py::_run_command_direct": "fixture reason"}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = census.census(root, exemptions=table)
        out = buf.getvalue()
        assert rc == 1, out
        assert "VIOLATION" in out and "_some_new_path" in out, out
        assert "exempt packages/widget/src/widget/w.py::_run_command_direct" in out, out

    def test_stale_exemption_fails_loudly(self, tmp_path):
        """An exemption whose site is gone must REFUSE, not pass. Without this, a bounded call is
        followed months later by an unbounded one under an entry nobody can say the reason for."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "clean.py").write_text("import subprocess\n\nsubprocess.run(['true'], timeout=5)\n")
        table = {"packages/widget/src/widget/clean.py::_gone": "an old reason"}
        with pytest.raises(SystemExit) as ei:
            census.census(root, exemptions=table)
        assert "stale exemption" in str(ei.value)

    def test_a_moved_definition_breaks_its_own_exemption(self, tmp_path):
        """The other half of "cannot age into a hole": the key names the function, so a RENAME of
        the excused code is a stale exemption and a refusal — not a waiver that silently follows
        the name to whatever now lives at that path."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "w.py").write_text(
            "import subprocess\n\ndef renamed_away():\n    subprocess.run(['true'], check=False)\n"
        )
        table = {"packages/widget/src/widget/w.py::_run_command_direct": "an old reason"}
        with pytest.raises(SystemExit) as ei:
            census.census(root, exemptions=table)
        assert "stale exemption" in str(ei.value)

    def test_exemption_over_its_ceiling_fails_loudly(self):
        """The exemption list cannot be silently extended: one more entry than ``MAX_EXEMPTIONS``
        is a hard refusal, and raising the ceiling is a visible edit in the same change."""
        table = {f"packages/x/src/x/f{i}.py::_g{i}": f"reason {i}" for i in range(census.MAX_EXEMPTIONS + 2)}
        with pytest.raises(SystemExit) as ei:
            census.census(REPO_ROOT, exemptions=table)
        assert "MAX_EXEMPTIONS" in str(ei.value)
        assert census.EXEMPTIONS, "the shipped table must carry its one named exemption"

    def test_a_reasonless_exemption_refuses(self, tmp_path):
        """An entry that says nothing excuses nothing — the reason is part of the mechanism, not
        commentary, so an empty one is a refusal rather than a waiver."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "w.py").write_text("import subprocess\n\ndef g():\n    subprocess.run(['true'], check=False)\n")
        with pytest.raises(SystemExit) as ei:
            census.census(root, exemptions={"packages/widget/src/widget/w.py::g": "   "})
        assert "no reason" in str(ei.value)

    def test_empty_scope_refuses_instead_of_passing(self, tmp_path):
        """A glob that resolves to nothing is blindness, and an instrument that is blind may not
        report green."""
        with pytest.raises(SystemExit) as ei:
            census.census(tmp_path)
        assert "blind" in str(ei.value)

    def test_unparseable_src_file_refuses(self, tmp_path):
        """Same family: a file the walker cannot read must stop the run, not be skipped into a
        clean verdict."""
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "broken.py").write_text("def (:\n")
        with pytest.raises(SystemExit) as ei:
            census.census(root)
        assert "does not parse" in str(ei.value)

    def test_the_from_subprocess_import_form_is_also_caught(self, tmp_path):
        """The census must not be evaded by the ordinary way to shorten the call.

        A walk keyed only to the ``subprocess.run`` attribute form reads
        ``from subprocess import run; run([...])`` as clean — a bound silently absent. This cell
        plants BOTH spellings and requires BOTH to be flagged, and then requires an unrelated
        project function named ``run`` to stay invisible, because a gate that flags everything
        gets switched off.
        """
        root = tmp_path / "repo"
        src = root / "packages" / "widget" / "src" / "widget"
        src.mkdir(parents=True)
        for i in range(census.MIN_SCANNED_FILES):
            (src / f"pad_{i}.py").write_text("x = 1\n")
        (src / "w.py").write_text(
            "from subprocess import run\nimport subprocess as sp\n\n"
            "def bare():\n    run(['true'], check=False)\n\n"
            "def aliased():\n    sp.run(['true'], check=False)\n\n"
            "def unrelated():\n    return _own_run(['true'])\n\n"
            "def _own_run(cmd):\n    return cmd\n"
        )
        sites = census.call_sites(src / "w.py")
        flagged = {(fn, name) for _, name, _, bounded, fn in sites if not bounded}
        assert ("bare", "run") in flagged, sites
        assert ("aliased", "run") in flagged, sites
        assert all(fn != "unrelated" for fn, _ in flagged), sites
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = census.census(root, exemptions={})
        assert rc == 1, buf.getvalue()
        out = buf.getvalue()
        assert "bare" in out and "aliased" in out, out

    def test_the_single_shipped_exemption_is_the_legacy_direct_path(self):
        """The named exemption, with its reason, asserted rather than assumed: exactly one entry,
        it names ``_run_command_direct`` in ``executor.py``, and the reason carries the two facts
        that make it survivable — test-only reach, and a bound that lives in communicate()/wait()."""
        assert len(census.EXEMPTIONS) == 1, census.EXEMPTIONS
        ((key, reason),) = census.EXEMPTIONS.items()
        assert key.endswith("executor.py::_run_command_direct"), key
        assert "VENYA_DIRECT_PATH_TIMEOUT" in reason and "#470" in reason, reason
        # The site it excuses is real and is still excusable: no `timeout=` keyword on that Popen.
        tree = ast.parse((REPO_ROOT / key.split("::")[0]).read_text())
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        found = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "Popen"
                and getattr(node.func.value, "id", None) == "subprocess"
            ):
                fn = node
                while fn is not None and not isinstance(fn, ast.FunctionDef):
                    fn = parents.get(fn)
                if fn is not None and fn.name == "_run_command_direct":
                    assert "timeout" not in {k.arg for k in node.keywords}
                    found = True
        assert found, "the exempted site no longer exists — delete the entry (the census would refuse too)"

    def test_the_egress_site_is_no_longer_unbounded(self):
        """And the instance this row fixed: the census's own walk of the shipped tree reports ZERO
        unbounded sites outside the exemption. If someone drops the bound, ``test_shipped_tree_is_clean``
        above is what reddens — this cell names which site was at issue."""
        path = REPO_ROOT / "packages/executor/src/executor/strategies/sbx_strategy.py"
        sites = census.call_sites(path)
        assert sites, "the walker sees no subprocess calls in the policy file — predicate drift"
        assert all(bounded for _, _, _, bounded, _ in sites), sites
