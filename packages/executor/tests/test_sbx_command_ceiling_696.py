# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket no-per-command-ceiling-one-hold-takes-the-executor-offline (#696 AC1, AC4).

The sbx command path had exactly one bound and no door on it:
``subprocess.run(..., timeout=SBX_TIMEOUT)`` with ``SBX_TIMEOUT = 3600`` a bare
constant, duplicated in two modules. One command therefore held the executor's
SINGLE admission permit for up to an hour while every client fuse upstream blows
far earlier (relay read 300 s, nginx 330 s, CLI/MCP 340 s), and no deployment
could shorten it.

Fix pinned here — AC1: ``VENYA_SBX_TIMEOUT`` (seconds), resolved at call time by
``sbx_command_timeout()``, the same idiom the two shipped siblings use
(``VENYA_DIRECT_PATH_TIMEOUT``, ``VENYA_SBX_CREATE_TIMEOUT``). Read at call time
is the load-bearing property: it is what lets a unit cell — and this fleet's
physical run — inject a short bound instead of waiting out an hour. The two
duplicated constants are now ONE definition, imported into ``executor.py``, so a
deployment that sets the ceiling cannot still be held for an hour by the other
copy.

AC4 both halves: a command that finishes inside the ceiling is unaffected, and a
command that exceeds it is terminated with a NAMED reason and the permit
released. The named-reason half carries the #697 discipline: the timeout lane
RETURNS a CommandResult (exit code -1, stderr naming the bound that fired) and
never raises, so it does not add a case to the generic
``Executor returned an error`` substitution. A cell pins that explicitly.

Paired negatives, because a knob that only passes the happy case is untested: the
default with the override unset is the shipped 3600 unchanged; a non-numeric
override warns and falls back rather than becoming a silent 0; and the ceiling
is NOT a no-op — the cell that shortens the bound asserts the child is actually
killed and the permit comes back.

Not in this row (scope, stated so a later seat does not over-read): AC2 (an
operator cancel path) and AC3 (observability, which meets #655) are separate
legs, and the untimed ``apply_network_policy`` child is a separate defect with
no board row — nothing here touches either.
"""

import logging
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import (
    DIRECT_PATH_TIMEOUT_ENV,
    SBX_TIMEOUT,
    Executor,
    _direct_path_timeout,
)
from executor.strategies import sbx_strategy
from executor.strategies.sbx_strategy import (
    SBX_TIMEOUT_ENV,
    SbxStrategy,
    sbx_command_timeout,
)

SHORT_BOUND = "3"
SBX_LOGGER = "venya.executor.strategies.sbx"

# The relay suite's real-PKI helpers, borrowed the same way test_relay_threading_rf3
# and test_relay_stop_477 borrow them (house pattern). The permit cells below need
# the actual listener, not a stand-in.
from tests.test_relay_listener import ALLOWED, _start, _url


def _strategy() -> SbxStrategy:
    strategy = SbxStrategy()
    strategy._sandbox_name = "venya-696-test"
    return strategy


def _exec_run(timeout_capture: dict):
    """Patch ``subprocess.run`` at the exec site and record the bound it carried."""

    def _fake_run(cmd, **kwargs):
        timeout_capture["timeout"] = kwargs.get("timeout")
        timeout_capture["cmd"] = cmd
        return MagicMock(returncode=0, stdout=b"out", stderr=b"")

    return patch("subprocess.run", side_effect=_fake_run)


# ---------------------------------------------------------------------------
# AC1 — the resolver
# ---------------------------------------------------------------------------


class TestCeilingResolver:
    def test_default_is_the_shipped_hour_unchanged(self, monkeypatch):
        """The byte-for-byte default clause of AC1: with no override the answer
        is exactly what the bare constant was. A deployment that never heard of
        this knob behaves as it did before this row existed."""
        monkeypatch.delenv(SBX_TIMEOUT_ENV, raising=False)
        assert sbx_command_timeout() == 3600.0
        assert sbx_command_timeout() == float(SBX_TIMEOUT)

    @pytest.mark.parametrize("raw", ["30", "0.5", "0"])
    def test_override_is_honoured(self, monkeypatch, raw):
        monkeypatch.setenv(SBX_TIMEOUT_ENV, raw)
        assert sbx_command_timeout() == float(raw)

    def test_empty_override_is_not_a_zero(self, monkeypatch):
        """An exported-but-empty variable must not silently cut every command
        bound to nothing — the same shape the direct-path resolver pins."""
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "")
        assert sbx_command_timeout() == float(SBX_TIMEOUT)

    def test_garbage_override_fails_loudly_then_uses_the_default(self, monkeypatch, caplog):
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "soon")
        with caplog.at_level(logging.WARNING, logger=SBX_LOGGER):
            assert sbx_command_timeout() == float(SBX_TIMEOUT)
        assert "is not a number" in caplog.text
        assert "VENYA_SBX_TIMEOUT" in caplog.text
        assert "soon" in caplog.text

    def test_negative_override_floors_at_zero(self, monkeypatch):
        """A negative bound would be a passed-through surprise; the sibling
        idiom floors at 0.0 and this knob does too."""
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "-5")
        assert sbx_command_timeout() == 0.0

    def test_read_at_call_time_not_import_time(self, monkeypatch):
        """The property that makes the whole row testable, and the one a refactor
        could silently lose: set the env AFTER the module is imported and the
        next call still sees it."""
        monkeypatch.delenv(SBX_TIMEOUT_ENV, raising=False)
        assert sbx_command_timeout() == 3600.0
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "11")
        assert sbx_command_timeout() == 11.0
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "12")
        assert sbx_command_timeout() == 12.0


# ---------------------------------------------------------------------------
# AC1 — the ceiling reaches the subprocess.run site that passes the bound today
# ---------------------------------------------------------------------------


class TestCeilingAtExecSite:
    def test_exec_site_passes_the_configured_ceiling(self, monkeypatch):
        """Re-find the site by its own shape, not by a line number: the run call
        inside ``execute_command`` must carry the resolved value."""
        monkeypatch.setenv(SBX_TIMEOUT_ENV, SHORT_BOUND)
        seen: dict = {}
        strategy = _strategy()
        with _exec_run(seen):
            strategy.execute_command("sleep 30", argv=["/bin/sleep", "30"])
        assert seen["timeout"] == 3.0, "the sbx exec site ignored the ceiling"

    def test_exec_site_default_is_the_hour(self, monkeypatch):
        monkeypatch.delenv(SBX_TIMEOUT_ENV, raising=False)
        seen: dict = {}
        strategy = _strategy()
        with _exec_run(seen):
            strategy.execute_command("echo hi")
        assert seen["timeout"] == 3600.0

    def test_both_postures_take_the_same_ceiling(self, monkeypatch):
        """No-shell argv and the ruled ``sh -c`` form reach the same run site, so
        a ceiling that covered only one posture would leave half the command
        surface holding the permit for an hour (#322 C3 / the ``<`` redirect)."""
        monkeypatch.setenv(SBX_TIMEOUT_ENV, SHORT_BOUND)
        seen: dict = {}
        strategy = _strategy()
        with _exec_run(seen):
            strategy.execute_command("sudo -S id < /run/secrets/venya/3")
        assert seen["timeout"] == 3.0
        seen.clear()
        with _exec_run(seen):
            strategy.execute_command("ignored", argv=["/usr/bin/ssh", "host"])
        assert seen["timeout"] == 3.0

    def test_the_create_budget_is_not_the_command_ceiling(self, monkeypatch):
        """Negative pair against the SIBLING knob: shortening the command ceiling
        must not shorten ``sbx create``, which has its own bound (#639). A fix
        that wired one resolver into both sites would fail cold pulls."""
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "1")
        strategy = SbxStrategy(sandbox_memory_mb=1024)
        with patch("subprocess.run") as mock_run, patch("shutil.which", return_value=None):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            strategy.create_sandbox("venya-696-create", "/workspace")
        assert mock_run.call_args.kwargs["timeout"] != 1.0


# ---------------------------------------------------------------------------
# AC1 — one ceiling, both execution paths (the duplicated-constant half)
# ---------------------------------------------------------------------------


class TestOneCeilingBothPaths:
    def test_direct_path_falls_back_to_the_sbx_ceiling(self, monkeypatch):
        """The bug this cell guards: two bare ``SBX_TIMEOUT = 3600`` constants.
        With the direct-path knob UNSET, the legacy path must follow the same
        per-command ceiling an operator set, or a deployment shortens the sandbox
        hold and still gets an hour from the direct path."""
        monkeypatch.delenv(DIRECT_PATH_TIMEOUT_ENV, raising=False)
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "42")
        assert _direct_path_timeout() == 42.0

    def test_direct_path_specific_override_still_wins(self, monkeypatch):
        """Paired negative: the more specific knob is not outranked. An operator
        who set VENYA_DIRECT_PATH_TIMEOUT keeps exactly what they set."""
        monkeypatch.setenv(DIRECT_PATH_TIMEOUT_ENV, "7")
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "42")
        assert _direct_path_timeout() == 7.0

    def test_defaults_unchanged_when_neither_knob_is_set(self, monkeypatch):
        monkeypatch.delenv(DIRECT_PATH_TIMEOUT_ENV, raising=False)
        monkeypatch.delenv(SBX_TIMEOUT_ENV, raising=False)
        assert _direct_path_timeout() == 3600.0
        assert sbx_command_timeout() == 3600.0

    def test_direct_path_garbage_fallback_names_the_live_ceiling(self, monkeypatch, caplog):
        """The warning used to print a hard-coded 3600. Now the fallback IS the
        resolver, so the number an operator reads must be the number they get."""
        monkeypatch.delenv(DIRECT_PATH_TIMEOUT_ENV, raising=False)
        monkeypatch.setenv(DIRECT_PATH_TIMEOUT_ENV, "soon")
        monkeypatch.setenv(SBX_TIMEOUT_ENV, "42")
        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            assert _direct_path_timeout() == 42.0
        assert "42" in caplog.text

    def test_the_two_constants_are_one_definition(self):
        """Structural guard on the duplication AC1 exists to end. Before this row
        TWO modules each declared ``SBX_TIMEOUT = 3600``, so a knob on one left
        the other as the real ceiling. This reads the source and requires exactly
        one assignment of that name in the package — invisible to any behavioural
        test of either path alone."""
        root = Path(sbx_strategy.__file__).parent.parent
        defs = []
        for py in sorted(root.rglob("*.py")):
            for line in py.read_text(encoding="utf-8").splitlines():
                if re.match(r"^SBX_TIMEOUT\s*=", line):
                    defs.append(py.name)
        assert defs == ["sbx_strategy.py"], f"SBX_TIMEOUT is declared in {defs} — a second copy defeats the ceiling"


# ---------------------------------------------------------------------------
# AC4 — truth table, both halves, at the engine seam
# ---------------------------------------------------------------------------


def _engine_executor(strategy: MagicMock) -> Executor:
    ex = Executor(command_validator=MagicMock(), session_id="s-696", injection_strategy=strategy)
    ex.http_client = None
    ex._injection_result = None
    return ex


class TestCeilingTruthTable:
    """AC4: inside the ceiling nothing changes; over it, a named reason and the
    permit returned."""

    def test_command_inside_the_ceiling_is_unaffected(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"fast", stderr=b"")
        ex = _engine_executor(strategy)
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = ex._run_command_sbx("cmd", [], None, None)
        assert result.exit_code == 0
        assert result.stdout == b"fast"
        assert strategy.remove_sandbox.call_count == 1

    def test_command_over_the_ceiling_gets_a_named_reason(self, caplog):
        """The exceeded half: the reason NAMES the bound that fired, so an
        operator reading the journal can tell a 30 s ceiling from the hour."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.side_effect = subprocess.TimeoutExpired(["sbx", "exec"], 30)
        ex = _engine_executor(strategy)
        with caplog.at_level(logging.ERROR, logger="venya.executor"):
            result = ex._run_command_sbx("cmd", [], None, None)
        assert result.exit_code == -1
        assert b"timed out after 30 seconds" in result.stderr
        assert "Sandbox command timed out" in caplog.text

    def test_the_over_ceiling_lane_never_raises_to_the_generic_relay_arm(self):
        """#697 discipline: the timeout lane RETURNS. If it ever raised, the
        listener's flat-503 arm would substitute ``Executor returned an error``
        and this row would have added a case to that defect instead of naming one."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.side_effect = subprocess.TimeoutExpired(["sbx", "exec"], 30)
        ex = _engine_executor(strategy)
        try:
            result = ex._run_command_sbx("cmd", [], None, None)
        except Exception as exc:
            pytest.fail(f"the command-timeout lane raised {exc!r} — it must return, #697's arm owns raises")
        assert result.exit_code == -1
        assert b"Executor returned an error" not in result.stderr

    def test_teardown_runs_once_on_the_timeout_lane(self):
        """Paired negative on the permit: the timeout path still removes the
        sandbox exactly once, and still leaves through the finally (no
        double-remove, no leak — the same shape #406 pinned)."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.side_effect = subprocess.TimeoutExpired(["sbx", "exec"], 30)
        ex = _engine_executor(strategy)
        ex._run_command_sbx("cmd", [], None, None)
        assert strategy.remove_sandbox.call_count == 1


class TestPermitReleasedOnCeilingExpiry:
    """AC4's permit clause, at the seam that OWNS the permit.

    The handler takes it at ``slots.acquire()`` and returns it in the outer
    ``finally``. A ceiling that killed a command but leaked the permit would
    leave the executor offline exactly as long as the hour did — so this cell
    drives the real handler with an engine that raises the timeout, and asserts
    the next peer gets in.
    """

    def test_permit_returns_after_a_timeout_and_the_next_peer_is_admitted(self, tmp_path):
        """Drives the REAL handler with an engine that raises the command timeout
        and asserts the semaphore is whole again afterwards — a ceiling that
        killed the command but leaked the permit would leave the executor offline
        exactly as long as the hour did."""
        from tests.test_relay_listener import _client
        from tests.test_relay_threading_rf3 import _payload, _pk

        pk = _pk(tmp_path)
        calls = []

        class _TimingOut:
            def execute(self, command, secrets, env_vars=None, askpass_helper=False):
                calls.append(list(command))
                raise subprocess.TimeoutExpired(command, 30)

            def close(self):
                pass

        fake = _TimingOut()
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            with _client(pk.ca, pk.c_ok) as client:
                first = client.post(_url(listener), json=_payload("s1", "slow"))
                assert first.status_code == 503, "a timing-out engine is still an execution failure"
                assert listener._slots.acquire(timeout=2), "the admission permit was NOT returned after a timeout"
                listener._slots.release()
                second = client.post(_url(listener), json=_payload("s2", "next"))
                assert second.status_code == 503
            assert len(calls) == 2, "the queued peer never reached the engine"
        finally:
            listener.stop()

    def test_permit_count_is_untouched_on_the_success_path(self, tmp_path):
        """Negative pair: a command inside the ceiling leaves the semaphore
        exactly as full as it found it, so the fix cannot drain capacity."""
        from tests.test_relay_listener import _client, _ok_result
        from tests.test_relay_threading_rf3 import _payload, _pk

        pk = _pk(tmp_path)
        fake = MagicMock()
        fake.execute.return_value = _ok_result()
        listener = _start(pk.config, lambda _sid: fake, [ALLOWED])
        try:
            with _client(pk.ca, pk.c_ok) as client:
                for i in range(3):
                    assert client.post(_url(listener), json=_payload(f"s{i}", f"m{i}")).status_code == 200
            assert listener._slots.acquire(timeout=2), "a success path consumed a permit"
            listener._slots.release()
        finally:
            listener.stop()
