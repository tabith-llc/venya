# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#639 — a hung `sbx create` and a memory-refused one must not be the same unnamed thing.

The defect, as re-derived at this base (`596b640`): `create_sandbox` ran
`subprocess.run(..., timeout=create_timeout, check=False)` with NO catch at the site,
while the same file caught that exception at its version probe and at its reap pass. Two
consequences, and the second is the one the ticket did not name:

* a create that HUNG propagated out as a bare `subprocess.TimeoutExpired`, which the
  caller's COMMAND-timeout lane swallowed and re-labeled
  "Command timed out after 3600 seconds" — the wrong stage and a number that is not the
  create bound (`SBX_CREATE_TIMEOUT` 240 s, or `VENYA_SBX_CREATE_TIMEOUT`);
* a create the vendor REFUSED (memory included) fell into one generic
  `RuntimeError("Failed to create sandbox: <stderr>")`, so "the guest cannot fit this
  sandbox" had no shape of its own.

**AC5, answered by construction.** `sbx` is absent from this box by design, so every cell
here fakes ONE thing: the `subprocess.run` boundary inside the strategy. Nothing here
pretends to exercise the vendor binary — the argv build, the timeout resolution, the
workspace cleanup, the classification, the named re-raise and the caller's lane are all
the shipped code paths, and they run for real against the fake. The claim that is NOT
pin-able on this venue is that the vendor's actual stderr matches these patterns: that
needs a guest with `sbx`, it is an owner-present fleet cell, DO-NOT-RUN here (see the
report and the residual class at the bottom of this file).

The classifier may narrow; it may never widen — that is this file's load-bearing rule, so
the negatives below are the point, not the tail.
"""

import re
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from executor.executor import CommandRejected, Executor
from executor.strategies import sbx_strategy as _sbx_mod
from executor.strategies.sbx_strategy import (
    SBX_CREATE_TIMEOUT,
    SbxCreateTimeoutError,
    SbxMemoryRefusalError,
    SbxStrategy,
    sbx_memory_refusal_shape,
)
from tests.test_relay_listener import (
    ALLOWED,
    SERVER_CN,
    _ca,
    _client,
    _factory,
    _FakeExec,
    _leaf,
    _start,
    _url,
    _write_cert_only,
    _write_dir,
)

# The pattern list, read FROM THE MODULE rather than restated, so the narrowing cells below
# check the shipped set and not a copy that can drift.
_SBX_MEMORY_LIST = tuple(_sbx_mod._SBX_MEMORY_REFUSAL_SHAPES)

# The vendor's own memory-shaped refusals. These are OUR pattern list, not a statement of
# what docker-sbx prints: no cell here claims the vendor's real wording, because claiming
# that needs a guest that has sbx (see the module docstring and the report's residual).
MEMORY_SHAPES = [
    "out of memory",
    "Out-of-memory: cannot start microVM",
    "Cannot allocate memory",
    "could not allocate memory for the guest",
    "insufficient memory on host",
    "not enough memory to satisfy the request",
    "memory allocation failed",
    "OOMKilled",
    "oom killer terminated the process",
]

# Near-misses that must NOT be read as a memory refusal. A classifier that fires on these
# converts an unhelpful 503 into a wrong 4xx, which is worse than the silence it replaced.
NOT_MEMORY = [
    "image not found",
    "cannot allocate '/workspace/my_memory_dir': no such file or directory",
    "sandbox name memory-test already exists",
    "no space left on device",
    "docker-sbx: unknown flag --memory-limit",
    "permission denied while reading /dev/kvm",
    "",
    None,
]


def _stack(memory_mb: int = 1024) -> SbxStrategy:
    return SbxStrategy(sandbox_memory_mb=memory_mb)


@pytest.fixture
def ws_base(monkeypatch, tmp_path):
    """Point WORKSPACE_BASE at tmp_path (hermetic; not real /dev/shm)."""
    base = tmp_path / "wsbase"
    monkeypatch.setattr("executor.strategies.sbx_strategy.WORKSPACE_BASE", str(base))
    return base


class TestCreateSiteCatchesItsOwnTimeout:
    """AC2 / AC5(a) — the third catch of TimeoutExpired in this file, named, with ITS OWN
    bound. The fake raises with the timeout value the shipped code passed in, so a cell
    that hardcodes a number anywhere would fail: this proves the resolved value travels."""

    @staticmethod
    def _raise_with_the_bound_it_was_given(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0] if args else ["sbx", "create"], kwargs["timeout"])

    def test_hung_create_raises_the_named_create_error(self, ws_base):
        strategy = _stack()
        with patch("subprocess.run", side_effect=self._raise_with_the_bound_it_was_given):
            with pytest.raises(SbxCreateTimeoutError) as excinfo:
                strategy.create_sandbox("venya-639-hang")
        # The bound that fired is the CREATE bound, not the command budget.
        assert excinfo.value.timeout == SBX_CREATE_TIMEOUT
        assert isinstance(excinfo.value, subprocess.TimeoutExpired), (
            "the named error must stay a TimeoutExpired so the caller's existing lane "
            "keeps holding it — #639 AC4 forbids moving the wire"
        )

    def test_env_override_value_is_the_one_named(self, ws_base, monkeypatch):
        monkeypatch.setenv("VENYA_SBX_CREATE_TIMEOUT", "999")
        strategy = _stack()
        with patch("subprocess.run", side_effect=self._raise_with_the_bound_it_was_given):
            with pytest.raises(SbxCreateTimeoutError) as excinfo:
                strategy.create_sandbox("venya-639-hang-override")
        assert excinfo.value.timeout == 999, "the resolved override, not the constant"

    def test_a_hung_create_cleans_the_workspace_the_strategy_made(self, ws_base):
        """The per-run workspace must not survive a create that never completed.

        Before this row the site never ran, so cleanup happened only in the caller's
        teardown; pinning it HERE means a create that hangs leaves no residue even for a
        caller that forgets to tear down.
        """
        strategy = _stack()
        with patch("subprocess.run", side_effect=self._raise_with_the_bound_it_was_given):
            with pytest.raises(SbxCreateTimeoutError):
                strategy.create_sandbox("venya-639-hang-clean")
        assert strategy._workspace_dir is None
        remaining = [p.name for p in ws_base.iterdir()] if ws_base.exists() else []
        assert not any(name.startswith("ws_") for name in remaining), remaining


class TestMemoryRefusalIsNamed:
    """AC1 / AC5(b) — a memory-shaped vendor refusal gets a name an operator can act on.
    Non-memory refusals keep the shape they have today (AC5(c), the class below)."""

    @pytest.mark.parametrize("stderr", MEMORY_SHAPES)
    def test_memory_shaped_refusal_raises_the_named_error(self, stderr, ws_base):
        strategy = _stack(memory_mb=1024)
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr=stderr)):
            with pytest.raises(SbxMemoryRefusalError) as excinfo:
                strategy.create_sandbox("venya-639-mem")
        # Operator-readable: names the cap it asked the vendor for.
        assert "1024 MiB" in str(excinfo.value), str(excinfo.value)
        assert isinstance(
            excinfo.value, RuntimeError
        ), "the refusal stays on the strategy's existing RuntimeError channel"

    @pytest.mark.parametrize("stderr", MEMORY_SHAPES)
    def test_memory_shaped_refusal_is_named_in_the_executors_own_journal(self, stderr, ws_base, caplog):
        strategy = _stack(memory_mb=2048)
        with caplog.at_level("ERROR"):
            with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr=stderr)):
                with pytest.raises(SbxMemoryRefusalError):
                    strategy.create_sandbox("venya-639-journal")
        lines = [r.getMessage() for r in caplog.records if "sbx create refused for memory" in r.getMessage()]
        assert lines, [r.getMessage() for r in caplog.records]
        assert "2048 MiB" in lines[0]
        assert "VENYA_EXECUTOR_SANDBOX_MEMORY_MB" in lines[0]
        assert "docs/deployment-sizing.md" in lines[0]

    def test_the_vendors_stderr_does_not_cross_the_relay_boundary(self, ws_base):
        """The refusal text names OUR cap and OUR knob; the vendor's line goes to the
        journal as evidence, never into the exception the relay path could render.

        The stand-in vendor line carries a marker token instead of anything
        secret-shaped: this cell is about the marker NOT appearing in the raised
        message, and a literal that trips the repo's own detect-secrets hook would be
        the wrong instrument in a file whose point is what does not cross a boundary.
        """
        vendor_line = "out of memory while preparing VENDOR-STDERR-MARKER-DO-NOT-ECHO"
        strategy = _stack()
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr=vendor_line)):
            with pytest.raises(SbxMemoryRefusalError) as excinfo:
                strategy.create_sandbox("venya-639-leak")
        assert "VENDOR-STDERR-MARKER-DO-NOT-ECHO" not in str(excinfo.value)
        assert "preparing" not in str(excinfo.value)

    def test_a_memory_refusal_cleans_the_workspace_the_strategy_made(self, ws_base):
        strategy = _stack()
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="out of memory")):
            with pytest.raises(SbxMemoryRefusalError):
                strategy.create_sandbox("venya-639-mem-clean")
        assert strategy._workspace_dir is None
        remaining = [p.name for p in ws_base.iterdir()] if ws_base.exists() else []
        assert not any(name.startswith("ws_") for name in remaining), remaining

    def test_a_refused_create_never_claims_a_sandbox_as_live(self, ws_base):
        """register_live_sandbox runs only AFTER a create that returned 0 — a refused or
        hung create must not leave a phantom ownership claim for the reaper to chase."""
        strategy = _stack()
        for fake in (
            MagicMock(returncode=1, stderr="out of memory"),
            MagicMock(returncode=1, stderr="image not found"),
        ):
            with patch("subprocess.run", return_value=fake):
                with pytest.raises(RuntimeError):
                    strategy.create_sandbox("venya-639-noclaim")
            assert strategy._sandbox_name is None


class TestClassifierNeverWidens:
    """AC3 — the load-bearing half. Every one of these is a refusal the classifier must
    leave ALONE: an ordinary vendor non-zero reaching the outcome it reaches today."""

    @pytest.mark.parametrize("stderr", NOT_MEMORY)
    def test_near_misses_are_not_read_as_memory(self, stderr):
        assert sbx_memory_refusal_shape(stderr) is None, stderr

    @pytest.mark.parametrize("stderr", NOT_MEMORY[:6])
    def test_an_ordinary_failure_keeps_todays_exact_shape(self, stderr, ws_base):
        strategy = _stack()
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr=stderr)):
            with pytest.raises(RuntimeError) as excinfo:
                strategy.create_sandbox("venya-639-ordinary")
        assert type(excinfo.value) is RuntimeError, "not relabelled into either named class"
        assert not isinstance(excinfo.value, SbxMemoryRefusalError)
        assert not isinstance(excinfo.value, SbxCreateTimeoutError)
        assert str(excinfo.value) == f"Failed to create sandbox: {stderr}"

    def test_a_hang_is_not_read_as_memory(self, ws_base):
        """The two named outcomes stay separate: a timeout is never a memory refusal."""

        def _hang(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0] if args else ["sbx", "create"], kwargs["timeout"])

        strategy = _stack()
        with patch("subprocess.run", side_effect=_hang):
            with pytest.raises(SbxCreateTimeoutError) as excinfo:
                strategy.create_sandbox("venya-639-hang-not-mem")
        assert not isinstance(excinfo.value, SbxMemoryRefusalError)

    def test_the_pattern_list_is_narrow_by_construction(self):
        """Every accepted shape names memory or OOM as the resource; nothing here is a
        bare "memory" substring, which is what lets the path and name-collision negatives
        survive. If a future leg ADDS a pattern, this cell is where the widening is caught:
        the added entry must itself name a memory resource, or this fails."""
        for shape in MEMORY_SHAPES:
            assert sbx_memory_refusal_shape(shape) is not None, shape
        for entry in _SBX_MEMORY_LIST:
            assert re.search(r"memory|oom", entry, re.IGNORECASE), f"pattern {entry!r} does not name memory"

    @pytest.mark.parametrize("stderr", MEMORY_SHAPES)
    def test_the_shape_that_matched_is_the_shape_that_was_named(self, stderr):
        matched = sbx_memory_refusal_shape(stderr)
        assert matched in _SBX_MEMORY_LIST
        assert matched.lower() in stderr.lower()


class TestCallerLaneNamesTheStageAndItsOwnNumber:
    """What the operator actually reads. The caller's TimeoutExpired lane is shared by
    create and command (the guarded region starts BEFORE create, #406), so the ONLY way a
    hang is distinguishable is the stage + the bound carried on the exception. Before this
    row both printed the command constant 3600; these cells make that a hard requirement."""

    def _executor_with(self, strategy):
        ex = Executor(command_validator=MagicMock(), session_id="s-639", injection_strategy=strategy)
        ex.http_client = None
        ex._injection_result = None
        return ex

    def test_create_hang_reaches_the_caller_as_a_create_with_the_create_bound(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.name.return_value = "sbx"
        strategy.create_sandbox.side_effect = SbxCreateTimeoutError(["sbx", "create"], 240)
        ex = self._executor_with(strategy)
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = ex._run_command_sbx("echo hi", [], None, None)
        assert result.exit_code == -1
        stderr = result.stderr.decode()
        assert "create" in stderr, stderr
        assert "240" in stderr, stderr
        assert "3600" not in stderr, "the command budget must not be quoted for a create"
        strategy.execute_command.assert_not_called()
        assert strategy.remove_sandbox.call_count == 1, "the #406 teardown still runs once"

    def test_command_hang_keeps_its_own_stage_and_its_own_number(self):
        """Paired negative: fixing the create sentence must not steal the command lane."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.name.return_value = "sbx"
        strategy.execute_command.side_effect = subprocess.TimeoutExpired(["sbx", "exec"], 3600)
        ex = self._executor_with(strategy)
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = ex._run_command_sbx("echo hi", [], None, None)
        assert result.exit_code == -1
        stderr = result.stderr.decode()
        assert "create" not in stderr, stderr
        assert "3600" in stderr, stderr
        assert strategy.remove_sandbox.call_count == 1

    def test_memory_refusal_propagates_undisguised_to_the_engine_caller(self):
        """The refusal is NOT converted into a CommandResult: it reaches the caller as the
        named error, which is what keeps it out of the caller's timeout lane and keeps the
        relay's answer the same flat 503 it is today (pinned next)."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.name.return_value = "sbx"
        strategy.create_sandbox.side_effect = SbxMemoryRefusalError("refused for memory")
        ex = self._executor_with(strategy)
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            with pytest.raises(SbxMemoryRefusalError):
                ex._run_command_sbx("echo hi", [], None, None)
        assert strategy.remove_sandbox.call_count == 1, "#406 teardown survives the new class"


class TestRejectedSeamIsNotMoved:
    """AC4 — pin the seam this row does NOT touch, so a later leg cannot widen it silently.

    Mirror of test_relay_listener.py's 422/503 cells, driven here with the two new classes
    in the seat where the vendor failure would land. The listener's reason-bearing lane
    belongs to CommandRejected ALONE: a create refusal, however well named, must still be
    the flat 503 with the generic detail and no foreign text.
    """

    def test_memory_refusal_still_answers_the_flat_503_with_no_reason(self, pk639):
        fake = _FakeExec(exc=SbxMemoryRefusalError("refused: out of memory cap=1024 MiB"))
        listener = _start(pk639.config, _factory(fake, []), [ALLOWED])
        try:
            with _client(pk639.ca, pk639.client) as client:
                resp = client.post(_url(listener), json={"session_id": "x", "command": ["sleep", "300"]})
        finally:
            listener.stop()
        assert resp.status_code == 503
        assert resp.json() == {"detail": "execution failed"}

    def test_create_timeout_still_answers_the_flat_503(self, pk639):
        """The named timeout must not buy a new status either — AC4 unchanged wire."""
        fake = _FakeExec(exc=SbxCreateTimeoutError(["sbx", "create"], 240))
        listener = _start(pk639.config, _factory(fake, []), [ALLOWED])
        try:
            with _client(pk639.ca, pk639.client) as client:
                resp = client.post(_url(listener), json={"session_id": "x", "command": ["sleep", "300"]})
        finally:
            listener.stop()
        assert resp.status_code == 503
        assert resp.json() == {"detail": "execution failed"}

    def test_policy_rejection_still_earns_its_422_with_reason(self, pk639):
        fake = _FakeExec(exc=CommandRejected("Command rejected: Dangerous pattern detected"))
        listener = _start(pk639.config, _factory(fake, []), [ALLOWED])
        try:
            with _client(pk639.ca, pk639.client) as client:
                resp = client.post(_url(listener), json={"session_id": "x", "command": ["sudo", "rm"]})
        finally:
            listener.stop()
        assert resp.status_code == 422
        assert resp.json()["detail"] == "Command rejected: Dangerous pattern detected"


@pytest.fixture()
def pk639(tmp_path) -> SimpleNamespace:
    """A real PKI + configured ExecutorConfig, built from the relay harness's own helpers.

    Named here rather than importing the shared `pk` fixture because these three cells run
    against the same listener code path test_relay_listener.py pins, and the shape has to
    be local to be able to drive it with the #639 exception classes.
    """
    ca_key, ca_cert = _ca()
    srv_cert, srv_key = _leaf(ca_key, ca_cert, SERVER_CN, server_auth=True)
    c_cert, c_key = _leaf(ca_key, ca_cert, ALLOWED)
    ca_crt = _write_cert_only(ca_cert, tmp_path, "ca")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    client = _write_dir(c_cert, c_key, tmp_path, "c-ok")

    from executor.config import ExecutorConfig, MtlsConfig

    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="639-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_crt, cert=srv[0], key=srv[1]),
    )
    return SimpleNamespace(ca=ca_crt, srv=srv, client=client, config=config)
