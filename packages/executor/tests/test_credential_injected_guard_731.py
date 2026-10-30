# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#731 — `credential_injected` is written only when a credential was injected.

`Executor.execute()` emitted the event for EVERY dispatch that reached its audit
block, including a run that bound nothing. With no entries to prepare the return
is an empty list, so the payload carried zero counts and an empty id list under an
event whose NAME asserts an injection. Those two fields are exactly the pair the MCP
audit renderer drops (that is row #709, deliberately NOT merged into this leg), so
the operator-visible face showed an injection event with no evidence behind it, and
the ledger asserted something the call did not do.

The module already guards its SIBLING call in this same method — `revoke_tokens()`
opens with `if not secret_ids: return` — so the guarded shape is shipped code, not
a new invention. The run-with-nothing case is still fully audited: `command_executed`
fires, and no secret material was ever resident, so no injection record was owed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from executor.bundles import SecretBundle
from executor.executor import Executor

_ARGV = ["/usr/bin/echo", "hello"]
_WRAPPED = b"[VENYA:00000000]eA==[/VENYA]"


def _executor(audit=None):
    from executor.strategies.sbx_strategy import SbxStrategy

    audit = MagicMock() if audit is None else audit
    strategy = MagicMock(spec=SbxStrategy)
    strategy.name.return_value = "sbx"
    strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
    ex = Executor(
        command_validator=MagicMock(validate=MagicMock(return_value=(True, ""))),
        session_id="s-731",
        injection_strategy=strategy,
        audit_logger=audit,
    )
    ex.http_client = None
    return ex, strategy


def _run(ex, strategy, injections):
    """execute() with `_prepare_injections` pinned to `injections` — the value the
    audit block reads — and the Stage-1 filter stubbed to pass text through."""
    with (
        patch.object(Executor, "_prepare_injections", return_value=injections),
        patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])),
    ):
        return ex.execute(_ARGV, [{"secret_id": 7, "value": b"x", "wrapped_value": _WRAPPED}] * len(injections))


def _bundle(secret_id="7"):
    return SecretBundle(secret_id=secret_id, value=b"x", wrapped_value=_WRAPPED, hash=None)


def _events(audit):
    return [c[0][0] for c in audit.emit.call_args_list]


class TestCredentialInjectedEmitsOnlyOnInjection:
    def test_no_injection_writes_no_credential_injected_row(self):
        """THE defect cell: nothing injected -> the event is NOT emitted. Proven able
        to fail: restoring the unguarded emit turns this red (`credential_injected`
        reappears in the event list)."""
        audit = MagicMock()
        ex, strategy = _executor(audit)
        result = _run(ex, strategy, [])
        assert result.exit_code == 0, "the command must still run — only the claim is withdrawn"
        assert "credential_injected" not in _events(audit), _events(audit)

    def test_one_injection_still_writes_the_row_unchanged(self):
        """Paired positive — the arm the original measurement confirmed ACCURATE: a
        bound credential still produces exactly one row, same event name, fd_count 1,
        the secret's id. This change is invisible to that case."""
        audit = MagicMock()
        ex, strategy = _executor(audit)
        result = _run(ex, strategy, [_bundle()])
        assert result.exit_code == 0
        rows = [c for c in audit.emit.call_args_list if c[0][0] == "credential_injected"]
        assert len(rows) == 1, _events(audit)
        assert rows[0][1]["fd_count"] == 1
        assert rows[0][1]["secret_ids"] == ["7"]

    def test_command_executed_is_written_on_both_paths(self):
        """The rest of the trail is unchanged: every run is audited, bound or not —
        the withdrawn row made an injection claim, the run record never did."""
        for injections in ([], [_bundle()]):
            audit = MagicMock()
            ex, strategy = _executor(audit)
            _run(ex, strategy, injections)
            assert "command_executed" in _events(audit), _events(audit)

    def test_empty_injection_still_revokes_nothing_and_cleans_up(self):
        """Negative control on the sibling guard this shape was copied from: with no
        injections the cleanup path runs and no revocation POST is attempted, so the
        zero-credential run leaves no dangling state behind the withdrawn row."""
        audit = MagicMock()
        ex, strategy = _executor(audit)
        ex.revoke_tokens = MagicMock()
        ex._cleanup_injections = MagicMock()
        _run(ex, strategy, [])
        strategy.create_sandbox.assert_called()
        ex._cleanup_injections.assert_called_once()
        assert ex.revoke_tokens.call_args[0][0] == []

    def test_no_audit_logger_still_runs(self):
        """The compound condition must not become a dispatch path: a daemon with no
        logger executes exactly as before."""
        ex, strategy = _executor(audit=None)
        result = _run(ex, strategy, [])
        assert result.exit_code == 0
        strategy.execute_command.assert_called_once()
