# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for leg 1565 (iid #805): the trail must not answer "nothing was refused" for
"I could not read the record".

The caller's stream already carries the third answer — leg 1440 put it there, and letter A of
that leg bars promoting an unreadable record into a denial claim. What was missing is the SECOND
channel: `egress_denied` is set only from `egress_denial is not None`, so a run whose policy log
this build could not read and a run with nothing refused leave the same fields, the same audit
rows, and therefore the same trail. These cells pin the four things #805 asks for:

  (a) a clean record writes the new row NOT at all;
  (b) an unreadable record writes it and `egress_denied` stays false (letter A, unmoved);
  (c) a real refusal still writes `egress_denied` exactly as landed;
  (d) the name is one the spool accepts, so the row is not silently dropped on the way out.

`egress_filter.py` and `sandbox_shape.py` are deliberately untouched here: the classifier already
answers `EGRESS_LOG_UNRECOGNISED` and is pinned in `test_egress_denial_two_faces_1440.py`, and the
faces below are ones that read the same way before and after leg 1562's ordering change.
"""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from executor import egress_filter as ef
from executor.audit import EVENT_TYPES
from executor.executor import CommandResult, CommandValidator, Executor
from executor.strategies import sbx_strategy as sbx_module
from executor.strategies.sbx_strategy import SbxStrategy

SANDBOX = "venya-sess-1565-a1b2c3d4e5f6"
REFUSED_AT = datetime(2026, 11, 16, 18, 11, 22, 97130, tzinfo=UTC)
RUN_STARTED = REFUSED_AT - timedelta(seconds=1)
REFUSED_HOST = "example.com:80"

# The runtime answered, in names this build does not know. No refusal list under either measured
# key, so this is `unrecognised` today and stays `unrecognised` under leg 1562's ordering rule —
# which is why this face, and not a null-under-a-known-name face, is used here.
UNREADABLE_FACE = {"refusals": [{"host": REFUSED_HOST}], "ok": True}
# A recognised envelope holding nothing refused: `clear`, the answer that must keep writing no row.
CLEAN_FACE = {"allowed_hosts": [], "blocked_hosts": []}
# The measured refusal face, as `sbx policy log` writes it, inside this run's window.
DENIED_FACE = {
    "allowed_hosts": [],
    "blocked_hosts": [
        {
            "host": REFUSED_HOST,
            "vm_name": SANDBOX,
            "proxy_type": "forward",
            "rule": "no applicable policies for op(action=net:connect:tcp, resource=net:domain:example.com:80)",
            "last_seen": "2026-11-16T18:11:22.097130532Z",
            "since": "2026-11-16T18:11:22.097130532Z",
            "count_since": 1,
            "reason": "No matching allow rule (default deny)",
        }
    ],
}


def _log(payload):
    return json.dumps(payload)


class TestTheStrategyNamesTheThirdAnswer:
    """The slot #805 needs is the one the reader already computes and nobody recorded."""

    clock = RUN_STARTED

    @pytest.fixture
    def strategy(self, tmp_path, monkeypatch):
        """A real strategy with the vendor's verbs faked and the clock inside the window, so the
        read reaches the classifier rather than the timeout arm. The clock is patched, not the
        classifier: `execute_command` stamps its own run start."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("")
        monkeypatch.setattr(sbx_module, "datetime", SimpleNamespace(now=lambda tz: self.clock))
        s = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=allowlist, sandbox_memory_mb=512)
        s._sandbox_name = SANDBOX
        return s

    def _patch_log(self, monkeypatch, faces, exec_stderr=b""):
        """`faces` are the policy-log answers, consumed one call at a time; `exec_stderr` is what
        the guest command itself wrote, which the slot must not be derived from."""
        answers = iter(faces)

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return SimpleNamespace(returncode=0, stdout=b"", stderr=exec_stderr)
            return SimpleNamespace(returncode=0, stdout=next(answers, faces[-1]), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

    def _run(self, strategy):
        return strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])

    def test_an_unreadable_record_sets_its_own_slot_and_no_denial(self, strategy, monkeypatch):
        """Positive: the answer came back, this build could not read it, and that is now a fact the
        engine can see — with letter A intact, the denial slot stays empty."""
        self._patch_log(monkeypatch, [_log(UNREADABLE_FACE)])
        self._run(strategy)
        assert strategy.egress_log_unreadable is True
        assert strategy.egress_denial is None, "the unknown is never promoted into a refusal claim"

    def test_a_clean_record_leaves_the_slot_false(self, strategy, monkeypatch):
        """★ Paired negative (a) at the reader: a recognised empty answer is not an unreadable one,
        or every allowed run would raise the alarm this row exists to raise."""
        self._patch_log(monkeypatch, [_log(CLEAN_FACE)])
        self._run(strategy)
        assert strategy.egress_log_unreadable is False

    def test_a_recorded_refusal_leaves_the_slot_false(self, strategy, monkeypatch):
        """★ Paired negative (c) at the reader: the denial face is its own answer, not a second
        finding about the instrument."""
        self._patch_log(monkeypatch, [_log(DENIED_FACE)])
        self._run(strategy)
        assert strategy.egress_log_unreadable is False
        assert strategy.egress_denial is not None

    def test_a_read_that_never_answered_is_not_reported_as_unreadable(self, strategy, monkeypatch):
        """`None` from the read means the instrument gave nothing (rc non-zero, empty body, or a
        timeout). #805's requirement is the record that CAME BACK and could not be read, so this
        arm stays quiet — widening it would put a new row on every host without sbx."""

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            return SimpleNamespace(returncode=1, stdout="", stderr="401 Unauthorized: user is not authenticated")

        monkeypatch.setattr(subprocess, "run", fake_run)
        self._run(strategy)
        assert strategy.egress_log_unreadable is False

    def test_the_slot_is_written_fresh_on_every_run(self, strategy, monkeypatch):
        """No carry-over: an unreadable run followed by a clean one leaves the second clean, or the
        engine would write yesterday's instrument finding into today's trail row."""
        self._patch_log(monkeypatch, [_log(UNREADABLE_FACE), _log(CLEAN_FACE)])
        self._run(strategy)
        assert strategy.egress_log_unreadable is True
        self._run(strategy)
        assert strategy.egress_log_unreadable is False

    def test_the_slot_comes_from_the_reader_not_from_the_stream_text(self, strategy, monkeypatch):
        """The derivation reads `outcome.unrecognised` — the classifier's own answer. A run whose
        output happens to carry the unreadable sentence, with a record this build CAN read, must
        not set the slot: a trail written from prose is a trail that can be forged by a guest."""
        self._patch_log(
            monkeypatch,
            [_log(CLEAN_FACE)],
            exec_stderr=b"the sandbox egress record could not be confirmed\n",
        )
        self._run(strategy)
        assert strategy.egress_log_unreadable is False


class TestTheTrailCarriesTheThirdAnswer:
    """The engine half: one field on the result, one row in the trail, the denial pair unmoved."""

    def _executor(self, strategy, audit=None):
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-1565",
            injection_strategy=strategy,
            audit_logger=audit,
        )
        ex.http_client = None
        return ex

    def _clean_strategy(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        return strategy

    def test_an_unreadable_record_writes_its_own_row_beside_the_executed_one(self):
        """Positive, and letter A in the same breath: a new row appears, the denial fields do not."""
        audit = MagicMock()
        strategy = self._clean_strategy()
        strategy.egress_denial = None
        strategy.egress_log_unreadable = True
        result = self._executor(strategy, audit=audit).execute(["/usr/bin/curl", "http://example.com/"], [])
        named = {c.args[0]: c for c in audit.emit.call_args_list}

        assert result.egress_log_unreadable is True
        assert "command_executed" in named, "the command DID run; its row is not rewritten"
        assert "egress_log_unreadable" in named, "the trail may not answer this run with one sole row"
        assert named["egress_log_unreadable"].kwargs["exit_code"] == 0
        assert "egress_denied" not in named, "an unreadable record is not a denial row"
        assert result.egress_denied is False and result.egress_denied_host == ""

    def test_a_clean_run_writes_no_unreadable_row(self):
        """★ Paired negative (a): the trail for a run with nothing refused is byte-for-byte the
        trail it was before this change."""
        audit = MagicMock()
        result = self._executor(self._clean_strategy(), audit=audit).execute(
            ["/usr/bin/echo", "ok"],
            [],
        )
        emitted = [c.args[0] for c in audit.emit.call_args_list]
        assert result.egress_log_unreadable is False
        assert "egress_log_unreadable" not in emitted
        assert "egress_denied" not in emitted
        assert "command_executed" in emitted

    def test_a_denied_run_still_writes_its_denial_row_exactly_as_landed(self):
        """★ Paired negative (c): #798's row is not relabelled, not widened, and not joined by a
        second row for a record this build DID read."""
        audit = MagicMock()
        strategy = self._clean_strategy()
        strategy.egress_denial = ef.ProxyEgressDenial(REFUSED_HOST, "No matching allow rule (default deny)", 2)
        self._executor(strategy, audit=audit).execute(["/usr/bin/curl", "http://example.com/"], [])
        named = {c.args[0]: c for c in audit.emit.call_args_list}

        assert named["egress_denied"].kwargs == {
            "command": "/usr/bin/curl http://example.com/",
            "exit_code": 0,
            "egress_host": REFUSED_HOST,
        }
        assert "egress_log_unreadable" not in named

    def test_a_strategy_without_the_slot_reads_as_clean_not_as_an_error(self):
        """The `getattr` default is the compatibility half: a stand-in engine, or an older strategy
        object on the same host, has no slot, and that is silence about the instrument — not a
        finding and not a crash."""
        audit = MagicMock()
        strategy = self._clean_strategy()
        assert not hasattr(strategy, "egress_log_unreadable")
        result = self._executor(strategy, audit=audit).execute(["/usr/bin/echo", "ok"], [])
        assert result.egress_log_unreadable is False

    def test_the_field_defaults_clean_on_the_result_itself(self):
        """The direct path never passes it: a `CommandResult` built without the keyword is a run the
        instrument had nothing to say about."""
        result = CommandResult(command="x", exit_code=0, stdout=b"", stderr=b"")
        assert result.egress_log_unreadable is False


class TestTheSpoolAcceptsTheNewName:
    def test_the_name_is_a_known_event_type(self):
        """`AuditLogger.emit` DROPS an unknown name with a warning, so a row that is not in the
        tuple is a silently missing half of the trail — the reason this cell exists."""
        assert "egress_log_unreadable" in EVENT_TYPES

    def test_the_name_lands_in_the_spool(self, tmp_path):
        from executor.audit import AuditLogger
        from executor.config import AuditForwarderConfig

        logger_ = AuditLogger(
            config=AuditForwarderConfig(spool_path=str(tmp_path / "spool.jsonl")),
            session_id="s-1565",
        )
        try:
            logger_.emit(
                "egress_log_unreadable",
                command="/usr/bin/curl http://example.com/",
                exit_code=0,
            )
        finally:
            logger_.shutdown()
        lines = [json.loads(x) for x in (tmp_path / "spool.jsonl").read_text().splitlines() if x.strip()]
        assert lines and lines[0]["event_type"] == "egress_log_unreadable"
        assert "egress_host" not in lines[0], "no destination is claimed by a record that named none"
