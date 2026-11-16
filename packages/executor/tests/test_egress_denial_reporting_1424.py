# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for leg 1424: a denied egress must not read as a delivered run.

The finding is NOT a wrong exit code. The sandbox proxy answers a refused request with
its own completed HTTP 403, so the number the caller reads is its own client's verdict on
a response it did receive — measured on an executor test guest (sbx v0.46.0) at
this leg: plain `curl` to a refused destination exits 0, `curl --fail` exits 22, and both
carry the proxy's "Approval required for example.com:80." body.

What the runtime DOES keep is its own refusal record: `sbx policy log <sandbox> --json`,
keyed to the sandbox name (which carries the venya session id) and surviving the sandbox.
These cells pin the three requirements built on it — the record is forwarded, the result
cannot be mistaken in either channel, and the repair line names the account that can
actually read it.

Paired negatives (root AGENTS.md §2) are the heart of this file: a genuinely delivered run
must still read as delivered, including when the SAME host carries an older refused row,
which is the face measured after an allow rule was added.
"""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from executor import egress_filter as ef
from executor.audit import EVENT_TYPES
from executor.executor import CommandValidator, Executor
from executor.strategies.sbx_strategy import SbxStrategy, daemon_account

# Run window used by the cells: a refusal logged at 18:11:22Z, read by a run that started
# one second earlier. `started_at` is what separates this run's refusal from history.
REFUSED_AT = datetime(2026, 11, 16, 18, 11, 22, 97130, tzinfo=UTC)
RUN_STARTED = REFUSED_AT - timedelta(seconds=1)
# The delivered request, measured minutes later on the same guest after the allow rule was
# added. Its own window starts AFTER the older refusal row, which is what makes it delivered.
DELIVERED_AT = datetime(2026, 11, 16, 18, 14, 2, 551004, tzinfo=UTC)
DELIVERED_STARTED = DELIVERED_AT - timedelta(seconds=1)
SANDBOX = "venya-sess-1424-a1b2c3d4e5f6"

# Captured verbatim from `sudo -n sudo -u venya sbx policy log f1-1424-denyprobe --json`
# on an executor test guest, host field kept as the vendor writes it (host:port).
BLOCKED_FACE = {
    "allowed_hosts": [],
    "blocked_hosts": [
        {
            "host": "example.com:80",
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

# The delivered face, measured on the same guest minutes later: an allow rule was added and
# `curl` reached the destination (HTTP 200). The blocked row for the SAME host:port is
# still there, because `blocked_hosts` is history — a reader that ignores `last_seen` would
# mark this delivered run as denied. That is the defect this cell exists to keep out.
DELIVERED_FACE = {
    "allowed_hosts": [
        {
            "host": "example.com:80",
            "vm_name": SANDBOX,
            "proxy_type": "forward",
            "rule": "",
            "last_seen": "2026-11-16T18:14:02.551004117Z",
            "since": "2026-11-16T18:14:02.551004117Z",
            "count_since": 1,
            "reason": None,
        }
    ],
    "blocked_hosts": [
        {
            "host": "example.com:80",
            "vm_name": SANDBOX,
            "proxy_type": "forward",
            "rule": "no applicable policies for op(action=net:connect:tcp, resource=net:domain:example.com:80)",
            "last_seen": "2026-11-16T18:11:22.097130532Z",
            "since": "2026-11-16T18:11:22.097130532Z",
            "count_since": 2,
            "reason": "No matching allow rule (default deny)",
        }
    ],
}


def _log(payload):
    return json.dumps(payload)


class TestTheRecordsOwnDenialIsRead:
    """Requirement 1: the evidence the runtime already keeps is read, and read for THIS run."""

    def test_the_measured_blocked_face_returns_the_refusal(self):
        got = ef.proxy_egress_denial(_log(BLOCKED_FACE), sandbox_name=SANDBOX, started_at=RUN_STARTED)
        assert got is not None
        assert got.host == "example.com:80"
        assert got.reason == "No matching allow rule (default deny)"
        assert got.hits == 1

    def test_the_verb_is_scoped_to_one_sandbox_and_asked_in_machine_form(self):
        assert ef.sbx_policy_log_argv(SANDBOX) == ["sbx", "policy", "log", SANDBOX, "--json"]

    def test_a_refusal_recorded_for_another_sandbox_is_not_this_runs(self):
        """Negative: the log is host-wide; only rows naming this sandbox may speak for it."""
        other = json.loads(json.dumps(BLOCKED_FACE))
        other["blocked_hosts"][0]["vm_name"] = "venya-sess-9999-deadbeef0000"
        assert ef.proxy_egress_denial(_log(other), sandbox_name=SANDBOX, started_at=RUN_STARTED) is None

    def test_the_newest_refusal_in_the_window_is_the_one_said_back(self):
        later = json.loads(json.dumps(BLOCKED_FACE))
        later["blocked_hosts"].append(
            {
                "host": "download.docker.com:443",
                "vm_name": SANDBOX,
                "proxy_type": "forward",
                "rule": "",
                "last_seen": "2026-11-16T18:11:23.000000000Z",
                "since": "2026-11-16T18:11:23.000000000Z",
                "count_since": 1,
                "reason": "No matching allow rule (default deny)",
            }
        )
        got = ef.proxy_egress_denial(_log(later), sandbox_name=SANDBOX, started_at=RUN_STARTED)
        assert got is not None and got.host == "download.docker.com:443"

    def test_bytes_and_str_arrive_equally(self):
        """`sbx policy log` is read with text=True here and capture=True elsewhere; both work."""
        as_bytes = _log(BLOCKED_FACE).encode()
        assert ef.proxy_egress_denial(as_bytes, sandbox_name=SANDBOX, started_at=RUN_STARTED) is not None


class TestADeliveredRunStillLooksDelivered:
    """★ THE PAIRED NEGATIVE (root §2). Nothing here may mark every egress as denied."""

    def test_a_run_the_runtime_allowed_is_not_a_denial(self):
        """Only `blocked_hosts` rows in the window can say a run was refused."""
        assert ef.proxy_egress_denial(_log(DELIVERED_FACE), sandbox_name=SANDBOX, started_at=DELIVERED_STARTED) is None

    def test_an_older_refusal_for_the_same_host_does_not_relabel_a_later_delivered_run(self):
        """The measured trap: `blocked_hosts` is history. The row for example.com:80 survives
        the allow rule that let the next request through, so recency, not membership, is the
        predicate. A reader keyed on the host alone would call a delivered run denied."""
        assert REFUSED_AT < DELIVERED_STARTED, "the fixture must hold the measured ordering"
        got = ef.proxy_egress_denial(_log(DELIVERED_FACE), sandbox_name=SANDBOX, started_at=DELIVERED_STARTED)
        assert got is None
        # ...and the same row IS this run's refusal when the window starts before it.
        early = ef.proxy_egress_denial(_log(BLOCKED_FACE), sandbox_name=SANDBOX, started_at=RUN_STARTED)
        assert early is not None and early.host == "example.com:80"

    def test_a_run_that_begins_after_the_refusal_is_clean(self):
        """Same face, other side of the boundary: start the window one second later."""
        started = REFUSED_AT + timedelta(seconds=1)
        assert ef.proxy_egress_denial(_log(BLOCKED_FACE), sandbox_name=SANDBOX, started_at=started) is None

    def test_an_empty_log_claims_nothing(self):
        empty = {"allowed_hosts": [], "blocked_hosts": []}
        assert ef.proxy_egress_denial(_log(empty), sandbox_name=SANDBOX, started_at=RUN_STARTED) is None


class TestAnInstrumentThatDidNotAnswerClaimsNothing:
    """A log that will not speak is read as no evidence — never as a denial, never as a clean run."""

    @pytest.mark.parametrize(
        "payload",
        [
            "",
            "not json at all",
            "[]",  # a list, not the documented object
            "{}",  # no blocked_hosts key
            '{"blocked_hosts": "example.com"}',  # wrong type for the list
            json.dumps({"blocked_hosts": [{"vm_name": SANDBOX, "host": "example.com:80"}]}),  # no last_seen
            json.dumps(
                {"blocked_hosts": [{"vm_name": SANDBOX, "host": "example.com:80", "last_seen": "2026-11-16T18:11:22"}]}
            ),  # names no zone
            json.dumps(
                {"blocked_hosts": [{"vm_name": SANDBOX, "last_seen": "2026-11-16T18:11:22.097130532Z", "host": ""}]}
            ),  # refuses without naming a destination
            None,
        ],
    )
    def test_shapes_that_are_not_the_measured_answer_yield_none(self, payload):
        assert ef.proxy_egress_denial(payload, sandbox_name=SANDBOX, started_at=RUN_STARTED) is None


class TestTheDenialLineAnOperatorCanActOn:
    """Requirement 3: the pointer names WHO can read the record and HOW.

    Measured on the same guest: as the daemon account the verb lists the refusals; as the
    login account it refuses with an authentication error. A repair line that sends an
    operator to the face that answers nothing is not a repair.
    """

    @pytest.fixture
    def egress(self, tmp_path):
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("web-server-3\n# a comment\n")
        return ef.EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")

    @pytest.fixture
    def denial(self):
        return ef.ProxyEgressDenial(
            host="example.com:80",
            reason="No matching allow rule (default deny)",
            hits=1,
        )

    def test_notice_names_the_account_and_the_scoped_verb(self, denial, egress):
        line = ef.proxy_egress_denial_notice(denial, sandbox_name=SANDBOX, daemon_user="venya", egress=egress)
        assert "sudo -n sudo -u venya sbx policy log" in line
        assert SANDBOX in line

    def test_notice_names_the_approval_verb_that_carries_allow_and_dismiss(self, denial, egress):
        """Measured face: `sbx policy approval ls` lists each open refusal with its verbs."""
        line = ef.proxy_egress_denial_notice(denial, sandbox_name=SANDBOX, daemon_user="venya", egress=egress)
        assert "sbx policy approval ls" in line

    def test_notice_says_the_exit_code_is_not_the_answer(self, denial, egress):
        line = ef.proxy_egress_denial_notice(denial, sandbox_name=SANDBOX, daemon_user="venya", egress=egress)
        assert "your own client" in line and "does not tell a delivered request" in line

    def test_notice_names_the_refused_destination_and_the_reason(self, denial, egress):
        line = ef.proxy_egress_denial_notice(denial, sandbox_name=SANDBOX, daemon_user="venya", egress=egress)
        assert "example.com:80" in line and "No matching allow rule (default deny)" in line

    def test_notice_carries_no_allowlist_contents(self, denial, egress):
        """Negative, in the house form for this file: counts and paths are named, entries and
        values are not, so the line cannot echo what the operator's file holds."""
        line = ef.proxy_egress_denial_notice(denial, sandbox_name=SANDBOX, daemon_user="venya", egress=egress)
        assert "web-server-3" not in line
        assert "carries 1 entry" in line

    def test_a_reason_that_is_not_there_adds_no_empty_parenthesis(self, egress):
        line = ef.proxy_egress_denial_notice(
            ef.ProxyEgressDenial(host="example.com:80", reason="", hits=0),
            sandbox_name=SANDBOX,
            daemon_user="venya",
            egress=egress,
        )
        assert " ()" not in line and "example.com:80" in line


class TestDaemonAccountIsNamedNotGuessed:
    def test_the_process_own_user_is_read_from_the_environment_first(self, monkeypatch):
        monkeypatch.setenv("USER", "venya")
        assert daemon_account() == "venya"

    def test_the_passwd_row_is_the_fallback_when_no_login_name_is_set(self, monkeypatch):
        monkeypatch.delenv("USER", raising=False)
        assert daemon_account()  # never empty: a repair line that names nothing is not a repair


class TestStrategyReadsTheRecordAfterTheRun:
    """The strategy half: one bounded read, and its outcome written into the caller's stream."""

    # The run start the strategy stamps for itself. Cells move this to the measured minute
    # they are describing: `RUN_STARTED` is inside the refusal window, `DELIVERED_STARTED`
    # begins after that refusal row and inside the allowed one.
    clock = RUN_STARTED

    @pytest.fixture
    def strategy(self, tmp_path, monkeypatch):
        """A real strategy with the vendor's two verbs faked, and a clock set inside the
        capture window. The clock is patched, not the classifier: `execute_command` stamps
        its own run start, and a fixture whose rows sit in November 2026 must be read as
        being *after* it or every cell below silently tests the wrong arm."""
        from executor.strategies import sbx_strategy as sbx_module

        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("")
        monkeypatch.setattr(sbx_module, "datetime", SimpleNamespace(now=lambda tz: self.clock))
        s = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=allowlist, sandbox_memory_mb=512)
        s._sandbox_name = SANDBOX
        return s

    def _exec_answer(self, stderr=b"Approval required for example.com:80.\n"):
        return SimpleNamespace(returncode=0, stdout=b"", stderr=stderr)

    def test_a_recorded_refusal_crosses_into_the_callers_stream(self, strategy, monkeypatch):
        """Positive: the refusal the runtime logged becomes a named line in the stream the
        caller reads, and the guest command's own rc is left exactly as it arrived (0)."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if cmd[:2] == ["sbx", "exec"]:
                return self._exec_answer()
            return SimpleNamespace(returncode=0, stdout=_log(BLOCKED_FACE), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])

        assert result.returncode == 0, "the fix must not second-guess the caller's own exit code"
        assert strategy.egress_denial is not None and strategy.egress_denial.host == "example.com:80"
        notice = result.stderr.decode()
        assert "venya: the sandbox proxy refused this run" in notice
        assert "sudo -n sudo -u" in notice and "sbx policy approval ls" in notice
        # The vendor body is forwarded untouched ABOVE the notice, not replaced.
        assert notice.startswith("Approval required for example.com:80.")

    def test_the_refusal_read_is_bounded_never_inherits_stdin_and_names_one_sandbox(self, strategy, monkeypatch):
        """The #695 hazard, applied to this read: an `sbx` client that inherits the daemon's
        stdin consumes it. venya's own exec path already sends DEVNULL; this read must too."""
        seen = []

        def fake_run(cmd, **kwargs):
            seen.append((cmd, kwargs))
            if cmd[:2] == ["sbx", "exec"]:
                return self._exec_answer()
            return SimpleNamespace(returncode=0, stdout=_log(BLOCKED_FACE), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        log_call = [call for call in seen if call[0][:3] == ["sbx", "policy", "log"]][-1]
        assert log_call[1]["stdin"] is subprocess.DEVNULL
        assert isinstance(log_call[1]["timeout"], (int, float))
        assert log_call[0][3] == SANDBOX

    def test_a_delivered_answer_leaves_the_stream_exactly_as_it_arrived(self, strategy, monkeypatch):
        """★ Paired negative at the strategy face: the runtime says allowed, so nothing is
        appended, nothing is claimed, and the result is byte-for-byte what the guest wrote."""
        raw = b"real page bytes\n"
        self.clock = DELIVERED_STARTED

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
            return SimpleNamespace(returncode=0, stdout=_log(DELIVERED_FACE), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])

        assert result.stderr == b""
        assert result.stdout == raw
        assert strategy.egress_denial is None

    def test_a_refused_log_read_claims_nothing_and_keeps_the_shape_fallback(self, strategy, monkeypatch):
        """The log belongs to the daemon account; a read from any other refuses. When it does,
        this run is NOT called denied, and the R-2909 shape notice still gets its chance —
        so the older face is not widened away by the newer one."""

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return SimpleNamespace(
                    returncode=255,
                    stdout=b"",
                    stderr=b"kex_exchange_identification: Connection closed by remote host\n",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="401 Unauthorized: user is not authenticated")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = strategy.execute_command(
            "/usr/bin/ssh bot@192.0.2.40 status", argv=["/usr/bin/ssh", "bot@192.0.2.40", "status"]
        )

        assert strategy.egress_denial is None
        stderr = result.stderr.decode()
        assert "the sandbox proxy refused this run" not in stderr
        assert "shape of a sandbox egress denial" in stderr, "the fallback face must still speak"

    def test_a_timeout_on_the_read_claims_nothing(self, strategy, monkeypatch):
        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return self._exec_answer()
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        assert strategy.egress_denial is None and b"venya: the sandbox proxy refused" not in result.stderr

    def test_the_denial_slot_is_written_fresh_on_every_run(self, strategy, monkeypatch):
        """No carry-over: a denied run followed by a delivered one leaves the second clean,
        or the executor would read yesterday's refusal into today's audit row."""
        faces = iter([(_log(BLOCKED_FACE)), (_log(DELIVERED_FACE))])

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return self._exec_answer()
            return SimpleNamespace(returncode=0, stdout=next(faces), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        self.clock = RUN_STARTED
        strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        assert strategy.egress_denial is not None
        self.clock = DELIVERED_STARTED
        strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        assert strategy.egress_denial is None


class TestExecutorCarriesTheDenialIntoBothChannels:
    """Requirement 2: the field on the result AND a distinct audit row."""

    def _executor(self, strategy, audit=None):
        ex = Executor(
            command_validator=CommandValidator(),
            session_id="s-1424",
            injection_strategy=strategy,
            audit_logger=audit,
        )
        ex.http_client = None
        return ex

    def test_the_result_field_is_set_from_the_recorded_refusal(self):
        strategy = MagicMock(spec=SbxStrategy)
        strategy.egress_denial = ef.ProxyEgressDenial("example.com:80", "No matching allow rule (default deny)", 1)
        strategy.execute_command.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        result = self._executor(strategy).execute(["/usr/bin/curl", "http://example.com/"], [])
        assert result.egress_denied is True
        assert result.egress_denied_host == "example.com:80"

    def test_a_denied_run_writes_its_own_audit_row_beside_the_executed_one(self):
        audit = MagicMock()
        strategy = MagicMock(spec=SbxStrategy)
        strategy.egress_denial = ef.ProxyEgressDenial("example.com:80", "No matching allow rule (default deny)", 2)
        strategy.execute_command.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self._executor(strategy, audit=audit).execute(["/usr/bin/curl", "http://example.com/"], [])
        named = {c.args[0]: c for c in audit.emit.call_args_list}
        assert "command_executed" in named, "the command DID run; its row is not rewritten"
        assert named["command_executed"].kwargs["exit_code"] == 0
        assert "egress_denied" in named, "a trail that reads only command_executed calls a denied run delivered"
        assert named["egress_denied"].kwargs["egress_host"] == "example.com:80"

    def test_a_delivered_run_writes_no_denial_row(self):
        """★ Paired negative: the trail for a clean run is exactly what it was before."""
        audit = MagicMock()
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        result = self._executor(strategy, audit=audit).execute(["/usr/bin/echo", "ok"], [])
        assert result.egress_denied is False and result.egress_denied_host == ""
        emitted = [c.args[0] for c in audit.emit.call_args_list]
        assert "egress_denied" not in emitted
        assert "command_executed" in emitted

    def test_a_strategy_without_the_slot_is_read_as_clean_not_as_an_error(self):
        """The getattr default is the compatibility half: a stand-in engine in the existing
        cells has no `egress_denial`, and that must not raise or invent a denial."""
        strategy = MagicMock(spec=SbxStrategy)
        strategy.execute_command.return_value = SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        assert not hasattr(strategy, "egress_denial")
        result = self._executor(strategy).execute(["/usr/bin/echo", "ok"], [])
        assert result.egress_denied is False


class TestTheSpoolAcceptsTheNewName:
    def test_egress_denied_is_a_known_event_type(self):
        """`AuditLogger.emit` DROPS an unknown name with a warning, so a row that is not in
        the tuple is a silently missing half of the trail — the reason this cell exists."""
        assert "egress_denied" in EVENT_TYPES

    def test_the_name_lands_in_the_spool(self, tmp_path):
        from executor.audit import AuditLogger
        from executor.config import AuditForwarderConfig

        logger_ = AuditLogger(
            config=AuditForwarderConfig(spool_path=str(tmp_path / "spool.jsonl")),
            session_id="s-1424",
        )
        try:
            logger_.emit(
                "egress_denied",
                command="/usr/bin/curl http://example.com/",
                exit_code=0,
                egress_host="example.com:80",
            )
        finally:
            logger_.shutdown()
        lines = [json.loads(x) for x in (tmp_path / "spool.jsonl").read_text().splitlines() if x.strip()]
        assert lines and lines[0]["event_type"] == "egress_denied"
        assert lines[0]["egress_host"] == "example.com:80"
