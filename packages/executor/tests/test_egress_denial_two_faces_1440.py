# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for leg 1440: one runtime, two field names, and a third answer that must speak.

`#798` made a refused egress distinguishable by reading the sandbox runtime's own record —
`sbx policy log <sandbox> --json`. It was written against one face (v0.46.0: `blocked_hosts` rows
keyed by `vm_name` and `count_since`) and met another on the estate (v0.50.1: `blocked` rows keyed by
`sandbox_id` and `count`), where the read returned `None` and the caller was handed `Command exited
with code: 0` for a run the proxy had refused. `None` was doing double duty for "nothing was
refused" and "I did not understand this", and only the first of those is a clean run.

The faces here are captures, not recollections: `tests/fixtures/` holds the bytes the tool printed
on an executor test guest for a refusal each sandbox actually earned, and the digests are pinned below
so an edit shows up as a red cell rather than as a quiet change of shape. Nothing here branches on a
version number — the installer sets a vendor floor and no ceiling, and the vendor repo on that guest
offered 0.51.0 the same afternoon, so the requirement is to read the envelope's own keys and to name
an answer this build cannot read as its own outcome.
"""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from executor import egress_filter as ef
from executor import sandbox_shape
from executor.executor import CommandValidator, Executor
from executor.strategies import sbx_strategy as sbx_module
from executor.strategies.sbx_strategy import SbxStrategy

FIXTURES = Path(__file__).parent / "fixtures"
FACE_0460 = FIXTURES / "sbx-policy-log-f2-1440-denyprobe-v0.46.0.json"
FACE_0501 = FIXTURES / "sbx-policy-log-f2-1440-denyprobe-b501-v0.50.1.json"

SANDBOX_0460 = "f2-1440-denyprobe"
SANDBOX_0501 = "f2-1440-denyprobe-b501"

# Each refusal row was stamped at the capture minute (see fixtures/README.md); a window that opens
# one second earlier contains it, and a window that opens after it is the history case.
WINDOW_0460 = datetime(2026, 11, 16, 21, 54, 59, tzinfo=UTC)
WINDOW_0501 = datetime(2026, 11, 16, 21, 57, 12, tzinfo=UTC)
AFTER_BOTH = datetime(2026, 11, 16, 22, 0, 0, tzinfo=UTC)

# The digests of the bytes as they were captured, re-derivable with `sha256sum *.json`. These are
# integrity pins over public vendor output, not credentials, hence the inline pragmas.
FACE_0460_SHA = "c5a92efaf54e99e489932124fabc4c6e836ef1a9884e6796ce14586d52c6ce46"  # pragma: allowlist secret
FACE_0501_SHA = "bab15e3e94c3b57a793215c925f48771bfcb986287b2e5a9261a5718fc0ca8c0"  # pragma: allowlist secret

REFUSED_HOST = "example.com:80"
REFUSED_REASON = "No matching allow rule (default deny)"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _payload(path: Path) -> dict:
    return json.loads(_text(path))


class TestTheCapturesAreTheToolAndNotAMemory:
    """Before any parser is trusted against a fixture, the fixture is pinned."""

    @pytest.mark.parametrize(("path", "digest"), [(FACE_0460, FACE_0460_SHA), (FACE_0501, FACE_0501_SHA)])
    def test_the_captured_bytes_are_unchanged(self, path, digest):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, (
            f"{path.name} no longer holds the bytes the vendor printed; re-capture it rather than "
            "editing it — see tests/fixtures/README.md for the command"
        )

    def test_the_two_faces_differ_in_names_only(self):
        """The property the whole leg rests on, read off the bytes rather than from prose."""
        old, new = _payload(FACE_0460), _payload(FACE_0501)
        assert "blocked_hosts" in old and "blocked" not in old
        assert "blocked" in new and "blocked_hosts" not in new
        old_row = next(r for r in old["blocked_hosts"] if r["vm_name"] == SANDBOX_0460)
        new_row = next(r for r in new["blocked"] if r["sandbox_id"] == SANDBOX_0501)
        assert old_row["host"] == new_row["host"] == REFUSED_HOST
        assert old_row["reason"] == new_row["reason"] == REFUSED_REASON


class TestBothFacesReadAsTheSameRefusal:
    """Requirement §2.2: read both faces, naming which one was recognised."""

    def test_the_0460_object_face_is_a_refusal(self):
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0460), sandbox_name=SANDBOX_0460, started_at=WINDOW_0460)
        assert outcome.shape == ef.EGRESS_LOG_DENIED
        assert outcome.denial is not None
        assert outcome.denial.host == REFUSED_HOST
        assert outcome.denial.reason == REFUSED_REASON
        assert outcome.denial.hits == 1

    def test_the_0501_face_is_the_same_refusal(self):
        """★ The regression cell. At `8a5a342f` this returned `None` on these very bytes, because
        the reader looked for `blocked_hosts` and the runtime said `blocked`."""
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0501), sandbox_name=SANDBOX_0501, started_at=WINDOW_0501)
        assert (
            outcome.shape == ef.EGRESS_LOG_DENIED
        ), f"the v0.50.1 capture is still unreadable to the detector: {outcome.detail}"
        assert outcome.denial is not None and outcome.denial.host == REFUSED_HOST
        assert outcome.denial.hits == 1, "the row counts under `count`, not `count_since`"

    @pytest.mark.parametrize(
        ("path", "sandbox", "window"),
        [(FACE_0460, SANDBOX_0460, WINDOW_0460), (FACE_0501, SANDBOX_0501, WINDOW_0501)],
    )
    def test_neither_face_is_reported_as_a_clean_run(self, path, sandbox, window):
        outcome = ef.proxy_egress_log_outcome(_text(path), sandbox_name=sandbox, started_at=window)
        assert outcome.shape != ef.EGRESS_LOG_CLEAR

    @pytest.mark.parametrize(
        ("path", "sandbox", "window"),
        [(FACE_0460, SANDBOX_0460, WINDOW_0460), (FACE_0501, SANDBOX_0501, WINDOW_0501)],
    )
    def test_the_two_value_view_still_returns_the_denial(self, path, sandbox, window):
        """Compatibility half: `proxy_egress_denial` keeps its contract, so the caller that only
        forwards a refusal is unchanged by the third outcome."""
        got = ef.proxy_egress_denial(_text(path), sandbox_name=sandbox, started_at=window)
        assert got is not None and got.host == REFUSED_HOST

    def test_a_top_level_array_of_the_same_rows_is_read_too(self):
        """The seam `sandbox_shape.rows_from_any_face` is the one this module was pointed at: it
        already carries the array form another verb prints, so this reader gets it free."""
        rows = _payload(FACE_0501)["blocked"]
        outcome = ef.proxy_egress_log_outcome(json.dumps(rows), sandbox_name=SANDBOX_0501, started_at=WINDOW_0501)
        assert outcome.shape == ef.EGRESS_LOG_DENIED


class TestPairedNegativesOnePerFace:
    """§2.4: each fixture must go RED when the parser is pointed at the other face's names.

    A reader that accepts both faces is only proven by the pair: narrow the names to one face and
    the other's capture has to stop being a refusal — and it must stop being one by SAYING so, not
    by falling back into the clean arm. That is what separates this leg from the bug it fixes.
    """

    def test_the_0460_capture_stops_being_read_when_only_the_new_list_name_is_looked_for(self, monkeypatch):
        monkeypatch.setattr(ef, "POLICY_LOG_LIST_KEYS", ("blocked",))
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0460), sandbox_name=SANDBOX_0460, started_at=WINDOW_0460)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED
        assert outcome.denial is None

    def test_the_0501_capture_stops_being_read_when_only_the_old_list_name_is_looked_for(self, monkeypatch):
        monkeypatch.setattr(ef, "POLICY_LOG_LIST_KEYS", ("blocked_hosts",))
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0501), sandbox_name=SANDBOX_0501, started_at=WINDOW_0501)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED
        assert outcome.denial is None

    def test_the_0460_rows_lose_their_owner_when_only_the_new_name_is_read(self, monkeypatch):
        monkeypatch.setattr(ef, "POLICY_LOG_SANDBOX_KEYS", ("sandbox_id",))
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0460), sandbox_name=SANDBOX_0460, started_at=WINDOW_0460)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED

    def test_the_0501_rows_lose_their_owner_when_only_the_old_name_is_read(self, monkeypatch):
        monkeypatch.setattr(ef, "POLICY_LOG_SANDBOX_KEYS", ("vm_name",))
        outcome = ef.proxy_egress_log_outcome(_text(FACE_0501), sandbox_name=SANDBOX_0501, started_at=WINDOW_0501)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED


class TestTheThirdOutcomeIsReachableAndHonest:
    """§2.3: "nothing refused" and "I did not understand this" are different answers, and an
    unrecognised one is never promoted into a refusal and never allowed to pass as clean."""

    def _unrecognised(self, payload) -> ef.ProxyEgressLogOutcome:
        outcome = ef.proxy_egress_log_outcome(payload, sandbox_name=SANDBOX_0501, started_at=WINDOW_0501)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED
        assert outcome.denial is None, "the third outcome must never claim a refusal"
        assert outcome.detail, "and it must be able to say what it saw"
        return outcome

    def test_an_envelope_under_other_names_is_unrecognised(self):
        outcome = self._unrecognised(json.dumps({"refusals": [{"host": REFUSED_HOST}], "ok": True}))
        assert "blocked" in outcome.detail and "blocked_hosts" in outcome.detail
        assert "refusals" in outcome.detail, "the answer's own key names are the useful part"

    def test_a_truncated_answer_is_unrecognised(self):
        text = _text(FACE_0501)
        self._unrecognised(text[: len(text) // 2])

    def test_an_empty_answer_is_unrecognised(self):
        self._unrecognised("")

    def test_rows_that_name_no_sandbox_are_unrecognised(self):
        payload = {"blocked": [{"host": REFUSED_HOST, "last_seen": "2026-11-16T21:57:13.66900777Z"}]}
        self._unrecognised(json.dumps(payload))

    def test_a_matching_row_with_no_timestamp_is_unrecognised(self):
        """A row that is clearly this sandbox's, but whose instant the build cannot read, is a
        shape fact — it must not land in the clean arm."""
        payload = {"blocked": [{"sandbox_id": SANDBOX_0501, "host": REFUSED_HOST}]}
        outcome = self._unrecognised(json.dumps(payload))
        assert "last_seen" in outcome.detail

    def test_a_scrambled_stamp_is_unrecognised_not_clean(self):
        payload = {
            "blocked": [{"sandbox_id": SANDBOX_0501, "host": REFUSED_HOST, "last_seen": "yesterday, about five"}]
        }
        self._unrecognised(json.dumps(payload))

    def test_an_empty_refusal_list_is_clean(self):
        """★ The other side of the pair: a recognised answer with nothing in it is still "nothing
        refused", and it claims no denial."""
        outcome = ef.proxy_egress_log_outcome(
            json.dumps({"allowed": [], "blocked": []}), sandbox_name=SANDBOX_0501, started_at=WINDOW_0501
        )
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None

    @pytest.mark.parametrize(("path", "sandbox"), [(FACE_0460, SANDBOX_0460), (FACE_0501, SANDBOX_0501)])
    def test_a_refusal_older_than_this_run_is_history_not_a_denial(self, path, sandbox):
        """Both captures keep their rows; a window opened after them means THIS run refused nothing."""
        outcome = ef.proxy_egress_log_outcome(_text(path), sandbox_name=sandbox, started_at=AFTER_BOTH)
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None

    @pytest.mark.parametrize(("path", "window"), [(FACE_0460, WINDOW_0460), (FACE_0501, WINDOW_0501)])
    def test_another_sandboxes_refusal_is_not_this_one(self, path, window):
        outcome = ef.proxy_egress_log_outcome(
            _text(path), sandbox_name="venya-sess-9999-deadbeef0000", started_at=window
        )
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None

    def test_the_notice_names_the_tool_the_version_and_its_own_limit(self):
        outcome = ef.ProxyEgressLogOutcome(
            ef.EGRESS_LOG_UNRECOGNISED,
            None,
            "no refusal list under " "'blocked_hosts' or 'blocked' (top-level keys: nope)",
        )
        line = ef.proxy_egress_unrecognised_notice(
            outcome,
            sandbox_name=SANDBOX_0501,
            daemon_user="venya",
            tool_version="sbx version v0.50.1 ddb0268d7124b9cf98955d0b08ffd71a0dfcebe4",
        )
        assert "could not be confirmed" in line
        assert "v0.50.1" in line, "the version read is part of what the operator needs"
        assert SANDBOX_0501 in line and "venya" in line
        assert "not a report that the traffic was allowed" in line
        assert REFUSED_HOST not in line, "the sentence carries key names, never a refused value"


class TestTheStrategySaysItOutLoud:
    """The call-site half: an unreadable record reaches the stream the caller reads."""

    clock = WINDOW_0501

    @pytest.fixture
    def strategy(self, tmp_path, monkeypatch):
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("")
        monkeypatch.setattr(sbx_module, "datetime", SimpleNamespace(now=lambda tz: self.clock))
        monkeypatch.setattr(
            sandbox_shape,
            "run_instrument",
            lambda argv, timeout=sandbox_shape.INSTRUMENT_TIMEOUT: (
                0,
                "sbx version v0.50.1 ddb0268d7124b9cf98955d0b08ffd71a0dfcebe4\n",
                "",
            ),
        )
        s = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=allowlist, sandbox_memory_mb=512)
        s._sandbox_name = SANDBOX_0501
        return s

    def _exec_answer(self, stderr=b"Approval required for example.com:80.\n"):
        return SimpleNamespace(returncode=0, stdout=b"", stderr=stderr)

    def _patch_log(self, monkeypatch, stdout: str, returncode: int = 0):
        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return self._exec_answer()
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

    def test_the_new_face_crosses_into_the_callers_stream(self, strategy, monkeypatch):
        """On these bytes the shipped build wrote nothing; now the refusal is named, and the
        guest command's own exit code is left exactly as it arrived (0)."""
        self._patch_log(monkeypatch, _text(FACE_0501))
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        assert strategy.egress_denial is not None and strategy.egress_denial.host == REFUSED_HOST
        assert "the sandbox proxy refused this run's egress to example.com:80" in result.stderr.decode()

    def test_an_unreadable_answer_is_confirmed_as_unknown_in_the_same_channel(self, strategy, monkeypatch):
        """The defect's own face: the runtime answered, in names this build does not know."""
        self._patch_log(monkeypatch, json.dumps({"refusals": [{"host": REFUSED_HOST}]}))
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        stderr = result.stderr.decode()
        assert strategy.egress_denial is None, "an unreadable answer is never promoted into a denial"
        assert "could not be confirmed" in stderr, "and it is never left as silence either"
        assert "v0.50.1" in stderr and SANDBOX_0501 in stderr

    def test_the_unreadable_answer_does_not_rewrite_the_result_fields(self, strategy, monkeypatch):
        """The audit and wire fields stay the pair #798 defined: no denial, no denial host. The
        unknown is carried in the stream, where the caller already reads it."""
        self._patch_log(monkeypatch, json.dumps({"refusals": [{"host": REFUSED_HOST}]}))
        strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "x"])
        ex = Executor(command_validator=CommandValidator(), session_id="s-1440", injection_strategy=strategy)
        ex.http_client = None
        result = ex.execute(["/usr/bin/curl", "http://example.com/"], [])
        assert result.egress_denied is False and result.egress_denied_host == ""

    def test_a_clean_answer_still_says_nothing_about_this_run(self, strategy, monkeypatch):
        """★ Paired negative at the call site: recognised, empty, and the caller hears no new
        sentence — the third outcome must not become a noise machine on every allowed run."""
        self._patch_log(monkeypatch, json.dumps({"allowed": [], "blocked": []}))
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        stderr = result.stderr.decode()
        assert "could not be confirmed" not in stderr
        assert "the sandbox proxy refused" not in stderr
        assert strategy.egress_denial is None

    def test_the_shape_fallback_and_the_unknown_are_both_said_when_both_apply(self, strategy, monkeypatch):
        """R-2909's transport face and this leg's instrument face are independent: a close-shaped
        stderr plus an unreadable record reports the refusal it can see AND the record it cannot."""
        self.clock = WINDOW_0501

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["sbx", "exec"]:
                return SimpleNamespace(
                    returncode=255,
                    stdout=b"",
                    stderr=b"kex_exchange_identification: Connection closed by remote host\n",
                )
            return SimpleNamespace(returncode=0, stdout=json.dumps({"refusals": []}), stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = strategy.execute_command(
            "/usr/bin/ssh bot@192.0.2.40 status", argv=["/usr/bin/ssh", "bot@192.0.2.40", "status"]
        )
        stderr = result.stderr.decode()
        assert "shape of a sandbox egress denial" in stderr, "the older face still speaks"
        assert "could not be confirmed" in stderr, "and the unreadable record is named beside it"

    def test_a_read_that_refuses_still_claims_nothing_and_adds_no_unknown_line(self, strategy, monkeypatch):
        """★ And its pair: rc 1 from the log is "the instrument did not answer", not "the answer is
        a shape I cannot read" — those are different sentences and only the first is today's path."""
        self._patch_log(monkeypatch, "", returncode=1)
        result = strategy.execute_command("curl -sS http://example.com/", argv=["curl", "-sS", "http://example.com/"])
        assert strategy.egress_denial is None
        assert "could not be confirmed" not in result.stderr.decode()
