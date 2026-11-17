# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for #806 and #807: two residuals in the one egress refusal-list reader.

Both rows came out of leg 1449's probes against the code leg 1440 landed, and both are about the
same three lines — `sandbox_shape._rows`, `sandbox_shape.rows_from_any_face`, and the name tuple
`egress_filter.POLICY_LOG_LIST_KEYS` reads with them:

* `#806` — a recognised refusal-list name whose value is `null` answered `clear`. For the two
  recorders that share `_rows` an explicit `null` genuinely is their empty answer, so the reading
  rule is the caller's, not the seam's.
* `#807` — the reader returned the FIRST name that was present at all, so an empty vestigial older
  name outranked a populated newer one and the refusal disappeared without an error.

Neither shape is reachable on the captures in `tests/fixtures/` — each prints its list under one
name, and prints `[]`, not `null` — so these are written as payloads, not as re-captured bytes. The
paired negatives beside them are the point: `[]` under either name stays `clear`, a populated older
name is still the one read, and the recorders keep their `null`.

"""

import json
from datetime import UTC, datetime

import pytest

from executor import egress_filter as ef
from executor import sandbox_shape

REFUSED_HOST = "example.com:80"
REFUSED_REASON = "No matching allow rule (default deny)"

# One row in each measured face's own names, taken from the captures in tests/fixtures/ so the
# shapes here are the vendor's shapes and not inventions.
NEW_SANDBOX = "f2-1440-denyprobe-b501"
NEW_WINDOW = datetime(2026, 11, 16, 21, 57, 12, tzinfo=UTC)
ROW_NEW = {
    "sandbox_id": NEW_SANDBOX,
    "host": REFUSED_HOST,
    "reason": REFUSED_REASON,
    "count": 1,
    "first_seen": "2026-11-16T21:57:13.66900777Z",
    "last_seen": "2026-11-16T21:57:13.66900777Z",
}

OLD_SANDBOX = "f2-1440-denyprobe"
OLD_WINDOW = datetime(2026, 11, 16, 21, 54, 59, tzinfo=UTC)
ROW_OLD = {
    "vm_name": OLD_SANDBOX,
    "host": REFUSED_HOST,
    "proxy_type": "forward",
    "reason": REFUSED_REASON,
    "count_since": 1,
    "last_seen": "2026-11-16T21:55:00.006241974Z",
}

LIST_KEYS = ef.POLICY_LOG_LIST_KEYS


def _read(payload, sandbox: str, window: datetime) -> ef.ProxyEgressLogOutcome:
    return ef.proxy_egress_log_outcome(json.dumps(payload), sandbox_name=sandbox, started_at=window)


class TestNullUnderARecognisedName:
    """#806: a refusal list that arrives as `null` is not an answer that nothing was refused."""

    @pytest.mark.parametrize("name", LIST_KEYS)
    def test_a_null_refusal_list_is_unrecognised(self, name):
        outcome = _read({"allowed": [], name: None}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_UNRECOGNISED, f"{name}: null still reads as a clean run"
        assert outcome.denial is None, "and it is never promoted into a refusal either"
        for key in LIST_KEYS:
            assert repr(key) in outcome.detail, "the sentence names the lists it looked for"

    @pytest.mark.parametrize("name", LIST_KEYS)
    def test_an_empty_refusal_list_stays_clear(self, name):
        """★ The paired negative that keeps the fix from becoming an over-refusal: this is what every
        captured face prints, so it must not move to `unrecognised`."""
        outcome = _read({"allowed": [], name: []}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None

    def test_a_real_list_outranks_the_other_names_null(self):
        """Both residuals meet here: a `null` under one name and rows under the other is a refusal."""
        outcome = _read({"blocked_hosts": None, "blocked": [ROW_NEW]}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_DENIED, outcome.detail
        assert outcome.denial is not None and outcome.denial.host == REFUSED_HOST

    def test_an_empty_list_outranks_the_other_names_null(self):
        """The reading this leg takes: `null` is "the record is not there" (#806 §1), so it is
        skipped rather than fatal, and a present empty list under the other name is still the empty
        answer both captures print."""
        outcome = _read({"blocked_hosts": [], "blocked": None}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None


class TestTheNameThatCarriesRowsWins:
    """#807: a vestigial empty older name must not swallow a populated newer one."""

    def test_an_empty_older_name_does_not_hide_a_populated_newer_one(self):
        outcome = _read({"blocked_hosts": [], "blocked": [ROW_NEW]}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_DENIED, outcome.detail
        assert outcome.denial is not None and outcome.denial.host == REFUSED_HOST

    def test_a_populated_older_name_is_still_the_one_read(self):
        """★ The second face of the pair the ticket asks for: the fix is an ordering rule, not a
        renamed tuple — the old name carrying the rows must keep working."""
        outcome = _read({"blocked_hosts": [ROW_OLD], "blocked": []}, OLD_SANDBOX, OLD_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_DENIED, outcome.detail
        assert outcome.denial is not None and outcome.denial.host == REFUSED_HOST

    def test_two_empty_names_are_still_clear(self):
        outcome = _read({"blocked_hosts": [], "blocked": []}, NEW_SANDBOX, NEW_WINDOW)
        assert outcome.shape == ef.EGRESS_LOG_CLEAR and outcome.denial is None


class TestTheSeamKeepsItsOtherReaders:
    """The same three lines answer `sbx template ls` and `sbx settings list`; those readers ask for
    the empty answer and get it, so the new rule is the egress caller's flag, not the seam's."""

    def test_the_seam_returns_the_name_that_carries_rows(self):
        rows = sandbox_shape.rows_from_any_face({"blocked_hosts": [], "blocked": [ROW_NEW]}, *LIST_KEYS)
        assert rows == [ROW_NEW]

    def test_the_seam_still_falls_back_to_an_empty_name(self):
        """`[]` is an answer, not a missing one: it comes back as the empty list, never as `None`."""
        assert sandbox_shape.rows_from_any_face({"blocked_hosts": [], "blocked": []}, *LIST_KEYS) == []

    def test_the_seam_reads_a_null_as_a_shape_when_the_caller_asks(self):
        payload = {"blocked": None}
        assert sandbox_shape.rows_from_any_face(payload, *LIST_KEYS, null_is_shape=True) is None

    @pytest.mark.parametrize(("payload", "key"), [({"images": None}, "images"), ({"settings": None}, "settings")])
    def test_the_recorders_keep_reading_a_null_as_their_empty_answer(self, payload, key):
        assert sandbox_shape.rows_from_any_face(payload, key) == []
