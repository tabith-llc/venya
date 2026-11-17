# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Leg 1565 (iid #805), the contract half of the seam.

`egress_log_unreadable` is the third answer the executor's own read of the sandbox egress record
can give: the runtime replied and this build could not parse the reply. It rides the relay body
because the core — not the executor — writes the operator's trail row for the run, and a field the
core cannot see is a row the trail never gets.

Both directions of the compatibility matrix are pinned here, the same discipline the `egress_denied`
pair was landed with in `test_relay_contract.py`: an older executor's body must parse with an inert
default, and a one-sided rename must fail loudly rather than read as a clean run.
"""

import json

import pytest
from pydantic import ValidationError
from venya_contract.relay import RelayResponse


def _body(**overrides):
    body = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "masked_count": 0}
    body.update(overrides)
    return body


class TestTheUnreadableAnswerCrossesAsData:
    def test_an_older_body_parses_with_the_default(self):
        """Compat direction 1: the six keys an executor from before this change sends still parse,
        and the new one lands inert — an executor that never read a record is not a finding."""
        resp = RelayResponse(**_body(egress_denied=False, egress_denied_host=""))
        assert resp.egress_log_unreadable is False

    def test_the_pre_egress_body_still_parses(self):
        """The four-key body from before #798 is the oldest shape on the wire; it must parse on the
        current model with every egress field inert."""
        resp = RelayResponse(**_body())
        assert resp.egress_denied is False and resp.egress_log_unreadable is False

    def test_the_answer_round_trips_exactly(self):
        """What the executor says is what the core reads — no prose parsing on either side."""
        resp = RelayResponse(**_body(egress_log_unreadable=True))
        parsed = RelayResponse(**json.loads(json.dumps(resp.model_dump())))
        assert parsed == resp
        assert parsed.egress_log_unreadable is True

    def test_the_field_is_in_the_body_the_consumer_indexes(self):
        """The seam cell, not an eyeball: `model_dump()` is what the route validates and then reads
        by key, so a field that is absent from it is a `KeyError` or a silent skip."""
        assert "egress_log_unreadable" in RelayResponse(**_body()).model_dump()

    def test_a_renamed_field_is_refused_not_dropped(self):
        """Direction 2, the loud half: if one peer renames this, the run fails instead of reporting
        a record it could not read as a record that refused nothing."""
        with pytest.raises(ValidationError):
            RelayResponse(**_body(egress_unreadable=True))

    def test_a_denial_is_not_a_substitute_for_the_unknown(self):
        """Letter A at the wire: the two answers are independent fields, so a body that claims the
        record was unreadable cannot also be read as a refusal claim, and the trail rows for the
        two states never collapse into one."""
        unreadable = RelayResponse(**_body(egress_log_unreadable=True))
        assert unreadable.egress_denied is False
        denied = RelayResponse(**_body(egress_denied=True, egress_denied_host="example.com:80"))
        assert denied.egress_log_unreadable is False
