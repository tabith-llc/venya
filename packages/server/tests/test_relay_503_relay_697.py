# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#697 OPTION 1 (owner ruling 2026-10-23) — the core relays the executor's honest 503.

The defect: when the relay listener answers with a named operational-fault refusal, the core's
``HTTPStatusError`` arm substituted ``"Executor returned an error"`` and the one component that
KNEW what happened was the one the operator could not hear.

What these cells hold, and the half of it that matters most:

* POSITIVE — a relay 503 whose detail opens with the shared operational-fault prefix is forwarded
  verbatim (both shipped literals, from the executor's own source, never retyped here).
* NEGATIVE (AC2, the paired half) — a relay 503 carrying an UNRECOGNISED string still yields the
  generic detail. That is the proof the #410 control survived this change; the mutation proof is
  in the report, and a negative half never shown RED is not a negative half.
* AC3 — the un-forwarded half is journalled as STRUCTURE only (length + digest prefix), never as
  text, because a relay body can echo a request fragment.
* DRIFT — the server-side prefix constant must still be the opening of both executor literals.
  Cross-import is refused by this row's design (server must not import executor), so the literals
  are read as TEXT from the source file and the cell is falsified against a planted literal here,
  which is what makes it a guard rather than decoration.

Harness: the app + relay mocks are the #410 file's own (``TestPolicyRejectionRelay410``), imported
rather than copied — a second fixture is a second answer about how the dial is faked. The relay
response is a REAL ``httpx2.Response``, so ``raise_for_status()`` and ``.json()`` behave as they do
in production.
"""

import ast
import hashlib
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from server.routes.executors import (
    GENERIC_RELAY_ERROR_DETAIL,
    OPERATIONAL_FAULT_DETAIL_PREFIX,
)

# Aliased with a leading underscore on purpose: a module attribute named `Test*` is COLLECTED here
# as well as in its own file, which would run the #410 cells twice and inflate this leg's gate delta.
from tests.test_execution_relay import TestPolicyRejectionRelay410 as _RelayHarness

REPO_ROOT = Path(__file__).resolve().parents[3]
LISTENER = REPO_ROOT / "packages" / "executor" / "src" / "executor" / "relay_listener.py"


@pytest.fixture(autouse=True)
def _relay_harness_seams():
    """The two seams the imported harness needs, re-declared HERE because they do not travel.

    ``test_execution_relay.py`` holds its own autouse fixtures (role permissions, and the #586
    dial-side CRL stub). Autouse fixtures are module-scoped, so importing that file's harness class
    does NOT import them — without this the request is refused at authorization long before the
    relay arm under test is reached, which is exactly the failure this cell first read as a defect.
    """
    role_manager = MagicMock()
    role_manager.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=role_manager):
        with patch("server.routes.executors._ensure_dial_crl_store", return_value=None):
            yield


#: The two literals the accept gate serves, read out of the executor source at test time.
_LITERAL_NAMES = ("REFUSE_NO_ANSWER", "REFUSE_NOT_WIRED")


def _listener_literals() -> dict[str, str]:
    """Module-level string literals of ``relay_listener.py``, by AST — no import of executor.

    ``ast.literal_eval`` on the assignment value: the shipped literals are parenthesised
    implicit concatenations, which the parser has already folded into one string constant, and a
    value that is NOT a plain string literal returns None and is reported, not guessed at.
    """
    found: dict[str, str] = {}
    for node in ast.parse(LISTENER.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _LITERAL_NAMES:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str):
                        found[target.id] = value
    missing = [n for n in _LITERAL_NAMES if n not in found]
    assert (
        not missing
    ), f"{LISTENER} no longer carries a plain string literal for {missing} — read it, do not re-type it"
    return found


def _hop(status: int, detail: str | object):
    """Drive the real route with a relay that answered `status` and `{"detail": detail}`.

    `detail` may be a non-string JSON value on purpose — the degrade paths are part of the truth
    table, and a real ``httpx2.Response`` is what makes ``raise_for_status()`` and ``.json()``
    behave as they do in production.
    """
    request = httpx2.Request("POST", "https://192.0.2.14:8443/execute")
    response = httpx2.Response(status, json={"detail": detail}, request=request)
    return _RelayHarness()._harness_with_response(response)


def _hop_raw(status: int, *, text: str, content_type: str = "application/json"):
    """Same hop with a NON-JSON body — the degrade path must stay the generic detail."""
    request = httpx2.Request("POST", "https://192.0.2.14:8443/execute")
    response = httpx2.Response(status, text=text, headers={"content-type": content_type}, request=request)
    return _RelayHarness()._harness_with_response(response)


# -----------------------------------------------------------------------------------------
# POSITIVE HALF — the honest literal reaches the operator (AC1, route side)
# -----------------------------------------------------------------------------------------


class TestOperationalFaultIsRelayed:
    @pytest.mark.parametrize("name", _LITERAL_NAMES)
    def test_relay_503_operational_fault_detail_survives_the_hop(self, name):
        """AC1 (route half): the executor's own 503 literal is the client's detail."""
        literal = _listener_literals()[name]
        assert literal.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX), f"{name} is no longer in the forwarded class"
        resp = _hop(503, literal)
        assert resp.status_code == 503, "the status must stay the executor's, not be re-cast"
        assert resp.json()["detail"] == literal

    def test_forwarded_detail_is_the_literal_not_a_wrapping_of_it(self):
        """Byte-equality, not containment: no prefix, no suffix, no re-flow."""
        literal = _listener_literals()["REFUSE_NOT_WIRED"]
        assert _hop(503, literal).json()["detail"] == literal

    def test_relay_503_rejection_class_still_never_forwards_on_the_503_lane(self):
        """The 422 lane's prefix is not honoured at 503 — each class opens its own door."""
        resp = _hop(503, "Command rejected: Dangerous pattern matched: rm -rf")
        assert resp.json()["detail"] == GENERIC_RELAY_ERROR_DETAIL


# -----------------------------------------------------------------------------------------
# NEGATIVE HALF (AC2) — the #410 control survived. THE MUTATION TARGET.
# -----------------------------------------------------------------------------------------


class TestUnrecognised503StaysGeneric:
    def test_relay_503_unrecognised_detail_stays_generic(self):
        """AC2: an unrecognised 503 string yields the generic detail.

        Shown RED by mutation (comment out the ``startswith(OPERATIONAL_FAULT_DETAIL_PREFIX)``
        guard so every 503 detail forwards) — this cell is what that mutation breaks.
        """
        resp = _hop(503, "some fault nobody named — includes /run/secrets/venya/abc123 and a token")
        assert resp.status_code == 503
        assert resp.json()["detail"] == GENERIC_RELAY_ERROR_DETAIL

    def test_relay_503_prefix_without_the_class_space_stays_generic(self):
        """Near-miss on the prefix: the separator is part of the contract."""
        resp = _hop(503, "503 OPERATIONAL FAULT-no space here")
        assert resp.json()["detail"] == GENERIC_RELAY_ERROR_DETAIL

    def test_relay_503_non_json_body_stays_generic(self):
        """A body that is not JSON degrades to the generic detail and never to a 500."""
        resp = _hop_raw(503, text="gate blew up: <html>502</html>")
        assert resp.status_code == 503
        assert resp.json()["detail"] == GENERIC_RELAY_ERROR_DETAIL

    def test_relay_503_non_string_detail_stays_generic(self):
        """A JSON document whose detail is a list/dict is not a sentence and is not forwarded."""
        assert _hop(503, {"detail": ["not", "a", "sentence"]}).json()["detail"] == GENERIC_RELAY_ERROR_DETAIL

    def test_relay_422_control_is_unchanged_by_this_row(self):
        """The #410 pair still holds on both halves: forward on prefix, generic without it."""
        reason = "Command rejected: Dangerous pattern matched: rm -rf"
        assert _hop(422, reason).json()["detail"] == reason
        assert _hop(422, "some other 422").json()["detail"] == GENERIC_RELAY_ERROR_DETAIL


# -----------------------------------------------------------------------------------------
# AC3 — the un-forwarded half is journalled, as STRUCTURE only
# -----------------------------------------------------------------------------------------


LOGGER_NAME = "server.routes.executors"


def _shape_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "detail not forwarded" in r.getMessage()]


class TestUnforwardedDetailIsLoggedAsShape:
    def test_unforwarded_503_detail_is_recoverable_as_length_and_digest(self, caplog):
        """Positive half of AC3: the journal carries enough to CONFIRM which literal arrived."""
        body = "execution failed — see /run/svc/x/deadbeef"
        expected = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            assert _hop(503, body).json()["detail"] == GENERIC_RELAY_ERROR_DETAIL
        lines = _shape_lines(caplog)
        assert len(lines) == 1, lines
        assert f"sha256={expected}" in lines[0], lines[0]
        assert f"chars={len(body.encode())}" in lines[0], lines[0]

    def test_the_journal_never_carries_the_detail_text(self, caplog):
        """PAIRED NEGATIVE — the whole point of the shape form.

        A relay body on this hop can echo a request fragment, so the log must not write it. The
        probe string is asserted absent from EVERY captured record, not merely from the shape line.
        """
        probe = "ZZZ-echo-probe-must-not-land-in-logs"
        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            _hop(503, f"unlabelled fault {probe}")
        assert _shape_lines(caplog), "the shape line did not fire, so the absence below proves nothing"
        assert all(probe not in r.getMessage() for r in caplog.records), [r.getMessage() for r in caplog.records]

    def test_forwarded_detail_emits_no_shape_line(self, caplog):
        """When the literal reaches the operator, the un-forwarded log must NOT also fire."""
        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            _hop(503, _listener_literals()["REFUSE_NO_ANSWER"])
        assert _shape_lines(caplog) == []

    def test_offlist_status_emits_no_shape_line(self, caplog):
        """AC3's own scope clause: only the refusal-family statuses get the new line.

        A 500 keeps the shipped single warning and nothing added — the row's control on how wide
        the new log can reach.
        """
        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            assert _hop(500, "internal fault text").json()["detail"] == GENERIC_RELAY_ERROR_DETAIL
        assert _shape_lines(caplog) == []

    def test_non_string_detail_logs_a_type_and_not_a_repr(self, caplog):
        """A dict/list body is described by TYPE only — no element content reaches the journal."""
        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            _hop(503, {"detail": {"token": "sq3drift-value-must-not-be-logged"}})
        lines = _shape_lines(caplog)
        assert len(lines) == 1, lines
        assert "type=" in lines[0] and "sq3drift" not in lines[0], lines[0]


# -----------------------------------------------------------------------------------------
# DRIFT GUARD — criterion 4. A cell that CAN fail, and is shown failing here.
# -----------------------------------------------------------------------------------------


class TestPrefixMatchesTheExecutorSource:
    def test_server_prefix_matches_both_executor_literals(self):
        """The mirrored prefix must still be the OPENING of both shipped 503 refusals.

        This is the only thing standing between a re-worded sentence in ``relay_listener.py`` and a
        silently closed door: the forwarding check is a prefix test, so if the opening moves, the
        literal stops being forwarded and NO cell in the tree notices — except this one.
        """
        literals = _listener_literals()
        for name, literal in literals.items():
            assert literal.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX), (
                f"{name} no longer opens with the server-side prefix {OPERATIONAL_FAULT_DETAIL_PREFIX!r} — "
                "the relay door is silently closed for it. Either restate the constant in "
                "routes/executors.py (keeping the two classes distinguishable) or forward the new class here."
            )

    def test_both_literals_share_the_forwarded_prefix(self):
        """The owner's ruling rests on ONE shared opening — if that splits, the shape is wrong."""
        literals = _listener_literals()
        openings = {lit[: len(OPERATIONAL_FAULT_DETAIL_PREFIX)] for lit in literals.values()}
        assert openings == {OPERATIONAL_FAULT_DETAIL_PREFIX}, openings

    def test_the_class_does_not_absorb_the_revocation_assertion(self):
        """403 REVOKED must NOT start with the operational-fault prefix.

        The #603 lesson, as a cell: an unanswered daemon must never read as a revocation claim. If
        someone ever re-flows the literals so the classes share an opening, forwarding would assert
        a server-side event that did not happen — this is that rejection's negative half.
        """
        revoked = next(
            (
                ast.literal_eval(node.value)
                for node in ast.parse(LISTENER.read_text(encoding="utf-8")).body
                if isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "REFUSE_REVOKED"
            ),
            None,
        )
        assert isinstance(revoked, str), "REFUSE_REVOKED is not a plain string literal any more — read it"
        assert not revoked.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX)
        assert not OPERATIONAL_FAULT_DETAIL_PREFIX.startswith(revoked[:5])

    def test_falsifier_a_planted_opening_goes_red_on_the_real_predicate(self):
        """RED BEFORE GREEN on this cell's own predicate — a guard that cannot fail is decoration.

        Half 1: plant a re-worded literal (the class name moved to a synonym) and show the SAME
        comparison this guard uses reports it. Half 2: the shipped page passes the same call.
        """
        literals = _listener_literals()
        name = _LITERAL_NAMES[0]
        planted = literals[name].replace("503 OPERATIONAL FAULT", "503 RELAY UNAVAILABLE", 1)
        red = [n for n, v in {**literals, name: planted}.items() if not v.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX)]
        assert red == [name], f"the planted drift was NOT detected — this guard would pass a re-worded literal: {red}"
        assert not [n for n, v in literals.items() if not v.startswith(OPERATIONAL_FAULT_DETAIL_PREFIX)]
