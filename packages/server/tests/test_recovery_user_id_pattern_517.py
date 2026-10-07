# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the break-glass new-admin ID grammar (#517).

``RecoveryRequest.new_user_id`` was a bare ``str``. The value lands in
``users.user_id`` as a NEW ADMIN, while the surface that later has to ADDRESS that
admin — ``routes/admin.py`` — requires ``USER_ID_PATTERN``
(``^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$``, the same grammar alembic migration
``009_executor_id_constraints`` puts on the column as ``chk_user_id_format``). So
break-glass could hand an operator an account the product refuses to name:
``Ops_Admin`` recovers fine and then 422s at the admin user routes, and a
70-character value reaches the ``String(64)`` column and dies inside the
transaction as a 500 instead of being refused as a 422 before any write.

The mint site now validates against the ONE grammar, imported from its shared home
``server/utils/user_id.py`` rather than pasted a fourth time. Three halves are
pinned here: bad shapes are refused before anything is written (and before the
one-shot code is burned), the legitimate shape still recovers, and the two surfaces
AGREE — no ID is acceptable to recovery and unacceptable to the admin surface.
"""

import re
from pathlib import Path

import pytest
from core.iam.models import RoleMember, User
from pydantic import ValidationError
from server.routes import admin as admin_routes
from server.routes import recovery as recovery_routes
from server.routes.recovery import RecoveryRequest
from server.utils.user_id import USER_ID_PATTERN
from starlette.testclient import TestClient

from tests.test_recovery import _build_real_app, _create_test_app

#: Shapes the admin surface has always refused. Each is something an operator could
#: plausibly type at break-glass, and each used to land in users.user_id.
BAD_IDS = [
    "Ops_Admin",  # uppercase + underscore
    "OPS-ADMIN",  # uppercase
    "ops_admin",  # underscore
    "ops admin",  # space
    "-ops-admin",  # leading punctuation
    "ops-admin-",  # trailing punctuation
    "x",  # one character — the grammar needs a start AND an end alphanumeric
    "ops/admin",  # separators a later path would have to quote
    "ops.admin",
    "x" * 65,  # longer than the String(64) column and the grammar's ceiling
    "",  # empty
]

#: Shapes both surfaces accept, boundaries included.
GOOD_IDS = [
    "ops-admin",  # the ticket's paired positive
    "ab",  # shortest legal ID
    "recovered-2",  # interior hyphen + digit
    "x" * 64,  # exactly the column width, exactly the grammar's ceiling
]

GRAMMAR = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"


def _recovery_rejects(value: str) -> bool:
    """True when the recovery request model refuses this new_user_id."""
    try:
        RecoveryRequest(code="ANYCODE", new_user_id=value)
    except ValidationError as exc:
        assert any(e["loc"] == ("new_user_id",) for e in exc.errors()), exc.errors()
        return True
    return False


def _admin_rejects(value: str) -> bool:
    """True when the admin surface refuses this user_id (body-model form)."""
    try:
        admin_routes.AdminEnrollRequest(user_id=value)
    except ValidationError as exc:
        assert any(e["loc"] == ("user_id",) for e in exc.errors()), exc.errors()
        return True
    return False


class TestBadShapesRefusedAtTheModel:
    """AC1, first half: a shape the admin surface cannot address never gets in."""

    @pytest.mark.parametrize("value", BAD_IDS)
    def test_invalid_new_user_id_is_rejected(self, value):
        assert _recovery_rejects(value), f"recovery accepted {value!r}, which admin refuses"

    def test_rejection_names_the_field_and_is_a_shape_error(self):
        """The refusal says WHICH input died — an operator mid-break-glass needs that."""
        with pytest.raises(ValidationError) as excinfo:
            RecoveryRequest(code="ANYCODE", new_user_id="Ops_Admin")
        errors = excinfo.value.errors()
        assert [e["loc"] for e in errors] == [("new_user_id",)], errors
        assert errors[0]["type"] == "string_pattern_mismatch", errors[0]


class TestGoodShapesAccepted:
    """AC1, second half + AC3: the legitimate shape keeps working."""

    @pytest.mark.parametrize("value", GOOD_IDS)
    def test_valid_new_user_id_is_accepted(self, value):
        assert not _recovery_rejects(value), f"recovery refused the legitimate ID {value!r}"

    def test_boundary_lengths(self):
        """2 and 64 are legal, 1 and 65 are not: the grammar's ceiling IS the
        users.user_id column width, so neither can be outgrown."""
        assert not _recovery_rejects("ab")
        assert not _recovery_rejects("x" * 64)
        assert _recovery_rejects("x")
        assert _recovery_rejects("x" * 65)


class TestSurfacesAgree:
    """AC2's promise as a cross-surface truth table.

    What break-glass can mint must be exactly what the admin surface can address;
    a verdict mismatch in either direction is the bug this ticket filed.
    """

    @pytest.mark.parametrize("value", BAD_IDS + GOOD_IDS)
    def test_recovery_and_admin_reach_the_same_verdict(self, value):
        says_recovery, says_admin = _recovery_rejects(value), _admin_rejects(value)
        assert says_recovery == says_admin, f"{value!r}: recovery={says_recovery} admin={says_admin}"

    def test_one_shared_definition_three_users(self):
        """AC2: not a fourth copy of the regex. Both routes resolve to the SAME
        object in ``server.utils.user_id``."""
        assert recovery_routes.USER_ID_PATTERN is USER_ID_PATTERN
        assert admin_routes.USER_ID_PATTERN is USER_ID_PATTERN

    def test_wire_contract_carries_the_pattern(self):
        """The OpenAPI surface states the grammar, so a client learns it up front."""
        schema = RecoveryRequest.model_json_schema()
        assert schema["properties"]["new_user_id"]["pattern"] == USER_ID_PATTERN, schema

    def test_no_route_file_carries_its_own_copy_of_the_grammar(self):
        """Grep pin (the single-writer idiom): the expression lives in
        ``server/utils/user_id.py``, the executor twin, and the migration that put
        the CHECK on the column. A route re-pasting it is how the two surfaces
        drifted apart in the first place."""
        routes_dir = Path(recovery_routes.__file__).parent
        copies = {
            py.name: py.read_text().count(GRAMMAR)
            for py in sorted(routes_dir.glob("*.py"))
            if GRAMMAR in py.read_text()
        }
        assert copies == {}, f"a route file hard-codes the grammar again: {copies}"

    def test_shared_definition_matches_the_documented_grammar(self):
        """A drift guard on the constant itself, written out so any future edit to
        ``utils/user_id.py`` has to be a deliberate act."""
        assert USER_ID_PATTERN == GRAMMAR
        compiled = re.compile(GRAMMAR)
        assert compiled.match("ops-admin")
        assert not compiled.match("Ops-Admin")
        assert not compiled.match("x")
        assert not compiled.match("x" * 65)


class TestHttpRefusesBeforeAnyWrite:
    """AC1 at the HTTP layer, on the real SQLite stack test_recovery builds.

    A 422 is a validation-layer answer: the handler never runs, so nothing is
    written AND the one-shot code is not burned — the operator can retry with a
    legal ID. Retry-ability is the paired property these cells check.
    """

    def test_uppercase_id_is_422_and_nothing_is_written(self, tmp_path):
        client, SessionLocal, code = _build_real_app(tmp_path)

        resp = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "Ops_Admin"})

        assert resp.status_code == 422, resp.text
        with SessionLocal() as s:
            assert [u.user_id for u in s.query(User).all()] == ["oldadmin"], "a new admin was minted"
            assert s.query(RoleMember).count() == 1, "a membership was minted"
            # The code survives a shape refusal — otherwise the bad typo would cost
            # the operator their only break-glass credential.
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is not None

    def test_over_length_id_is_422_not_a_500(self, tmp_path):
        """The ticket's second half: 65 characters used to reach the column. A 422
        is the answer, never a value-too-long/CHECK violation inside the transaction."""
        client, SessionLocal, code = _build_real_app(tmp_path)

        resp = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "x" * 65})

        assert resp.status_code == 422, resp.text
        assert "value too long" not in resp.text.lower()
        with SessionLocal() as s:
            assert s.query(User).count() == 1

    def test_undeclared_key_still_422_beside_the_new_pattern(self):
        """PAIRED NEGATIVE for the neighbouring rule: the #371 extra=forbid sweep is
        untouched by this field's pattern — an undeclared key still dies loudly."""
        from unittest.mock import MagicMock

        app = _create_test_app(backend=MagicMock())
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/v1/recovery", json={"code": "c", "new_user_id": "ops-admin", "force": True})

        assert resp.status_code == 422, resp.text
        assert any(tuple(e["loc"]) == ("body", "force") for e in resp.json()["detail"]), resp.text

    def test_legal_id_still_recovers_after_a_refused_shape(self, tmp_path):
        """AC3: a refusal is not a dead end. Same code, legal ID, 200 — the admin
        and its membership exist, and THAT success burns the code."""
        client, SessionLocal, code = _build_real_app(tmp_path)

        assert client.post("/api/v1/recovery", json={"code": code, "new_user_id": "OPS"}).status_code == 422

        ok = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "ops-admin"})
        assert ok.status_code == 200, ok.text
        assert ok.json() == {"success": True, "action": "new_admin", "user_id": "ops-admin"}

        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "ops-admin").count() == 1
            assert s.query(RoleMember).filter(RoleMember.user_id == "ops-admin").count() == 1
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is None


class TestRecoveredAdminIsAddressableByTheAdminSurface:
    """The point of the ticket, driven through a real route.

    The admin user route is mounted with its own path grammar; the ID break-glass
    mints is nameable there, and the shape that used to be mintable is refused on
    BOTH sides. Only ``require_admin`` is overridden (its role lookup is a different
    ticket's surface) — the path validation under test is the route's own.
    """

    def _stack(self, tmp_path):
        from server.dependencies import require_admin

        client, SessionLocal, code = _build_real_app(tmp_path)
        app = client.app
        app.include_router(admin_routes.router, prefix="/api/v1")
        app.dependency_overrides[require_admin] = lambda: {"caller": "admin", "user_id": "oldadmin"}
        return client, SessionLocal, code

    def test_minted_id_names_a_route_that_accepts_it(self, tmp_path):
        client, SessionLocal, code = self._stack(tmp_path)

        minted = client.post("/api/v1/recovery", json={"code": code, "new_user_id": "ops-admin"})
        assert minted.status_code == 200, minted.text

        # The shape that used to be mintable is refused on the admin side too...
        refused = client.delete("/api/v1/admin/users/Ops_Admin")
        assert refused.status_code == 422, refused.text
        # ...and the ID that WAS minted is addressable: the same route takes it, and
        # the removal runs to completion. oldadmin still holds admin, so the #443
        # last-admin lockout guard does not fire here.
        answer = client.delete("/api/v1/admin/users/ops-admin")
        assert answer.status_code == 200, answer.text
        with SessionLocal() as s:
            assert s.query(User).filter(User.user_id == "ops-admin").count() == 0
            assert s.query(User).filter(User.user_id == "oldadmin").count() == 1


class TestFieldContractUnchanged:
    """The field keeps everything else it was: required, a plain string on the wire,
    and the model still forbids undeclared keys."""

    def test_field_is_still_required(self):
        with pytest.raises(ValidationError) as excinfo:
            RecoveryRequest(code="ANYCODE")
        assert any(e["loc"] == ("new_user_id",) and e["type"] == "missing" for e in excinfo.value.errors())

    def test_pattern_is_not_a_length_cap_on_the_python_side(self):
        """The grammar does the bounding; no separate max_length was added, so the
        String(64) column keeps exactly one mirror."""
        import typing

        hints = typing.get_type_hints(RecoveryRequest)
        assert hints["new_user_id"] is str
