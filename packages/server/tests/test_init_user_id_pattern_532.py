# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the first-admin bootstrap ID grammar (#532).

``InitRequest.user_id`` and ``InitCompleteRequest.user_id`` were bare ``str``
fields. Both values land in ``users.user_id`` (``String(64)``) and in the
``RoleMember`` row, while the surface that later has to ADDRESS that admin —
``routes/admin.py`` — requires ``USER_ID_PATTERN`` (the same grammar alembic
migration ``009_executor_id_constraints`` puts on the column as
``chk_user_id_format``). So the bootstrap could mint an admin the product
refuses to name: ``Ops_Admin`` inits fine and then 422s at the admin routes,
and a 65-character value reaches the column and dies inside the transaction.

This mirrors ``test_recovery_user_id_pattern_517.py`` (the #517 shape) across
BOTH init models: bad shapes are refused with a 422 BEFORE any write (no user
row, no role, no membership, no session), the legitimate shape still bootstraps
end to end, and the init / recovery / admin surfaces agree because all three
read the ONE definition in ``server/utils/user_id.py`` — no fourth copy.
"""

import re
from pathlib import Path

import pytest
from core.iam.models import Role, RoleMember, User, WebAuthnCredential
from core.iam.models import Session as SessionModel
from pydantic import ValidationError
from server.routes import admin as admin_routes
from server.routes import init as init_routes
from server.routes import recovery as recovery_routes
from server.routes.init import InitCompleteRequest, InitRequest
from server.routes.recovery import RecoveryRequest
from server.utils.user_id import USER_ID_PATTERN

from tests.test_init_concurrent_admin_510 import _complete, _seed_roles, _stack

#: Shapes the admin surface has always refused (the #517 list, reused verbatim
#: so the two tickets test the SAME shape set). Each used to be bootstrapable.
BAD_IDS = [
    "Ops_Admin",  # uppercase + underscore
    "OPS-ADMIN",  # uppercase
    "ops_admin",  # underscore
    "ops admin",  # interior space
    "-ops-admin",  # leading punctuation
    "ops-admin-",  # trailing punctuation
    "x",  # one character — the grammar needs a start AND an end alphanumeric
    "ops/admin",  # separators a later path would have to quote
    "ops.admin",
    "x" * 65,  # longer than the String(64) column and the grammar's ceiling
    "",  # empty
]

#: Shapes every surface accepts, boundaries included.
GOOD_IDS = [
    "ops-admin",  # the ticket's paired positive
    "ab",  # shortest legal ID
    "recovered-2",  # interior hyphen + digit
    "x" * 64,  # exactly the column width, exactly the grammar's ceiling
]

GRAMMAR = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"


def _step1_rejects(value: str) -> bool:
    """True when init step 1 refuses this user_id."""
    try:
        InitRequest(user_id=value)
    except ValidationError as exc:
        assert any(e["loc"] == ("user_id",) for e in exc.errors()), exc.errors()
        return True
    return False


def _step2_rejects(value: str) -> bool:
    """True when init step 2 refuses this user_id."""
    try:
        InitCompleteRequest(user_id=value, challenge_id="c", response={})
    except ValidationError as exc:
        assert any(e["loc"] == ("user_id",) for e in exc.errors()), exc.errors()
        return True
    return False


def _recovery_rejects(value: str) -> bool:
    try:
        RecoveryRequest(code="ANYCODE", new_user_id=value)
    except ValidationError:
        return True
    return False


def _admin_rejects(value: str) -> bool:
    try:
        admin_routes.AdminEnrollRequest(user_id=value)
    except ValidationError:
        return True
    return False


class TestBadShapesRefusedAtTheModel:
    """AC1/AC2, first half: a shape the admin surface cannot address never gets
    in — on BOTH init models, because the tip carries two, not one."""

    @pytest.mark.parametrize("value", BAD_IDS)
    def test_step1_invalid_user_id_is_rejected(self, value):
        assert _step1_rejects(value), f"InitRequest accepted {value!r}, which admin refuses"

    @pytest.mark.parametrize("value", BAD_IDS)
    def test_step2_invalid_user_id_is_rejected(self, value):
        assert _step2_rejects(value), f"InitCompleteRequest accepted {value!r}, which admin refuses"

    def test_rejection_names_the_field_and_is_a_shape_error(self):
        """The refusal says WHICH input died — a bootstrap operator needs that."""
        for model in (InitRequest, InitCompleteRequest):
            kwargs = {"user_id": "Ops_Admin"}
            if model is InitCompleteRequest:
                kwargs.update(challenge_id="c", response={})
            with pytest.raises(ValidationError) as excinfo:
                model(**kwargs)
            errors = excinfo.value.errors()
            assert [e["loc"] for e in errors] == [("user_id",)], (model.__name__, errors)
            assert errors[0]["type"] == "string_pattern_mismatch", (model.__name__, errors[0])


class TestGoodShapesAccepted:
    """AC1/AC2, second half: the legitimate shape still bootstraps, boundaries
    included. 2 and 64 are legal, 1 and 65 are not — the grammar's ceiling IS
    the users.user_id column width."""

    @pytest.mark.parametrize("value", GOOD_IDS)
    def test_step1_valid_user_id_is_accepted(self, value):
        assert not _step1_rejects(value), f"InitRequest refused the legitimate ID {value!r}"

    @pytest.mark.parametrize("value", GOOD_IDS)
    def test_step2_valid_user_id_is_accepted(self, value):
        assert not _step2_rejects(value), f"InitCompleteRequest refused the legitimate ID {value!r}"

    def test_boundary_lengths(self):
        for rejects in (_step1_rejects, _step2_rejects):
            assert not rejects("ab")
            assert not rejects("x" * 64)
            assert rejects("x")
            assert rejects("x" * 65)


class TestSurfacesAgree:
    """AC3: what the bootstrap can mint is exactly what the admin surface can
    address, and step 2 agrees with step 1 — one shape set, four models, zero
    verdict mismatches."""

    @pytest.mark.parametrize("value", BAD_IDS + GOOD_IDS)
    def test_all_four_surfaces_reach_the_same_verdict(self, value):
        says_step1 = _step1_rejects(value)
        assert _step2_rejects(value) == says_step1, f"{value!r}: step2 disagrees with step1"
        says_recovery, says_admin = _recovery_rejects(value), _admin_rejects(value)
        assert (
            says_recovery == says_admin == says_step1
        ), f"{value!r}: init={says_step1} recovery={says_recovery} admin={says_admin}"

    def test_one_shared_definition_four_users(self):
        """Not a fifth copy of the regex: every route resolves to the SAME object
        in ``server.utils.user_id``."""
        assert init_routes.USER_ID_PATTERN is USER_ID_PATTERN
        assert recovery_routes.USER_ID_PATTERN is USER_ID_PATTERN
        assert admin_routes.USER_ID_PATTERN is USER_ID_PATTERN

    def test_wire_contract_carries_the_pattern(self):
        """AC4: the OpenAPI surface states the grammar for BOTH init models, so a
        client learns it up front."""
        for model in (InitRequest, InitCompleteRequest):
            schema = model.model_json_schema()
            assert schema["properties"]["user_id"]["pattern"] == USER_ID_PATTERN, (model.__name__, schema)

    def test_no_route_file_carries_its_own_copy_of_the_grammar(self):
        """The #517 sweep guard's own rule, restated for this change: init.py sits
        inside the guard's ``routes/*.py`` glob, so the fix imports the shared
        constant rather than pasting it — and this cell proves the copy count
        stays zero with the new pattern in place."""
        routes_dir = Path(recovery_routes.__file__).parent
        scanned = {py.name for py in routes_dir.glob("*.py")}
        assert "init.py" in scanned, "the #517 guard does not see init.py — extend its scan set"
        copies = {
            py.name: py.read_text().count(GRAMMAR)
            for py in sorted(routes_dir.glob("*.py"))
            if GRAMMAR in py.read_text()
        }
        assert copies == {}, f"a route file hard-codes the grammar again: {copies}"

    def test_shared_definition_matches_the_documented_grammar(self):
        """Drift guard on the constant itself (the #517 cell, inherited)."""
        assert USER_ID_PATTERN == GRAMMAR
        compiled = re.compile(GRAMMAR)
        assert compiled.match("ops-admin")
        assert not compiled.match("Ops-Admin")
        assert not compiled.match("x")
        assert not compiled.match("x" * 65)


class TestHttpRefusesBeforeAnyWrite:
    """AC1/AC2 at the HTTP layer, on the real SQLite stack #510 built for init.

    A 422 is a validation-layer answer: the handler never runs, so no user, no
    role, no membership, no session — and the fresh core stays uninitialized
    (the paired property: a refused typo costs nothing and is retryable).
    """

    def test_step1_uppercase_id_is_422_and_nothing_is_written(self, tmp_path):
        client, SessionLocal, _fido = _stack(tmp_path)

        resp = client.post("/api/v1/init", json={"user_id": "Ops_Admin"})

        assert resp.status_code == 422, resp.text
        with SessionLocal() as s:
            assert s.query(User).count() == 0, "a pending admin was minted"
            assert s.query(Role).count() == 0, "a role was seeded by the refused request"
            assert s.query(RoleMember).count() == 0, "a membership was minted"
            assert s.query(SessionModel).count() == 0, "a session was minted"

    def test_step1_over_length_id_is_422_not_a_500(self, tmp_path):
        """65 characters used to reach the column. A 422 is the answer, never a
        value-too-long/CHECK violation inside the transaction."""
        client, SessionLocal, _fido = _stack(tmp_path)

        resp = client.post("/api/v1/init", json={"user_id": "x" * 65})

        assert resp.status_code == 422, resp.text
        assert "value too long" not in resp.text.lower()
        with SessionLocal() as s:
            assert s.query(User).count() == 0

    @pytest.mark.parametrize("value", BAD_IDS)
    def test_step2_bad_shape_is_422_and_no_pending_row_is_enrolled(self, tmp_path, value):
        """Step 2's half: with a legitimate pending admin seeded, a bad-shape
        submission dies at the model — the pending row keeps its ``enrolled_at``
        of None and stores no credential or recovery hash. 422 (not the 400 a
        consumed-challenge ceremony would give) proves nothing handler-side ran."""

        def seed(s):
            _seed_roles(s)
            admin_role = s.query(Role).filter_by(name="admin").one()
            s.add(User(user_id="ops-admin", auth_mode="security-key", enrolled_at=None))
            s.add(RoleMember(user_id="ops-admin", role_id=admin_role.id))
            s.commit()

        client, SessionLocal, _fido = _stack(tmp_path, seed=seed)

        resp = client.post(
            "/api/v1/init/complete",
            json={
                "user_id": value,
                "challenge_id": "challenge-ops-admin",
                "response": {"id": "dGVzdC1jcmVk", "rawId": "dGVzdC1jcmVk"},
            },
        )

        assert resp.status_code == 422, resp.text
        with SessionLocal() as s:
            user = s.query(User).filter(User.user_id == "ops-admin").one()
            assert user.enrolled_at is None, "a bad-shape submission enrolled the pending admin"
            assert user.recovery_code_hash is None, "a bad-shape submission issued a recovery code"
            assert s.query(WebAuthnCredential).count() == 0, "a bad-shape submission stored a credential"

    def test_valid_id_still_bootstraps_after_a_refused_shape(self, tmp_path):
        """AC2 + AC6: a refusal is not a dead end. Same fresh core, legal ID,
        201 — and the two-step flow then completes end to end."""
        client, SessionLocal, fido = _stack(tmp_path)

        assert client.post("/api/v1/init", json={"user_id": "Ops"}).status_code == 422

        ok = client.post("/api/v1/init", json={"user_id": "ops-admin"})
        assert ok.status_code == 201, ok.text
        assert ok.json()["user_id"] == "ops-admin"

        # Step 2 completes the ceremony the fresh 201 issued.
        fido.start_registration(user_id="ops-admin", username="ops-admin")
        done = _complete(client, "ops-admin")
        assert done.status_code == 201, done.text
        with SessionLocal() as s:
            user = s.query(User).filter(User.user_id == "ops-admin").one()
            assert user.enrolled_at is not None
            assert s.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == "ops-admin").count() == 1


class TestFieldContractUnchanged:
    """The fields keep everything else they were: required, a plain string on
    the wire, extra=forbid intact, and — matching the #517 precedent — NO
    separate max_length: the pattern does the bounding so the String(64)
    column keeps exactly one mirror."""

    def test_fields_are_still_required(self):
        with pytest.raises(ValidationError) as excinfo:
            InitRequest()
        assert any(e["loc"] == ("user_id",) and e["type"] == "missing" for e in excinfo.value.errors())
        with pytest.raises(ValidationError) as excinfo:
            InitCompleteRequest(challenge_id="c", response={})
        assert any(e["loc"] == ("user_id",) and e["type"] == "missing" for e in excinfo.value.errors())

    def test_pattern_is_not_a_length_cap_on_the_python_side(self):
        import typing

        for model in (InitRequest, InitCompleteRequest):
            hints = typing.get_type_hints(model)
            assert hints["user_id"] is str

    def test_undeclared_key_still_422_beside_the_new_pattern(self, tmp_path):
        """PAIRED NEGATIVE for the neighbouring rule: the #357 extra=forbid sweep
        is untouched by this field's pattern."""
        client, _SessionLocal, _fido = _stack(tmp_path)

        resp = client.post("/api/v1/init", json={"user_id": "ops-admin", "force": True})

        assert resp.status_code == 422, resp.text
        assert any(tuple(e["loc"]) == ("body", "force") for e in resp.json()["detail"]), resp.text
