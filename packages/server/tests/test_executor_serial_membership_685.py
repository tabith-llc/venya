# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#685 — `admin revoke-executor` SERIAL form must consult the credential population.

The defect (probe table in `wave33-specs-20261020/flash1-684-fix-244-report.md`, rows A and C):
the serial arm's only lookup before `db.add(ExecutorCertRevocation(...))` was the idempotency
query, so a serial NO certificate holds was accepted with 200 + a stored row, and a path
`executor_id` present in no table was accepted too — a revocation attributed to nothing that
revoked nothing. The identity arm (probe D) already refused via `ExecutorCert`; this file pins
the serial arm to the same population.

Truth table (every accept paired with its reject, per the AGENTS truth-table rule):

| serial in `ExecutorCert` | path executor_id holds it | already revoked | outcome |
|---|---|---|---|
| yes | yes | no | 200 `revoked=true`, row written, audit written |
| yes | yes | yes | 200 `revoked=false`, one row (idempotency UNCHANGED, #301/#481) |
| yes | no (other executor) | no | **404**, nothing written, nothing audited |
| no | — | no | **404**, nothing written, nothing audited |
| no | — | yes | 200 `revoked=false` — the shipped repeat face, ordered before the gate on purpose |
| — | — | — | identity form → **404** for an unknown executor, unchanged |

Membership is decided with the shipped `serial_match_clause` (#481), never a raw string compare,
so a legacy unpadded/uppercase record row is still found; and every teardown here deletes by the
CANONICAL form the route stores, which is the instrument defect a prior worker lane hit when its first cleanup
filtered the typed spelling and deleted zero rows.

Real SQLite on the shipped `env` fixture (FKs on, `require_admin` overridden) — sibling-module
helper import is house precedent (`test_admin_revocation_read_bound_658.py:67`,
`test_require_role_executor_refusal_449.py:212`). No guest, no network: the store is a
per-cell `tmp_path` file.
"""

from core.iam.models import AuditEvent, Executor, ExecutorCertRevocation
from core.utils.cert_serial import canonical_serial

try:  # the shape the sibling cell that does this already uses (test_admin_revocation_read_bound_658.py:54-72)
    from .test_executor_revocation_identity import (
        _seed_cert,
        _seed_executor,
        _seed_revocation,
        env,  # re-exported: the cells below take it as a fixture
    )
except ImportError:  # pytest rootdir/tests-path import mode
    from test_executor_revocation_identity import (  # house precedent, see module docstring
        _seed_cert,
        _seed_executor,
        _seed_revocation,
        env,  # noqa: F401
    )

EXECUTOR_ID = "exec-a"
RECORDED = "0000000000001000"  # the serial the seeded credential actually holds
UNKNOWN = "0000000000000abc"  # held by no certificate in any cell below
OTHER_EXECUTOR = "exec-b"  # a real executor that does not hold RECORDED
URL_TPL = "/api/v1/admin/executors/{}/revoke"


def _revocation_rows(s, serial):
    """Read back by the CANONICAL form, never the spelling typed into the request."""
    return s.query(ExecutorCertRevocation).filter_by(serial_number=canonical_serial(serial)).all()


def _audit_rows(s):
    return s.query(AuditEvent).filter_by(event_type="executor_cert_revoked").all()


def _store_face(s):
    return sorted(r.serial_number for r in s.query(ExecutorCertRevocation).all())


class TestSerialFormMembershipGate:
    def test_recorded_serial_of_a_real_executor_is_revoked(self, env):
        """Positive half: the legitimate arm still works, row + audit both written."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": RECORDED})
        assert resp.status_code == 200 and resp.json()["revoked"] is True

        s = SessionLocal()
        try:
            assert len(_revocation_rows(s, RECORDED)) == 1
            assert len(_audit_rows(s)) == 1
            # the a722 intent the pre-existing cell carried, kept here: the serial arm kills
            # the CREDENTIAL and leaves the IDENTITY alone.
            assert s.query(Executor).filter_by(id=EXECUTOR_ID).first().revoked_at is None
        finally:
            s.close()

    def test_unknown_serial_on_a_real_executor_is_refused(self, env):
        """Probe A, now refused: a serial no certificate holds writes NOTHING.

        This is the cell that pins the defect — before the gate it read 200 + one row.
        """
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": UNKNOWN})
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert UNKNOWN in detail  # AC2: the sentence names WHAT was unknown

        s = SessionLocal()
        try:
            assert _store_face(s) == [], "a refused serial must not persist"
            assert _revocation_rows(s, UNKNOWN) == []
            assert len(_audit_rows(s)) == 0  # AC4: no audit row on a refusal
            # the identity it was aimed at is untouched, and so is the real credential
            assert s.query(Executor).filter_by(id=EXECUTOR_ID).first().revoked_at is None
        finally:
            s.close()

    def test_fabricated_executor_id_with_a_real_serial_is_refused(self, env):
        """Probe C's shape on the executor plane: the serial exists, but not for this identity.

        Writing this row would attribute another executor's credential to an identity that
        never held it — the same attribution defect as probe A, arriving from the other end.
        """
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)
        _seed_executor(SessionLocal, OTHER_EXECUTOR)
        _seed_cert(SessionLocal, executor_id=OTHER_EXECUTOR, serial="0000000000002000")

        resp = client.post(URL_TPL.format(OTHER_EXECUTOR), json={"serial": RECORDED})
        assert resp.status_code == 404

        s = SessionLocal()
        try:
            assert _store_face(s) == []
            assert len(_audit_rows(s)) == 0
            # the true holder is not revoked by someone else's attempt
            assert s.query(Executor).filter_by(id=EXECUTOR_ID).first().revoked_at is None
        finally:
            s.close()

    def test_executor_id_in_no_table_is_refused(self, env):
        """The wholly-fabricated identity: neither the serial nor the id resolves."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format("no-such-exec"), json={"serial": UNKNOWN})
        assert resp.status_code == 404

        s = SessionLocal()
        try:
            assert _store_face(s) == []
            assert len(_audit_rows(s)) == 0
        finally:
            s.close()


class TestSerialFormIdempotencyUnchanged:
    """AC3 last half: the repeat face is shipped behavior (#301 Q3, #481) and must not move."""

    def test_already_revoked_serial_is_still_idempotent(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        first = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": RECORDED})
        assert first.status_code == 200 and first.json()["revoked"] is True
        second = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": RECORDED})
        assert second.status_code == 200 and second.json()["revoked"] is False

        s = SessionLocal()
        try:
            assert len(_revocation_rows(s, RECORDED)) == 1, "no duplicate row"
        finally:
            s.close()

    def test_repeat_of_a_legacy_blind_row_is_still_idempotent(self, env):
        """Rows the defect ALREADY wrote must keep reading as repeats, not turn into 404s.

        This is why the gate is ordered AFTER the idempotency lookup: a serial that is in the
        revocation table but in no certificate is a known-and-done revocation, and re-sending it
        is the operator checking, not a fresh attempt to revoke nothing.
        """
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_revocation(SessionLocal, UNKNOWN, executor_id=EXECUTOR_ID, reason="legacy blind insert")

        resp = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": UNKNOWN})
        assert resp.status_code == 200 and resp.json()["revoked"] is False

        s = SessionLocal()
        try:
            assert len(_revocation_rows(s, UNKNOWN)) == 1, "the legacy row is neither doubled nor removed"
        finally:
            s.close()


class TestSerialFormCanonicalization:
    """AC5: membership is decided by the #481 match key, so spelling cannot hide a credential."""

    def test_legacy_unpadded_record_row_is_found_by_the_canonical_request(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial="a1b2c3d4e5f6071")  # stored unpadded

        # typed padded-lowercase, the canonical spelling; the record row is the legacy face
        resp = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": "0a1b2c3d4e5f6071"})
        assert resp.status_code == 200 and resp.json()["revoked"] is True

        s = SessionLocal()
        try:
            assert len(_revocation_rows(s, "0a1b2c3d4e5f6071")) == 1  # pragma: allowlist secret
        finally:
            s.close()

    def test_uppercase_typed_serial_resolves_to_the_lowercase_record(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format(EXECUTOR_ID), json={"serial": RECORDED.upper()})
        assert resp.status_code == 200 and resp.json()["revoked"] is True

        s = SessionLocal()
        try:
            # the row lands in the ONE canonical form the route stores, whatever was typed
            assert len(_revocation_rows(s, RECORDED)) == 1
        finally:
            s.close()


class TestIdentityArmUnchanged:
    """AC3 last clause: prove the identity arm's 404 still fires — this fix must not move it."""

    def test_identity_form_unknown_executor_still_404s(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format("no-such-exec"), json=None)
        assert resp.status_code == 404
        assert "no-such-exec" in resp.json()["detail"]

        s = SessionLocal()
        try:
            assert _store_face(s) == []
        finally:
            s.close()

    def test_identity_form_known_executor_still_revokes(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, EXECUTOR_ID)
        _seed_cert(SessionLocal, executor_id=EXECUTOR_ID, serial=RECORDED)

        resp = client.post(URL_TPL.format(EXECUTOR_ID), json=None)
        assert resp.status_code == 200 and resp.json()["revoked"] is True

        s = SessionLocal()
        try:
            assert len(_revocation_rows(s, RECORDED)) == 1
            assert s.query(Executor).filter_by(id=EXECUTOR_ID).first().revoked_at is not None
        finally:
            s.close()
