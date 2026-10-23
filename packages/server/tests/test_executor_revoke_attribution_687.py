# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#687 — a duplicate serial-form revoke is attributed to the revocation ROW's owner.

The defect (owner assessment 2026-10-21, `wave34-specs-20261021/owner-687-assessment-fix-s155.md`):
`admin_revoke_executor`'s serial arm answers the already-revoked case at the idempotency lookup,
which sits BEFORE the #685 population/pairing gate. So the `executor_id` it wrote into
`EXECUTOR_CERT_REVOKED` was the caller's path value, checked against nothing — and `audit_events` is
append-only, so an admin could pin any executor's name onto a permanent record with one repeat call.
The event's EXISTENCE was correct; the FIELD VALUE was the defect.

Ruled shape, implemented as written: emit `existing.executor_id` (the value the original, gated
revocation stored); when the path value disagrees, keep the attempt on the record as
`requested_executor_id` + `executor_id_mismatch`; correct the response in parallel so the client is
not fed the value the log refused to write. #301/#481 idempotency semantics are unchanged — the
attempt still emits, the no-op is still visible. No retroactive correction of written events: the
suspect class is self-labeled (`already_revoked: True`) and joinable to truth.

Truth table (paired, per the AGENTS truth-table rule). `S` = the serial, `A` = who really held it:

| revocation row for S | path executor_id | stored owner | event names | payload mismatch keys | response |
|---|---|---|---|---|---|
| present | A (correct) | A | A | ABSENT (byte-identical to the pre-fix face) | A, 3 keys only |
| present | B (fabricated) | A | **A** | `requested_executor_id=B`, `executor_id_mismatch=True` | **A** + the pair |
| present, NO `ExecutorCert` row for S (rotation overwrote it) | B | A | **A** | pair present | **A** |
| present | B | NULL (alembic 002 allows it) | B | ABSENT — no stored truth to prefer | B |

Rotation is the case that would bite a cert-sourced fix, and it is tested here rather than argued:
`routes/executors.py:1215-1216` (`# Update existing cert record`) OVERWRITES the one
`ExecutorCert` row an executor has, so after a rotation the predecessor serial lives ONLY in
`ExecutorCertRevocation` — which is exactly where the stored owner is read from.

Real SQLite on the sibling module's `env` fixture (FKs on, `require_admin` overridden), house
precedent (`test_executor_serial_membership_685.py`). No guest, no network.
"""

import json
from datetime import UTC, datetime, timedelta

from core.iam.models import AuditEvent, ExecutorCert, ExecutorCertRevocation
from core.utils.cert_serial import canonical_serial

try:
    from .test_executor_revocation_identity import _seed_cert, _seed_executor, env  # re-exported fixture
except ImportError:  # pytest rootdir/tests-path import mode
    from test_executor_revocation_identity import (  # house precedent, see module docstring
        _seed_cert,
        _seed_executor,
        env,  # noqa: F401
    )

A = "exec-a"
B = "exec-b"
S = "0000000000001000"  # the serial under test — A's credential
AFTER = "0000000000002000"  # the serial A's record row holds AFTER a rotation
URL_TPL = "/api/v1/admin/executors/{}/revoke"
_UNSET = object()  # "default the owner to the holder" — distinct from NULL_OWNER below
NULL_OWNER = None  # the nullable-column case, stored as SQL NULL

# --- THE PRE-FIX FACE, captured at base 802bbbd by a temporary probe, not recalled.
# A correctly-paired repeat sent exactly these bytes; negative 2 compares against them.
PRE_FIX_BODY = {"executor_id": A, "revoked": False, "serial_number": S}
PRE_FIX_PAYLOAD = {"executor_id": A, "serial_number": S, "already_revoked": True}


def _certs(s, executor_id):
    return s.query(ExecutorCert).filter_by(executor_id=executor_id).all()


def _revoke_events(s):
    rows = s.query(AuditEvent).filter_by(event_type="executor_cert_revoked").all()
    return [json.loads(r.fields) if isinstance(r.fields, str) else r.fields for r in rows]


def _seed_holder_with_revoked_serial(SessionLocal, executor_id=A, serial=S, owner=_UNSET):
    """A real holder whose serial is ALREADY in the revocation table, the way a genuine
    first revocation leaves it: the certificate population row, the executors row, and the
    revocation row naming `owner` (default: the true holder; pass `NULL_OWNER` for a row that
    names no owner — the nullable-column case, which is NOT the same as omitting the argument)."""
    _seed_executor(SessionLocal, executor_id)
    _seed_cert(SessionLocal, executor_id=executor_id, serial=serial)
    s = SessionLocal()
    s.add(
        ExecutorCertRevocation(
            serial_number=canonical_serial(serial),
            executor_id=executor_id if owner is _UNSET else owner,
            reason="Admin revocation (serial form)",
        )
    )
    s.commit()
    s.close()


class TestFabricatedPairing:
    """Negative 1: a duplicate submitted under a path value that is NOT the owner."""

    def test_event_and_response_both_name_the_stored_owner_not_the_path(self, env):
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S)
        _seed_executor(SessionLocal, B)  # a real executor, framed by someone else's call

        resp = client.post(URL_TPL.format(B), json={"serial": S})

        assert resp.status_code == 200  # no status-code change, ruled
        body = resp.json()
        assert body["revoked"] is False  # the no-op is still visible (#301)
        assert body["executor_id"] == A, "the response must not carry the caller's claim"
        assert body["requested_executor_id"] == B
        assert body["executor_id_mismatch"] is True

        events = _revoke_events(SessionLocal())
        assert len(events) == 1, "the attempt is still recorded — 409-and-drop was rejected"
        payload = events[0]
        assert payload["executor_id"] == A, "the append-only row names the true holder"
        assert payload["requested_executor_id"] == B, "and the attempt itself stays on the record"
        assert payload["executor_id_mismatch"] is True
        assert payload["already_revoked"] is True
        assert payload["serial_number"] == canonical_serial(S)

    def test_the_framed_executor_is_untouched(self, env):
        """PAIRED: naming B in the path must not revoke, or even mark, B."""
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S)
        _seed_executor(SessionLocal, B)

        client.post(URL_TPL.format(B), json={"serial": S})

        s = SessionLocal()
        try:
            assert len(_certs(s, B)) == 0, "the attempt must not create or touch B's credential"
            # and A's revocation row is neither doubled nor rewritten
            assert s.query(ExecutorCertRevocation).filter_by(serial_number=canonical_serial(S)).count() == 1
        finally:
            s.close()

    def test_a_path_value_in_no_table_at_all_is_still_answered_and_recorded(self, env):
        """The wholly-invented identity: the arm answers (idempotency is unchanged), and the
        record names A while `requested_executor_id` names the nobody that was asked for."""
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S)

        resp = client.post(URL_TPL.format("no-such-exec"), json={"serial": S})

        assert resp.status_code == 200
        assert resp.json()["executor_id"] == A
        assert resp.json()["requested_executor_id"] == "no-such-exec"
        payload = _revoke_events(SessionLocal())[0]
        assert payload["executor_id"] == A
        assert payload["requested_executor_id"] == "no-such-exec"


class TestCorrectRetryIsByteIdentical:
    """Negative 2: the legitimate repeat must not move at all.

    Compared against literals captured at the base commit by a probe run, not against a
    reconstruction of what the old code did — "nothing changed" is not evidence, a diff is.
    """

    def test_repeat_under_the_true_owner_sends_the_pre_fix_body(self, env):
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S)

        resp = client.post(URL_TPL.format(A), json={"serial": S})

        assert resp.status_code == 200
        assert resp.json() == PRE_FIX_BODY, "no new keys on the correct face, no dropped ones"

    def test_repeat_under_the_true_owner_writes_the_pre_fix_payload(self, env):
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S)

        client.post(URL_TPL.format(A), json={"serial": S})

        assert _revoke_events(SessionLocal()) == [PRE_FIX_PAYLOAD]

    def test_the_first_revocation_still_answers_as_it_did(self, env):
        """The non-duplicate arm is untouched by this change — same body, same flag, same row."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, A)
        _seed_cert(SessionLocal, executor_id=A, serial=S)

        resp = client.post(URL_TPL.format(A), json={"serial": S})

        assert resp.status_code == 200 and resp.json() == {
            "revoked": True,
            "executor_id": A,
            "serial_number": canonical_serial(S),
        }


class TestRotationCase:
    """Negative 3 — the one that actually bites.

    Rotation OVERWRITES the single `ExecutorCert` row (`routes/executors.py:1215-1216`), so the
    predecessor serial survives only in `ExecutorCertRevocation`. A fix that sourced the owner from
    the certificate table would find nothing here and would re-accept the caller's claim.
    """

    def test_predecessor_serial_with_no_surviving_cert_row_still_names_its_owner(self, env):
        client, SessionLocal = env
        _seed_executor(SessionLocal, A)
        s = SessionLocal()
        # the post-rotation face: A's ONE record row now holds AFTER; S is in no certificate table,
        # and its revocation row (written by the rotation auto-revoke) names A.
        s.add(
            ExecutorCert(
                executor_id=A,
                serial_number=AFTER,
                not_before=datetime.now(UTC),
                not_after=datetime.now(UTC) + timedelta(days=30),
                fingerprint="AA:BB:CC",
            )
        )
        s.add(
            ExecutorCertRevocation(
                serial_number=canonical_serial(S), executor_id=A, reason="Replaced by re-registration/rotation"
            )
        )
        s.commit()
        s.close()
        _seed_executor(SessionLocal, B)

        resp = client.post(URL_TPL.format(B), json={"serial": S})

        assert resp.status_code == 200 and resp.json()["revoked"] is False
        assert resp.json()["executor_id"] == A
        assert resp.json()["executor_id_mismatch"] is True

        s = SessionLocal()
        try:
            # proof the shape is the rotation shape, not a fixture accident: S holds no certificate
            assert s.query(ExecutorCert).filter_by(serial_number=canonical_serial(S)).count() == 0
            payload = _revoke_events(s)[0]
            assert payload["executor_id"] == A, "owner came from the revocation table"
            assert payload["requested_executor_id"] == B
        finally:
            s.close()

    def test_rotation_repeat_under_the_real_owner_stays_clean(self, env):
        """PAIRED: the legitimate incident-response retry on that same orphaned predecessor serial
        gains no mismatch keys and answers with the three-key body."""
        client, SessionLocal = env
        _seed_executor(SessionLocal, A)
        s = SessionLocal()
        s.add(
            ExecutorCertRevocation(
                serial_number=canonical_serial(S), executor_id=A, reason="Replaced by re-registration/rotation"
            )
        )
        s.commit()
        s.close()

        resp = client.post(URL_TPL.format(A), json={"serial": S})

        assert resp.json() == PRE_FIX_BODY


class TestNullOwnerRowStandsAsBefore:
    """The column is nullable (alembic `002_executor_cert_revocations`), so a row may name no
    owner. There is no stored truth to prefer — the path value stands, and NO mismatch flag is
    raised, because nothing on this side disagrees. Pinned so the branch is not later "fixed" into
    a false accusation of every legacy row."""

    def test_a_row_naming_no_owner_does_not_flag_a_mismatch(self, env):
        client, SessionLocal = env
        _seed_holder_with_revoked_serial(SessionLocal, A, S, owner=NULL_OWNER)

        resp = client.post(URL_TPL.format(B), json={"serial": S})

        assert resp.status_code == 200
        assert "executor_id_mismatch" not in resp.json()
        assert "requested_executor_id" not in resp.json()
        payload = _revoke_events(SessionLocal())[0]
        assert payload["executor_id"] == B
        assert "executor_id_mismatch" not in payload
