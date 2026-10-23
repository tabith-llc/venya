# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""FIDO2 ceremony challenge state is process-portable (#534).

The defect: a pending WebAuthn challenge lived in a per-process
Fido2Store._challenges dict, so a core restart between issuance and the
verifier's response killed the ceremony (401 "Challenge not found or
expired"), and any future worker-hop routing failed the same way. The
sibling fix (#528, elevation_challenges) moved the auth-binding half of the
ceremony to the database; this file pins the protocol half.

The cells mirror the 528 shape: each "worker" is its own engine plus its
own Fido2Manager over the same SQLite file, so a challenge issued by A is
genuinely claimed by B through shared storage rather than a lucky
same-process global. A restart is modelled by disposing the engine and
building a fresh one.

Truth-table pairs: cross-worker claim ACCEPTED / second claim (already
consumed) REFUSED with an audit row; unknown, expired, and already-consumed
ids refuse with the SAME message and the SAME value-free audit shape (AC2 —
no oracle on which half failed, no challenge id or ceremony material in any
field). AC1 static pin: the dict is gone from src, pinned by inspection.
"""

import base64
import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import AuditEvent, Fido2Challenge
from server.fido2.manager import (
    CHALLENGE_TTL_SECONDS,
    Fido2Manager,
    Fido2Store,
    WebAuthnError,
    _decode_payload,
    _encode_payload,
)
from sqlalchemy.orm import sessionmaker

from tests.fido2_db import make_engine, peek_challenge_data

RP_ID = "venya-core-1"
DENY_FIELDS = {"outcome", "reason"}
UNIFORM_MSG = "Challenge not found or expired"


def _worker(db_path, **manager_kwargs):
    """One 'worker' = its own engine + store/manager over the same file."""
    engine = make_engine(db_path)
    factory = sessionmaker(bind=engine)
    manager = Fido2Manager(rp_id=RP_ID, rp_name="Venya", session_factory=factory, **manager_kwargs)
    return manager, engine, factory


def _rows(factory, model):
    db = factory()
    try:
        return db.query(model).all()
    finally:
        db.close()


def _fields(event):
    """AuditEvent.fields serializes dicts to JSON text at the column."""
    return json.loads(event.fields) if isinstance(event.fields, str) else event.fields


def _age(factory, challenge_id, seconds):
    """Backdate a row past its TTL window instead of waiting on the clock."""
    db = factory()
    try:
        row = db.query(Fido2Challenge).filter(Fido2Challenge.challenge_id == challenge_id).one()
        past = datetime.now(UTC) - timedelta(seconds=seconds)
        row.created_at = past
        row.expires_at = past + timedelta(seconds=CHALLENGE_TTL_SECONDS)
        db.commit()
    finally:
        db.close()


def _denials(factory):
    return [e for e in _rows(factory, AuditEvent) if e.event_type == "fido2_challenge_denied"]


class TestDictGone:
    """AC1 static: the per-process challenge dict is gone from src."""

    def test_store_has_no_challenges_attr(self):
        store = Fido2Store(session_factory=lambda: None)
        assert not hasattr(store, "_challenges")

    def test_manager_source_no_longer_holds_the_dict(self):
        import server.fido2.manager as manager_module

        src = inspect.getsource(manager_module)
        assert "self._challenges" not in src
        assert "_challenges.pop(" not in src
        assert "_challenges[" not in src


class TestCrossProcessCeremony:
    def test_challenge_issued_on_one_worker_claims_on_another(self, tmp_path):
        """AC4: the ceremony survives the worker hop — the row lives in the
        DB and B's claim reads it through shared storage. At the old HEAD
        (dict store) B found nothing and this cell REDs."""
        db = tmp_path / "venya.db"
        manager_a, engine_a, _ = _worker(db)
        cid, options = manager_a.start_authentication()
        raw_a = options["challenge"]

        del manager_a, engine_a  # "process A exits"
        manager_b, _, factory_b = _worker(db)
        stored = manager_b.store.get_challenge(cid)
        assert stored is not None
        # the claimed bytes answer exactly what A issued (same bytes, b64 in options)
        assert base64.b64encode(stored.data["raw_challenge"]).decode("ascii") == raw_a
        # and the ceremony binding came along for the ride
        assert stored.data["user_verification"] == "discouraged"
        # the row flips to consumed rather than disappearing: replay-proof state
        assert [r.state for r in _rows(factory_b, Fido2Challenge) if r.challenge_id == cid] == ["consumed"]

    def test_restart_mid_ceremony_is_claimable(self, tmp_path):
        """Restart variant: same file, a brand-new engine after the issue —
        the dict died with the process, the row does not."""
        db = tmp_path / "venya.db"
        manager_a, engine_a, _ = _worker(db)
        cid, _ = manager_a.start_authentication()
        del manager_a
        engine_a.dispose()
        manager_b, _, _ = _worker(db)
        assert manager_b.store.get_challenge(cid) is not None

    def test_registration_payload_round_trips_through_storage(self, tmp_path):
        """A bytes-heavy registration payload (raw_challenge plus a
        list[bytes] of excluded credential ids) survives the JSON + base64
        codec trip into the table and back out in another process."""
        db = tmp_path / "venya.db"
        manager_a, _, _ = _worker(db)
        existing = [b"\xaa" * 10, b"\xbb" * 4]
        cid, _ = manager_a.start_registration(user_id="u1", username="user1", existing_credential_ids=existing)
        del manager_a

        manager_b, _, _ = _worker(db)
        stored = manager_b.store.get_challenge(cid)
        assert stored is not None
        assert stored.user_id == "u1"
        assert stored.data["username"] == "user1"
        assert isinstance(stored.data["raw_challenge"], bytes)
        assert stored.data["existing_credential_ids"] == existing


class TestSingleConsume:
    """AC3: exactly one claim of a challenge ever succeeds."""

    def test_two_claims_exactly_one_wins(self, tmp_path):
        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)
        cid, _ = manager.start_authentication()
        assert manager.store.get_challenge(cid) is not None
        assert manager.store.get_challenge(cid) is None
        # the row survives (as consumed) so the replay is provably refused,
        # not merely invisible
        assert len([r for r in _rows(factory, Fido2Challenge) if r.challenge_id == cid]) == 1

    def test_two_independent_sessions_claim_one_winner(self, tmp_path):
        """Two sessions, interleaved claim/commit: the atomic
        UPDATE ... WHERE state='created' rowcount gives exactly one winner.
        (True concurrent MVCC contention is the integration tier's proof —
        the shape that guarantees it is the guarded UPDATE, pinned here.)"""
        db = tmp_path / "venya.db"
        manager, engine, _ = _worker(db)
        cid, _ = manager.start_authentication()
        s1 = sessionmaker(bind=engine)()
        s2 = sessionmaker(bind=engine)()
        try:
            now = datetime.now(UTC)

            def claim(db):
                return (
                    db.query(Fido2Challenge)
                    .filter(
                        Fido2Challenge.challenge_id == cid,
                        Fido2Challenge.state == "created",
                        Fido2Challenge.expires_at > now,
                    )
                    .update({"state": "consumed"}, synchronize_session=False)
                )

            first = claim(s1)
            s1.commit()
            second = claim(s2)
            s2.commit()
            assert first == 1
            assert second == 0
            assert first + second == 1
        finally:
            s1.close()
            s2.close()

    def test_second_worker_cannot_reconsume_after_a_completed_ceremony(self, tmp_path):
        """PAIRED NEGATIVE across processes: once one worker has claimed, the
        next worker gets the uniform refusal plus exactly one denial row."""
        db = tmp_path / "venya.db"
        manager_a, _, factory = _worker(db)
        cid, _ = manager_a.start_authentication()
        assert _worker(db)[0].store.get_challenge(cid) is not None
        assert _worker(db)[0].store.get_challenge(cid) is None
        assert len(_denials(factory)) == 1


class TestUniformRefusalNoOracle:
    """AC2: unknown / expired / already-consumed refuse with the SAME
    message and the SAME value-free audit shape — nothing distinguishes
    which half failed, and no challenge material is written anywhere."""

    def test_all_three_refuse_identically_on_the_auth_path(self, tmp_path):
        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)

        # 1. an id that was never issued
        with pytest.raises(WebAuthnError, match=UNIFORM_MSG):
            manager.finish_authentication("never-issued", {"id": "dGVzdA=="})

        # 2. an id that outlived its window
        cid_exp, _ = manager.start_authentication()
        _age(factory, cid_exp, CHALLENGE_TTL_SECONDS + 1)
        with pytest.raises(WebAuthnError, match=UNIFORM_MSG):
            manager.finish_authentication(cid_exp, {"id": "dGVzdA=="})

        # 3. an id already spent by a successful claim
        cid_used, _ = manager.start_authentication()
        assert manager.store.get_challenge(cid_used) is not None
        with pytest.raises(WebAuthnError, match=UNIFORM_MSG):
            manager.finish_authentication(cid_used, {"id": "dGVzdA=="})

        denials = _denials(factory)
        assert len(denials) == 3
        for event in denials:
            assert set(_fields(event)) == DENY_FIELDS
            assert _fields(event) == {"outcome": "denied", "reason": "challenge_not_found"}
            blob = str(event.fields)
            for secret in ("never-issued", cid_exp, cid_used, "raw_challenge"):
                assert secret not in blob
            # an untargeted login-start denial records no principal either
            assert event.user_id is None

    def test_expired_row_never_re_arms(self, tmp_path):
        """The expired half refuses through the atomic UPDATE's guard and the
        prune-at-touch drops the row: it cannot be claimed a second time."""
        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)
        cid, _ = manager.start_authentication()
        _age(factory, cid, CHALLENGE_TTL_SECONDS + 1)
        assert manager.store.get_challenge(cid) is None
        assert [r for r in _rows(factory, Fido2Challenge) if r.challenge_id == cid] == []

    def test_denied_ceremony_does_not_replay_after_refusal(self, tmp_path):
        """A claim that commits and is then refused for another reason must
        not leave the challenge live (pop-on-all-paths, #345 meaning)."""
        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)
        cid, _ = manager.start_authentication()
        with pytest.raises(WebAuthnError, match="Missing credential ID"):
            manager.finish_authentication(cid, {})
        states = [r.state for r in _rows(factory, Fido2Challenge) if r.challenge_id == cid]
        assert states == ["consumed"]
        assert manager.store.get_challenge(cid) is None


class TestPayloadCodec:
    """The bytes-tagging codec round-trips every payload shape the store sees
    (bytes, list of bytes, nested dicts, plain values, None)."""

    def test_round_trip(self):
        payload = {
            "username": "user1",
            "user_id": "u1",
            "existing_credential_ids": [b"\x00\xff", b""],
            "raw_challenge": b"\x01\x02\x03",
            "target_user_id": None,
            "user_verification": "required",
        }
        encoded = json.dumps(_encode_payload(payload))
        assert _decode_payload(json.loads(encoded)) == payload

    def test_bytes_are_tagged_not_stringified(self):
        encoded = _encode_payload({"raw_challenge": b"\x01"})
        assert encoded == {"raw_challenge": {"__b64__": "AQ=="}}
        assert json.dumps(encoded)  # JSON-safe: no bytes reach the column


class TestNoCredentialPathChange:
    """AC7: the credential side keeps its per-process startup cache — the
    change is confined to challenge state."""

    def test_credential_store_is_still_in_memory(self, tmp_path):
        from server.fido2.manager import StoredCredential

        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)
        cred = StoredCredential(user_id="u1", credential_id=b"\x99" * 8, public_key=b"pub")
        manager.store.store_credential(cred)
        assert manager.store.get_credential(b"\x99" * 8) is cred
        assert manager.store.get_user_credentials("u1") == [cred]
        assert manager.store.remove_credential(b"\x99" * 8) is True
        # and no challenge row was written by credential work
        assert _rows(factory, Fido2Challenge) == []

    def test_a_manager_over_a_shared_store_still_serves_ceremonies(self, tmp_path):
        """The ceremony half that used to be a dict poke now reads the row:
        peeking does not consume, so a follow-up claim still succeeds once."""
        db = tmp_path / "venya.db"
        manager, _, factory = _worker(db)
        cid, _ = manager.start_authentication(user_id="u1")
        data = peek_challenge_data(factory, cid)
        assert data["target_user_id"] == "u1"
        assert manager.store.get_challenge(cid) is not None
        with pytest.raises(WebAuthnError, match=UNIFORM_MSG):
            manager.finish_authentication(cid, {"id": "dGVzdA=="})
