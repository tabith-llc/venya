# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Fido2Store challenge TTL sweep (#408, DB shape since #534): every stored
challenge carries an expiry, abandoned ceremonies are pruned on the next
store/get touch (the #345 elevation pattern, now on the table side), and a
timed-out challenge reads as absent so "Challenge not found or expired"
stays honest.

Truth-table pairs: aged entries rejected / fresh entries unchanged; the
consume-on-read meaning stays intact (the claim flips state, it never
re-arms).
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.iam.models import Fido2Challenge
from server.fido2.manager import CHALLENGE_TTL_SECONDS, Fido2Store, WebAuthnError
from sqlalchemy.orm import sessionmaker

from tests.fido2_db import challenge_rows, live_challenge_ids, make_engine, manager_with_db


def _db_store(tmp_path):
    """(store, session_factory) over a fresh SQLite file (#534 shape)."""
    factory = sessionmaker(bind=make_engine(tmp_path / "ttl.db"))
    return Fido2Store(factory), factory


def _age(session_factory, challenge_id: str, seconds: float) -> None:
    """Backdate a row past its window instead of waiting on the real clock."""
    db = session_factory()
    try:
        row = db.query(Fido2Challenge).filter(Fido2Challenge.challenge_id == challenge_id).one()
        past = datetime.now(UTC) - timedelta(seconds=seconds)
        row.created_at = past
        row.expires_at = past + timedelta(seconds=CHALLENGE_TTL_SECONDS)
        db.commit()
    finally:
        db.close()


class TestStoreTtl:
    def test_aged_challenge_get_returns_none_and_swept(self, tmp_path):
        """Expiry half: a timed-out challenge reads absent and is pruned."""
        store, factory = _db_store(tmp_path)
        store.store_challenge("c1", "u1", {"k": "v"})
        _age(factory, "c1", CHALLENGE_TTL_SECONDS + 1)
        assert store.get_challenge("c1") is None
        assert challenge_rows(factory) == []

    def test_fresh_challenge_survives_the_sweep(self, tmp_path):
        """Paired negative: an aged touch does not disturb a fresh entry."""
        store, factory = _db_store(tmp_path)
        store.store_challenge("aged", "u1", {})
        store.store_challenge("fresh", "u1", {})
        _age(factory, "aged", CHALLENGE_TTL_SECONDS + 1)
        assert store.get_challenge("aged") is None
        assert "fresh" in live_challenge_ids(factory)

    def test_store_prunes_aged_seeds_keeps_fresh(self, tmp_path):
        """Sweep-at-insert: bounded growth — aged seeds die, the new entry lives."""
        store, factory = _db_store(tmp_path)
        for i in range(3):
            store.store_challenge(f"seed{i}", "u1", {})
            _age(factory, f"seed{i}", CHALLENGE_TTL_SECONDS + 1)
        store.store_challenge("new", "u1", {})
        assert [cid for cid, _state in challenge_rows(factory)] == ["new"]

    def test_get_consumes_fresh_challenge_once(self, tmp_path):
        """Regression: single-consume semantics unchanged for a fresh entry."""
        store, factory = _db_store(tmp_path)
        store.store_challenge("c1", "u1", {"k": "v"})
        assert store.get_challenge("c1") is not None
        assert store.get_challenge("c1") is None
        assert [state for _cid, state in challenge_rows(factory)] == ["consumed"]

    def test_store_without_a_session_factory_fails_loudly(self):
        """No silent memory fallback: with the dict gone, a store that cannot
        reach the database refuses rather than half-serving a ceremony."""
        with pytest.raises(RuntimeError, match="session factory"):
            Fido2Store().store_challenge("c1", "u1", {})
        with pytest.raises(RuntimeError, match="session factory"):
            Fido2Store().get_challenge("c1")


class TestAuthenticationPathHonestExpiry:
    def test_aged_challenge_rejected_on_authentication(self, tmp_path):
        """The login path: the expiry error text matches behavior."""
        mgr, factory = manager_with_db(tmp_path, "auth.db", rp_id="venya-core-1", rp_name="Venya")
        cid, _ = mgr.start_authentication()
        _age(factory, cid, CHALLENGE_TTL_SECONDS + 1)
        with pytest.raises(WebAuthnError, match="Challenge not found or expired"):
            mgr.finish_authentication(cid, {"id": "dGVzdA=="})
        assert live_challenge_ids(factory) == []

    def test_fresh_challenge_passes_the_expiry_gate(self, tmp_path):
        """Paired positive: the fresh path is unchanged — the ceremony gets
        past the expiry check and fails later on the bogus response."""
        mgr, factory = manager_with_db(tmp_path, "auth.db", rp_id="venya-core-1", rp_name="Venya")
        cid, _ = mgr.start_authentication()
        with pytest.raises(WebAuthnError) as excinfo:
            mgr.finish_authentication(cid, {})
        assert "not found or expired" not in str(excinfo.value)
        # pop-on-all-paths: the failed ceremony consumed the challenge
        assert [state for _cid, state in challenge_rows(factory)] == ["consumed"]
