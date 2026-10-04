# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Fido2Store challenge TTL sweep (#408): stored challenges carry created_at,
abandoned ceremonies are pruned on the next store/get touch (the #345
elevation pattern, copied in-store), and a timed-out challenge reads as
absent so "Challenge not found or expired" becomes honest.

Truth-table pairs: aged entries rejected / fresh entries unchanged; the
consume-on-read pop semantics stay intact.
"""

import time

import pytest
from server.fido2.manager import CHALLENGE_TTL_SECONDS, Fido2Manager, Fido2Store, WebAuthnError


def _age(store: Fido2Store, challenge_id: str, seconds: float) -> None:
    """Backdate an entry instead of waiting on the real clock."""
    store._challenges[challenge_id].created_at = time.time() - seconds


class TestStoreTtl:
    def test_aged_challenge_get_returns_none_and_swept(self):
        """Expiry half: a timed-out challenge reads absent and is pruned."""
        store = Fido2Store()
        store.store_challenge("c1", "u1", {"k": "v"})
        _age(store, "c1", CHALLENGE_TTL_SECONDS + 1)
        assert store.get_challenge("c1") is None
        assert "c1" not in store._challenges

    def test_fresh_challenge_survives_the_sweep(self):
        """Paired negative: an aged touch does not disturb a fresh entry."""
        store = Fido2Store()
        store.store_challenge("aged", "u1", {})
        store.store_challenge("fresh", "u1", {})
        _age(store, "aged", CHALLENGE_TTL_SECONDS + 1)
        assert store.get_challenge("aged") is None
        assert "fresh" in store._challenges

    def test_store_prunes_aged_seeds_keeps_fresh(self):
        """Sweep-at-insert: bounded growth — aged seeds die, the new entry lives."""
        store = Fido2Store()
        for i in range(3):
            store.store_challenge(f"seed{i}", "u1", {})
            _age(store, f"seed{i}", CHALLENGE_TTL_SECONDS + 1)
        store.store_challenge("new", "u1", {})
        assert list(store._challenges) == ["new"]

    def test_get_consumes_fresh_challenge_once(self):
        """Regression: pop-on-read semantics unchanged for a fresh entry."""
        store = Fido2Store()
        store.store_challenge("c1", "u1", {"k": "v"})
        assert store.get_challenge("c1") is not None
        assert store.get_challenge("c1") is None


class TestAuthenticationPathHonestExpiry:
    def test_aged_challenge_rejected_on_authentication(self):
        """The login path: the expiry error text now matches behavior."""
        mgr = Fido2Manager(rp_id="venya-core-1", rp_name="Venya")
        cid, _ = mgr.start_authentication()
        _age(mgr.store, cid, CHALLENGE_TTL_SECONDS + 1)
        with pytest.raises(WebAuthnError, match="Challenge not found or expired"):
            mgr.finish_authentication(cid, {"id": "dGVzdA=="})
        assert cid not in mgr.store._challenges

    def test_fresh_challenge_passes_the_expiry_gate(self):
        """Paired positive: the fresh path is unchanged — the ceremony gets
        past the expiry check and fails later on the bogus response."""
        mgr = Fido2Manager(rp_id="venya-core-1", rp_name="Venya")
        cid, _ = mgr.start_authentication()
        with pytest.raises(WebAuthnError) as excinfo:
            mgr.finish_authentication(cid, {})
        assert "not found or expired" not in str(excinfo.value)
