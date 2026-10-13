# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#586 change C — the core's relay dial refuses an unusable executor credential.

Carrier: ``crl-enforcement-absent-relay-mtls-handshake``. Before this leg the dial
in ``execute_command_on_executor`` consulted the shared revocation state (added by
``executor-revocation-by-identity``, and NOT re-implemented here) and nothing else:
an executor row with no current certificate record, or one whose record had expired,
was still dialled, and the failure surfaced as an unlabeled transport error.

The owner's ruled status split, adopted verbatim:

* ``403`` = REVOKED — the answer ``server/revocation.py`` gives, consulted through
  ``executor_revocation_state``;
* ``503`` = operational fault — no registered certificate, or an expired one.

One rulebook (DoD point 1): the revoked arm is NOT re-derived here. The hardened
proposal's sketch of a direct ``ExecutorCertRevocation`` query inside the route would
have been the second implementation ``revocation.py``'s module comment forbids, so
this leg reads the record row for PRESENCE and EXPIRY only — neither is a revocation
semantic, and the revocation lookup stays the single call above it.

Backend honesty (the #510/#513 posture in this directory): the route is real, the
session is real SQLite, and the only fakes are the relay transport and the SSL
context. ``relay.post.await_count`` is what makes "the relay never ran" a physical
assertion rather than a status code that could have come from anywhere.
"""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from core.iam.models import (
    AuditEvent,
    ExecutionSession,
    Executor,
    ExecutorCert,
    ExecutorCertRevocation,
)

from tests.test_execute_session_replay_513 import (
    _execution_session_utc_loader,
    _make_stack,
)

BODY = {"session_id": "sess-586", "command": ["echo", "hello"]}


@contextmanager
def _relay_patched(relay_client):
    """The relay transport and the SSL build are the ONLY fakes (same seam as #513)."""
    with (
        patch("server.routes.executors.httpx2.AsyncClient", return_value=relay_client),
        patch("server.routes.executors._build_relay_ssl_context", return_value=MagicMock()),
        # #586 Slice 1: same faked-transport seam as in test_execute_session_replay_513
        patch("server.routes.executors._ensure_dial_crl_store", return_value="/nonexistent-in-fake"),
    ):
        yield


@pytest.fixture(autouse=True)
def _utc_loader():
    """SQLite hands back naive datetimes; the route compares against aware-now."""
    _execution_session_utc_loader()


def _seed_session(s, sid="sess-586"):
    now = datetime.now(UTC)
    s.add(
        ExecutionSession(
            id=sid,
            user_id="test-user",
            executor_id="exec-1",
            command="",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )


def _cert_row(s, *, not_after, serial="0000000000001000"):
    s.add(
        ExecutorCert(
            executor_id="exec-1",
            serial_number=serial,
            not_before=not_after - timedelta(days=30),
            not_after=not_after,
            fingerprint="ab" * 32,
        )
    )


def _stack(tmp_path, name, seed):
    """A cell's stack, with the #513 default cert record cleared first.

    ``_make_stack`` seeds a live ``ExecutorCert`` — the #586 paired-positive shape
    the #513 cells need in order to reach the dial at all. Every cell here states its
    own credential state, so the default goes away before the cell's seed runs.
    """

    def _seed(s):
        s.query(ExecutorCert).filter(ExecutorCert.executor_id == "exec-1").delete()
        _seed_session(s)
        if seed is not None:
            seed(s)

    return _make_stack(tmp_path, name, _seed)


def _credential_refusals(session):
    return [
        e
        for e in session.query(AuditEvent).all()
        if e.event_type == "command_rejected" and "refused_executor_credential" in (e.fields or "")
    ]


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else (row.fields or {})


class TestDialRefusesUnusableCredential:
    """The two new 503 arms, each with its paired positive in the class below."""

    def test_no_registered_certificate_is_503_and_never_relays(self, tmp_path):
        client, _SessionLocal, engine, relay = _stack(tmp_path, "586-nocert.db", None)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 503, resp.text
            assert "no registered certificate" in resp.json()["detail"]
            assert relay.post.await_count == 0, "the dial ran against an off-record executor"
        finally:
            engine.dispose()

    def test_expired_certificate_is_503_and_never_relays(self, tmp_path):
        def seed(s):
            _cert_row(s, not_after=datetime.now(UTC) - timedelta(days=1))

        client, _SessionLocal, engine, relay = _stack(tmp_path, "586-expired.db", seed)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 503, resp.text
            assert "expired" in resp.json()["detail"]
            assert relay.post.await_count == 0, "the dial ran with an expired record"
        finally:
            engine.dispose()

    def test_refusal_is_audited_naming_the_executor_and_the_cause(self, tmp_path):
        """DoD: a silent refusal is invisible to the customer whose premise is the
        trail. Each new arm leaves its own ledger row, value-free."""
        client, SessionLocal, engine, relay = _stack(tmp_path, "586-audit.db", None)
        try:
            with _relay_patched(relay):
                assert client.post("/api/v1/executors/exec-1/execute", json=BODY).status_code == 503
            with SessionLocal() as s:
                rows = _credential_refusals(s)
                assert len(rows) == 1, rows
                f = _fields(rows[0])
                assert f["executor_id"] == "exec-1"
                assert f["session_id"] == "sess-586"
                assert "no registered certificate" in f["reason"]
                assert rows[0].user_id == "test-user"
                # Value-free: no command text ever rides into this row.
                assert "command" not in f, f
        finally:
            engine.dispose()

    def test_expired_refusal_audits_its_own_cause(self, tmp_path):
        def seed(s):
            _cert_row(s, not_after=datetime.now(UTC) - timedelta(days=2))

        client, SessionLocal, engine, relay = _stack(tmp_path, "586-audit2.db", seed)
        try:
            with _relay_patched(relay):
                assert client.post("/api/v1/executors/exec-1/execute", json=BODY).status_code == 503
            with SessionLocal() as s:
                rows = _credential_refusals(s)
                assert len(rows) == 1, rows
                assert "certificate expired" in _fields(rows[0])["reason"], _fields(rows[0])
        finally:
            engine.dispose()

    def test_revoked_identity_still_wins_403_over_the_503_arms(self, tmp_path):
        """Ruled order (``revocation.py``: identity flag FIRST). A revoked executor
        with no cert row reads as REVOKED, not as an operational fault — the paired
        negative that keeps the two status classes apart."""

        def seed(s):
            row = s.query(Executor).filter_by(id="exec-1").one()
            row.revoked_at = datetime.now(UTC)

        client, _SessionLocal, engine, relay = _stack(tmp_path, "586-order.db", seed)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 403, resp.text
            assert "revoked" in resp.json()["detail"]
            assert relay.post.await_count == 0
        finally:
            engine.dispose()

    def test_serial_form_revocation_of_the_record_serial_is_403_not_503(self, tmp_path):
        """The one-rulebook pin: a CRL hit on the CURRENT record serial is answered
        403 by the shared state, and the new 503 arms do not pre-empt it."""

        def seed(s):
            _cert_row(s, not_after=datetime.now(UTC) + timedelta(days=30))
            s.add(
                ExecutorCertRevocation(
                    serial_number="0000000000001000",
                    executor_id="exec-1",
                    revoked_at=datetime.now(UTC),
                    reason="cell",
                )
            )

        client, _SessionLocal, engine, relay = _stack(tmp_path, "586-serial.db", seed)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 403, resp.text
            assert "revoked" in resp.json()["detail"]
        finally:
            engine.dispose()

    def test_refusal_does_not_burn_the_single_use_session(self, tmp_path):
        """The gate sits BEFORE the #513 claim, so an operational fault leaves the
        caller's session unclaimed — the #407 retry posture, extended to a dial that
        never started."""
        client, SessionLocal, engine, relay = _stack(tmp_path, "586-noburn.db", None)
        try:
            with _relay_patched(relay):
                assert client.post("/api/v1/executors/exec-1/execute", json=BODY).status_code == 503
            with SessionLocal() as s:
                sess = s.query(ExecutionSession).filter_by(id="sess-586").one()
                assert sess.completed_at is None, "a refused dial consumed the session"
        finally:
            engine.dispose()


class TestDialStillRoutesALiveCredential:
    """#586 acceptance 2 — the paired positive. A gate that refuses everything
    satisfies the refusal cells and fails THIS one."""

    def test_current_registered_certificate_relays(self, tmp_path):
        def seed(s):
            _cert_row(s, not_after=datetime.now(UTC) + timedelta(days=30))

        client, SessionLocal, engine, relay = _stack(tmp_path, "586-live.db", seed)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 200, resp.text
            assert relay.post.await_count == 1
            with SessionLocal() as s:
                assert _credential_refusals(s) == []
        finally:
            engine.dispose()

    def test_cert_expiring_hours_out_relays_inside_the_rotation_window(self, tmp_path):
        """The rotation HINT fires 3 days out; a hint is not a refusal. This is the
        boundary the 503-expired arm must not swallow."""

        def seed(s):
            _cert_row(s, not_after=datetime.now(UTC) + timedelta(hours=6))

        client, _SessionLocal, engine, relay = _stack(tmp_path, "586-window.db", seed)
        try:
            with _relay_patched(relay):
                resp = client.post("/api/v1/executors/exec-1/execute", json=BODY)
            assert resp.status_code == 200, resp.text
        finally:
            engine.dispose()
