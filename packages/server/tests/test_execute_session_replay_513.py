# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the execution-session replay gate (#513).

``POST /executors/{id}/execute`` validated existence, expiry, ownership,
binding and revocation — and never read ``completed_at``, the marker the
route wrote only POST-HOC through a best-effort bulk UPDATE. A session that
had already relayed therefore stayed usable for the rest of its 10-minute
TTL, and the model itself documents the intended contract: "Tracks a SINGLE
command execution request" (core/iam/models.py, ExecutionSession).

The fix claims the session BEFORE the relay: one conditional UPDATE
(``_claim_execution_session``) matches the row on ``id`` AND
``completed_at IS NULL`` and stamps the marker in the SAME statement; a
rowcount of 0 refuses (409) and is audited with the session id. The claim
rides the request transaction, so a failed relay rolls the marker back and
the operator can retry the same session (the #407 retry posture) — but a
session whose relay COMMITTED can never relay again.

Backend honesty (the #510/#511/#512 posture): SQLite serializes writers and
ignores ``FOR UPDATE``. These cells prove (1) the claim is atomic WITH THE
CHECK — evaluated at write time against committed state, including by a
session whose own read saw the row fresh — and (2) the handler decides on the
rowcount, never on its read: the interleaving here is a REAL second
transaction committing its claimed+completed state at a seam that exists at
HEAD too (the route's own revocation-state call, which sits between the
session read and the relay), so the same cell is RED at HEAD (the loser
relays anyway) and GREEN after the fix (the claim finds 0 rows and refuses).
The cross-PROCESS two-connection race is the PostgreSQL-gated class at the
bottom, which SKIPS on a venue without a scratch database. Assumed isolation
level: PostgreSQL READ COMMITTED (the server default) — the loser's claim
UPDATE blocks on the winner's row lock and re-evaluates its WHERE clause
after the winner commits.
"""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import (
    AuditEvent,
    Base,
    ExecutionSession,
    Executor,
    Role,
    RoleMember,
    User,
)
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import executors as executors_routes
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

PG_URL_ENV = "VENYA_TEST_PG_URL"
TEST_USER = {"user_id": "test-user", "roles": ["admin"], "caller": "human"}
RELAY_RESULT = {"exit_code": 0, "stdout": "hello world\n", "stderr": "", "masked_count": 0}


def _execution_session_utc_loader():
    """Re-stamp UTC on naive datetimes read back from SQLite.

    SQLite has no timestamptz; without this, the route's aware-now expiry
    comparison TypeErrors on re-read rows (the #340 loader, this model).
    """
    if getattr(ExecutionSession, "_race513_utc_loader", False):
        return
    ExecutionSession._race513_utc_loader = True

    @event.listens_for(ExecutionSession, "load")
    def _localize(obj, *event_args):  # signature varies across SQLAlchemy releases
        for field in ("created_at", "expires_at", "completed_at"):
            value = getattr(obj, field)
            if value is not None and value.tzinfo is None:
                setattr(obj, field, value.replace(tzinfo=UTC))


def _seed_execution_session(
    session, sid, *, completed=False, expires_in_min=5, user_id="test-user", executor_id="exec-1"
):
    now = datetime.now(UTC)
    session.add(
        ExecutionSession(
            id=sid,
            user_id=user_id,
            executor_id=executor_id,
            command="",
            created_at=now,
            expires_at=now + timedelta(minutes=expires_in_min),
            completed_at=now - timedelta(seconds=1) if completed else None,
        )
    )
    session.commit()


def _make_stack(tmp_path, name, seed):
    """Real executors route + real SQLite + a COUNTING fake relay transport.

    The httpx transport and SSL-context build are the ONLY fakes — they stand
    in for the executor daemon itself (no fleet on this leg). Every gate,
    claim, UPDATE and audit these cells assert runs against real rows on a
    real session, and ``relay.post.await_count`` makes "the relay never ran"
    a physical assertion.
    """
    _execution_session_utc_loader()
    db_path = str(tmp_path / name)
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as s:
        admin_role = Role(name="admin", permissions="read-write")
        s.add(admin_role)
        s.flush()
        s.add(User(user_id="test-user", status="active", auth_mode="security-key"))
        s.add(Executor(id="exec-1", hostname="203.0.113.14", status="active"))
        s.flush()
        s.add(RoleMember(user_id="test-user", role_id=admin_role.id))
        if seed is not None:
            seed(s)
        s.commit()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.state.backend = backend
    app.state.config = SimpleNamespace(ca_dir=str(tmp_path), mtls_cert=None, mtls_key=None)
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.include_router(executors_routes.router, prefix="/api/v1")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = dict(RELAY_RESULT)
    mock_response.raise_for_status = MagicMock()
    relay_client = MagicMock()
    relay_client.__aenter__ = AsyncMock(return_value=relay_client)
    relay_client.__aexit__ = AsyncMock(return_value=False)
    relay_client.post = AsyncMock(return_value=mock_response)

    return TestClient(app, raise_server_exceptions=False), SessionLocal, engine, relay_client


@contextmanager
def _relay_patched(relay_client):
    with (
        patch("server.routes.executors.httpx2.AsyncClient", return_value=relay_client),
        patch("server.routes.executors._build_relay_ssl_context", return_value=MagicMock()),
    ):
        yield


@contextmanager
def relay_stack(tmp_path, sid, **session_kwargs):
    """One cell's stack: route under a patched relay, session seeded fresh."""

    def seed(s):
        _seed_execution_session(s, sid, **session_kwargs)

    client, SessionLocal, engine, relay = _make_stack(tmp_path, f"relay513-{sid}.db", seed)
    try:
        with _relay_patched(relay):
            yield client, SessionLocal, relay
    finally:
        engine.dispose()


def _body(sid):
    return {"session_id": sid, "command": ["echo", "hello"]}


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else (row.fields or {})


def _replay_refusals(session):
    return [e for e in session.query(AuditEvent).all() if e.event_type == "execution_session_replay_refused"]


class TestCompletedSessionRefused:
    """AC1 — RED at HEAD: at HEAD a completed session relays AGAIN (200 +
    a live relay call); post-fix the gate refuses 409 BEFORE any relay."""

    def test_execute_on_completed_session_is_refused_and_never_relays(self, tmp_path):
        with relay_stack(tmp_path, "sess-done", completed=True) as (client, _SL, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-done"))
        assert resp.status_code == 409, resp.text
        assert relay.post.await_count == 0, "the relay ran on a completed session"
        detail = resp.json()["detail"].lower()
        assert "already completed" in detail, detail

    def test_refusal_is_audited_with_the_session_id(self, tmp_path):
        """AC5: the refusal leaves its own record naming the session, the
        executor and the cause — value-free."""
        with relay_stack(tmp_path, "sess-audit", completed=True) as (client, SessionLocal, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-audit"))
            assert resp.status_code == 409
            with SessionLocal() as s:
                rows = _replay_refusals(s)
                assert len(rows) == 1, rows
                fields = _fields(rows[0])
                assert fields["session_id"] == "sess-audit"
                assert fields["executor_id"] == "exec-1"
                assert fields["outcome"] == "refused_session_already_completed"
                assert rows[0].user_id == "test-user"
        assert relay.post.await_count == 0


class TestSingleUseEndToEnd:
    """AC2 + AC4 positive halves over the real route."""

    def test_fresh_session_relays_once_and_the_marker_lands(self, tmp_path):
        with relay_stack(tmp_path, "sess-fresh") as (client, SessionLocal, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-fresh"))
            assert resp.status_code == 200, resp.text
            assert relay.post.await_count == 1
            with SessionLocal() as s:
                row = s.query(ExecutionSession).filter(ExecutionSession.id == "sess-fresh").one()
                assert row.completed_at is not None
                assert row.exit_code == 0

    def test_sequential_replay_over_http_refused(self, tmp_path):
        """RED at HEAD (the serialized double submission): at HEAD the second
        POST relays AGAIN — await_count would be 2 and the status 200.
        Post-fix: exactly ONE relay, the replay refuses 409."""
        with relay_stack(tmp_path, "sess-seq") as (client, SessionLocal, relay):
            first = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-seq"))
            second = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-seq"))
            assert first.status_code == 200, first.text
            assert second.status_code == 409, second.text
            assert relay.post.await_count == 1, "double relay on one session"
            with SessionLocal() as s:
                assert len(_replay_refusals(s)) == 1


class TestClaimIsAtomicWithTheCheck:
    """AC3: the marker is written by the SAME statement that checks it."""

    def test_claim_wins_then_loses_on_two_real_sessions(self, tmp_path):
        """First claim rowcount 1, second claim rowcount 0 — even though the
        second session READ the row (completed_at NULL) before the first
        committed: the claim re-evaluates at write time, no read-then-write
        window survives."""
        _execution_session_utc_loader()
        engine = create_engine(f"sqlite:///{tmp_path / 'claim513.db'}")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        with SessionLocal() as s:
            _seed_execution_session(s, "s1")
        first = SessionLocal()
        second = SessionLocal()
        try:
            assert first.query(ExecutionSession).filter(ExecutionSession.id == "s1").first().completed_at is None
            assert second.query(ExecutionSession).filter(ExecutionSession.id == "s1").first().completed_at is None
            assert executors_routes._claim_execution_session(first, "s1", datetime.now(UTC)) == 1
            first.commit()
            assert executors_routes._claim_execution_session(second, "s1", datetime.now(UTC)) == 0
            second.rollback()
        finally:
            first.close()
            second.close()
            engine.dispose()

    def test_claim_rejected_when_row_vanished(self, tmp_path):
        """The replaced contract, pinned: a vanished row claims 0 — the
        silent post-hoc no-op is now a decision-point refusal (404 through
        the route, next cell)."""
        _execution_session_utc_loader()
        engine = create_engine(f"sqlite:///{tmp_path / 'claim513gone.db'}")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        with SessionLocal() as s:
            _seed_execution_session(s, "gone-1")
        s1 = SessionLocal()
        try:
            s1.query(ExecutionSession).filter(ExecutionSession.id == "gone-1").delete()
            s1.commit()
            assert executors_routes._claim_execution_session(s1, "gone-1", datetime.now(UTC)) == 0
            s1.rollback()
        finally:
            s1.close()
            engine.dispose()

    def test_claim_statement_is_one_conditional_update(self):
        """Statement construction (the #339 pin): ONE UPDATE — SET
        completed_at with WHERE id AND completed_at IS NULL in the same
        statement."""
        captured = []

        class _R:
            rowcount = 1

        class _Db:
            def execute(self, stmt, *a, **k):
                captured.append(str(stmt))
                return _R()

        now = datetime(2026, 1, 1, tzinfo=UTC)
        assert executors_routes._claim_execution_session(_Db(), "s9", now) == 1
        assert len(captured) == 1, captured
        stmt = captured[0]
        assert stmt.lstrip().upper().startswith("UPDATE EXECUTION_SESSIONS"), stmt
        assert "WHERE execution_sessions.id = :" in stmt, stmt
        assert "execution_sessions.completed_at IS NULL" in stmt, stmt
        assert "completed_at=:" in stmt.replace(" ", ""), stmt


class TestHandlerTrustsClaimNotRead:
    """AC2 — the concurrent loser, deterministically.

    Seam: the module-level ``executor_revocation_state`` call, which every
    legit submission makes BETWEEN its session read and its claim — it exists
    at HEAD and post-fix alike, so nothing under test is stubbed. The wrapper
    lets a REAL second transaction claim the row, write its results, and
    COMMIT (the winner's full committed effect) while the loser is mid-flight.

    At HEAD: the loser has no claim — it proceeds to relay (await_count 2,
    status 200) -> this cell is RED at HEAD.
    Post-fix: the loser's claim matches 0 rows -> 409, relay never ran,
    refusal audited -> GREEN.
    """

    def test_loser_is_refused_when_the_winner_commits_midflight(self, tmp_path):
        with relay_stack(tmp_path, "sess-mid") as (client, SessionLocal, relay):
            real_state = executors_routes.executor_revocation_state
            state = {"fired": False}

            def _winner_effect(session_id):
                """Everything the winner's committed transaction leaves:
                claimed marker + result fields (its bookkeeping)."""
                with SessionLocal() as w:
                    assert executors_routes._claim_execution_session(w, session_id, datetime.now(UTC)) == 1
                    executors_routes._mark_execution_session_completed(
                        w, session_id, "echo hello", ["echo", "hello"], datetime.now(UTC), RELAY_RESULT
                    )
                    w.commit()

            def state_with_race(db, executor_id, presented_serial=None, executor_row=None):
                if not state["fired"]:
                    state["fired"] = True
                    _winner_effect("sess-mid")
                return real_state(db, executor_id, presented_serial, executor_row=executor_row)

            executors_routes.executor_revocation_state = state_with_race
            try:
                resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-mid"))
            finally:
                executors_routes.executor_revocation_state = real_state

            assert state["fired"], "the seam never fired — the cell proved nothing"
            assert resp.status_code == 409, resp.text
            assert relay.post.await_count == 0, "the loser relayed despite a claimed row"
            with SessionLocal() as s:
                row = s.query(ExecutionSession).filter(ExecutionSession.id == "sess-mid").one()
                assert row.exit_code == 0  # the winner's result stands, untouched
                assert len(_replay_refusals(s)) == 1


class TestRetainedRefusalsRealDB:
    """AC4 paired negatives on the real stack: expiry/binding/revocation/
    ownership refuse with their existing statuses — and never claim the row."""

    def test_expired_session_400_marker_stays_null(self, tmp_path):
        with relay_stack(tmp_path, "sess-exp", expires_in_min=-5) as (client, SessionLocal, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-exp"))
            assert resp.status_code == 400, resp.text
            assert relay.post.await_count == 0
            with SessionLocal() as s:
                assert s.query(ExecutionSession).filter(ExecutionSession.id == "sess-exp").one().completed_at is None

    def test_wrong_binding_403(self, tmp_path):
        with relay_stack(tmp_path, "sess-bind", executor_id="exec-2") as (client, _SL, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-bind"))
            assert resp.status_code == 403 and "different executor" in resp.json()["detail"]
            assert relay.post.await_count == 0

    def test_revoked_executor_403_before_claim(self, tmp_path):
        with relay_stack(tmp_path, "sess-rev") as (client, SessionLocal, relay):
            with SessionLocal() as s:
                ex = s.query(Executor).filter(Executor.id == "exec-1").one()
                ex.revoked_at = datetime.now(UTC)
                s.commit()
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-rev"))
            assert resp.status_code == 403 and "revoked" in resp.json()["detail"]
            assert relay.post.await_count == 0
            with SessionLocal() as s:
                assert s.query(ExecutionSession).filter(ExecutionSession.id == "sess-rev").one().completed_at is None

    def test_foreign_user_session_403(self, tmp_path):
        with relay_stack(tmp_path, "sess-other", user_id="someone-else") as (client, _SL, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-other"))
            assert resp.status_code == 403 and "does not belong" in resp.json()["detail"]
            assert relay.post.await_count == 0

    def test_missing_session_still_404(self, tmp_path):
        with relay_stack(tmp_path, "sess-ghost") as (client, _SL, relay):
            resp = client.post("/api/v1/executors/exec-1/execute", json=_body("nope"))
            assert resp.status_code == 404
            assert relay.post.await_count == 0


class TestFailedRelayReleasesTheClaim:
    """The #407 retry posture: a transport failure rolls the uncommitted
    claim back, so the operator can retry the SAME session."""

    def test_relay_connect_error_then_retry_succeeds(self, tmp_path):
        import httpx2

        with relay_stack(tmp_path, "sess-retry") as (client, SessionLocal, relay):
            relay.post.side_effect = httpx2.ConnectError("connection refused")
            down = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-retry"))
            assert down.status_code == 503, down.text
            with SessionLocal() as s:
                assert (
                    s.query(ExecutionSession).filter(ExecutionSession.id == "sess-retry").one().completed_at is None
                ), "the failed relay left the session consumed"
            relay.post.side_effect = None
            retry = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-retry"))
            assert retry.status_code == 200, retry.text
        assert relay.post.await_count == 2  # one failed, one real


@pytest.mark.skipif(
    not __import__("os").environ.get(PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestConcurrentExecutePostgresql:
    """AC2/AC3 cross-PROCESS, physically (WRITTEN, NOT RUN ON THIS LEG — the
    spec bars VMs and fleet; its claims are unverified against a live
    server). Point ``VENYA_TEST_PG_URL`` at a SCRATCH database — it drops
    and recreates the IAM tables — never at anything live.

    Two threads, two connections, one barrier, one fresh session. READ
    COMMITTED: the loser's claim UPDATE blocks on the winner's row lock,
    re-evaluates its WHERE after the winner commits, matches 0 rows and
    answers 409 — exactly ONE relay. At HEAD both submissions pass every
    gate and BOTH relay: the command runs twice on the target.

    DO-NOT-RUN live double-execution cell against a real executor fleet:
    design in the leg report only (owner-present venue required).
    """

    def test_two_threads_one_relay(self):
        import os
        import threading

        db_url = os.environ[PG_URL_ENV]
        engine = create_engine(db_url)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        now = datetime.now(UTC)
        with SessionLocal() as s:
            admin_role = Role(name="admin", permissions="read-write")
            s.add(admin_role)
            s.flush()
            s.add(User(user_id="test-user", status="active", auth_mode="security-key"))
            s.add(Executor(id="exec-1", hostname="203.0.113.14", status="active"))
            s.flush()
            s.add(RoleMember(user_id="test-user", role_id=admin_role.id))
            s.add(
                ExecutionSession(
                    id="sess-race",
                    user_id="test-user",
                    executor_id="exec-1",
                    command="",
                    created_at=now,
                    expires_at=now + timedelta(minutes=5),
                )
            )
            s.commit()

        backend = Backend(BackendConfig(database_url=db_url, kek=b"k" * KEK_SIZE))
        backend._engine = engine
        backend._session_factory = SessionLocal

        class _PerRequest:
            def __init__(self, factory):
                self._factory = factory

            def get_session(self):
                return self._factory()

        app = FastAPI()
        app.state.backend = _PerRequest(SessionLocal)
        app.state.config = SimpleNamespace(ca_dir="/tmp/tabichat", mtls_cert=None, mtls_key=None)
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        app.include_router(executors_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = dict(RELAY_RESULT)
        mock_response.raise_for_status = MagicMock()
        relay_client = MagicMock()
        relay_client.__aenter__ = AsyncMock(return_value=relay_client)
        relay_client.__aexit__ = AsyncMock(return_value=False)
        relay_client.post = AsyncMock(return_value=mock_response)

        barrier = threading.Barrier(2, timeout=10)
        codes = {}

        def run(name):
            barrier.wait()
            codes[name] = client.post("/api/v1/executors/exec-1/execute", json=_body("sess-race")).status_code

        with _relay_patched(relay_client):
            threads = [threading.Thread(target=run, args=(n,)) for n in ("t1", "t2")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

        assert sorted(codes.values()) == [200, 409], codes
        assert relay_client.post.await_count == 1, "double relay across connections"
        with SessionLocal() as s:
            assert s.query(ExecutionSession).filter(ExecutionSession.id == "sess-race").one().exit_code == 0
            assert len(_replay_refusals(s)) == 1
