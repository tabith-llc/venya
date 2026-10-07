# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth table for the recovery-code double-spend race (#512).

``POST /recovery`` matched the one-shot break-glass code with an UNLOCKED read
and burned it by mutating that read's ORM object, so two concurrent
submissions of the same code both passed the read, both minted an admin, and
both nulled the hash. The fix replaces the read-then-write pair with an
atomic check-and-burn — a single conditional ``UPDATE ... WHERE user_id = :uid
AND recovery_code_hash = :hash`` whose rowcount decides the winner (the
``admin_reissue_recovery_code`` shape already used in routes/admin.py).

Backend honesty (the #510/#511 posture, stated rather than hidden): SQLite
ignores ``FOR UPDATE`` and serializes writers, so what the SQLite cells below
prove is (1) the claim is a CHECK AND A BURN IN ONE STATEMENT evaluated
against COMMITTED state — a second claim on a second real session gets
rowcount 0 even when its own read saw the live row, because the UPDATE
re-evaluates at write time — and (2) the handler trusts the claim's rowcount,
not its read: a mid-flight interleaving (a real second transaction burning the
row between this request's read and its claim) is refused 409, mints nothing,
and is audited. The two-thread cross-PROCESS race is the PostgreSQL-gated
class at the bottom, which SKIPS on a venue without a scratch database.

No predicate is stubbed: the interleaving is a real second transaction
committing a real burn against a real database.
"""

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import AuditEvent, Base, Role, RoleMember, User
from fastapi import FastAPI, HTTPException
from server.recovery_codes import hash_recovery_code
from server.routes import recovery as recovery_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

PG_URL_ENV = "VENYA_TEST_PG_URL"
PEPPER = "test-pepper-512"
CODE = "ABCDEF-GHIJKL-MNOPQR-STUVWX"  # pragma: allowlist secret — synthetic dev-test value


def _stack(tmp_path, name="rec512.db"):
    """Real recovery route + real SQLite, seeded with one code-holding admin.

    The Backend is the real object with the engine/session-factory injected
    (the test_recovery.py `_build_real_app` shape) — every write these cells
    observe goes through a real session and a real transaction.
    """
    db_path = tmp_path / name
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    code_hash = hash_recovery_code(CODE, PEPPER)
    with SessionLocal() as s:
        admin_role = Role(name="admin", permissions="read-write")
        s.add(admin_role)
        s.flush()
        s.add(User(user_id="oldadmin", auth_mode="security-key", recovery_code_hash=code_hash))
        s.flush()
        s.add(RoleMember(user_id="oldadmin", role_id=admin_role.id))
        s.commit()

    backend = Backend(BackendConfig(database_url=f"sqlite:///{db_path}", kek=b"k" * KEK_SIZE))
    backend._engine = engine
    backend._session_factory = SessionLocal

    app = FastAPI()
    app.state.backend = backend
    app.state.config = SimpleNamespace(recovery_code_pepper=PEPPER)
    app.include_router(recovery_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False), SessionLocal, code_hash


def _fields(row):
    return json.loads(row.fields) if isinstance(row.fields, str) else (row.fields or {})


def _new_admins(session):
    return sorted(u.user_id for u in session.query(User).filter(User.user_id != "oldadmin").all())


class TestClaimAtomicityRealDB:
    """AC2: the claim is check-and-burn in ONE statement, across sessions."""

    def test_first_claim_wins_second_claim_is_zero(self, tmp_path):
        """Two REAL sessions, one code. The loser's own read still sees the
        live row (its transaction started before the burn committed), but the
        claim UPDATE re-evaluates at write time and matches 0 rows — that is
        the atomicity: no read-then-write window survives into the burn.
        """
        _, SessionLocal, code_hash = _stack(tmp_path)
        stale_reader = SessionLocal()
        try:
            # The identification read the route performs, on its own snapshot.
            seen = (
                stale_reader.query(User)
                .join(RoleMember)
                .join(Role)
                .filter(Role.name == "admin")
                .filter(User.recovery_code_hash == code_hash)
                .first()
            )
            assert seen is not None and seen.user_id == "oldadmin"

            # The winner burns on ANOTHER session and commits.
            with SessionLocal() as other:
                assert recovery_routes.claim_recovery_code(other, "oldadmin", code_hash) == 1
                other.commit()
                assert other.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is None

            # The loser's claim — its read above found the row — matches zero.
            assert recovery_routes.claim_recovery_code(stale_reader, "oldadmin", code_hash) == 0
            stale_reader.rollback()
        finally:
            stale_reader.close()

    def test_claim_burns_only_the_matching_hash(self, tmp_path):
        """Paired negative inside the claim: a submission whose hash does not
        match the stored one burns NOTHING (rowcount 0). Wrong-code attempts
        cannot consume anybody's code."""
        _, SessionLocal, code_hash = _stack(tmp_path)
        with SessionLocal() as s:
            assert recovery_routes.claim_recovery_code(s, "oldadmin", "f" * 64) == 0
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash == code_hash
            s.rollback()

    def test_claim_emits_one_conditional_update(self):
        """Statement construction (the #339 pin): the burn is ONE UPDATE whose
        WHERE carries BOTH the identified user and the submitted hash — check
        and burn together, no read-then-write window. A recording fake stands
        in for the session here; the real-DB cells above prove the effect."""
        captured = []

        class _R:
            rowcount = 1

        class _Db:
            def execute(self, stmt, *a, **k):
                captured.append(str(stmt))
                return _R()

        assert recovery_routes.claim_recovery_code(_Db(), "oldadmin", "deadbeef") == 1
        assert len(captured) == 1, captured
        stmt = captured[0]
        assert stmt.lstrip().startswith("UPDATE users")
        assert "WHERE users.user_id = :" in stmt and "users.recovery_code_hash = :" in stmt, stmt
        assert (
            stmt.count("SET recovery_code_hash=") == 1 and stmt.count("WHERE") == 1
        ), "one SET in one statement — no read-then-write pair"
        # Literal-render the same statement so the burned value is visible:
        # the SET target is NULL in the SAME statement that checks the hash.
        from sqlalchemy.dialects import postgresql

        rendered = None

        class _Render(_Db):
            def execute(self, statement, *a, **k):
                nonlocal rendered
                rendered = str(statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
                return _R()

        recovery_routes.claim_recovery_code(_Render(), "oldadmin", "deadbeef")
        assert "SET recovery_code_hash=NULL" in rendered, rendered
        assert "WHERE users.user_id = 'oldadmin' AND users.recovery_code_hash = 'deadbeef'" in rendered, rendered


class TestHandlerTrustsClaimNotRead:
    """AC1: two concurrent submissions of the same code — exactly ONE mints.

    The interleaving is driven for real: the loser's handler runs its
    identification read, then the WINNER's committed effect lands (a real
    second transaction burning the hash and minting its admin), then the
    loser's burn executes. The seam is a one-shot wrapper around the route's
    existing post-read critical log line — a call that exists at HEAD and
    post-fix alike, so the wrapper changes no predicate and the same cell is
    RED at HEAD (the loser's read-object burn no-ops silently and its mint
    commits) and GREEN after the fix (the claim re-evaluates, finds 0 rows,
    refuses 409).
    """

    def _run_interleaved(self, tmp_path):
        _, SessionLocal, _code_hash = _stack(tmp_path)
        real_logger = recovery_routes.logger
        fired = {"done": False}

        def _winner_effect():
            """What a winning submission commits: burned hash + its admin."""
            with SessionLocal() as w:
                w.query(User).filter(User.user_id == "oldadmin").update(
                    {"recovery_code_hash": None}, synchronize_session=False
                )
                w.add(User(user_id="winner-admin", auth_mode="security-key", enrolled_at=None))
                w.flush()
                admin_role = w.query(Role).filter(Role.name == "admin").one()
                w.add(RoleMember(user_id="winner-admin", role_id=admin_role.id))
                w.commit()

        class _Seam:
            """Proxy logger: fires the winner's commit once, right after the
            loser's identification read and before its burn. Pass-through
            otherwise — the wrapper adds no behavior the route depends on."""

            def critical(self, msg, *args):
                if "successful break-glass" in msg and not fired["done"]:
                    fired["done"] = True
                    _winner_effect()
                real_logger.critical(msg, *args)

            def __getattr__(self, name):
                return getattr(real_logger, name)

        loser_db = SessionLocal()
        request = SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.5"),
            app=SimpleNamespace(state=SimpleNamespace(config=SimpleNamespace(recovery_code_pepper=PEPPER))),
        )
        req = recovery_routes.RecoveryRequest(code=CODE, new_user_id="late-arrival")
        recovery_routes.logger = _Seam()
        try:
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(recovery_routes.recovery(req, request, loser_db))
        finally:
            recovery_routes.logger = real_logger
            loser_db.rollback()
            loser_db.close()
        return excinfo.value, SessionLocal

    def test_loser_is_refused_with_a_named_status(self, tmp_path):
        """RED at HEAD: at HEAD the wrapper's winner commit lands and the
        loser still mints (its ORM-object burn no-ops silently — no check
        re-evaluates), so this call RETURNS 200 and the raises-assertion
        fails with DID NOT RAISE. Post-fix the loser is refused 409 with a
        reason naming the cause and mints nothing."""
        exc, SessionLocal = self._run_interleaved(tmp_path)
        assert exc.status_code == 409
        assert "already consumed" in exc.detail.lower()
        with SessionLocal() as s:
            assert _new_admins(s) == ["winner-admin"], "only the winner's admin may exist"
            assert s.query(RoleMember).filter(RoleMember.user_id == "late-arrival").count() == 0
            assert s.query(User).filter(User.user_id == "late-arrival").count() == 0

    def test_refusal_is_audited_and_value_free(self, tmp_path):
        """AC1 audit half: the refusal leaves a lifecycle row naming the
        source admin and the attempted new user — and NO code material."""
        _exc, SessionLocal = self._run_interleaved(tmp_path)
        with SessionLocal() as s:
            rows = [e for e in s.query(AuditEvent).all() if e.event_type == "break_glass_recovery_used"]
            assert len(rows) == 1, rows
            fields = _fields(rows[0])
            assert fields["outcome"] == "refused_code_already_consumed"
            assert fields["new_user_id"] == "late-arrival"
            assert fields["code_consumed"] is False
            assert CODE not in json.dumps(fields) and hash_recovery_code(CODE, PEPPER) not in json.dumps(fields)


class TestSequentialContractRetained:
    """AC3 + AC4 paired positives/negatives on the full HTTP route."""

    def test_legit_recovery_still_works_and_burns(self, tmp_path):
        client, SessionLocal, _ = _stack(tmp_path)
        resp = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "fresh-admin"})
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert _new_admins(s) == ["fresh-admin"]
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is None
            rows = [e for e in s.query(AuditEvent).all() if e.event_type == "break_glass_recovery_used"]
            assert _fields(rows[-1])["code_consumed"] is True

    def test_second_submission_over_http_is_refused_mints_nothing(self, tmp_path):
        """The serialized form of the double-spend: the second submission
        (whose read now finds no hash) is refused and mints nothing — the
        end-state the whole ticket demands is ONE new admin."""
        client, SessionLocal, _ = _stack(tmp_path)
        first = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "alpha-admin"})
        second = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "beta-admin"})
        assert first.status_code == 200, first.text
        assert second.status_code == 401, second.text
        with SessionLocal() as s:
            assert _new_admins(s) == ["alpha-admin"]

    def test_wrong_code_and_burned_code_stay_401(self, tmp_path):
        """AC4 retained: wrong code 401 (and survives), and an already-burned
        code 401 — the pre-#512 negative halves must not change class."""
        client, SessionLocal, _ = _stack(tmp_path)
        bad = client.post("/api/v1/recovery", json={"code": "NOT-THE-CODE", "new_user_id": "xy-admin"})
        assert bad.status_code == 401
        good = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "xy-admin"})
        assert good.status_code == 200
        burned = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "zz-admin"})
        assert burned.status_code == 401
        with SessionLocal() as s:
            assert _new_admins(s) == ["xy-admin"]

    def test_failed_recovery_still_does_not_burn(self, tmp_path):
        """The pre-#512 placement contract survives the atomic claim: a 400
        user-exists refusal leaves the code LIVE (claim rolled back with the
        transaction), and the retry succeeds."""
        client, SessionLocal, code_hash = _stack(tmp_path)
        with SessionLocal() as s:
            s.add(User(user_id="clash-admin", auth_mode="security-key"))
            s.commit()
        clash = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "clash-admin"})
        assert clash.status_code == 400
        with SessionLocal() as s:
            assert (
                s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash == code_hash
            ), "the 400 consumed the code"
        retry = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": "fresh-admin"})
        assert retry.status_code == 200, retry.text


@pytest.mark.skipif(
    not os.environ.get(PG_URL_ENV),
    reason=f"real-concurrency cell needs a scratch PostgreSQL in {PG_URL_ENV} (not available on this venue)",
)
class TestDoubleSpendPostgresql:
    """AC1 + AC2 cross-PROCESS, physically: two sessions on two connections
    released together by a barrier (WRITTEN, NOT RUN ON THIS LEG — the spec
    bars VMs and fleet; its claims are unverified against a live server).
    Point VENYA_TEST_PG_URL at a SCRATCH database — it drops and recreates
    the IAM tables — never at anything live.

    Under READ COMMITTED the two claims serialize on the row lock; the loser
    re-evaluates its WHERE against the committed row (hash NULL) and gets
    rowcount 0 → 409. Before the fix (HEAD) both submissions mint — the harm
    this ticket is filed for.
    """

    def test_two_concurrent_submissions_one_admin(self):
        import threading

        db_url = os.environ[PG_URL_ENV]
        engine = create_engine(db_url)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        code_hash = hash_recovery_code(CODE, PEPPER)
        with SessionLocal() as s:
            admin_role = Role(name="admin", permissions="read-write")
            s.add(admin_role)
            s.flush()
            s.add(User(user_id="oldadmin", auth_mode="security-key", recovery_code_hash=code_hash))
            s.flush()
            s.add(RoleMember(user_id="oldadmin", role_id=admin_role.id))
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
        app.state.config = SimpleNamespace(recovery_code_pepper=PEPPER)
        app.include_router(recovery_routes.router, prefix="/api/v1")
        client = TestClient(app, raise_server_exceptions=False)

        barrier = threading.Barrier(2, timeout=10)
        codes = {}

        def run(uid):
            barrier.wait()
            codes[uid] = client.post("/api/v1/recovery", json={"code": CODE, "new_user_id": uid}).status_code

        threads = [threading.Thread(target=run, args=(uid,)) for uid in ("alpha-admin", "beta-admin")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        with SessionLocal() as s:
            assert sorted(codes.values()) in ([200, 409], [200, 401]), codes
            # 409 = the loser raced past the read; 401 = serialized (read
            # already saw the burn). Either refusal is legal; a SECOND mint
            # is not.
            assert len(_new_admins(s)) == 1, _new_admins(s)
            assert s.query(User).filter(User.user_id == "oldadmin").one().recovery_code_hash is None
