# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#440 truth table — secret/session authorization checks bind to the CALLER.

secret-session-authorization-scoping: four gates in the secret/session surface
scoped by object NAME or by caller CLASS instead of the caller's own binding.
Every cell here runs ZERO mocks over the DB — real SQLite, real rows, real
`Core` visibility enforcement, and the routes under test — because each defect
was invisible to a mock: a MagicMock `filter()` ignores predicates, so a
cross-owner row pick and a cross-executor session pick both looked green.

Paired-negative law applied per gate:

* gate 1 (routes/secrets.py `update_secret_metadata`) — a key the caller does
  not own is 404 and the owner's row stays byte-identical.
* gate 2 (routes/secrets.py `revoke_session_secrets`) — an executor revoking
  another executor's session is 403 and that session's bindings survive.
* gate 3 (routes/filter.py `filter_session_output`) — an executor filtering
  another executor's session is 403, with no masking answer to leak.
* gate 4 (routes/filter.py, same function) — the route resolves EXECUTION
  sessions only; an id that names an AUTH session is not a secret source, and
  the bound path masks exactly its bound secrets and nothing else.
"""

from datetime import UTC, datetime, timedelta

import pytest
from core.engine.backend import Backend, BackendConfig
from core.engine.encryption import KEK_SIZE
from core.iam.models import (
    Base,
    ExecutionSession,
    Executor,
    Role,
    RoleMember,
    Secret,
    Session,
    SessionSecret,
    User,
)
from fastapi import FastAPI
from server.routes import filter as filter_routes
from server.routes import secrets as secrets_routes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

KEK = b"k" * KEK_SIZE
VALUE_ONE = b"one-bound-marker"
VALUE_TWO = b"two-unbound-marker"
SESSION_A = "sess-A"
SESSION_B = "sess-B"
AUTH_SESSION_ID = 4321


def _make_engine(tmp_path, name="scoping440.db"):
    """Real SQLite schema + the identity graph every gate needs.

    Users alice/bob both hold 'dev' (read-write), so BOTH pass
    require_role("read-write") and both would pass a role-scoped visibility
    check — the distinction the gates must still make is OWNERSHIP and
    BINDING, not visibility. Backend._create_engine is bypassed: it issues
    PostgreSQL-only pragmas that break SQLite (same convention as
    tests/test_secrets.py::TestSecretUpsertRoute).
    """
    db_path = tmp_path / name
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    now = datetime.now(UTC)
    s = SessionLocal()
    dev = Role(name="dev", permissions="read-write")
    s.add_all([User(user_id="alice"), User(user_id="bob"), dev])
    s.flush()
    s.add_all([RoleMember(user_id="alice", role_id=dev.id), RoleMember(user_id="bob", role_id=dev.id)])
    s.add_all(
        [
            Executor(id="exec1", hostname="192.0.2.14", status="active"),
            Executor(id="exec2", hostname="192.0.2.15", status="active"),
        ]
    )
    s.add_all(
        [
            # The session kinds are DISTINCT tables — gate 4's whole point:
            # ExecutionSession.id is a String UUID, auth Session.id is an Integer.
            Session(
                id=AUTH_SESSION_ID,
                user_id="alice",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            ),
            ExecutionSession(
                id=SESSION_A,
                user_id="alice",
                executor_id="exec1",
                command="",
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            ),
            ExecutionSession(
                id=SESSION_B,
                user_id="alice",
                executor_id="exec2",
                command="",
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            ),
        ]
    )
    s.commit()
    s.close()
    return engine, SessionLocal


def _make_backend(engine, SessionLocal):
    backend = Backend(BackendConfig(database_url="sqlite:///:memory:", kek=KEK))
    backend._engine = engine
    backend._session_factory = SessionLocal
    return backend


def _executor_app(engine, SessionLocal, executor_id, routes=("revoke", "filter")):
    """Routes under test + the mTLS executor identity the middleware attaches."""

    class ExecutorAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": executor_id}
            return await call_next(request)

    app = FastAPI()
    app.state.backend = _make_backend(engine, SessionLocal)
    if "revoke" in routes:
        app.include_router(secrets_routes.router, prefix="/api/v1")
    if "filter" in routes:
        app.include_router(filter_routes.router, prefix="/api/v1")
    app.add_middleware(ExecutorAuthMiddleware)
    return TestClient(app, raise_server_exceptions=False)


def _env(tmp_path, executor_id, routes=("revoke", "filter")):
    """One fresh dataset + a client whose caller is `executor_id`."""
    engine, SessionLocal = _make_engine(tmp_path)
    client = _executor_app(engine, SessionLocal, executor_id, routes=routes)
    return client, SessionLocal, engine


def _human_app(SessionLocal, engine, user_id):
    """App for the HUMAN secrets routes with a real Core in the visibility path."""
    from server.dependencies import get_current_user

    app = FastAPI()
    backend = _make_backend(engine, SessionLocal)
    app.state.backend = backend
    app.state.core = backend.get_core()
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id, "caller": "human"}
    return TestClient(app, raise_server_exceptions=False)


def _secret_rows(SessionLocal):
    s = SessionLocal()
    try:
        return {row.key: (row.created_by, dict(row.meta or {}), row.id) for row in s.query(Secret).all()}
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Gate 1 — PATCH /secrets/{key}/metadata scopes the WRITE to the caller's row.
# ---------------------------------------------------------------------------


class TestMetadataWriteScopedToCaller:
    def test_non_owner_cross_user_key_404_owner_row_untouched(self, tmp_path):
        """Negative half: bob may SEE alice's role-scoped key (core.get passes —
        'dev' is in scope) but he does not OWN it, so the metadata writer must
        not touch alice's row and the answer is a 404 indistinguishable from a
        nonexistent key (no existence leak, the convention in this file)."""
        engine, SessionLocal = _make_engine(tmp_path)
        client = _human_app(SessionLocal, engine, "bob")

        core = _make_backend(engine, SessionLocal).get_core()
        core.put("shared-key", b"alice-value", "alice", ["dev"], "v1", meta={"purpose": "original"})

        resp = client.patch(
            "/api/v1/secrets/shared-key/metadata",
            json={"metadata": {"purpose": "pwned"}},
        )
        assert resp.status_code == 404, resp.text

        rows = _secret_rows(SessionLocal)
        assert rows["shared-key"] == (
            "alice",
            {"purpose": "original"},
            rows["shared-key"][2],
        ), "a cross-owner PATCH must leave the owner's meta byte-identical"
        engine.dispose()

    def test_owner_patch_still_succeeds_and_merges(self, tmp_path):
        """Positive half: the same key, same request, from the OWNER — 200 and
        the merge semantics (existing fields preserved) still work. Without this
        cell the negative test could 'pass' by the route rejecting everything."""
        engine, SessionLocal = _make_engine(tmp_path)
        client = _human_app(SessionLocal, engine, "alice")

        core = _make_backend(engine, SessionLocal).get_core()
        core.put(
            "shared-key",
            b"alice-value",
            "alice",
            ["dev"],
            "v1",
            meta={"executor": "web-server-3", "purpose": "original"},
        )

        resp = client.patch(
            "/api/v1/secrets/shared-key/metadata",
            json={"metadata": {"purpose": "updated", "username": "bot"}},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["metadata"] == {
            "executor": "web-server-3",
            "purpose": "updated",
            "username": "bot",
        }
        assert data["key"] == "shared-key"

        rows = _secret_rows(SessionLocal)
        assert rows["shared-key"][0] == "alice"
        assert rows["shared-key"][1] == {
            "executor": "web-server-3",
            "purpose": "updated",
            "username": "bot",
        }
        engine.dispose()

    def test_two_rows_same_key_each_owner_writes_only_its_own(self, tmp_path):
        """Truth table on uq_secrets_key_created_by: two rows, same key string,
        different owners. Each owner's PATCH resolves their OWN row — before the
        fix the bare `Secret.key` read resolved the first row in id order and
        rewrote alice's meta out from under her."""
        engine, SessionLocal = _make_engine(tmp_path)
        core = _make_backend(engine, SessionLocal).get_core()
        core.put("dup-key", b"alice-value", "alice", ["dev"], "v1", meta={"who": "alice"})
        with SessionLocal() as s:
            bob_role = Role(name="bob-only", permissions="read-write")
            s.add(bob_role)
            s.flush()
            s.add(RoleMember(user_id="bob", role_id=bob_role.id))
            s.commit()
        # bob stores his own row under the same key string (scoped to a role alice
        # is not in), so exactly two rows share the name "dup-key".
        core.put("dup-key", b"bob-value", "bob", ["bob-only"], "v1", meta={"who": "bob"})

        bob_client = _human_app(SessionLocal, engine, "bob")
        resp = bob_client.patch("/api/v1/secrets/dup-key/metadata", json={"metadata": {"note": "from-bob"}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["key"] == "dup-key"

        s = SessionLocal()
        try:
            rows = s.query(Secret).filter(Secret.key == "dup-key").order_by(Secret.id).all()
            assert len(rows) == 2, "two owners may hold the same key (uq_secrets_key_created_by)"
            by_owner = {r.created_by: dict(r.meta or {}) for r in rows}
            assert by_owner["bob"] == {"who": "bob", "note": "from-bob"}
            assert by_owner["alice"] == {"who": "alice"}, "alice's row must be untouched"
        finally:
            s.close()
        engine.dispose()

    def test_unknown_key_404(self, tmp_path):
        """Baseline: a key nobody owns stays 404 (the negative half of the
        positive PATCH cell, and the shape the cross-owner deny imitates)."""
        engine, SessionLocal = _make_engine(tmp_path)
        client = _human_app(SessionLocal, engine, "alice")
        resp = client.patch("/api/v1/secrets/nope/metadata", json={"metadata": {"purpose": "x"}})
        assert resp.status_code == 404
        engine.dispose()


# ---------------------------------------------------------------------------
# Gate 2 — POST /sessions/{id}/secrets/revoke binds the session to the caller.
# ---------------------------------------------------------------------------


class TestRevokeCallerBinding:
    def _seed_binding(self, SessionLocal, session_id):
        """One real Secret row bound to `session_id`; returns its id."""
        s = SessionLocal()
        try:
            secret = Secret(
                key=f"pw-{session_id}",
                encrypted_value=b"x",
                nonce=b"n",
                wrapped_dek=b"w",
                key_version_id="v1",
                created_by="alice",
                meta={},
            )
            s.add(secret)
            s.flush()
            s.add(SessionSecret(session_id=session_id, secret_id=secret.id, wrapped_value="[VENYA]x[/VENYA]"))
            s.commit()
            return secret.id
        finally:
            s.close()

    def test_foreign_executor_revoke_403_and_rows_survive(self, tmp_path):
        """Negative half: exec1 (the caller) revoking exec2's session must be a
        403 with that session's bindings INTACT — the class check alone accepted
        it before, so any enrolled executor could blind another executor's run."""
        client, SessionLocal, engine = _env(tmp_path, "exec1", routes=("revoke",))
        secret_id = self._seed_binding(SessionLocal, SESSION_B)

        resp = client.post(f"/api/v1/sessions/{SESSION_B}/secrets/revoke", json={"secret_ids": [str(secret_id)]})
        assert resp.status_code == 403, resp.text
        assert "another executor" in resp.json()["detail"]

        s = SessionLocal()
        try:
            rows = s.query(SessionSecret).filter(SessionSecret.session_id == SESSION_B).all()
            assert [r.secret_id for r in rows] == [secret_id], "the foreign session keeps its bindings"
        finally:
            s.close()
        engine.dispose()

    def test_bound_executor_revoke_succeeds(self, tmp_path):
        """Positive half: the executor the session IS bound to revokes its own
        secrets — 200, honest count, rows gone (the #411 ruled shape)."""
        client, SessionLocal, engine = _env(tmp_path, "exec2", routes=("revoke",))
        secret_id = self._seed_binding(SessionLocal, SESSION_B)

        resp = client.post(f"/api/v1/sessions/{SESSION_B}/secrets/revoke", json={"secret_ids": [str(secret_id)]})
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"revoked": True, "count": 1, "session_id": SESSION_B}

        s = SessionLocal()
        try:
            assert s.query(SessionSecret).filter(SessionSecret.session_id == SESSION_B).all() == []
        finally:
            s.close()
        engine.dispose()

    def test_vanished_session_revoke_still_honest_noop(self, tmp_path):
        """Scope pin: a session row that the TTL purge already removed stays the
        documented 200 / count=0 answer (#411) — the binding check denies a
        FOREIGN executor, it does not add a new failure mode for the reaper."""
        client, _, engine = _env(tmp_path, "exec1", routes=("revoke",))
        resp = client.post("/api/v1/sessions/never-existed/secrets/revoke", json={"secret_ids": ["1"]})
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"revoked": True, "count": 0, "session_id": "never-existed"}
        engine.dispose()


# ---------------------------------------------------------------------------
# Gates 3 + 4 — POST /sessions/{id}/filter binds the session to the caller and
# resolves EXECUTION sessions only.
# ---------------------------------------------------------------------------


class TestFilterCallerBindingAndSessionKind:
    def _seed_secrets(self, SessionLocal, label, values, bind_first_to=None):
        """Store real encrypted Secret rows for alice; bind the FIRST one to
        `bind_first_to` when given.

        The unbound rows are the bait: masking against them would prove the
        route read more than the session's SessionSecret bindings (gate 4).
        """
        from core.engine.encryption import encrypt_secret

        s = SessionLocal()
        try:
            ids = []
            for i, value in enumerate(values):
                wrapped_dek, nonce, ciphertext = encrypt_secret(KEK, value)
                secret = Secret(
                    key=f"secret-{label}-{i}",
                    encrypted_value=ciphertext,
                    nonce=nonce,
                    wrapped_dek=wrapped_dek,
                    key_version_id="v1",
                    created_by="alice",
                    meta={},
                )
                s.add(secret)
                s.flush()
                ids.append(secret.id)
            if bind_first_to is not None and ids:
                s.add(
                    SessionSecret(
                        session_id=bind_first_to,
                        secret_id=ids[0],
                        wrapped_value="[VENYA]aaa[/VENYA]",
                    )
                )
            s.commit()
            return ids
        finally:
            s.close()

    def test_foreign_executor_filter_403_no_masking_answer(self, tmp_path):
        """Gate 3 negative half: exec1 asking about exec2's session gets 403 —
        and gets NO FilterResponse, so there is no masked_count/masked_hashes
        oracle about a session it was never routed to."""
        engine, SessionLocal = _make_engine(tmp_path)
        self._seed_secrets(SessionLocal, "b", [VALUE_ONE], bind_first_to=SESSION_B)

        client = _executor_app(engine, SessionLocal, "exec1", routes=("filter",))
        import base64

        stdout = base64.b64encode(b"leaked " + VALUE_ONE).decode()
        resp = client.post(
            f"/api/v1/sessions/{SESSION_B}/filter",
            json={"stdout": stdout, "stderr": base64.b64encode(b"").decode()},
        )
        assert resp.status_code == 403, resp.text
        assert "another executor" in resp.json()["detail"]
        # No masking knowledge in the body at all.
        assert "masked_count" not in resp.text
        assert VALUE_ONE.decode() not in resp.text
        engine.dispose()

    def test_bound_executor_filter_masks_exactly_its_bound_secret(self, tmp_path):
        """Gates 3 + 4 positive half: the bound executor gets the definitive
        answer, and the knowledge set is EXACTLY this session's bound secrets —
        the same user's other secrets are not consulted (pre-fix the
        auth-session branch decrypted every secret that user owns)."""
        engine, SessionLocal = _make_engine(tmp_path)
        self._seed_secrets(SessionLocal, "a", [VALUE_ONE, VALUE_TWO], bind_first_to=SESSION_A)

        client = _executor_app(engine, SessionLocal, "exec1", routes=("filter",))
        import base64

        payload = b"one " + VALUE_ONE + b" two " + VALUE_TWO
        stdout = base64.b64encode(payload).decode()
        resp = client.post(
            f"/api/v1/sessions/{SESSION_A}/filter",
            json={"stdout": stdout, "stderr": base64.b64encode(b"").decode()},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        decoded = base64.b64decode(data["stdout"]).decode()

        assert VALUE_ONE.decode() not in decoded, "bound secret must be masked"
        assert "[REDACTED:" in decoded
        assert VALUE_TWO.decode() in decoded, (
            "an UNBOUND secret of the same user is not this session's business — masking it "
            "would mean the route is reading more than the SessionSecret bindings (gate 4)"
        )
        assert data["masked_count"] == 1
        engine.dispose()

    def test_auth_session_id_is_not_a_secret_source_404(self, tmp_path):
        """Gate 4 negative half: the integer 4321 exists in the AUTH sessions
        table (with its owner holding real secrets) and in NO execution_sessions
        row. It must resolve nothing — 404, the fail-closed shape this route
        already uses for unknown sessions, so the executor keeps its Stage-1
        masking instead of adopting an answer built from the wrong table."""
        engine, SessionLocal = _make_engine(tmp_path)
        # One secret bound to exec1's own session: a 200 for AUTH_SESSION_ID
        # could then only come from reading the WRONG table.
        self._seed_secrets(SessionLocal, "auth", [VALUE_ONE], bind_first_to=SESSION_A)

        client = _executor_app(engine, SessionLocal, "exec1", routes=("filter",))
        import base64

        stdout = base64.b64encode(b"leaked " + VALUE_ONE).decode()
        resp = client.post(
            f"/api/v1/sessions/{AUTH_SESSION_ID}/filter",
            json={"stdout": stdout, "stderr": base64.b64encode(b"").decode()},
        )
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"] == "Session not found"
        # The caller never learns anything about alice's secrets either way.
        assert "masked_count" not in resp.text
        assert base64.b64encode(b"leaked " + VALUE_ONE).decode() not in resp.text
        engine.dispose()

    def test_zero_binding_session_still_returns_200(self, tmp_path):
        """Positive control for the 404 cell: a real ExecutionSession bound to
        the caller with NO secret bindings is a legitimate 200 no-op (the
        stage2 fail-closed rule refuses UNKNOWN sessions only)."""
        engine, SessionLocal = _make_engine(tmp_path)
        client = _executor_app(engine, SessionLocal, "exec1", routes=("filter",))
        import base64

        stdout = base64.b64encode(b"nothing bound").decode()
        resp = client.post(
            f"/api/v1/sessions/{SESSION_A}/filter",
            json={"stdout": stdout, "stderr": base64.b64encode(b"").decode()},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["stdout"] == stdout
        engine.dispose()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
