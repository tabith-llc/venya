# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL-2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#452 — the stage-2 filter refuses an undecodable body (ticket
refs #452: an undecodable ``stdout``/``stderr`` was swallowed to ``b""`` and
answered HTTP 200 with ``masked_count=0`` — the route could not tell
"nothing matched" from "I could not parse you". The fix answers 400 BEFORE any
secret is decrypted, naming the offending field; the executor's existing
non-200 fallback then keeps the Stage-1 masked results.

Truth table (every refusal cell has its paired negative):
- malformed bodies  -> 400, field named, warning logged, NO body/no masked_count
- well-formed bodies -> the SAME 200 shape as before the change
- ``""`` is LEGAL base64 (decodes to ``b""``) -> still 200-with-zero-knowledge,
  NOT a 400 — pinned out loud below.
"""

import base64
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.engine.secure_memory import KekCache
from fastapi import FastAPI
from server.routes import filter as filter_routes
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.testclient import TestClient

SESSION_ID = "sess-452"


def _create_test_app(backend=None, executor_id="venya-exec-1"):
    """Minimal test app: the filter route behind executor-mTLS caller state."""

    app = FastAPI()
    if backend is not None:
        app.state.backend = backend
    app.include_router(filter_routes.router, prefix="/api/v1")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            request.state.auth_user = {"caller": "executor", "executor_id": executor_id}
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    return app


def _exec_session(session_id=SESSION_ID, executor_id="venya-exec-1"):
    return SimpleNamespace(id=session_id, executor_id=executor_id)


def _db_stub(*, exec_session=None, bindings=(), secrets=()):
    """Query stub over the three reads the stage-2 route makes (same shape as
    test_filter_endpoint.py's stub: ExecutionSession, SessionSecret, Secret)."""
    secret_by_id = {s.id: s for s in secrets}

    class _Q:
        def __init__(self, kind):
            self._kind = kind
            self._wanted = None

        def filter(self, *args, **kwargs):
            if self._kind == "secret" and args:
                try:
                    self._wanted = args[0].right.value
                except AttributeError:
                    pass
            return self

        def first(self):
            if self._kind == "exec":
                return exec_session
            if self._kind == "secret":
                return secret_by_id.get(self._wanted)
            return None

        def all(self):
            if self._kind == "bindings":
                return list(bindings)
            return []

    def query_side_effect(model):
        name = model.__name__
        if name == "ExecutionSession":
            return _Q("exec")
        if name == "SessionSecret":
            return _Q("bindings")
        return _Q("secret")

    db = MagicMock()
    db.query.side_effect = query_side_effect
    return db


def _secret_row(secret_id=1, key="mysecret"):
    return SimpleNamespace(
        id=secret_id,
        key=key,
        encrypted_value=b"encrypted_data",
        nonce=b"nonce12345678901",
        wrapped_dek=b"wrapped_dk12345678",
    )


def _binding_db():
    """An existing session bound to one decryptable secret."""
    return _db_stub(
        exec_session=_exec_session(),
        bindings=[SimpleNamespace(secret_id=1)],
        secrets=[_secret_row(1, "aws_api_key")],
    )


def _client(backend):
    return TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)


GOOD_STDOUT = base64.b64encode(b"clean stdout").decode()
GOOD_STDERR = base64.b64encode(b"clean stderr").decode()


class TestStage2DecodeRefusal:
    """The silent swallow is gone: undecodable fields get 400, named, logged."""

    def test_nonbase64_stdout_refused_400_names_field_warns_and_has_no_body(self, caplog):
        """AC1/AC3: non-base64 ``stdout`` -> 400 naming ``stdout``; caplog shows
        the warning with the session id; the 400 carries NO masked_count/masked_hashes
        body — assert the keys are absent, not merely empty."""
        caplog.set_level(logging.WARNING, logger="venya.server")
        client = _client_with_plain_kek(_binding_db())
        resp = client.post(
            f"/api/v1/sessions/{SESSION_ID}/filter",
            json={"stdout": "not-valid-base64!!!", "stderr": GOOD_STDERR},
        )
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "stdout" in detail
        assert "base64" in detail.lower()
        # No empty-knowledge answer rides along with the refusal:
        assert "masked_count" not in resp.json()
        assert "masked_hashes" not in resp.json()
        # AC3 — the silent branch must not exist: warning names session + field.
        assert SESSION_ID in caplog.text
        assert "stdout" in caplog.text

    def test_nonbase64_stderr_refused_400_names_stderr(self):
        """Paired field: non-base64 ``stderr`` -> 400 naming ``stderr`` (and it
        must NOT blame stdout)."""
        client = _client_with_plain_kek(_binding_db())
        resp = client.post(
            f"/api/v1/sessions/{SESSION_ID}/filter",
            json={"stdout": GOOD_STDOUT, "stderr": "also!invalid!!!"},
        )
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "stderr" in detail
        assert "stdout" not in detail

    def test_leniently_decodable_junk_is_refused(self):
        """The class the OLD ``b64decode`` (validate=False) ACCEPTED silently:
        ``base64.b64decode('!!!!aGVsbG8=')`` -> ``b'hello'`` (non-alphabet chars
        dropped). With the fix this input is a 400, not a masked 'hello'.
        Quoted assertion below."""
        # Mechanism of verification, stated out loud:
        assert base64.b64decode("!!!!aGVsbG8=") == b"hello"  # lenient accepts
        import binascii

        try:
            base64.b64decode("!!!!aGVsbG8=", validate=True)
            raise AssertionError("validate=True should reject non-alphabet input")
        except binascii.Error:
            pass

        client = _client_with_plain_kek(_binding_db())
        resp = client.post(
            f"/api/v1/sessions/{SESSION_ID}/filter",
            json={"stdout": "!!!!aGVsbG8=", "stderr": GOOD_STDERR},
        )
        assert resp.status_code == 400
        assert "stdout" in resp.json()["detail"]

    def test_truncated_padding_wrong_is_refused(self):
        """Truncated / wrongly-padded base64 -> 400. Asserted inputs:
        ``'aGVsbG8'`` (padding stripped -> binascii 'Incorrect padding') and
        ``'aGVsbG8=XXXX'`` (data after padding)."""
        client = _client_with_plain_kek(_binding_db())
        for bad in ("aGVsbG8", "aGVsbG8=XXXX"):
            resp = client.post(
                f"/api/v1/sessions/{SESSION_ID}/filter",
                json={"stdout": bad, "stderr": GOOD_STDERR},
            )
            assert resp.status_code == 400, bad
            assert "stdout" in resp.json()["detail"]

    def test_refusal_costs_no_decryption_work(self):
        """The refusal fires BEFORE the secret walk: with a decryptable secret
        bound, a malformed body must still 400 with decrypt_secret NEVER
        called (no decryption work happens for a refused request)."""
        backend_db = _binding_db()
        backend = MagicMock()
        backend.get_session.return_value = backend_db
        backend.kek_cache = KekCache.from_bytes(b"A" * 32, mlock=False)
        client = TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)
        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
            resp = client.post(
                f"/api/v1/sessions/{SESSION_ID}/filter",
                json={"stdout": "not-valid-base64!!!", "stderr": GOOD_STDERR},
            )
        assert resp.status_code == 400
        mock_decrypt.assert_not_called()

    def test_empty_string_is_legal_base64_and_still_200(self):
        """Pinned out loud: ``stdout=""`` is the base64 of empty input — it
        decodes to ``b''`` LEGALLY, so the empty-string body must still be the
        200-with-zero-knowledge answer, NOT a 400. This is the only
        zero-answer case that stays, and it is a well-formed one.
        (Session has zero bindings — the legitimate nothing-to-mask 200.)"""
        client = _client_with_plain_kek(_db_stub(exec_session=_exec_session()))
        resp = client.post(
            f"/api/v1/sessions/{SESSION_ID}/filter",
            json={"stdout": "", "stderr": ""},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == ""
        assert data["stderr"] == ""
        assert data["masked_count"] == 0


class TestStage2HappyPathUnchanged:
    """Paired negatives — what must KEEP working, byte-identically."""

    def test_wellformed_with_matching_secret_masks_as_before_and_logs_no_warning(self, caplog):
        """Paired negative 1: well-formed body with a matching secret -> the
        same 200 shape (masked content, masked_count=1) and a CLEAN caplog —
        zero venva.server warnings on the happy path."""
        caplog.set_level(logging.WARNING, logger="venya.server")
        backend = MagicMock()
        backend.get_session.return_value = _binding_db()
        backend.kek_cache = KekCache.from_bytes(b"A" * 32, mlock=False)
        client = TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)

        plaintext = b"AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
        stdout = base64.b64encode(b"output: AKIAIOSFODNN7EXAMPLE done").decode()  # pragma: allowlist secret
        stderr = GOOD_STDERR
        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
            mock_decrypt.return_value = plaintext
            resp = client.post(
                f"/api/v1/sessions/{SESSION_ID}/filter",
                json={"stdout": stdout, "stderr": stderr},
            )

        assert resp.status_code == 200
        data = resp.json()
        decoded = base64.b64decode(data["stdout"]).decode()
        assert "AKIAIOSFODNN7EXAMPLE" not in decoded  # pragma: allowlist secret
        assert "[REDACTED:" in decoded
        assert data["masked_count"] == 1
        assert data["stderr"] == stderr
        # caplog clean: no venva.server warning on the happy path.
        warnings = [r for r in caplog.records if r.name == "venya.server" and r.levelno >= logging.WARNING]
        assert warnings == []

    def test_wellformed_nothing_matches_keeps_zero_answer_200(self):
        """Paired negative 2 (truth table): well-formed body, nothing matches ->
        200 + masked_count=0. This zero answer is the ONLY case that keeps it —
        it proves the fix discriminates 'nothing matched' (200/0) from
        'undecodable' (400), where before both were 200/0."""
        backend = MagicMock()
        backend.get_session.return_value = _binding_db()
        backend.kek_cache = KekCache.from_bytes(b"A" * 32, mlock=False)
        client = TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)

        with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
            mock_decrypt.return_value = b"SOMETHING-ELSE-12345"
            resp = client.post(
                f"/api/v1/sessions/{SESSION_ID}/filter",
                json={"stdout": GOOD_STDOUT, "stderr": GOOD_STDERR},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["stdout"] == GOOD_STDOUT
        assert data["stderr"] == GOOD_STDERR
        assert data["masked_count"] == 0
        assert data["masked_hashes"] == []


def _client_with_plain_kek(db_stub):
    """Backend stub with a populated KEK; the malformed-body cells never reach
    decryption, so no decrypt_secret patch is needed."""
    backend = MagicMock()
    backend.get_session.return_value = db_stub
    backend.kek_cache = KekCache.from_bytes(b"A" * 32, mlock=False)
    return TestClient(_create_test_app(backend=backend), raise_server_exceptions=False)
