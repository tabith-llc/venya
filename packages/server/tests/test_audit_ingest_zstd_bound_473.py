# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#473 — the audit-ingest zstd brake bounds DECOMPRESSION, not just the body.

The old handler called the module-level ``zstd.decompress(body)``, which
materializes the FULL expansion (compressed_size x expansion_ratio) before
the ``len(payload) > INGEST_MAX_DECOMPRESSED_BYTES`` check could refuse it.
The fix asks ``ZstdDecompressor.decompress`` for exactly ``cap + 1`` bytes,
so the refusal is paid for in bounded RAM.

Load-bearing cells here assert the *mechanism* (the max_length the
decompression call received), not only the status code — a regression to the
unbounded form keeps answering 413 but FAILS these cells.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import audit as audit_routes
from starlette.testclient import TestClient

EXEC_CN = "venya-exec-1"
CAP = audit_routes.INGEST_MAX_DECOMPRESSED_BYTES


def _sqlite_ingest_backend():
    """Real in-memory SQLite backend (mirrors test_audit.py's ingest fixture,
    incl. the revocation tables the handler reads for sender_revoked) so
    rows land for real and refusals are paired with a zero-row check."""
    from core.iam.models import AuditEvent, Executor, ExecutorCert, ExecutorCertRevocation
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    for table in (
        AuditEvent.__table__,
        Executor.__table__,
        ExecutorCert.__table__,
        ExecutorCertRevocation.__table__,
    ):
        table.create(engine)
    session = sessionmaker(bind=engine)()
    session.add(Executor(id=EXEC_CN, hostname="venya-exec-1"))
    session.commit()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: sessionmaker(bind=engine)()
    return backend, sessionmaker(bind=engine), engine


def _ingest_app(auth_user, backend):
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    app = FastAPI()
    app.state.backend = backend
    app.include_router(audit_routes.router, prefix="/api/v1")

    class _AuthUserMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if auth_user is not None:
                request.state.auth_user = dict(auth_user)
            return await call_next(request)

    app.add_middleware(_AuthUserMiddleware)
    return app


def _executor_auth():
    return {"caller": "executor", "executor_id": EXEC_CN}


def _post(app, body: bytes, headers=None):
    hdrs = {"Content-Type": "application/x-ndjson", "Content-Encoding": "zstd"}
    if headers is not None:
        hdrs.update(headers)
    return TestClient(app, raise_server_exceptions=False).post("/api/v1/audit/ingest", content=body, headers=hdrs)


def _line(**over) -> str:
    payload = {
        "event_type": "command_executed",
        "session_id": "sess-473",
        "timestamp": (datetime.now(UTC) + timedelta(hours=-2)).isoformat(),
        "command": "ls -la",
    }
    payload.update(over)
    return json.dumps(payload)


def _compress(text: str) -> bytes:
    from compression import zstd

    return zstd.compress(text.encode(), level=3)


def _install_spy(monkeypatch, returns: bytes, eof=False, needs_input=False):
    """Replace compression.zstd.ZstdDecompressor (the name the handler looks
    up at call time) with a spy that records every max_length it receives.
    Replacing the CLASS keeps the spy independent of the real object's
    read-only eof/needs_input attributes; the handler must not read state it
    did not go through the spy for."""
    from compression import zstd as zstd_module

    recorded: list[int] = []

    class _SpyDecompressor:
        def __init__(self):
            self.eof = eof
            self.needs_input = needs_input
            self.unused_data = b""

        def decompress(self, data, max_length=-1):
            recorded.append(max_length)
            return returns

    monkeypatch.setattr(zstd_module, "ZstdDecompressor", _SpyDecompressor)
    return recorded


# --------------------------------------------------------------------------
# Load-bearing: the brake bounds the WORK, not just the verdict


def test_bounded_decompress_asks_for_cap_plus_one_and_refuses(monkeypatch):
    """High-expansion frame (50 MB of one byte -> a few KB compressed):
    the handler answers 413 AND the decompression call was asked for at most
    cap+1 bytes. Asserting the recorded kwarg (not only the 413) makes a
    regression to zstd.decompress(body) — which answers the same 413 after
    materializing 50 MB — FAIL this cell (kwarg list would be empty)."""
    bomb_frame = _compress("A" * 50_000_000)
    assert len(bomb_frame) < 10_000  # small request, huge expansion
    recorded = _install_spy(monkeypatch, returns=b"A" * (CAP + 1))
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)

    resp = _post(app, bomb_frame)

    assert resp.status_code == 413
    assert resp.json()["detail"] == f"Decompressed batch exceeds {CAP} bytes"
    assert recorded and all(m <= CAP + 1 for m in recorded), recorded
    assert recorded[0] == CAP + 1
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 0
    s.close()


def test_non_executor_403_before_any_decompression(monkeypatch):
    """Paired negative on the gate: the mTLS 403 fires first — the spy is
    never constructed/called, so a forged request cannot make the server
    decompress anything at all."""
    recorded = _install_spy(monkeypatch, returns=b"")
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app({"caller": "user", "user_id": "u1"}, backend)

    resp = _post(app, _compress(_line()))

    assert resp.status_code == 403
    assert recorded == []
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 0
    s.close()


# --------------------------------------------------------------------------
# Real-mechanism edges (no spy — the bounded class API does the work)


def test_legit_batch_under_cap_accepted():
    """Under-cap batch → 200 with rows written and the same line count."""
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)
    text = "\n".join([_line(), _line(session_id="sess-473b")]) + "\n"

    resp = _post(app, _compress(text))

    assert resp.status_code == 200
    assert resp.json() == {"accepted": 2}
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 2
    s.close()


def test_exact_cap_frame_still_accepted():
    """Decompressed size EXACTLY the cap → accepted (no off-by-one). One
    valid line, padded with blank lines to land on the cap; blank lines are
    filtered before the line cap, so only the byte edge is under test."""
    line = _line()
    text = line + "\n" * (CAP - len(line))  # len(text) == CAP exactly
    assert len(text.encode()) == CAP
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)

    resp = _post(app, _compress(text))

    assert resp.status_code == 200
    assert resp.json() == {"accepted": 1}
    s = sm()
    from core.iam.models import AuditEvent

    assert s.query(AuditEvent).count() == 1
    s.close()


def test_one_byte_over_cap_refused_413():
    """Decompressed size cap+1 → 413 with the byte-identical detail string."""
    line = _line()
    text = line + "\n" * (CAP + 1 - len(line))  # len(text) == CAP+1 exactly
    assert len(text.encode()) == CAP + 1
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)

    resp = _post(app, _compress(text))

    assert resp.status_code == 413
    assert resp.json()["detail"] == f"Decompressed batch exceeds {CAP} bytes"
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 0
    s.close()


# --------------------------------------------------------------------------
# Failure path did not move


def test_non_zstd_garbage_400():
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)

    resp = _post(app, b"this is not a zstd frame")

    assert resp.status_code == 400
    assert resp.json()["detail"] == "zstd decompression failed"
    s = sm()
    from core.iam.models import AuditEvent

    assert s.query(AuditEvent).count() == 0
    s.close()


def test_truncated_frame_400():
    """Half a valid frame: the module-level decompress used to raise on this
    (400); the class API returns partial output with needs_input=True, and
    the fix keeps the 400 rather than accepting the partial payload."""
    full = _compress("\n".join([_line()] * 200) + "\n")
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)

    resp = _post(app, full[: len(full) // 2])

    assert resp.status_code == 400
    assert resp.json()["detail"] == "zstd decompression failed"
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 0
    s.close()


def test_line_cap_still_413():
    """INGEST_MAX_LINES brake unchanged: over-cap line count → 413 with the
    existing detail, zero rows."""
    backend, sm, _engine = _sqlite_ingest_backend()
    app = _ingest_app(_executor_auth(), backend)
    over = audit_routes.INGEST_MAX_LINES + 1
    body = _compress("\n".join([_line()] * over))

    resp = _post(app, body)

    assert resp.status_code == 413
    assert resp.json()["detail"] == f"Batch exceeds {audit_routes.INGEST_MAX_LINES}-line ingest cap"
    from core.iam.models import AuditEvent

    s = sm()
    assert s.query(AuditEvent).count() == 0
    s.close()
