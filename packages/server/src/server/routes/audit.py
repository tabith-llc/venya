# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Audit log endpoints."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..dependencies import get_db, require_role

logger = logging.getLogger("venya.server")

router = APIRouter()

# Ingest guards (#307): the executor forwarder batches are bounded by its
# max_batch_lines (default 500) — #310 clamps that config to THIS cap at
# executor boot and makes the forwarder halve-and-retry on 413
# (executor config.py symbol SERVER_INGEST_MAX_LINES mirrors it; interlock-
# tested, no import), so this server-side line cap is now a defense-in-
# depth guard (D3), not a stall trigger. The byte budget is the
# decompression-bomb brake checked BEFORE any DB write (the request-size
# middleware bounds the COMPRESSED body; zstd can expand thousands-fold).
INGEST_MAX_LINES = 2000
INGEST_MAX_DECOMPRESSED_BYTES = 8_000_000


# --- Request/Response models ---


class AuditEventResponse(BaseModel):
    id: int
    event_type: str
    user_id: str | None = None
    fields: dict[str, Any] | None = None
    timestamp: str


class AuditListResponse(BaseModel):
    events: list[AuditEventResponse]
    total: int = 0
    limit: int = 100
    offset: int = 0


# --- Endpoints ---


@router.get(
    "/audit",
    response_model=AuditListResponse,
    status_code=status.HTTP_200_OK,
)
async def audit_list(
    user: str | None = Query(None, description="Filter by user ID"),
    key: str | None = Query(None, description="Filter by secret key"),
    start_date: str | None = Query(None, description="Start date (ISO 8601)"),
    end_date: str | None = Query(None, description="End date (ISO 8601)"),
    days: int | None = Query(None, description="Last N days"),
    hours: int | None = Query(None, description="Last N hours"),
    event_type: str | None = Query(None, description="Filter by event type"),
    executor_id: str | None = Query(None, description="Filter by executor ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    auth_user: dict = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> AuditListResponse:
    """Query audit log.

    Gated at the AUDITOR tier (ticket auditor-role): auditor or read-write
    roles pass (admin holds read-write); plain "read" memberships are denied
    — audit access is auditor-scoped, a deliberate release-notes behavior
    change for read-only users who previously queried this route.

    Admin users and auditor-tier holders see all events; other callers
    see only their own events (filtered by user_id). Non-human callers
    (no user_id) receive an empty result to prevent event leakage.
    """
    from datetime import datetime, timedelta

    from core.iam.models import AuditEvent

    query = db.query(AuditEvent)

    # Non-human callers (no user_id, e.g. mTLS executors) get empty result.
    user_id = auth_user.get("user_id")
    if user_id is None:
        return AuditListResponse(events=[], total=0, limit=limit, offset=offset)

    # Non-admin: filter to own events only — UNLESS the caller holds an
    # auditor-tier membership (auditor-role ticket, owner ruling
    # 2026-09-30: an auditor who can only see their own events is not an
    # auditor — auditor-tier sees the FULL log). The tier map rides the
    # require_role("auditor") gate's fetch (_checker attaches it
    # request-scoped); a missing map falls back to the self-filter —
    # conservative on leakage.
    is_admin = _is_admin(db, user_id)
    role_permissions = auth_user.get("_role_permissions") or {}
    full_visibility = is_admin or any(p == "auditor" for p in role_permissions.values())
    if not full_visibility:
        query = query.filter(AuditEvent.user_id == user_id)

    # Apply filters
    if user is not None:
        query = query.filter(AuditEvent.user_id == user)

    if start_date is not None:
        try:
            start = datetime.fromisoformat(start_date)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid start_date: {start_date!r}. Must be ISO 8601.",
            )
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        query = query.filter(AuditEvent.timestamp >= start)

    if end_date is not None:
        try:
            end = datetime.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid end_date: {end_date!r}. Must be ISO 8601.",
            )
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        query = query.filter(AuditEvent.timestamp <= end)

    if days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        query = query.filter(AuditEvent.timestamp >= cutoff)

    if hours is not None:
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        query = query.filter(AuditEvent.timestamp >= cutoff)

    if executor_id is not None:
        from sqlalchemy import JSON, cast

        query = query.filter(cast(AuditEvent.fields, JSON).op("->>")("executor_id") == executor_id)

    if event_type is not None:
        query = query.filter(AuditEvent.event_type == event_type)

    # Get total count
    total = query.count()

    # Apply pagination and ordering
    events = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()

    result = [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            user_id=e.user_id,
            fields=json.loads(e.fields) if e.fields else None,
            timestamp=e.timestamp.isoformat(),
        )
        for e in events
    ]

    return AuditListResponse(
        events=result,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/audit/ingest",
    status_code=status.HTTP_200_OK,
)
async def audit_ingest(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, int]:
    """Executor-mTLS audit-spool ingest (ticket audit-forwarder-server-sink #307).

    Receives the executor forwarder's zstd-compressed ndjson batch
    (Content-Encoding: zstd, Content-Type: application/x-ndjson — the exact
    shape ``executor/audit.py::_forward_once`` sends) and appends every line
    to the append-only ``audit_events`` ledger, where the auditor tier reads
    it through the existing GET filters (``event_type``, ``executor_id``).

    Auth: SessionMiddleware grants caller=executor ONLY on a verified client
    cert whose CN is a registered executor; the guard below is the
    route-side defense-in-depth mirror of the heartbeat pattern. Revoked-but-
    registered senders are NOT refused (D2 ruling): their rows land flagged
    ``sender_revoked: true`` — evidence preservation outranks silence.

    Value-free doctrine: lines carry no secret VALUES by the executor-side
    contract (env NAMES / secret ids only). Command TEXT is stored UNMASKED
    by the existing architecture step-5 convention (the operator rule "never
    inline a secret in command text" is what keeps that safe).

    Idempotency (Q5 ruling a): duplicates are TOLERATED and documented — the
    forwarder keeps lines on any failure (at-least-once); a retried batch
    duplicates rows. Dedupe needs a schema change and waits for observed
    volume.

    Malformed input rejects the WHOLE BATCH with 400 (D4: a malformed line
    is a producer bug; the forwarder keeps its lines and the server log names
    the failing line index). Unknown-but-valid event types LAND (String(64)
    no-CHECK forward compatibility is deliberate).
    """
    caller = getattr(request.state, "auth_user", {})
    if caller.get("caller") != "executor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor mTLS authentication required",
        )
    executor_id = caller.get("executor_id")
    if not executor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Executor identity missing from authenticated caller",
        )

    content_encoding = request.headers.get("content-encoding", "").strip().lower()
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_encoding != "zstd" or content_type != "application/x-ndjson":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expected Content-Type: application/x-ndjson and Content-Encoding: zstd",
        )

    body = await request.body()
    if not body:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty ingest body")

    from compression import zstd

    try:
        payload = zstd.decompress(body)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="zstd decompression failed")

    # Decompression-bomb brake: byte/line budgets enforced BEFORE any DB
    # write (the request-size middleware only bounds the compressed body).
    if len(payload) > INGEST_MAX_DECOMPRESSED_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Decompressed batch exceeds {INGEST_MAX_DECOMPRESSED_BYTES} bytes",
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Batch is not valid UTF-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Batch contains no event lines")
    if len(lines) > INGEST_MAX_LINES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Batch exceeds {INGEST_MAX_LINES}-line ingest cap",
        )

    # Whole-batch validation first (D4) — zero partial writes.
    parsed: list[tuple[str, datetime, dict[str, Any]]] = []
    for idx, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except ValueError:
            logger.error("Audit ingest from %s: line %d is not valid JSON — whole batch rejected", executor_id, idx)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"line {idx}: not valid JSON",
            )
        if not isinstance(obj, dict):
            logger.error("Audit ingest from %s: line %d is not a JSON object — whole batch rejected", executor_id, idx)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"line {idx}: not a JSON object",
            )
        event_type = obj.get("event_type")
        if not isinstance(event_type, str) or not event_type or len(event_type) > 64:
            logger.error(
                "Audit ingest from %s: line %d has invalid event_type — whole batch rejected", executor_id, idx
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"line {idx}: event_type must be a non-empty string of at most 64 characters",
            )
        try:
            json.dumps(obj)
        except (TypeError, ValueError):
            logger.error(
                "Audit ingest from %s: line %d is not JSON-serializable — whole batch rejected", executor_id, idx
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"line {idx}: fields must be JSON-serializable",
            )
        parsed.append((event_type, _spool_timestamp(obj.get("timestamp")), obj))

    # Flag and admission share one derivation by construction (audit-ingest-revoked-serial-flag-divergence):
    # read the middleware's stashed verdict; re-derive only if the key is
    # absent (defense against unseen caller shapes), and then WITH the serial.
    sender_revoked = caller.get("revoked")
    if sender_revoked is None:
        from ..revocation import executor_revocation_state

        sender_revoked = executor_revocation_state(
            db, executor_id, presented_serial=caller.get("presented_serial")
        ).revoked

    _write_forwarded_events(db, executor_id, sender_revoked, parsed)
    db.commit()
    return {"accepted": len(parsed)}


def _spool_timestamp(raw: Any) -> datetime:
    """Spool-line timestamp when ISO-parseable AND tz-aware, else now(UTC)
    (naive wall-clock datetimes are banned tree-wide; a garbage timestamp
    degrades to now, never to a naive value)."""
    if isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw)
        except ValueError:
            return datetime.now(UTC)
        if ts.tzinfo is not None:
            return ts
    return datetime.now(UTC)


def _write_forwarded_events(
    db: Session,
    executor_id: str,
    sender_revoked: bool,
    parsed: list[tuple[str, datetime, dict[str, Any]]],
) -> None:
    """Append the forwarded rows to the ledger (no commit — the route
    commits once: one batch, one transaction).

    Separate from server.audit_lifecycle BY DESIGN: that module is the
    single writer for ADMIN LIFECYCLE events (grep-pinned); this is the
    executor-forwarder writer. Provenance per D2/Q4: user_id carries the
    sending executor's cert CN (migration-022 'principal verbatim incl.
    mTLS CNs'), fields carry the spool payload verbatim plus executor_id
    (the GET executor_id filter's key), sender_revoked, and forwarded.
    """
    from core.iam.models import AuditEvent

    for event_type, ts, obj in parsed:
        db.add(
            AuditEvent(
                event_type=event_type,
                user_id=executor_id,
                fields={**obj, "executor_id": executor_id, "sender_revoked": sender_revoked, "forwarded": True},
                timestamp=ts,
            )
        )


def _is_admin(db: Session, user_id: str) -> bool:
    """True if the user holds a role granting admin visibility."""
    from core.iam.models import Role, RoleMember

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if admin_role is None:
        return False
    return (
        db.query(RoleMember).filter(RoleMember.user_id == user_id).filter(RoleMember.role_id == admin_role.id).first()
        is not None
    )
