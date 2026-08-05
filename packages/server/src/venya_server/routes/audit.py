"""Audit log endpoints."""

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

router = APIRouter()


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
    request: Request,
    user: str | None = Query(None, description="Filter by user ID"),
    key: str | None = Query(None, description="Filter by secret key"),
    start_date: str | None = Query(None, description="Start date (ISO 8601)"),
    end_date: str | None = Query(None, description="End date (ISO 8601)"),
    days: int | None = Query(None, description="Last N days"),
    hours: int | None = Query(None, description="Last N hours"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> AuditListResponse:
    """Query audit log.

    Requires admin or auditor permission.
    """
    from datetime import datetime, timedelta, timezone

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend not initialized",
        )

    from venya.iam.models import AuditEvent

    db = backend.get_session()
    try:
        query = db.query(AuditEvent)

        # Apply filters
        if user is not None:
            query = query.filter(AuditEvent.user_id == user)

        if start_date is not None:
            start = datetime.fromisoformat(start_date)
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            query = query.filter(AuditEvent.timestamp >= start)

        if end_date is not None:
            end = datetime.fromisoformat(end_date)
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            query = query.filter(AuditEvent.timestamp <= end)

        if days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            query = query.filter(AuditEvent.timestamp >= cutoff)

        if hours is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            query = query.filter(AuditEvent.timestamp >= cutoff)

        # Get total count
        total = query.count()

        # Apply pagination and ordering
        events = (
            query.order_by(AuditEvent.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

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
    finally:
        db.close()
