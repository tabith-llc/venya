"""Audit log endpoints."""

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..dependencies import get_db, require_admin

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
    user: str | None = Query(None, description="Filter by user ID"),
    key: str | None = Query(None, description="Filter by secret key"),
    start_date: str | None = Query(None, description="Start date (ISO 8601)"),
    end_date: str | None = Query(None, description="End date (ISO 8601)"),
    days: int | None = Query(None, description="Last N days"),
    hours: int | None = Query(None, description="Last N hours"),
    executor_id: str | None = Query(None, description="Filter by executor ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    _: dict = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AuditListResponse:
    """Query audit log.

    Requires admin or auditor permission.
    """
    from datetime import datetime, timedelta, timezone

    from core.iam.models import AuditEvent

    query = db.query(AuditEvent)

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
            start = start.replace(tzinfo=timezone.utc)
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
            end = end.replace(tzinfo=timezone.utc)
        query = query.filter(AuditEvent.timestamp <= end)

    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(AuditEvent.timestamp >= cutoff)

    if hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = query.filter(AuditEvent.timestamp >= cutoff)

    if executor_id is not None:
        from sqlalchemy import JSON, cast

        query = query.filter(
            cast(AuditEvent.fields, JSON).op("->>")("executor_id") == executor_id
        )

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
