"""Audit log endpoints."""

from typing import Any

from fastapi import APIRouter, Query, Request, status
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
    # TODO: Query audit_events from DB with filters
    return AuditListResponse(events=[], total=0, limit=limit, offset=offset)
