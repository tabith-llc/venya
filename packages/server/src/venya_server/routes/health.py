"""Health check endpoints."""

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Liveness probe — is the server running?

    No authentication required. Not rate-limited.
    """
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check(request: Request) -> dict:
    """Readiness probe — is the server ready to serve traffic?

    Checks database connectivity. No authentication required. Not rate-limited.
    """
    from sqlalchemy import text

    backend = getattr(request.app.state, "backend", None)
    if backend is None:
        return {"status": "degraded", "checks": {"database": "not_configured"}}

    db = backend.get_session()
    try:
        db.execute(text("SELECT 1"))
        db.commit()
        return {"status": "ok", "checks": {"database": "connected"}}
    except Exception as e:
        db.rollback()
        return {"status": "degraded", "checks": {"database": f"error: {e}"}}
    finally:
        db.close()
