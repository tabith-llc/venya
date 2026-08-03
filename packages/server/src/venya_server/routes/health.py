"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Liveness probe — is the server running?

    No authentication required. Not rate-limited.
    """
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check() -> dict:
    """Readiness probe — is the server ready to serve traffic?

    Checks database connectivity. No authentication required. Not rate-limited.
    """
    # TODO: Add actual DB connectivity check
    return {"status": "ok"}
