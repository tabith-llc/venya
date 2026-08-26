"""Static file serving for browser web UI.

Serves HTML pages, CSS, JS, and other static assets.
Includes SPA fallback for client-side routing.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from starlette.responses import FileResponse

logger = logging.getLogger("venya.server")

router = APIRouter()

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Regex to reject directory traversal attempts
_TRAVERSAL_PATTERN = re.compile(r"(\.\.|//|\\\\)")


def _sanitize_path(relative_path: str) -> Path:
    """Validate and resolve a static file path.

    Args:
        relative_path: The path segment from the URL.

    Returns:
        Resolved absolute path within STATIC_DIR.

    Raises:
        HTTPException: If path contains traversal attempts or is outside STATIC_DIR.
    """
    if _TRAVERSAL_PATTERN.search(relative_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file path",
        )

    resolved = (STATIC_DIR / relative_path).resolve()

    if not str(resolved).startswith(str(STATIC_DIR.resolve())):
        logger.warning("Directory traversal attempt: %s", relative_path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    if not resolved.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    return resolved


@router.get("/")
async def serve_index() -> FileResponse:
    """Serve the login page."""
    return FileResponse(STATIC_DIR / "index.html")


@router.get("/enroll")
async def serve_enroll() -> FileResponse:
    """Serve the user enrollment page."""
    return FileResponse(STATIC_DIR / "enroll.html")


@router.get("/enroll-admin")
async def serve_enroll_admin() -> FileResponse:
    """Serve the admin enrollment page."""
    return FileResponse(STATIC_DIR / "enroll-admin.html")


@router.get("/dashboard")
async def serve_dashboard() -> FileResponse:
    """Serve the dashboard page."""
    return FileResponse(STATIC_DIR / "dashboard.html")


@router.get("/static/{file_path:path}")
async def serve_static(file_path: str) -> FileResponse:
    """Serve static assets (CSS, JS, images, etc.).

    Args:
        file_path: Relative path to the static file.

    Raises:
        HTTPException: If path is invalid or not found.
    """
    path = _sanitize_path(file_path)
    return FileResponse(path)
