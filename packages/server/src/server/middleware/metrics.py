# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""ASGI middleware for request-level Prometheus metrics.

Records request duration and count per endpoint/method/status_code.
No PII — endpoint paths are normalized (no user_id, executor_id, etc.).
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .. import metrics


def _normalize_endpoint(path: str) -> str:
    """Normalize path for low-cardinality grouping.

    Replaces numeric/UUID segments with {id} placeholder.
    """
    parts = path.strip("/").split("/")
    normalized = []
    for part in parts:
        # Replace pure numeric segments (IDs, serials) with {id}
        if part.isdigit() or _looks_like_uuid(part):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)


def _looks_like_uuid(s: str) -> bool:
    """Quick heuristic for UUID-like strings."""
    if len(s) not in (32, 36):
        return False
    chars = set(s.replace("-", ""))
    return chars.issubset(set("0123456789abcdef"))


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request duration and count for every request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start

        endpoint = _normalize_endpoint(request.url.path)
        method = request.method
        status_code = str(response.status_code)

        metrics.REQUEST_DURATION.labels(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
        ).observe(elapsed)

        metrics.REQUESTS_TOTAL.labels(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
        ).inc()

        return response
