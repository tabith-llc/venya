# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#464 site 1 — the health cache ages on a monotonic clock, not the wall clock.

``routes/health.py::_get_cached_check`` used to compute the entry's age from
``time.time()``. A BACKWARD clock step (NTP correction, snapshot restore) made
that age NEGATIVE, and a negative age is always younger than the 15 s TTL, so a
cached ``ok`` kept answering the readiness probe for the whole skew interval even
after the CA key became unreadable — fail-open on the signal a load balancer
acts on. The guard now reads elapsed real time from ``time.monotonic()``; the
wall stamp is still recorded, but nothing decides anything with it.

Clock control: the module's own ``time`` name is replaced with a two-dial fake
(``monotonic()`` and ``time()`` move independently), so a step is a step and not
a sleep. The rest of the process — TestClient, starlette — keeps the real clock.

Paired negatives per the truth-table rule: normal monotonic aging still works,
and a FORWARD jump still does not make a live entry look stale.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import health as health_routes
from starlette.testclient import TestClient

TTL = health_routes._HEALTH_CACHE_TTL


class _FakeClock:
    """Stand-in for the ``time`` module inside ``routes.health`` only."""

    def __init__(self, mono: float = 1_000.0, wall: float = 10_000.0) -> None:
        self.mono = mono
        self.wall = wall

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall


def _app_with_ca(ca: MagicMock) -> TestClient:
    health_routes._reset_health_cache()
    app = FastAPI()
    app.state.ca_manager = ca
    app.state.config = SimpleNamespace(admin_mtls=None)
    app.include_router(health_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


class TestHealthCacheIgnoresWallSteps:
    def test_backward_step_does_not_keep_a_dead_ok_cached(self, monkeypatch):
        """AC2 backward half + the site-1 fail-open probe.

        An ``ok`` is cached; the wall clock then steps BACK past the TTL and the
        CA key becomes unreadable. Under the wall-clock guard the age went
        negative, so the cached ``ok`` was served and ``load_ca`` never re-ran.
        On the monotonic clock the entry is 20 s of real time old, so the probe
        re-runs the check and the balancer sees the failure.
        """
        clock = _FakeClock()
        monkeypatch.setattr(health_routes, "time", clock)
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        client = _app_with_ca(ca)

        assert client.get("/api/v1/health").json()["status"] == "ok"
        assert ca.load_ca.call_count == 1

        # Backward step, bigger than the TTL, and the key goes unreadable.
        clock.wall -= 500.0
        clock.mono += TTL + 5.0
        ca.load_ca.side_effect = RuntimeError("CA key unreadable")

        resp = client.get("/api/v1/health")
        assert resp.status_code == 503
        assert resp.json()["checks"]["ca"] == "check_failed"
        assert ca.load_ca.call_count == 2, "the check must re-run; the cached ok is not immortal"

    def test_forward_jump_does_not_reset_a_live_entry(self, monkeypatch):
        """AC2 forward half: a jump ahead of the wall clock must not discard a
        live cache entry (the old guard read that as 500 s of age and re-ran
        the check on every probe after the jump)."""
        clock = _FakeClock()
        monkeypatch.setattr(health_routes, "time", clock)
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        client = _app_with_ca(ca)

        assert client.get("/api/v1/health").json()["status"] == "ok"

        clock.wall += 500.0  # forward jump; only 1 s of real time has passed
        clock.mono += 1.0

        assert client.get("/api/v1/health").json()["status"] == "ok"
        assert ca.load_ca.call_count == 1, "1 s of real time is inside the TTL — the check must stay cached"

    def test_normal_monotonic_aging_still_expires_the_entry(self, monkeypatch):
        """Paired negative: real elapsed time past the TTL still re-runs the
        check, with the wall clock untouched — the fix must not make the cache
        immortal in the ordinary case."""
        clock = _FakeClock()
        monkeypatch.setattr(health_routes, "time", clock)
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        client = _app_with_ca(ca)

        client.get("/api/v1/health")
        clock.mono += TTL + 1.0  # wall clock does not move at all
        client.get("/api/v1/health")
        assert ca.load_ca.call_count == 2

    def test_wall_stamp_is_still_recorded(self, monkeypatch):
        """The wall field stays in the entry for log/diagnostic readers even
        though the guard no longer uses it (design note in the #464 report)."""
        clock = _FakeClock(wall=12_345.0)
        monkeypatch.setattr(health_routes, "time", clock)
        ca = MagicMock()
        ca.load_ca.return_value = (MagicMock(), MagicMock())
        _app_with_ca(ca).get("/api/v1/health")

        entry = health_routes._health_cache["ca"]
        assert entry["time"] == 12_345.0
        assert entry["mono"] == clock.mono
