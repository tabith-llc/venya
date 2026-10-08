# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work will be available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#455 — the readiness surface must answer differently for "admin CA not
initialized yet" than for "admin CA probe is broken".

At dev ``d56f8e3`` the two states were byte-identical: ``_get_cached_check``
swallows every exception into ``"check_failed"``, so the handler's
``except RuntimeError: pass`` never fired and an uninitialized manager
returned the same 200/degraded/``admin_ca="check_failed"`` body as a broken
one. The fix inspects the manager's presence on state directly (mirroring
the main CA check's honest ``"skipped"`` vocabulary): uninitialized now
carries ``checks["admin_ca"] == "uninitialized"`` plus a WARNING log, while
a raising probe keeps the existing ``"check_failed"`` failure vocabulary.

Paired negatives per the truth-table rule: the healthy body is unchanged
(zero-mutation guard, exact dict comparison), the main-CA critical failure
still returns 503, and the debug endpoint's ``advisory`` field names the
``<inspect_failed>`` sentinel instead of leaving it inside a bare 200 body.
"""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from server.routes import debug as debug_routes
from server.routes import health as health_routes
from starlette.testclient import TestClient

HEALTH_LOGGER = "server.routes.health"


def _enabled_config() -> SimpleNamespace:
    return SimpleNamespace(admin_mtls=SimpleNamespace(enabled=True))


def _healthy_ca() -> MagicMock:
    ca = MagicMock()
    ca.load_ca.return_value = (MagicMock(), MagicMock())
    return ca


def _health_client(*, admin_ca_manager=None, config=None, ca_manager=None) -> TestClient:
    """Fresh app + client with the health routes; cache reset every time."""
    health_routes._reset_health_cache()
    app = FastAPI()
    app.state.ca_manager = ca_manager if ca_manager is not None else _healthy_ca()
    if admin_ca_manager is not None:
        app.state.admin_ca_manager = admin_ca_manager
    app.state.config = config if config is not None else _enabled_config()
    app.include_router(health_routes.router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


def _warning_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == HEALTH_LOGGER and r.levelno == logging.WARNING]


class TestAdminCAUninitializedState:
    def test_uninitialized_carries_state_and_warning(self, caplog):
        """admin_mtls enabled, NO admin_ca_manager on state → the body CARRIES
        the state instead of silencing it: 200, degraded, checks value
        "uninitialized", and a WARNING naming it."""
        with caplog.at_level(logging.WARNING, logger=HEALTH_LOGGER):
            resp = _health_client(admin_ca_manager=None).get("/api/v1/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["checks"]["admin_ca"] == "uninitialized"
        assert any("uninitialized" in m for m in _warning_lines(caplog)), caplog.text

    def test_broken_probe_keeps_check_failed(self):
        """Paired positive for the OTHER half: manager present but the probe
        raises → the existing failure vocabulary "check_failed" survives."""
        bad = MagicMock()
        bad._load_ca_key.side_effect = RuntimeError("admin key missing")
        resp = _health_client(admin_ca_manager=bad).get("/api/v1/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["checks"]["admin_ca"] == "check_failed"

    def test_the_two_states_read_differently(self):
        """The whole ticket in one cell: uninitialized and broken bodies are
        NOT equal, and their admin_ca values are two DISTINCT names — the
        form that catches "you made two names for one state"."""
        bad = MagicMock()
        bad._load_ca_key.side_effect = RuntimeError("admin key missing")

        resp_u = _health_client(admin_ca_manager=None).get("/api/v1/health")
        body_u = resp_u.json()
        resp_b = _health_client(admin_ca_manager=bad).get("/api/v1/health")
        body_b = resp_b.json()

        assert resp_u.status_code == resp_b.status_code == 200
        assert body_u["status"] == body_b["status"] == "degraded"
        assert (
            body_u["checks"]["admin_ca"] != body_b["checks"]["admin_ca"]
        ), "uninitialized and broken must not share one value"
        assert {body_u["checks"]["admin_ca"], body_b["checks"]["admin_ca"]} == {
            "uninitialized",
            "check_failed",
        }
        assert body_u != body_b

    def test_disabled_mtls_still_emits_no_admin_ca_key(self):
        """admin_mtls disabled is NOT uninitialized — it stays silent exactly
        as before (no key, ok status); the new state is only for enabled-but-
        unwired."""
        config = SimpleNamespace(admin_mtls=SimpleNamespace(enabled=False))
        resp = _health_client(config=config).get("/api/v1/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "admin_ca" not in data["checks"]


class TestHealthyBodyZeroMutation:
    def test_healthy_body_is_byte_for_byte_todays_answer(self, caplog):
        """Manager present and healthy → the exact pre-#455 body: same keys,
        same values, same status — and NO new warning."""
        admin = MagicMock()
        admin._load_ca_key.return_value = MagicMock()
        expected = {
            "status": "ok",
            "version": health_routes._SERVER_VERSION,
            "checks": {"ca": "ok", "admin_ca": "ok"},
        }
        with caplog.at_level(logging.WARNING, logger=HEALTH_LOGGER):
            resp = _health_client(admin_ca_manager=admin).get("/api/v1/health")

        assert resp.status_code == 200
        assert resp.json() == expected
        assert _warning_lines(caplog) == []

    def test_ca_critical_failure_still_503(self):
        """Paired negative: the real failure class was not demoted. Broken
        main CA still lands 503/error even with the new vocabulary present."""
        broken_ca = MagicMock()
        broken_ca.load_ca.side_effect = RuntimeError("CA key corrupted")
        resp = _health_client(ca_manager=broken_ca).get("/api/v1/health")

        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "error"
        assert data["checks"]["ca"] == "check_failed"


class TestDebugAdvisory:
    def _debug_client(self) -> TestClient:
        from server.dependencies import get_backend, require_admin

        health_routes._reset_health_cache()
        app = FastAPI()
        app.include_router(debug_routes.router, prefix="/api/v1/admin")

        class NoEngineBackend:
            pass

        app.dependency_overrides[get_backend] = lambda: NoEngineBackend()
        app.dependency_overrides[require_admin] = lambda: {"user_id": "admin", "caller": "admin"}
        return TestClient(app, raise_server_exceptions=False)

    def test_advisory_always_present_on_200_body(self):
        """The debug body carries an explicit advisory naming the inspection
        sentinels — an operator reads it before the task list."""
        resp = self._debug_client().get("/api/v1/admin/asyncio-state")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["advisory"], list) and data["advisory"]
        assert "<inspect_failed>" in data["advisory"][0]

    def test_sentinel_value_cannot_be_read_as_health_without_advisory(self, monkeypatch):
        """Force every task's coro_name to the sentinel: the advisory must
        then name the count and the affected handles, so a "<inspect_failed>"
        sitting inside the 200 body is explicitly flagged, not buried."""
        monkeypatch.setattr(debug_routes, "_get_coro_name", lambda task: "<inspect_failed>")
        resp = self._debug_client().get("/api/v1/admin/asyncio-state")
        assert resp.status_code == 200
        data = resp.json()

        sentinels = [t for t in data["tasks"] if t["coro_name"] == "<inspect_failed>"]
        assert sentinels, "monkeypatch should have produced sentinel tasks"
        named = [entry for entry in data["advisory"] if "unresolved coro names" in entry]
        assert len(named) == 1
        assert str(len(sentinels)) in named[0]
        for t in sentinels:
            assert t["handle"] in named[0]
