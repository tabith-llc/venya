# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#459: the operator clock-skew knob reaches the session expiry gates.

The server built the core ``SessionConfig`` at nine sites and every one of them
passed the three timeouts while omitting ``clock_skew_tolerance_seconds``, so
the dataclass default (60 s) won and
``server_config.clock_skew.token_tolerance_seconds`` never reached the gate.
Tightening the knob to 15 s changed nothing; the session tier also disagreed
with the dependency tier, which already read the knob.

Cells (the ticket's acceptance matrix):

* builder: a configured knob of 15 lands on the built config,
* builder paired negative: with no ``clock_skew`` section the core default (60)
  still wins — an honest install keeps today's behaviour,
* bearer plane: the middleware gate honours 15, not 60 (RED at the parent tip),
* browser plane: the cookie validator honours 15 (RED at the parent tip),
* agreement: one knob, both planes — the same row gets the same verdict on the
  bearer and cookie paths (the actual bug class: two tiers, one knob),
* every construction site in the shipped source carries the value (AST sweep;
  RED at the parent tip, which had nine offenders).

Harness idiom borrowed from ``test_access_token_expiry_gate.py`` /
``test_browser_cookie_session_plane.py``: mock backend, the SESSION manager kept
REAL (patching it would test the patch, not the gate), ``RoleManager`` patched.
"""

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.iam.session_manager import SessionConfig as CoreSessionConfig
from fastapi import FastAPI, Request
from server.middleware.auth import SessionMiddleware
from server.routes import auth_browser
from server.session_gate_config import DEFAULT_TOKEN_TOLERANCE_SECONDS, build_core_session_config
from starlette.testclient import TestClient

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "server"

# Idle-dead by 30 s: inside the 60 s default (accepted today) and outside a
# 15 s tolerance (rejected once the knob reaches the gate).
AGED_SECONDS = 30


def _server_config(*, tolerance=None, session_timeout=900):
    """App-state config shaped like ``ServerConfig`` (or a bare namespace in tests).

    ``tolerance=None`` deliberately omits the whole ``clock_skew`` section — the
    honest-install shape the paired negatives exercise.
    """
    sections = {
        "session": SimpleNamespace(
            session_timeout=session_timeout,
            access_token_ttl=300,
            max_session_duration=14400,
        ),
        "admin_mtls": SimpleNamespace(enabled=False),
    }
    if tolerance is not None:
        sections["clock_skew"] = SimpleNamespace(token_tolerance_seconds=tolerance)
    return SimpleNamespace(**sections)


def _aged_row(*, aged_seconds=AGED_SECONDS):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=1,
        user_id="user1",
        created_at=now - timedelta(minutes=5),
        expires_at=now - timedelta(seconds=aged_seconds),
        user=SimpleNamespace(user_id="user1", status="active"),
        access_token_jti="jti-1",
        # Fresh on purpose: the bearer-tier #342 gate must NOT be what rejects,
        # so a rejection here proves the session-idle gate (the tolerance) ran.
        access_token_expires_at=now + timedelta(minutes=5),
    )


def _backend_for(row):
    db = MagicMock()

    def query_side_effect(_model):
        q = MagicMock()
        q.filter.return_value.first.return_value = row
        return q

    db.query.side_effect = query_side_effect
    backend = MagicMock()
    backend.get_session.return_value = db
    return backend


# --- builder cells ---------------------------------------------------------


def test_builder_passes_configured_tolerance():
    config = _server_config(tolerance=15)
    built = build_core_session_config(config)
    assert built.clock_skew_tolerance_seconds == 15
    # The timeouts ride along unchanged — the knob did not displace them.
    assert built.session_timeout == timedelta(seconds=900)
    assert built.access_token_ttl == timedelta(seconds=300)
    assert built.max_session_duration == timedelta(seconds=14400)


def test_builder_keeps_core_default_when_knob_unset():
    # Paired negative / honest-install guard: no clock_skew section at all.
    built = build_core_session_config(_server_config(tolerance=None))
    assert built.clock_skew_tolerance_seconds == 60


def test_builder_default_is_read_from_the_dataclass():
    """The fallback is the dataclass value, not a restated literal (AC-1 shape)."""
    assert DEFAULT_TOKEN_TOLERANCE_SECONDS == CoreSessionConfig().clock_skew_tolerance_seconds


# --- bearer plane ----------------------------------------------------------


def _bearer_client(config, row):
    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = config
    app.state.backend = _backend_for(row)

    @app.get("/api/v1/protected")
    def protected():
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    client.headers.update({"Authorization": "Bearer tok-abc"})
    return client


def _bearer_verdict(config, row):
    with patch("core.iam.role_manager.RoleManager") as mock_rm:
        mock_rm.return_value.get_user_roles.return_value = []
        return _bearer_client(config, row).get("/api/v1/protected").status_code


def test_bearer_gate_honours_configured_tolerance():
    """RED at the parent tip: the site omitted the field, so 60 s swallowed it."""
    assert _bearer_verdict(_server_config(tolerance=15), _aged_row()) == 401


def test_bearer_gate_default_unchanged_when_knob_unset():
    # Paired negative: an install that never set the knob keeps today's verdict.
    assert _bearer_verdict(_server_config(tolerance=None), _aged_row()) == 200


# --- browser (cookie) plane ------------------------------------------------


def _browser_verdict(config, row):
    """Call the real cookie validator through a live Request object.

    Returns True when the validator accepted the cookie, False when it refused.
    The probe route's own status is asserted by the caller so a 500 in the
    helper can never read as a refusal.
    """
    app = FastAPI()
    app.state.config = config
    app.state.backend = _backend_for(row)
    seen = {}

    @app.get("/probe")
    def probe(request: Request):
        seen["result"] = auth_browser._get_session_from_cookie(request)
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set(auth_browser.COOKIE_NAME, "tok-abc")
    with patch("core.iam.role_manager.RoleManager") as mock_rm:
        mock_rm.return_value.get_user_roles.return_value = []
        resp = client.get("/probe")
    assert resp.status_code == 200, f"probe route failed: {resp.status_code} {resp.text}"
    assert "result" in seen, "probe route never ran"
    return seen["result"] is not None


def test_browser_validator_honours_configured_tolerance():
    """RED at the parent tip: the five ``auth_browser.py`` sites also omitted it."""
    assert _browser_verdict(_server_config(tolerance=15), _aged_row()) is False


def test_browser_validator_default_unchanged_when_knob_unset():
    # Paired negative on the cookie plane.
    assert _browser_verdict(_server_config(tolerance=None), _aged_row()) is True


# --- AC-5: one knob, both planes agree -------------------------------------


def test_both_planes_agree_on_one_tolerance():
    """The ticket-proving cell: the same row + the same config get the SAME verdict.

    At the 15 s knob both planes refuse the 30 s-idle-dead row; at the untouched
    60 s default both accept it. Before #459 the two planes could not be driven
    at all — the knob reached neither.
    """
    tight = _server_config(tolerance=15)
    assert _bearer_verdict(tight, _aged_row()) == 401
    assert _browser_verdict(tight, _aged_row()) is False

    default = _server_config(tolerance=None)
    assert _bearer_verdict(default, _aged_row()) == 200
    assert _browser_verdict(default, _aged_row()) is True


# --- every site carries it (AC-1 interlock) --------------------------------

_TIMEOUT_KWARGS = {"session_timeout", "access_token_ttl", "max_session_duration"}
_TOLERANCE_KWARG = "clock_skew_tolerance_seconds"


def _omitting_sites():
    """Shipped-source constructions of the CORE SessionConfig that pass a
    timeout but omit the clock-skew tolerance.

    A zero-argument construction is skipped on purpose: it reads a dataclass
    default (``dependencies.py`` ``SessionConfig().max_session_duration`` and
    this builder's own default read), it does not configure a gate.
    """
    offenders = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        bound = {
            (alias.asname or alias.name)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "core.iam.session_manager"
            for alias in node.names
            if alias.name == "SessionConfig"
        }
        if not bound:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in bound:
                continue
            passed = {kw.arg for kw in node.keywords if kw.arg}
            if not passed:
                continue
            if passed & _TIMEOUT_KWARGS and _TOLERANCE_KWARG not in passed:
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")
    return offenders


def test_no_construction_site_omits_the_tolerance():
    """RED at the parent tip with nine offenders; zero once every site calls the builder."""
    offenders = _omitting_sites()
    assert offenders == [], "session-config sites omit clock_skew_tolerance_seconds: " + ", ".join(offenders)


def test_the_builder_is_the_only_config_assembler():
    """Positive half of the interlock: the nine sites exist and they call the builder.

    Guards against an implementation that deletes call sites instead of fixing
    them. The count is the shipped session-gate surface (#459: nine sites in
    four files — the ticket body's five was a grep under-count).
    """
    total = 0
    for path in sorted(SRC_ROOT.rglob("*.py")):
        if path.name == "session_gate_config.py":
            continue  # the builder itself (definition + docstring)
        total += path.read_text(encoding="utf-8").count("build_core_session_config(")
    assert total == 9, f"expected nine builder call sites, counted {total}"
