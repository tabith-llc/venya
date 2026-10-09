# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#449 require-role-blanket-executor-pass — the refusal contract, both halves.

``require_role._checker`` used to return the caller BEFORE any tier check whenever
``user_info.get("caller") == "executor"``. That was a blanket pass on every
``require_role(...)`` route in the tree — including all five ``read-write`` ones
(secret create/delete/patch, session create, execute). Its sibling ``require_admin``
did the opposite and denied executor callers outright, so the gate the routes trust
granted everything while the real control over executor reachability lived in the
middleware PATH MATCHER, outside the gate.

Ruled shape (#449 AC1-AC4 + the s79 re-pin ruling):

* AC1 — the gate REFUSES executor-class callers on every TIERED gate (403 + a stated
  reason, no role lookup attempted). ``"none"`` keeps behaving as before.
* AC2 — no identity without a ``user_id`` reaches ``user_info["user_id"]`` and gets a
  traceback-driven 500; the gate refuses cleanly instead.
* AC3 — BOTH halves: executor refused (negative) AND the legitimate executor routes
  unchanged (positive, real routes, not the checker in isolation).
* AC4 — one static pair cell pins the single-source comment: the MATCHER decides
  executor reachability; this gate's job is to refuse.

Fixtures mirror the middleware's real shapes: the executor grant at
``middleware/auth.py:834`` writes ``caller/executor_id/presented_serial/revoked`` and
NO ``user_id`` — a cell that hands the gate a ``user_id``-bearing executor dict is
testing an invention, which is how the old blanket pass stayed invisible for so long.
"""

import re
from pathlib import Path
from typing import Annotated
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Depends, FastAPI
from server.dependencies import get_current_user, require_role
from starlette.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPS = REPO_ROOT / "packages" / "server" / "src" / "server" / "dependencies.py"
AUTH_MW = REPO_ROOT / "packages" / "server" / "src" / "server" / "middleware" / "auth.py"

# The refusal text, asserted rather than inferred: three distinct 403s live on these
# routes (the gate's executor refusal, "Read-write permission required", the tier
# denies) and a status-only cell cannot tell them apart.
EXECUTOR_GATE_REFUSAL = "Executor callers are not permitted on role-gated routes"
NO_USER_ID_REFUSAL = "Caller identity carries no user to authorize"

TIERS = ("read", "auditor", "read-write")

# What middleware/auth.py:834 actually attaches for a cert-verified executor.
EXECUTOR_GRANT = {
    "caller": "executor",
    "executor_id": "venya-exec-1",
    "presented_serial": "aa11bb22",
    "revoked": False,
}


def _gate_app(permission, user_info, rm_permissions=None, rm=None):
    """One route behind one real require_role gate, with a fixed caller."""
    app = FastAPI()
    app.state.backend = MagicMock()

    @app.get("/guarded")
    # Annotated form, not a Depends() default arg: the latter trips ruff B008, and
    # the fix there is to use the documented Annotated style rather than widen the
    # per-file-ignores list (that list is scoped on purpose).
    async def guarded(user: Annotated[dict, Depends(require_role(permission))]):
        # Body marker: if this key reaches the client, the gate PASSED.
        return {"body_ran": True, "map": user.get("_role_permissions")}

    app.dependency_overrides[get_current_user] = lambda: dict(user_info)
    if rm is None:
        rm = MagicMock()
        rm.get_user_permissions.side_effect = lambda uid: (rm_permissions or {})
    return TestClient(app, raise_server_exceptions=False), rm


# --- AC3 negative half: every tiered gate refuses the executor class ---


@pytest.mark.parametrize("permission", TIERS)
def test_executor_refused_on_every_tiered_gate(permission):
    """The blanket pass is gone: read, auditor and read-write all refuse, and the
    route body never runs (``body_ran`` absent). RED at the parent commit, where all
    three answered 200 with body_ran."""
    client, rm = _gate_app(permission, EXECUTOR_GRANT)
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == EXECUTOR_GATE_REFUSAL
    assert "body_ran" not in resp.json(), "route body ran for an executor caller"
    rm.get_user_permissions.assert_not_called()


def test_executor_refusal_is_403_not_a_500_traceback():
    """The old pass existed because an executor carries no user_id, so the tiered
    path would have indexed ``user_info["user_id"]`` and raised KeyError — FastAPI
    surfaces that as a 500. An authorization decision must never arrive as a server
    fault: status is 403 and no exception leaked."""
    client, rm = _gate_app("read-write", EXECUTOR_GRANT)
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code != 500
    assert resp.status_code == 403
    assert "KeyError" not in resp.text


def test_identity_without_user_id_gets_clean_refusal():
    """AC2's paired negative: a NON-executor identity carrying no user_id used to
    reach the dict index and 500. It now gets the gate's stated 403, and the role
    table is never queried with a None key."""
    rm = MagicMock()
    rm.get_user_permissions.side_effect = AssertionError("no lookup may run without a user_id")
    client, _ = _gate_app("read", {"caller": "human", "session_id": "s1"}, rm=rm)
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == NO_USER_ID_REFUSAL
    assert "body_ran" not in resp.json()


# --- AC1's stated exception: "none" is unchanged ---


def test_none_tier_still_passes_any_authenticated_caller():
    """AC1 keeps ``"none"`` behaving as today (any authenticated caller passes, no
    role check). The refusal applies to the TIERED gates only. No route uses "none"
    at this tip — the cell pins the factory contract so the refusal cannot quietly
    widen into it later."""
    client, rm = _gate_app("none", EXECUTOR_GRANT)
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code == 200, resp.text
    assert resp.json()["body_ran"] is True
    rm.get_user_permissions.assert_not_called()


# --- AC3 positive halves: humans behave EXACTLY as before ---


@pytest.mark.parametrize(
    "permission,table,expected",
    [
        ("read", {1: "read"}, 200),
        ("auditor", {1: "auditor"}, 200),
        ("read-write", {1: "read-write"}, 200),
        # Refused exactly as before — same status, same body shape.
        ("read-write", {1: "read"}, 403),
        ("auditor", {1: "read"}, 403),
        ("read", {}, 403),
    ],
)
def test_human_caller_verdicts_unchanged(permission, table, expected):
    """Humans are untouched by #449: the tier verdicts that existed at the parent
    commit still hold, pass and deny alike."""
    client, rm = _gate_app(permission, {"user_id": "u1", "caller": "human"}, rm_permissions=table)
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code == expected, resp.text
    if expected == 200:
        assert resp.json()["body_ran"] is True
    else:
        assert resp.json()["detail"] in (
            "Insufficient permissions",
            "Auditor permission required",
            "Read-write permission required",
        )
        assert "body_ran" not in resp.json()


def test_human_with_tier_still_gets_role_map_attached():
    """The #448-era request-scoped ``_role_permissions`` attach (ruling 1b/1c) is
    unchanged — the refusal sits ahead of it and cannot disturb it."""
    client, rm = _gate_app("read", {"user_id": "u1", "caller": "human"}, rm_permissions={1: "auditor"})
    with patch("server.dependencies.RoleManager", return_value=rm):
        resp = client.get("/guarded")

    assert resp.status_code == 200, resp.text
    assert resp.json()["map"] == {"1": "auditor"}


# --- AC3 positive half on REAL routes: the executor-reachable paths are unchanged ---


def _net():
    """Reuse the tree-wide authorization net's own traversal + guard collector.

    This FastAPI build includes routers LAZILY: a hand-rolled ``app.routes`` walk finds
    ZERO APIRoutes, so an overlap check built on it passes vacuously (measured the hard
    way on the first run of this cell). The net already solves both problems, and its
    file carries a ``seen > 0`` anti-vacuity guard for exactly this reason.
    """
    try:
        from .test_route_authorization import _endpoints, _guards
    except ImportError:  # direct-file invocation (pytest tests/foo.py)
        from test_route_authorization import _endpoints, _guards

    from server.app import create_app
    from server.config import ServerConfig

    app = create_app(ServerConfig(recovery_code_pepper="test-pepper-unused")).app
    return app, _endpoints, _guards


def _route_guards():
    """[(path, [guard markers])] for every endpoint on the assembled app."""
    app, endpoints, guards = _net()
    return [
        (p, guards(guards_deps))
        for p, dependant, guards_deps in endpoints(app)
        for guards_deps in [list(dependant.dependencies)]
    ]


def test_no_require_role_route_is_executor_reachable():
    """The premise that makes the refusal safe, pinned as a cell: the middleware
    grants caller=executor on the session-pair regex, /api/v1/heartbeat and
    /api/v1/audit/ingest, and NONE of the tiered-gate routes has one of those paths.
    If a future route is BOTH executor-reachable AND role-gated, this cell goes red
    before a live path does.

    Not allowed to pass vacuously: the walk must find the five read-write gates the
    ticket names, or "no overlap" would just mean "nothing was looked at".
    """

    def executor_reachable(path):
        if re.match(r"^/api/v1/sessions/[^/]+/(secrets/revoke|filter)$", path):
            return True
        return path in {"/api/v1/heartbeat", "/api/v1/audit/ingest"}

    walked = _route_guards()
    assert walked, "assembled-app walk yielded no endpoints — traversal is broken"
    tiered = [p for p, gs in walked if any(g in TIERS for g in gs)]
    read_write = [p for p, gs in walked if "read-write" in gs]
    assert len(tiered) >= 13, f"only {len(tiered)} role-gated routes found — traversal drift"
    assert len(read_write) == 5, f"expected the ticket's five read-write gates, found {read_write}"

    offenders = [p for p, gs in walked if any(g in TIERS for g in gs) and executor_reachable(p)]
    assert offenders == [], f"executor-reachable AND role-gated: {offenders}"


@pytest.mark.parametrize(
    "path_regex",
    [
        r"^/api/v1/heartbeat$",
        r"^/api/v1/audit/ingest$",
        r"^/api/v1/sessions/\{session_id\}/secrets/revoke$",
        r"^/api/v1/sessions/\{session_id\}/filter$",
    ],
)
def test_executor_reachable_routes_do_not_carry_the_gate(path_regex):
    """The legitimate executor paths carry NO tiered gate on the assembled app, so
    #449's refusal cannot intercept them. Those routes re-check identity in-body (the
    #440 binding shape); body verdicts belong to the existing #440/#307 cells.

    Asserted on the guard list, not an HTTP status: a bare request into a half-wired
    app fails for wiring reasons (mock core, empty body), which would make the cell
    measure its fixture instead of the control.

    Matched against FastAPI's path TEMPLATE ({session_id}) — the app stores templates,
    and comparing against a filled example matched zero routes.
    """
    matched = [(p, gs) for p, gs in _route_guards() if re.match(path_regex, p.rstrip("/") or p)]
    assert matched, f"no route matched {path_regex} — traversal or template drift"
    for p, gs in matched:
        assert not any(g in TIERS for g in gs), f"{p} is role-gated ({gs}) — reachability would be narrowed"


# --- AC4: the single-source rule is recorded, not implied ---


def _strip_comment_markers(src: str) -> str:
    """Join a python comment block into flowing text so a pin can assert a PHRASE
    rather than a line-bounded fragment (the wording is what must survive, not the
    column at which it wraps)."""
    return re.sub(r"\s+", " ", re.sub(r"#[ \t]*", " ", src)).strip()


def test_ac4_single_source_comment_shipped():
    """Grep-form pin (the repo's static-fact style): the checker comment NAMES the
    matcher as the single source of executor reachability and says adding an
    executor-reachable path is not this gate's job. Mechanism: the text is read out
    of dependencies.py, comment markers are joined (see _strip_comment_markers), and
    the phrases are asserted inside the refusal's own block — which is pinned by
    asserting them AFTER the executor check's position in the file."""
    src = DEPS.read_text()
    assert "SINGLE SOURCE (AC4)" in src
    start = src.index("SINGLE SOURCE (AC4)")
    # Bounded STRUCTURALLY: from the note to the refusal statement it documents, so
    # the pin cannot drift if the comment grows and a fixed window starts truncating.
    end = src.index('if user_info.get("caller")', start)
    block = _strip_comment_markers(src[start:end])
    assert "middleware PATH MATCHER" in block
    assert "middleware/auth.py" in block
    assert "_is_executor_session_path" in block
    assert "is NOT this gate's job" in block, block
    assert "never by re-widening this refusal" in block
    # And the factory docstring no longer claims the pass.
    assert "Executors\n            (mTLS) always pass." not in src
    assert "REFUSED on every tiered gate" in src


def test_matcher_regex_still_the_only_granter():
    """Cross-check the other half of the control: the matcher file still names the
    session-pair regex and the two literal grants, and the executor dict it writes
    carries no user_id — which is what made the old hybrid test double an invention."""
    mw = AUTH_MW.read_text()
    assert r"^/api/v1/sessions/[^/]+/(secrets/revoke|filter)$" in mw
    assert '"/api/v1/heartbeat"' in mw
    assert '"/api/v1/audit/ingest"' in mw
    grant = mw[mw.index('request.state.auth_user = {\n                "caller": "executor",') :]
    grant_block = grant[:600]
    assert "user_id" not in grant_block, "the executor grant gained a user_id — premise changed"
