# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#733 — one run, ONE command text across the three surfaces that store it.

Cross-package integration cell (root §9: those live in this test dir) because the
defect is drift BETWEEN packages. The executor stored its ``command_executed`` text
from ``render_command`` (the ruled RAW pair, #332); the server re-derived its own
display text with ``shlex.join``, which QUOTES that pair. One run therefore wrote two
different commands, and ``execution_sessions.command`` — the text the MCP
``get_audit`` line prints — carried the inert one, the very shape the merged #332
ruling put out of business.

The ruling is FOLLOWED, not re-decided: iid 332
(`redirect-allowance-neutralized-by-quoting`, closed ``status/merged``) ruled that
the accepted session-bound ``<`` pair renders RAW, because quoting it hands the guest
shell a literal ``<`` argument instead of a redirect. The alignment is structural:
the ONE renderer and the ONE path template now live in the frozen wire contract
(``venya_contract.relay``), which BOTH ends already import — the same single-source
shape #332 chose for the pair condition and #374 for the template.

Truth table: the ruled pair reads identically on all three surfaces (positive); a
plain argv with no pair reads identically too (the zero-drift half of #332); an
UNBOUND ``<`` target never reaches any surface because the gate refuses it first
(paired negative); and a REFUSED argv stores the same rendered text an accepted one
does, on both refusal lanes of ``execute`` — the site leg 759's review found still
joining the list, and the reason the rejection rows are in this file's scope.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

# --- the ONE argv under test: key auth + remote sudo -S + the ruled pair ----------
BOUND_SECRET_ID = 12
BOUND_PATH = f"/run/secrets/venya/{BOUND_SECRET_ID}"
ARGV = [
    "/usr/bin/ssh",
    "bot@web-server-3",
    "/usr/bin/sudo",
    "-S",
    "/usr/bin/apt",
    "install",
    "-y",
    "apache2",
    "<",
    BOUND_PATH,
]
# Ruled rendering (#332): every element `shlex.quote`'d EXCEPT the accepted pair.
# None of these tokens needs quoting, so the ruled text is the argv joined with the
# `<` and its bound path RAW — and it is NOT what `shlex.join` produces, which wraps
# the `<` in quotes.
RULED = " ".join(ARGV)
TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}


@pytest.fixture(autouse=True)
def _default_role_permissions():
    """Every user holds a read-write role — the same seam the relay tests use, so
    this cell exercises the route and not the authorization layer."""

    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    with patch("server.dependencies.RoleManager", return_value=rm):
        yield rm


# ----------------------------------------------------------------------------------
# Surface 1 — the executor's own `command_executed` audit row
# ----------------------------------------------------------------------------------


def _executor_surface(argv=ARGV, secret_ids=(BOUND_SECRET_ID,)) -> str:
    from executor.command_validator import CommandValidator
    from executor.executor import Executor
    from executor.strategies.sbx_strategy import SbxStrategy

    strategy = MagicMock(spec=SbxStrategy)
    strategy.name.return_value = "sbx"
    strategy.execute_command.return_value = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
    audit = MagicMock()
    ex = Executor(
        command_validator=CommandValidator(),
        session_id="s-733",
        injection_strategy=strategy,
        audit_logger=audit,
    )
    ex.http_client = None
    secrets = [{"secret_id": sid, "value": b"x", "wrapped_value": b""} for sid in secret_ids]
    with (
        patch.object(Executor, "_prepare_injections", return_value=[]),
        patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])),
    ):
        ex.execute(argv, secrets)
    rows = [c for c in audit.emit.call_args_list if c[0][0] == "command_executed"]
    assert len(rows) == 1, [c[0][0] for c in audit.emit.call_args_list]
    return rows[0][1]["command"]


# ----------------------------------------------------------------------------------
# Surface 1b — the REJECTION lane: the `command_rejected` row the executor writes when
# the structural gate refuses an argv. Leg 759's review found this site still joining the
# list while the success lane and the server both carried the rendered text.
# ----------------------------------------------------------------------------------

#: An argv carrying the ruled session-bound pair plus one metachar element, so the
#: structural gate refuses it — the shape the reviewer's probe drives.
REJECT_ARGV = ["cat", "<", BOUND_PATH, "a;b"]


def _reject_row_command(argv=REJECT_ARGV, secret_ids=(BOUND_SECRET_ID,), *, bypass_structure=False) -> str:
    """The stored `command` of the single `command_rejected` row one refused run writes.

    `bypass_structure=True` lets the structural gate pass and the POLICY gate refuse
    instead, so the two refusal lanes in `execute` can be compared on one argv.
    """
    from executor.command_validator import CommandValidator
    from executor.executor import CommandRejected, Executor
    from executor.strategies.sbx_strategy import SbxStrategy

    strategy = MagicMock(spec=SbxStrategy)
    strategy.name.return_value = "sbx"
    audit = MagicMock()
    ex = Executor(
        command_validator=CommandValidator(),
        session_id="s-733-reject",
        injection_strategy=strategy,
        audit_logger=audit,
    )
    ex.http_client = None
    secrets = [{"secret_id": sid, "value": b"x", "wrapped_value": b""} for sid in secret_ids]
    with (
        patch.object(Executor, "_prepare_injections", return_value=[]),
        patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])),
        patch.object(
            CommandValidator,
            "validate",
            return_value=(False, "dangerous pattern rejected by preset 'standard'"),
        ),
        patch(
            "executor.executor._validate_command_structure",
            side_effect=(None if bypass_structure else ValueError("shell metacharacter in an argument")),
        ),
    ):
        with pytest.raises(CommandRejected):
            ex.execute(argv, secrets)
    rows = [c[1]["command"] for c in audit.emit.call_args_list if c[0][0] == "command_rejected"]
    assert len(rows) == 1, [c[0][0] for c in audit.emit.call_args_list]
    return rows[0]


# ----------------------------------------------------------------------------------
# Surface 2 — the server: `command_executed` fields["command"] AND the
# `execution_sessions.command` column (the two writes the route makes from ONE
# `display_command`), captured from a real POST through the shipped route.
# ----------------------------------------------------------------------------------


def _relay_response() -> httpx2.Response:
    request = httpx2.Request("POST", "https://192.0.2.14:8443/execute")
    return httpx2.Response(
        200,
        json={"exit_code": 0, "stdout": "ok", "stderr": "", "masked_count": 0},
        request=request,
    )


def _server_surfaces(argv=ARGV, bound_id=BOUND_SECRET_ID) -> tuple[str, str]:
    """Drive POST /executors/{id}/execute once with `bound_id` injected (None = no
    secret bound, the plain-argv case). Returns the two server-side stored texts."""
    """Return (audit-row command, execution_sessions.command) for one relay run."""
    from server.dependencies import get_current_user
    from server.routes import executors as executors_routes

    backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app = FastAPI()
    app.state.backend = backend
    mock_config = MagicMock()
    mock_config.ca_dir = "/var/lib/venya/ca"
    mock_config.mtls_cert = None
    mock_config.mtls_key = None
    app.state.config = mock_config
    app.state.core = MagicMock()
    if bound_id is None:
        app.state.core.get_for_injection.return_value = None
    else:
        app.state.core.get_for_injection.return_value = (bound_id, "s3cret-value", {})
    app.state.core.decrypt_secret.return_value = "s3cret-value"
    app.include_router(executors_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    mock_db = MagicMock()
    backend.get_session.return_value = mock_db

    exec_session = MagicMock()
    exec_session.id = "sess-1"
    exec_session.user_id = "test-user"
    exec_session.expires_at = datetime.now(UTC) + timedelta(minutes=5)
    exec_session.executor_id = "exec-1"
    session_q = MagicMock()
    session_q.filter.return_value.first.return_value = exec_session

    executor_row = MagicMock()
    executor_row.id = "exec-1"
    executor_row.hostname = "192.0.2.14"
    executor_row.revoked_at = None
    executor_row.serial_number = None
    executor_row.version = "0.1.0a14"
    executor_row.not_after = datetime.now(UTC) + timedelta(days=30)
    executor_q = MagicMock()
    # the dial gate reads a LIVE current cert; the revocation queries read nothing revoked
    executor_q.filter.return_value.first.return_value = executor_row

    bound_rows = (
        []
        if bound_id is None
        else [
            _session_secret_row(bound_id),
        ]
    )
    secrets_q = MagicMock()
    secrets_q.all.return_value = bound_rows
    secrets_q.filter.return_value.all.return_value = bound_rows

    # no shape metadata on the bound secret -> plain file injection, and the ruled
    # `<` pair is the consumption the argv is asking for
    meta_rows = [] if bound_id is None else [_meta_row(bound_id)]
    meta_q = MagicMock()
    meta_q.filter.return_value.all.return_value = meta_rows

    def query_side_effect(model):
        name = getattr(model, "__name__", "")
        if name == "ExecutionSession":
            return session_q
        if name == "SessionSecret":
            return secrets_q
        if name == "Secret":
            return meta_q
        if name in ("Executor", "ExecutorCert"):
            q = MagicMock()
            q.filter.return_value.first.return_value = _current_cert() if name == "ExecutorCert" else executor_row
            q.filter.return_value.all.return_value = []
            return q
        none_q = MagicMock()
        none_q.filter.return_value.first.return_value = None
        none_q.filter.return_value.all.return_value = []
        none_q.all.return_value = []
        return none_q

    mock_db.query.side_effect = query_side_effect

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=_relay_response())
    with (
        patch("server.routes.executors.httpx2.AsyncClient", return_value=mock_client),
        patch("server.routes.executors.ssl.SSLContext", return_value=MagicMock()),
        patch("server.routes.executors._ensure_dial_crl_store", return_value=None),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/executors/exec-1/execute", json={"session_id": "sess-1", "command": argv})
    assert resp.status_code == 200, resp.text

    audit_cmd = None
    for call in mock_db.add.call_args_list:
        event = call[0][0] if call[0] else None
        if getattr(event, "event_type", None) == "command_executed":
            fields = event.fields
            fields = json.loads(fields) if isinstance(fields, str) else fields
            audit_cmd = fields["command"]
            break
    assert audit_cmd is not None, "the success path wrote no command_executed row"

    # execution_sessions.command: the bulk UPDATE bind the route issues next
    session_cmd = None
    for call in mock_db.execute.call_args_list:
        if len(call[0]) < 2:
            continue  # the claim UPDATE takes one arg; this one is text()+params
        params = call[0][1]
        if isinstance(params, dict) and "command" in params and "sid" in params:
            session_cmd = params["command"]
    assert session_cmd is not None, "the route never wrote execution_sessions.command"
    return audit_cmd, session_cmd


def _session_secret_row(secret_id: int):
    row = MagicMock()
    row.secret_id = secret_id
    row.wrapped_value = "[VENYA:00000000]eA==[/VENYA]"
    return row


def _meta_row(secret_id: int):
    row = MagicMock()
    row.id = secret_id
    row.meta = {}
    return row


def _current_cert():
    return SimpleNamespace(
        serial_number="0000000000001000",
        not_after=datetime.now(UTC) + timedelta(days=30),
    )


# ----------------------------------------------------------------------------------
# Surface 3 — the MCP-visible command text, i.e. what an agent reads
# ----------------------------------------------------------------------------------


async def _mcp_surface(stored_command: str) -> str:
    from venya_mcp.server import call_tool

    mock = MagicMock()
    mock.get_audit = AsyncMock(
        return_value=[
            {
                "timestamp": "2026-01-01T12:00:00Z",
                "event_type": "command_executed",
                "user_id": "alice",
                "fields": {"executor_id": "exec-1", "command": stored_command, "exit_code": 0},
            }
        ]
    )
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool("get_audit", {})
    return result[0].text


class TestOneRunOneCommandText:
    def test_ruled_pair_reads_identically_on_all_three_surfaces(self):
        """THE deliverable: executor audit row, server audit row, and the stored
        execution_sessions column for ONE run are byte-equal, and the MCP line shows
        that same text. Rejects: the server re-deriving the text with `shlex.join`."""
        executor_text = _executor_surface()
        audit_text, session_text = _server_surfaces()
        assert executor_text == audit_text == session_text == RULED, (
            f"executor={executor_text!r}\nserver audit={audit_text!r}\n" f"execution_sessions={session_text!r}"
        )

    def test_the_stored_text_is_the_raw_pair_not_the_quoted_form(self):
        """The other half of the claim: identical is not automatically RIGHT. All three
        must carry the #332 ruled rendering, and none may carry the quoting shape that
        made the redirect inert. Proven able to fail: a surface still on `shlex.join`
        reads the quoted form and this cell goes red."""
        executor_text = _executor_surface()
        audit_text, session_text = _server_surfaces()
        for label, text in (
            ("executor", executor_text),
            ("server audit", audit_text),
            ("session column", session_text),
        ):
            assert f"'{BOUND_PATH}'" not in text, f"{label} quoted the bound secret path"
            assert " '<' " not in text, f"{label} quoted the '<' token — the #332 inertness class"
            assert text.endswith(f"< {BOUND_PATH}"), f"{label} did not emit the ruled pair raw: {text!r}"

    def test_the_rejected_command_stores_the_rendered_text_too(self):
        """#759's one surviving site: a REFUSAL row stores a command like any other row.

        The structural gate refuses an argv before the rendered string exists further down
        `execute`, so this row was written from a join of the list while the success lane and
        the server's `display_command` carried `render_command` — one argv, two texts, on the
        path an operator reads when a command is denied. The refusal must carry the ruled
        rendering: the pair raw, the metachar element quoted.
        """
        import shlex

        from venya_contract.relay import bound_secret_paths, render_command

        stored = _reject_row_command()
        expected = render_command(REJECT_ARGV, bound_secret_paths([BOUND_SECRET_ID]))
        assert stored == expected, f"rejection row={stored!r} rendered={expected!r}"
        assert stored != shlex.join(REJECT_ARGV), f"the rejection row is back on shlex.join: {stored!r}"
        assert " '<' " not in stored, f"the rejection row quoted the '<' token: {stored!r}"

    def test_one_argv_refused_by_either_lane_stores_one_text(self):
        """The cross-lane negative: two refusal sites in `execute`, one stored text.

        The structural gate (which had no rendered string in scope, and was the defect) and
        the policy gate (which already read the rendered form) both emit `command_rejected`.
        Driving the same argv through each is what turns 'these two happen to agree' into a
        checked property; a regression on either lane reddens the last assertion.
        """
        from venya_contract.relay import bound_secret_paths, render_command

        structural = _reject_row_command()
        policy = _reject_row_command(bypass_structure=True)
        expected = render_command(REJECT_ARGV, bound_secret_paths([BOUND_SECRET_ID]))
        assert structural == expected, f"structural lane={structural!r} expected={expected!r}"
        assert policy == expected, f"policy lane={policy!r} expected={expected!r}"
        assert structural == policy, f"one argv, two refusals, two texts:\n{structural!r}\n{policy!r}"

    def test_mcp_line_prints_what_the_ledger_holds(self):
        """Surface 3, read from the stored value rather than re-derived: the agent-visible
        text contains the same command, so the operator and the agent cannot be shown two
        renderings of one run."""
        _audit_text, session_text = _server_surfaces()
        line = _mcp_run(session_text)
        assert session_text in line, f"the MCP line hides the stored command:\n{line}"
        assert f"< {BOUND_PATH}" in line, line

    def test_plain_argv_still_reads_identically_everywhere(self):
        """Zero-drift half of #332, kept honest at this face: with NO pair in play the
        ruled rendering is byte-identical to `shlex.join`, so this alignment changes
        nothing for the common command."""
        argv = ["/usr/bin/ssh", "bot@web-server-3", "/usr/bin/uptime"]
        import shlex

        expected = shlex.join(argv)
        executor_text = _executor_surface(argv, secret_ids=())
        audit_text, session_text = _server_surfaces(argv, bound_id=None)
        assert (
            executor_text == audit_text == session_text == expected
        ), f"{executor_text!r} / {audit_text!r} / {session_text!r}"

    def test_unbound_redirect_never_reaches_a_surface(self):
        """Paired negative: a `<` whose target is NOT session-bound is refused at the
        gate, so no surface stores a command for it — the alignment cannot bless the
        shape #732 refuses. The server-side write for an unbound pair would have been
        the QUOTED text; the gate is what stops it, unchanged here."""
        from executor.executor import _validate_command_structure

        with pytest.raises(ValueError, match="SESSION-BOUND"):
            _validate_command_structure(ARGV[:-1] + ["/etc/passwd"], frozenset({BOUND_PATH}))


def _mcp_run(stored_command: str) -> str:
    import asyncio

    return asyncio.run(_mcp_surface(stored_command))
