# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#710 option (a) — `run_command` emits progress while the command runs.

Driven through the SDK's own in-memory session harness (`mcp.shared.memory`), i.e. the runtime
dispatch path, never the undecorated handler: the progress token is minted by the client in
`send_request` and the notification has to travel the real channel to be counted as evidence.
Cadence is patched down so a cell costs milliseconds, not seconds.

The hard bar these cells exist to hold (owner ruling `R-2632`): the channel carries STAGE AND
LIVENESS ONLY. Command text, argv, an output fragment, a secret key, a path or an executor id on
this channel is a new disclosure surface, and it collides with the #715 escaping ruling and the
two-stage masking. So every cell that proves liveness also proves the absence of content.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import venya_mcp.server as server_mod
from mcp.types import CallToolResult  # noqa: F401  (documentary: the result type the harness returns)
from venya_mcp.client import VenyaAPIError, VenyaClient

# A value that is shaped like something worth hiding: a bound-secret path. If any part of the
# request were forwarded onto the progress channel, this is what would show up.
MARKER_PATH = "/run/secrets/venya/00000000-0000-4000-8000-000000000710"
MARKER_ARGV = f"sshpass|-f|{MARKER_PATH}|bot@web-3"

_FAST_TICK = 0.01
# The stage word, pinned by LITERAL (the #713 `SHELL_METACHARS` membership shape, not an import):
# importing the constant would make the cell unfalsifiable — it would agree with itself whatever
# the emitter sent. This is the whole wire vocabulary of the channel: one word and a counter.
_PROGRESS_STAGE = "running"


def _has_content(kwargs: dict) -> bool:
    """True if a send carried anything the caller could have learned content from."""
    blob = repr(sorted(kwargs.items()))
    return MARKER_PATH in blob or "sshpass" in blob or "web-3" in blob


def _make_mock_client() -> MagicMock:
    mock = MagicMock(spec=VenyaClient)
    mock.run_command = AsyncMock(
        return_value={
            "exit_code": 0,
            "stdout": "done",
            "stderr": "",
            "masked_count": 0,
        }
    )
    return mock


def _slow_client(delay: float, result: dict | None = None, error: Exception | None = None) -> MagicMock:
    """A client whose run_command stays in flight for `delay` seconds."""
    mock = _make_mock_client()

    async def _run(**kwargs):
        await asyncio.sleep(delay)
        if error is not None:
            raise error
        if result is not None:
            return result
        return {
            "exit_code": 0,
            "stdout": "done",
            "stderr": "",
            "masked_count": 0,
        }

    mock.run_command = AsyncMock(side_effect=_run)
    return mock


async def _call(mock: MagicMock, *, progress_callback=None, command: str = "ls"):
    """One tools/call through the real SDK dispatch path."""
    from mcp.shared.memory import create_connected_server_and_client_session

    with patch("venya_mcp.server.get_client", return_value=mock):
        async with create_connected_server_and_client_session(server_mod.app) as session:
            await session.initialize()
            return await session.call_tool(
                "run_command",
                {"executor_id": "web-3", "command": command, "secret_keys": ["k"]},
                progress_callback=progress_callback,
            )


# --- cell 1: liveness. ticks arrive DURING the call, before the answer.


async def test_ticks_arrive_while_run_command_is_in_flight(monkeypatch):
    """#710 AC1 (the part a build leg owes): a caller that asked for progress is re-armed
    while the command runs. Red at base: nothing is emitted today, so zero ticks arrive."""
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)
    ticks: list[tuple] = []

    async def cb(progress, total, message):
        ticks.append((progress, total, message))

    mock = _slow_client(0.06)
    result = await _call(mock, progress_callback=cb)

    assert len(ticks) >= 2, f"expected several ticks during a 60 ms call, got {ticks}"
    # liveness only: a strictly increasing counter and one fixed stage word.
    assert [t[0] for t in ticks] == sorted({t[0] for t in ticks}), "progress must increase"
    assert all(t[2] == _PROGRESS_STAGE for t in ticks)
    assert all(t[1] is None for t in ticks), "total is unknown and must not be invented"
    # the answer is still the answer
    assert not result.isError


# --- cell 2: THE PAIRED NEGATIVE — no command text, ever, on the channel.


async def test_progress_channel_carries_no_command_text_or_argv(monkeypatch):
    """The load-bearing negative for the R-2632 bar, mirrored from #713 AC3's no-echo cell.

    The command carries a distinctive bound-secret-shaped value that WOULD appear if the
    emitter forwarded anything about the call. Non-vacuity: passing `stage=str(arguments)`
    — or interpolating the command, the executor id, or the secret key — reddens this cell.
    """
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)
    seen: list[tuple] = []

    async def cb(progress, total, message):
        seen.append((progress, total, message))

    mock = _slow_client(0.06)
    await _call(mock, progress_callback=cb, command=MARKER_ARGV)

    assert seen, "the cell is vacuous unless ticks actually arrived"
    blob = repr(seen)
    for forbidden in (
        MARKER_PATH,
        "00000000-0000-4000-8000-000000000710",
        "sshpass",
        "bot@web-3",
        "web-3",  # the executor id is an identifier the caller supplied; not this channel's
        "k",
        "ls",
    ):
        assert forbidden not in blob, f"the progress channel carried {forbidden!r}"


# --- cell 3: the token is OPT-IN. no progressToken -> served normally, emits nothing.


async def test_request_without_progress_token_emits_nothing(monkeypatch):
    """637 cell E, as a shipped-behavior guard: a caller that did not ask for progress gets
    the answer and no traffic. Emission here would be unsolicited load on a channel nobody
    is listening to, and would fire the LookupError-free path on every fast call.

    Patched on `ServerSession`, the class the emitter actually holds (`mcp/server/session.py`,
    `send_progress_notification`) — a patch on the `BaseSession` twin is a silent no-op and
    this cell passes for the wrong reason there. That wrong instrument was measured here: the
    first draft of this cell patched the base class and returned `await_count 0` even on the
    ticking path. The positive-control half below is what keeps that from being vacuous again.
    """
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)
    sent = AsyncMock(side_effect=lambda **kw: None)
    monkeypatch.setattr(
        "mcp.server.session.ServerSession.send_progress_notification",
        sent,
    )

    result = await _call(_slow_client(0.06))

    assert not result.isError
    assert "exited with code 0" in result.content[0].text
    sent.assert_not_awaited()

    # positive control in the same instrument: the SAME patch, with a token asked for, must
    # observe sends — otherwise "not_awaited" above measures the patch, not the behavior.
    async def cb(progress, total, message):
        pass

    sent.reset_mock()
    await _call(_slow_client(0.06), progress_callback=cb)
    assert sent.await_count >= 2, f"the spy cannot see sends (got {sent.await_count})"
    assert all(not _has_content(c.kwargs) for c in sent.await_args_list)


# --- cell 4: the terminal state is untouched. progress must not alter the answer.


async def test_terminal_answer_is_the_same_with_progress_as_without(monkeypatch):
    """#712 mirror-of-precedent, run in reverse: what the caller finally gets — rc, stdout,
    stderr, masked count, and the executor the command ran on (#712) — is byte-identical
    whether or not the call ticked. A progress channel that changed the answer would be a
    second response surface, not a liveness signal."""
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)

    async def cb(progress, total, message):
        pass

    final = {"exit_code": 3, "stdout": "out\n", "stderr": "err\n", "masked_count": 2}
    with_ticks = await _call(_slow_client(0.05, result=final), progress_callback=cb)
    no_ticks = await _call(_slow_client(0.0, result=final))

    assert with_ticks.content[0].text == no_ticks.content[0].text
    text = with_ticks.content[0].text
    assert "code 3" in text and "out" in text and "err" in text
    assert "2 secret(s) masked" in text
    assert "executor=web-3" in text


# --- cell 5: the failure path emits its terminal state without content.


async def test_refused_command_still_answers_and_leaks_nothing(monkeypatch):
    """A policy refusal (422 from the executor gate) is a terminal state. The caller must
    still get the refusal, ticks must still have been only liveness, and the refusal must
    not have been laundered onto the progress channel on the way out."""
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)
    seen: list[tuple] = []

    async def cb(progress, total, message):
        seen.append((progress, total, message))

    refusal = VenyaAPIError(422, f"Argument 2 contains a disallowed shell metacharacter: {MARKER_ARGV}")
    mock = _slow_client(0.05, error=refusal)
    result = await _call(mock, progress_callback=cb, command=MARKER_ARGV)

    assert result.isError is True, "the refusal must still reach the caller as an error"
    assert seen and all(t[2] == _PROGRESS_STAGE for t in seen)
    assert MARKER_ARGV not in repr(seen) and MARKER_PATH not in repr(seen)


# --- cell 6: a tick that cannot be delivered does not eat the answer.


async def test_undeliverable_tick_leaves_the_answer_intact(monkeypatch):
    """A caller that has already gone mid-command is the expected case, not the exotic one:
    the notification write fails, and that must not replace the answer with a second defect.
    Control-own-inputs clause: the emitter must not be able to break the response."""
    monkeypatch.setattr(server_mod, "_PROGRESS_TICK_SECONDS", _FAST_TICK)

    async def cb(progress, total, message):
        pass

    boom = AsyncMock(side_effect=RuntimeError("transport closed"))
    monkeypatch.setattr("mcp.server.session.ServerSession.send_progress_notification", boom)

    result = await _call(_slow_client(0.06), progress_callback=cb)

    assert not result.isError
    assert "exited with code 0" in result.content[0].text
    assert boom.await_count >= 2, "the cell must actually have driven a failing tick"


# --- guard: the helper is request-context-free-callable (unit shape, not SDK shape)


async def test_direct_handler_call_without_request_context_is_served_unchanged():
    """The unit suite calls `call_tool` directly, outside any request. `request_context`
    raises LookupError there; that is the "nobody to notify" case, and the answer must be
    exactly what it was before this change."""
    from venya_mcp.server import call_tool

    mock = _make_mock_client()
    with patch("venya_mcp.server.get_client", return_value=mock):
        result = await call_tool(
            "run_command",
            {"executor_id": "web-3", "command": "ls", "secret_keys": []},
        )
    assert "exited with code 0" in result[0].text
