# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The running MCP server picks up the session a later `venya login` wrote (#705, #776).

The client used to hold only the token it read at construction, so an operator who logged
in after the server started had to restart it before any tool call worked. Now the file is
statted per call and read only when its mtime moves, a refused refresh asks it once more,
and the session sentence names which of three states it found.

Cells follow leg 1555's negatives, as amended by the lead at 17:29:

(a) a file holding the SAME token cannot loop — one read, then the usual error;
(b) a success path costs a stat, not a read — the hot path stays one in-memory token;
(c) the re-read never puts a token value in the log (checked on the log face);
(d) a file that is gone, unreadable or unparseable answers the same session error;
(e) the sentence names the resolved path and which of the three states it found;
(f) #706, folded in at 17:40 by the collision rule: a state that never held a token is not
    called expired, and the state that WAS refused still is — one cell per distinction.

The remedy wording is asserted on its stable stem, not byte-for-byte: leg 1554 edits the
verb inside that same sentence, and a cell pinning the whole string would fail on landing
rather than on behaviour.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from venya_mcp.client import SessionExpiredError, VenyaClient
from venya_mcp.config import MCPConfig

STARTUP_TOKEN = "startup-token"
DISK_TOKEN = "login-landed-after-startup-token"
OTHER_CORE = "https://venya-core-2"
STEM = "Venya session expired and could not be renewed"
NEVER_HELD = "This process never held a token"


def _write(path: Path, token: str | None, server_url: str = "https://venya-core-1") -> None:
    payload: dict = {"server_url": server_url}
    if token is not None:
        payload["access_token"] = token
    path.write_text(json.dumps(payload))


def _client(path: Path, token: str | None = STARTUP_TOKEN) -> VenyaClient:
    _write(path, token)
    return VenyaClient(MCPConfig(path), verify=False)


def _response(status_code: int, body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {}
    resp.text = ""
    resp.headers = {}
    return resp


def _login_landed(client: VenyaClient, token: str = DISK_TOKEN, server_url: str = "https://venya-core-1") -> None:
    """Rewrite the session file the way a `venya login` does, one second past the stamp
    the server recorded.

    The gate is an mtime test and this box gives two writes inside one filesystem clock
    tick the same mtime (measured: identical st_mtime_ns for back-to-back writes), so the
    cells that mean "the file moved" move it on purpose. The still-clock shape is not
    untested — see test_still_mtime_is_caught_by_the_missing_token_door.
    """
    config = client.config
    _write(config.path, token, server_url=server_url)
    stamp = (config._mtime or 0) + 1_000_000_000
    os.utime(config.path, ns=(stamp, stamp))


def _count_file_work(config: MCPConfig) -> tuple[list[int], list[int]]:
    """Shadow this config's read and stat with counters — instance attributes, so no
    other test's config is touched and no class method is patched."""
    reads: list[int] = []
    stats: list[int] = []
    real_read, real_stat = config.reload, config._stat_mtime

    def counting_read() -> str | None:
        reads.append(1)
        return real_read()

    def counting_stat() -> int | None:
        stats.append(1)
        return real_stat()

    config.reload = counting_read  # type: ignore[method-assign]
    config._stat_mtime = counting_stat  # type: ignore[method-assign]
    return reads, stats


def _ok_http() -> MagicMock:
    http = MagicMock()
    http.post = AsyncMock(return_value=_response(401))
    http.request = AsyncMock(return_value=_response(200, {"ok": True}))
    return http


# --- the capability: a login that lands after startup -----------------------


async def test_mtime_door_picks_up_a_login_written_after_startup(tmp_path: Path) -> None:
    """The file moves while the server runs: the very next call dials with that token.

    This is reports/361's repro without a key ceremony — no 401 round trip is needed to
    learn the new session, so the operator's first dial is already the good one.
    """
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client)

    http = _ok_http()
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert http.request.await_count == 1
    assert http.request.call_args[1]["headers"]["Authorization"] == f"Bearer {DISK_TOKEN}"


async def test_missing_token_adopts_the_session_on_disk(tmp_path: Path) -> None:
    """A server that started with no token at all reads the one the CLI wrote since."""
    path = tmp_path / "config.json"
    client = _client(path, token=None)
    _login_landed(client)

    http = _ok_http()
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert http.request.await_count == 1
    assert client._access_token == DISK_TOKEN


async def test_still_mtime_is_caught_by_the_missing_token_door(tmp_path: Path) -> None:
    """Paired negative on the gate: a file whose mtime did not move is still read when
    the process holds no token, so the capability does not depend on the clock moving."""
    path = tmp_path / "config.json"
    _write(path, None)  # what the server saw at startup: a file, and no token in it
    config = MCPConfig(path)
    _write(path, DISK_TOKEN)  # the login lands...
    os.utime(path, ns=(config._mtime, config._mtime))  # ...and the clock does not move
    client = VenyaClient(config, verify=False)

    http = _ok_http()
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert client._access_token == DISK_TOKEN


async def test_refused_refresh_retries_with_the_token_that_landed_mid_call(tmp_path: Path) -> None:
    """401, refresh refused, and the login arrives during the call: one retry, with it."""
    path = tmp_path / "config.json"
    client = _client(path)

    sent: list[str] = []

    def dial(method, url, **kwargs):
        sent.append(kwargs["headers"]["Authorization"])
        if len(sent) == 1:
            _login_landed(client)  # the operator logs in while the request is in flight
            return _response(401)
        return _response(200, {"ok": True})

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(401))
    http.request = AsyncMock(side_effect=dial)
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert sent == [f"Bearer {STARTUP_TOKEN}", f"Bearer {DISK_TOKEN}"]
    assert http.post.await_count == 1  # the refresh was refused, not skipped


async def test_adoption_does_not_repoint_the_dial(tmp_path: Path) -> None:
    """A re-read takes the token only: the bearer stays aimed at the core it started on."""
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client, server_url=OTHER_CORE)

    http = _ok_http()
    client._http = http

    await client._request("GET", "/api/v1/test")
    assert client._access_token == DISK_TOKEN
    assert http.request.call_args[0][1] == "https://venya-core-1/api/v1/test"


# --- negative (a): the same token on disk cannot loop -----------------------


async def test_identical_disk_token_ends_the_attempt(tmp_path: Path) -> None:
    """401, refresh refused, file still holds the rejected token: no second dial."""
    path = tmp_path / "config.json"
    client = _client(path)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(401))
    http.request = AsyncMock(side_effect=[_response(401)])
    client._http = http

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    assert STEM in str(exc_info.value)
    assert http.request.await_count == 1
    assert http.post.await_count == 1


async def test_a_refresh_that_hands_back_the_same_token_does_not_retry(tmp_path: Path) -> None:
    """An unchanged value is not a renewal: the attempt ends instead of dialling twice."""
    path = tmp_path / "config.json"
    client = _client(path)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(200, {"access_token": STARTUP_TOKEN}))
    http.request = AsyncMock(side_effect=[_response(401), _response(200, {"ok": True})])
    client._http = http

    with pytest.raises(SessionExpiredError):
        await client._request("GET", "/api/v1/test")
    assert http.request.await_count == 1


# --- negative (b): a success path costs a stat, not a read ------------------


async def test_unchanged_file_costs_one_stat_and_no_read(tmp_path: Path) -> None:
    """The hot path is the in-memory token: a call that works reads nothing."""
    path = tmp_path / "config.json"
    client = _client(path)
    reads, stats = _count_file_work(client.config)

    client._http = _ok_http()
    await client._request("GET", "/api/v1/test")

    assert reads == []
    assert len(stats) == 1  # one stat per header composition, and no content touched
    assert client._access_token == STARTUP_TOKEN


async def test_successful_refresh_never_asks_the_file(tmp_path: Path) -> None:
    """A refresh that works is a success: no re-read sits behind it."""
    path = tmp_path / "config.json"
    client = _client(path)
    reads, _stats = _count_file_work(client.config)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(200, {"access_token": "refreshed-token"}))
    http.request = AsyncMock(side_effect=[_response(401), _response(200, {"ok": True})])
    client._http = http

    await client._request("GET", "/api/v1/test")
    assert reads == []
    assert client._access_token == "refreshed-token"


# --- negative (c): the value stays out of the log ---------------------------


async def test_adoption_logs_the_file_not_the_token(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The operator learns a swap happened and where; no token value is ever printed."""
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client)

    client._http = _ok_http()
    with caplog.at_level(logging.DEBUG, logger="venya.mcp"):
        await client._request("GET", "/api/v1/test")

    # the whole value and its leading slice: "log the first 8" is the realistic leak
    # at this seam, so a truncated one fails this cell too
    for leak in (DISK_TOKEN, DISK_TOKEN[:8], STARTUP_TOKEN):
        assert leak not in caplog.text
    assert str(path) in caplog.text
    assert "Adopted the session token" in caplog.text


# --- negatives (d) and (e): a broken file, and the state the sentence names --

_BROKEN_SHAPES = ["vanished", "unparseable", "not_an_object", "no_token"]
if os.geteuid() != 0:
    # root reads a mode-000 file, so the unreadable shape is only measured for a real one
    _BROKEN_SHAPES.append("unreadable")


@pytest.mark.parametrize("entry", ["missing_token", "refused_refresh"])
@pytest.mark.parametrize("shape", _BROKEN_SHAPES)
async def test_broken_session_file_answers_the_session_error(tmp_path: Path, shape: str, entry: str) -> None:
    """No traceback, no second error class: a file we cannot use reads as 'expired'."""
    path = tmp_path / "config.json"
    client = _client(path, token=None if entry == "missing_token" else STARTUP_TOKEN)

    if shape == "vanished":
        path.unlink()
    elif shape == "unparseable":
        _write(path, DISK_TOKEN)
        path.write_text("{ not json")
    elif shape == "not_an_object":
        _write(path, DISK_TOKEN)
        path.write_text("[1, 2, 3]")
    elif shape == "no_token":
        _write(path, None)
    elif shape == "unreadable":
        _write(path, DISK_TOKEN)
        path.chmod(0)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(401))
    http.request = AsyncMock(side_effect=[_response(401), _response(200, {"ok": True})])
    client._http = http

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    message = str(exc_info.value)
    if entry == "refused_refresh":
        # the token in hand was dialled and refused; the file offered nothing to retry with
        assert STEM in message
        assert http.request.await_count == 1
        assert client._access_token == STARTUP_TOKEN
    else:
        # #706: nothing was ever dialled, so nothing may claim a session expired
        assert NEVER_HELD in message
        assert STEM not in message
        assert http.request.await_count == 0
        assert client._access_token is None

    if shape == "unreadable":
        path.chmod(0o600)


@pytest.mark.parametrize(
    ("shape", "expect", "remedy"),
    [
        ("no_file", "there is no session file at", "venya login"),
        ("no_key", "holds no access_token", "venya login"),
        # the refused state keeps dev's remedy fragment untouched: leg 1554 owns that
        # sentence (#776), and this leg owns the states
        ("refused", "was refused by the core", "Run the `venya` CLI"),
    ],
)
async def test_the_sentence_names_the_state_and_the_resolved_path(
    tmp_path: Path, shape: str, expect: str, remedy: str
) -> None:
    """Three states, three remedies, one sentence (#705's operator half)."""
    path = tmp_path / "venya-config.json"

    if shape == "no_file":
        _write(path, DISK_TOKEN)
        config = MCPConfig(path)  # the path was there at startup and is not now
        client = VenyaClient(config, verify=False)
        client._access_token = None
        path.unlink()
        http = _ok_http()
    elif shape == "no_key":
        client = _client(path, token=None)
        http = _ok_http()
    else:  # "refused": a token exists, the core says no, and the file holds the same value
        client = _client(path)
        http = MagicMock()
        http.post = AsyncMock(return_value=_response(401))
        http.request = AsyncMock(side_effect=[_response(401)])

    client._http = http
    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    message = str(exc_info.value)
    assert expect in message
    assert str(path) in message  # the path this process resolved, not a placeholder
    assert remedy in message  # the remedy travels with the state that names it


# --- #706: a session that never existed is not an expired one ---------------


async def test_a_never_held_session_is_not_called_expired(tmp_path: Path) -> None:
    """The file is there and holds no token: no expiry claim, no refusal claim, no restart.

    RED at base, where this state printed "Venya session expired …" and asked the operator
    to approve a key as though a refresh had just been refused — the hour of owner time
    #706 was filed for.
    """
    path = tmp_path / "config.json"
    client = _client(path, token=None)
    client._http = _ok_http()

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    message = str(exc_info.value)
    assert NEVER_HELD in message
    assert "no restart is needed" in message
    # the false claims are the ones #706 was filed about, by their own words
    assert "session expired" not in message
    assert STEM not in message
    assert "was refused" not in message
    assert "restart the MCP server" not in message
    assert "venya list" not in message
    assert "nothing expired" in message  # it says the truth, not merely not the lie
    assert "venya login" in message
    assert str(path) in message


async def test_a_refused_token_is_still_called_expired(tmp_path: Path) -> None:
    """#706 AC2's paired negative: making the no-token case honest does not soften this one."""
    path = tmp_path / "config.json"
    client = _client(path)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(401))
    http.request = AsyncMock(side_effect=[_response(401)])
    client._http = http

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    message = str(exc_info.value)
    assert STEM in message
    assert "was refused by the core" in message
    assert NEVER_HELD not in message
    # AC3: the refusal it observed is named, and no status code it did not observe is
    assert "401" not in message


def test_the_startup_precondition_names_the_path_and_the_login(tmp_path: Path) -> None:
    """`MCPConfig._load`, the third site (#706's "count is honest" paragraph).

    This state really does need a start afterwards — a server that never came up has
    nothing that can reload — so that tail stays, the verb becomes the one that renews, and
    the stem the run-entry and version-surface cells pin is unchanged.
    """
    path = tmp_path / "absent-config.json"
    with pytest.raises(FileNotFoundError) as exc_info:
        MCPConfig(path)

    message = str(exc_info.value)
    assert "No Venya session token found" in message  # the pinned stem, unweakened
    assert str(path) in message
    assert "venya login" in message
    assert "venya list" not in message  # a read verb is not a way back (#776)
    assert "expired" not in message.lower()
