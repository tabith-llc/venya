# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The running MCP server reads the session file again — and refuses a swap it cannot attest.

The client used to hold only the token it read at construction, so an operator who logged
in before the server started and held nothing had no way in without a restart. Now the file is
statted per call and read only when its mtime moves, a refused refresh asks it once more, and the
session sentence names which of three states it found.

What that read may do is the other half of #705, and the owner ruled it refuse-and-tell: the file
carries `server_url` and `access_token` and names no principal, and the bearer is 256 random bits, so
this process cannot show a differing token to be its own login's. It therefore establishes a session
from the file when it holds nothing, and refuses one when it does — in words that say what was
refused and what to do about it.

Cells follow leg 1555's negatives, as amended by the lead at 17:29:

(a) a file holding the SAME token cannot loop — one read, then the usual error;
(b) a success path costs a stat, not a read — the hot path stays one in-memory token;
(c) the re-read never puts a token value in the log (checked on the log face);
(d) a file that is gone, unreadable or unparseable answers the same session error;
(e) the sentence names the resolved path and which of the three states it found;
(f) #706, folded in at 17:40 by the collision rule: a state that never held a token is not
    called expired, and the state that WAS refused still is — one cell per distinction;
(g) leg 1558's review finding, fixed in source: the renewing clause is one constant composed
    at all three sites (both client refusals and the startup precondition), so no site can
    name a verb that clears the token (#776).
(h) #705 as ruled: a differing token on disk is refused while a session is in hand, and the
    refusal is told; a pickup that establishes a session (nothing in hand) still works, and only
    for the core the file names.

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
from venya_mcp.client import SessionExpiredError, VenyaClient, session_error_text
from venya_mcp.config import RENEW_CLAUSE, MCPConfig

STARTUP_TOKEN = "startup-token"
DISK_TOKEN = "login-landed-after-startup-token"
OTHER_CORE = "https://venya-core-2"
STEM = "Venya session expired and could not be renewed"
NEVER_HELD = "This process never held a token"
DECLINED = "did not obtain"


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


async def test_mtime_door_refuses_a_login_written_while_a_session_is_held(tmp_path: Path) -> None:
    """The file moves while a token is in hand: the swap is refused, the call is not.

    #705 as the owner ruled it — this process dials only the session it obtained. A refusal must
    never cost the operator a working call, so the dial still goes out with the token in hand, and
    the declined value is recorded because it is the fact the next sentence has to tell.
    """
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client)

    http = _ok_http()
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert http.request.await_count == 1
    assert http.request.call_args[1]["headers"]["Authorization"] == f"Bearer {STARTUP_TOKEN}"
    assert client._access_token == STARTUP_TOKEN
    assert client._adoption_refused


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


async def test_refused_refresh_refuses_the_token_that_landed_mid_call(tmp_path: Path) -> None:
    """401, refresh refused, and a login arrives during the call: that token is not presented.

    This is the shape the ruling is about. The core has refused the credential in hand and the file
    holds a different one; retrying with it would act as a login this process cannot attest, so the
    attempt ends at one dial, one refresh POST, and a refusal sentence that names the declined value.
    """
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

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    message = str(exc_info.value)
    assert sent == [f"Bearer {STARTUP_TOKEN}"]
    assert http.post.await_count == 1  # the refresh was refused, not skipped
    assert STEM in message  # AC3: a credential the core did refuse is still called expired
    assert "was refused by the core" in message
    assert DECLINED in message  # and the file's other token is named as declined
    assert "no restart is needed" not in message  # at this site the restart is the remedy again
    assert client._access_token == STARTUP_TOKEN


async def test_a_refused_adoption_leaves_the_refresh_working(tmp_path: Path) -> None:
    """Refusing the file is not refusing the session: the core's own renewal still renews.

    The renewal needs no attestation from the file — the core minted it for the credential in hand —
    so it is the half of #705's remedy that must survive the refusal. A foreign token sits on disk
    for the whole call to prove the two do not interfere.
    """
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client)

    http = MagicMock()
    http.post = AsyncMock(return_value=_response(200, {"access_token": "refreshed-token"}))
    http.request = AsyncMock(side_effect=[_response(401), _response(200, {"ok": True})])
    client._http = http

    assert await client._request("GET", "/api/v1/test") == {"ok": True}
    assert client._access_token == "refreshed-token"
    assert http.request.call_args_list[1][1]["headers"]["Authorization"] == "Bearer refreshed-token"
    assert json.loads(path.read_text())["access_token"] == "refreshed-token"


async def test_a_pickup_is_refused_when_the_file_names_another_core(tmp_path: Path) -> None:
    """A read that establishes a session takes a token only for the core this process dials.

    The file is repointed at another core and a token for that core lands in it. Nothing was held
    here, so the read may still establish a session — but carrying that bearer to this process's own
    dial is the crossing the ruling names, and it is refused before a request goes out (#540's dial
    stays where it is; this is not a second https guard, it is the token's own home.
    """
    path = tmp_path / "config.json"
    client = _client(path, token=None)
    _login_landed(client, server_url=OTHER_CORE)

    http = _ok_http()
    client._http = http

    with pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    assert http.request.await_count == 0  # nothing was dialled with a bearer it would not attest
    assert client._access_token is None
    message = str(exc_info.value)
    assert DECLINED in message
    assert NEVER_HELD in message  # #706 holds at this site too: nothing expired, nothing was refused
    assert STEM not in message
    assert str(path) in message


# --- negative (a): the same token on disk cannot loop -----------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"access_token": DISK_TOKEN}, id="no-server_url-key"),
        pytest.param(
            {"server_url": ["https://venya-core-1"], "access_token": DISK_TOKEN},
            id="server_url-not-a-string",
        ),
    ],
)
async def test_a_pickup_is_refused_when_the_file_names_no_core(
    tmp_path: Path, payload: dict, caplog: pytest.LogCaptureFixture
) -> None:
    """The adoption guard asks what the file NAMES, not whether it answered (leg 1576, ruled DECLINE).

    `disk_server_url` reports None for a file with no `server_url` and for one whose value is not a
    string, and the shipped guard read `disk_core is not None and ...`, so both shapes fell through to
    adoption — the sentence promised a comparison the code skipped. This process cannot attest that a
    file naming no core still names the core it dials, so nothing is taken: it gets the same answer the
    file naming ANOTHER core already gets. Driven through the real `_request` seam, nothing in hand.
    """
    path = tmp_path / "config.json"
    client = _client(path, token=None)
    config = client.config
    path.write_text(json.dumps(payload))
    # the mtime door needs the clock to move to read again; see `_login_landed` for why
    stamp = (config._mtime or 0) + 1_000_000_000
    os.utime(path, ns=(stamp, stamp))

    http = _ok_http()
    client._http = http

    with caplog.at_level(logging.DEBUG, logger="venya.mcp"), pytest.raises(SessionExpiredError) as exc_info:
        await client._request("GET", "/api/v1/test")

    assert http.request.await_count == 0  # nothing was dialled with a bearer it cannot attest
    assert client._access_token is None
    assert config.disk_server_url is None  # the very shape the guard used to fall through on
    message = str(exc_info.value)
    assert DECLINED in message
    assert NEVER_HELD in message  # #706 holds here too: nothing expired, nothing was refused
    assert STEM not in message
    assert str(path) in message
    # and the declined value stays off the log face in this branch too
    for leak in (DISK_TOKEN, DISK_TOKEN[:8]):
        assert leak not in caplog.text
    assert "Did not adopt the session token" in caplog.text
    assert "Adopted the session token" not in caplog.text


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
    """A session established from the file is logged as a path and an act; no value is printed.

    The pickup that survives the ruling is the one that finds nothing in hand, so this cell runs
    through that shape — `token=None` at startup, the login landing after it.
    """
    path = tmp_path / "config.json"
    client = _client(path, token=None)
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


async def test_a_refusal_logs_the_file_not_the_token(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The declined token is written down as declined, and its value stays off the log face.

    This is the leak cell for the branch the ruling adds: a refusal that names the value it refused
    would move a bearer credential into the log, which is the file #706's whole complaint reversed.
    """
    path = tmp_path / "config.json"
    client = _client(path)
    _login_landed(client)

    client._http = _ok_http()
    with caplog.at_level(logging.DEBUG, logger="venya.mcp"):
        await client._request("GET", "/api/v1/test")

    for leak in (DISK_TOKEN, DISK_TOKEN[:8]):
        assert leak not in caplog.text
    assert str(path) in caplog.text
    assert "Did not adopt the session token" in caplog.text
    assert "Adopted the session token" not in caplog.text


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
        # every state now closes with the one renewing clause leg 1554 ruled for #776 — the
        # faults differ, the remedy a reader has to act on does not
        ("refused", "was refused by the core", "venya login"),
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
    # and the #776 rule holds at this site too, in source rather than in an assertion
    assert "venya login" in message
    assert "<USER_ID>" in message
    for banned in ("venya list", "venya run"):
        assert banned not in message


def test_the_declined_token_is_told_at_both_states_and_asserts_nothing_more() -> None:
    """The refusal rides on the state that observed it, and never borrows a status (#705, #706).

    Both sentences must say the same thing about the file — a token this process did not obtain, and
    will not use — and must keep the two faults apart: the state that watched the core refuse a
    bearer still says so, the state that never sent one still does not. And neither may print a
    number it did not observe, because the refusal has no status of its own.
    """
    path = Path("/fixture/venya-config.json")
    refused = session_error_text(path, refused=True, adoption_refused=True)
    never_held = session_error_text(path, adoption_refused=True)

    assert STEM in refused and STEM not in never_held
    assert NEVER_HELD in never_held and NEVER_HELD not in refused
    for text in (refused, never_held):
        assert DECLINED in text
        assert str(path) in text
        assert RENEW_CLAUSE in text
        assert "restart or reconnect the MCP server" in text
        for observed in ("401", "403", "503", "no verdict"):
            assert observed not in text
        for banned in ("venya list", "venya run"):
            assert banned not in text


def test_the_remedy_is_one_clause_at_every_site() -> None:
    """Three sites, one renewing clause (leg 1558's finding, fixed in source).

    1554 pinned that its two sites answer with one sentence; #706 rules that the two FAULTS
    must be distinguishable, so whole-message equality is the wrong instrument here. What is
    true, and what this pins, is that the remedy a reader acts on is composed from one
    constant at every site — the two client refusals and the startup precondition — so no
    site can drift back to a verb that clears the token.
    """
    path = Path("/fixture/venya-config.json")
    refused = session_error_text(path, refused=True)
    never_held = session_error_text(path)

    with pytest.raises(FileNotFoundError) as excinfo:
        MCPConfig(path)  # the third site: the startup precondition, no file at all
    startup_text = str(excinfo.value)

    assert RENEW_CLAUSE in refused
    assert RENEW_CLAUSE in never_held
    assert RENEW_CLAUSE in startup_text
    assert refused != never_held  # #706: the faults stay distinguishable
    for text in (refused, never_held, startup_text):
        assert "<USER_ID>" in text
        assert "MCP server" in text
        for banned in ("venya list", "venya run"):
            assert banned not in text


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
