# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#650 — the PostgreSQL test door's pre-flight: read it loud, or read it not at all.

WHY THIS EXISTS. The opt-in PostgreSQL door is ``VENYA_TEST_PG_URL``. When a leg sets it, it is
asking for the door's cells to RUN; when a leg does not, the cells skip and that skip is the honest
"not run". Between those two states there is a third one that nothing in the tree used to name: the
door was ASKED FOR and the host cannot give it. On 2026-10-16 the shared tmpfs ``/tmp`` reached zero
bytes and the scratch fixture sitting on it self-shut on ``ENOSPC`` — and the suites answered with
``psycopg2.OperationalError: … Is the server running on that host and accepting TCP/IP
connections?``. That is a RED PRODUCT CELL. Two lanes filed door-ON reds that were host state, and
the five hours between first ENOSPC (01:35:27) and the self-shut surfacing (06:37:14) ended only
because some other lane's own write failed. **A dependency that load-bearing was discovered by
tripping over it** (#650 §Problem 2).

WHAT THIS MODULE DOES. ``read_door()`` inspects the door the way a lane should have to see it —
requested or not, reachable or not, and with how much writable space left on the filesystem that
holds it — and ``abort_message()`` renders ONE line that states the cause, the number, the
consequence and the fix. It distinguishes the two states #650 AC3 demands be told apart:

* **never started** — the socket directory does not exist at all; nobody ran the fixture.
* **died mid-run** — the socket file is there and nothing answers it; that is what an
  ``ENOSPC`` self-shut looks like from outside, and it is NOT a missing fixture.
* **refused** — a TCP door with no listener behind it (Door A's host service down, say).
* **space low** — the door's own filesystem is below the floor, reachable or not. This is the
  half that would have caught the 2026-10-16 window while it was still only a *disk*: a
  reachable door on a nearly-full tmpfs is a door about to lie.

WHAT IT DOES NOT DO. It never edits the door, never starts a fixture, and never moves one: #650 AC5
is explicit that repair legs propose and do not relocate, and the host is not a test artifact's
home. It also never prints a credential — the door URL can carry a password (Door A does), so
``redact_url()`` strips it before anything reaches a message, a report or a terminal.

WHO CALLS IT. Each package's ``tests/conftest.py`` calls ``pytest_runtest_setup`` with a collected
item; if the door was requested and is unusable, every PG-gated cell FAILS LOUD with this message
instead of skipping clean or dying as a psycopg error, and every non-gated cell keeps answering.
The shared implementation lives HERE, in ``scripts/``, one copy for both packages — the same
posture ``scripts/detect_secrets_baseline_guard.py`` set for the #546 baseline guard, which core's
interlock also loads by path. Two conftests, one rulebook.
"""

from __future__ import annotations

import logging
import os
import socket
import tempfile
from dataclasses import dataclass

logger = logging.getLogger("venya.tooling")

#: The opt-in door. The literal lives here so a cell can assert the gate signature rather than
#: retyping it — see ``detects_gate``.
DOOR_ENV = "VENYA_TEST_PG_URL"

#: The substring that marks a cell as gated on the door. Every gated class in the tree names the
#: env var in its ``skipif`` reason (that is the house form, and #650's cells pin it), so the
#: string — not a marker registration — is what identifies a door cell.
GATE_SIGNATURE = DOOR_ENV

#: Floor for the door's own filesystem, in bytes. 64 MiB is a GUARD BAND, not a measured minimum:
#: the observed failure was 0 available, and a scratch cluster writes WAL and temp files well above
#: this. Stated as what it is. shortcut: the floor is a guard band, not a PostgreSQL requirement;
#: upgrade when a door-ON leg measures the fixture's actual high-water write.
MIN_FREE_BYTES = 64 * 1024 * 1024

#: How long to wait for a socket that may not exist. Kept short because a pre-flight that can hang
#: is worse than one that can't speak: this runs before every test in the package.
PROBE_TIMEOUT_SECONDS = 1.0

# --- the causes, named once, in one closed set ---------------------------------------------------

CAUSE_NEVER_STARTED = "never started"
CAUSE_DIED_MID_RUN = "died mid-run (stale socket file, no listener)"
CAUSE_REFUSED = "refused (no listener on that address)"
CAUSE_SPACE_LOW = "space low"
CAUSE_NO_URL_SHAPE = "not a readable PostgreSQL URL"
CAUSE_REACHABLE = None  # the good state is the ABSENCE of a cause


@dataclass(frozen=True)
class DoorState:
    """What the door looks like from this host, right now.

    ``filesystem`` and ``free_bytes`` always describe the volume the door lives on (or the temp dir
    for a TCP door), because #650's lesson is that the disk is part of the door.
    """

    requested: bool
    kind: str  # "unix" | "tcp" | "unknown"
    target: str  # redacted — never carries a password
    reachable: bool
    filesystem: str
    free_bytes: int
    cause: str | None

    @property
    def unusable(self) -> bool:
        """True when a leg asked for the door and this host cannot answer it."""
        return self.requested and self.cause is not None

    @property
    def free_mib(self) -> float:
        return round(self.free_bytes / (1024 * 1024), 1)


def redact_url(url: str) -> str:
    """The door URL without any credential in it.

    Masker law applies to a message nobody prints on purpose: Door A is
    ``…://venya_test:<value>@127.0.0.1:5432/…``, and this string goes into a failure line that a
    lane will paste into a report. Username is a host account and stays; the password never does.
    """
    if "://" not in url:
        return "<unreadable url>"
    scheme, _, rest = url.partition("://")
    userinfo, _, hostpart = rest.rpartition("@") if "@" in rest else ("", "", rest)
    if not userinfo:
        return url
    user, _, _passwd = userinfo.partition(":")
    return f"{scheme}://{user}@{hostpart}"


def _is_postgres_scheme(url: str) -> bool:
    """The scheme gate, separate because it must run BEFORE anything is probed.

    Measured on this box: ``make_url("mysql://agent@localhost/db")`` parses happily, the fallback then
    reads host ``localhost`` with no port, the probe defaults to 5432 — and the HOST cluster listens
    on 127.0.0.1:5432, so a scheme-blind pre-flight calls a driver this product does not use a
    HEALTHY door. An unusable door URL must be a named cause, never a green.
    """
    return "://" in url and url.split("://", 1)[0].lower().startswith("postgres")


def _parse_plain(url: str) -> dict:
    """The no-SQLAlchemy path, as its own function so it can be tested rather than hoped for.

    This exists because a pre-flight that dies with the door is worse than the silence it replaces, so
    it must keep working in an environment where the import fails. It is also where a real bug hid:
    the first cut read the host out of the netloc and never looked for a port in the query, which made
    it ask for ``.s.PGSQL.5432`` on a unix door and report ``never started`` about a fixture that had
    died mid-run. The port-in-query shape is the common one (``?host=/sock&port=N``), so it is now read
    first, and two cells drive this function directly instead of relying on sqlalchemy being absent.
    """
    rest = url.partition("://")[2]
    _userinfo, sep, tail = rest.rpartition("@")
    if not sep:
        tail = rest
    authority_and_path, has_query, query = tail.partition("?")
    authority, _slash, path = authority_and_path.partition("/")
    params = dict(part.split("=", 1) for part in query.split("&") if "=" in part) if has_query else {}
    socket_dir = params.get("host") if params.get("host", "").startswith("/") else None
    host_part, colon, port_text = authority.rpartition(":")
    host = host_part if colon else authority
    raw_port = params.get("port") or (port_text if colon else None)
    if socket_dir:
        # A unix door puts the database in the path position ("/db"), not a host: reading it as a
        # host is how the first cut tried to TCP-probe an address called "/nodb".
        host, dbname = None, path or None
    else:
        dbname = path or params.get("dbname")
    return {
        "host": host or None,
        "port": int(raw_port) if raw_port is not None and str(raw_port).isdigit() else None,
        "socket_dir": socket_dir,
        "database": dbname,
    }


def _parse(url: str) -> dict:
    """Split the door URL into the parts a probe needs — SQLAlchemy when it answers, plain text when not.

    A local import is deliberate: this file is loaded by a conftest before collection, and a heavy
    import there is a cost on every run of the package. When SQLAlchemy is missing or refuses the
    string, ``_parse_plain`` answers — and it is a tested path, not a hopeful one.
    """
    try:
        from sqlalchemy.engine import make_url

        parsed = make_url(url)
        query = dict(parsed.query or {})
        query_port = query.get("port")
        return {
            "host": parsed.host,
            # A unix-socket URL carries its port in the QUERY, not the netloc: sqlalchemy answers
            # ``parsed.port`` as None for ``…@/db?host=/sock&port=55442``, and a pre-flight that then
            # defaults to 5432 looks for the wrong socket file and reports "never started" about a
            # fixture that died mid-run. Measured on exactly that shape.
            "port": parsed.port or (int(query_port) if query_port is not None and str(query_port).isdigit() else None),
            "socket_dir": query.get("host") or query.get("hostaddr") or None,
            "database": parsed.database,
        }
    except Exception as parse_fault:
        # A URL SQLAlchemy will not parse is not an error at this layer: the plain-text path below
        # still reads the shapes the door actually uses, and a pre-flight that raises is its own
        # outage. Recorded rather than swallowed — a bare `except: pass` is the shape of a silenced
        # alarm, which is the thing this whole row is about.
        logger.debug("sqlalchemy could not parse the door URL (%r); using the text path", parse_fault)
        return _parse_plain(url)


def _socket_path(socket_dir: str, port: int) -> str:
    """PostgreSQL's own unix-socket filename: ``.s.PGSQL.<port>`` in the socket directory."""
    return os.path.join(socket_dir, f".s.PGSQL.{port}")


def _connect_unix(path: str) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(PROBE_TIMEOUT_SECONDS)
            sock.connect(path)
        return True
    except OSError:
        return False


def _connect_tcp(host: str, port: int) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=PROBE_TIMEOUT_SECONDS)
    except OSError:
        return False
    connection.close()
    return True


def _free_bytes(path: str) -> tuple[str, int]:
    """The volume holding ``path``, and its bytes available — walking UP to something that exists.

    The 2026-10-16 shape is exactly this: the socket directory is gone (cluster stopped, or the path
    was never created), and a pre-flight that only reports "cannot find the socket dir" hides the
    fact that the reason is a full tmpfs. So the parent is asked instead.
    """
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    if not probe:
        probe = tempfile.gettempdir()
    try:
        usage = os.statvfs(probe)
        available = usage.f_bavail * usage.f_frsize
        return probe, int(available)
    except OSError:
        return probe, -1


def read_door(url: str | None = None) -> DoorState:
    """Inspect the door. Never raises: an unparseable URL is a named cause, not a traceback.

    ``url=None`` reads ``os.environ``, which is what the conftest wants; cells pass the string
    directly so they can drive every branch without touching the process environment.
    """
    raw = DOOR_ENV if url is None else url
    if url is None:
        raw = os.environ.get(DOOR_ENV)
    if not raw:
        tmp = tempfile.gettempdir()
        probe, free = _free_bytes(tmp)
        return DoorState(
            requested=False,
            kind="none",
            target="<unset>",
            reachable=False,
            filesystem=probe,
            free_bytes=free,
            cause=None,
        )

    parts = _parse(raw)
    target = redact_url(raw)
    if not _is_postgres_scheme(raw):
        probe, free = _free_bytes(tempfile.gettempdir())
        return DoorState(True, "unknown", target, False, probe, free, CAUSE_NO_URL_SHAPE)
    port = parts["port"] or 5432
    socket_dir = parts["socket_dir"]

    if socket_dir:
        path = _socket_path(socket_dir, port)
        probe_root = socket_dir
        reachable = os.path.exists(path) and _connect_unix(path)
        kind = "unix"
    elif parts["host"]:
        path = f"{parts['host']}:{port}"
        probe_root = tempfile.gettempdir()
        reachable = _connect_tcp(parts["host"], port)
        kind = "tcp"
    else:
        probe, free = _free_bytes(tempfile.gettempdir())
        return DoorState(True, "unknown", target, False, probe, free, CAUSE_NO_URL_SHAPE)

    probe, free = _free_bytes(probe_root)

    if free >= 0 and free < MIN_FREE_BYTES:
        # Space first, always: the disk is the cause that hides behind every other symptom here.
        return DoorState(True, kind, target, reachable, probe, free, CAUSE_SPACE_LOW)
    if reachable:
        return DoorState(True, kind, target, True, probe, free, CAUSE_REACHABLE)
    if kind == "unix":
        cause = CAUSE_DIED_MID_RUN if os.path.exists(path) else CAUSE_NEVER_STARTED
    else:
        cause = CAUSE_REFUSED
    return DoorState(True, kind, target, False, probe, free, cause)


def detects_gate(text: str) -> bool:
    """True when a cell's skip reason says it is gated on the door.

    The gate is found by the env var's name in the reason, which is the house form every one of the
    gated classes uses — so a cell that invents its own wording is NOT silently un-aborted: #650's
    own cells enumerate the gated files and assert each names the var.
    """
    return isinstance(text, str) and GATE_SIGNATURE in text


def abort_message(state: DoorState) -> str:
    """The one line a failed gated cell must print: cause, number, consequence, fix."""
    space = f"{state.free_mib} MiB free on {state.filesystem}"
    if state.cause == CAUSE_SPACE_LOW:
        because = (
            f"the door's own filesystem is below the {MIN_FREE_BYTES // (1024 * 1024)} MiB floor "
            f"({space}); a scratch cluster on a full tmpfs self-shuts on ENOSPC and its cells then "
            "read as product reds — that is the #650 window, caught before the door died"
        )
    elif state.cause == CAUSE_NEVER_STARTED:
        because = (
            f"no socket directory at the address the door names ({state.target}) — the fixture was "
            f"never started in this boot ({space})"
        )
    elif state.cause == CAUSE_DIED_MID_RUN:
        because = (
            f"a socket file exists at {state.target} and nothing answers it — the fixture was "
            f"running and has STOPPED. Read its own log for the reason it gave; the volume under it "
            f"reports {space}, so a full disk is a candidate only if that number says so — and file "
            "nothing against the tree until the log has been read"
        )
    elif state.cause == CAUSE_REFUSED:
        because = (
            f"nothing listens at {state.target} — the door was requested against an address that "
            f"is not serving ({space})"
        )
    elif state.cause == CAUSE_NO_URL_SHAPE:
        because = f"{DOOR_ENV} is set but is not a readable PostgreSQL URL ({target_redacted(state)})"
    else:
        return ""
    return (
        f"PG DOOR ABORTED BY PRE-FLIGHT, not skipped and not a product failure: {because}. "
        f"Every PostgreSQL-gated cell in this run is aborted with this line (it arrives as a setup "
        f"error, which is the loud half; non-gated cells are unaffected and keep answering). "
        f"Fix: start the fixture (lead recipe: wave28-specs-20261015/wren-pg-fixture-s125.md, Door A "
        f"host cluster or Door B private cluster in /tmp), or UNSET {DOOR_ENV} to run door-OFF and "
        f"let the cells skip honestly. Do not file a defect off a red that says this."
    )


def target_redacted(state: DoorState) -> str:
    """The target as it may be printed. Kept separate so a test can assert no credential escapes."""
    return state.target


def describe_for_report(state: DoorState) -> str:
    """The header line: what the pre-flight found, in the report's own evidence voice."""
    if not state.requested:
        return f"{DOOR_ENV} unset — door OFF; PostgreSQL-gated cells skip (that is 'not run', not green)"
    if state.cause is None:
        return f"{DOOR_ENV} set and answered at {state.target}; {state.free_mib} MiB free on {state.filesystem}"
    return f"{DOOR_ENV} set and UNUSABLE: {abort_message(state)}"


#: One process-wide read of the door. The pre-flight asks the host once per run, not once per cell:
#: a 1 s socket probe before every test in a package would be its own kind of outage.
_state_cache: DoorState | None = None


def door_state(*, refresh: bool = False) -> DoorState:
    global _state_cache
    if _state_cache is None or refresh:
        _state_cache = read_door()
    return _state_cache


def reset_door_state_cache() -> None:
    """Test seam: drop the cached read. Never called by product code."""
    global _state_cache
    _state_cache = None


def gate_reasons(item) -> list[str]:
    """Every ``skipif`` reason a collected item carries, from its own markers and its class.

    The gated classes decorate with ``@pytest.mark.skipif(cond, reason=...)``, and the reason is
    positional in some files and keyword in others — both shapes are read, because a pre-flight that
    only understands one spelling silently aborts nothing.
    """
    out: list[str] = []
    try:
        markers = list(item.iter_markers(name="skipif"))
    except Exception:
        return out
    for marker in markers:
        candidate = marker.kwargs.get("reason") if isinstance(marker.kwargs, dict) else None
        if candidate is None and len(marker.args) > 1:
            candidate = marker.args[1]
        if candidate is not None:
            out.append(str(candidate))
    return out


def abort_unusable_door(item) -> None:
    """The hook body both packages call: fail the gated cell LOUD, or leave it alone.

    Called from ``pytest_runtest_setup``. Does nothing when the door was not requested, when it is
    answering, or when the cell is not one of the door's — so a healthy host behaves exactly as it
    does today, which is #650's paired negative.
    """
    import pytest

    state = door_state()
    if not state.unusable:
        return
    if not any(detects_gate(reason) for reason in gate_reasons(item)):
        return
    pytest.fail(abort_message(state), pytrace=False)


def door_report_header(config) -> str:
    """The pre-flight's own words, printed once in the run header so the report carries the check.

    #650 AC1: the pre-flight is stated WHERE IT BINDS, with its output in the report. A header line
    is that, per package, without a lane having to remember to run anything.
    """
    return f"pg-door-pre-flight: {describe_for_report(door_state())}"
