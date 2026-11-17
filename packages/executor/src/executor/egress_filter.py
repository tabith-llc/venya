# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Egress allowlist reader for sbx sandbox network policies.

Reads /etc/venya/egress-allowlist.txt at sandbox creation time.
Returns a list of hosts (IPs, CIDRs, hostnames) to allow via sbx policy.

Fail-closed: missing or empty file -> only DNS resolver is allowed.

Four doors make a closed set observable, because a deny that reports nothing
reads to the caller as somebody else's broken network: ``describe()`` names the
path, the entry count and the resolver at start and at every create,
``proxy_egress_denial()`` reads the refusal out of the runtime's own log and
``proxy_egress_denial_notice()`` says it back to the caller, ``egress_deny_notice()``
relabels the transport-close shape as venya's own where the log did not answer,
``proxy_egress_log_outcome()`` is the three-way read behind the first of those — refused, nothing
refused, or an answer this build cannot read, named as its own outcome — and
``resolver_address_problem()`` refuses a resolver value that names no host.
"""

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from .sandbox_shape import rows_from_any_face

logger = logging.getLogger("venya.executor.egress")

DEFAULT_ALLOWLIST_PATH = Path("/etc/venya/egress-allowlist.txt")

# What a sandbox egress denial arrives as. Measured face (report 311): a denied
# `ssh` died with `kex_exchange_identification: Connection closed by remote
# host`, and the negative control — the same probe against a port the operator's
# own log shows is blocked — failed the same way, which a peer rejection cannot
# produce. The sandbox network path completes the handshake locally and closes
# it, so the words that reach the guest belong to no peer. A second close face is
# measured (leg 1295, `venya-exec-1`, product path create -> apply_network_policy
# -> execute_command): the same destination arrives as `Connection closed by
# <address> port <n>`, which carries the words `remote host` nowhere, so the
# specific entry below does not reach it and the generic close phrase is the
# fixed part the shape needs. Both close faces are matched from the same
# transport, and the control still holds: the allowed resolver reaches the
# protocol on the same path. A match below is only ever a named SHAPE: the
# notice claims the sandbox path as the closer ONLY where the policy file never
# admitted the destination it names — see `egress_deny_notice`, where the listed
# and no-destination arms stop at the shape, because review 1307 measured a
# permitted destination closing from a real peer in exactly these words.
DENY_SIGNATURES: tuple[str, ...] = (
    "kex_exchange_identification",
    "connection closed by remote host",
    "connection closed by",
    "connection reset by peer",
    "connection timed out",
    "network is unreachable",
    "could not resolve host",
    "name or service not known",
    "temporary failure in name resolution",
)

# Two-word prose can carry the close phrase without any socket: review 1307
# measured `worker: the client-side connection closed by our own idle timer`
# (rc 1, no network event) matching the generic entry. The transport face the
# entry was added for always names the port the client printed
# (`Connection closed by <address> port <n>`, measured both directions there),
# so for these entries only, a match requires the port token as well. This is
# a token test, not a wording test: the pair cell proves a prose line WITH a
# port token still matches, and the guard leaves every other entry — the kex
# form, the remote-host form, timeouts, unreachable, DNS shapes — untouched.
PORT_PROVEN_SIGNATURES: frozenset[str] = frozenset({"connection closed by"})
_PORT_SHAPE = " port "

#: Commands that put a remote host in plain sight in their own arguments. A bare
#: dotted token counts as a destination only behind one of these, because
#: `notes.txt` is host-shaped to a regex and is not a destination.
HOST_TAKING_COMMANDS: frozenset[str] = frozenset(
    {
        "ssh",
        "sshpass",
        "scp",
        "sftp",
        "rsync",
        "curl",
        "wget",
        "git",
        "nc",
        "ncat",
        "socat",
        "telnet",
        "ftp",
        "ping",
        "ping6",
        "host",
        "dig",
        "nslookup",
        "getent",
        "openssl",
        "mysql",
        "psql",
        "mongosh",
        "redis-cli",
    }
)

# At least one dot, labels in RFC1123 shape, final label alphabetic. An IP
# literal is accepted by the caller before this regex is reached.
_HOST_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$"
)


def find_deny_signature(stderr: str) -> str | None:
    """The first deny shape the output carries, or None.

    Case-insensitive: the guests write these in both cases (`Name or service not
    known` and `name or service not known` are the same failure). An entry in
    ``PORT_PROVEN_SIGNATURES`` must also find `` port `` in the line — the
    transport proof — or it is skipped and the scan continues.
    """
    if not stderr:
        return None
    lowered = stderr.lower()
    for signature in DENY_SIGNATURES:
        if signature not in lowered:
            continue
        if signature in PORT_PROVEN_SIGNATURES and _PORT_SHAPE not in lowered:
            continue
        return signature
    return None


def _plausible_host(value: str | None) -> str | None:
    """Whether one string is host-shaped: an IP literal or a dotted name.

    A single label (`localhost`, `printer`) is not returned: it needs the
    resolver's search list to mean anything, and a notice that guessed wrong is
    worse than one that says it could not name the destination.
    """
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return value
    return value if _HOST_NAME_RE.fullmatch(value) else None


def _host_candidate(token: str, *, allow_bare: bool) -> str | None:
    """The host part of one argument, or None when the token names no host.

    A token carries its own host signal when it holds a scheme, a userinfo `@`,
    or the `host:port` / `host:path` separator ssh, scp, rsync and git use; those
    are read anywhere in the command. A bare dotted or numeric token is read only
    when `allow_bare` is set. A token that starts with a path separator or a dash
    is a file or a flag, never a destination.
    """
    if not token or token.startswith(("-", "/", "./", "../", "~")):
        return None
    if "://" in token:
        # urlsplit gives up the userinfo and the port, so a credential typed
        # into a URL never rides into a message the caller reads.
        return _plausible_host(urlsplit(token).hostname)
    if token.startswith("["):
        end = token.find("]")
        return _plausible_host(token[1:end]) if end > 1 else None
    head = token
    explicit = False
    if "@" in head:
        head = head.rsplit("@", 1)[-1]
        explicit = True
    if ":" in head:
        head = head.split(":", 1)[0]
        explicit = True
    if not explicit:
        if not allow_bare:
            return None
        head = head.split("/", 1)[0]
    return _plausible_host(head)


def find_destination(tokens: list[str]) -> str | None:
    """The first destination a command names, or None when it names none.

    A token that carries its own host signal (a scheme, a userinfo `@`, a
    `host:port` or `host:/path` separator) is read anywhere in the command, and
    is looked for FIRST: `scp file.txt host.example:/tmp` names one destination
    and one local file, and the file must not win. A bare dotted token is read
    only behind a command that takes a remote host.

    shortcut: a best-effort read of the caller's own tokens, used by the shape notice
    below when the runtime's log did not answer. The runtime DOES report its own deny with
    the destination on it — see `proxy_egress_denial`, which is the primary face — so this
    reading is only the fallback. Upgrade when the shape notice itself retires.
    """
    for token in tokens:
        host = _host_candidate(token, allow_bare=False)
        if host:
            return host
    if any(token.split("/")[-1].split("@")[-1] in HOST_TAKING_COMMANDS for token in tokens):
        # A remote host sits after the local files and the flags in an
        # ssh/scp/curl invocation, so the bare reading runs from the end.
        for token in reversed(tokens):
            host = _host_candidate(token, allow_bare=True)
            if host:
                return host
    return None


def resolver_address_problem(value: str) -> str | None:
    """Why this resolver value cannot be a host address, or None when it can.

    The seam (report 311): the sandbox runtime writes its own resolver file
    naming the bridge NETWORK address rather than a host, an operator copies that
    number into `dns_resolver`, and
    the egress rule then permits an address no resolver answers on. Venya does
    not guess the network and does not accept a number that names no host.
    A value that carries its prefix is judged against that prefix; a bare IPv4 is
    judged against the /24 that contains it, which is the shape the copied
    network address arrives in.
    """
    text = value.strip()
    if not text:
        return "is empty"
    host_text, slash, _ = text.partition("/")
    try:
        address = ipaddress.ip_address(host_text)
    except ValueError:
        return (
            "is not an IP address — a name needs the very resolution this value exists to "
            "permit (the executor installer refuses a hostname here too)"
        )
    if address.is_unspecified:
        return "is the unspecified address, which names no host"
    if address.is_multicast:
        return "is a multicast group, where no resolver answers"
    if slash:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return "carries a prefix length that does not parse"
        if address == network.network_address:
            return f"is the network address of {network}, not a host inside it"
        if address == network.broadcast_address:
            return f"is the broadcast address of {network}, not a host inside it"
        return None
    if address.version == 4 and address.packed[-1] in (0, 0xFF):
        containing = ipaddress.ip_network(f"{host_text}/24", strict=False)
        kind = "network" if address == containing.network_address else "broadcast"
        return (
            f"is the {kind} address of {containing}, not a host inside it — name the resolver "
            f"itself, or write the value with its prefix if your site is larger than a /24 "
            f"(a bare IPv6 value is not boundary-checked here)"
        )
    return None


class EgressFilter:
    """Reads egress allowlist and returns hosts to allow in sbx sandbox.

    The allowlist is a static file read once at sandbox creation.
    No hot-reload, no per-command updates.

    Format: one entry per line. Entries can be:
      - IP addresses: 198.51.100.7
      - CIDRs: 203.0.113.0/24
      - Hostnames: web-server-3
    Lines starting with # are comments. Blank lines are ignored.
    """

    def __init__(
        self,
        allowlist_path: Path | None = None,
        *,
        dns_resolver: str,
    ):
        self.allowlist_path = allowlist_path or DEFAULT_ALLOWLIST_PATH
        self.dns_resolver = dns_resolver

    def _entries(self) -> list[str]:
        """The parsed allowlist entries, read silently.

        No warnings here: a summary line that re-reads the file must not
        duplicate the two refusals in ``read_allowlist``.
        """
        if not self.allowlist_path.exists():
            return []
        entries = []
        for line in self.allowlist_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            entries.append(stripped)
        return entries

    def read_allowlist(self) -> list[str]:
        """Parse the allowlist file. Returns list of hosts to allow.

        Missing or empty file -> returns empty list (fail-closed).
        DNS resolver is always added by get_allowed_hosts(), not here.
        """
        if not self.allowlist_path.exists():
            logger.warning(
                "Egress allowlist not found at %s -- fail-closed (only DNS allowed)",
                self.allowlist_path,
            )
            return []

        entries = self._entries()

        if not entries:
            logger.warning(
                "Egress allowlist is empty at %s -- fail-closed (only DNS allowed)",
                self.allowlist_path,
            )

        return entries

    def describe(self) -> str:
        """One line naming the live egress inputs: path, exists, entry count, resolver.

        Names and counts only, never file contents. This exists for the third
        fail-closed arm — the file is present and carries entries, and the host
        you asked for is not one of them — which warns nothing today, so an
        operator reading the journal could not tell it apart from a network
        problem. Read alongside ``egress_deny_notice``, which is the same case
        told to the caller rather than to the journal.
        """
        exists = self.allowlist_path.exists()
        try:
            count = len(self._entries())
        except OSError as exc:
            # An unreadable allowlist is its own finding, and a startup line that
            # exists to be read at startup must not die over it: name the failure
            # in the line instead of raising past the boot guards above it.
            return (
                f"allowlist={self.allowlist_path} exists={exists} "
                f"entries=unreadable({exc.__class__.__name__}) dns_resolver={self.dns_resolver}"
            )
        return f"allowlist={self.allowlist_path} exists={exists} " f"entries={count} dns_resolver={self.dns_resolver}"

    def get_allowed_hosts(self) -> list[str]:
        """Return all hosts to allow in the sandbox, including DNS resolver.

        DNS resolver is always included -- without it, hostname-based
        allowlist entries cannot resolve inside the sandbox.
        """
        hosts = self.read_allowlist()
        if self.dns_resolver not in hosts:
            hosts.append(self.dns_resolver)
        return hosts


def _entry_names(entry: str, destination: str) -> bool:
    """Whether one allowlist entry covers this destination.

    An entry matches by the text it carries, and a CIDR entry also matches an
    address that falls inside it. A hostname entry is never treated as proof
    about an IP destination: this answers "does the file name this?", not "can
    the proxy reach this?".
    """
    if entry == destination:
        return True
    if "/" not in entry:
        return False
    try:
        return ipaddress.ip_address(destination) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def _allowlist_state(egress: EgressFilter, entries: list[str]) -> str:
    """Which fail-closed arm this sandbox is in, in the caller's words.

    Three arms, three distinct sentences, because they need three different
    repairs: create the file, add a host to it, or look somewhere else.
    """
    if not egress.allowlist_path.exists():
        return f"There is no egress allowlist file at {egress.allowlist_path}."
    if not entries:
        return f"The egress allowlist at {egress.allowlist_path} is empty."
    count = len(entries)
    return (
        f"The egress allowlist at {egress.allowlist_path} carries {count} " f"{'entry' if count == 1 else 'entries'}."
    )


def egress_deny_notice(
    stderr: str,
    *,
    returncode: int,
    command: str,
    egress: EgressFilter,
    argv: list[str] | None = None,
) -> str | None:
    """A line naming the denial as venya's egress policy, or None.

    The caller-visible half of the fail-closed default: the text carries the
    destination the command asked for, which fail-closed arm the policy file is
    in, and whether that file names the destination. The causal sentence — the
    sandbox path closed this, not the peer — is claimed ONLY where the policy
    can support it: a destination the file never admitted, because no other
    path carried those bytes. Where the file DOES name the destination, and
    where none could be read, the line stops at the shape, the names, the
    counts and the path: a permitted destination can close exactly this way
    from a real peer (measured, review 1307), and an in-sandbox refusal arrives
    in close wording, so naming a closer there would guess. It claims nothing
    beyond that — never a value, never file contents.
    """
    if returncode == 0:
        return None
    signature = find_deny_signature(stderr)
    if signature is None:
        return None
    destination = find_destination(list(argv) if argv else command.split())
    entries = egress._entries()
    if destination is None:
        target = (
            "No destination could be read from this command, so this line names the policy "
            "file instead of blaming one host."
        )
        closer = (
            " This line names the shape the output carries and the state of the policy file; "
            "it does not say which side closed the connection."
        )
    elif any(_entry_names(entry, destination) for entry in entries):
        target = (
            f"The destination this command names, {destination}, is carried by that file, so this "
            f"is not a missing-entry denial."
        )
        closer = (
            " A path the file admitted can close from the peer's side exactly as it closes from "
            "the sandbox path, and an in-sandbox refusal arrives in close wording, so this line "
            "does not say which side closed the connection."
        )
    else:
        target = (
            f"{destination}, the destination this command names, is not listed by it, so the "
            f"sandbox was never given a path to it."
        )
        closer = (
            " The text above is the sandbox network path closing the connection, not a message "
            "from the peer, so it is not evidence that the destination refused you."
        )
    return (
        f"venya: exit {returncode} with the shape of a sandbox egress denial (matched: {signature}). "
        f"{_allowlist_state(egress, entries)} {target} The file is read once, when the sandbox is "
        f"created, and the only resolver address the policy allows is {egress.dns_resolver}."
        f"{closer}"
    )


# --- the runtime's own refusal record -------------------------------------------------
# A refused egress is not a failed connection. The sandbox proxy completes the handshake,
# answers the request with its own HTTP 403 and closes, so `find_deny_signature` above
# never fires: the number the caller reads is its OWN client judging a response it did
# receive — plain `curl` answers 0 and `curl --fail` answers 22 over one and the same
# refusal. The denial itself is recorded by the runtime, in `sbx policy log`, keyed to the
# sandbox name (which carries the venya session id) and it survives the sandbox. Read this
# record and say it back: that is what makes a denied run distinguishable in both channels.
#
# Measured faces, both captured from the tool and kept as fixtures under
# `packages/executor/tests/fixtures/` (leg 1440), on an executor test guest:
#
# v0.46.0 (``sbx version: v0.46.0 991967dc…``, first read by leg 1424) — the verb is
# `sbx policy log [SANDBOX] --json` and its answer is
#   {"allowed_hosts": [...],
#    "blocked_hosts": [{"host": "example.com:80", "vm_name": "<sandbox>",
#      "proxy_type": "forward", "rule": "no applicable policies for op(...)",
#      "last_seen": "<RFC3339 UTC>", "since": "<RFC3339 UTC>", "count_since": 1,
#      "reason": "No matching allow rule (default deny)}"}
#
# v0.50.1 (``sbx version v0.50.1 ddb0268d…``, the estate face leg 1435 met, captured here on a
# test guest by leg 1440) — same verb, same rows, different names:
#   {"allowed": [],
#    "blocked": [{"sandbox_id": "<sandbox>", "host": "example.com:443",
#      "proxy_type": "forward", "rule": "...", "reason": "No matching allow rule (default deny)",
#      "count": 1, "first_seen": "<RFC3339 UTC>", "last_seen": "<RFC3339 UTC>"}]}
#
# The rows are read by field name from either envelope through `sandbox_shape.rows_from_any_face`
# — one seam, no second shape table — because the installer sets a vendor version FLOOR and no
# ceiling, so both faces are admissible on a customer machine and an unseen release is still
# unseen. Nothing here branches on a version number. The seam returns the name that carries ROWS, so
# a vestigial empty key left behind by a rename cannot hide the list, and `null_is_shape` is set here
# and nowhere else: a refusal list that arrives as `null` is a record this build cannot read, while
# the two recorders sharing `_rows` still write `null` as their own empty answer.
#
# `blocked_hosts` / `blocked` rows are HISTORY, not this run: the same host keeps its earlier row after
# an allow rule is added, so a reader that ignored `last_seen` would mark a later, genuinely
# delivered run as denied. That window is what `started_at` below is for.


class ProxyEgressDenial(NamedTuple):
    """One refused destination, as the runtime recorded it."""

    host: str
    reason: str
    hits: int


#: The three things one `sbx policy log` answer can honestly say.
#: `denied` and `clear` are claims about THIS run; `unrecognised` is a claim about the
#: instrument, and it is never either of the other two.
EGRESS_LOG_DENIED = "denied"
EGRESS_LOG_CLEAR = "clear"
EGRESS_LOG_UNRECOGNISED = "unrecognised"

#: The names the runtime has been measured using for one refusal list, and for the row that
#: says which sandbox it belongs to. Read from the captures in `tests/fixtures/`, not from a
#: version table: a version test would be a guess about a release nobody has met.
POLICY_LOG_LIST_KEYS: tuple[str, ...] = ("blocked_hosts", "blocked")
POLICY_LOG_SANDBOX_KEYS: tuple[str, ...] = ("vm_name", "sandbox_id")
POLICY_LOG_COUNT_KEYS: tuple[str, ...] = ("count_since", "count")


class ProxyEgressLogOutcome(NamedTuple):
    """What one policy-log read says, with the reason kept beside it.

    `denial` is set only for `denied`. `detail` is a short, value-free description of what the
    answer looked like, and it is what the operator-facing sentence names when the shape is not
    one this build can read.
    """

    shape: str
    denial: ProxyEgressDenial | None = None
    detail: str = ""

    @property
    def unrecognised(self) -> bool:
        """The answer arrived, and this build could not read it — the one outcome that must never
        be reported as a clean run."""
        return self.shape == EGRESS_LOG_UNRECOGNISED


def _row_value(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    """The first of `names` this row actually carries."""
    for name in names:
        if name in row:
            return row[name]
    return None


def _describe_answer(parsed: Any) -> str:
    """Which keys the answer did carry — names only, never values.

    An operator reading the unrecognised sentence needs to know what the runtime said, not what
    it refused, and a row value can carry a destination the caller should not see echoed.
    """
    if isinstance(parsed, dict):
        return "top-level keys: " + ", ".join(sorted(str(key) for key in parsed))
    if isinstance(parsed, list):
        return f"a top-level array of {len(parsed)} rows"
    return f"a {type(parsed).__name__}"


def sbx_policy_log_argv(sandbox_name: str) -> list[str]:
    """The argv that reads ONE sandbox's own policy log, in machine form."""
    return ["sbx", "policy", "log", sandbox_name, "--json"]


def _log_timestamp(value: object) -> datetime | None:
    """One log instant as an aware datetime, or None when it is not a usable one.

    A stamp that names no zone is not evidence about a run window written in UTC, so this
    returns None rather than guessing: the paired answer from `proxy_egress_denial` is then
    "nothing claimed", which is today's behavior, not a wrong claim.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def proxy_egress_log_outcome(
    log_output: str | bytes,
    *,
    sandbox_name: str,
    started_at: datetime,
) -> ProxyEgressLogOutcome:
    """Read one `sbx policy log --json` answer and say which of three things it is.

    `denied` — the runtime recorded a refusal for this sandbox inside this run's window.
    `clear` — the answer is one this build reads, and it holds no refusal for this sandbox in
    this window, including the history case: an older row for the same host is not this run.
    `unrecognised` — an answer came back and this build could not read it: no refusal list under
    either measured name, a refusal list that arrived as `null`, rows that name no sandbox, JSON
    that does not arrive whole, or an envelope that is not the one this verb prints.

    The third case is the one this function exists to separate from the second. Both used to
    answer `None`, which let a vendor release that renamed two fields report a refused run as an
    allowed one — the one claim a customer must not be handed silently. An unreadable instrument
    is still not evidence that traffic was refused, so this never promotes an `unrecognised`
    answer into a denial either; it names its own limit and the caller says it out loud.
    """
    if isinstance(log_output, bytes):
        log_output = log_output.decode("utf-8", "replace")
    try:
        parsed = json.loads(log_output)
    except (TypeError, ValueError):
        return ProxyEgressLogOutcome(EGRESS_LOG_UNRECOGNISED, None, "the answer did not arrive as one JSON value")

    rows = rows_from_any_face(parsed, *POLICY_LOG_LIST_KEYS, null_is_shape=True)
    if rows is None:
        return ProxyEgressLogOutcome(
            EGRESS_LOG_UNRECOGNISED,
            None,
            f"no refusal list under {' or '.join(repr(key) for key in POLICY_LOG_LIST_KEYS)} "
            f"({_describe_answer(parsed)})",
        )
    if not rows:
        return ProxyEgressLogOutcome(EGRESS_LOG_CLEAR, None, "an empty refusal list")

    named = [row for row in rows if _row_value(row, POLICY_LOG_SANDBOX_KEYS) is not None]
    if not named:
        return ProxyEgressLogOutcome(
            EGRESS_LOG_UNRECOGNISED,
            None,
            f"{len(rows)} rows, none naming a sandbox under "
            f"{' or '.join(repr(key) for key in POLICY_LOG_SANDBOX_KEYS)}",
        )

    mine = [row for row in named if _row_value(row, POLICY_LOG_SANDBOX_KEYS) == sandbox_name]
    if not mine:
        return ProxyEgressLogOutcome(EGRESS_LOG_CLEAR, None, f"{len(named)} rows, none for this sandbox")

    newest: tuple[datetime, ProxyEgressDenial] | None = None
    unusable = 0
    for row in mine:
        host = row.get("host")
        seen = _log_timestamp(row.get("last_seen"))
        if not isinstance(host, str) or not host or seen is None or seen < started_at:
            # A missing `last_seen` on a row that does name this sandbox is a field the runtime
            # no longer prints, not a quiet run: count it and speak if the window holds nothing
            # else, but never claim a refusal from a row with no place in time.
            if seen is None and isinstance(host, str) and host:
                unusable += 1
            continue
        raw_hits = _row_value(row, POLICY_LOG_COUNT_KEYS)
        raw_reason = row.get("reason")
        denial = ProxyEgressDenial(
            host=host,
            reason=raw_reason if isinstance(raw_reason, str) else "",
            hits=raw_hits if isinstance(raw_hits, int) and not isinstance(raw_hits, bool) else 1,
        )
        if newest is None or seen > newest[0]:
            newest = (seen, denial)
    if newest:
        return ProxyEgressLogOutcome(EGRESS_LOG_DENIED, newest[1], "this run's refusal recorded")
    if unusable:
        return ProxyEgressLogOutcome(
            EGRESS_LOG_UNRECOGNISED,
            None,
            f"{unusable} rows for this sandbox carry no usable `last_seen` timestamp",
        )
    return ProxyEgressLogOutcome(
        EGRESS_LOG_CLEAR, None, f"{len(mine)} rows for this sandbox, all before this run began"
    )


def proxy_egress_denial(
    log_output: str | bytes,
    *,
    sandbox_name: str,
    started_at: datetime,
) -> ProxyEgressDenial | None:
    """The refusal THIS run earned, or None.

    The two-value view of `proxy_egress_log_outcome`, kept because a caller that only forwards a
    denial needs exactly that. A reader that must tell "nothing was refused" apart from "this
    answer is not one I can read" calls the outcome function instead: an unreadable instrument is
    not evidence that traffic was refused, and it is no longer evidence that it was allowed.
    """
    return proxy_egress_log_outcome(log_output, sandbox_name=sandbox_name, started_at=started_at).denial


def proxy_egress_denial_notice(
    denial: ProxyEgressDenial,
    *,
    sandbox_name: str,
    daemon_user: str,
    egress: EgressFilter,
) -> str:
    """The caller-visible sentence for a refusal the runtime itself recorded.

    Carries the refused ``host:port``, the runtime's own reason, and the repair line. The
    repair line names WHO can read the record and HOW: the log belongs to the account the
    sandbox daemon signs in under, and the same verb from any other account answers nothing
    (measured both directions on an executor test guest, and filed for the estate face too). It
    claims nothing the record does not: no rule text, no guest output, no value.
    """
    reason = f" ({denial.reason})" if denial.reason else ""
    times = f" ({denial.hits} time{'s' if denial.hits != 1 else ''})" if denial.hits > 0 else ""
    return (
        f"venya: the sandbox proxy refused this run's egress to {denial.host}{reason}{times}. "
        f"That is a completed refusal, not a broken connection: the exit code above is your own "
        f"client's answer to this refusal, so it does not tell a delivered request from a denied "
        f"one. {_allowlist_state(egress, egress._entries())} The file is read once, when the "
        f"sandbox is created, and the only resolver address the policy allows is "
        f"{egress.dns_resolver}. Read the runtime's own record on the executor host as "
        f"{daemon_user!r}, the account the sandbox daemon signs in under: "
        f"`sudo -n sudo -u {daemon_user} sbx policy log {sandbox_name}` — the same command from "
        f"any other account answers nothing, which is a visibility wall and not an empty log. "
        f"Open refusals, each with its allow and dismiss verbs, are on "
        f"`sudo -n sudo -u {daemon_user} sbx policy approval ls`."
    )


def proxy_egress_unrecognised_notice(
    outcome: ProxyEgressLogOutcome,
    *,
    sandbox_name: str,
    daemon_user: str,
    tool_version: str,
) -> str:
    """The caller-visible sentence for an answer this build could not read.

    Three things and no more: which tool was asked, the version it reported, and that the refusal
    could not be confirmed. It claims neither a denial nor a clean run — the record exists, in a
    form venya has not learned — and the repair line names the account that can read it by hand,
    because a policy log belongs to whoever the sandbox daemon signs in as. `outcome.detail` carries
    key NAMES only, so nothing the runtime refused travels onward in this sentence.
    """
    return (
        f"venya: the sandbox runtime answered the egress record for this run in a shape venya cannot "
        f"read ({outcome.detail}), so whether the proxy refused this run's destination could not be "
        f"confirmed. Tool: {tool_version or 'no sbx version is recorded on this executor'}; sandbox {sandbox_name}. "
        f"This is not a report that the traffic was allowed, and it is not a refusal claim either. "
        f"Read the record by hand on the executor host as {daemon_user!r}, the account the sandbox "
        f"daemon signs in under: `sudo -n sudo -u {daemon_user} sbx policy log {sandbox_name}`. A new "
        f"vendor name for the refusal list is one entry in "
        f"`egress_filter.POLICY_LOG_LIST_KEYS` plus a capture beside it in `tests/fixtures/`."
    )
