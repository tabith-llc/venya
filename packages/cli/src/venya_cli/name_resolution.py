# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""One classifier for the two transport faults an operator must tell apart (#633).

A dial that never left the workstation (the name did not resolve) and a dial that
reached the network and got no answer (refused, timeout, handshake) are different
problems with different repairs, but every CLI dial site rendered both as a
connection/fetch sentence. This module holds the separation in ONE place so the
call sites do each grow a wording branch of their own.

Classification is by CAUSE CLASS, not by message text: httpx2 wraps the resolver
failure as ``ConnectError`` whose cause chain ends in ``socket.gaierror``. The
rendered text differs per platform (Windows renders its own resolver errno, POSIX
renders another) and no errno number is inspected, so neither a wording change nor
a platform split moves this check. It is the same
cause-chain shape as ``fido2_client.Fido2Auth._tls_absent_hint`` (#439) and the
server-side pairing at ``routes/executors.py`` (``Executor hostname does not
resolve``).

The remedy names the hosts file and the name service without printing an OS
specific path: the workstation CLI runs on Linux, macOS and Windows, and the
hosts file lives in a different place on each.
"""

import socket
from typing import Any

# Exception chains are short in practice; the bound is a guard against a cyclic
# __context__ chain, not a tuning knob. shortcut: 12 links, raise it if a real
# transport error is ever reported with a deeper chain.
_MAX_CAUSE_DEPTH = 12


def find_name_resolution_cause(exc: BaseException | None) -> socket.gaierror | None:
    """The socket.gaierror in this exception's cause chain, or None.

    Walks ``__cause__`` (explicit ``raise ... from ...``) then ``__context__``
    (implicit chaining), the way ``_tls_absent_hint`` walks for an SSL class.
    Returns the FIRST gaierror seen; a chain that carries one means the resolver
    answered "no such name" and no packet was ever put on the wire.
    """
    seen: set[int] = set()
    cause: BaseException | None = exc
    depth = 0
    while cause is not None and depth < _MAX_CAUSE_DEPTH and id(cause) not in seen:
        if isinstance(cause, socket.gaierror):
            return cause
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
        depth += 1
    return None


def host_from_url(value: str | None) -> str | None:
    """The host part of a server URL, or None when there is nothing to name.

    Tolerates a bare hostname (``venya-core-1``), a scheme-prefixed URL, and a
    trailing port, because the CLI accepts all three shapes for server_url.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    rest = value.strip().split("://", 1)[1] if "://" in value else value.strip()
    rest = rest.split("/", 1)[0].split("?", 1)[0]
    if not rest:
        return None
    # Strip a port, but leave an IPv6 address (with its own colons) intact.
    if "]" in rest:
        rest = rest.split("]", 1)[0].lstrip("[")
        return rest or None
    if ":" in rest:
        head, _, tail = rest.rpartition(":")
        if head and tail.isdigit():
            return head
        return rest
    return rest or None


def _request_host(exc: BaseException) -> str | None:
    """Host from the wrapped httpx request, when the caller passed no URL.

    httpx2's ``.request`` property raises RuntimeError when it was never set, so
    the read is guarded rather than trusted — a bare ``ConnectError("...")`` built
    by a caller (or a test) has no request on it at all.
    """
    try:
        request: Any = getattr(exc, "request", None)
        url = getattr(request, "url", None) if request is not None else None
        host = getattr(url, "host", None) if url is not None else None
    except (RuntimeError, AttributeError):
        return None
    return host if isinstance(host, str) and host else None


def name_resolution_text(exc: BaseException, *, url: str | None = None) -> str:
    """Operator sentence for a name that did not resolve, or "" for any other fault.

    Non-empty only when the cause chain holds a ``socket.gaierror``. It names the
    host, says the name did not resolve ON THIS WORKSTATION, and points at the
    local places that answer a name — never at fetch/connection wording, which is
    what sent operators looking at routing instead of one missing hosts line.
    """
    gai = find_name_resolution_cause(exc)
    if gai is None:
        return ""
    host = host_from_url(url) or _request_host(exc)
    if host:
        lead = f"cannot resolve {host}"
        repair = f"add a hosts entry for {host}, or point the server URL at its address, then re-run"
    else:
        lead = "cannot resolve the server name"
        repair = "add a hosts entry for the core, or point the server URL at its address, then re-run"
    return (
        f"{lead} — the name did not resolve on this workstation (neither the hosts file nor the "
        f"configured name service answered), so no request was sent; {repair}. "
        f"Underlying error: {gai}"
    )


def dial_failure_text(exc: BaseException, *, default: str, url: str | None = None) -> str:
    """The caller's own sentence, unless this is a name-resolution fault.

    Each dial site keeps the wording it already has (and its paired negatives
    keep passing unchanged); only the gaierror case is re-worded, from here.
    """
    return name_resolution_text(exc, url=url) or default
