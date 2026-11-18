# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Venya API client — handles auth, token refresh, and tool calls.

Uses httpx2 (the monorepo-standard httpx fork) for async HTTP.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import warnings
from pathlib import Path

import httpx2

from .config import RENEW_CLAUSE, MCPConfig

logger = logging.getLogger("venya.mcp")


class VenyaAPIError(Exception):
    """Raised when the Venya API returns an error response.

    ``status_code`` is the status the core actually answered, or ``None`` when it answered
    nothing at all — a timeout, a refused connection. ``None`` is rendered as "no response"
    and never as a number: this client must not report a status it did not observe (#707).
    """

    def __init__(self, status_code: int | None, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        seen = f"{status_code}" if status_code is not None else "with no response"
        super().__init__(f"Venya API error {seen}: {detail}")


class SessionExpiredError(Exception):
    """Raised when no usable session could be presented — the human must re-authenticate.

    Which of the causes this carries is told by the message, never by the class: a session
    the core refused, and a session this process never held, are different faults and the
    operator reads different words for each (#706). An unreachable core is not carried here
    at all — that is a ``VenyaAPIError`` (#707).
    """


def _bootstrap_tls_verify() -> bool | str:
    """Determine TLS verify setting at startup.

    Returns:
        True if VENYA_CA_CERT is set (use that path),
        False if VENYA_TLS_VERIFY=false (with warning),
        raises if CA cert is required but missing.
    """
    ca_cert = _resolve_ca_cert()
    tls_verify = os.environ.get("VENYA_TLS_VERIFY", "").lower()

    if ca_cert is not None:
        return ca_cert

    if tls_verify == "false":
        msg = (
            "TLS verification is disabled (VENYA_TLS_VERIFY=false). "
            "This is an alpha debug mode — never use in production. "
            "Set VENYA_CA_CERT to the Venya CA bundle path instead."
        )
        warnings.warn(msg, stacklevel=2)
        logger.warning(msg)
        return False

    msg = (
        "Venya CA certificate not found. "
        "Set the VENYA_CA_CERT environment variable to the path of the "
        "Venya CA bundle (e.g. /etc/venya/ca/ca-bundle.crt). "
        "TLS verification cannot be silently disabled."
    )
    raise RuntimeError(msg)


def _resolve_ca_cert() -> str | None:
    """Return VENYA_CA_CERT path if set, else None."""
    ca_cert = os.environ.get("VENYA_CA_CERT")
    if ca_cert is not None:
        path = Path(ca_cert)
        if not path.is_file():
            raise RuntimeError(f"VENYA_CA_CERT points to a file that does not exist: {ca_cert}")
        return str(path)
    return None


#: The anchored-only posture in the shipped words of ``_bootstrap_tls_verify`` below (#571). The
#: repair sentence and the posture sentence are quoted VERBATIM from that function so the
#: constructor seam and the startup resolver read the same; ``_bootstrap_tls_verify`` itself is
#: left exactly as it ships (#540's ruled False-escape path is hands-off), which is why this is a
#: quoted constant rather than a shared helper.
ANCHORED_ONLY_REFUSAL = (
    "Set the VENYA_CA_CERT environment variable to the path of the "
    "Venya CA bundle (e.g. /etc/venya/ca/ca-bundle.crt). "
    "TLS verification cannot be silently disabled."
)


#: R9 (owner ruling 2026-10-10, booked in decisions.md at 135337e): the refusal names NO
#: mechanism. "a trust store that is not the Venya CA" is true for both refused shapes at this seam —
#: ``verify=True`` lands on the machine's own store, an omitted ``verify`` lands on the transport's
#: built-in default bundle — and a reader cannot reproduce a mechanism they were never shown, so the
#: sentence states what is wrong (wrong CA) and leaves the detail to developer prose below. One
#: sentence for both shapes BY RULING: not split per shape. The repair pointer that follows it is the
#: shipped ``ANCHORED_ONLY_REFUSAL`` text, quoted once, not restated.
UNANCHORED_REFUSAL = "names a trust store that is not the Venya CA"


def _require_anchored_verify(verify: object) -> str | bool:
    """The constructor seam's anchored-or-refuse check (#571), BEFORE any transport exists.

    Same posture the CLI bearer dial and the FIDO2 ceremony dial landed in #530/#533/#536: a
    value that is not the Venya CA bundle — or the ruled alpha debug escape, exactly ``False`` —
    is refused, never defaulted. What the refusal no longer says is *which* store a bad value
    lands on: per R9 the operator-facing sentence names no mechanism (see
    ``UNANCHORED_REFUSAL``); the mechanism detail stays here, in developer prose — ``True``
    reaches httpx2's ``truststore.SSLContext`` (``_config.py`` ``create_ssl_context``, measured
    at this venue on httpx2 2.12.0) and an omitted value reaches its built-in default bundle.

    The refusal lands before ``httpx2.AsyncClient`` is constructed, so a refused call never dials.
    """
    if verify is True or verify is None:
        raise RuntimeError(
            f"VenyaClient was built with verify={verify!r}, which {UNANCHORED_REFUSAL}. "
            f"{ANCHORED_ONLY_REFUSAL} Pass False only for the ruled alpha debug escape."
        )
    if isinstance(verify, str) and verify:
        return verify
    if verify is False:
        return False
    raise RuntimeError(
        f"VenyaClient was built with verify={verify!r}, which is neither the Venya CA bundle path "
        f"nor the alpha debug escape (False). {ANCHORED_ONLY_REFUSAL}"
    )


#: What this client says about a session token on disk that it will not take (#705, refuse-and-tell).
#: Stated as what was OBSERVED — this process did not obtain that value — and never as a claim about
#: which login wrote it, because the file names no principal and the bearer is 256 random bits.
REFUSAL_CLAUSE = (
    "the session file holds a token this process did not obtain, and it will not use a token it "
    "cannot tie to its own session"
)


def session_error_text(path: Path, *, refused: bool = False, adoption_refused: bool = False) -> str:
    """The session sentence, naming the resolved path, the fault, and the one renewing clause.

    Three states reach a refusal and they are not the same fault (#705, #706): there is no
    session file at the path; a file is there but holds no ``access_token`` (the shape that made
    a running server answer "expired" when nothing had expired — an unreadable or unparseable
    file lands here too, because nothing usable could be read from it); or a token was dialled
    and the core refused it. The first two never held a session, so they do not get the word
    "expired", do not get a restart this branch made unnecessary, and are not told the core
    refused anything — no request went out. Only the third state observed a refusal.

    A fourth fact can ride on any of them: the file was read and held a token this process would
    not take (``adoption_refused``, #705 as ruled). It changes the middle of the
    sentence and it changes the tail, because under that ruling the restart is the remedy again —
    saying "no restart is needed" beside a token the process declined to use would be a lie.

    All of them close with ``RENEW_CLAUSE``, the wording leg 1554 ruled for #776: the verb that
    renews, never one that can clear the token. Composing it from one constant instead of
    retyping it is what keeps the sites from drifting apart, which is what leg 1558's review
    found at this face, and it is why a test that needs this message calls this function rather
    than hand-building a sentence. The path is the one this process resolved, VENYA_CONFIG
    first, so an operator pointed at the wrong file can see that.
    """
    if adoption_refused:
        tail = (
            f"{RENEW_CLAUSE}, then restart or reconnect the MCP server: it dials only the session "
            "it obtained itself, so a login written after it started is read when it starts again."
        )
    else:
        tail = f"{RENEW_CLAUSE}; the MCP server reads the file again on its next call, so no restart " "is needed."
    if refused:
        core = f"the access_token read from {path} was refused by the core"
        detail = f"{core}, and {REFUSAL_CLAUSE}" if adoption_refused else core
        return f"Venya session expired and could not be renewed ({detail}). {tail}"
    if adoption_refused:
        return (
            f"No Venya session to send ({REFUSAL_CLAUSE}, at {path}). This process never held a "
            f"token, so nothing expired and the core refused no request. {tail}"
        )
    where = (
        f"there is no session file at {path}"
        if not path.exists()
        else f"the session file at {path} holds no access_token"
    )
    return (
        f"No Venya session to send ({where}). This process never held a token, so nothing "
        f"expired and the core refused no request. {tail}"
    )


# Last-fuse read timeout for the long-running execute call: server→executor
# relay 300s < nginx proxy_read_timeout 330s < 340s here, so a clean upstream
# error always reaches the agent before this client gives up. The former 30s
# client default abandoned cold-sandbox runs (~65s template pull) the server
# was still completing (ticket cli-execution-timeout-cold-start-default; the
# CLI twin exposes this default as VENYA_EXECUTION_TIMEOUT).
_EXECUTE_TIMEOUT_SECONDS = 340.0


#: #707: the one sentence for every shape in which the core gave no verdict on this session —
#: a 5xx, a timeout, a refused connection. Modelled on the CLI's transient arm, which #776 landed
#: for the same fault (``venya_cli/api_client.py``); the mcp package does not depend on venya-cli
#: (``packages/mcp/pyproject.toml``), so the words are copied deliberately, the same arrangement
#: as ``_https_refusal`` in ``config.py``. Two facts it carries: the stored session is untouched,
#: and no security key is owed — so it never appears beside the ceremony wording.
_NO_VERDICT_DETAIL = (
    "the Venya core gave no verdict on this session; the stored token was left in place "
    "and the next call refreshes automatically"
)


#: Statuses that ARE a verdict on the credential: the core reached its own refresh endpoint and
#: refused this token. Everything else the core answers is not a session judgement (#707).
_REFRESH_REFUSAL_STATUSES = (401, 403)


class VenyaClient:
    """Async HTTP client for the Venya API.

    Token lifecycle:
    1. Read access_token from config file (written by `venya login`)
    2. Stat that file per call; when its mtime has moved, read it again. A stat is not a read: the
       hot path stays one in-memory token. What that read may DO with what it found is decided by
       step 5 — the file is never a way to change a session this process already has (#705).
    3. On 401 → POST /api/v1/auth/refresh with current token → get new token
    4. Update config file in-place with new token (atomic write)
    5. A token the file holds that differs from the one in hand is REFUSED, and said out loud: the
       session file carries `server_url` and `access_token` and no principal, and the bearer is 256
       random bits, so a swap can never be shown to be the same login's. A process holding no token
       still reads one from the file it was started on — that establishes a session rather than
       replacing one — and only while the file names the core this process dials (#705)
    6. If nothing usable is in hand → SessionExpiredError, naming the resolved path and
       which of the three states it found: a never-held session says so in those words and
       is not called expired (#706), a refused token is (#705), and a token this process
       declined to adopt is named as declined (#705)

    TLS: verified against VENYA_CA_CERT at startup. No silent downgrade. The constructor takes no
    trust default (#571): ``verify`` must name the Venya CA bundle, or be exactly ``False`` for
    the ruled alpha debug escape. ``True`` — or nothing at all — is refused before a transport
    exists, in words that name no mechanism (R9): either shape ends up trusting something that is
    not the Venya CA.
    """

    #: The one refresh this client exposes to concurrent callers (#707). Declared on the class as
    #: the "nothing in flight" value rather than in ``__init__``, because the task can only be born
    #: inside a running loop; ``_refresh`` assigns it on the instance before its first ``await``,
    #: so two callers cannot both decide to POST. A server-wide client shared by every tool call
    #: (``server.py`` ``_client``) is what makes that race reachable.
    _refresh_task: asyncio.Task[bool] | None = None

    def __init__(
        self,
        config: MCPConfig,
        verify: str | bool | None = None,
    ) -> None:
        # #571: no default trust. ``None`` is the OMITTED case, not "take what the library
        # defaults to" — it refuses with the same CA-naming words a ``True`` would. The annotation
        # stays permissive (``_bootstrap_tls_verify`` returns ``bool | str`` and server.py is not
        # this leg's file); the enforcement is the guard, which runs before any transport exists.
        anchored = _require_anchored_verify(verify)
        self.config = config
        self._http = httpx2.AsyncClient(
            verify=anchored,
            timeout=httpx2.Timeout(30.0, connect=10.0),
        )
        self._access_token: str | None = config.access_token
        # One unconditional session-file re-read per request (#705); _request resets it.
        # The mtime door does not count against it — it reads only when the file moved.
        self._disk_reread = False
        # Set only when a read of the file actually found a token this process declined (#705);
        # the session sentence composes it, and it is reset with the re-read budget each request.
        # shortcut: one flag per request, saying a read saw a value worth declining; a file rewritten
        # twice inside one request can date the wording, and the upgrade is to re-read at compose time.
        self._adoption_refused = False

    async def close(self) -> None:
        await self._http.aclose()

    def _headers(self) -> dict[str, str]:
        # The mtime door: one stat per call, a read only when the file moved (#705). What the read
        # finds is weighed by `_adopt`, which will not trade a session it holds for one it cannot
        # attest; a process that never had a token still picks the login up here, with no restart.
        self._adopt(self.config.reload_if_changed())
        if not self._access_token:
            self._adopt(self.config.reload())
        if not self._access_token:
            # The remedy names the renewing verb only — a read verb is not a way back, since a
            # refused transparent refresh clears the stored token (#776, leg 1554).
            raise self._session_error()
        return {"Authorization": f"Bearer {self._access_token}"}

    def _session_error(self, *, refused: bool = False) -> SessionExpiredError:
        """This client's resolved path and observed adoption state, phrased by ``session_error_text``."""
        return SessionExpiredError(
            session_error_text(self.config.path, refused=refused, adoption_refused=self._adoption_refused)
        )

    def _adopt(self, disk_token: str | None) -> bool:
        """Take the token the session file holds only when this process has no session to displace
        and the file names the core this process dials.

        #705 is refuse-and-tell: the MCP must not use a session token a different
        principal wrote, and it must say so. What this process can attest is narrow, and it is worth
        naming — the file carries ``server_url`` and ``access_token`` and no principal (the CLI writes
        those two keys), the bearer is 256 random bits with no subject to read, and there is no
        identity call on this path. So a differing value cannot be shown to be the same login's, and
        this client dials only what it obtained: the file read at construction, or a token the core
        minted for the session already in hand. Three rules, and no branch logs a value:

        * equal to the token in hand — not an adoption, nothing to decide;
        * differs while a token is in hand — refused, and ``self._adoption_refused`` records that the
          file was seen to hold something else, which is the fact the sentence later tells;
        * nothing in hand — take it, but only while the file names THIS core. That establishes a
          session instead of replacing one, and it is the same trust the startup read already
          carries; the file has to say which core it belongs to, so a token minted for another core
          is never carried here (#705, and the https://-only dial of #540 stays where it is). A file
          that names no core at all — no ``server_url``, or one that is not a string — is declined on
          the same grounds as one naming a different core: this process cannot attest that silence
          still names its own dial.
        """
        if not disk_token or disk_token == self._access_token:
            return False
        if self._access_token:
            self._adoption_refused = True
            logger.info(
                "Did not adopt the session token on disk at %s: that file names no principal, and "
                "this process keeps dialling the session it obtained",
                self.config.path,
            )
            return False
        disk_core = self.config.disk_server_url
        # A file that names no core cannot be shown to name this one, so "unattested" answers the
        # same way as "attested elsewhere" (#705 as ruled; the guard used to fall through on None).
        if disk_core is None or disk_core.rstrip("/") != self.config.server_url:
            self._adoption_refused = True
            logger.info(
                "Did not adopt the session token on disk at %s: that file names %s and this process " "dials %s",
                self.config.path,
                disk_core if disk_core is not None else "no server_url",
                self.config.server_url,
            )
            return False
        self._access_token = disk_token
        logger.info("Adopted the session token on disk at %s", self.config.path)
        return True

    def _re_read_after_refusal(self) -> None:
        """Ask the session file once per request after the core refused a token (#705).

        It is no longer a second chance to swap: under the ruling there is nothing to swap to, so this
        read does two things only — it settles whether the file holds something other than the refused
        value, which is what the operator is owed in the refusal sentence, and it leaves the in-hand
        credential exactly where it was. Bounded once per request, and a file still holding the refused
        value records nothing, so nothing loops on it.
        """
        if self._disk_reread:
            return
        self._disk_reread = True
        if not self._adopt(self.config.reload()):
            logger.info("No other session token to weigh against the refused one at %s", self.config.path)

    async def _refresh(self) -> bool:
        """Refresh once per burst: concurrent 401s share one POST (#707).

        Every tool call dials through this one client, so a burst of expired-token 401s used
        to launch one refresh POST each. Two things followed from that: the core saw N refreshes
        for one session, and a call whose own refresh came back non-200 was reported to its
        caller as an expired session even when a sibling refresh in the same burst had just
        succeeded. Now the first caller creates the task and any caller that arrives while it is
        in flight awaits *that* outcome, so a burst costs exactly one refresh.

        A refused outcome is still a real answer, shared with every waiter — but the caller's 401
        branch reads the response itself now, so "the core refused" and "the core could not be
        reached" reach the operator as different sentences (#706, #707).

        Returns True when a token was obtained, False when it was not.
        """
        if not self._access_token:
            return False

        in_flight = self._refresh_task
        if in_flight is not None and not in_flight.done():
            logger.info("Joining the token refresh already in flight")
            return await in_flight

        task: asyncio.Task[bool] = asyncio.ensure_future(self._post_refresh())
        self._refresh_task = task
        return await task

    async def _post_refresh(self) -> bool:
        """The refresh POST itself — reached once per burst, never once per call.

        Sends current access token to /api/v1/auth/refresh.
        Server returns a new access_token. Updates config file in-place.
        Returns True on success, False when the core refused THIS credential.

        Raises ``VenyaAPIError`` when the core gave no verdict on it — a 5xx, a timeout, a
        refused connection (#707). That distinction is the whole point: only a refusal may be
        reported to the operator as an expired session.
        """
        if not self._access_token:
            return False

        try:
            resp = await self._http.post(
                f"{self.config.server_url}/api/v1/auth/refresh",
                headers=self._headers(),
            )
            if resp.status_code != 200:
                if resp.status_code in _REFRESH_REFUSAL_STATUSES:
                    logger.warning("Token refresh refused by the core: %d", resp.status_code)
                    return False
                # Reached the core, answered with something that is not a judgement on this
                # credential. The caller's retry cannot fix that, and the operator is not owed
                # a key ceremony for it (#707).
                logger.warning("Token refresh got %d from the core", resp.status_code)
                raise VenyaAPIError(resp.status_code, _NO_VERDICT_DETAIL)

            data = resp.json()
            new_token = data.get("access_token")
            if not new_token:
                logger.warning("Refresh response missing access_token")
                return False

            self._access_token = new_token
            self.config.update_token(new_token)
            logger.info("Token refreshed successfully")
            return True

        except httpx2.HTTPError as e:
            # Covers both shapes the caller asked to be told apart: a timeout and a transport
            # failure. Neither observed a status, so neither may be reported as one, and neither
            # is evidence that this session expired (#707).
            logger.warning("Token refresh HTTP error: %s", e)
            raise VenyaAPIError(None, _NO_VERDICT_DETAIL) from e

    async def _request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        params: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Make an authenticated request with automatic refresh on 401.

        Every Venya endpoint returns a JSON object (envelope), never a bare
        array, so this is always a dict.

        timeout: per-request override (seconds); None keeps the client default.
        Only the execute call passes one (_EXECUTE_TIMEOUT_SECONDS) — httpx
        treats an explicit None as "no timeout", so it must not be forwarded.
        """
        url = f"{self.config.server_url}{path}"
        extra: dict = {"timeout": timeout} if timeout is not None else {}
        self._disk_reread = False
        self._adoption_refused = False
        headers = self._headers()
        sent_token = self._access_token

        resp = await self._http.request(method, url, json=json_body, params=params, headers=headers, **extra)

        # 401 → try the refresh, then weigh what the session file holds, then retry once only with a
        # token this process obtained itself (#705). A differing value on disk is refused and said, so
        # the retry is reachable from the refresh alone; the state is decided by the token, never by
        # which door moved it.
        if resp.status_code == 401:
            logger.info("Got 401, attempting token refresh...")
            if not await self._refresh():
                self._re_read_after_refusal()
            if self._access_token != sent_token:
                resp = await self._http.request(
                    method, url, json=json_body, params=params, headers=self._headers(), **extra
                )
            else:
                # Same renewing clause as `_headers()`, never a read verb (#776, leg 1554).
                raise self._session_error(refused=True)

        if resp.status_code >= 400:
            content_type = resp.headers.get("content-type", "")
            if content_type.startswith("application/json"):
                detail = resp.json().get("detail", resp.text)
            else:
                detail = resp.text
            raise VenyaAPIError(resp.status_code, str(detail))

        return resp.json()

    # --- Tool convenience methods ---

    async def list_secrets(
        self,
        executor: str | None = None,
        purpose: str | None = None,
        username: str | None = None,
    ) -> list[dict]:
        """List secrets with optional metadata filters. Never returns values."""
        params: dict[str, str] = {}
        if executor:
            params["executor"] = executor
        if purpose:
            params["purpose"] = purpose
        if username:
            params["username"] = username
        resp = await self._request("GET", "/api/v1/secrets", params=params)
        return resp["secrets"]

    async def list_executors(self) -> dict:
        """List registered executors with online status.

        Returns the full response envelope {executors: [...]}.
        """
        return await self._request("GET", "/api/v1/executors")

    async def run_command(
        self,
        executor_id: str,
        command: str,
        secret_keys: list[str],
    ) -> dict:
        """Execute a command on a remote executor with secret injection.

        Two-step internal flow (exposed as single tool to LLM):
        1. POST /executors/sessions with {executor_id, secret_keys}
           → server resolves, decrypts, wraps, stores secrets server-side
        2. POST /executors/{id}/execute with {session_id, command: argv list}
           → {exit_code, stdout, stderr, masked_count}

        The MCP server never sees secret plaintext. Output contains
        [REDACTED:<id>] markers where secret values would appear.

        If secret_keys is empty, step 1 creates a session with no secrets.
        """
        # Parse argv BEFORE the session POST (ticket mcp-session-created-before-
        # argv-parse #415): an unparseable command must not churn a secret-bound
        # session row that then waits on TTL reap. The shlex split needs no
        # session — it leads.
        # M1 boundary split (ticket execution-command-wire-unstructured-string
        # #322, owner ruling): the MCP TOOL surface stays a shell string, but
        # ExecuteRequest.command is a list[str] since #322 — argv is split
        # HERE so the wire carries structured tokens. An unparseable string
        # (unbalanced quote) becomes a ValueError, which rides the EXISTING
        # tool-error path (server.py: handler exceptions become isError=True
        # results carrying this message; no traceback reaches the agent).
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise ValueError(f"Command could not be parsed as a shell line: {exc}") from None

        # Step 1: Create session (with optional secret keys)
        session_body: dict = {"executor_id": executor_id}
        if secret_keys:
            session_body["secret_keys"] = secret_keys

        session_resp = await self._request(
            "POST",
            "/api/v1/executors/sessions",
            json_body=session_body,
        )
        session_id = session_resp["session_id"]

        # Step 2: Execute command — long-running: last-fuse timeout (ticket
        # cli-execution-timeout-cold-start-default).
        result = await self._request(
            "POST",
            f"/api/v1/executors/{executor_id}/execute",
            json_body={
                "session_id": session_id,
                "command": argv,
            },
            timeout=_EXECUTE_TIMEOUT_SECONDS,
        )

        return result

    async def get_audit(
        self,
        hours: int = 1,
        event_type: str | None = None,
        executor_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query audit log. Admin or auditor-tier callers see the full log; other read-write callers see only their own events; plain-read callers are denied (403)."""
        params: dict[str, str] = {"limit": str(limit), "hours": str(hours)}
        if event_type:
            params["event_type"] = event_type
        if executor_id:
            params["executor_id"] = executor_id
        resp = await self._request("GET", "/api/v1/audit", params=params)
        return resp["events"]
