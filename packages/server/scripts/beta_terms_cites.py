# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Curated cite manifest for docs/beta-known-limitations.md.

**Why a manifest and not prose inference.** The generator was first written to read the symbol off the
sentence beside each coordinate, because that is how a human audits it. Measured on this page it
resolved **10 of 105** cites: names like ``_build_relay_ssl_context`` occur as both the ``def`` and a
call site, so "nearest literal that exists in the file" either picks the wrong line or, when the tool
is made honest and refuses ambiguity, refuses almost everything. A guessed resolution is worse than a
missing one — it publishes a NEW wrong coordinate under a passing check, which is precisely the defect
this leg exists to end.

So each cite carries three human-decided facts here, and only these:

``symbol``
    The literal the page's claim is about. Verified present in ``path`` or the cite is refused.
``occurrence``
    Which matching line, counting matches from 1, when the symbol legitimately occurs more than
    once. This is the part no prose reader can recover and no machine should guess.
``kind``
    ``pin`` (re-pin the number at the cut), ``dated`` (a historical record — the number is part of
    what was measured then, and re-pinning it would destroy the observation), or ``exempt`` (no
    symbol is claimed, e.g. a page-docstring quote or a line RANGE whose endpoints are the claim).

The maintenance/anchor block at the foot of the page is ``dated`` as a rule: it records "moved :622
to :628 at c36439b", and rewriting those digits to today's lines turns a dated observation into a
false claim about a commit that never had them. That is the provenance law, not a convenience.
"""

from __future__ import annotations

E = "packages/server/src/server/routes/executors.py"
R = "packages/executor/src/executor/relay_listener.py"
D = "packages/executor/src/executor/daemon.py"
C = "packages/server/src/server/ca.py"
A = "packages/server/src/server/middleware/auth.py"
M = "packages/core/src/core/iam/models.py"
L = "packages/cli/src/venya_cli/cli.py"
CM = "packages/cli/src/venya_cli/commands.py"
AR = "packages/cli/src/venya_cli/at_rest_key.py"
KP = "packages/executor/src/executor/key_passphrase.py"
CFG = "packages/executor/src/executor/config.py"
AC = "packages/server/src/server/routes/admin_certs.py"
AD = "packages/server/src/server/routes/admin.py"
HL = "packages/server/src/server/routes/health.py"
T586 = "packages/server/tests/test_relay_dial_crl_586.py"
TCF = "packages/server/tests/test_clock_skew_fraction_rf7.py"
HC = "install-venya-core.sh"
HE = "install-venya-executor.sh"

#: key = the token exactly as the page prints it. value = (path, symbol, occurrence, kind).
#: ``symbol`` must be a verbatim literal of ``path``. ``occurrence`` is 1-based among lines
#: containing that literal. Kinds: pin | dated | exempt.
MANIFEST: dict[str, tuple[str, str, int, str]] = {
    # ---- #586 entry: the dial door
    "packages/server/src/server/routes/executors.py:639": (E, "def _build_relay_ssl_context", 1, "pin"),
    "packages/server/src/server/routes/executors.py:687-688": (E, "VERIFY_CRL_CHECK_LEAF", 1, "pin"),
    "packages/server/src/server/routes/executors.py:713": (E, "def _ensure_dial_crl_store", 1, "pin"),
    f"{E}:1979": (E, "crl_capath = _ensure_dial_crl_store(request, db)", 1, "pin"),
    f"{E}:1994": (E, "ssl_ctx = _build_relay_ssl_context", 1, "pin"),
    f"{E}:789": (E, "Executor certificate revoked", 1, "pin"),
    f"{E}:699": (E, "_STALE_LIST_DETAIL = REVOCATION_UNAVAILABLE_DETAIL", 1, "pin"),
    f"{E}:1987": (E, "Server TLS misconfiguration", 1, "pin"),
    # ---- the `.../executors.py:N` short forms the #586 entry prints
    "packages/server/src/server/routes/executors.py:2027": (
        E,
        "crl_capath = _ensure_dial_crl_store(request, db)",
        1,
        "pin",
    ),
    "packages/server/src/server/routes/executors.py:2042": (E, "ssl_ctx = _build_relay_ssl_context", 1, "pin"),
    "packages/server/src/server/routes/executors.py:810": (E, "Executor certificate revoked", 1, "pin"),
    "packages/server/src/server/routes/executors.py:710": (
        E,
        "_STALE_LIST_DETAIL = REVOCATION_UNAVAILABLE_DETAIL",
        1,
        "pin",
    ),
    "packages/server/src/server/routes/executors.py:2035": (E, "Server TLS misconfiguration", 1, "pin"),
    ":1997": (E, "Server TLS misconfiguration", 2, "pin"),
    "packages/server/src/server/routes/executors.py:674": (E, "VERIFY_X509_STRICT", 1, "pin"),
    "packages/server/src/server/routes/executors.py:717-722": (
        E,
        "refuse everything until a properly refreshed list arrives",
        1,
        "pin",
    ),
    "packages/server/src/server/routes/executors.py:2023-2025": (E, "Scope note (ruled boundary)", 1, "pin"),
    "packages/server/src/server/routes/executors.py:1619": (
        E,
        "is_online = 0.0 <= delta.total_seconds() < 60",
        1,
        "pin",
    ),
    f"{E}:775": (E, "def _dial_crl_verdict_for", 1, "pin"),
    # ---- #586 entry: the listener door
    "packages/executor/src/executor/relay_listener.py:697": (R, "def _build_ssl_context", 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:712-723": (
        R,
        "context.verify_mode = ssl.CERT_REQUIRED",
        1,
        "pin",
    ),
    "packages/executor/src/executor/relay_listener.py:405": (R, "def revocation_accept_reason", 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:550": (
        R,
        "reason = revocation_accept_reason(self.revocation_state)",
        1,
        "pin",
    ),
    "packages/executor/src/executor/relay_listener.py:414": (R, "the EXECUTOR-serial list never describes", 1, "pin"),
    f"{R}:116": (R, "peer_cn not in self.server.allowed_client_ids", 1, "pin"),
    f"{R}:46": (R, "RELAY_PORT = 8443", 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:654": (R, 'host: str = "0.0.0.0"', 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:364-386": (R, "ConnectionRefusedError(reason)", 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:718-723": (R, "relay_client_ids is empty", 1, "pin"),
    "packages/executor/src/executor/relay_listener.py:774": (R, "def reload_ssl_context", 1, "pin"),
    # ---- #586 entry: the daemon state machine
    f"{D}:249": (D, "self.revoked = False", 1, "pin"),
    f"{D}:255": (D, "self.revocation_answered = False", 1, "pin"),
    "packages/executor/src/executor/daemon.py:2168": (D, "self.state.revoked = True", 1, "pin"),
    "packages/executor/src/executor/daemon.py:2180": (D, "self.state.revocation_answered = True", 1, "pin"),
    "packages/executor/src/executor/daemon.py:2204": (D, "if self.state._consecutive_revocation_failures >=", 1, "pin"),
    "packages/executor/src/executor/daemon.py:2149": (D, "self.relay.reload_ssl_context()", 1, "pin"),
    "packages/executor/src/executor/daemon.py:2219": (D, "self._shutdown_event.wait(30.0)", 1, "pin"),
    "packages/executor/src/executor/daemon.py:1947": (D, "relay_client_ids is empty", 1, "pin"),
    "packages/executor/src/executor/daemon.py:1404": (D, "CA certificate expired", 1, "pin"),
    # ---- installers and CA
    "install-venya-core.sh:1024": (HC, "-CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key", 2, "pin"),
    "install-venya-core.sh:1026": (HC, '-CAcreateserial -out "$RELAY_DIR/relay-client.crt" -days 365', 1, "pin"),
    "install-venya-core.sh:1017": (HC, '-subj "/O=Venya/CN=${CORE_HOSTNAME}-relay"', 1, "pin"),
    "install-venya-core.sh:1009": (HC, '-out "$RELAY_DIR/relay-client.key"', 1, "pin"),
    "install-venya-core.sh:969": (HC, "-out /etc/venya/tls/server.key", 1, "pin"),
    ":967": (HC, "chmod 600 /etc/venya/tls/server.key", 1, "pin"),
    ":1007": (HC, 'chmod 600 "$RELAY_DIR/relay-client.key"', 1, "pin"),
    ":1063": (HC, '-out "$INNER_DIR/inner.key"', 1, "pin"),
    ":1065": (HC, 'chmod 600 "$INNER_DIR/inner.key"', 1, "pin"),
    f"{HE}:558": (HE, "printf 'relay_client_ids = ", 1, "pin"),
    f"{HE}:573": (HE, "} > /etc/venya/executor.toml", 1, "pin"),
    ":586-587": (HE, "rm -f /etc/venya/venya-executor.env", 1, "pin"),
    "packages/server/src/server/ca.py:395": (C, 'self.ca_cert_path = self.ca_dir / "ca.crt"', 1, "pin"),
    "packages/server/src/server/ca.py:622": (
        C,
        "not_valid_after(now + timedelta(days=EXECUTOR_VALIDITY_DAYS))",
        1,
        "pin",
    ),
    "packages/server/src/server/ca.py:716": (
        C,
        "def generate_crl(self, db_session, max_entries: int = 1000, revocations=None)",
        1,
        "pin",
    ),
    "packages/server/src/server/ca.py:760": (C, "db_session.query(ExecutorCertRevocation)", 1, "pin"),
    "packages/server/src/server/ca.py:769": (C, "builder = builder.next_update(now + timedelta(hours=1))", 1, "pin"),
    "packages/server/src/server/ca.py:1475": (C, "builder = builder.next_update(now + timedelta(hours=1))", 2, "pin"),
    "packages/server/src/server/ca.py:47": (C, "EXECUTOR_VALIDITY_DAYS = 30", 1, "pin"),
    "packages/server/src/server/ca.py:52": (C, "EXECUTOR_LEAF_EKU", 1, "pin"),
    f"{C}:803": (C, "ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600", 1, "pin"),
    "packages/server/src/server/ca.py:46": (C, "CA_VALIDITY_DAYS = 3650", 1, "pin"),
    "packages/server/src/server/ca.py:479": (C, "not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))", 1, "pin"),
    f"{C}:796": (C, "ADMIN_CA_VALIDITY_DAYS = 3650", 1, "pin"),
    "packages/server/src/server/ca.py:1070": (
        C,
        "not_valid_after(now + timedelta(days=ADMIN_CA_VALIDITY_DAYS))",
        1,
        "pin",
    ),
    "packages/server/src/server/ca.py:1140": (C, "def sign_admin_cert", 1, "pin"),
    ":1244-1247": (C, "encryption_algorithm=serialization.NoEncryption()", 1, "pin"),
    # ---- models, middleware, cli
    "packages/core/src/core/iam/models.py:382": (M, "Revoked executor certificate serial numbers", 1, "pin"),
    f"{M}:379": (M, "class ExecutorCertRevocation", 1, "pin"),
    f"{M}:613": (M, "class AdminCertRevocation", 1, "pin"),
    "packages/server/src/server/middleware/auth.py:860": (A, "async def _validate_executor_mtls", 1, "pin"),
    "packages/server/src/server/middleware/auth.py:975": (A, "rev = executor_revocation_state(", 1, "pin"),
    "packages/server/src/server/middleware/auth.py:555": (
        A,
        "ssl_crl, so this lookup is the enforcement point",
        1,
        "pin",
    ),
    f"{A}:203-206": (A, "dropped expired certs at the outer TLS layer", 1, "exempt"),
    "packages/cli/src/venya_cli/cli.py:410": (L, '"split-ca-key"', 1, "pin"),
    "packages/executor/src/executor/config.py:422": (CFG, "relay_client_ids: list[str] = Field(", 1, "pin"),
    # ---- the two live NoEncryption() writers and the four comments
    "packages/cli/src/venya_cli/commands.py:2157": (CM, "NoEncryption(): an admin private key in the clear", 1, "pin"),
    f"{CM}:3241": (CM, "NoEncryption(), an executor private key in the clear beside the cert", 1, "pin"),
    "packages/core/src/core/iam/models.py:744": (M, "class CoreRelayCredential", 1, "pin"),
    f"{CM}:3678": (CM, "the renew path wrote NoEncryption(): an executor private key", 1, "pin"),
    # the page prints these two as BARE `commands.py:N` on the continuation line — same file, so
    # keyed here; the guard still demands the page say a full path (see the ambiguity cell)
    "packages/cli/src/venya_cli/commands.py:3334": (
        CM,
        "NoEncryption(), an executor private key in the clear beside the cert",
        1,
        "pin",
    ),
    "packages/cli/src/venya_cli/commands.py:3771": (
        CM,
        "the renew path wrote NoEncryption(): an executor private key",
        1,
        "pin",
    ),
    f"{KP}:10": (KP, "serialization.NoEncryption()", 1, "pin"),
    f"{AR}:55": (AR, "def unwrap_at_rest", 1, "pin"),
    ":86-89": (AR, "encryption_algorithm=NoEncryption()", 1, "pin"),
    # ---- tests and admin routes
    "packages/server/tests/test_relay_dial_crl_586.py:23-26": (
        T586,
        "no venya executor code runs on either side",
        1,
        "pin",
    ),
    # The quoted value is a keyword-argument literal in product source, cited verbatim because the
    # page's claim is about that exact text. Not a credential — the pragma must sit on the flagged
    # line itself, which an earlier attempt here got wrong by commenting the line ABOVE instead.
    f"{AC}:317": (AC, "lifetime_seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS", 1, "pin"),  # pragma: allowlist secret
    f"{TCF}:55": (TCF, "assert ADMIN_SHORT_CERT_LIFETIME_SECONDS == 3600", 1, "pin"),
    "packages/server/src/server/routes/admin.py:1077": (AD, "executor's next heartbeat (~30 s)", 1, "pin"),
    f"{HL}:78": (HL, "def _check_ca", 1, "pin"),
    "packages/server/src/server/routes/executors.py:796": (E, "def _dial_crl_verdict_for", 1, "pin"),
    "executors.py:702": (E, "def _ensure_dial_crl_store", 1, "pin"),
    "executors.py:628": (E, "def _build_relay_ssl_context", 1, "pin"),
    "executors.py:1571": (E, "is_online = 0.0 <= delta.total_seconds() < 60", 1, "pin"),
    # Two entries used to sit at the foot of this dict —
    # `packages/executor/src/executor/relay_listener.py:116` and `.../daemon.py:2148` — duplicating
    # `f"{R}:116"` and `f"{D}:2148"` above with byte-identical VALUES. Python resolves a repeated dict
    # key last-wins at import time and raises nothing, so source keys (98) outnumbered runtime keys (96)
    # and the two later entries were dead code the moment the file loaded. They are removed rather than
    # kept-and-keyed-by-line: the lookup key IS the coordinate as the page prints it, so a line number
    # cannot join it without changing what `parse_cites()` matches, and nothing was gained because the
    # duplicated meanings were the same. #675 (a prior worker lane) added `audit_keys()` in the generator, which
    # counts keys in the SOURCE before the dict collapses them; it is now the thing that keeps a
    # re-pin from clobbering a cite's meaning, so do not re-introduce a duplicate to satisfy it.
}

#: The maintenance/anchor block below the entries. Every coordinate there is a RECORD of what was
#: measured at a named past commit — re-pinning it would assert that commit had today's lines.
#: ``dated`` means: the guard checks the SYMBOL still exists (so the record stays about a real
#: thing), but the number is never rewritten.
DATED_BLOCK_FIRST_PAGE_LINE = 660

#: Tokens deliberately outside the pin set, with the reason. Anything else that is neither
#: manifest nor dated makes the guard RED rather than being quietly skipped.
DATED_OVERRIDES: dict[str, str] = {
    f"{HC}:1385-1389": "c36439b pass record: what that commit shipped, not what the reader should open",
    "config.py:149-152": "90f2bcb pass record",
    "auth.py:731": "90f2bcb pass record (`:731`→`:748`)",
    "middleware/auth.py:493": "583d902/7b055e4 pass record",
    "executors.py:690": "583d902 pass record",
    "executors.py:687": "583d902 pass record",
    "daemon.py:2163": "583d902 pass record",
    "ca.py:758": "583d902 pass record",
    "ca.py:803": "583d902 pass record",
    "ca.py:45": "c36439b 'did not move' roster",
    "ca.py:1470": "pre-move face in the old→new record",
    "routes/admin_certs.py:317": "583d902 pass record",
    "tests/test_clock_skew_fraction_rf7.py:55": "583d902 pass record",
    "test_clock_skew_fraction_rf7.py:55": "c36439b 'did not move' roster",
    "routes/admin.py:1064": "old face in an old→new pair",
    "admin.py:1064": "old face in an old→new pair",
    "models.py:379": "c36439b 'did not move' roster",
    "models.py:380": "c36439b 'did not move' roster",
    "routes/executors.py:1525": "old face in an old→new pair",
    "executors.py:1525": "90f2bcb pass record",
    "middleware/auth.py:731": "90f2bcb pass record",
    "install-venya-core.sh:965": "c36439b 'did not move' roster",
    "install-venya-executor.sh:558": "c36439b 'did not move' roster",
    "test_relay_dial_crl_586.py:21-24": "c36439b 'did not move' roster",
}
