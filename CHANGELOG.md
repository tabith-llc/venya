# Changelog

Notable changes to Venya will be documented in this file.

## [Unreleased]

## [0.1.0beta1] - 2026-10-15

- **The executor's revocation poll is answered from a freshness-bounded snapshot
  (#603, AC2 step 2).** A core republishes the revoked-serial and revoked-identity
  population every 10 s and answers `GET /api/v1/executors/certs/revocation-list` from
  that snapshot, so the poll no longer queues behind ordinary command traffic for a
  database connection and no longer waits on a lock held over the revocation table.
  The visible change for an operator is a new, deliberate answer on that endpoint: a
  snapshot older than 45 s — or none yet, during a core's own startup — is refused with
  `503` and the "no revocation asserted" wording the dial paths already used, never
  served as a stale all-clear. A refused poll is counted by the executor exactly as an
  unreachable core is counted today, so three consecutive refusals stop the daemon with
  the operational-fault reason, not a revocation claim. Enforcement at the dial gates is
  unchanged and does not depend on the snapshot; the numbers 45 s and 10 s are shipped
  constants, not configuration.
- **The stale-class refusal now says "request refused" instead of "dial refused"
  (#603).** One sentence serves both the TLS dial and the poll, so the wording names
  whichever request was refused rather than one transport. The clause operators read
  for meaning — `no revocation asserted` — is unchanged, and `docs/beta-known-limitations.md`
  cites that clause by name and line, so it needed no edit. Journal lines that begin
  `Relay dial refused` are dial-true log prefixes and were left alone; a composed line
  can now read `Relay dial refused, Revocation list stale or unavailable — request
  refused (no revocation asserted)`, which is redundant and correct.
- **Executor: the `[session]` and `[output_capture]` tables are gone (#620).** Seven keys
  an operator could set in `/etc/venya/executor.toml` — `session_timeout`,
  `access_token_ttl`, `max_session_duration`, `max_output_bytes`, `hash_window_size`,
  `min_match_length`, and `[audit] local_retention_days` — were read by no code. Session
  lifetimes are decided on the core from the server's own config, output limits come from
  the executor's `MAX_OUTPUT_BYTES` constant, and the audit spool is bounded by buffer
  size and batch lines. The #598 start-up line had been telling whoever set them that
  "the file value is in use", which was not true of any of the seven; the promise now
  stops where the capability does. A deployed `executor.toml` that still carries these
  tables loads unchanged — unrecognised keys are ignored — so no reinstall is needed.
- **The revocation-snapshot publisher now survives a faulty teardown and says so (#626).** A core
  republishes the revocation population every 10 s; if the session teardown at the end of one of
  those publishes raised, the publisher task ended, the snapshot plane went back to the lockable
  live DB read for the rest of the process's life, and the only journal evidence was a warning that
  appears once per process. Such a publish now absorbs the teardown fault, keeps the population it
  had already read, and retries on a bounded backoff (1 s doubling to 30 s), so the plane recovers on
  its own when the fault clears. A publisher task that ends for any other reason is logged at ERROR
  with its reason, and a shutdown cancel is still logged quietly at INFO. The poll's answers are
  unchanged: the 45 s freshness ceiling, the 10 s interval, and the stale-class `503` that says "no
  revocation asserted" all stand as shipped, and a core with no publisher still answers from the
  current live read.
- **A CLI error that carried no message now names itself (#595).** The catch-all that prints the
  one line an operator sees used to render a bare `Error:` when the raised exception had nothing
  to say — an empty prompt read, a queue that timed out, a bare `ValueError`. That line now
  carries the exception type (`queue.Empty`, not `Empty`), the command that was running, where the
  detail was logged, and the `--verbose` hint for the traceback. Every exception that does have a
  message prints exactly the line it printed before: command bodies keep their own wording, and
  the argument values a command was given are deliberately not included, so a secret passed as a
  positional cannot reach the terminal or the log through this path.
- **`venya admin executor enroll --output-dir` makes the directory it documents (#616).** The
  generated reference says this command creates the output directory, and the directory was in
  fact only made after a successful round trip. It is now created before the token is minted, at
  `0700` through the same secret-directory helper the rest of the CLI uses, so a path that cannot
  be made — an existing file of that name, a parent with no write permission — stops with a
  refusal that names the path and says nothing was minted, rather than printing an OS error string
  after a token had already been issued.
- **The installer stops on a source patch it can no longer find (#618).** `venya_apply_code_fixes`
  reports each patch as applied, already clean, or a dead anchor, and a dead anchor used to be a
  `[WARN]` the run sailed past. It is now an `[ERROR]` that ends the install nonzero before the
  virtualenv, the migrations and the service start, so the only thing touched is the extracted
  tree. The DB-URL patch it guards was also re-anchored: the two source forms the old check looked
  for are not in the product any more — shipped source now reads
  `database_url = db_url or os.environ.get("VENYA_DB_URL")` with `app.py` passing the configured
  URL — so the guard could only ever report a miss, which is what it did on every healthy install.
  It now asserts that live shape and touches nothing, and the message names which half it could not
  satisfy: the expression in `dependencies.py`, or the call site in `app.py`.
- **The admin-pair advice points at the ceremony, not at a copy (#619).** When
  `VENYA_ADMIN_CERT` or `VENYA_ADMIN_KEY` named a file that is not there, the CLI told the operator
  to copy the core's admin pair to the workstation. It now says not to, and gives the supported
  route instead: `venya setup <core>`, then `venya login <user-id>`, then
  `venya admin cert renew`. The pair on a core names that core, not a person.
- **`venya admin configure-user` no longer accepts a setting nothing reads (#625).** The command
  had one knob, `--timeout`, and the value it wrote went into `users.session_timeout`, a column no
  expiry decision in the product reads — the live idle window comes from the core's own
  `session.session_timeout` / `VENYA_SESSION__SESSION_TIMEOUT`. The option, the request field, the
  write and the audit entry for that value are gone, and the command now refuses by name until a
  setting that reaches a read field joins it, instead of reporting success on a change with no
  effect. An operator still sending the old key gets a `422` rather than a quiet no-op. The
  `users.session_timeout` column stays as it is; dropping it would cost a migration for no gain.
- **Windows install paths with `[` or `]` in the name are seen (#628).** `Test-Path`'s positional
  parameter resolves wildcards, so a directory named with brackets — a test root called
  `C:\temp[gate]`, say — matched nothing and files that existed read as missing: the installer
  could stop at the `uv` check or report a shim it had just installed as absent. Nine existence
  probes in `install-venya-cli.ps1` now bind `-LiteralPath`, which does not parse wildcards. The
  #493 ACL gate keeps its own checks; this brings the probes upstream of it into the same form.
- **The Windows uninstaller finds the same kind of path (#629).** The three install-root probes in
  `uninstall-venya-cli.ps1` were positional for the same reason #628 fixed, so a root whose name
  contains wildcard characters was read as absent: nothing was removed and the run still reported
  the directory gone. They now bind `-LiteralPath`, so that root is seen, removed, and verified
  gone. The verify-absent loop is untouched — it is the check that catches this class.
- **A core name that does not resolve says so (#633).** A dial that never left the workstation and
  a dial that reached the network and got no answer used to render as the same connection or fetch
  sentence, which sent operators looking at routing for a missing hosts line. One classifier in
  `packages/cli/src/venya_cli/name_resolution.py` now reads the exception cause chain for
  `socket.gaierror` — by cause class, not by message text, so no platform's errno wording and no
  wording change moves it — and the setup CA read, the API client dials and the login path route
  through it. The new line names the host, says the name did not resolve on this workstation, and
  points at the hosts file or the server URL. A refused connection, a timeout and a handshake
  failure keep the sentence they had.
- **A hung sandbox create and a vendor memory refusal now name themselves (#639).** Both used to
  reach the operator through the shared command-timeout lane, which reported the wrong stage and
  the wrong number: a create bounded by `SBX_CREATE_TIMEOUT` (240 s) could be announced as
  "Command timed out after 3600 seconds", and a refusal that came from the vendor's memory check
  was indistinguishable from any other failed create. The create site now raises named errors, the
  executor's journal carries the stage and the bound that actually fired, and the create path
  reads the timeout it used rather than the constant. The wire is unchanged: a refused create
  stays the flat `503` it was, and the vendor's own stderr still does not cross the relay
  boundary — the distinction is made in the executor's own lines.
- **The core installer checks the value before it removes anything (#641).** The stale CA-link
  cleanup in `/etc/ssl/certs` built its operand from an unsanitized, error-silenced
  `openssl x509 -subject_hash`: when that produced nothing, the operand degraded to a
  directory-wide dotfile pattern and the run removed files it never meant to name. The hash is now
  resolved once, asserted to be a bare hex name, and used only for that one prefix; an openssl that
  is missing or fails warns, names what it gave back, and continues the install without the
  cleanup.
- **The plane marker reads one arc now (#601).** Venya's plane marker moved to the project's registered
  enterprise number at 0.1.0alpha17, and the reader accepted the arc it used to sit on alongside it so
  credentials already minted kept resolving while each plane was re-minted. That window is now closed:
  `1.3.6.1.4.1.67159.1.1` is the only marker the reader consults, and a plane-shaped extension on any
  other arc is read as no marker at all — the certificate is refused the way an unmarked one is, through
  the executor-mTLS path included. This follows the owner's ruling of 2026-10-16 that nothing alpha-era is
  supported, which removes the precondition the second read was kept for. `docs/cert-rotation-runbook.md`
  now says the same thing the code does, and the paired negative that pins the closure is
  `packages/server/tests/test_plane_marker_pen_arc_601.py`, class `TestAnyOtherArcIsNoLongerRead`.
- **A locked revocation read now answers in the stale class instead of waiting (#603, AC1).** The
  revocation population is read on the executor request path — the per-request mTLS check, the heartbeat
  and register routes, the two dial gates, audit ingest, the admin lists, and the public CRL route. When a
  lock was held over that table the wait was unbounded; the read now runs inside a savepoint carrying a
  `SET LOCAL lock_timeout`, and a read that cannot finish in time is refused with the same `503` and the
  same `no revocation asserted` sentence a stale snapshot already answers — never as an all-clear and never
  as a revocation claim. The bound ships as `crl.revocation_read_lock_timeout_ms` = 300 ms
  (`VENYA_CRL__REVOCATION_READ_LOCK_TIMEOUT_MS`); it bounds the LOCK WAIT, not a slow scan, and
  `statement_timeout` stands as it ships. A refusal is counted by `venya_revocation_read_refusals_total`,
  labelled by site, and `docs/revocation-table-operations-runbook.md` is new and covers the operations that
  can take that table and what each one costs. Because a deadline set on a pooled connection would follow
  onto an unrelated later request, the seam reverts it explicitly, and a refusal cannot discard the
  caller's own pending write — three savepoint properties, each pinned by a cell in
  `packages/server/tests/test_revocation_read_bound_603.py`.

## [0.1.0alpha17] - 2026-10-13

There is no backwards compatibility during alpha. Three changes in this window are
things an operator has to act on, so they are named at the top rather than buried in
the lists below.

- **The database encryption passphrase now has a length floor (#573, #615).** A
  `VENYA_DB_PASSPHRASE` shorter than 15 characters — counted the way you type them,
  as Unicode code points, so 15 passes and 14 refuses — is refused twice over: by the
  installer at the point where the value resolves, BEFORE it writes or changes
  anything on the host, and by the core at boot. The same floor carries the CA-key
  passphrases, and blank or whitespace-only values are refused on those planes
  (#554, #570). An install made earlier that holds a shorter passphrase is not
  quietly rotated: its re-run refuses at that gate, and the path forward is a
  deliberate reinstall or a deliberate rotation, made by the operator.
- **A freshly installed executor ships a per-sandbox memory cap (#589).** The shipped
  number is 1024 MiB per sandbox, passed to `sbx create --memory`. Before this
  release the knob had no shipped value: a sandbox command either ran under the
  vendor's own default (half of the guest) or, since #578, refused at create until an
  operator named a number. An operator value in the config file or in the environment
  still wins, and the vendor band (512 MiB floor, 75% of this machine as the ceiling)
  is still checked at config load.
- **A core re-run that meets a running service now stops it before migrating
  (#587).** The
  run announces it (`NOTICE: stopping venya-core.service BEFORE database migrations`)
  and guards it — a first install has no unit yet, so there it never stops and never
  aborts. The guard is the unit being up, not the version moving: a same-version
  re-run takes the same pause, and its migrations change nothing. The end-of-run
  proof now has three named outcomes instead of two: FRESH
  proceeds, STALE (the running process provably predates the bytes just deployed)
  refuses the success claim, and UNDECIDABLE (a timestamp that could not be read or
  parsed) withholds the claim without reporting a good install as broken.
  `docs/UPGRADE.md` and `docs/installation.md` §1 carry the re-run contract.

### Added

- **Docs: added `docs/UPGRADE.md`** — the tested in-place upgrade runbook (core upgrade drill alpha15→alpha16: backup, migrations, config preservation, downgrade policy).
- **Docs: added `docs/ease-of-use.md`** — the deliberate-relaxation guide: the scp worked recipe (command policy + egress allowlist, with the paired locked default), a per-knob gain/loss catalog of every supported relaxation surface, and the never-relax list. Docs-only; no behavior change.
- **Break-glass recovery-code RE-ISSUE.** `venya admin reissue-recovery-code`
  mints a fresh code for the logged-in caller without reinstalling: gated by
  admin mTLS (the `/api/v1/admin/` middleware chain) AND a session bearer AND
  a fresh WebAuthn elevation assertion — strictly more proof than holding the
  old code. The new code prints exactly once, the old one dies in the same
  commit (one live code, always), and every reissue/denial writes a value-free
  audit row. Lost-printed-code operators keep their key AND their
  break-glass. Multi-factor loss (key AND code) remains out of scope:
  Shamir CA shares + backups + reinstall is still the last-resort path.
- **Server: the admin lifecycle is now auditable.** Every lifecycle write —
  core init and first-admin enrollment, login (success and value-free failure),
  browser session end, break-glass recovery, user create/update/delete, role
  create/update/delete, role member add/remove, security-key add/remove —
  records a value-free `audit_events` row (ids/names only; never tokens,
  codes, hashes, key material, or IP addresses) IN THE SAME TRANSACTION as
  the action, so a failed audit write aborts the action: the append-only log
  is complete or nothing happened. The auditor tier therefore sees the full
  "who created this role / who added this user / who logged in" trail its
  visibility promise is built on.
- **Added: executor audit-spool ingest endpoint.** `POST /api/v1/audit/ingest`
  accepts an executor's spool-forwarder batch (ndjson + zstd) over executor
  mTLS and appends every event — including `command_rejected` policy refusals —
  to the append-only `audit_events` ledger, where the auditor tier sees it
  through the existing `event_type` / `executor_id` filters. Rows carry the
  sending executor's cert CN as the principal and `executor_id` /
  `sender_revoked` / `forwarded` provenance fields; a revoked-but-registered
  sender's evidence still lands, flagged. Batches from a revoked sender or an
  unregistered/forged sender are refused or flagged per ruling; malformed
  lines reject the whole batch (400), and delivery is at-least-once (retried
  batches may duplicate rows). On the executor side the forwarder now presents
  its mTLS client certificate and drains in bounded batches
  (`[audit] max_batch_lines`, default 500, bounded by `max_buffer_size`).
- **Server: the audit lifecycle tail is closed.** The remaining
  control-plane writes now carry value-free `audit_events` rows in the same
  transaction: key-version rotate/rollback/deactivate/revoke, every issued
  elevation token (`elevation_granted`, mode and endpoint only), executor
  and admin-certificate revocations (both forms; a duplicate attempt is
  recorded with the no-op visible in fields), user re-enrollment and
  enrollment-token issue/revoke (ids and counts — never the token
  plaintext), and allowlist additions. The command-policy and executor
  enrollment-token audit rows moved behind the single lifecycle writer, so
  every lifecycle event shares one construction path and one posture.
- **Docs: added `docs/beta-known-limitations.md`** — the release-facing carrier for
  what beta does not yet enforce, one entry per tracked issue, read against the
  shipped source rather than summarized from intent.
- **Handing out a value is now itself an audit event (#602).** The elevated unmask
  path writes a disclosure row in the same transaction as the burn, naming the key,
  the caller and the time. No value, token or token hash is ever written there, and a
  disclosure that loses its row loses the burn with it.
- **Attestation material is stored with a security key (#565, leg 1).** Migration 038
  adds the columns that keep the raw attestation object beside the credential, so
  attestation policy can act retroactively later. Storage only — nothing is enforced
  on it yet.

### Changed

- **Changed: `POST /api/v1/admin/command-policy` now rejects unknown body
  keys with 422** (`extra="forbid"` on the request model, #289 Q4). Junk
  keys on this control-plane route can no longer succeed silently; documented
  senders (which use the real fields) are unaffected.
- **CLI: local `admin` commands no longer ask for a key ceremony (#590).** The
  subcommands whose bodies issue no request (the list is body-verified) skip the
  ceremony, which could neither authenticate them nor succeed against a core with an
  empty user table. The certificate checks are NOT skipped: a cert without its key, a
  key without its cert, and a nonexistent cert path still raise exactly as before.
- **Executor configuration states its precedence, and says when two spellings
  disagree (#598).** The ruled order is config file, then environment, then the field
  default. When one key is set in both carriers to different values, the start now
  names the key and the value in use instead of choosing silently.
- **The pip-audit hook names the feed it queried (#566, #568).** A clean result is now
  a statement about OSV, and a test pins the feed choice so that statement cannot
  rot.

### Removed

- **Removed: `venya admin set-command-policy --custom`.** The flag was inert
  surface (#289): it posted a `custom` key the API model does not define (and
  never even opened the file it named), so the server silently dropped it.
  Replaced by explicit `--custom-allowed` / `--custom-dangerous` (comma-
  and/or space-separated), each mapping 1:1 to a real API field; each list
  REPLACES its stored counterpart (replace-not-union), an omitted flag leaves
  the stored list untouched.

### Fixed

- **CLI: `exec register` verification carries the register-path trust (#395).**
  The post-register verify call now builds its TLS trust in the ruled order —
  config-dir CA if present, else the resolved `--ca-bundle`, else a loud
  error — so a config-less host that registered with `--ca-bundle` can verify
  instead of always hitting a certificate error. Verification failure now
  exits non-zero with the certificate kept and the wording
  `registered, auth NOT verified`; a verified registration still exits 0 with
  `registered successfully` as before. refs #395
- **Installer: interactive secret prompts now confirm at entry.** The core
  install's server encryption passphrase, PostgreSQL password, and both CA
  key passphrases, and the executor install's Docker access token, are read
  twice (echo-off) and retried until the entries match — a mistyped single
  entry can no longer silently become the stored secret. Unattended/env-supplied
  paths, stored-reuse match-or-abort behavior, and non-TTY branches are
  unchanged. (ticket 31-confirm-at-entry)
- **Executor: audit-spool forwarding durability hardening.** Three related
  improvements to the audit forwarder (refs #310). (1) When an event is
  appended while a batch is in flight and the spool crosses its capacity,
  the accepted batch is now removed BY CONTENT instead of by count, so lines
  that were never sent always survive the interleaving — a line leaves the
  spool only if it was forwarded or explicitly reported by the spool-full
  drop warning. (2) The spool is created 0600 on EVERY create path (previously
  only at startup), so a drain-to-empty followed by a new event no longer
  re-creates the file at the umask default. (3) Layered batch-cap interlock:
  `audit.max_batch_lines` now also validates against the server's ingest line
  cap (2000) at boot, and the forwarder additionally halves-and-retries a
  batch if a sink answers 413, so a lowered server cap degrades to split
  forwards rather than a stalled backlog. Behavior change to note: a
  hand-configured `max_batch_lines` above 2000 now refuses to load at startup
  with a clear error instead of booting into the retry-and-evict loop.
- **Server: a wrong encryption passphrase no longer boots silently.** The KEK
  derives from the passphrase plus a persisted salt, so a mismatch previously
  surfaced only at the first decrypt — while the wrong KEK could already wrap
  NEW DEKs, making secrets stored during that window permanently
  unrecoverable. A single-row KEK sentinel (fixed known plaintext wrapped
  with the SAME AES-256-KW envelope as secret DEKs — no new crypto format) is
  now unwrapped at every startup; a mismatch logs a loud CRITICAL error and
  aborts before any new wrapping can happen, value-free. Legacy installs
  without a sentinel fall back to sampling up to 5 stored DEK envelopes —
  only an all-fail verdict aborts, so one corrupt row cannot brick boot.
  Fresh empty installs boot with one WARNING (nothing to verify, nothing to
  corrupt). The sentinel is minted idempotently at the first successful
  crypto use (the single wrap-convergence point, Core.encrypt). Adds Alembic
  migration 032 (kek_sentinel table; model+migration together per repo rule).
- **CLI: `venya audit --json` now prints parseable JSON when the audit log is
  empty.** With zero events the command printed the human string
  "No audit events found." even under `--json`, breaking scripted
  consumption (e.g. `jq`). The `--json` branch now runs BEFORE the empty
  check and passes the API envelope through verbatim, so an empty log
  yields a parseable object with an empty `events` list — the same
  ordering `venya list --json` already uses. Non-empty `--json` output is
  byte-identical to before, and the human path (empty and non-empty) is
  unchanged.
- **CLI: `venya exec audit --json` now prints parseable JSON when the audit
  log is empty.** With zero events the command printed the human string
  "No audit events found for {executor_id}." even under `--json`, breaking
  scripted consumption (e.g. `jq`). The `--json` branch now runs BEFORE the
  empty check and passes the API envelope through verbatim, so an empty log
  yields a parseable object with an empty `events` list — the same ordering
  `venya list --json` and `venya audit --json` already use. Non-empty
  `--json` output is byte-identical to before, and the human path (empty and
  non-empty) is unchanged.
- **Executor: the `[audit]` forwarder is no longer a dead knob.** With a
  configured `remote_url` the forwarder previously sent unauthenticated POSTs
  no server endpoint accepted, and without one it went silently inert; now a
  configured forwarder authenticates with the executor's mTLS client
  certificate, refuses to send (loud error, spool lines kept) if that
  material is missing, and pairs with the new server ingest endpoint above.
  An unconfigured forwarder stays honestly inert (spool-only, no network).
- **Server: browser logout no longer swallows session-revocation failures.**
  When revoking the session fails, the server now logs the error, records a
  `session_ended` lifecycle audit row with `revoked: false`, and answers 503
  without clearing the session cookie — the user keeps the cookie as a retry
  handle instead of being told they logged out while the session stays live.
  Successful logout is unchanged (200, cookie cleared, `revoked: true`).
- **Server: admin create-user can no longer bypass the auditor separation-of-duties
  control (#302).** `POST /admin/users` minted role memberships by direct ORM,
  skipping the one enforcement point (core `RoleManager.add_member`), so a
  mixed {auditor + anything} grant succeeded through the admin path while the
  role-members endpoint refused the identical mixture — silently breaking the
  shipped AC-5 exclusivity control through the front door. Grants now flow
  through the chokepoint inside a savepoint: a refusal rolls back the pending
  user and partial memberships (complete-or-nothing — no phantom user, no
  phantom lifecycle audit row), records the same `auditor_sod_denied` event as
  the sibling path, and answers 409 with the same message.
- **Core: dropped the phantom FK on `executor_enrollment_tokens.created_by`
  (#303).** The model still declared
  `ForeignKey("users.user_id", ondelete="CASCADE")` although migration 022
  deliberately dropped `fk_executor_enrollment_tokens_created_by` (the
  column stores the auth principal verbatim regardless of mechanism —
  mTLS CNs have no `users` row); any future autogenerate/migration diff
  would hallucinate re-adding the dropped-by-ruling FK (sibling of #299).
  The declaration is removed (column stays `String(64)`, `nullable=False`);
  a pin test plus a sweep test that replays every FK drop in
  `alembic/versions` and asserts no dropped column re-declares an FK in a
  model close the whole drift class.
- **Core: dropped the phantom FK on `audit_events.user_id` (#299).** The
  model still declared `ForeignKey("users.user_id")` on `AuditEvent.user_id`
  although migration 022 deliberately dropped `audit_events_user_id_fkey`
  (the column stores the auth principal verbatim regardless of mechanism —
  mTLS CNs have no `users` row); any future autogenerate/migration diff
  would hallucinate re-adding the dropped-by-ruling FK. The declaration is
  removed (column stays `String(64)`, `nullable=True`); a pin test inspects
  the model so the drift class cannot re-widen.
- **CLI: CA-key custody round-trip works on encrypted-at-rest installs
  (#297).** Since encrypt-at-rest (4218ec1/3667c6e), `venya admin
  export-ca-key` / `split-ca-key` read `ca.key` as plaintext, exporting/
  splitting the at-rest ciphertext instead of the key, and `restore-ca-key`
  could never re-install its own export (the #39 validator correctly aborted
  — the documented custody escrow promise was unfulfillable; DR drill R6-b).
  Export/split now unwrap the server's PKCS#8 at-rest envelope (in memory,
  plaintext never persisted) before wrapping/sharding; restore re-encrypts
  into the envelope with an atomic write (temp + rename, 0600, ownership
  preserved, byte-identity on abort). Server passphrase acquisition: hidden
  getpass primary, `VENYA_CA_KEY_PASSPHRASE` /
  `VENYA_ADMIN_CA_KEY_PASSPHRASE` env override for automation; paths are
  key-agnostic (`ca.key` or `admin-ca.key` via `--ca-dir`). Wrong server
  passphrase is LOUD at all three sites with zero writes/zero shards.
- **CLI: role subcommands honor their "Role ID or name" promise.** `venya
  role get|delete|members|add-member|remove-member` previously interpolated
  the raw `role_id` argument into the int-validated `/api/v1/roles/{role_id}`
  path, so every NAME died with a raw 422 dump. All five handlers now share
  ONE resolver: int IDs pass through untouched, names are looked up in
  `GET /api/v1/roles` with a case-folded match (mirroring the server's
  lowercased-name convention), and an unresolvable name exits 1 with a clean
  error naming the lookup.
- **CLI: `venya store --roles a,b` now actually means TWO roles.** `cmd_store`
  passed the raw token(s) into the secret payload, so a comma-separated
  `--roles` list reached the server as ONE role name ("Role not found:
  a,b") while the sibling `admin create-user --roles` split correctly.
  Store now splits AND strips every comma token (space-separated tokens keep
  working); help updated to say "comma- and/or space-separated".
- **CLI: CA-key restore is fail-closed on content.** A wrong-passphrase
  restore from a legacy (pre-canonical) backup blob previously passed with
  ~1/256 probability (padding coincidence) and silently wrote corrupt key
  material behind a success banner. Restored data is now validated as a
  parseable PEM private key before anything is written to disk, in both
  backup and shares restore modes.
- **Server: enroll-complete session honors the configured session settings.**
  The browser enrollment completion handler built its session with core
  defaults (`SessionManager(db)`), silently bypassing the operator's `session`
  config (idle timeout / access-token TTL / max duration) that every other
  session-creation path (login, refresh, browser login, middleware) already
  honored. It now constructs the session from
  `request.app.state.config.session`, mirroring the login path. Paired guard:
  `session.session_timeout` greater than `session.max_session_duration` now
  fails config validation loudly at startup (nothing else validated that
  pairing).
- **GET /secrets/{key} now passes the caller's role names to core.get.**
  The GET route omitted the `role_names` argument that `_resolve_secret_in`
  uses as the visibility contract, so every role-scoped secret 404'd for
  non-creator role-holders (masked AND unmask) while LIST correctly showed
  it. Role names are resolved once per request (same idiom as LIST) and
  passed at all three core.get call sites; scoped-out keys stay
  404-indistinguishable from nonexistent ones, and a visibility 404 on the
  unmask path still never burns the elevation token (rollback pin test).
- **Rotated executor certificates no longer leak their HTTP clients.**
  Cert rotation rebuilt the mTLS client and swapped it into the daemon,
  cert manager, and reaper, but never closed the pre-rotation client — its
  connection pool and TLS session (holding the now-revoked cert) lingered
  until daemon stop. The outgoing client is now closed as the last step of
  the swap, and a close failure is warned-about, never rotation-aborting.
- **Adding a second security key no longer fails with a CTAP error.**
  `venya credential add` (and any PIN-only-key registration carrying
  excludeCredentials) died at the key with `CTAP 0x11 CBOR_UNEXPECTED_TYPE`:
  the CLI's raw CTAP path read the credential/user id bytes back through
  python-fido2's JSON view, which re-encodes bytes as base64url STRINGS —
  the authenticator requires byte strings. Those fields now cross to the
  key as bytes (the library's own CTAP convention); users with zero
  existing credentials were never affected, which is why first-time
  init/enroll worked.
- **CLI: `set-command-policy` custom lists actually reach the server (#289).**
  The dead-key payload (a `custom` path string pydantic silently dropped) is
  gone; the command now posts only real `AdminSetCommandPolicyRequest`
  fields, and a drift-guard test pins every postable CLI key against the
  server model so this dead-payload-key class cannot ship again. The GET
  docstring's stale "server→executor propagation is not wired" claim was
  corrected — propagation is wired (861a682) and the row enforces fleet-wide
  via heartbeat.
- **Installer: fresh executor installs fail fast without an enrollment token
  (#28).** A missing or empty `VENYA_EXECUTOR_ENROLLMENT_TOKEN` on an install
  with no incumbent `/etc/venya/executor/executor.crt` now exits 1 with
  minting guidance (`venya admin executor-enroll <id>`, single-use, ~30-min
  TTL) before any system write, mirroring the `VENYA_SERVER_URL` Require
  block; re-runs over an existing certificate proceed tokenless as before.
-- **Installer: confirm questions no longer print before the skip check
   (#389).** `venya_prompt_gate` now runs before `Install to ...? [Y/n]` and
   `Reinstall? [y/N]` are emitted: with `VENYA_SKIP_PROMPT=yes` the documented
   default is taken silently with zero question lines; a non-TTY run without
   the flag exits loud with guidance instead of consuming EOF defaults; the
   interactive TTY path is unchanged. The #203/EXEC co-location hard stop is
   untouched and still refuses regardless of the skip flag.
- **`GET /api/v1/audit` applies the `key=` filter it accepts (#607).** The clause was
  collected and never applied, so a disclosure or a denied secret read could not be
  found by the key it names. It is cast against the same JSON operator idiom the
  `executor_id` filter already uses; the self-filter for non-privileged callers is
  unchanged and proven by its own cell.
- **The relay listener presents rotated certificate material on new connections
  (#579).** The mTLS context is published to the accept path and rebuilt from the
  on-disk material, so a rotation reaches the `:8443` side instead of leaving that
  door on its boot-time context.
- **Migration 039 gives two declared CASCADEs a real `ON DELETE` (#591).**
  `execution_sessions.user_id` and `role_members.role_id` carried cascade semantics
  the schema never had, so a path that trusted the declaration — an ops clear, an
  offboarding script, your own SQL — met an FK violation instead of a cascade.
- **CLI: `venya store --help` renders its default the way argparse displays it
  (#604)**, and the generated reference agrees with the shipped text.
- **Windows installer: the DAcl enumeration no longer walks a wildcard path (#493).**
- **Elevation repair strings name the real command (#583)** instead of a form the CLI
  does not accept.
- **The docs read the way the tip behaves (#563 follow, #600, #601, #605, #609, #615).**
  The disclosure and secret-lifecycle claims now state the mechanism the code
  implements; `BACKUPS.md` names the shipped authenticated envelope and says which
  blob an operator is holding; the CA-key comments describe the CLI-only codec, the
  server pair having been retired; the re-run, rotation and beta-terms pages match
  what the installer does today; and the served README and `installation.md` name the
  passphrase minimum.

### Security

- **Executor mTLS key is encrypted at rest on every write path (#565).** The
  executor's own leaf key (`/etc/venya/executor/executor.key`) was serialized
  unencrypted by all four of its writers — the daemon's registration and rotation
  paths, and the workstation CLI's `venya exec register` / `venya exec cert renew`
  — and none of the readers could answer a passphrase. They now write a PKCS#8
  `BestAvailableEncryption` envelope keyed by `VENYA_EXECUTOR_KEY_PASSPHRASE`, and
  every reader (the daemon's control-channel client, the boot identity probe, the
  relay listener, the audit forwarder, the boot certificate/key pair gate, and the
  CLI's own renew/heartbeat dials) opens it. A writer with no passphrase configured
  refuses BEFORE it generates a key or sends a request, so nothing is written and an
  enrollment token is not consumed. Keys written by earlier releases are plaintext on
  disk and keep loading unchanged — the requirement lands on the next write. This is
  disk protection by a file passphrase, not hardware-key custody; the interim shape
  and its retirement trigger are recorded in `docs/cert-rotation-runbook.md` §2 and
  `docs/design-fido2-keywrap-565.md` §6. refs #565
- **End-to-end mTLS: client identity is crypto-verified at the app.** Admin
  and executor mTLS now read identity from the client certificate the app
  verifies itself (forwarded by nginx over the new inner nginx→uvicorn mTLS
  channel as a per-connection certificate file), replacing the
  `X-Client-Verified`/`X-Client-Subject`/`X-Client-Serial` header chain. The
  app serves TLS with required client certificates when
  `VENYA_INNER_MTLS__ENABLED=true`, so a direct app-port connection stops at
  the handshake; per-plane CA binding (admin stage vs admin CA, executor
  stage vs Root CA) refuses cross-plane certificates at the chain check.
  Header-based identity reads no longer exist in the server package
  (interlock test pins the posture). refs #314
- **IAM: `auditor` permission tier.** Roles can now be created with
  `permissions="auditor"` (API, CLI `role create --permissions auditor`).
  Auditors keep the read-tier listings (secrets/roles/executors metadata)
  and gain audit-log visibility, but NEVER satisfy read-write gates (no
  secret create/delete, no session create, no command execution) and never
  reach admin routes.
- **Secret values deny auditors at the chokepoint.** An auditor-only caller
  (ALL memberships auditor-tier; a union with any other tier keeps its
  rights) receives a 403 on any secret-value read — enforced inside the
  masked-get unmask path BEFORE the single-use elevation token is consumed,
  so denied attempts never burn tokens. Every denial is audit-logged
  (`auditor_secret_read_denied`, value-free fields; the audit-write itself
  can never turn a denial into an allow).
- **Elevation tokens are not issued to auditor-only callers.** Both elevate
  assert endpoints (CLI/API and browser) 403 before creating the token, and
  audit-log the refusal (`auditor_elevation_denied`).
  Because the same token gates self-service security-key registration
  (`credential add`), an auditor cannot add their own credential: an
  administrator provisions it (the tiers being exclusive means a
  second non-auditor role is not an option either — release-notes item).
- **The auditor tier is EXCLUSIVE by design (separation of duties).** A
  role grant (`POST /roles/{id}/members`) or role tier flip
  (`PUT /roles/{id}`) that would make one user hold `auditor` together
  with any other tier is refused with 409 and audit-logged
  (`auditor_sod_denied`, value-free fields; the refusal stands even if the
  audit write itself fails). Auditor+auditor remains legal; the tier ships
  for the first time with this rule, so no mixed state can pre-exist. The
  union permission math is unchanged underneath as defense-in-depth.
  Aligned with NIST SP 800-53 Rev 5 AC-5 (Separation of Duties); the
  audit-logged denials above provide evidence for NIST AU-3/AU-6 and PCI
  DSS 10.2.1. Aligned — not certified: attestation requires an assessor.
- **Behavior change: the audit log is auditor-scoped.** `GET /api/v1/audit`
  moved from the read tier to the auditor gate: plain `read`-only users are
  now 403 there (auditor and read-write/admin retain access). Auditor-tier
  holders see the FULL log — other users' events included — the same
  visibility the `admin` role holds; every other non-admin caller keeps
  the self-filter to their own events.
- **The relay asks the revocation question at both ends it can answer (#586).** The
  core's dial to an executor now consults the certificate revocation list at the TLS
  handshake: a revoked leaf is refused and the refusal says revoked, while a stale or
  unreadable list is refused with a 503 whose text says "no revocation asserted" and
  never claims a revocation that did not happen. On the other side, the executor's
  relay accept gate (`revocation_accept_reason`,
  `packages/executor/src/executor/relay_listener.py`) refuses a new `:8443`
  connection while THIS daemon's own credential is revoked server-side or has
  received no revocation answer since boot — it fails closed on "cannot tell", and
  the two answers stay distinct status strings. What a peer's credential can still do
  at that door is written up in `docs/beta-known-limitations.md`.
- **Plane markers on Venya certificates are carried non-critical and enforced by the
  app (#588), and now mint on Tabith LLC's registered enterprise number (#601).** The
  marker OID moved to the project's own PEN; the reader accepts the earlier arc for a
  bounded window so credentials already in the field keep resolving.
- **The CA and certificate directories are tighter at creation and across re-runs
  (#606, #610).** `/var/lib/venya/ca` and the admin CA directory are created 0700 and
  pinned back to 0700 on every run, so an interrupted install never leaves them
  group-readable.
- **A passphrase that will not open a stored key says so in Venya's words, at one
  home, naming the real file (#569, #572, #574, #576).** A damaged key file is no
  longer blamed on the passphrase: which refusal you get is chosen by whether the
  BYTES PARSE, not by whether an input was supplied (#577).
- **The MCP client transport requires an explicit verify anchor (#571).** The
  constructor seam refuses an unanchored configuration before any transport exists,
  rather than falling back to a system store.

## [0.1.0alpha16] - 2026-09-27

### Added
- **Docs: deployment sizing guide.** `docs/deployment-sizing.md` — how many
  executors you need and the measured CPU/RAM/disk/throughput figures behind it
  (concurrent-session sizing + serial-path benchmark numbers).
- **CLI: factory-fresh security keys can now be registered.** A key whose
  PIN has never been set (CTAP2 `clientPin: false`) previously dead-ended
  `venya init` / enroll / `credential add` with a misleading "neither
  built-in UV nor clientPin" error. The CLI now detects the unset PIN and
  walks the operator through creating one (double entry, 4-63 bytes,
  validated client-side, no retry-counter burn), sets it over the CTAP2
  encrypted handshake, and continues registration without re-prompting.
  Windows platform ceremonies are unchanged (PIN lifecycle there remains
  the operator/vendor-tool step, per the documented Windows guidance).
- **CLI: `venya list --json`.** The secrets list now supports the same
  `--json` flag as `audit`, `admin list`, and `exec list`, emitting the API
  envelope byte-exact (`{"secrets": [...]}` — parseable even when empty;
  keys and metadata only, never values). Human table output is unchanged
  without the flag.
- **Installer: upgrade-aware core re-runs.** The core installer now reports
  the version transition (`Upgrade: X -> Y`), refuses downgrades unless
  `VENYA_ALLOW_DOWNGRADE=yes` (alembic migrations never reverse
  automatically — old code on a newer schema is unsupported), and takes a
  compressed `pg_dump` backup to `/var/backups/venya/` before running
  migrations on any version-changing re-run (failure aborts the upgrade;
  the 3 newest backups are kept). Operator-added `VENYA_*` keys in
  `/opt/venya/.env` now survive re-runs — the template owns only its 13
  managed keys; preserved lines are re-appended under a marker comment.
  Unattended re-runs no longer demand `VENYA_DB_PASSWORD`: the stored value
  is reused like the other four secrets (an explicitly-passed mismatch
  still aborts; fresh installs unchanged).
- **Executor installer: the sbx agent template is warmed at install time.**
  A throwaway `sbx create`/`sbx rm --force` pair (after Docker auth and the
  deny-all policy init) caches the multi-GiB template, so the first relayed
  command on a fresh executor is seconds-scale instead of ~60–90 s. Warm
  failure is non-fatal (loud warning; first run falls back to the cold path)
  and is skipped under `VENYA_SKIP_DOCKER_LOGIN=yes`. The installation
  troubleshooting entry claiming the first run "times out client-side" is
  corrected — that has not been possible on default timeouts since the
  alpha13 fuse chain (create cap 240 s < relay 300 s < nginx 330 s <
  client 340 s).
- **Central command policy now ENFORCES fleet-wide.** `venya admin set-command-policy` / `add-allowed-command` previously wrote a policy row with zero consumers — executors enforced only their local `/etc/venya/executor.toml`, so the admin commands silently affected nothing. The core's "default" policy now propagates as an additive field on executor registration and heartbeat (~30 s) responses and is hot-applied through the command validator. Semantics mirror the local config exactly: the preset drives trusted-path behavior (balanced/strict/permissive), an explicit dangerous-pattern list replaces the built-ins, null keeps them. A corrupt or absent policy never kills the heartbeat and never reverts a live policy mid-run (last applied persists until daemon restart, which re-bootstraps from toml). Policy changes are audit-logged (`command_policy_changed`, attributed to the acting admin). Old daemons ignore the field — wire-compatible both directions.

### Fixed
- **Executor registration now activates the `users`-side identity row.**
  The auto-created account inherited the human default `pending_enrollment`
  and was never flipped (the transition lives in the WebAuthn enrollment
  path machine identities never traverse), so `venya admin list` showed
  working, heartbeating executors as pending enrollment. New registrations
  are born `active` with `enrolled_at` set; re-registration self-heals
  stranded rows; a data migration backfills existing installs
  (`auth_mode='mtls'` rows only — human enrollments untouched).
- **Every `venya admin` mTLS command TypeErrored in the natural flow** (config CA from `venya setup` + `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY`, no `SSL_CERT_FILE` exported): httpx2 >= 2.12 rejects `cert=` combined with a string `verify`, so the client died with a cryptic constructor error before any request was sent. The CLI now builds a single `ssl.SSLContext` carrying both the server-trust anchors (`SSL_CERT_FILE` > setup-installed CA > system store — precedence unchanged) and the admin client cert. Affects alpha14–alpha15; masked in the documented runbook flows because they export `SSL_CERT_FILE`. **Workaround on older releases:** `export SSL_CERT_FILE=<venya ca.crt>` before admin commands.
- `venya store` piped-stdin values are now stored BYTE-EXACT (no trailing-newline stripping). The previous behavior corrupted PEM private keys (`--shape ssh-key`): OpenSSH >= 10 refuses to load a key whose armor file is not newline-terminated (`Load key: error in libcrypto`), so a key stored via `venya store key - < keyfile` was unusable at consumption time with no in-product remedy. Line-based consumers (`sshpass -f`, `sudo -S`) and output masking (trimmed-hash filter variant) tolerate a trailing newline, so single-line password secrets are unaffected.
- Corrected the no-PIN security-key error guidance: the stale "set a PIN with yubikey-manager" advice now points at Venya's own in-registration PIN creation; keys reporting PIN support with no PIN set get power-cycle/re-run guidance.

### Changed
- **Usage-template authoring:** canonical `sudo -S` templates over ssh must NOT carry `-p ''` — ssh re-joins remote arguments without re-quoting, the empty argument vanishes, and remote sudo swallows the next token as its prompt string (usage error, exit 1; field-proven). The sudo prompt text appearing in stderr is harmless and carries no secret. ssh-based templates SHOULD carry `-o StrictHostKeyChecking=accept-new` — every sandbox starts with no `known_hosts`, and without the option the first connection can fail silently (sshpass exit 6, empty stderr); changed host keys are still refused. Both documented in the operator-rule section of `architecture.md`; the exit-6 diagnostic also joins the `agent-prompts.md` paste-block.
- MCP `list_secrets` now renders stored `host` metadata beside `username`, so an agent can fill a usage template's `{host}` placeholder from the listing alone instead of relying on the human's prompt to name the target (field omitted when no host is stored).
- **Behavior change for pipers:** `echo "pass" | venya store key` now stores the trailing newline with the value — use `printf %s "pass" |` for byte-exact single-line values. `--help` text and the generated CLI reference updated to match.
- Executor-installer relay-wiring summary reworded to describe the empty-allowlist/CN-mismatch outcomes as the intended secure behavior — copy-only.

## [0.1.0alpha15] - 2026-09-25

### Added
- New `docs/agent-prompts.md` — a paste-ready operating contract for customer AI agents (AGENTS.md / CLAUDE.md / Cursor rules), linked from the README banner + docs table, installation §6, and agents.md. An interlock test pins the block's claims (tool names, redaction marker, injection path, 401/503 behavior) to the live MCP tool surface so the prompt cannot silently rot.

### Changed
- Test fixtures and docs no longer embed development-fleet addresses or identities: private-range (RFC1918) literals swept to documentation ranges (RFC 5737), `dust@montana` → `admin@example.com`, dev password probe → synthetic. A tree-wide interlock test now fails CI if any RFC1918 literal re-enters `packages/` or `docs/` (installer-artifact guard extended; CHANGELOG and the guard's own self-test excluded). No product behavior change.

- **BREAKING — Executor: the built-in DNS-resolver default is removed; `dns_resolver`
  is now explicit config.** The sandbox egress policy previously always admitted a
  hardcoded resolver IP (`10.27.28.1` — a development-fleet address, functionally
  dead on any other network). Now set `dns_resolver = "<your resolver IP>"` in
  `/etc/venya/executor.toml` — fresh installs take it from the required
  `VENYA_DNS_RESOLVER` installer knob (re-runs reuse the stored value) — or
  `VENYA_EXECUTOR_DNS_RESOLVER` in the service environment. An executor without it
  REFUSES TO START with a named error (by design: Venya never guesses your network).
  Find your resolver with `resolvectl status` or `grep nameserver /etc/resolv.conf`.
  **Upgrading:** add the key to `/etc/venya/executor.toml` BEFORE restarting the
  executor.

- **CLI: `venya admin enroll --mode` and `venya admin configure-user --mode`
  removed.** The flag advertised a platform-authenticator enrollment mode
  (e.g. Windows Hello) that did nothing: no authentication path ever read the
  stored `auth_mode` value, and enrollment completion overwrote it to
  `webauthn` regardless. Platform authenticators are not offered at this time.
  The server API is unchanged (the `auth_mode` field and its default remain;
  `venya admin list` still displays stored values). Scripts passing `--mode` —
  including the former default `security-key` — now fail with a usage error
  instead of silently doing nothing.

- **Executor: `dns_resolver` and `egress_allowlist_path` config knobs now take
  effect.** Both were loadable from `/etc/venya/executor.toml` (or the
  `VENYA_EXECUTOR_DNS_RESOLVER` / `VENYA_EXECUTOR_EGRESS_ALLOWLIST_PATH` env
  keys) but had no readers — the sandbox network policy used hardcoded values.
  Defaults are unchanged; operator overrides are now honored.

- **Installer: fresh executor installs no longer seed the development fleet's
  subnet into the sandbox egress allowlist.** `/etc/venya/egress-allowlist.txt`
  is now written empty by design (fail-closed: all sandbox egress blocked
  except DNS) with in-file guidance, and can be seeded explicitly at install
  time with `VENYA_EGRESS_ALLOW` (comma/space-separated IPs, CIDRs, hostnames;
  any invalid entry aborts the install loudly — a partially applied allowlist
  is never written). A standing interlock test fails if a private-range
  literal returns to any shipped installer script. **Installed a release
  before this fix?** Check `/etc/venya/egress-allowlist.txt`: releases through
  `v0.1.0alpha14` seeded `10.27.28.0/24` — a development-fleet subnet that is
  not yours. Delete it or replace it with your own target ranges; the file is
  read at sandbox creation, so no restart is needed.

### Fixed
- MCP `list_secrets` output now carries what its tool description promised: each secret's numeric id and — when stored — its `shape` and `usage` metadata. `{secret_path}`/`{secret_id}` placeholders in usage templates are resolved renderer-side to the injected sandbox file path (`/run/secrets/venya/<id>`), so agents receive a ready-to-run command template instead of having to substitute placeholders themselves; `{host}`/`{user}` stay as authored (task-context). Secret values remain unreachable, and description pins now fail CI if the promise and the rendering drift apart again.

## [0.1.0alpha14] - 2026-09-23

- **Supersede of `v0.1.0alpha13` (packaging defect — product code IDENTICAL;
  the `packages/` delta is version literals only)**: alpha13's GitHub
  installer-script ASSETS (`install-venya-core.sh`, `install-venya-executor.sh`,
  `install-venya-cli.sh`, `install-venya-cli.ps1`) were uploaded from the
  LAN-mirror build directory and carried a rewritten default `TARBALL_URL`
  pointing at a build-network address — installs outside that network aborted
  at the tarball fetch (fail-closed, loud; workaround `VENYA_TARBALL=<github
  url>`), and the rewrite exposed private network addressing. The tarballs and
  sidecars were canonical and hash-verified; the repository files at the tag
  were always correct. The defective alpha13 release was DELETED from GitHub
  by owner order ~1h after publishing (no known consumers); this version is
  the canonical release of that code. Publish flow fixed: script assets are
  now extracted from the tag itself and hash-checked against tag bytes before
  upload.
- **Private-infrastructure scrub of the published tree**: release tarballs are
  whole-tree archives, so the E2E harness and docs previously published lab
  coordinates (build-mirror addresses, workstation paths, a dev DB password in
  harness defaults). All such values are now `VENYA_TEST_*` environment
  parameters with loud skips/errors and NO built-in defaults; docs use
  placeholders. No product behavior change.

## [0.1.0alpha13] - 2026-09-23

> **Note:** the `v0.1.0alpha13` GitHub release was DELETED by owner order
> shortly after publishing — its uploaded installer-script assets carried a
> build-network origin rewrite (private-address exposure; broken installs off
> that network). The code content of alpha13 ships, unchanged, in
> `v0.1.0alpha14`; the section below is retained as the accurate record of
> that content.

> **Backfill note (recorded late):** every UNMARKED entry in this section
> shipped in `v0.1.0alpha12` but was absent from its CHANGELOG section — the
> squash-at-tag-cut flow only collects what merges had already added to
> `[Unreleased]`, and these merges shipped code without an entry. Found by the
> completeness audit of `v0.1.0-alpha.11..v0.1.0alpha12` (51 merges classified
> covered / entry-not-required / gap — ticket
> `changelog-alpha12-completeness-gap`). The published `[0.1.0alpha12]` section
> is immutable and is NOT edited. Entries added after the backfill are marked
> *(post-alpha12)*.

### Security

- *(post-alpha12)* The Stage-2 output filter (the definitive masker) no longer
  answers `200` with unmasked output for unknown or vanished sessions. The
  executor treats the Stage-2 response as authoritative over its own local
  masking, so an empty-knowledge passthrough could discard Stage-1
  `[REDACTED:…]` masking and return plaintext secret values to the caller —
  reachable through a proven race (the 10-minute TTL reaper deletes session
  rows while a long command is still running). Unknown sessions now answer
  `404` and the executor falls back to its own masked result: masking can
  degrade to one stage, never to zero. Sessions that exist with zero bound
  secrets still answer `200` (legitimately nothing to mask).
- Executor session endpoints (`/api/v1/sessions/{id}/filter`, session-secret
  revoke) now require a verified executor mTLS identity — client certificate
  checked against the registration record and revocation state — instead of
  granting executor context from the URL path with no credential check. Audit
  events on these paths carry the executor identity.
- Admin mTLS hardening: the admin-certificate allowlist fails closed (an empty
  allowlist no longer means "allow"), and admin-certificate revocation is
  checked in-process — a revoked admin serial answers 403 "Admin certificate
  revoked".
- The CLI's executor-heartbeat transport rejects `http://` server URLs outright
  (exit 1 with the named requirement, before any transport is built):
  executor-identifying state no longer POSTs in plaintext. `VENYA_TLS_VERIFY`
  covers distrusted certificates over https — it never means "no TLS".
- The public revocation endpoints (revocation-list and CRL GETs) are now
  read-only — they previously purged expired entries on read (a write-on-read
  path on unauthenticated endpoints); the purge moved into the authenticated
  maintenance loop.
- Exception-detail leaks eliminated: client-visible error details are limited
  to audited exception classes (internals go to the journal only), the
  dead-letter debug exemption was removed from the DB-passphrase boot check,
  and nginx now runs `server_tokens off` (no version disclosure in the
  `Server` header).
- Removed debug log scaffolding that leaked raw session cookies to the journal.

### Changed

- *(post-alpha12)* **Remote sudo with a password** is now a runnable shape
  (user-ruled: corporate targets almost never grant NOPASSWD sudo). The
  structural gate gains ONE narrow exception: a standalone `<` token
  immediately followed by an exactly-matching session-bound secret path
  (`/run/secrets/venya/<id>`) is permitted, so the password can flow over ssh
  stdin to a remote `sudo -S`. Every other `<` form (`<<`, `<>`, `<&`, fused,
  quoted, trailing), unbound/prefix-trick/relative targets, and every other
  metacharacter remain rejected whole-string (the 2026-09-16
  unconditional-gate ruling is intact; full truth table re-run). Canonical
  shape: `sshpass -f /run/secrets/venya/<id1> ssh <user>@<target> sudo -S
  -p '' <cmd> < /run/secrets/venya/<id2>`. `shape=sudo-stdin` loses its
  declarative-only warning (mechanism shipped; the pending set is now empty).
- *(post-alpha12)* **env-shape and askpass secrets now EXECUTE**: a secret
  stored with `--shape env:NAME` has its value injected into the sandbox
  environment as `NAME`, carried by a 0600 host-side env file passed via
  `sbx exec --env-file` — values never ride host argv (the former `-e K=V`
  transport exposed them in `/proc/<pid>/cmdline` for the command's duration
  and is gone), and the file is zeroed the moment the command returns.
  Consumption is via tools that read their environment IMPLICITLY (aws,
  kubectl via `KUBECONFIG`, psql via `PGPASSFILE`, docker via
  `DOCKER_CONFIG`): a command can never reference `$NAME` itself — `$` is a
  blocked metacharacter. `--shape askpass` wires `GIT_ASKPASS`/`SSH_ASKPASS`
  to a static in-sandbox helper that prints the injected credential file
  (username comes from the `username` metadata). The relay wire gains
  OPTIONAL `env`/`askpass_helper` fields (coordinated contract change): the
  server version-gates on the executor's heartbeat-reported build — older
  executors get an actionable 422 naming the upgrade instead of a mystery
  502 — and regular (file-shape) traffic keeps the exact pre-env wire shape.
  Multi-line values are rejected at store AND execute time (the env-file
  format is line-based). `sudo-stdin` remains declarative-only pending its
  gate work.
- *(post-alpha12)* Secret **shape metadata**: `venya store` and
  `venya update-metadata` gain `--shape` and `--usage` flags (equivalently
  `-m shape=… -m usage=…`) declaring how a secret is meant to be consumed —
  e.g. `--shape ssh-key --usage 'ssh -i {secret_path} -o IdentitiesOnly=yes
  {user}@{host} <cmd>'`. The server validates the convention at store and
  metadata-update: usage templates interpolating the secret VALUE (`{value}`
  and friends) are rejected with a 400 that names the path-only rule and why
  (values in command text persist UNMASKED in the audit log); unknown shape
  names are accepted as CUSTOM shapes with a teaching warning; unknown
  placeholders warn. Shapes whose consumption mechanism has not shipped yet
  are accepted but answer with a DECLARATIVE-ONLY warning that points at the
  file path that DOES work — a label must never imply capability the product
  lacks (that set was `env:NAME`, `askpass`, `sudo-stdin` when this entry was
  first written; the env and askpass mechanisms ship in this same unreleased
  train — see the entry above — leaving `sudo-stdin` as the only pending
  label). `venya list` shows the shape. MCP `list_secrets` and
  `run_command` descriptions now teach agents the injected-file pattern
  (`/run/secrets/venya/<id>`) and usage templates — the previous
  `run_command` example showed a command that could not consume its bound
  secret at all.
- nginx relay timeouts raised to 330s at the server level of the core site
  config (the 300s server→executor relay ceiling + 30s margin): a cold-sandbox
  command taking >60s previously answered an nginx 504 while the command still
  succeeded executor-side (a client retry meant double execution); now the
  server's clean `503 "Executor timed out"` wins at the boundary. Existing
  cores need an installer re-run to regenerate the site config.
- Execution-session lifecycle: the 10-minute TTL is now actually reaped (every
  5-minute maintenance pass, FK-ordered deletes), and post-relay bookkeeping
  tolerates a session row that vanished mid-execute (bulk UPDATE no-op +
  WARNING instead of `StaleDataError` → 500 after the command already ran).
- Installer re-runs now restart stale services: a running process older than
  the just-deployed bytes is detected (both timestamps printed as a NOTICE),
  restarted, and proven with a PROOF-OF-FRESH-BYTES line — absence of the
  proof means do not trust the install. Previously a re-run swapped packages
  under the live process and "verified" the OLD bytes.
- Installer hardening: apt steps wait for the dpkg lock natively
  (`DPkg::Lock::Timeout`, default 120s, override `VENYA_APT_LOCK_TIMEOUT`) and
  surface the error tail + keep the log on failure instead of dying silently;
  host Python requirements are pinned to `uv.lock` (regenerate:
  `scripts/pin-requirements.sh`, enforced by pre-commit) so installed
  dependency versions can no longer drift from the lockfile.
- Version surfaces single-sourced: `venya --version`, the health endpoint
  `"version"`, FastAPI/openapi, `venya-executor --version`, and the
  heartbeat-reported `executors.version` column all read package metadata via
  `importlib.metadata` — no independent version literals left to drift, and
  per-executor build drift is fleet-visible without SSH.
- The executor bootstrap enrollment token moved to a read-write canonical path
  (`/var/lib/venya/executor/bootstrap-token`), out of the read-only-hardened
  `/etc/venya` tree — daemon-side deferred registration no longer bricks on
  token cleanup (EROFS). The legacy `executor.toml [bootstrap]` location is
  still read-honored; a failure to clear is a loud ERROR + PROCEED.

### Fixed

- *(post-alpha12)* **`venya run` / MCP `run_command` no longer abandon long
  sandbox runs at 30s**: the execute call's read timeout now defaults to
  **340s**, keeping the client the LAST fuse in the chain (server→executor
  relay 300s < nginx 330s < client 340s) so a clean upstream error always
  beats a local timeout. The first run on a fresh executor (~65s cold sbx
  template pull) previously died client-side as `Request timed out` while the
  server completed it correctly — and the natural retry executed the command a
  second time. `VENYA_EXECUTION_TIMEOUT` (positive integer seconds) overrides
  and is now actually wired to the execute path — it was previously read only
  by the executor-register transport, where it did nothing for runs (register
  keeps a fixed 30s).
- *(post-alpha12)* Rate-limit `429`s now carry `Retry-After` (delta-seconds) on
  all four middleware paths — auth tier, generic tier, break-glass hourly, and
  the break-glass failure backoff (seconds until the window resets / the
  backoff expires). Previously only the route-level registration and
  token-generation limiters set the header; middleware 429s left client backoff
  as guesswork.
- Alpha-QA sweep bundle (shipped in `v0.1.0alpha12`, recorded late; per-item
  detail via `git log --merges v0.1.0-alpha.11..v0.1.0alpha12`): the broken
  `venya fido2 enroll` command was deleted; credential removal now evicts
  stored sessions; registration 500s fixed (PIN-only authenticator
  attestation; registration-start with an existing credential); `venya init`
  is idempotent over existing roles (no raw UniqueViolation, no leaked SQL);
  the daemon heartbeat queue gained a backpressure guard; the CLI gained a
  headless admin-mTLS gate; WebAuthn credential IDs are consistently
  base64url-encoded; CLI enroll token-output bundling; core-installer
  DB-password guard; executor-installer sshpass provisioning; the executor
  installer's empty-token warning now names the real rejection mechanism; the
  admin executor listing reads revocation from the single authoritative
  source.

- *(post-alpha12)* **`venya init` now works with clientPin-only security
  keys** (keys with no built-in user-verification, e.g. TrustKey T120 class):
  registration dispatches on the key's advertised options and drives the raw
  CTAP2 clientPin path for such keys — the same spec-canonical path
  `venya login` has always used — instead of the high-level library ceremony,
  which mishandled them and surfaced as a cryptic
  `(<ERR.BAD_REQUEST: 2>, CtapError('CTAP error: 0x31 - PIN_INVALID'))` that
  burned one key PIN-retry per attempt. Wrong-PIN handling on registration now
  retries (3×) with a friendly message instead of leaking the raw tuple. A
  failed first-admin ceremony no longer bricks retry either: an abandoned
  PENDING enrollment (e.g. from a key-less `venya init` attempt) is superseded
  by the next plain `venya init <user>` — `--installation-reset` is no longer
  required for that state (it remains the path for a COMPLETED admin; that
  409 is unchanged).
- *(post-alpha12)* Operator-facing fix bundle from the Gavin field reports and
  the session sweeps (per-item detail via `git log --merges
  v0.1.0alpha12..v0.1.0alpha13` — see the release commit's ticket list): the
  installers REFUSE co-location — installing the executor on a host that
  already runs a core (or vice versa) exits 1 with the detection evidence
  before any prompt, and `VENYA_SKIP_PROMPT` does not bypass the guard
  (same-component re-runs stay supported); `venya exec register` honors the
  configured executor-id and accepts the enrollment token via
  `VENYA_EXECUTOR_ENROLLMENT_TOKEN` (off argv), with consistent
  `--server-url`/`VENYA_SERVER_URL` naming; the executor installer gained a
  non-fatal dial-address pre-check with the remedy recipe, actionable
  health-probe 401 diagnostics, and enrollment-token expiry guidance; unbound
  installer env vars no longer crash mid-install; bare `GET /health` aliases
  `/api/v1/health` (unknown paths still 401); `venya admin
  get-command-policy` works (the CLI GETted a POST-only route — 405 since the
  command shipped; the GET reports the stored policy or honest defaults and
  never mutates); `venya-executor --version` prints the bare version (no
  `venya-executor ` prefix); the uninstallers are fully self-contained (the
  LAN-default fetch is gone — uninstall is 100% local).

### Added

- *(post-alpha12)* `venya setup` — one command points the CLI at a core and
  installs its CA certificate: saves the server URL to the CLI config and
  fetches the root CA from `/.well-known/venya-ca.crt` beside the config,
  replacing the manual cert-export + `SSL_CERT_FILE` dance for workstation
  onboarding. Trust precedence is unchanged: `SSL_CERT_FILE` env wins, then
  the setup-installed CA, then system trust.

## [0.1.0alpha12] - 2026-09-21

> **Operator-facing behavior changes in this release — failure signatures:**
> - **Auth-endpoint rate limiting now actually fires.** More than 20 requests/min
>   per IP to `/api/v1/auth/*` answers `429` with detail `Auth endpoint rate
>   limited: too many requests per minute` (the tier was silently unenforced
>   before). E2E scaffolds and scripts that hammer auth endpoints must pace
>   themselves or set `VENYA_RATE_LIMIT__AUTH_REQUESTS_PER_MINUTE` explicitly.
> - **Executor registration requires an enrollment token by default**
>   (`executor_enrollment.require_token`): a tokenless `POST /executors/register`
>   fails with an error naming the knob and the re-enrollment path. Deployments
>   that relied on open registration must enroll with a token (recommended) or
>   deliberately set the knob to `false`.
> - **Secret unmasking and credential operations take the elevation token in the
>   `X-Elevation-Token` header.** `GET /api/v1/secrets/{key}?elevation_token=…`
>   answers `403 Elevation token required to unmask` — query-param transport is
>   removed (tokens in URLs leaked into access logs).

### Security

- Per-IP rate-limit counters now persist: the counter increment previously ran
  in a transaction that was rolled back on every request, so none of the
  database-backed tiers (auth 20/min, generic, break-glass 5/hr) ever enforced
  — only the in-memory break-glass failure backoff fired. The break-glass
  hourly tier and the auth tier are now physically enforced and their
  fixed-window counters survive across requests and restarts.
- WebAuthn login is now refused when the signature-counter persist fails
  (previously the login succeeded and the counter update was silently
  lost, erasing a future clone-detection opportunity). Fail-closed,
  consistent with the credential active-state check in the same path: a
  database write failure during authentication yields an actionable error
  and a retryable login, not a quiet degradation of clone detection.
- Executor audit spool (`~/.venya/audit-spool.jsonl` — holds full command
  lines) is now created 0600, and a legacy world-readable spool (pre-fix
  default umask, typically 0644) is repaired at daemon startup.
- A malformed relay response no longer leaks response-body fragments into
  the server journal: the validation error is logged as offending field
  names + error types only (the pydantic repr embedded `input_value=`
  body content, which the redacting log formatter cannot catch — the
  relay hop must never reach a logger by design).
- Contract honesty: the relay wire docstring no longer claims
  `wrapped_value` is ciphertext — it is sentinel-wrapped base64 of the
  plaintext (plaintext-equivalent); confidentiality rests on the mTLS
  transport, the 10-minute session-secret purge, and host disk
  protections, never on the encoding.
- WebAuthn registration ceremonies are now verified: `finish_registration`
  validates the `clientDataJSON` (type `webauthn.create`, issued-challenge
  binding, RP origin), the RP ID hash in the authenticator data, and the
  user-presence flag — previously any parseable attestationObject was
  accepted for an issued challenge id without these WebAuthn spec checks.
  The three registration routes (user enrollment, installation init,
  credential add) additionally reject credentials minted from a DIFFERENT
  user's challenge (challenge↔user binding). Registration deliberately
  enforces a stricter RP context (origin) than the authentication side;
  the divergence is documented in code, not an inconsistency.
- Elevation tokens are single-use and user-bound on every surface: the
  credential endpoints now consume the token with an atomic conditional
  update bound to the calling user (previously any valid token from ANY
  user could be replayed within its 60-second TTL). `venya credential add`
  correspondingly performs a second security-key touch for the completion
  step. Secret-unmasking elevation tokens move from a URL query parameter —
  which persisted tokens in nginx/uvicorn access logs — to the
  `X-Elevation-Token` header, matching the credential endpoints and the
  CLI. Breaking: `GET /api/v1/secrets/{key}?elevation_token=…` no longer
  elevates (transport standardized in coordination with the concurrent
  elevation-gate hardening, sec-secret-caller-param-plaintext-bypass).
- Disabled users lose access immediately: session validation re-checks user
  status on every request through one central predicate, so a disabled
  user's EXISTING sessions die at their next API call instead of surviving
  until idle expiry (15 minutes by default) or the 4-hour hard cap. Session
  issuance was already gated.
- Secret metadata updates (`PATCH /api/v1/secrets/{key}/metadata`) enforce
  the same role-scope visibility as every other secret read, routed through
  the core single enforcement point — previously any read-write role member
  could rewrite metadata on ANY secret, including secrets scoped to roles
  they do not hold (IDOR). Scoped-out secrets stay indistinguishable from
  nonexistent ones (404, no mutation).
- Executor heartbeat (`POST /api/v1/heartbeat`) is no longer public: it
  requires a verified executor mTLS identity (registered, non-spoofable CN)
  and binds the reported `executor_id` to the client certificate. Previously
  any unauthenticated caller could liveness-stamp any executor row and read
  the fleet revocation/rotation state as an oracle. A revoked executor still
  receives its advisory `200 {revoked: true}` (the cooperative-stop channel
  is preserved) but no longer writes to its row. The dead alpha-only
  `POST /api/v1/executors/{id}/heartbeat` variant was removed.
- Per-IP rate limits now key on the trustworthy RIGHTMOST `X-Forwarded-For`
  entry (the one our own nginx appends) instead of the attacker-controlled
  leftmost entry — one spoofed header previously reset the bucket on every
  request, bypassing the break-glass 5/hr limit, the auth tier, and the
  failure backoff. Rests on the existing loopback-only-backend deployment
  invariant (exactly one trusted proxy hop), now shared with the X-Client-*
  mTLS header chain.
- Executor revocation is now identity-based (hybrid model): `venya admin
  revoke-executor <id>` terminally revokes the IDENTITY (`Executor.revoked_at`,
  previously a dead-wired column) — command routing refuses revoked executors
  server-side, registration under a revoked identity is rejected even with a
  valid token, and a restarted daemon on a diverged/stale certificate is caught
  via the new `revoked_identities` list entries and the heartbeat `revoked`
  flag. A `--serial` form kills one credential without touching the identity
  (incident tool for orphans), and re-registration/rotation now auto-revokes
  the replaced serial in the same transaction — normal operation no longer
  leaves off-record, chain-valid predecessor certificates.
- Executor registration now requires an enrollment token by default
  (`executor_enrollment.require_token` — previously open: any host reaching the
  core could enroll itself as an executor). Rejections carry an actionable error
  naming the knob and the re-enrollment path. Breaking for deployments relying
  on tokenless enrollment; `VENYA_EXECUTOR_ENROLLMENT__REQUIRE_TOKEN=false`
  restores the old behavior deliberately. Certificate auto-rotation keeps
  working under the new default via the incumbent-mTLS exemption: a tokenless
  rotation is accepted only from a verified client certificate whose
  revocation state is clean and whose serial matches the current record
  (see cert-rotation-runbook §1).

### Changed

- The auth-endpoint rate-limit tier is now actually enforced: 20 requests/min
  per IP (previously silently collapsed into the generic 1000/min limit — the
  middleware constructor overwrote it). Scripted login/enrollment loops that
  never hit a limit before will now see `429` on `/api/v1/auth/*` and
  `/api/v1/enrollment/*`. Diagnosis + override:
  `VENYA_RATE_LIMIT__AUTH_REQUESTS_PER_MINUTE` (e2e scaffolds should set this
  explicitly rather than discover the tier nondeterministically).
- The core installer now encrypts the root CA private key at rest and delivers
  its passphrase through a restricted systemd EnvironmentFile, matching the
  existing admin CA key handling.
- Preparing for beta: the core installer no longer carries a development
  passphrase. `VENYA_DB_PASSPHRASE` is now always operator-provided — prompted
  on interactive installs, required for unattended installs — and, together
  with the recovery pepper, is safely reused across idempotent re-installs.

### Fixed

- CA-key break-glass backups now use ONE canonical envelope — AES-256-GCM
  (authenticated encryption) behind a versioned `VENYACA1` header — across the
  CLI and the server. Previously the CLI wrote AES-256-CBC while the server
  wrote headerless GCM: cross-format blobs could not read each other, and the
  CLI restore validated only the last padding byte's range, so a wrong
  passphrase or tampered CBC blob could restore silently-corrupted key
  material. New exports are authenticated-encrypted (tampering and wrong
  passphrases fail loudly). Break-glass backups exported by alpha.11
  (`venya admin export-ca-key`, CBC) remain restorable: `venya admin
  restore-ca-key` is a dual-format reader (canonical GCM primary, legacy CBC
  read-only with full PKCS7 validation), and the server restore likewise
  still reads its pre-magic GCM blobs. No exported key material is stranded.
- Session token refresh now works as designed: `/api/v1/auth/refresh` is gated
  by the 4-hour hard cap ONLY, so idle-expired sessions (15-min idle window by
  default) renew without human intervention. Previously the refresh applied
  the same idle check as the API middleware — a session idle-expired at the
  API could never be refreshed, making every client 401→refresh→retry recovery
  path dead code. The hard cap stays non-negotiable: past it, FIDO2 re-auth is
  required. Ruled trade-off (recorded): idle-expiry revival extends a stolen
  token's renewable window to the hard cap; refresh rotates the token (old one
  dies immediately), keeping a theft race detectable.
- `venya` CLI now honors `VENYA_SERVER_URL` for every command; previously most
  paths only accepted `--server-url` or a stored config, so headless,
  env-driven invocations could fall back to the wrong default URL.

## [0.1.0-alpha.11] - 2026-09-19

### Added

- **`docs/cli-reference.md`: complete CLI reference** — every command and
  argument, generated from the live argument parser and kept honest by tests
  (any parser change without regeneration fails the suite; every documented
  example invocation is parse-validated). Linked from the README docs table.
- Installation docs: macOS-workstation + lima-VM-core topology note (the
  server cert carries the VM hostname while lima forwards 443 — map
  `127.0.0.1 <vm-hostname>` in the mac's `/etc/hosts`, or install with
  `CORE_HOSTNAME` set; never disable verification).
- Internal: exhaustive argparse-contract test surface (419 parser-derived
  cases) plus doc anti-drift interlocks; five-suite total 1,872 → 2,416.

### Security

- **Shamir CA-key backup: threshold + integrity enforcement (V2 shares).**
  Restoring with fewer than K shares, corrupt/truncated files, or files from
  different splits now fails loudly — previously it SILENTLY reconstructed a
  corrupt CA key. Pre-V2 share files still restore (with a CLI warning to
  verify the result against `ca.crt`).
- `venya admin export-ca-key` / `restore-ca-key` passphrase prompts are
  hidden (getpass) instead of echoed to the terminal.
- **Executor cert auto-rotation now persists on deployed systems.** The
  systemd unit grants write access to `/etc/venya/executor` (identity files
  only — config stays read-only); `rotate()` refuses BEFORE contacting the
  server when the identity dir is unwritable, and adopts the new serial only
  after the disk writes succeed. Executors installed before this fix need the
  refreshed unit: re-run the executor installer or add a
  `ReadWritePaths=/etc/venya/executor` drop-in (cert-rotation runbook §1).

### Fixed

- `venya admin key-version revoke <id>` was dead on arrival — the parser
  accepted no argument while the handler required one, so every invocation
  failed. (The server route always existed.)
- **Installer re-run over an existing core no longer dead-ends**: unattended
  re-runs regenerated the admin CA passphrase while the existing encrypted
  key was (correctly) preserved — then aborted decrypting it. The stored
  passphrase from `/etc/venya/venya-core.env` is now reused; an explicit
  `VENYA_ADMIN_CA_PASSPHRASE` still takes precedence (a wrong value still
  fails loudly).
- Admin CA commands' `--ca-dir` default now points at the real CA storage
  (`/var/lib/venya/ca`, matching the server and the flag's own help text)
  instead of a path that exists in no deployment.
- CORS: the installer writes `VENYA_CORS__ORIGINS`; the previously written
  flat `VENYA_CORS_ORIGINS` mapped to no config field and was silently
  ignored (servers ran on the default).
- Operator-facing messages now name env vars that actually work:
  `VENYA_DB__PASSPHRASE` and `VENYA_RECOVERY_CODE_PEPPER` in the startup
  RuntimeErrors (with the installer input vars named as such),
  `VENYA_CORS__ORIGINS` in the CORS warning, `VENYA_VENYA_CA_FILE` in the
  executor-enroll hint.
- Dead executor config knobs removed (`cert_rotation.rotation_days`,
  `revocation_poll_seconds`) — defined but never read, so tuning them was a
  silent no-op. Real values: 30-day cert validity (server-side constant) and
  ~30 s revocation poll (daemon main loop). Legacy `executor.toml` files
  carrying the removed keys still load.

### Documentation

- Repo-wide accuracy sweep against source: cert-rotation runbook REWRITTEN
  (the previous version described a pre-nginx layout — wrong CA paths,
  wrong URLs, nonexistent commands and users — and was largely unrunnable);
  bandit-suppressions register regenerated from the live tree with a drift
  interlock; corrections across installation, architecture, FAQ, agent
  brief, alpha demo, deployment-config, and the full-lifecycle test plan.

## [0.1.0-alpha.10] - 2026-09-19

### Added

- **Windows support for the venya CLI** (first release). Machine-wide
  PowerShell installer `install-venya-cli.ps1` (admin-run once per machine —
  Windows junction-trust semantics make per-user standard installs impossible;
  standard users then USE the CLI with no admin rights) plus matching
  uninstaller. Per-user config/token/state in `%APPDATA%\venya\`. FIDO2
  ceremonies (`init`, `login`, `enroll`, `credential add`) route through the
  Windows platform WebAuthn API, so **standard (non-admin) users** get
  OS-drawn PIN/touch dialogs — raw CTAP/HID access has been admin-only since
  Windows 10 1903. Interactive desktop sessions only (the platform API needs
  a foreground window; SSH/WinRM cannot drive ceremonies). Authenticator
  reset and PIN set/change remain with the vendor tool / customer IT.
  Accepted physically on Windows 11 as a genuine standard user.
- CLI error log: every stderr write is teed to `<config-dir>/venya.log`
  (session headers, 1 MiB single-generation rotation); failed commands print
  the log path.
- Platform-aware ceremony guidance on Windows: which key to use at which
  dialog (registered vs enrolling), insert-vs-touch wording, and the
  dual-key `credential add` sequence.

### Security

- Server refuses to boot when relay mTLS material is unset or missing — named
  RuntimeError before DB/CA initialization instead of failing later in
  ambiguous ways; the executor daemon fails the same way at startup (exit 1,
  named single-line error) while keeping its runtime cert-rotation tolerance.

### Fixed

- Windows config saves: `os.replace` ran inside the open temporary-file block,
  and Windows cannot rename an open handle — every config write died
  `PermissionError [WinError 32]`, first save included (the CLI was entirely
  non-functional on Windows before this fix; POSIX unaffected).
- `venya credential add` never worked on ANY platform: its duplicated inline
  ceremony read `credential.auth_response` (absent from the `RegistrationResponse`
  the pinned fido2 library returns — AttributeError after every successful
  ceremony) and hardcoded an `https://localhost` collector origin (RP-ID
  verification failure on every real deployment). The duplication is deleted;
  the command now routes through the same proven machinery as `venya enroll`.
- Elevation (`venya credential add/remove`, unmask, and every elevated
  operation) sent no session bearer token — every elevation 401'd "Missing
  authentication token" on every platform since inception.
- `venya credential list` crashed on the server's integer credential ids
  ("object of type 'int' has no len()") in table mode.
- WebAuthn options normalizer: elevation challenges (browser-adapter shape)
  carry the RP id inside an `rp` object rather than an `rpId` scalar; the
  normalizer now derives it, fixing `rp_id=None` ceremonies (platform
  NTE_INVALID_PARAMETER on Windows; RP-hash rejection elsewhere).
- Windows platform errors now surface as readable messages (pinned texts for
  observed HRESULTs such as duplicate-key registration; OS text + HRESULT
  preserved for everything else) instead of raw `ClientError` tuples.

## [0.1.0-alpha.9] - 2026-09-18

### Security

- Commands are now structurally validated on the production execution path.
  An unconditional whole-string shell-metachar gate (``| ; & $ ` ( ) { } < > ! * ?``
  and newlines) runs in `Executor.execute()` BEFORE policy validation and
  before any sandbox dispatch — previously the structural check existed only
  on the unused memfd/direct path while the production sandbox path passed
  the raw string to `sh -c`. Quoted metachars (e.g. `echo "a; b"`) are
  rejected as well: a documented accepted tradeoff, since quote-scoped
  parsing cannot soundly distinguish local from remote interpretation.
  Shell features must use the script-file path; the full-lifecycle test
  plan's D.6 command shapes were rewritten metachar-free in the same
  changeset. Structural and policy rejections both emit `command_rejected`
  audit events with distinct reason strings.

- Executor relay listener is bounded against misbehaving authenticated
  peers: a 16 MiB request-body cap (checked before any read/allocation,
  413 on excess), negative `Content-Length` rejected with 400 (previously
  `read(-N)` meant read-until-EOF — an unbounded hang), and a 30-second
  per-recv inactivity timeout so a silent peer cannot pin the single
  handler thread. Fixed-length protocol documented: chunked bodies are
  never decoded and answer 400.

- Executor daemon refuses to boot "deaf": an empty `relay_client_ids`
  allowlist now exits 1 at startup with a log line naming the knob —
  checked BEFORE registration, so the one-shot enrollment token is never
  consumed on a doomed boot. Previously the daemon logged a single ERROR,
  never bound the relay, and kept running healthy-looking to every normal
  ops probe. The bind/SSL-failure deaf class gets the same refusal.

### Fixed

- Output-truncation metadata tells the truth. The sandbox path sliced
  stdout/stderr to the 256 KB cap BEFORE computing `output_truncated`
  (structurally always `False`) and `original_*_size` recorded post-slice
  lengths on both paths — oversized output silently lied about
  completeness. True pre-slice sizes are now threaded through the shared
  result builder; a truncated payload is exactly the cap (the truncation
  marker is carved out of it); and the direct path's marker — which raised
  `KeyError: 'n'`, crashing capture on ANY real >256 KB output — now works.

- Core relay handler maps `httpx2.RemoteProtocolError` (executor died
  mid-response) to 503 "Executor unreachable (connection lost mid-response)"
  instead of an unhandled 500 — completing the ConnectError/Timeout guard
  class.

- `venya run -- <command>` no longer ships the literal `--` separator to
  the executor. argparse REMAINDER captures it verbatim; the resulting
  `-- `-prefixed command string broke the validator's ssh-shape recognition
  (false "Dangerous pattern" rejections of legitimate sshpass-to-target
  flows) and would exit 127 in the sandbox. Exactly one leading separator
  is consumed; `run --help` documents it.

## [0.1.0-alpha.8] - 2026-09-18

### Security

- Break-glass recovery codes are now truly single-use. `POST /api/v1/recovery`
  always CLAIMED (docstring) to burn the one-shot code but never did: the same
  recovery code could mint new admins repeatedly, forever. The stored hash is
  now nulled in the same transaction that mints the recovered admin; reuse
  answers the same 401 as an invalid code and mints nothing. Failed recoveries
  (existing user id → 400, missing admin role → 503) deliberately do NOT
  consume the code — the operator needs it for the retry. Re-issuance of a
  fresh code for the recovered system remains separate scope.

### Fixed

- Key rotation is no longer administratively broken. `POST
  /admin/key-versions/rotate` previously created an inactive key version plus
  a pending rotation job that nothing ever completed — and deactivated the
  old version — leaving the installation with NO active key version
  (`GET /key-versions/active` 503, secret storage without an explicit
  `--key-version` dead). Rotation is now a synchronous label-boundary
  operation under single-KEK alpha semantics: the new version is active when
  the request returns and the rotation job is terminal with truthful
  counters. No secrets are re-wrapped (there is no per-version key material;
  decryption never consults key versions) — existing secrets keep their
  label and remain decryptable; new secrets receive the new label
  automatically. Rollback (both routes) now performs a real flip-back of the
  active version instead of only marking the job row.
- `venya store` now actually reads the secret value from stdin, as its help
  text always claimed: pass `-` as the value positional (or omit it when
  stdin is piped), or omit it at an interactive TTY for a hidden `getpass`
  prompt. Trailing newline stripped from piped input (`echo` convention).
  Empty input fails with an actionable error (exit 1, nothing sent). The
  argv positional still works and takes precedence; the stdin/prompt paths
  keep values out of `/proc/*/cmdline` and shell history — the same
  stdin-carriage discipline the installers use for passwords.
- Executor sandbox path no longer silently drops `env_override` and `cwd`:
  both now thread through to `sbx exec` as `-e KEY=VALUE` / `-w DIR` argv
  tokens (docker-exec semantics — values are data, never shell-parsed; `-w`
  overrides the workspace-mount default per command without conflicting with
  the mount; physically probed on the deployed sbx). Previously
  `Executor.execute()` accepted both parameters and returned success while
  honoring them only on the unused direct path. No wire surface
  (relay/API/CLI/MCP) sends either today, so no observable caller behavior
  changes — the internal contract simply stops lying.

### Changed

- `POST /admin/key-versions/rotate` (and its alias `POST
  /admin/key-rotation`) now answer **200** with `status: "completed"` and a
  `note` field ("no re-wrap: single-KEK alpha semantics") instead of **202**
  with `status: "pending"` — the operation is synchronous. The request
  body's `new_key` field (advertised per-version key material that never
  existed) is removed; the body is now empty. No production caller existed.
  Rollback answers 409 (was: silently "succeeded") for jobs that are not the
  most recent completed rotation, and `restored_secrets_count` is 0 by
  construction.
- Database: migration 028 adds a partial unique index enforcing at most one
  ACTIVE key version at the database level — concurrent rotations can no
  longer both commit (the loser gets a 409). Includes a defensive pre-clean
  keeping the newest of any legacy extra-active rows.
- `venya store` / `POST /api/v1/secrets` are now an UPSERT on keys the caller
  can see (one of the caller's roles in scope, or caller is the creator —
  the same visibility rule as get/inject/list): the existing row is replaced
  in place (stable id, immutable `created_by`; value, key version, metadata
  and role scope overwritten), the response gains `"replaced": true`, and
  the CLI prints "replaced existing". Re-storing a key that exists but is
  scoped out for the caller still inserts a second row with an identical
  response shape — no existence leak, no cross-role clobber. Previously
  every re-store created a duplicate row.

## [0.1.0-alpha.7] - 2026-09-17

### Fixed

- Fresh installs now seed an initial active key version (`v1`) at migration
  time: `venya store` works without `--key-version`, and
  `GET /api/v1/key-versions/active` answers 200 instead of 503. The seed is
  idempotent and never touches installs that already have key versions.
- `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` (minutes) is now wired: it was defined
  but read by nothing — user-enrollment token lifetimes were hardcoded to
  900 s and the reported `expires_in_seconds` was a literal. All enrollment
  routes now construct through a single config-aware helper, and reported
  lifetimes are derived from the same config. Default unchanged (15 min).
- `venya-mcp` startup precondition failures (no session/config yet, or a
  malformed config file) now print their actionable message to stderr and
  exit 1 — no raw Python traceback on first run.
- Executor reaper: orphaned-secret cleanup scanned a pre-sandbox file layout
  that the live writer no longer produces (it never matched anything), and
  revocations targeted a phantom session id. The reaper now scans the real
  per-run session directories, and revocations are attributed to the actual
  execution session — audit records no longer misattribute.
- Installer robustness: nine command-substitution sites under `set -e` could
  kill installs silently at the assignment, making the intended error
  handling unreachable (e.g. a failing Rust-extension import check died
  before printing its own diagnostic). Error paths now fire as designed.

## [0.1.0-alpha.4] - 2026-09-17

### Security

- Secret role scoping is now enforced on listing and execution-session
  injection. A secret is visible/usable only if one of the caller's roles is
  in its `--roles` scope or the caller created it — no admin bypass. A
  scoped-out key returns the same 404 as a nonexistent one (no cross-role
  key-name enumeration). Previously any read-permission user could list every
  secret and any read-write user could inject and use any secret via
  `run_command` (values stayed masked by output redaction — the gap was
  *use*, e.g. ssh-ing with an admin-scoped credential unseen). Physically
  accepted: the exact probe that succeeded pre-fix now 404s, and the
  admin/creator happy path still injects and redacts.
- Test hardening: the core visibility rules now have a real-SQLite truth
  table (in-scope, out-of-scope-indistinguishable, creator fallback,
  injection pos+neg, list matrix, metadata filters); the server test that
  had *pinned* the old any-reader-sees-all behavior was reversed into a
  shared-role-visible + out-of-scope-hidden pair; session-create gained an
  indistinguishable-404 paired negative. Suites at the tag: 1,729 passed
  (cli 291 / core 95+7 skipped / server 726 / executor 581 / mcp 36).

## [0.1.0-alpha.3] - 2026-09-17

### Added

- Full-lifecycle test plan (`docs/full-lifecycle-test.md`) and interactive MCP
  driver (`testing/mcp_manual_drive.py`): reproducible A-Z validation from a
  clean hypervisor to the MCP use-a-secret redaction proof, operator-run.
  Verified with opencode and local-LLM (omlx.ai) clients; two live PASS runs
  2026-09-17. Full A-Z testing is ongoing.
- macOS support for the Workstation CLI: config dir follows the platform
  convention (`~/Library/Application Support/venya`), and the CLI installer
  runs on stock macOS (`shasum` fallback for hash verification, no
  `readlink -f` dependency, Linux-only `/dev/hidraw` check replaced with an
  IOKit note). Verified on macOS 26.6.2 arm64 with a full FIDO2 login
  round-trip.
- `venya store --key-version`: explicit key version ID to encrypt with.
  Fresh installs have no active key version yet — pass `--key-version v1`
  until key-version bootstrap lands.

### Changed

- Admin commands that mint enrollment tokens (`admin enroll`, `admin
  create-user`, `admin executor-enroll`, `admin issue-token`, `admin
  re-enroll`) now always print the token. These are single-use, short-TTL
  bootstrap artifacts handed to the enrolling party — the redaction gate
  added friction without protecting anything (the `--json` output of the
  same commands already printed tokens unredacted).

### Fixed

- CLI installer day-one printout: now lists `venya init <user-id>` (creates
  the first admin account, FIDO2 key required) before `venya login` —
  previously an operator following the printout attempted login with no
  account.
- `venya store` now sends the required `key_version_id`; previously every
  store failed with HTTP 422 on every server. Without `--key-version`, the
  CLI resolves the server's active key version
  (`GET /api/v1/key-versions/active`); a failed lookup (fresh install, 503)
  exits loudly with a `--key-version` hint and writes nothing.
- Executor installer: registration failures are now loud — full command
  output plus an explicit error block — instead of a silent exit that left
  no service unit and no diagnostics.

### Removed

- `--show-sensitive` global flag: tokens no longer redacted, so the flag has
  nothing to unlock. Passing it now fails with an argparse error instead of
  being silently accepted.
- `venya store --force`: silent no-op — the server never accepted a `force`
  field and has no upsert semantics. Storing an existing key creates a new
  row; delete the old secret first when replacing one.
