# Changelog

Notable changes to Venya will be documented in this file.

## [Unreleased]

Nothing is pending here at the `v0.1.0beta2` cut: the rows that had landed since `v0.1.0beta1` are
folded into the `0.1.0beta2` section below. The same emptying marked that earlier cut (`e9c7c25`).

## [0.1.0beta2] - 2026-10-28

> Dated at the cut: this is the local date of the commit preparing the `v0.1.0beta2` cut, not a date
> the tag has been struck on yet. The tag is the owner's keystroke; if it lands on a later day, this
> heading is re-dated in the commit that cuts it — a stale ship date here would be a false statement
> in a shipped document, which is the rule the `0.1.0beta1` heading above carries in its own note.

- **An executor refusal now says which argument it means and what kind of character it
  carries (`#713`).** The command gate has refused a metacharacter inside an argv element by
  printing one sentence that named nothing: on a fifteen-element command the caller had to
  bisect to find the element. The refusal now reads `Argument 3 contains a disallowed shell
  metacharacter — classes: grouping-braces.` and names every class the element trips, in the
  order `pipe/semicolon-ampersand, quoting/expansion, grouping-braces, redirect,
  glob-history, whitespace-control`. It names classes, never the element's own characters: a
  refused argument can be a session-bound secret path, and this sentence is re-emitted as the
  relay's 422 detail, forwarded by the server hop, journalled and stored in the audit reason.
  The one ruled exception keeps its own wording — a `<` fused into a larger element is refused
  for its SHAPE, so no class word belongs in that sentence. The "wrap complex commands in a
  script file" advice stays, written for the human operator who reads it. No character was
  added to the refused set: `%` is still accepted, and the shape that motivated the report
  (`%{http_code}`) is refused for its braces, which is what the new text now says out loud.

- **`venya admin split-ca-key` no longer leaves the key material in its own buffer
  (`#674` AC3).** The splitter builds a working copy of what it is handed — a checksum
  plus the key — and until now that copy stayed as it was when the command finished. It is
  now cleared on every path out of the splitter, including the one where a failure lands
  part-way through the work. No format change, no encryption change, no migration: the
  share files an operator already holds are the same bytes, and they restore the same key.
  This completes the custody change the `0.1.0beta1` section describes for the split and
  restore commands, which covered the holder's copy; the splitter's copy is this row.
  The cleared buffer is the splitter's own: the promise is that copy is erased, not that
  no other copy exists in the process.

- **Registering a sandbox's egress rules now has a time limit of its own (`R-2614`).**
  Before this row the call that added each network rule to the sandbox waited without a
  bound, and it was the only such unbounded call in the shipped source. Because the
  executor admits one command at a time, a sandbox daemon that stopped answering held that
  single slot: the command neither finished nor failed, and the next caller queued behind it
  with no end. Each rule registration is now bounded at 30 seconds
  (`VENYA_SBX_POLICY_TIMEOUT`, read per call), the command is refused rather than run when a
  rule cannot be confirmed, the log says which stage timed out and with what budget, and the
  executor returns to idle. No migration, no wire change, no new status code: the refusal
  lands on the same channel a setup failure always used. A repository-wide check now keeps
  every subprocess call in `packages/*/src` bounded, with one named exemption recorded with
  its reason.

- **`run_command` answers now name the executor they ran on (`#712`).** The MCP tool used to
  reply with only the exit code, stdout, stderr and the masked-count note, so an answer
  read the same whether it came from a sandbox or from the host the caller meant. The
  reply line now carries the `executor_id` the caller supplied — echoed from the call,
  never guessed from the command text — on success and on a non-zero exit alike. The
  `get_audit` face has printed `executor=` this whole time; this puts the two siblings in
  the same shape. No new field on any wire message, no change to what a caller has to
  send, and nothing about secrets moves: the id is already in the caller's own request.

- **`get_audit` lines now name the command they ran, escaped (`#709`).** The tool
  asked to show what commands had been executed and printed only the timestamp, the
  event type, the user and the executor: the command text, its exit code, its duration
  and the row's own session id were all stored, all returned by the API, and dropped at
  the last hop, so "did my write run?" could not be answered from the tool's own output.
  They are printed now, on one line each — the command text arrives escaped, so a newline
  stored inside a command stays data inside that line rather than becoming a second audit
  record an agent would read as its own event. A row whose answer is genuinely unknown
  keeps saying so: `exit_code=None` beside `outcome='relay_timeout'`, which is never
  rendered as a clean run, and a row that never stored a command is rendered exactly as
  before. No migration, no wire change, no new endpoint — every field already existed in
  the stored row.

- **A `masked_count` now says what it does not say (`#715`, disclosed as a known limitation).**
  Two passes can produce that number — the executor's own Stage-1 mask, and the server-side
  Stage-2 filter — and the answer carries no record of which one ran. The count itself is honest
  about which pass won; what is missing is the history. On the fallback arm, where the server did
  not answer, the mask reflects the local set only, which may be narrower than the session's full
  set. The masking posture is unchanged and holds in every state: Stage 1 always runs, the fallback
  keeps Stage 1's masked output rather than passing anything through, and a deployment with no
  Stage 2 configured was always on the local set. What is deferred is the provenance signal, so the
  limitation is written down in `docs/beta-known-limitations.md` for the duration rather than left
  for a reader to discover. No behaviour changed and no field moved on any wire message: this row is
  a disclosure, and it leaves with the leg that adds the three-valued answer.

- **The `run_command` example shows both supported authentication postures
  (`#711`).** The shipped example paired `sshpass` with an unattended remote
  `sudo` — the one combination beta does not support, because `sshpass` reads the
  password from its own side and the remote `sudo -S` is answered by nothing — so
  the description pointed an agent at a command that could not finish the job it
  described. It now shows the two shapes the product does support, each with the
  condition that makes it the right one: key authentication with the
  session-bound redirect where the target enrolls the key and a remote `sudo` is
  needed, and `sshpass` password authentication with no remote `sudo` in the same
  command where the target grants a stored password only. Neither posture is
  assumed, because a customer target may grant either, and the description says
  so. Both example commands are read back out of the shipped description and run
  through the real command gate in the test suite, so an example cannot drift
  into a shape the product would refuse. The limitation entry in
  `docs/beta-known-limitations.md` stands exactly as written: the example moved,
  the disclosure did not.

- **`venya run` names the executor it used, and refuses when none is set (`#712` half (a)).**
  The CLI run path invented an executor id when the operator gave none and sent that
  made-up token to the server, which answered with a failure naming neither the id nor
  where it came from — so a missing flag read on the terminal exactly like an executor
  that was not installed. It now resolves the id the way the rest of the executor plane
  does, `--executor-id` first then `executor_id` in `/etc/venya/executor.toml`, and when
  neither is present it refuses before any network call, saying that no executor id was
  configured and naming the two places to set it. On the paths that do run, the answer
  now ends `Command exited with code: 0 (executor=venya-exec-1)` — the caller's own id,
  echoed, on a non-zero exit and on a failed session or relay call too, never a host read
  out of the command text. This is parity with the MCP face above, and it puts the two
  surfaces a human and an agent drive during an incident in the same shape. No wire
  change, no new field, no migration; commands that already pass an id behave as before.

- **`run_command` now ticks while a command is in flight (`#710`).** A host calls an MCP tool at its own
  per-request deadline, and that deadline is shorter than the time `venya_mcp` is willing to wait for an
  executor, so a slow command was lost at the harness and the caller could not tell "still running" from
  "never ran". A conforming client re-arms its deadline when a `notifications/progress` arrives, so the
  tool now sends one while the call is outstanding. The payload is a tick counter and one fixed stage
  word: no command text, no argv, no output fragment, no secret key, no path and no executor id cross
  that channel, so it adds no disclosure surface beside the output masking that already runs. It is
  opt-in per request — a caller that sent no `progressToken`, or a handler invoked outside a request
  context, is served exactly as before and nothing is emitted — and a notification that cannot be
  delivered is dropped and logged rather than altering the answer. The reply itself is unchanged in
  every field. No timeout moves: the relay, the nginx and client-side bounds and the execute read
  timeout are all untouched, because a tick interval is a cadence, not a fuse.

- **A session-bound `<` redirect that `sshpass` would take for itself is now refused (`#695`).** The
  one ruled exception to the metacharacter gate is a standalone `<` followed by a secret path bound to
  the same call, and it exists so a command can answer a `sudo -S` prompt. The guest shell binds that
  `<` to the first process it starts, so in `sshpass … ssh … sudo -S …` the file is read as
  `sshpass`'s own password and the remote `sudo` is never answered: the command ran for its full time
  limit and got nothing. The gate now refuses that shape before anything runs, and the refusal names
  the redirect and says to authenticate `ssh` with a key or drop the redirect — not both uses at once.
  Three shapes are accepted exactly as before: `sshpass` with no redirect, a redirect with no
  `sshpass`, and `sshpass` plus a redirect whose remote command carries no `sudo -S` or `--stdin`. The
  remote command is read in both forms the wire carries — separate elements (`sudo -S id`) and one
  quoted element (`"sudo -S id"`). No character was added to the refused set and no timeout moved.

## [0.1.0beta1] - 2026-10-23

> Dated at the cut: this is the local date the `v0.1.0beta1` tag was cut. If the tag ever slips to another day, the heading is re-dated in the commit that cuts it — a stale ship date here would be a false statement in a shipped document.

- **The pre-beta alpha line is withdrawn by owner order (2026-10-18).** The
  `v0.1.0alpha*` and `v0.1.0-alpha.*` releases are retired: new installs and upgrade
  recipes pin a beta tag (`v0.1.0beta1` is the name the cut creates), never an alpha
  tag. Removing the tag refs and their GitHub releases is a SEPARATE owner act (a
  squash deletes commits, not tags; and a tag is not its release), so an alpha name may
  still resolve until that runs. The
  alpha sections below stay exactly as written either way — the product did ship those
  builds, and a record that names them is history, not an error.

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

- **A revocation read that runs slowly is now refused, counted and visible (#654, #656).** The
  bounded read shipped under #603 AC1 bounds the wait for a lock; it never said how long a statement
  could take once it had one, so the only ceiling on execution time was the `statement_timeout` both
  engines set at the session level — 300 s against a read whose caller waits 10 s. A slow read that
  answered late was invisible everywhere: no exception, no refusal, no counter, no log line, a parked
  core event loop, and a caller that had already given up and counted a failure the core recorded as
  a 200. Request-path revocation reads now also carry their own execution deadline,
  `crl.revocation_read_scan_timeout_ms` (default 2 000 ms, env
  `VENYA_CRL__REVOCATION_READ_SCAN_TIMEOUT_MS`), set inside the same savepoint as the lock deadline
  and reverted with it. A read that misses it is refused in the stale class the plane already uses —
  the same `503` and the same "no revocation asserted" wording, never a `403` and never an all-clear
  — and it is counted on a new cumulative series, `venya_revocation_read_scan_refusals_total{site=…}`,
  deliberately kept apart from `venya_revocation_read_refusals_total` so a lock convoy and a slow scan
  stay two different diagnoses. A slow read that still answers is now an observation on
  `venya_revocation_read_duration_seconds{site=…}`, bucketed up to the 300 s that actually governed
  these reads, because the shipped request histogram stops at 10 s. Two more reads of the same
  lockable population joined the seam: the CRL the dial mints on its own path, and the
  whole-population read the public poll falls back to when the snapshot publisher is not running
  (#656) — both of them still answering, which is the half that keeps a freeze fix from becoming a
  refusal the fleet cannot recover from.

- **A stale or missing revocation snapshot is now counted where operators read it (#657).** The
  poll that answers `GET /api/v1/executors/certs/revocation-list` already refused with the
  `503` "no revocation asserted" answer when its snapshot was older than 45 s or not there yet;
  it did not increment anything, so the arm an operator was being refused by was absent from the
  scrape the runbook points at. That refusal now increments the shipped
  `venya_revocation_read_refusals_total` under its own site label, `poll/revocation-list`, on the
  same series as the lock-deadline refusals, and the family's help text names both arms. A reader
  of `site=…` can tell "the pool or the publisher is starving" from "a lock is held over the
  revocation table" without a second metric being introduced, and `docs/revocation-table-operations-runbook.md`
  names the arm it documents.
- **The admin request path's revocation read carries the same bound (#658).** The admin-mTLS path
  checks the revocation table on every admin request; that read waited on a lock over the table
  for as long as the holder kept it. It now runs inside the shipped bounded seam with its own site
  label, `admin-mtls`, reusing the existing `crl.revocation_read_lock_timeout_ms` knob. The
  decision is unchanged: a row that matches still answers `403` and still fails closed, and any
  other fault keeps the generic `403` it answers today. What is new is the lock-wait arm, which
  answers `503` in the "no revocation asserted" class and is counted, so a held lock on the
  revocation table is a visible refusal on the admin plane rather than a stalled request.
- **The metrics scrape door is open by default on an installed core (#653).**
  `systemd/venya-core.service` now ships `Environment=VENYA_METRICS_PORT=10011`, so a freshly
  installed core answers `curl -s http://127.0.0.1:10011/metrics` with no operator step and no
  extra unit to enable. The server binds that port on `127.0.0.1` only and the address is not
  configurable, because the endpoint is plain unauthenticated HTTP and carries telemetry only —
  never payload, and never the high-cardinality labels (`executor_id`, `user_id`, `ip`,
  `session_id`). Change it with `systemctl edit venya-core`; unset it there to close the door.
  `docs/FIREWALL.md`, `docs/installation.md` and the runbook name the port and the read path.
- **A taken metrics port is a named line, not a stopped core (#653 follow-on).** If the OS refuses
  the bind — the port is already in use, or this host will not grant it — the core now logs one
  `ERROR` line naming the port, the OS reason, and the fix, and serves on. Exactly those two
  reasons are caught; a value that is not a usable port number still refuses at the config door,
  so a typo is not quietly absorbed. Before this the `Environment=` line was the only place the
  port was mentioned, and a refused bind left the scrape surface dark with nothing saying why.
- **The audit spool keeps its own count (#651).** A spool that reaches its capacity logged its
  warning once per band entry and re-stated it per audit event while it sat there, and every drop
  emitted its own line on top — so a full spool moved the log flood onto the drop path. Both lines
  are now edge-triggered, the band line re-states on an interval rather than per event, and a new
  cumulative `dropped_total` counts every drop behind that single line. The count is monotonic for
  the life of the process. What an operator reads is one line per condition and one number that
  says how much was lost, instead of a journal whose size is the only hint.
- **The executor's `--log-level` flag only wins when it is actually given (#647).** Passing no flag
  now leaves the configured value in charge; previously the flag's built-in default was applied on
  every start and overwrote `/etc/venya/executor.toml` one moment after the file had been read, so
  `log_level` in the file — and `VENYA_EXECUTOR_LOG_LEVEL` below it — were set and ignored. The two
  surfaces also share one list of accepted names now, so the flag and the file cannot advertise
  different sets. A file or environment value that names no level is not fatal: the daemon logs one
  `WARNING` naming the key and the value it could not use, and starts at the built-in default,
  because a typo in a verbosity knob must not park a whole executor in a restart loop. When a flag
  does override a value the precedence note had already claimed for the file, one further line
  names the flag as the actual winner.
- **The revocation-failure threshold has a floor and a ceiling (#660).**
  `revocation.max_revocation_failures` is now bounded to 1–1000 at the config door and refuses by
  name outside that range; it is never clamped. A `0` previously stopped a healthy executor on its
  very first poll, before the core had had any chance to answer, and a very large value silently
  disabled the stop-on-no-answer posture the operators are told about — 1 000 consecutive
  unanswered checks at the 30 s beat is roughly 8.3 hours. `docs/deployment-config.md` states the
  range where an operator reads the knob.
- **The core's own relay client credential now has a registry row and a revoke path (#597).** The
  certificate the core presents when it dials an executor's `:8443` listener was minted by the
  installer outside the product, so it appeared in no revocation table and the CRL drawn from those
  tables could never name it. It is recorded in a new `core_relay_credentials` table at core
  startup (migration `040`), read from the same file the core loads, and two admin commands act on
  it: `venya admin core-relay-cert list` and `venya admin core-relay-cert revoke --serial …`,
  backed by `POST /api/v1/admin/core-relay-certs/revoke`. A revoke against a serial the registry
  does not name is refused and writes nothing. Membership is carried on the revocation feed, so an
  executor's listener can act on it: a new `:8443` connection presenting a serial the registry
  names as revoked is refused with `403 REVOKED` on the peer's credential. A registry with no rows
  admits at that door — refusing there would stop every healthy executor — so the refusal is at the
  verb, and the door's own behavior is described in `docs/beta-known-limitations.md`.
- **The executor's relay door can now name a revoked PEER, not only itself (#586).** The accept
  gate on `:8443` already refused a new connection while this daemon's own credential was revoked
  or unanswered. It now also consults the executor-serial population the core publishes about the
  credential arriving on the other side of the socket: a peer whose executor serial is on the
  revoked population is refused `403 REVOKED` naming the peer's credential, and the refusal is
  keyed on that population alone, so it cannot be tangled with the freshness question this daemon
  asks about itself. The self-check still runs first, and a peer serial the population does not
  name is admitted — the door refuses what is known revoked and asserts nothing else.



- **Installer and CLI-surface fixes from the field-reports wave (recorded late).** These landed on
  `dev` between `v0.1.0alpha16` and this release and were not named individually in a release note;
  per-item detail is `git log --first-parent --merges 54c0b5b..c7a4075`. What an operator sees:
  the generated nginx site config and the core's relay TLS context state the protocol floor
  explicitly (TLS 1.2 / 1.3) instead of inheriting what the OS offers (#323); a tarball source that
  is not HTTPS requires the operator's pin before anything is fetched or written, in the shell and
  PowerShell installers alike (#328, #375); the CLI uninstaller removes the `uv` tool environments
  and shims at the sites that created them (#390); the executor's key file keeps the mode it was
  written at, and the installer verifies the mode rather than assuming it (#457); `docker.list` is
  left readable by the unprivileged sandbox reader after the repository is set up (#434); an
  install directory whose name contains shell metacharacters is passed through without being
  re-interpreted (#489); a server URL given once on the command line stays out of the config file,
  so a later save cannot persist it (#423); shape help lists every built-in shape, including the
  `sudo-stdin` form (#484); a ruled `< ` redirect in a sudo-remote command works again, through one
  shared renderer (#332); the core install creates the `venya_audit` database role and trust map the
  append-only audit trail needs (#66); the interactive install banner is safe to run with no
  terminal, the CLI's stderr tee honors isolation, an executor with a ghost identity refuses at boot
  with the re-enroll path named, and the Docker gate runs after enrollment (#360, #361, #362, #363,
  #365); and the secret-bearing files and directories the CLI creates are written at their final
  mode instead of tightened afterwards.

- **Authorization, session, audit and timekeeping fixes from the same wave (recorded late; same
  range).** Secret writes are scoped to the caller's own groups, and the secret and session
  authorization checks read the caller rather than the request; the role member roster reads to
  members and their oversight tiers (#448); the server-minted root CA carries the key identifiers
  strict verifiers expect (#522); an account-status write can no longer strand the last usable
  admin, and the lockout guards count the roster under a row lock so a concurrent request cannot
  slip past them (#486, #487); a reset needs admin authority once the core is initialized, and it
  re-checks that precondition under the bootstrap lock (#450, #511); a break-glass recovery code is
  claimed atomically so one code cannot be spent twice, and an executed command session cannot be
  replayed (#512, #513); a secret upsert takes a locking read on its own key, and the account rate
  limiter keeps its counters consistent under concurrency (#515, #516); admin user delete completes
  for a user who still holds credentials or roles, and deleting a non-empty role returns the
  dependency message instead of failing (#425); rate-limit lockout answers `429` with `Retry-After`
  and a failed secret retrieval arms the account limiter the way a failed login does (#385, #421);
  a stored FIDO2 challenge expires with the ceremony lifetime instead of lingering (#408);
  session-demanding admin routes verify the certificate and the session (#340); the command wire
  carries argument lists, and a NUL byte in an argument is refused at the structural gate (#322);
  the direct path's inner guard and the ruled gate now share one bound-path helper (#374); the
  disk-encryption check reads the mount it was asked about and that mount's own device lineage
  (#444, #488); the close-on-exec sweep steps over a descriptor that closed while it was being read
  instead of reporting a failure (#535); the database key-encryption key has one protected owner in
  the backend cache, which the filter and sentinel paths read (#472); the audit spool's FIFO writer
  logs the path it gave up on (#420); rate-limit windows come from the shared database clock, age
  gates that could go backwards are clamped, and the expiry-clock relabel applies only to a naive
  input, so a clock step neither shortens nor lengthens a session (#460, #464, #465, #549); and a
  paginated list carries a tiebreaker, so two reads in the same instant return the same page
  (#463).

- **Executor concurrency, certificate issuance cadence, and the boot-cleanups (recorded late; same
  range).** Two new settings an operator can set: the executor now admits relay commands under one
  named ceiling — `[executor] max_concurrent_commands`, env
  `VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS`, shipped default 1 which is the old sequential posture,
  with no fixed ceiling because the honest maximum is the machine's memory (RF-3); and admin
  certificate mints are rate-limited per key per hour by `rate_limit.cert_issuance_requests_per_hour`
  (env `VENYA_RATE_LIMIT__CERT_ISSUANCE_REQUESTS_PER_HOUR`, shipped default 5), so a script cannot
  out-mint an operator's willingness to touch a security key (RF-7). The workstation CLI rebuilds
  its admin TLS context when the certificate file's content changes rather than when its timestamp
  changes, so a restore that preserves `mtime`, a `cp`, or a re-download of an identical file all
  get the new material presented instead of the old (RF-8c). At boot the executor reaps the leftovers of
  earlier runs: sandboxes no teardown claimed (#474), and shared-memory directories under either
  prefix the sandbox strategy writes, older than the session lifetime (#469). The static askpass
  helper is copied to a path that allows execution before the sandbox calls it, keeping mode 0555
  and the no-secret-in-argv posture (#426); the core installer picks the active PostgreSQL cluster
  head rather than an inactive one (#496); each installer code fix verifies its own post-condition
  and says so, instead of reporting success on the `sed` exit status alone (#519); the core
  installer confirms the nginx restart it asked for instead of assuming it (#454); a sandbox
  teardown that fails is logged and no longer allowed to replace the command's own outcome (#417); a truncated
  sandbox output carries the in-band marker the direct path already used (#409); and a policy
  rejection returns `422` with the reason rather than a transport-shaped error (#410).


- **CLI secret handling and dead code, from the same wave (recorded late; same range).** A security
  key or CA material the CLI holds in memory now lives in one protected buffer that is zeroed on
  release, with the pinning outcome reported as it was measured rather than as a promise (#538);
  files and directories that carry secrets are created at their final mode — atomic
  write-then-rename at seven write sites including the enrollment token, `0700` at the ten secret
  directories — so no value is briefly readable under the process umask, and the redundant
  after-the-fact `chmod`s are gone (#15-class wave, `fix(cli): create secret-bearing files and dirs
  at their final mode`); two zero-caller methods found dead were removed (#15); the injector helpers
  nothing called and the shared-memory prose that outlived them were removed (#471); the deploy
  record refuses a dirty source tree (#16); and the browser-auth router's module docstring now
  states what is mounted instead of what was disabled in August (#312, documentation).


- **Backfilled from the release completeness audit (leg 389, applied here).** Every row below is one merged change that had no entry in this file. The wording is the merge's own subject where the merge wrote one; where a merge landed with only a branch name, the row is the ticket's title, marked "Addressed:" so it cannot be read as shipped behaviour. Each row names the ticket ids it carries, the count of operative files, and the merge sha. One row per merge: several tickets rode a single merge, and those ids are listed together rather than repeated as separate changes.
- **touch cue prints once per operation, re-shown on PIN retry** (`#10`; 2 operative files; merge `587801e5a`).
- **Stage-1 filter contract tightening** (`#20`; 5 operative files; merge `8890b7f80`).
- **register retries back off, permanent rejections stop loud** (`#24`; 4 operative files; merge `6729ec12c`).
- **clean startup exit for missing-CA TLS refusal** (`#41`; 2 operative files; merge `9742a4494`).
- **dns_resolver wording made honest about egress-allow semantics across surfaces** (`#50`; 5 operative files; merge `a4fa16a66`).
- **auditor help copy — full-visibility + exclusive-tier wording; regen cli-reference; lifecycle-test SoD notes; +1 help-pin test; wording owner-approved; expected cli 1022** (`#290`; 4 operative files; merge `7d490e91c`).
- **middleware stashes the admission verdict + presented serial so the audit-ingest sender flag shares one derivation by construction** (`#311`; 4 operative files; merge `80ad7ca15`).
- **tree-wide baseline resync + core tripwire interlock — the UPGRADE.md prose finding baselined, one-time delta +1 entry; detect-secrets==1.5.0 pinned dev-side** (`#313`, `#321`; 4 operative files; merge `69e9e60eb`).
- **daemon umask 077 + atomic private-mode writes — world-writable key window closed on boot and rotation** (`#316`; 5 operative files; merge `f46900619`).
- **per-end boundary anchoring + component-aware trusted-path compare — 2 vacuous default patterns and the custom-config surface now match as written** (`#318`; 2 operative files; merge `76f3e5c67`).
- **stop the core install when the PostgreSQL config dir is missing, and purge the macOS config dir in the CLI uninstaller** (`#319`; 2 operative files; merge `f1f3d12f7`, also `2a5ec5e04`).
- **boundary validation of server-issued secret_id before both path sinks, reject-before-write** (`#320`; 2 operative files; merge `58ab3d89f`).
- **Addressed: lone-surrogate argv executes then crashes the completion audit write — side effects kept** (`#334`; 7 operative files; merge `7e21a5990`).
- **retire the server-side CA export/restore pair in favor of the CLI custody format, and make the CRL conditional-GET ETag cover the served capped population with loud truncation signal** (`#336`, `#337`; 7 operative files; merge `ec367999e`).
- **retire the unread require_in_production knob, elevation challenge lifecycle, rotation-model forbid with dead CLI flag retired, admin-plane enumerated constraints, and the PostgreSQL-dialect guard on the enrollment advisory lock** (`#338`, `#345`, `#355`, `#356`, `#366`; 16 operative files; merge `f270d29ca`).
- **enrollment-cap advisory locking, browser cookie session-plane alignment, persisted bearer-token expiry with fail-closed validation, and direct 48-char recovery-code generation** (`#339`, `#341`, `#342`, `#344`; 16 operative files; merge `ea615e40e`).
- **Addressed: legacy /enrollment/tokens mint/revoke bypasses the lifecycle audit events its admin twins emit** (`#343`; 3 operative files; merge `e602a2142`).
- **Addressed: revoke-cert reason field unguarded against String(64) column — 65+ chars 500s the admin action** (`#346`, `#347`; 6 operative files; merge `27c8505ad`).
- **Addressed: MCP get_audit hours accepts negatives — future cutoff returns silently empty audit** (`#348`, `#349`, `#350`; 4 operative files; merge `42f58dc12`).
- **redact secret argv in the support-log header, stage renew writes to random-name temps, refuse structural characters in admin identities before minting, and encode secret keys and user IDs in URL paths with ruled charset validation** (`#351`, `#352`, `#353`, `#354`; 10 operative files; merge `be6bd736f`).
- **repo-wide extra=forbid on request-body models with interlock pin and ruled exemptions** (`#357`; 13 operative files; merge `51cddf46b`).
- **recovery requests carry only declared wire fields, local flags stay client-side** (`#367`; 2 operative files; merge `199aee866`).
- **the serve-time hash embed lands only at the assignment default with the guard comparison made embed-invisible, and executor credentials are hardened right after registration so a Docker-gate abort leaves a bootable install** (`#368`, `#370`; 5 operative files; merge `85e6e2741`).
- **RecoveryRequest carries the same declared-fields-only rule as the rest of the request models now that its exemption condition is gone** (`#371`; 4 operative files; merge `791045c57`).
- **exec-register certificate writes are atomic and mode-pinned, and the setup CA directory takes the standard secret-dir idiom** (`#376`; 3 operative files; merge `40441375e`).
- **the recovery --force/--confirm no-ops are retired with paired reject cells and the regenerated reference carrying the leaner surface** (`#377`; 6 operative files; merge `312cd832b`).
- **executor state-dir mode pin now applies on both install paths** (`#380`; 2 operative files; merge `200874b0b`).
- **ignored-knob notice for VENYA_EGRESS_ALLOW on core installs** (`#382`; 2 operative files; merge `49467962f`).
- **kvm group re-assert now runs on every executor install** (`#384`; 2 operative files; merge `535f8510d`).
- **drop the inert --allow-host/--no-network daemon flags** (`#386`; 2 operative files; merge `663569dec`).
- **chokepoint honors --core-url alias** (`#387`; 2 operative files; merge `aa615fc69`).
- **renew public-material posture** (`#388`; 2 operative files; merge `5b6a74dd7`).
- **admin executor row removal — DELETE /admin/executors/{id} + 'venya admin remove-executor** (`#391`; 8 operative files; merge `72dfb7141`).
- **drop seven inert server config fields** (`#392`; 1 operative file; merge `625d12091`).
- **remove /var/backups/venya in core uninstaller** (`#394`; 2 operative files; merge `8ca35fb48`).
- **core/executor uninstallers verify removals before claiming success** (`#396`; 3 operative files; merge `370f2296f`).
- **one-shot register URL stays in memory, CLI config no longer written** (`#398`; 2 operative files; merge `5467ad8e3`).
- **uninstallers fail loud, not silent, on non-interactive confirm** (`#399`; 4 operative files; merge `01640220d`).
- **ps1 ACL check reports coverage honestly** (`#400`; 2 operative files; merge `e4f490042`).
- **ps1 mcp install claim gates on verification, temp sweep discloses** (`#401`; 2 operative files; merge `14cf05c63`).
- **ps1 uninstaller verifies removal sites before claiming success** (`#402`; 2 operative files; merge `f822e0aec`).
- **cli installer discloses a skipped venya-mcp import check instead of claiming install** (`#403`; 2 operative files; merge `5712d022a`).
- **sandbox setup runs inside the remove guard — a setup raise no longer leaves an orphan VM** (`#406`; 2 operative files; merge `6f381dca2`).
- **best-effort honest audit row written when the execution relay times out** (`#407`; 2 operative files; merge `deb4d8de0`).
- **session-secret revoke deletes the session's rows so revoked means non-resolvable** (`#411`; 3 operative files; merge `63318fab8`).
- **enrollment complete validates token state like the completer, before side effects** (`#412`; 2 operative files; merge `3214d645b`).
- **server-side user-verification knob wired; enforcement branch reachable** (`#413`; 5 operative files; merge `50bff3b7d`).
- **get_audit tool text now matches the auditor-tier gate** (`#414`; 2 operative files; merge `e6b6d99a7`).
- **argv parsed before session creation — malformed commands issue no POST** (`#415`; 2 operative files; merge `fe307908a`).
- **credential id crosschecked against the attested id before any store/DB write** (`#416`; 7 operative files; merge `df97de63d`).
- **relayed pre-sandbox rejections now land a command_rejected row on the core ledger** (`#424`; 2 operative files; merge `866af5c50`).
- **Addressed: installer-reuses-dead-dns-resolver-silently — executor.toml carry-forward skips reachability check** (`#428`; 1 operative file; merge `b120dd3fb`).
- **Addressed: sbx-exec-env-file-noop — deployed sbx 0.38.0 accepts 'exec --env-file' and injects nothing** (`#430`; 7 operative files; merge `659ba9881`).
- **Addressed: audit-forwarder-httpx-cert-verify-conflict — forwarder TypeErrors every cycle on httpx2 2.12** (`#432`; 2 operative files; merge `ed73b888b`).
- **Addressed: audit-spool-forwarder-session-lifetime — forwarder exists only during command sessions** (`#436`; 2 operative files; merge `0f05fa8ac`).
- **Addressed: cli-windows-posix-geteuid-crash — POSIX-only os.geteuid() calls crash the Windows CLI on setup/exec-register/cert-renew paths** (`#438`; 4 operative files; merge `3eb1db9f9`).
- **Addressed: auth-me-ignores-bearer-token — a bearer-authenticated client is told it is unauthenticated** (`#445`; 2 operative files; merge `dd32442e2`).
- **Addressed: shm-session-dir-leak-on-secret-write-failure — staged secret directory survives a mid-stage failure** (`#446`; 2 operative files; merge `ea58056dc`).
- **Addressed: require-role-blanket-executor-pass — an early return passes every role gate for an executor identity** (`#449`; 8 operative files; merge `658fcd45a`).
- **Addressed: stage2-decode-swallow-empty-masked-count — an undecodable filter body answers 200 with zero knowledge and no log** (`#452`; 5 operative files; merge `9224c5ddf`).
- **Addressed: health-probe-cannot-distinguish-uninitialized-from-broken — the readiness surface answers fine for a component it never checked** (`#455`; 3 operative files; merge `48a802bcd`).
- **Addressed: secret-destroy-failure-warns-and-reports-success — a failed secret destroy leaves material resident and the run green** (`#456`; 2 operative files; merge `07ead2550`, also `68aa9595d`).
- **Addressed: enrollment-token-used-at-backdated-by-tolerance — one bind value serves the expiry check and the record column** (`#462`; 2 operative files; merge `64a88e691`).
- **Addressed: zstd-ingest-expands-before-size-brake — the decompression brake is paid for in RAM before it applies** (`#473`; 2 operative files; merge `87b04cd1c`).
- **Addressed: installer-temps-survive-abort-outside-fetch-trap — CSRs and a large tarball outlive an aborted install** (`#475`; 4 operative files; merge `99302cfef`).
- **Addressed: cli-cert-save-cleanup-guard-too-narrow — the one staged-temp site guarded by OSError instead of BaseException** (`#476`; 2 operative files; merge `f9833d5ce`).
- **Addressed: core IP written to /etc/hosts unvalidated — executor installer permits host poisoning** (`#490`; 3 operative files; merge `43b000dcd`).
- **Addressed: IPv4 validator word-splits unquoted input — wildcard octets expand against the working directory** (`#491`; 2 operative files; merge `3f1bd77b0`).
- **the relay dial trusts only the configured Venya anchor** (`#501`; 3 operative files; merge `81583b12a`).
- **the revocation read and the FIDO2 ceremony transport now require an https core URL** (`#521`; 4 operative files; merge `d354917d9`).
- **the workstation bearer dial now requires its own CA anchor instead of the host store** (`#530`; 4 operative files; merge `89daa44e3`).
- **the ceremony dial anchors to the Venya CA or refuses** (`#533`; 6 operative files; merge `e3fcc93ba`).
- **Addressed: cli-register-executor-dial-falls-back-to-host-store — the executor registration dial still accepts the workstation OS trust store** (`#536`; 10 operative files; merge `98ed0493c`).
- **Addressed: ca-key-load-plaintext-with-passphrase-typeerror — a legacy unencrypted CA key plus a configured passphrase raises TypeError instead of a helpful refusal** (`#541`; 5 operative files; merge `bc75ddc9a`).
- **Addressed: detect-secrets-hook-rewrites-shared-baseline-mid-commit** (`#546`; 4 operative files; merge `facea4898`).
- **Addressed: cli init-admin-ca — no-passphrase branch writes plaintext CA key while the server path refuses** (`#547`; 6 operative files; merge `8cfe15104`, also `f9d3dc195`).
- **Addressed: baseline self-reference makes naive filename greps over-count the detect-secrets baseline** (`#550`; 4 operative files; merge `4cd8a9908`).
- **Addressed: revocation-list HTTP status error escapes both handlers and stops the executor daemon** (`#551`; 2 operative files; merge `d420b8e5e`).
- **Addressed: revocation-list-malformed-payload-stops-daemon — a 200 with an unparseable revocation body takes the executor daemon down** (`#552`; 2 operative files; merge `b2fe78e17`).
- **the sbx store-over-HTTP path is gone: it had no production caller, its two cells passed even with the transport removed so they asserted nothing, and the sentence describing third-party behaviour behind it had never been observed by anyone in this workspace; the generated bandit register moves 64 to 63 in the same commit and the interlock holds, verified by checker with all five veto questions answered by command and output, and independently audited pre-veto by a second seat that confirmed the deletion is complete and no coverage was lost** (`#556`, `#558`; 3 operative files; merge `232e56278`).
- **the engine comments now name the SET statements they actually guard instead of calling them PRAGMAs, which PostgreSQL has no such statement of; comment prose only, proven by a parse-tree check, and the baseline pointer it moved is a separate commit with its own reason** (`#636`; 2 operative files; merge `e4d3c9688`).
- **the PostgreSQL test door now says what is wrong with it: a pre-flight at the door's own setup reads the socket or address the URL names, reads the free space on the volume that holds it, and when a leg asked for the door and this host cannot give it, the gated cells are aborted with the cause, the number, the consequence and the fix instead of dying as psycopg2 product reds. Four causes are kept apart on purpose — never started, died mid-run, refused, space low — because a lane told the disk is short when 4.8 GiB is free goes and frees a disk that was never the problem, and a healthy door plus every non-gated cell pass straight through. One shared rule in scripts/pg_door_preflight.py with two thin conftest wirings; the new core conftest is proved inert for the other 542 collected cells and server's hook shadows no fixture, and 29 cells cover the causes, the paired negatives, the redaction, and a contract that walks the tree to assert every gated class actually names the door in its skip reason** (`#650`; 4 operative files; merge `492fe4e3b`).
- **Addressed: cli-admin-cert-bootstrap-init-gate-self-blocks-first-mint — APIClient constructor requires the pair that admin cert renew exists to create** (`#667`; 3 operative files; merge `413194b1c`).
- **Addressed: already-revoked-serial-echoes-the-path-executor-id — the duplicate branch answers before the pairing check** (`#687`; 2 operative files; merge `f07066c9a`).
- **Addressed: legal-command-redirect-starves-remote-sudo-when-sshpass-is-present — the blessed < allowance is legal by validation and un-executable by construction** (`#695`; 2 operative files; merge `41874131f`, also `fa77a48d9`).
- **batch after the owner read** (`#698`; 2 operative files; merge `dcf25968f`).

- **Backfilled from the merge audit in tiered form:** each entry
  was reconstructed from merge deltas, names the merges it stands for, and minor families are combined.
- **CA and admin key material is written encrypted and rotation is all-or-nothing.** An unencrypted CA key is refused when a passphrase is set, the root CA key is encrypted at rest, and a rotation
  that is interrupted cannot leave a mismatched pair or overwrite its own trust anchor; the core installer's own key-handling half
  changed with it (`install-venya-core.sh`, +67/-22). Merges `04c1c28ca`, `0c44386fe`, `919298256`, `2cb92a425`, `e52e9589c`. Tickets named by those merges: (`#316`)
  (`#361`) (`#500`).
- **Admin certificates are short-lived, and status tells you which one you are holding.** A renewed admin certificate is issued short-lived, an expired one is refused rather than presented, and the
  fingerprint context it was issued into is named. Merges `41d49426c`, `f6a1120c2`, `e07b5ada1`, `a28e6355d`, `e606be446`. Tickets named by those merges: (`#504`).
- **A loose admin key is now reported instead of silently accepted.** The CLI checks the mode bits on the admin mTLS key file on POSIX and prints a `warning:` naming the path, the mode it found and the `0600` it wants when group or other can read it; the trigger is the group/other read bits, correct modes stay silent, and it **warns and never blocks** — the exit code, stdout and every request the CLI makes are unchanged. Merges `7309444bd`.
- **Every trust decision goes to the configured CA anchor, and plaintext is refused.** Setup, config-set, register and the MCP dial refuse a non-TLS origin; the executor's dials trust only the CA
  installed on this host, not the host store added to it; admin mTLS is gated on both of its values being set; CSR signing accepts the curves the register route advertises. Merges `896e0dca4`,
  `c58bec54c`, `815a882ee`, `2728796d9`, `549179373`, `c4ef6afc0`, `b9e9e622f`, `d59a06803`. Tickets named by those merges: (`#17`) (`#506`) (`#508`).
- **CLI setup and register follow the server's answer instead of asserting one.** Setup and exec-register resolve the identity, token and URL the server returned instead of the values the client
  guessed. Merges `2ccc0142a`, `28a2fe075`, `92e87af89`, `d7cb70624`, `b0ee5134a`. Tickets named by those merges: (`#3`) (`#4`) (`#5`) (`#366`).
- **Authorization is scoped to the caller, and unauthenticated paths that could claim an identity are closed.** Secret writes and session reads are checked against the calling principal, the
  registration route refuses an unauthenticated takeover, the reset wipe is no longer reachable as a race, and role removal or admin disable refuse the state that leaves no way back in. Merges
  `50364584a`, `03097624f`, `0dd03ae0f`, `f159fcc13`, `bdf6e073b`, `08bf24df5`, `d3245c739`. Tickets named by those merges: (`#3`) (`#15`) (`#16`) (`#450`).
- **Admin mTLS callers are checked against an allowlist, and a revoked certificate stops working.** The admin middleware reads the client certificate serial and tests it against the known admin set and the in-process revocation record; an empty allowlist fails closed, as does a missing serial or a lookup error, so no caller is admitted by an absent answer. Merges `851f7e6db`.

- **Re-running init over a database that was wiped but still seeded converges instead of failing.** Role creation is now get-or-create on `roles.name`, so the stale-roles path no longer raises; the full detail, including any SQL, is logged server-side and the client receives a generic `Reset failed` rather than the internals. Merges `985acc698`.
- **Elevation is bound to the session that asked for it.** An elevation token is bound to the session and challenge state it was minted with, and refresh refuses when no active user backs it, and two schema additions carry that
  binding — migration `035` adds the elevation token's session column and migration `036` adds the elevation-challenges
  table, so a fresh install gets both. Merges
  `d3b264a48`, `53352d089`, `ce81db155`, `efa7660ef`, `d8ec78f18`. Tickets named by those merges: (`#341`) (`#345`).
- **Runtime settings are obeyed where they were ignored, and failures no longer read as clean.** The concurrency ceiling is read from configuration, a capture honours its
  timeout, a relay stop runs its cleanup under systemd, credential load and removal stop swallowing failures, a file-descriptor scan with an empty set no longer reads clean, and debug logging stopped
  carrying session cookies. Merges `dca43dd43`, `ea9414175`, `02823ab7f`, `2d51ed9f2`, `3527ce4fd`, `7525d072c`, `19aabdada`, `876286ab2`. Tickets named by those
  merges: (`#453`) (`#477`).
- **One canonical certificate serial everywhere, so a revocation actually takes effect.** The same serial was written zero-padded and presented unpadded, and revocation lookups compared the two by exact string equality — a leading zero nibble (roughly one certificate in sixteen) left a revoked credential matching as live. Serial handling now lives in one shared module used by the CLI, the executor daemon, the server CA, its admin middleware and the revocation paths. Merges `8f7647a3e` (`#481`).

- **Error responses stopped carrying internals to the client.** Registration and authentication failures return a generic detail while the full text, including any SQL or library message, is logged server-side; the WebAuthn manager forwards only what an operator needs, and the core installer's nginx config now sets `server_tokens off`. Merges `ad8e5f59e`.

- **The broken browser-enrolment FIDO2 helper is removed, and with it the `venya-fido2` command.** The server no longer ships `server.fido2.cli_enroll` (228 lines) or its tests (121 lines), the `venya-fido2` console entry point is gone from the server package, and the generated suppression register moved down with it — the page and the dependency list are already in step, so nothing else rides on the removal. Merges `8078a4a33`.
- **Requirements are now generated from the lock, so an install gets the versions that were tested.** The core and executor
  requirement files went from five hand-written lines to a frozen `uv export` pin set (125 and 92 lines added), so a fresh
  install resolves the same third-party versions the project tested against instead of whatever the index offers that day;
  the generator and the hook that keeps the files derived rather than typed ship with it. Merges `fc63faa4f`.
- **Executor build is now reported and stored, via a new column.** Migration `029` adds `executors.version` — nullable, with
  deliberately no backfill, so a `NULL` honestly means "this daemon predates version reporting" — and the heartbeat, the CLI,
  the server and the admin surfaces carry the value. Merges `aac1a8656`.
- **The consumed bootstrap enrolment token moved where the daemon can actually write it.** `/etc/venya` is `ReadOnlyPaths` for
  the service, so clearing the old section failed and could crash-loop the boot; the token now lives under
  `/var/lib/venya/executor/`, which is writable, and the legacy hand-placed section is still honoured; the executor installer moved with it (+22/-20). Merges `064cda32f`.
- **Installer and uninstaller prompts, guards and copy.** Merges `ffd66e458`, `a1e6e146d`, `a26af9bb7`, `47dd345c0`, `6f500035c`,
  `357e0561b`, `84842b261`, `f81ff9cf2`, `4de076954`, `a1f9926f7`, `302aa657d`.
- **Enrolment-surface fixes.** Merges `e8dfdb831`, `fc943083f`, `dbd5eaa7b`.
- **A dead public-path entry is retired, and two low-information sweeps.** `/api/v1/enrollment/confirm`
  left `SessionMiddleware.PUBLIC_PATHS`: no route ever matched it, and a dead allowlist entry is how an unmounted path
  stays mounted, so its absence is now pinned by a cell in `test_session_middleware.py`. The rest of this pair is unused
  code and sweep residue. Merges `d9ec2ccd7`, `4b487edfe`.



- **The shipped tree carries no development-site names (`#689`).** Test fixtures, two
  docs and one database column comment named real development hosts, an operator
  identity and a workspace path. They now use the documentation forms the tree already
  uses (`admin@example.com`, RFC 5737 ranges, a `<core-host>`-shaped example). The
  interlock that was written to stop this only matched IP literals and only walked
  `packages/` and `docs/`, so it could not see a hostname, an email or a path, and it
  never opened the root `CHANGELOG.md` at all; it now matches hostnames, operator
  identities and workspace paths too, and walks every top level the release bundle
  actually ships. No product behavior change — one column COMMENT changes, through a
  migration (`042`).
- **A revoke command now accepts the whole serial it can be shown (`#682`, `#676`).**
  Certificate serials on this product are wider than the sixteen characters the revoke
  inputs used to allow, so a serial copied from a listing or a journal line could be
  refused as malformed. The input bound now matches the width the store holds, at every
  gate that reads one, and the help text names the new length. Nothing about how a serial
  is stored or matched changed — the same value is accepted where part of it used to be
  cut off.
- **`venya exec list` prints a certificate's full serial (`#682`, `#481`).** The listing
  showed a sixteen-character prefix, which is the value an operator then typed back into
  a revoke command. It now prints the whole canonical serial, and the cell that guards
  the row asserts it against the same helper the write path uses, so the listing and the
  store cannot drift apart again.
- **An administrator certificate with a protected key now works for admin calls
  (`#565` Part B).** The TLS layer supplies a passphrase callback, so a key written
  encrypted at rest by `venya admin cert renew` or `venya admin generate-admin-cert` can
  authenticate an admin request. A key that is already plaintext is untouched; an
  encrypted key with no passphrase in the environment is refused by name before anything
  is sent, and a wrong passphrase gets its own sentence. The passphrase is read through
  the same rule the writers use, so the length and blank checks answer once on both sides.
- **The install summary names the variable an admin command needs (`#673`).** Where the
  banner formerly said that loading a protected admin key was still open work, it now
  names `VENYA_ADMIN_CA_KEY_PASSPHRASE`, says it must be in the environment of any admin
  command presenting a renewed pair, and states that the machine-plane pair needs no
  passphrase and stays the headless pattern. The banner no longer prints a command that
  reads a stored secret back; it points at the runbook section that describes where it
  lives and how it is recovered.
- **The installer no longer advertises a way to turn admin mTLS off (`#673`).** The
  variable stays documented where documentation lives; it is left out of the text an
  operator reads at the moment a connection is refusing, where the pressure to disable a
  check is highest. The heartbeat route's role comment now describes what it does, and a
  new suite names that contract as a test — a revoked executor still receives the
  cooperative-stop answer that lets it wind down on its own.
- **`venya admin revoke-token` reads the core's answer before it reports success (`#666`).**
  The route returns a per-token result, so an identity it did not touch used to arrive
  with the request accepted. The command now requires the answer to say the token was
  revoked, names the user plane in its confirmation, and otherwise exits non-zero saying
  nothing was revoked.
- **CA key custody keeps its unwrapped material under management (`#674`).** The split path
  and both restore arms now run the decrypted key through the same holder the file
  already uses elsewhere, so plaintext CA material is not held past the act that needed
  it. No format change, no encryption change, no migration; the share files an operator
  already holds restore exactly as before.
- **`/ready` answers on capacity reserved for it (`#603` AC2).** The readiness probe reads
  on the liveness pool, so it keeps answering while ordinary traffic holds every shared
  slot, and it no longer reports itself healthy after winning a slot on a contended path.
  A capacity event stays a capacity event: the probe answers degraded rather than raising
  out of a health endpoint. The refusal counter, its threshold and its cadence are
  unchanged.
- **A passphrase prompt says where its rule bites (`#675`).** The read door that unlocks an
  existing CA key states the length rule and names the gate that enforces it, rather than
  implying a check that is not there — the floor governs writing a new passphrase, and a
  read that refused one would lock an operator out of their own key.
- **The beta terms page names only a variable that exists (`#678`, `#675`).** The entry for
  the administrator key passphrase carried a name the shipped installer never wrote; the
  page now names the one it does, so following the documented recovery step cannot point
  an operator at an unset variable.
- **The revocation registry is described where an operator would look (`#597` AC5, `#597`).**
  `BACKUPS.md`, `cert-rotation-runbook.md` and `FIREWALL.md` now state that the core's own
  relay credential holds a registry row, how to list it, and that revoking it is a step
  with its own command. The firewall page's loopback rows name the certificate that hop
  actually presents, and its relay row says a revoked credential is refused when the
  connection is admitted — before any request is served, not at the handshake.
- **The backup page states the one artifact it excluded (`#221`).** The machine-plane
  administrator pair under `/etc/venya/admin/` is named as deliberately not backed up,
  with the reason: the installer re-mints that pair on every run that turns admin mTLS on,
  so an off-site copy of it buys nothing. The delivered-mode table already carried the
  modes; the exclusion is now written down beside them.
- **Documentation reads to the beta program.** The installation guide, the FAQ, the
  README, `FIREWALL.md`, `architecture.md`, `BACKUPS.md`, `secret-shapes.md`,
  `beta-known-limitations.md` and `installation.md`'s air-gap section now describe the
  program as it is priced and admitted, and the trusted-path rule as the gate actually
  computes it — a command is refused when it does not resolve into a trusted directory,
  which is not the same claim as "shell builtins are rejected". A command that has a real
  binary behind it is accepted; the refusal reason is printed for the ones that do not.
- **Three install-time writes are atomic, and the surface scan that checks them is
  installed (`#447`, `#675`).** The beta-terms generator, the citation helper beside it and
  the install-time fix application now write through a temporary file and a rename, so an
  interrupted run leaves the previous file in place rather than a half-written one. A
  pre-commit census keeps every bound on the HTTP client named in one place.

- **`admin revoke-admin-cert` refuses a serial no admin credential ever held (`#684`).**
  That verb used to check the shape of the string, find nothing in the revocation table,
  and write a revocation anyway: exit 0, while the live administrator credential kept
  transacting. The core now keeps a registry of the admin credentials it has seen — at
  boot for the machine-plane pair, at every issuance, at every connection the admin check
  admits, and by an explicit register command — so there is something to be a member of.
  A serial that registry does not name is refused before anything is written, and the
  refusal says so by name. A serial already revoked keeps its repeat answer. The registry
  is a new table, so an existing install picks it up on the normal migration step.
- **The executor revoke verb binds a serial to the certificate holding it (`#685`).**
  The same gap on the executor plane: a serial no certificate carries, or a serial that
  belongs to a different executor than the command names, is now refused instead of stored
  as a revocation attributed to nothing. A predecessor serial that a rotation already
  retired keeps its repeat answer, so revoking the same value twice does not become a
  refusal.
- **A revoked executor is no longer aged out on a timer (`#685`).** The maintenance pass
  that deleted executor revocation rows older than the retention window is gone, together
  with the method it called, so no shipped path can drop a revocation while the credential
  it names may still be valid. A dropped row stopped answering the lookup and stopped being
  listed, and the revoked executor kept connecting. The counter that tracked those deletes
  stays published at zero on purpose: an operator who ever sees it above zero is watching a
  purge run again, which is the behavior this change removed. And the retention setting is
  now checked when a core loads its config — a
  window shorter than the longest lifetime among the credentials these tables name is
  refused at startup rather than quietly honored, which is why that setting's usable range
  no longer reaches down to 1.
- **A revoke command says whether this call did it (`#666` class).** Revoking a credential
  that was already revoked reported the reason typed into this call, which is not the
  reason on record. The command now prints that nothing changed. The executor removal
  headline names the serial it revoked, or says there was no certificate record to revoke,
  and an already-revoked certificate or identity is reported as such. Exit status is
  unchanged: the report follows the core's answer rather than asserting the action.
  Merges `685e3cca9`, `fcd1b34c6`, `daf745e2b`. Tickets named by those merges: (`#481`) (`#666`).
- **A revocation limit claims only the door it was measured at (`#676`).** The beta
  limitation entry no longer states that both directions of a connection were seen
  refusing. It says what was seen: the listener door, in both of its populations, refused a
  revoked peer on a running deployment; the core's own dial-out has never been observed
  refusing one, and the entry names that half as unobserved instead of implying it.
- **The executor enrollment-token revoked state is documented as unreachable (`#672`).**
  No shipped command can put an executor enrollment token into that state on this plane, so
  those tokens expire on their time limit and nothing else. The code now says so where the
  branch sits, and a test fails if anyone later adds a writer for it, so the branch cannot
  quietly become load-bearing.
- **Operator pages read to the beta program.** The firewall page's status line,
  the upgrade guide and the installer's own readme now say beta where they said alpha. The
  upgrade guide stops understating a restore drill: the restore path is validated by the
  drill recorded in the backup page, and what stays unverified is named as the CA-key
  custody round-trip rather than the whole procedure. The passphrase row for a re-run now
  states the rule the installer actually enforces — the length floor applies to the stored
  value too, so a short passphrase already on disk refuses at the pre-mutation gate, and
  the way forward is a deliberate reinstall or a deliberate rotation, never a silent one.
- **Three documented guarantees became tests (`#597`, `#684`, `#634`).** The relay-credential
  adoption case — an on-disk credential with no registry row, ingested at a real boot, with
  four paired negatives — the citation check against the beta terms page, and the executor
  token store each now have a cell that fails if the behavior drifts; the token store's cell
  also turns on the foreign-key enforcement its sqlite engine used to declare without
  applying. Four of the five adoption cells were shown failing against an ingest deliberately
  made to do nothing, so the guard is proven to bite. Nothing an operator types changed in
  these three.

## 0.1.0alpha17 — BELAYED, never released (date below is when the name was withdrawn, not a ship date)

> This version was **belayed as a release name** by the owner on 2026-10-15 ("alpha17 belayed as a release name"), and **no `v0.1.0alpha17` tag exists on any face** — the entry body below is kept as the dated record of work that shipped later under `v0.1.0beta1`. Deliberately not written as `## [0.1.0alpha17]`: the bracket form is what a release claim is matched on, and this is not one.

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
  `docs/design-fido2-keywrap.md` §6. refs #565
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
- Test fixtures and docs no longer embed development-fleet addresses or identities: private-range (RFC1918) literals swept to documentation ranges (RFC 5737), the operator identity in fixtures → `admin@example.com`, dev password probe → synthetic. A tree-wide interlock test now fails CI if any RFC1918 literal re-enters `packages/` or `docs/` (installer-artifact guard extended; the guard's own self-test excluded — and note that scan never opened the root `CHANGELOG.md` at all, which is what the later scrub-and-widen leg fixed). No product behavior change.

- **BREAKING — Executor: the built-in DNS-resolver default is removed; `dns_resolver`
  is now explicit config.** The sandbox egress policy previously always admitted a
  hardcoded resolver IP (a development-fleet address, functionally
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
  `v0.1.0alpha14` seeded a development-fleet subnet — a private RFC 1918
  range that is not yours. If the file holds a private `10.*` range you did not add,
  delete it or replace it with your own target ranges; the file is
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
