# Changelog

Notable changes to Venya will be documented in this file.

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
