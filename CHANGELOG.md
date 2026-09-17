# Changelog

Notable changes to Venya will be documented in this file.

## [Unreleased]

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
