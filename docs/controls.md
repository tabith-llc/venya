# What Venya enforces, and how to check it

**Alignment, not certification.** This page lists mechanisms Venya's code enforces and tells you how
to re-derive each one yourself. It is **not** an attestation, an audit opinion, or a claim of
certification: SOC 2 attestation requires an independent assessor, and NIST SP 800-53 compliance
requires an assessed, authorized system boundary. Nothing here says either happened. The word this
page supports is **alignment**; the word it never claims is **certified**.

**Who this is for.** An operator or an auditor who has this repository and does not have anyone's
word for it. Every row carries four cells and none of them is optional:

| Cell | Content |
|---|---|
| Control | What is enforced, scoped to where the code actually scopes it |
| Mechanism | `file:symbol` — a symbol, not a bare line number, because line numbers rot and symbols resolve |
| Verified at | The `venya-dev` commit the row was checked against, in the changeset that wrote it |
| Re-derive with | The ONE command you run to re-check it |

Run a row's command and it either prints the symbol at that commit, or it does not. A row that could
not be filled this way was not allowed into the table; it is named in **Not verified here** at the
bottom, with its reason. No row below cites a command nobody ran: every cell-four command was
executed at the face named in cell three, and the raw output is preserved with the release leg's
report (`wave35-specs-20261022/flash3-controls-383-instrument.txt`).

`git -c safe.directory='*'` appears in the commands because these repositories are shared by several
accounts on the build host; without it `git` refuses the repository and returns 128, which is an
instrument fault and not a result.

---

## Command policy

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| A deny-by-default blocklist of destructive, exfiltration, privilege-escalation and device-access patterns is scanned into every command before execution. The list ships as a **default**, not a mandate: an administrator can replace it wholesale, and the replacement reaches executors on the next heartbeat. | `packages/executor/src/executor/command_validator.py::DEFAULT_DANGEROUS_PATTERNS` | `564583eb` | `git -c safe.directory='*' grep -n DEFAULT_DANGEROUS_PATTERNS 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/command_validator.py` |
| The blocklist can be swapped out by an operator, and the value that ships in front of that is the policy the core hands an executor when nobody has set one — so "deny-by-default" means *unless the operator changes it*, never *cannot be changed*. | `packages/server/src/server/routes/executors.py::_default_command_policy_payload` | `564583eb` | `git -c safe.directory='*' grep -n _default_command_policy_payload 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/routes/executors.py` |

**How many patterns, and which count you are looking at.** Three numbers are true of this one control
and they are not interchangeable — quote one without its predicate and you have written a defect:

| Number | What it counts | Where it comes from |
|---|---|---|
| **20** | entries in the shipped tuple | `packages/executor/src/executor/command_validator.py::DEFAULT_DANGEROUS_PATTERNS` — `"rm -rf"` and `"rm -rf "` are two entries, and `" nc "`/`" ncat "` are padded forms |
| **16** | distinct command **names** an operator is told about | the Default blocklist sentence in `docs/agents.md` (`scp`, `rsync`, `nc`, `ncat`, `sudo`, `su`, `dd`, `rm -rf`, `mkfs`, `fdisk`, `shred`, `mount`, `insmod`, `modprobe`, `chmod 4755`, `setuid`) |
| 5 | examples, of a list it does not enumerate | an earlier sales-page draft, superseded by this page |

A reader who runs `grep -c` on the tuple gets **20** and is right. A reader who counts the documented
commands gets **16** and is also right. This page cites the **16 names**, because that is the surface an
operator can act on.

## Command policy scope — the row most likely to be read too broadly

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| On an `ssh`/`sshpass` remote-exec command **only the LOCAL (sandbox) half is scanned**; tokens after the destination are remote-side and pass. Any other command is scanned whole. A blocked verb therefore refuses its local form and accepts the same payload written as `ssh <host> <verb>` — this is shipped design with a guarding test, not a bug. | `packages/executor/src/executor/command_validator.py::_split_local_remote` | `564583eb` | `git -c safe.directory='*' grep -n _split_local_remote 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/command_validator.py` |
| The scope above is asserted by a named test class, so a future merge that widens or narrows it reddens a cell instead of quietly changing the guarantee. | `packages/executor/tests/test_command_validator.py::TestHostScopedValidation::test_ssh_remote_sudo_allowed` | `564583eb` | `.venv/bin/python -m pytest 'packages/executor/tests/test_command_validator.py::TestHostScopedValidation::test_ssh_remote_sudo_allowed' -q` |

Read the scope sentence and the blocklist together: **`sudo` belongs on the REMOTE side of an ssh
command only.** `docs/agents.md` states this in full, and this page deliberately links rather than
restates it — duplication is how the next merge ends up with two truths and one drift.

## Command resolution and the one ruled exception

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| Commands resolve against a fixed set of trusted paths before execution. | `packages/executor/src/executor/command_validator.py::DEFAULT_TRUSTED_PATHS` | `564583eb` | `git -c safe.directory='*' grep -n DEFAULT_TRUSTED_PATHS 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/command_validator.py` |
| In the default balanced and permissive presets the strict-mode allowlist ships **empty**, so strict mode is a different wall from the blocklist: nothing is allowed at all until an operator populates it. | `packages/executor/src/executor/command_validator.py::STRICT_DEFAULT_COMMANDS` | `564583eb` | `git -c safe.directory='*' grep -n STRICT_DEFAULT_COMMANDS 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/command_validator.py` |
| Shell metacharacters, pipes and redirects are refused **structurally**, per element, before the pattern layer runs — and the single ruled exception is a standalone `<` reading a session-bound secret path (`/run/secrets/venya/<id>`) for a secret injected in the same call. That exception is conditional: the same pair is refused when `sshpass` is the first element and the remote command behind `ssh` carries a `sudo -S`/`--stdin`. | `packages/executor/src/executor/executor.py::_validate_command_structure` | `564583eb` | `git -c safe.directory='*' grep -n _validate_command_structure 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/executor.py` |
| The session-bound `<` pair is refused in the one shape where it cannot reach the process it was written for: `sshpass` as the first element, a session-bound `<` pair, and a remote `sudo` carrying `-S`/`--stdin` behind the `ssh`. The three shapes that are not that conjunction are accepted as before, so the rule is a condition on the exception, not a narrowing of it. | `packages/executor/src/executor/executor.py::_sshpass_owns_the_stdin` | `e057a6cb` | `git -c safe.directory='*' grep -n _sshpass_owns_the_stdin e057a6cb92cfc46ef7177b6ee48f08ce82dd9840 -- packages/executor/src/executor/executor.py` |

## Egress

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| Sandboxed commands are bounded by a deny-by-default egress allowlist read from a fixed path; a missing or empty list resolves to **no hosts allowed**, it is never treated as "unrestricted". | `packages/executor/src/executor/egress_filter.py::DEFAULT_ALLOWLIST_PATH` | `564583eb` | `git -c safe.directory='*' grep -n DEFAULT_ALLOWLIST_PATH 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/egress_filter.py` |
| The fail-closed half of that is asserted by a named test: with no allowlist file the result is an empty allow set, not an open one. | `packages/executor/tests/test_egress_filter.py::TestReadAllowlist::test_missing_file_returns_empty` | `564583eb` | `.venv/bin/python -m pytest 'packages/executor/tests/test_egress_filter.py::TestReadAllowlist::test_missing_file_returns_empty' -q` |

Bounds **network** egress of a sandboxed command. It is not a data-loss-prevention control over what an
allowlisted host is sent, and the DNS-allowlist proxy's own trust model is documented in
`docs/FIREWALL.md` and `docs/agents.md` rather than restated here.

## Secret shapes, injection, and output

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| Consumption shapes are a closed declared set; the pending-mechanism set is **empty**, so every built-in a caller can name has a working mechanism behind it. An unknown shape is stored as a CUSTOM label, warned — not executed. | `packages/server/src/server/routes/secrets.py::BUILTIN_SHAPES` | `564583eb` | `git -c safe.directory='*' grep -n BUILTIN_SHAPES 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/routes/secrets.py` |
| The pending set is empty as a fact of the tree, not of prose — this is the cell that reddens the first time a shape is declared without a mechanism. | `packages/server/src/server/routes/secrets.py::MECHANISM_PENDING_SHAPES` | `564583eb` | `git -c safe.directory='*' grep -n MECHANISM_PENDING_SHAPES 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/routes/secrets.py` |
| The askpass helper is a static script written into the sandbox **after** the secret files it reads, on the same create call — so there is no window where a command can be handed a helper whose credential is not yet there. | `packages/executor/src/executor/strategies/sbx_strategy.py::write_askpass_helper` | `564583eb` | `git -c safe.directory='*' grep -n 'def write_askpass_helper' 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/strategies/sbx_strategy.py` |
| Command output is redacted by a compiled filter, not by a regex in the calling language, and the Python door wraps it. | `packages/executor/src/executor/filter.py::filter_output` | `564583eb` | `git -c safe.directory='*' grep -n 'def filter_output' 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/executor/filter.py` |
| The Rust entry point behind that door, for readers who want the implementation rather than the wrapper. | `packages/executor/src/rust/filter.rs::filter_output` | `564583eb` | `git -c safe.directory='*' grep -n 'fn filter_output' 564583eb195c5292221319df733079bac574bc2c -- packages/executor/src/rust/filter.rs` |

**What the redaction does not cover, stated because the row above would otherwise read too clean:**
the **command text** is recorded and forwarded unmasked. A secret interpolated into argv is outside the
redaction surface. `docs/secret-shapes.md` and the audit rows below carry that disclosure; the shape
vocabulary and its injection paths are documented there and are not duplicated here.

## Human authorization and role tiers

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| A session is minted only after a WebAuthn/FIDO2 assertion is verified server-side — the key touch is the credential, and no human password pathway exists. | `packages/server/src/server/fido2/manager.py::finish_authentication` | `564583eb` | `git -c safe.directory='*' grep -n 'def finish_authentication' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/fido2/manager.py` |
| The auditor tier is exclusive by construction: a caller holding it cannot be granted secret **values** or issued an elevation token, so an auditor cannot self-enrol a key. | `packages/server/src/server/dependencies.py::auditor_only_permissions` | `564583eb` | `git -c safe.directory='*' grep -n 'def auditor_only_permissions' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/dependencies.py` |
| The admin plane additionally requires an admin client certificate, separately from the bearer/cookie token door. | `packages/server/src/server/middleware/auth.py::_validate_admin_mtls` | `564583eb` | `git -c safe.directory='*' grep -n 'def _validate_admin_mtls' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/middleware/auth.py` |

Hardware **attestation** of key genuineness is a separate claim and does not ship — see *Not verified
here* and `docs/beta-known-limitations.md`.

## Executor identity and the revocation plane

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| Executor calls arrive on a mutual-TLS channel validated against the configured CA, and the CN must name a registered executor. | `packages/server/src/server/middleware/auth.py::_validate_executor_mtls` | `564583eb` | `git -c safe.directory='*' grep -n 'def _validate_executor_mtls' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/middleware/auth.py` |
| Revocation state is read **fail-closed**: a stale or unavailable list refuses the request rather than asserting "not revoked". | `packages/server/src/server/revocation_read.py::REVOCATION_UNAVAILABLE_DETAIL` | `564583eb` | `git -c safe.directory='*' grep -n REVOCATION_UNAVAILABLE_DETAIL 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/revocation_read.py` |
| The core's own dial to an executor consults a CRL at the TLS layer, in LEAF mode, and adds that source without widening the anchor set. **Physical half uncaptured** — code-present and unit-asserted; a refused revoked peer at the core's dial has never been observed on a served fleet. | `packages/server/src/server/routes/executors.py::_build_relay_ssl_context` | `564583eb` | `git -c safe.directory='*' grep -n 'def _build_relay_ssl_context' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/routes/executors.py` |
| The unit guard for that dial row, run in this changeset: 15 cells green. This is the evidence the row above rests on, which is why the row says `unit-asserted` and not `proven`. | `packages/server/tests/test_relay_dial_crl_586.py` | `564583eb` | `.venv/bin/python -m pytest packages/server/tests/test_relay_dial_crl_586.py -q` |

## Audit recording

| Control | Mechanism | Verified at | Re-derive with |
|---|---|---|---|
| The trail is append-only at the SQL door: the application identity gets blanket DML and then `REVOKE UPDATE, DELETE ON audit_events` runs **last**, so it wins. | `packages/core/alembic/versions/031_audit_append_only_grants.py::REVOKE_AUDIT_SQL` | `564583eb` | `git -c safe.directory='*' grep -n REVOKE_AUDIT_SQL 564583eb195c5292221319df733079bac574bc2c -- packages/core/alembic/versions/031_audit_append_only_grants.py` |
| That revoke ordering is asserted by a migration test, run in this changeset: 6 cells green. | `packages/core/tests/test_migration_031_audit_append_only.py` | `564583eb` | `.venv/bin/python -m pytest packages/core/tests/test_migration_031_audit_append_only.py -q` |
| Review scope is enforced server-side: non-privileged callers are self-filtered, so "who may read the whole trail" is not a configuration an operator has to get right. | `packages/server/src/server/routes/audit.py::audit_list` | `564583eb` | `git -c safe.directory='*' grep -n 'def audit_list' 564583eb195c5292221319df733079bac574bc2c -- packages/server/src/server/routes/audit.py` |

**Limits a reader should not infer past.** The protection is against the **application path**, not
against a PostgreSQL superuser on the host, and there is no hash chain or per-record signature — so
"tamper-evident" is stronger than what ships, and this page does not use it. `docs/auditor-role.md`
carries the tier and review-surface detail.

---

## Not verified here

Rows the four-cell rule kept out of the tables above. Each is a real property of the product or a real
customer-facing claim; what it does **not** have is one command at this commit that re-derives it. Listed
so the absence is legible rather than implied.

- **Physical capture of the dial-out revocation refusal.** The unit guard is in the table and green;
  no served-fleet capture exists. Reason: a physical row needs a booted executor fleet and a minted
  revoked leaf, which is a run, not a command. `docs/beta-known-limitations.md` states the residue.
- **Hardware attestation of FIDO2 authenticators.** Not claimed anywhere on this page. Registration
  requests `"attestation": "none"`, so possession of a registered credential ships and device
  genuineness does not — roadmap, and it is a *missing* capability, not an unverified one.
- **Audit export, SIEM or alerting integration.** Nothing ships. The trail is queryable and forwarded
  to the core over CA-mandatory HTTPS; no notifier, webhook or collector format exists in the tree.
  *Missing (planned)*, and no row here implies otherwise.
- **The pre-deploy gate as a product control.** `docs/deploy-gate.md` documents an operator procedure;
  no enforcement symbol exists in `packages/`, so it is not a control this page can cite. Searching
  for one at `564583eb` returned nothing to hang a command on.
- **Backup-by-restore-drill.** `docs/BACKUPS.md` states the requirement and the drill. The mechanism
  that re-encrypts CA backup material exists (`packages/cli/src/venya_cli/commands.py::_derive_ca_backup_key`),
  but proving a restore works is a ceremony with hardware keys and a live core, not a one-command check.
- **Tier ceilings and tier-gated governance features.** Contractual terms, not software behaviour — the
  signed price page says in its own words that the software will not stop you. Out of scope for a page
  about what the code enforces.
- **Air-gapped / offline installation.** Requires internet today. Tracked as a capability, named in
  `docs/beta-known-limitations.md`, and *not* a defect against this page.

## What this page is for, and what it is not

A reviewer asks "which of your controls do you touch, and how do I check that myself?" — every row
answers with the mechanism, the commit it was verified at, and the command that re-derives it, in one
read. It is a technical self-description, not an attestation, and an assessor's engagement would start
from the shipped tree plus an assessor, not from this file.

`docs/controls.md` is guarded by a test (`packages/server/tests/test_controls_doc_cite_interlock.py`):
it parses every row here, resolves each `file::symbol` against the recorded commit, and reddens when a
symbol stops resolving. That is what keeps a page like this true after the day it was written —
line numbers rot within a day or two on this tree, and prose that nobody reads is prose nobody checks.
