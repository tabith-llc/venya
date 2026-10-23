# RF-9 — Service identity inside the `split` model: design confirmation

**Confirmation leg (a prior worker lane, 2026-10-08).** RF-6 (`docs/design/rf6-shortcert-dossier-20261007.md`) §9 was approved
by the owner 2026-10-08 and already answers the RF-9 question. This file is the confirmation artifact: §9's claims
re-verified against the live tree, the four headless cases walked against it, the acceptance list restated for the
implementers, and the three open choices proposed — not decided — with a recommendation each. Zero product code.
Verified at branch base `80921ca` (RF-6 dossier merge). Line cites below are LIVE at that base; every dossier pin
that drifted is corrected here.

## 1. Verdict (one line)

**Yes** — `split` plus the executor-enrollment precedent fully answers headless admin work: every §9.3 mechanism
is live, audited code, the §9.4 cases all resolve without a ceremony, and nothing here needs a new capability
(ruling 1's budget). What remains is three named choices (§5 below), none of them a capability question.

## 2. The §9.3 mechanism, confirmed against the tree

Each claim re-grepped at `80921ca`; `rc` is the grep exit status. All rows land as described.

| §9.3 piece | Live site (verified) | rc |
|---|---|---|
| Admin mints short, single-use bootstrap token | `packages/server/src/server/routes/admin.py` — `@router.post("/admin/executors/{executor_id}/enroll")` :1625-1629, `plaintext = "enrl_exec_" + get_secure_token(32)` :1669, HMAC-SHA256 hash before storage :1671-1675, plaintext returned once | 0 |
| Rate-limited + admin-gated | `Depends(rate_limit_admin_token_gen)` + `Depends(require_admin)` :1633-1634 (dossier pin `:1635-1636` drifted 2 lines) | 0 |
| TTL knob, default 1800 | `packages/server/src/server/config.py` — `class ExecutorEnrollmentConfig` :148, `token_ttl_seconds` `default=1800, ge=120, le=86400` :152-156, wired `executor_enrollment` :373-375 | 0 |
| Attribution survives the machine | `packages/core/src/core/iam/models.py` — `class ExecutorEnrollmentToken` :214 (dossier pin `:221-258` drifted); `created_by` :228-236 with column comment "FK INTENTIONALLY absent (migration 022) — stores the auth principal verbatim … (incl. mTLS CNs), which have no users row"; forensic cols :237-244 | 0 |
| Forensic cols nullified after 90 days | `packages/server/src/server/maintenance.py` — `purge_admin_identity_metadata(db, days=90)` :115, NULLs `created_from_ip`/`_user_agent`/`_session_id` + wrapped meta :123-136 | 0 |
| Machine exchanges token for cert, key generated locally | `packages/server/src/server/routes/executors.py` — `"/executors/register"` :671-676, `register_executor` :676; `csr_pem` request field :140; CSR parse :694; token verified by hash :732-739; single-use consumption incl. race-guarded `UPDATE … WHERE state='created'` :753-802; server returns signed cert, never a key | 0 |
| Machine renews without ceremony, before expiry | `packages/executor/src/executor/daemon.py` — `def rotate` :692 (span :692-790 as pinned); fresh `_generate_ecdsa_p256_keypair` :725 + CSR, re-POSTs `/api/v1/executors/register` :730-737; clock trigger `needs_rotation` :668-690 vs `cert_rotation.rotate_before_days` (`config.py:39`) — planned window, not expiry panic | 0 |
| Rotation refuses a foreign trust anchor (#500) | `daemon.py` — `anchor_pem = self._resolve_rotation_anchor(ca_cert_pem)` :758, `def _resolve_rotation_anchor` :799 | 0 |
| Staged writes key→cert→CA, loud on read-only (#480) | `daemon.py` — pre-POST `os.access(cert_dir, os.W_OK)` refusal :714-724; `_atomic_write` order key :776 → cert :778 → CA :781, serial adopted only after all writes :790 | 0 |
| Failure text actionable, never silent | `daemon.py` — `def _token_required_error(…, rotation=False)` :239; rotation call :746; non-400/detail-mismatch returns None and the caller re-raises (:749) — no silent degrade; docstring names the day-0/day-30 death-spiral class it prevents | 0 |
| Plane is carried, not inferred | `packages/server/src/server/middleware/auth.py` — slot check `config.admin_mtls.known_admin_ids` :415; EMPTY ⇒ fail closed :416-430; membership 403 :427-431. `config.py` field `known_admin_ids` :271 | 0 |
| Executor plane is NOT an admin plane | `packages/server/src/server/dependencies.py` — `caller == "executor"` denied on admin routes :326-331 (dossier pin `:324-330` drifted ~2); cert-only `caller == "admin"` shortcut follows :333-335 | 0 |
| Today's headless shape | `install-venya-core.sh` — banner :1000-1006 (dossier pin `:1001-1006`); `ADMIN_IDENTITY="admin@${CORE_HOSTNAME}"` :368; `VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS` seeding :584; keypair minted on-core via `cm.sign_admin_cert` :420 → `ca.py:732` (90 days: `ADMIN_CERT_VALIDITY_DAYS = 90`, `ca.py:566`; Admin CA 10y, `:565`) | 0 |
| CLI headless exemption stays narrow | `packages/cli/src/venya_cli/commands.py` — `admin_mtls_exempt = command == "admin" and …` :167; `packages/cli/src/venya_cli/api_client.py` — `self.has_admin_mtls = bool(cert_path and key_path)` :357 (existence-only, command-scoped) | 0 |

Pin correction to carry back to the dossier: §9.1's revocation row cites `models.py:564` for
`admin_cert_revocations`; at this base the table is `packages/core/src/core/iam/models.py:607` (`:564` now sits in
the `fido2_challenges` docstring). The symbol exists — the pin rotted, the claim holds.

**Design answer restated, confirmed:** a service identity behaves exactly like an executor — admin-authorized,
single-use, TTL-bounded, attributed bootstrap (`admin.py:1669-1675`); keypair generated where the key lives
(`executors.py:694` CSR-only); renewal by its own enrollment/rotation, clock-driven (`daemon.py:668-690`,
`:692-790`); never a ceremony. Every leg of that sentence is shipped, tested code on the executor plane.

## 3. The four §9.4 cases, walked against the live tree

- **A — script a human starts, walked away from.** Today the copied standing cert works indefinitely: the server
  accepts cert-only (`dependencies.py:333-335`), the CLI exempts `admin` when both files exist
  (`commands.py:167`, `api_client.py:357`). Under the design the job runs on the 60-minute human cert and dies
  cleanly past `not_valid_after`. Verified live: no expiry pre-flight refusal exists in the CLI yet —
  `not_valid_after_utc` appears only in lifetime-read sites (`commands.py:2710`, `:4036`); the §4.4 refusal text
  is RF-8's to implement. The case resolves as designed; flag: case A is only honest once RF-8 lands, because
  today's copy-file path is exactly what §9.4's "Today" column says it is.
- **B — long-running daemon with admin needs** (the `install-venya-core.sh:1000-1006` shape). Stays machine plane:
  slot identity `admin@${CORE_HOSTNAME}` (`:368`) checked against `known_admin_ids` (`auth.py:415-431`, empty ⇒
  fail closed). Ceremony-free re-issue precedent is live across the board on the executor plane (§2 rows above).
  Honest gap, named not redesigned: the admin-plane pair itself has NO rotation client today — `sign_admin_cert`
  has exactly one caller, the installer (`ca.py:732`, `install-venya-core.sh:420`). §9.3's answer is a COPY of the
  executor machinery onto the admin plane (that copy is RF-7/RF-10 build work), not an invention — confirmed
  against ruling 1's "no new capability" budget.
- **C — CI / scheduled automation.** Verified today nothing would even notice a copied human cert:
  `has_admin_mtls` is an existence check (`api_client.py:357`), and the slot check accepts any
  `known_admin_ids` string (`auth.py:427`). Under the design CI gets a §9.3 service identity scoped to need, or is
  refused; the marker (§3.2, CA-written, {machine, human}, fail-closed outside the set) is what stops a
  human-shaped request from sitting on the machine policy path. Enforcement is RF-7's; the gate it lands on is
  live and tight (§2 row "Plane is carried, not inferred").
- **D — core that lost its admin's key.** Recovery-code path is live (pepper consumed at the mint,
  `admin.py:1670` `config.recovery_code_pepper`), and machine-plane continuity holds as claimed: the core's own
  credential never depended on a person (`:368`/`:584` are host-shaped slot values minted at install). The case
  does NOT require anything new from RF-9.

## 4. Acceptance checklist (§9.5) for RF-7 / RF-10 implementers

1. **Machine marker, no per-use role check** — the service mint MUST NOT be reachable through the human issuance
   endpoint; minting surface is admin-gated; identity is a slot name, never a `user_id`. Gate it lands on:
   `auth.py:415-431` (empty list fails closed). Negative test (truth-table law): human-shaped request asking for a
   service mint ⇒ 403.
2. **Key generated where it lives** — CSR in, signed cert out; never POST a key back. Copy
   `executors.py:694` (parse) + `:676` request shape; refuse a key field outright.
3. **Rotation planned, not emergency** — copy all three live properties, not the happy path: clock trigger with a
   window (`daemon.py:668-690`), refuse a rotation response that ships its own anchor (`:758`, `:799`, #500), fail
   loudly before any network call if the write target is read-only (`:714-724`, #480).
4. **Attribution survives the machine** — `created_by` verbatim, FK intentionally absent
   (`models.py:228-236`, migration-022 rationale in the column comment); forensic cols nullified after 90 days
   (`maintenance.py:115-136`); audit rows for admin USE of a service credential name the slot, not a person.
5. **Tight `known_admin_ids` as the only authorization gate** — the list is a config value the installer seeds
   from one operator string (`config.py:271`, `install-venya-core.sh:584`); every service slot added is a standing
   credential by definition. Additions are a deliberate act; removal story = rotation + serial revocation
   (`models.py:607` `admin_cert_revocations`), not config deletion (RF-11 runbook words).
6. **No new capability** (ruling 1's third clause) — the answer is the existing
   token/enrollment/rotation/consumption machinery plus the §3.2 marker. See §6.

## 5. The three open choices — proposals, rulings owed elsewhere

None of these is decided here; the dossier (§9.3) explicitly leaves them open.

- **a) New table vs `executor_enrollment_tokens` + scope column. Recommendation: a new table** (e.g.
  `admin_service_enrollment_tokens`, cloning the :214 model incl. `created_by`/forensic/`expires_at` shape).
  Cost: one Alembic migration + duplicated state-machine SQL (consumption race guard `executors.py:792-796` and
  its tests) + a purge-job sibling in `maintenance.py`. Why it wins: cross-plane token confusion becomes
  structurally impossible; with a scope column every existing AND future consumer of
  `executor_enrollment_tokens` must remember a `WHERE scope=…` and one missed clause is a cross-plane mint —
  the mistake class §9.5 item 1 forbids.
- **b) Admin-plane service-cert TTL. Recommendation: rotation-window class, not 60 minutes** — i.e. the
  existing long-lived shape with clock-driven rotation (`ADMIN_CERT_VALIDITY_DAYS = 90`, `ca.py:566`, is the
  incumbent value and the executor precedent's cadence story applies). Ruling 4a bounds HUMANS only; a service
  identity has no ceremony to re-run, so a human-length TTL converts age-out into an expiry panic with nobody in
  the room. Cost: theft window measured in days, not minutes — paid for by item 5 (tight list), serial kill
  (`models.py:607`) and planned rotation (item 3), which is exactly how the loopback cert is accepted today.
- **c) Marker value for a service identity: `machine` vs a third value. Recommendation: reuse `machine`.**
  §9.1/§3.2 put the service identity ON the machine plane; a third marker value adds a third policy branch at
  every marker read (auth middleware, dependencies, issuance) that no check currently consumes, re-opening
  ruling 2's clean two-plane split — that IS new-capability creep (§6). Distinguishing operator-loopback from
  CI-slot inside the plane is name-shaped (`admin@<host>` slot strings), which `known_admin_ids` already does.
  Cost: zero code; the burden moves to RF-11 docs/runbook to name the classes.

## 6. No-new-capability statement (ruling 1's budget)

RF-9's answer adds **no new protocol, table semantics, credential shape, verifier branch, or handshake**: it is
§2's shipped mechanism re-pointed at service slots, plus the §3.2 marker that RF-7 builds. What would violate the
budget, named so implementers can reject it: a static service password/token as a ceremony substitute; a
cert-factory route not admin-gated (mint shape `admin.py:1633-1634` is the bar); reusing executor certs for admin
routes (already refused, `dependencies.py:326-331` — smuggling by reuse is the pre-existing NO); a third marker
value with a third policy branch; any new trust anchor or verification path; expiry-driven "renew or die" for
machines with no human (§9.3's clock-not-panic clause). If implementation ever needs one of these, that is an
owner ruling, not a lane choice.

## 7. What RF-9 does NOT answer (named)

Human issuance endpoint and marker implementation (RF-7); CLI renew/lifetime UX and the §4.4 refusal text
(RF-8); installer mint/banner/seed edits incl. `:1000-1006` text and the marker write on the on-core mint
(RF-10, owner-ok-gated); rollout, age-out accounting, runbook words for adding/removing service slots (RF-11);
the machine loopback credential's own behavior — it stays long-lived under `split`; the three §9.3 choices
themselves (proposals above, rulings owed); and §8's Windows remote-bootstrap limitation, which this file neither
fixes nor re-derives.
