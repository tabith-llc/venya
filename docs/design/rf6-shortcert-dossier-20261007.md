# RF-6 — Short-lived, FIDO2-gated admin certificate: design dossier

Carrier: `features/RF-6-shortcert-design-dossier.md` (tabith root). Class: REFACTOR, design only — **zero
product code, zero installer edits** in this document's series.
Author lane: flash1 (venue `work3/`, branch `feature/rf6-shortcert-dossier`).

Tip this dossier is re-derived against: **dev `d0d3d0d`** (`Merge branch 'bug/ca-get-ca-key-pem-unreferenced-plaintext-claim' — the unreferenced CA key accessor is retired (refs 539)`).
Every line number below was produced by grep at that tip on the day of writing. Line numbers rot: **grep the
symbol, never trust the pin** — including the pins in this file.

Sections 1-5 are in this chunk. Sections 6-10 and the assembly pass are separate, sequenced dispatches on the
same branch.

---

## 1. Scope, the four rulings, and the ten problems re-derived

### 1.1 Scope

This dossier specifies the end-to-end design for FIDO2-gated short-lived admin client certificates: how a human
gets an admin credential, what that credential contains, how it is checked at use time, how it is renewed, and
how the existing long-lived credential is retired. It is an input contract for five downstream legs — RF-7
(issuance), RF-8 (CLI), RF-9 (service identity), RF-10 (installer mechanics), RF-11 (rollout/age-out/docs).

Out of scope here: the `modewarn` interim mitigation (its own carrier,
`features/admin-key-mode-warn.md`, RULED YES — see 1.4), all installer text changes (RF-10, owner-ok-gated), and
every `NoEncryption()` site except the core-side admin key (ruling 4d boundary, section 7).

The problem being solved, in one paragraph: admin login to the core is an mTLS client certificate whose private
key is minted **on the core** and then **handed to a human** by our own installer banner
(`install-venya-core.sh:980-981`, `scp root@<core>:/etc/venya/admin/admin.{crt,key} ~/venya-admin.{crt,key}`).
That credential is valid for 90 days (`ADMIN_CERT_VALIDITY_DAYS = 90`, `packages/server/src/server/ca.py:566`),
it leaves a `0600` root-owned path for a workstation home directory, and it authenticates admin operations
**with no security-key touch** — the CLI's headless-admin exemption
(`packages/cli/src/venya_cli/commands.py:159-165`) plus the server's cert-only shortcut
(`packages/server/src/server/dependencies.py:332-333`) make the copied file alone the authority.

### 1.2 The four rulings (restated — they are law, not premises)

These are restated from the RF-6 carrier. This dossier designs **to** them. It does not re-open, re-weigh, or
improve them. Any objection is recorded in 1.5.

**Ruling 1 — `split` (headless-automation replacement).** Two halves plus an existing path, verbatim from the
record: (1) the machine credential stays long-lived, stays on the core (it already authenticates
loopback-to-itself) and is never handed to a human again; (2) humans move to short-lived, FIDO2-minted admin
certs; (3) "the blocker is answered by those two plus the existing recovery-code path — no new capability is
required to remove the standing human credential." Consequence for this dossier: the design has **two credential
planes**, and every subsequent section must say which plane it is talking about.

**Ruling 2 — person identity with per-use re-check (attribution).** The ceremony names the person; the identity
is embedded in the short-lived admin cert; the static `known_admin_ids` allowlist check is **replaced by a
per-use role check on the human path**; the used identity is written into the audit row. Two-plane corollary:
the loopback/machine cert stays long-lived and **slot-shaped** against the static allowlist, because machines
have no person. `known_admin_ids` therefore keeps meaning on the machine plane only. The ruling carries two
caveats that this dossier states explicitly rather than gliding past — DB reachability becoming an
authorization dependency (mandatory statement 1, section 3.5) and admin-username disclosure (mandatory statement
2, section 3.6).

**Ruling 3 — CSR from the CLI (key location).** The workstation generates the admin keypair; the server only
signs the request. The private key never transits the server. Consequences carried: the admin CA signing path
reuses or extends the `sign_csr` shape; the installer's admin-key return-shape dependency changes (RF-10, not a
security regression); no new work lands on the open CA cluster (#537 write half, #541 load half, #538 envelope).
The ruling also orders a **disposition of `sign_admin_cert`** — fix or remove, stated explicitly, test cells
handled in the same breath. That disposition is section 6 (chunk 2); section 1.5 records a finding that bears on
it directly.

**Ruling 4 — lifetime, refresh, age-out, Q4a scope.** Four fields, all closed:
- **4a — 60 minutes.** The load-bearing reframe: under ruling 2, lifetime **stopped being the revocation
  mechanism and became purely the theft window**. That is what makes 60 defensible instead of 15. Two conditions
  ride along: skew tolerance is a small fraction of lifetime (section 5), and the NTP mass-lockout note with
  error text that names it (section 5.4). Cadence is driven by job length, never by fear of expiry — 60 minutes
  sits far above ceremony cost (one FIDO2 touch).
- **4b — explicit renew only.** Never an automatic ceremony mid-run. A paused headless script holding admin
  privileges while waiting for a human is worse than a clean failure; the helpful-refusal precedent governs and
  the error text names the exact command (section 4). Plus the owner-ordered **lifetime-readable check** — a
  `status`-style command or `renew --dry-run` that prints remaining lifetime (section 4.5).
- **4c — natural age-out, no re-root, with honest exposure accounting.** The age-out date **is the closure date
  of the original exposure**; the clock starts only when the installer stops minting the old handoff (RF-10 lands
  WITH OR AHEAD of rollout); the published date is computed as `max(install date) + 90 days` from the cut-over
  commit, not guessed. Full treatment in section 10 (chunk 2/3).
- **4d — Q4a scoped to the core-side admin key ONLY**, with the boundary sentence carried word-for-word in
  section 7: the other sites are #537/#538 CA-cluster territory and must not be read as blanket-approved.

### 1.3 The ten problems, re-derived at `d0d3d0d`

Source list: `features/admin-key-short-lived-certs.md`, "The ten problems this introduces (ranked by harm)".
All ten re-derived against the current tip. The "pin → live" column records where the inherited citation landed,
because several have rotted and one is wrong for a reason that matters (problem 3).

| # | Problem (input-file wording, abridged) | Re-derived status at `d0d3d0d` | Where designed |
|---|---|---|---|
| 1 | Headless automation loses its credential | Live. The cert-only path is real and reachable: `admin_mtls_exempt = command == "admin" and ... has_admin_mtls` (`commands.py:167`); server-side `caller == "admin"` returns without a DB role check (`dependencies.py:333-334`). Under `split` the human half of this path is retired and the machine half is served by the loopback cert, so the design must not keep both human paths alive. | §1.2 R1, §3.2, §9 |
| 2 | Shortening does not buy attribution | Live, exactly as described. Identity is extracted SAN-RFC822 → SAN-DNS → CN (`middleware/auth.py:38-65`), checked against a static `known_admin_ids` list (`auth.py:415-431`, fails closed when empty at `:416-426`); `known_admin_ids` is a config field (`server/config.py:271`). Ruling 2 replaces the human-path allowlist check with a per-use role check. | §3 |
| 3 | The mint must not become a cert factory | **Live AND MISDESCRIBED.** `sign_admin_cert(admin_identity)` still generates the keypair itself (`ca.py:749`) and returns the private key PEM unencrypted (`ca.py:812-815`), with no authorization and no rate limit. But the input file's claim that it "has no caller today", and ruling 3's "dead production code at this tip", are **false beyond `packages/`**: the installer calls it. See §1.5 finding F-1 — this is the STOP condition the spec anticipated. | §2, §6 (flag) |
| 4 | Expiry mid-session | Live. The CLI resolves the admin pair at construction (`api_client.py:342-343`, stored at `:385-386`, existence-only check at `:364-370`) and builds **one** TLS context that loads the cert chain (`:447-451` -> `_build_ssl_context` at `:157`, `load_cert_chain` at `:199`). Nothing re-reads a renewed cert inside a live process. | §4 |
| 5 | Clock skew becomes a mass-lockout mechanism | Live and unchanged in mechanism: short validity is enforced by OpenSSL at the proxy; no product-side tolerance exists in the design today. Sized as a fraction of the 60-minute lifetime. | §5 |
| 6 | Installer edits, each owner-ok-gated | Live, all three cites confirmed at this tip: mint site `install-venya-core.sh:408-426` (the `sign_admin_cert` call is `:420`), copy instruction `:978-981` (scp lines `:980-981`), managed env key `VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS` in `MANAGED_ENV_KEYS` (`:555`, written at `:584`). Design does not touch them; consequences handed to RF-10. | §2.7, §10 |
| 7 | Dual-path rollout | Live. 90-day admin certs keep validating until they age out; the Admin CA is 10-year (`ADMIN_CA_VALIDITY_DAYS = 3650`, `ca.py:565`) and chains are unchanged, so nginx verification needs no edit. Age-out accounting per 4c. | §10 |
| 8 | The security key becomes the lock, not just the login | Live. Roster guard exists (`assert_removal_keeps_admin`, `core/iam/role_manager.py`); an admin-cert recovery story does not — the recovery-code path from ruling 1 is the answer, and the design must specify which path a locked-out admin walks. | §3.7, §9 |
| 9 | Windows admins cannot bootstrap remotely | Live. The FIDO2 ceremony requires an interactive desktop (`info/reference-win11-venue.md`); documented, not discovered mid-incident. | §8 |
| 10 | It closes the admin path only | Live. Scope guard re-derived by grep at this tip: **8** non-test `NoEncryption()` sites (not 9) — see §1.6. Ruling 4d's narrow scope and the audited list are the deliverable. | §7 |

### 1.4 The named interim mitigation (`modewarn`) — carried, not folded

`features/admin-key-mode-warn.md` (id `admin-modewarn-20261007`) is RULED YES and is **independent** of this
design. It warns, never blocks: one stderr line naming the file, the mode found, and `0600`; silent at `0600`
or stricter; exit code and stdout unchanged; one honest copy recipe in the docs; POSIX-only check with the
Windows behavior stated. Its premise is confirmed at this tip — the CLI's admin key handling checks **existence
only** (`api_client.py:364-370`) and a grep for `chmod|st_mode|0o6|0o7` in `api_client.py` returns only the
**config-file** save path (`:233-248`), never the admin key: the carrier's "zero hits on this file" claim holds.

Why it is named here and not absorbed: `split` decides *what the credential is*; `modewarn` decides *what we say
when a human leaves it lying around*. It is the mitigation that ships while the design is implemented, and it
stays useful after, because a 60-minute key left world-readable is still a theft window. This dossier changes no
credential behavior on its account and takes no dependency on it.

### 1.5 Ruling friction

Two items. Neither re-opens a ruling; both are recorded so a downstream lane does not re-derive them as news.

**F-1 (finding, STOP condition reported, work continued as instructed).** Ruling 3 states that `sign_admin_cert`
is "DEAD PRODUCTION CODE AT THIS TIP — lead-verified: zero callers outside `packages/server/tests/` (grep for the
symbol; the only hits are `test_admin_mtls.py` cells and one pycache artifact)". The lead's grep was scoped to
`packages/`. At `d0d3d0d` the symbol has a **production caller outside that scope: the installer**. Verbatim,
`install-venya-core.sh:408-420`:

```
    # Generate first admin cert. sign_admin_cert loads the CA key — now
    # encrypted — so this block needs the passphrase on stdin too (identical
    # carry). $1=ca_dir $2=cert_dir $3=identity, all positional.
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
        IFS= read -r VENYA_ADMIN_CA_KEY_PASSPHRASE
        export VENYA_ADMIN_CA_KEY_PASSPHRASE
        exec python -c "
...
cert, key_pem, cert_pem = cm.sign_admin_cert(sys.argv[1])
```

and the same script's re-run idempotency comment at `:341` names it as the abort point ("an existing install
PRESERVES the encrypted admin CA key ... a re-run must reuse the passphrase ... or [it] aborts the run at
`sign_admin_cert`"). Consequences, in order of what this dossier does with them:

1. **The spec's STOP condition is tripped and reported, not acted on.** The dispatch says: quote the grep, note
   it, continue, flag for chunk 2. That is what is happening.
2. **"Remove it" is not a free option any more.** Section 6 must disposition a function with a live caller in an
   owner-ok-gated installer script. Removing it means the installer's first-admin-cert mint changes shape in the
   same breath — which is RF-10 territory and is owner-ok-gated. The dossier's options in section 6 are therefore:
   (a) keep it as the **installer's bootstrap-only mint**, narrowed and documented as such, or (b) replace the
   installer mint with the CSR path and then remove it, sequenced with RF-10. Both must be stated against the
   real caller; neither is a `packages/`-only edit.
3. **The "standing temptation" argument still stands, and is sharper.** The reason ruling 3 wants the function
   dispositioned is that it is a server-side private-key exporter bolted next to the new flow. It is not merely a
   temptation — it is **the current production mint** for the very credential this design retires. That raises the
   value of an explicit disposition and does not change the requirement.

This finding does not contradict another ruling, so the "rulings contradict" STOP does not fire: ruling 3's
*shape* (CSR from the CLI, key never transits the server) is unaffected. What is affected is one factual premise
inside the supporting note.

**F-2 (friction, informational).** The carrier's `sign_admin_cert` pin (`ca.py:744` at `d0bfbb4`) is now
`ca.py:732`; its `sign_csr` pin (`ca.py:340`) still lands exactly. Both were re-grepped; §1.3 and §2 cite the
live numbers. `#539` (merged in this train) removed the unreferenced CA key accessor, which is why the
`NoEncryption()` count moved and why `get_ca_key_pem` no longer appears in the enumeration — see §1.6.

### 1.6 The `NoEncryption()` enumeration, re-derived (input to section 7)

Counted here, audited in section 7 (chunk 2). Command run at `d0d3d0d`:

```
grep -rn "NoEncryption()" packages/ --include='*.py' | grep -v '/tests/' | grep -v __pycache__
```

**8 live non-test sites** — matching the carrier's `d0bfbb4` re-derivation, with the site inside `server/ca.py`
now at `:815` rather than `:827` (the #539 removal shifted it):

| # | File:line | Enclosing function | Plane |
|---|---|---|---|
| 1 | `packages/server/src/server/ca.py:815` | `AdminCAManager.sign_admin_cert` | server-side admin key mint (the Q4a site) |
| 2 | `packages/cli/src/venya_cli/commands.py:2551` | `executor_register` | executor |
| 3 | `packages/cli/src/venya_cli/commands.py:2947` | `executor_cert_renew` | executor |
| 4 | `packages/cli/src/venya_cli/commands.py:3758` | `cmd_admin_init_admin_ca` | admin CA bootstrap |
| 5 | `packages/cli/src/venya_cli/commands.py:3978` | `cmd_admin_generate_admin_cert` | admin |
| 6 | `packages/cli/src/venya_cli/at_rest_key.py:87` | `unwrap_at_rest` | at-rest envelope |
| 7 | `packages/executor/src/executor/daemon.py:573` | `register` | executor |
| 8 | `packages/executor/src/executor/daemon.py:753` | `rotate` | executor |

Arithmetic stated rather than smoothed, per the carrier: the input file says NINE with TWO on the admin path
(9−2 = 7); the live grep says EIGHT with the ninth already removed by the #537 refusal (`e3a760d`) and the #539
accessor retirement. This dossier measured **8**. The 7-outside-the-boundary destination is reached by a different
route and section 7 publishes it that way.

### 1.7 Inheritance — what later legs take from this section

- **RF-7 (issuance):** §1.2 rulings 1-3 are its contract; F-1 tells it that the mint it is replacing has a live
  caller, so its changeset must name the installer hand-off rather than assume a vacant function.
- **RF-8 (CLI):** §1.2 ruling 3 (keygen on the workstation) and problem 4 (context built once) are its two
  binding constraints; §1.4 tells it `modewarn` is a separate leg it must not absorb.
- **RF-9 (service identity):** ruling 1's machine plane and problem 1's "do not keep both human paths alive".
- **RF-10 (installer):** problem 6's three confirmed live cites (`:408-426`, `:978-981`, `:555`/`:584`) plus F-1,
  which converts "delete the dead function" into a sequenced installer change.
- **RF-11 (rollout/age-out/docs):** problems 7 and 8, §1.2 4c's accounting law, and the §1.6 count of 8 so the
  docs state the audited number rather than the remembered nine.



---

## 2. Issuance path — ceremony to workstation-held short cert

Ruling 3 fixes the shape: **the workstation generates the keypair and the server only signs.** This section
turns that into an end-to-end path and pins each piece to code that exists at `d0d3d0d`.

### 2.1 Path at a glance

```
 human CLI                        core (server)                       admin CA
 ─────────                       ─────────────                       ────────
 1. login (bearer) ────────────► session
 2. elevate/challenge ─────────► Fido2Manager.start_authentication
    elevate/assert ───────────► verify assertion → ElevationToken row (60s TTL, single-use)
 3. keygen (P-256) + CSR  ──┐
 4. POST /admin/certs/issue ─┴► authorize: bearer + elevation token
   (PEM CSR, no private key)    derive identity FROM THE SESSION (never from the CSR)
                                rate-limit → sign CSR (Admin CA) → audit ADMIN_CERT_ISSUED
 5. receive cert PEM ◄───────── 201 with certificate only
 6. write 0600 outside the home dir; use until expiry; renew is an EXPLICIT command (§4)
```

Private-key material crosses the boundary in exactly one direction: **outbound inside a CSR**. Nothing in this
design returns a private key from the server to a human.

### 2.2 The bootstrap problem, and why the elevation path is the right anchor

The new issuance endpoint cannot be protected by an admin **certificate**, because a brand-new install has no
human short cert to present — the credential it mints is the credential it would require. The fix is to anchor
authorization on the plane that does not depend on the cert being retired: **bearer session + fresh FIDO2
assertion**.

This primitive already exists and is already the product's answer to "prove you are the person, again, for one
sensitive operation": `packages/server/src/server/routes/auth_elevation.py` — `POST` challenge at `:160`
(`elevate_challenge`) and `POST` assert at `:211` (`elevate_assert`). Its properties, re-derived:

| Property | Live value | Site |
|---|---|---|
| Requires bearer auth | yes, `Depends(get_current_user)` | module docstring `:8-16` + route signatures |
| Ceremony | WebAuthn assertion via `Fido2Manager` (`start_authentication` `fido2/manager.py:387`, `finish_authentication` `:440`) | `auth_elevation.py` |
| Token lifetime | `ELEVATION_TOKEN_TTL_SECONDS = 60` | `auth_elevation.py:36` |
| Pending-ceremony binding | DB row, committed immediately so **any worker on any core claims the same challenge** (#528) | `_store_elevation_challenge` `:56`, `:76` |
| Single-use consumption | `ElevationToken` row matched on `token_hash`, `user_id`, `used.is_(False)`, `expires_at > cutoff` | consumer pattern at `routes/secrets.py:496-518` |
| Audit on grant | `ELEVATION_GRANTED` lifecycle event | `auth_elevation.py:327`, name at `audit_lifecycle.py:57` |
| Rate-limited by the auth middleware | yes — `/api/v1/auth/` prefix | `middleware/rate_limit.py:268-274` |

Two consequences worth stating plainly:

1. **The 60-second elevation TTL and the 60-minute cert lifetime are unrelated numbers that happen to match.**
   The elevation token authorizes *one mint request*; the cert it returns is valid for an hour. A reviewer
   should not read the coincidence as a design dependency.
2. **The cross-worker property is load-bearing, not incidental.** The #528 move of the pending challenge into the
   DB exists because the old per-process `app.state` dict stranded ceremonies on the wrong worker. Issuance must
   use the DB-backed elevation record for the same reason — a mint that starts on core-1 and completes on core-2
   is normal in the HA deployment (`features/beta-highly-available-core.md`).

**Not** an option, and stated so a later lane does not try it: authorizing issuance with the caller's existing
admin cert (the `require_admin` shape at `routes/admin.py:2042-2046`) reproduces exactly the standing-credential
dependency this whole program exists to delete. A first-human bootstrap is served by the existing
installer/`cmd_admin_init_admin_ca` + recovery-code paths (§2.3, §9), not by cert-based self-service.

### 2.3 Bootstrap and recovery stay on existing paths

- **First admin:** unchanged — the installer's admin CA init plus first-cert mint, which today is the
  `sign_admin_cert` call at `install-venya-core.sh:420`. Section 6 (chunk 2) dispositions that call; RF-10 owns
  the installer text. This design does not add a bootstrap capability.
- **Lost security key:** ruling 1's third clause — the existing **recovery-code** path
  (`routes/recovery.py`; break-glass endpoint `/api/v1/recovery`, rate-limited separately at
  `middleware/rate_limit.py:276-279` with its own backoff at `:205-240`). Problem 8's "the key is now the lock"
  is answered by that path plus the roster guard, not by a backdoor mint. Detail in §9 (chunk 2).

### 2.4 Key and CSR generation on the workstation (RF-8's contract)

The CLI generates an ECDSA keypair and builds the CSR locally. Design constraints, each traced to what the
signing authority will actually accept:

- **Curve:** must be on the accepted CSR list. That list is a single source of truth —
  `ACCEPTED_CSR_CURVE_LABELS` (`ca.py:59-63`) = **P-256 / P-384 / P-521**, read at call time by
  `accepted_csr_curve_names()` (`ca.py:66`), with `csr_curve_hint()` (`ca.py:71`) building the error text from
  the same dict so a refusal can never advertise a different list than the vault enforces (#503 option A).
  **The CLI default for admin short certs is P-256 (`secp256r1`)** — the curve every CA key and every leaf in
  this product uses today (`ca.py:228`, `:636`, `:749` are all `SECP256R1`). P-384 is the declared direction of
  `features/p384-end-to-end-pki-reroot.md`, which is **OPEN** work; a design that pinned P-384 would ship a CLI
  that mints CSRs the current CA signs but that mismatch the CA doing the signing. Acceptance stays
  list-driven, so the re-root needs no CLI change.
- **The CSR's subject is advisory only.** See §2.6 — the server overwrites identity. Generating the CSR with an
  empty or placeholder CN is fine and should not be treated as the identity carrier.
- **Private key never leaves the workstation process.** It is never POSTed, never logged, never placed in an
  env var. The CLI writes it `0600` in a `0700` directory outside the home directory where that is expressible
  (the product's own standard `ensure_secret_dir` in `at_rest_key.py`; the CLI's config save already does
  `mkdir(mode=0o700)` + `fchmod(0o600)` at `api_client.py:233-248`). On Windows the mode-bit story does not
  exist — same honesty requirement `modewarn` carries (§1.4, §8).
- **CSR transport shape:** mirror the executor registration contract — a PEM string field with a length bound
  (`csr_pem: str = Field(..., max_length=2048)`, `routes/executors.py:140`), parsed with
  `x509.load_pem_x509_csr` (`executors.py:694`), and a parse failure mapped to a 400, never a 500.

### 2.5 The signing authority — reusing the `sign_csr` shape at the ADMIN CA

Ruling 3 says reuse or extend `sign_csr`. Its behavior, re-derived at `ca.py:340-451`, with what each item means
for an admin variant:

| `sign_csr` behavior | Site | Carry to the admin signer? |
|---|---|---|
| Verifies the CSR self-signature; `ValueError` → caller maps to 400 | `:368-370` | **Yes, unchanged.** Same error-class contract: bad CSR is client input, a CA that cannot load is a service fault (`RuntimeError` → 503) |
| ECDSA-only, curve must be on the accepted list, hint text from the same dict | `:372-381` | **Yes, unchanged** — reads the shared list, no admin-specific curve fork |
| **Replaces the CSR CN** with a server-supplied id | `:383-389` | **Yes — and this is the security-critical reuse.** §2.6 |
| Serial from `secrets.token_bytes(8)` | `:365` | **Yes** — also what `sign_admin_cert` does (`:746`), and keeps serials compatible with the canonical-form revocation lookup (§2.9) |
| `not_valid_before = now`, `not_valid_after = now + EXECUTOR_VALIDITY_DAYS` (30d) | `:396-397` | **Structure yes, value no** — admin uses a minutes-scale lifetime (ruling 4a, §5) |
| SKI from subject public key, AKI `from_issuer_public_key` | `:398-405` | **Yes** — the #504 placement rule, already mirrored in `sign_admin_cert` (`:767-781` comment) |
| `BasicConstraints(ca=False)`, `KeyUsage(digital_signature only)`, both critical | `:406-423` | **Yes, identical** |
| EKU = `EXECUTOR_LEAF_EKU` = SERVER_AUTH + CLIENT_AUTH | `:424-427`, `ca.py:50` | **Narrow it: CLIENT_AUTH only.** An admin leaf is a client credential; `sign_admin_cert` already does exactly this (`:796-803`). Carrying SERVER_AUTH would let an admin cert impersonate a core endpoint |
| SAN = `DNSName(executor_id)` | `:428-431` | **No — use the identity-shape-aware builder.** `_build_san_for_identity` (`ca.py:569-585`) emits RFC822 for `@`-bearing identities, DNS otherwise, matching the middleware's extraction order (RFC822 → DNS → CN, `middleware/auth.py:52-64`). Person identities are email-shaped, so the RFC822 branch is the one that matters |
| Optional CRL Distribution Points from `crl_url` | `:434-448`; caller passes `config.crl.crl_url` at `executors.py:901-904` | **Yes, same optional wiring** — but note the enforcement reality: nginx has no `ssl_crl`, so CDP is informational and the real revocation point is the in-process serial check (§2.9) |
| Signed with `SHA256` | `:450` | Yes |

Two ways to get there, and the choice:

- **(a) Generalize `CAManager.sign_csr`** with lifetime/EKU/SAN parameters. Cheaper diff, but it puts an
  ADMIN-plane leaf behind the executor CA's manager and its `load_ca()` (Root/executor CA), which the middleware's
  per-plane chain anchors already refuse for admin routes. Rejected.
- **(b) Add `AdminCAManager.sign_admin_csr(csr, identity, lifetime_seconds, crl_url=None)`** — the admin CA's own
  `_load_ca_cert_and_key` (`ca.py:821-828`), the §2.5 column above, and *no* private-key return. The CSR variant
  replaces the keypair-generating `sign_admin_cert` rather than sitting beside it. **This is the design.** It also
  gives section 6 a clean disposition target: the new function takes the old one's job, and the old one's caller
  problem (F-1) is resolved in the same breath.

**A signing function that returns a private key must not survive this change** — that is the whole content of
ruling 3, and the reason §6 exists.

### 2.6 Identity binding — the mint must not be self-described

The naive shape ("sign whatever CSR the caller sends") leaks identity: the caller controls the CSR subject.
`sign_csr`'s CN-replacement (`ca.py:383-389`) is the existing defense and is mandatory here:

1. **Subject CN, SAN RFC822/DNS, O and OU are all set from the server-derived identity** — the `user_id` of the
   authenticated session that produced the elevation assertion (`get_current_user` → `user_info["user_id"]`, the
   same value the elevation row is bound to at `auth_elevation.py:307-320`). Every attribute in the CSR subject is
   discarded; the caller's subject carries no authority.
2. **No delegation.** The asserted user is the identity in the cert. A request that wants a cert for someone else
   is not a thing this endpoint can express.
3. **Role re-checked at mint time too, not only at use time.** §3 puts the per-use role check on the request path;
   the mint additionally refuses a caller with no admin role, so the endpoint is not a general "cert for any user"
   factory. Both checks are required: mint-time keeps the factory closed, per-use keeps revocation live (ruling 2).
4. `sign_admin_cert` took `admin_identity` as a **free-form string from its caller** (`ca.py:732`) with no
   authorization and no derivation — with zero production callers in `packages/` that was latent; with the
   installer as its real caller (F-1) the identity comes from `ADMIN_IDENTITY`, an operator-supplied value
   (`install-venya-core.sh:584`). The server-derived rule above is what closes that class.

### 2.7 Caller authorization, rate limiting, and the route contract

- **Route:** `POST /api/v1/admin/certs/issue` (name per RF-7; must sit under a prefix the rate limiter classifies
  — see next bullet). Requires: valid bearer session, valid unused unexpired `ElevationToken` for that session's
  user (consumed atomically, the `secrets.py:496-518` UPDATE-`used` pattern, so two concurrent requests cannot
  both spend one ceremony), and the admin role (§2.6.3).
- **Rate limiting — choose the DB-backed middleware, not the in-memory limiter.** The carrier points at "the
  server's RateLimiter"; both exist and only one is correct for a multi-core deployment:
  - `core/engine/rate_limiter.py:41` — `RateLimiter`, in-memory, per-process. Its own docstring is explicit
    (#516): state is **NOT shared between processes**, one instance per core process
    (`backend.py:354`, `factory.py:79`, `core.py:75`), so N workers enforce `max_attempts` **N×** and a restart
    clears it. Fine for login lockout heuristics; wrong for a mint cap.
  - `server/middleware/rate_limit.py` — `RateLimitMiddleware`, fixed-window counters in the
    **`rate_limit_failures` table with an atomic UPSERT** (`_increment_counter` `:175-190`), `Retry-After` on
    every 429 (`:48-56`, `:143`). Wired at `app.py:184`. Classified prefixes are `/api/v1/auth/` and
    `/api/v1/enrollment/` (`:268-274`); `/api/v1/recovery` is break-glass (`:276-279`).
  - **Design: the issuance endpoint must be added to the DB-backed middleware's classified set** (prefix or exact
    path, RF-7's call) so the cap is per-account across cores and survives a restart. Suggested starting shape,
    for RF-7 to rule on: a small number of mints per user per window (single digits per hour), since the honest
    cost of one mint is one FIDO2 touch and 4a says cadence is driven by job length, not by fear of expiry.
- **Failure modes, all loud, none of them a 500:** bad/expired/used elevation token → 401/403 with text naming
  the exact repair command (`venya admin elevate`-class, per 4b's naming law); CSR parse or curve refusal → 400
  naming the accepted curves from `csr_curve_hint()`; missing admin role → 403; CA material unusable → 503
  (`RuntimeError` from `_load_ca_cert_and_key`, kept distinct from client error exactly as `sign_csr`'s
  docstring does at `ca.py:357-361`); rate limit → 429 + `Retry-After`.
- **Response body carries the certificate PEM and nothing else** — no key, no CSR echo. The core-side copy is not
  written to disk as a key file; the server holds no private material for this flow at any point.

### 2.8 Issuance audit event

Mirror the revoke path's shape (`routes/admin.py:2086-2099`): `audit_lifecycle(db, event, user_id, fields)` +
`db.commit()`, event name defined as a module constant in `server/audit_lifecycle.py` alongside
`ADMIN_CERT_REVOKED` (`:60`) and `ELEVATION_GRANTED` (`:57`).

- **New event: `ADMIN_CERT_ISSUED`** (constant name per RF-7; the `AuditEvent.event_type` column is
  `String(64)` — `core/iam/models.py:164-172`).
- **`fields` should carry** at minimum: canonical serial (`canonical_serial`, the one form the revocation lookup
  compares — `#481`), identity as embedded in the cert, `not_valid_before`/`not_valid_after` (offset-aware UTC,
  per the datetime rule), curve name, the requesting `user_id`, and a mint reason
  (`issue` / `renew` — §4.4). **It must NOT carry** the CSR bytes, the public key PEM, or the cert PEM: the audit
  row is readable by non-admin auditors, and the public key plus CSR would let a log reader reconstruct subject
  detail we did not decide to publish. `user_id` on `AuditEvent` intentionally has no FK and stores the principal
  verbatim, including mTLS CNs (`models.py:173-180` comment) — for this event the human `user_id` is the point
  (ruling 2's "the used identity is written into the audit row").
- Metrics: `CA_SIGNED_TOTAL.labels(cert_type=...)` already exists with `cert_type="executor"`
  (`executors.py:905`); the admin mint should emit the same counter with a distinct label rather than invent a
  metric.
- Paired negative test per the truth-table rule: a mint with an **already-spent** elevation token is refused and
  produces **no** `ADMIN_CERT_ISSUED` row and no `CA_SIGNED_TOTAL` increment.

### 2.9 Revocation still works, and is the mechanism ruling 2 relies on

Per-use re-check makes revocation *behavioral* (role removed → next request refused). Serial revocation stays as
the *credential*-level kill, and it already exists end to end: `POST /admin/certs/revoke` (`admin.py:2042`),
`AdminCertRevocation` rows (`models.py:564`), enforced in-process at `middleware/auth.py:435-470` because nginx
has no `ssl_crl` (`:436-438`). Short lifetime changes the economics, not the plumbing: a stolen 60-minute cert
expires on its own, so revocation is for the case where you want it dead **now**. The canonical-serial discipline
(`:446`, `#481`) is mandatory for the new mint — 8-byte serials from `secrets.token_bytes(8)` can be short hex
strings, and the case/padding-insensitive match is what keeps a revocation from silently missing.

### 2.10 Inheritance — what later legs take from this section

- **RF-7:** the endpoint contract (§2.7), `AdminCAManager.sign_admin_csr` (§2.5b), the server-derived-identity
  rule (§2.6), the DB-backed rate-limit choice with its rationale (§2.7), and `ADMIN_CERT_ISSUED` field set (§2.8).
- **RF-8:** keygen/CSR constraints (§2.4) — curve default, P-256, the "subject is advisory" rule, `0600`/`0700`
  write discipline, and the requirement that its error text name the repair command.
- **RF-9:** the two-plane rule — this section mints **human** certs only; the loopback machine cert is never
  issued through it (§1.2 R1, §9).
- **RF-10:** the return-shape change (cert only, never a key) is what breaks the installer's current
  key-file dependency at `install-venya-core.sh:408-426`/`:978-981`; plus F-1 — the function it would remove has
  a live caller.
- **RF-11:** issuance audit is the data source for age-out accounting (§10) — the event carries the lifetime so
  the rollout can prove which certs are still live.

---

## 3. Two-plane identity — person identity with a per-use role check

Ruling 2 is the load-bearing decision of this design: **the credential stops naming a slot and starts naming a
person, and the role is checked every time it is used.** Revocation therefore becomes behavioral (remove the
role → the next request is refused) instead of lifetime-shaped. This section specifies both planes and the
boundary between them.

### 3.1 The current state is ONE plane serving both uses

Re-derived at `d0d3d0d`. The admin route path in `packages/server/src/server/middleware/auth.py`:

| Step | Live behavior | Site |
|---|---|---|
| 1 | Verify the forwarded leaf against the **admin-plane** anchors (`_admin_ca_certs`), which also applies the validity window + skew tolerance and the signature link | `_verify_forwarded_cert` `:178-220`, called at `:385`; anchors `_admin_ca_certs` `:123` |
| 2 | Extract identity: SAN RFC822 → SAN DNS → CN | `_extract_identity_from_cert` `:38-65`, called `:400` |
| 3 | **Static allowlist** — empty list fails closed, identity must be enumerated | `:413-431`; `known_ids = config.admin_mtls.known_admin_ids` `:415`, empty-list branch `:416`, membership branch `:427` |
| 4 | In-process serial-revocation lookup, **opens a DB session**, all failures 403 | `:435-497` (session `:457`, `except Exception` `:477`) |
| 5 | Attach `{"caller": "admin", "user_id": identity}` — the cert identity IS the user_id | `:499` |
| 6 | Route-level `require_admin` returns immediately for `caller == "admin"`, **no DB role check** | `dependencies.py:332-333` |

So today a single code path authenticates the loopback machine cert and (in the installer's design) a human's
copied file identically, and step 6 means neither is ever re-authorized against the role table. `known_admin_ids`
is a config field (`server/config.py:271`, `AdminMTLSConfig` `:256`), written by the installer from one operator
value (`install-venya-core.sh:584`, key enumerated at `:555`).

### 3.2 The design: two planes, and how a request knows which one it is on

- **Machine plane (unchanged).** The loopback/service cert stays long-lived and **slot-shaped**: it is checked
  against `known_admin_ids` exactly as today, and it gets **no** per-use role check — machines have no person, and
  putting one on the loopback path would make an internal hop depend on the role table for no benefit. Ruling 1
  keeps this cert on the core and out of human hands.
- **Human plane (new).** A short cert is **person-shaped**: identity is the `user_id` the ceremony produced
  (§2.6), the static allowlist does **not** apply to it, and `require_admin` performs a real role lookup on
  every use.

**The boundary cannot be inferred from the identity string, and it cannot be inferred from lifetime.** Both
inferences fail the same way: a misclassified credential silently walks the wrong policy path. A long-lived
bootstrap cert whose identity is *not* in `known_admin_ids` would be treated as a person cert and 403 with a
confusing message; a human short cert *named* in the allowlist would silently keep the old no-revocation
behavior, which is precisely the hole ruling 2 closes. The design therefore requires an **explicit,
CA-written marker**:

- **Marker:** a dedicated X.509 extension with a Venya private OID carrying the plane (`machine` | `human`),
  written by the server's own signer, never taken from a CSR. (The product already relies on signer-written
  extensions for identity: SAN and CN are overwritten in `sign_csr`, `ca.py:383-389`, `:428-431`.)
- **Why an extension and not an OU string:** OU is also signer-written today (`ca.py:753-754` sets `O=Venya`,
  `OU=Admin`) and is a workable fallback, but an extension with a critical bit is a statement the verifier can
  refuse to parse rather than a name that can drift. RF-7 may implement the marker as OU if it prefers a
  human-readable dump; what is **not** negotiable is that the plane is explicit and CA-set.
- **A cert with no marker, an unparseable marker, or a value outside {machine, human} fails closed at step 3.5**
  with a 403 whose text says the certificate predates the two-plane model and must be re-issued. That is the
  rollout-facing behavior (§3.8, §10): old certs are refused *loudly on the human path* rather than silently
  defaulting into either plane. Machine certs get their marker written at the same time the change lands, by the
  core's own bootstrap path (RF-10's scope, not this design's).

### 3.3 The per-use role check — exact semantics

`require_admin` (`dependencies.py:307-358`) already does the right thing for **token** callers: role lookup via
`RoleManager.get_role_by_name("admin")` (`core/iam/role_manager.py:279`) +
`has_permission(user_id, role.id, "read-write")` (`:647-664`), 403 on miss. The design **removes the shortcut
branch at `:332-333` so admin-mTLS callers run the same lookup**, with one structural addition:

1. `user_info["user_id"]` for a human-plane cert is the embedded identity. Because §2.6 derives it from the
   authenticated session's `user_id`, it resolves against `User.user_id` (`core/iam/models.py:48`, `String(64) unique`) by construction — no fuzzy name matching, no email-to-user mapping table.
2. The lookup requires: user row exists, `status` admits admin use, the `admin` role exists, and membership has
   `read-write` (`Role.permissions`, `models.py:69`). Any miss → 403, same body shape as today's
   `detail="Admin permission required"` (`dependencies.py:351`, token-path denial).
3. **Executor callers stay denied outright** (`dependencies.py:325-330`) — unchanged, and unchanged in reason:
   admin routes are human-only, and the executor identity carries no `user_id`.
4. The **`caller` key stays** for plane identification (logging, audit, and any plane-aware route logic); what
   dies is the *bypass*. The docstring at `dependencies.py:332` ("mTLS admin callers are already verified by
   nginx + middleware") must be corrected in the same commit — it states the very premise ruling 2 replaces, and
   note it is already partly wrong: nginx runs `ssl_verify_client optional` (`install-venya-core.sh:911`) and the
   middleware docstring says app-side verification is the gate (`middleware/auth.py:182-185`).

Where the check lives: **route dependency, not middleware.** The middleware authenticates (who presented a valid,
non-revoked cert of plane X); the dependency authorizes (does that person hold admin now). That split already
exists in the code and keeps one lookup per request on the path that needs it.

### 3.4 Audit: the used identity in the row

Ruling 2's last clause. The admin request path must write the acting identity the way the mint does (§2.8):
`user_id` = the embedded person identity, plus the serial and the plane marker, so an audit reader can tell
"person X used cert serial S" from "the loopback machine used cert serial S". `AuditEvent.user_id` deliberately
has no FK and stores the principal verbatim, including mTLS CNs (`core/iam/models.py:173-180`), so this needs no
schema change — it needs the route paths to pass the identity they now actually have. Paired negative (truth-table
law): a human-plane request refused by the per-use role check still produces its denial record, and a
machine-plane request must **not** be written up as if a person acted.

### 3.5 Mandatory statement 1 — DB reachability becomes an AUTHORIZATION dependency

> **Stated plainly, not glided past:** per-use role checks make the human admin path depend on database
> reachability for **authorization**, not merely authentication. **If the database is down, admin operations from
> a human short cert FAIL CLOSED.** A degraded DB is an admin lockout. This is ruled correct-by-design — the
> alternative is an admin cache that outlives the role removal ruling 2 exists to make effective — and it is a
> **documented behavior change**, not a hidden one.

Honest framing of the delta, because the carrier's caveat overstates the novelty and the next lane must not
discover the nuance mid-review: the admin path **already** touches the DB on every request. Step 4 opens a
session (`middleware/auth.py:457`) and its `except Exception` at `:463` turns a dead DB into a 403. So a DB outage
locks admins out today. What changes is the *layer and the meaning*: authorization moves onto that dependency, so
the failure is no longer "we could not check your revocation status" but "we could not establish that you are an
admin". Consequences:

- **Distinguish the two 403s.** The revocation-lookup failure text stays as-is; the role-lookup failure should be
  a **503** (service unavailable) rather than a 403 (permission denied), because an operator reading 403 will
  debug certificates and roles while the actual fault is the database. The CLI surfaces the server's `detail`
  string to the operator verbatim (`api_client.py:528`, `:647`, `:784`), so the text is the operator's only
  diagnostic and must name the cause. Fail-closed is satisfied by either code; clarity is only achieved by 503.
- **Pool reality:** `Backend.get_session()` is a fresh `session_factory()` per call (`core/engine/backend.py:254`)
  on an engine with `pool_pre_ping=True`, `pool_size=5`, `max_overflow=10` (`backend.py:260-264`). A per-use
  role check adds one lightweight query (`RoleMember` filter, `role_manager.py:658-665`) to a path that already
  opens a session — not a new connection source. No caching is proposed; a cache is a revocation delay wearing
  a performance costume.
- **Docs obligation (RF-11):** the admin runbook must state that an admin can be locked out by infrastructure,
  and that the recovery-code path (§2.3) is the escape hatch.

### 3.6 Mandatory statement 2 — the embedded identity DISCLOSES ADMIN USERNAMES

> **Stated plainly, not glided past:** a certificate is a public object. The person identity embedded per ruling 2
> is **readable by anyone who holds the file** — no key, no password, no server. `subject` and the SAN are not
> secret; they are covered by nothing more than the file's permission bits. **This design therefore discloses
> admin usernames to every party that can read the cert file** — a workstation backup agent, a synced home
> directory, a copied artifact in a support ticket, or the proxy logs that carry the forwarded PEM. The owner
> **accepted** this at 60-minute lifetimes with FIDO2-gated issuance. It is a consequence of the ruling, not a
> defect in the design, and it is not remedied here.

What the design does do is keep the disclosure surface as small as honesty allows:

- **Username = the `user_id` the system already exposes.** The User model has no `username` or `email` column
  (`core/iam/models.py:42-58`: `user_id`, `display_name`, `status`, `auth_mode`, …), and `user_id` is already
  rendered in the admin user list and in audit rows. Embedding it adds no name that was previously private inside
  the deployment; it adds the name to *files outside* the deployment. That is the disclosure.
- **Nothing else goes in the subject.** No `display_name`, no email beyond what `user_id` already is, no tenant
  or site metadata. `_build_san_for_identity` (`ca.py:569-585`) keeps `@`-shaped ids in the RFC822 branch and
  plain ids in the DNS branch — it does not synthesize either.
- **The audit row is not a leak channel and must not become one:** `ADMIN_CERT_ISSUED` carries the identity
  (§2.8) because attribution requires it, and deliberately omits cert/CSR/public-key material.
- **Pairing matters:** the identity is disclosed while the **private key stays on the workstation** (§2.4). A
  reader who has the cert file but not the key cannot authenticate. The combined-file case — both in one
  directory, world-readable — is what `modewarn` exists to complain about (§1.4).

### 3.7 The key becomes the lock (problem 8)

Under this design a lost security key means no ceremony, therefore no mint, therefore no human admin path — while
the cert file that used to be the escape hatch no longer exists as a standing credential. Two paths must be
specified, and both already exist:

1. **Recovery code** (ruling 1, third clause): `routes/recovery.py`, break-glass rate limiting
   (`middleware/rate_limit.py:276-279`, `:205-240`). This is the *admin-lockout* answer.
2. **Re-enrollment** under the roster guard `assert_removal_keeps_admin` (`core/iam/role_manager.py:416`), which
   is what stops an operator from removing the last admin by accident.

What is **not** an answer: keeping a standing human cert "for emergencies". That reintroduces the exact exposure
this program retires. RF-9 owns the service-identity detail; RF-11 owns the runbook text that tells a locked-out
admin which of the two paths to walk (the machine plane stays up regardless, so a lost key never stops the core —
it stops *human* admin work).

### 3.8 Negative tests required at this boundary (truth-table law)

Every row is a rejection that must be proven, not assumed:

| Case | Expected |
|---|---|
| Human-plane cert, role removed after mint | 403 on the very next request (§3.3) — this is ruling 2's whole point |
| Human-plane cert, DB down | fail closed (503 per §3.5), never a silent allow |
| Machine-plane cert, identity absent from `known_admin_ids` | 403 (today's behavior, unchanged — `auth.py:415-431`) |
| Machine-plane cert held by a human (copied off the core) | refused by *not being mintable* for a human (§2.6) and by plane marker discipline; RF-11 must state that copying the loopback key is unsupported |
| Cert with **no plane marker** (pre-change cert) | 403 naming the re-issue requirement (§3.2) |
| Cert with a marker **self-signed by the caller** in a CSR | impossible — marker is signer-written only; a cell must prove a CSR-supplied marker is discarded (§2.6.1) |
| Human cert whose `user_id` was deleted | 403 (lookup miss), no 500 (`dependencies.py:325-330` precedent for clean denial) |
| Revoked serial, valid person, intact role | 403 at step 4, before the role check ever runs |

### 3.9 Inheritance — what later legs take from this section

- **RF-7:** the plane marker as a signer-written extension with fail-closed parsing (§3.2), `ADMIN_CERT_ISSUED`
  audit fields (§3.4), and the 503-vs-403 distinction for DB faults (§3.5).
- **RF-8:** the operator-facing text consequences — the CLI prints the server `detail` verbatim
  (`api_client.py:528`, `:647`, `:784`), so a DB-down refusal and a no-permission refusal must be
  distinguishable *from the string alone*, and the pre-two-plane-cert refusal must name the re-issue command.
- **RF-9:** the machine plane's rules restated here are its contract — slot-shaped, allowlist-checked, no role
  check, never handed to a human (§3.2).
- **RF-10:** writing the marker at the machine/bootstrap mint, and the `VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS`
  meaning shift (config `:271`; installer `:555`/`:584`) becomes a rollout transition, not a semantics edit.
- **RF-11:** the two mandatory statements (§3.5, §3.6) are runbook and doc text, plus the lockout path (§3.7) and
  the "do not copy the loopback key" rule.

---

## 4. Renewal plumbing — explicit renew, a real seam, and the lifetime-readable check

Ruling 4b: renewal is **explicit, never an automatic ceremony mid-run**. The owner's reasoning is carried as
design law: a paused headless script holding admin privileges while it waits for a human is a worse state than a
clean failure. The helpful-refusal precedent governs and the error text names the exact command. 4b additionally
orders a **lifetime-readable check** so a long job can be pre-flighted. This section designs all of it against the
code that actually exists.

### 4.1 The mechanism, verified (and one inherited premise corrected)

What the CLI does today, re-derived at `d0d3d0d`:

| Step | Live code | Site |
|---|---|---|
| Admin pair resolved from env at construction | `VENYA_ADMIN_CERT` / `VENYA_ADMIN_KEY` | `api_client.py:342-343` |
| Existence checked, content never inspected | `os.path.isfile` → `APIClientError` | `:364-370` |
| Paths stored | `self._admin_certfile` / `_admin_keyfile` | `:385-386` |
| Transport built **lazily on the FIRST DIAL**, once | `if self.__http is None: … self.__http = httpx2.Client(**kwargs, verify=verify)` | `:412-453`, guard `:429`, build `:452`; comment `:395-396` says an already-built `_http` still bypasses the real build |
| Context built from the stored paths | `_build_ssl_context(cafile, certfile, keyfile)` | `:447-451`, function `:157-205` |
| Key+chain handed to OpenSSL once | `ctx.load_cert_chain(certfile=…, keyfile=…)` | `:199` |
| Client closed only on `close()` / context exit | `if self.__http is not None: self.__http.close()` | `:800-805`, `:806-810` |

**Premise correction, stated because it changes the fix:** the input file's problem 4 cites "`api_client.py:199`"
and says "the CLI builds its TLS context once". True at the time of writing, but the live site is `:412-453` and
the number that matters is *when*: the build is deferred to the first request (ticket #530 moved it off
construction, precisely because `run_command()` builds an `APIClient` for **every** command before dispatch). So
"once per process" is right, and "once at startup" would be wrong — and the seam below exploits that: **there is
already a single choke point through which every request passes.**

**Corrected premise 2 — the proxy is not the strict enforcer.** Problem 5's framing ("short validity is strictly
enforced by OpenSSL at the proxy") is not what the shipped config does. nginx runs
`ssl_verify_client optional` (`install-venya-core.sh:911`) and there is **no `ssl_crl` and no CDP fetching** in
the served config; the client cert is forwarded and the **application is the enforcement point**, as
`_verify_forwarded_cert`'s own docstring states ("nginx dropped expired certs at the outer TLS layer; end-to-end
the app must check too, since app-side verification is now the gate", `middleware/auth.py:182-185`), with the
window check at `:198-202`. Consequence: the skew fix in §5 is a **product config knob that already exists**, not
an OpenSSL/nginx change. Handled fully in §5.

**Capability-isolation constraint (not negotiable, from the source itself):** the CLI is barred from importing
`core` — `tests/test_capability_isolation.py` keeps `venya-cli` standalone, which is why the canonical serial
format is deliberately duplicated in the CLI with an instruction to keep it byte-identical to
`core.utils.cert_serial.canonical_serial` (`commands.py:4005-4008`). Any lifetime/serial formatting added here
follows that same rule: **duplicate the literal, cite the source, do not import.**

### 4.2 The renew command (the mint path, re-invoked)

`venya admin cert renew` is not new plumbing — it is §2's issuance flow re-entered, with the existing cert as
input rather than a fresh keypair:

- Same transport, same authorization (bearer session + single-use elevation token), same signer
  (`AdminCAManager.sign_admin_csr`, §2.5b), same audit (`ADMIN_CERT_ISSUED`, mint reason `renew`, §2.8).
- **Key handling, the choice RF-8 must implement:** reuse the **existing** workstation keypair and submit a fresh
  CSR signed by it. Rationale: the key never left the machine, so a re-key buys nothing, and reusing it means a
  renewal cannot orphan an in-flight connection or require re-distributing a key. The CLI must still refuse to
  renew when the key file is missing or unreadable, with text naming both paths. (A `--rekey` flag is
  deferrable; it is not required by any ruling.)
- **One consequence RF-8 must not miss:** `known_admin_ids` plays no part here, but the **identity must come from
  the session again** (§2.6), not from the old cert's subject. Renewing must not become a way to launder a
  subject an operator edited locally.
- Renewal is allowed while the current cert is still valid (that is the pre-flight case, §4.5) and while it is
  expired (that is the recovery case). It is **not** allowed to be triggered by the request path — see §4.6.

### 4.3 Expiry-mid-process: the design makes it work, and says how

The naive expectation — "a renewal written by another process is picked up automatically" — is false at the
mechanism level, so it must be designed against: `load_cert_chain` (`:199`) copies the chain into the OpenSSL
context at build time, and the built client is cached (`:452`) until `close()` (`:800-805`). Rewriting the file
under a live process changes nothing it will send.

**Design: fingerprint-triggered context rebuild at the existing choke point.**

- At context build, record a fingerprint of the admin cert file: **`sha256` of the file bytes**, computed once per
  dial (a certificate is ~1 KB; the cost is irrelevant next to the network round trip).
- Before each request, at the `_http` property (`:413`), re-read and re-hash the cert file. If the hash differs →
  **rebuild the context and the client** (close the old client, rebuild via the same `_build_ssl_context` call),
  then send. If it matches → send on the existing client, zero added syscalls beyond one read.
- **Why content-hash and not `mtime`/size:** `cp`, `rsync`, and a re-download of an identical file all change
  `mtime` without changing material, which would rebuild contexts on noise; and — the failure that matters — a
  restore that leaves `mtime` behind (archive tools, some `cp -p` paths, filesystem clock oddities) would **not**
  rebuild, silently continuing to present the old, soon-to-be-dead cert. Size-only comparison is worse: two
  certs for the same identity are the same length by construction. Content hash is the only cheap signal that
  cannot lie in both directions.
- Negative case that must be proven (truth-table law): renew to a **different file** and point `VENYA_ADMIN_CERT`
  there — a process holding the old path must keep using the old file and must not silently adopt anything.
  And: replacing the file with byte-identical content must **not** rebuild (no churn, no connection storm).
- Why not "rebuild every request": correct but wasteful, and it throws away connection reuse for every command
  including the non-admin ones. Why not "never rebuild": it means a long-running admin script dies at the 60-minute
  mark even after a successful renew, which turns 4b's explicit renew into "restart your job" — a worse operator
  story than the one ruled, and one that would push people toward the standing credential this design deletes.

### 4.4 What expiry looks like when no renewal happened — the helpful refusal

If the material on disk is past its own `not_valid_after`, the CLI refuses **before** dialing, in the product's
established style. Two precedents, both live:

- **One wording, reused not copied:** `_https_refusal` / `_require_https_server_url` (`commands.py:1505-1530`)
  exist as "the ONE refusal wording … Split out … so the sites that cannot print then return 1 … reuse the SAME
  text instead of hand-copying it. One check, one wording, no variant." The expiry guard is built the same way:
  one function, called from every dial site, no hand-written variants per command.
- **Wrap, never silence, and name the repair:** `_build_ssl_context` already models this — an unloadable anchor
  raises text that names the file, says what is wrong, gives the repair command, and appends the original OpenSSL
  error (`api_client.py:184-196`); the admin pair load failure does the same for the cert/key pair
  (`:197-203`).

Required properties of the refusal (RF-8 implements the string; these are the acceptance criteria):

1. **Names the exact command** — `venya admin cert renew` (4b's law). Not "refresh your credentials", not a
   generic "re-authenticate".
2. **Names the file and the instant**: the path from `VENYA_ADMIN_CERT`, `not_valid_after` in ISO-8601 with offset,
   and how long ago it expired — all computed locally, so the text is honest about being local (§5.3).
3. **Distinguishes the two clock faults**: "expired" (past `not_valid_after`) and "not yet valid" (before
   `not_valid_before`) are different failures with different causes; the second one is almost always skew (§5).
4. **Surfaces the server's reason when the dial happened anyway** — the CLI prints the server `detail` verbatim
   (`api_client.py:528`, `:647`, `:784`), so the server-side strings in §3.5 and §5.4 reach the operator as
   written.
5. **Exit non-zero, stdout clean** — same discipline as `modewarn` (§1.4): diagnostics on stderr, so a script's
   captured output does not change shape when a cert dies.
6. It is a **refusal, not a prompt.** No "touch your key now?" y/n. A script must die cleanly; a human must be
   told the one command to run.

### 4.5 Mandatory statement (4b) — the lifetime-readable check

The owner's addition exists so headless work stays composable without hiding a ceremony inside it:
**`venya admin cert status`** (or `renew --dry-run`, RF-8's naming call) must print remaining lifetime and **make
no credential mutation**. Design requirements:

- **Reuse the existing shape.** The CLI already does exactly this for executor certs: a read-local-parse-report
  helper returning `serial`, `subject`, `not_after`, `days_remaining` (`commands.py:2670-2700`), and the admin
  mint already prints `Serial` / `Expires` / `Key … permissions` / `Cert … permissions`
  (`commands.py:4010-4016`). The admin status command is the same two pieces bolted to the admin pair — not a new
  reporting framework.
- **`days_remaining` is the wrong unit at 60 minutes.** Print **minutes remaining** (and the absolute expiry
  instant). A 0.75-day figure is how a lifetime check becomes useless.
- **Three answers, not two:** no valid cert file → say so and name the mint/renew command; valid but expiring
  within the job window the operator can state → say "renew before starting"; valid → print the lifetime and exit
  0. This is the pre-flight that 4b asks for: *renew at script start, run the job, fail cleanly if the job outlives
  the cert.*
- **Honesty clause:** the figure is computed against the **local** clock. The authority is the server's window check
  with §5's tolerance (`middleware/auth.py:198-202`). If the local clock is skewed the printed lifetime can be
  wrong in either direction — the output must label it (one line, not a lecture), and the "not yet valid" case must
  point at §5.4's text rather than silently reporting a bogus negative lifetime.
- **Zero-mutation guarantee is testable:** the command performs no POST, no ceremony, no key read of the private
  material, and no file write. A cell must assert that (a transport spy sees no request), because the moment a
  "status" command can trigger a mint, 4b's "no ceremony mid-run" is quietly dead.
- Suggested operator flow in the docs (RF-11): `status` → `renew` if needed → run the job → the job fails with the
  §4.4 refusal if it outlived the cert → re-invoke after renew (and §4.3's rebuild means a *long-lived* process
  that renewed out-of-band does not even need re-invocation).

### 4.6 The boundary 4b draws — no automatic ceremony, stated as a testable rule

The request path **never** initiates a ceremony, never opens a browser, never waits on a prompt, and never
re-mints on a 401/403. Contrast with the bearer session, which *does* have a refresh concept elsewhere in the
product (`middleware/auth.py:236-243` discusses the refreshable idle-expired session); that pattern must not be
copied onto the admin-cert path, because the refresh there costs no human and the refresh here costs a FIDO2
touch. Acceptance: a cell driving a request with an expired cert must observe **exactly one** attempt and a clean
refusal — no ceremony call, no retry loop.

### 4.7 Inheritance — what later legs take from this section

- **RF-7:** renew is the §2 endpoint with reason `renew` (§4.2); the identity stays session-derived (§4.2).
- **RF-8:** the fingerprint-triggered rebuild at the `_http` choke point with **content hash**, the one-function
  refusal wording, the six refusal properties (§4.4), the status command's three answers plus its zero-mutation
  cell (§4.5), and the no-import constraint on serial/lifetime formatting (§4.1).
- **RF-9:** service identities renew **without** a ceremony — which means they cannot use §4.2 as written; the
  split's machine plane needs its own answer (§9). Do not extend "explicit renew only" to the machine plane
  without saying so there.
- **RF-10:** the installer's printed workflow must name `renew`/`status`, replacing the `scp` handoff lines
  (`install-venya-core.sh:978-981`) — proposed text only, owner-ok-gated.
- **RF-11:** the operator runbook text for §4.5's pre-flight flow, plus the refusal strings' user-visible wording.

---

## 5. Clock skew — tolerance as a fraction of a 60-minute life

Ruling 4a attaches two conditions to the 60-minute number, and both land here: **skew tolerance must be a small
fraction of lifetime (minutes, not tens of minutes)**, and **NTP drift on a workstation is now a plausible
admin-lockout cause that the error text must say so**. Problem 5's framing ("short validity is strictly enforced
by OpenSSL at the proxy") needed correction against the shipped config; §4.1 did the correction, and this section
carries the consequence.

### 5.1 The law this section implements

> **Tolerance is a fraction of lifetime, not a constant.** With lifetime at 60 minutes, the tolerance budget is
> **minutes**. Any tolerance value must be justified as a stated fraction of the current lifetime, and a lane that
> changes either number must re-check the fraction. **A tolerance that is large relative to the lifetime converts
> the theft window into a suggestion.**

The fraction test is what makes this checkable rather than rhetorical: at 60 minutes, 300 s is 8.3 %, 60 s is
1.7 %, 30 s is 0.8 %. RF-7/RF-11 can argue about 30 vs 60; neither number can quietly be 3000.

### 5.2 Where validity is actually enforced (verified)

| Layer | What it does with validity | Verified at |
|---|---|---|
| nginx outer TLS | `ssl_client_certificate` + `ssl_verify_client optional` — no `ssl_crl`, no explicit verify-mode in the served config. With `optional`, a verification failure does not kill the handshake; the PEM is forwarded anyway | `install-venya-core.sh:910-911` |
| **Application (the gate)** | `_verify_forwarded_cert` re-does chain + validity end-to-end, **and this is the layer that applies the product's skew tolerance**: `tolerance = config.clock_skew.cert_tolerance_seconds` (or 0), then `now < not_before - tol` / `now > not_after + tol` both fail closed | `middleware/auth.py:198-202`; docstring `:182-185`; per-plane anchors `:123`, `:140` |
| Executor/session layer | same builder, executor anchors | `:688`, `:715` |
| Token/session layer | separate knob, `token_tolerance_seconds`, consumed by `session_manager` / `enrollment_manager` via `clock_skew_tolerance_seconds` | `config.py:242`, `session_manager.py:174`, `:338`, `:361`, `enrollment_manager.py:97`, `:157`, `:256` |
| CLI (local, pre-flight) | reads its own cert for lifetime display; no clock authority | §4.5 |

Consequence: **skew policy is a product config value the application already reads**, not an OpenSSL build
decision. That makes the fix cheap and makes the current default a real review item rather than a curiosity.

### 5.3 The current default silently extends the theft window — with the arithmetic

`cert_tolerance_seconds` defaults to **300** (`config.py:248-251`, `ge=0, le=600`) and is documented as such
(`docs/ease-of-use.md:208`: "60 s tokens / 300 s certs"). It was sized when an admin cert lived **90 days**
(`ADMIN_CERT_VALIDITY_DAYS = 90`, `ca.py:566`), where 300 s is 0.08 % of life and free of consequence.

At a 60-minute life the same default means:

```
tolerance:    now > not_valid_after + 300s  → still admitted  (middleware/auth.py:202)
theft window: 60 min + 5 min = 65 min       → +8.3 % over the ruled number
```

That is not a hypothetical: the replay path is the application's own admission decision. A copied short cert is
replayable for five minutes past expiry, on the machine that holds it, with no ceremony. 8.3 % is still a "small
fraction" by §5.1's test, so this is **not** a blocker — but a design that rules 60 minutes as *the theft window*
should not leave the effective window at 65 by inherited default.

**Design position:** lower the admin-relevant `cert_tolerance_seconds` default to **≤ 60 s** (a 1.7 % fraction),
and make the relationship **asserted rather than remembered** — one test cell that reads the lifetime constant and
the tolerance constant and fails if `tolerance > lifetime/20`. Constant-coupling tests are the only defense against
a future lane raising one number and not the other. RF-7 owns the value choice; the fraction bound is the
requirement.

**Direction asymmetry, stated because it is uncomfortable and one-sided:** a tolerance window is applied in both
directions (`:200` and `:202`), so the same number that rescues a clock running slightly *behind* also grants a
stolen cert extra life on a clock running *right*. A forward-skewed verifier grants life; a backward-skewed
verifier causes lockout. If the product later wants different budgets per direction (tight forward, looser
backward — or, since the server's clock governs minting, applied only to the verifier's own clock), that is an
implementation detail for RF-7 to rule on; what is **not** optional is that the *total* stay inside §5.1's
fraction, and that whoever splits the knob re-runs §5.3's arithmetic on the forward half.

### 5.4 The two lockout shapes, and what the error text must say

The ruled condition is that the error text **names NTP drift as a plausible cause**. It must also name the right
*subject*, because the two shapes have different blast radii and different fixes:

- **Workstation-side drift (individual lockout).** The core's clock is authoritative for the window check
  (`:199`), so a skewed client clock does **not** usually cause rejection — the server's `now` decides. It causes
  lockout in two real ways: (a) the **local pre-flight lies** (§4.5's honesty clause — a machine 10 minutes behind
  reports 70 minutes of life on a 60-minute cert, then the job dies mid-run); and (b) **inner-TLS deployments**,
  where the client's certificate is validated at a TLS layer whose clock is the verifier's
  (`config.InnerTLSConfig`, `:277`; the inner channel's client cert is the *inner* cert at
  `install-venya-core.sh:932-933`, so the human cert is not on that hop, but the same class applies to any
  verifier-side skew).
- **Core-side drift (mass lockout).** Every admin's request is judged against **one** clock. If a core's clock
  steps forward, `not_before - tol` is unattainable and every short cert is "not yet valid" at once; step it back
  and every cert is expired at once. At 90-day lifetimes, clock drift of minutes was noise; at 60-minute
  lifetimes **it is an outage of the entire admin plane, all installs sharing that host's clock, within the
  tolerance plus one mint.** NTP discipline on the cores is now an availability dependency of admin access, not
  just a logging nicety. This is the note the carrier asked for and RF-11 must put in the ops docs, not in a
  footnote.

Required properties of the refusal strings (server side; they reach the operator because the CLI prints the server
`detail` verbatim — `api_client.py:528`, `:647`, `:784`):

1. **Name the fault class, not just the outcome.** "Certificate is not yet valid according to this core's clock"
   and "certificate has expired according to this core's clock" are separate strings from the generic
   `Admin access requires valid client certificate` (`auth.py:395`, `:405`, `:425`, `:431`, `:454`, `:481`).
2. **Name NTP/clock drift as a plausible cause** in both, per ruling 4a's condition — verbatim intent: a
   not-yet-valid rejection on a cert that was minted seconds ago means *someone's clock* is the problem.
3. **Name the direction and the delta where the server can compute them**: presented `not_before`/`not_after`,
   server `now`, and the difference — so an operator can tell "core clock 40 minutes fast" from "wrong cert".
4. **Name the operator's next command** (4b's naming law applied to skew): the repair is time sync plus a fresh
   `venya admin cert renew` for the expired case; for the not-yet-valid case it is time sync only, and the text
   must not tell a user to re-mint against a clock that will still be wrong.
5. **Fail closed regardless.** None of this is a reason to widen tolerance ad hoc; a deployment that genuinely
   cannot sync clocks raises the value in `/opt/venya/.env` (§5.5) and accepts the §5.3 arithmetic on its own head.

### 5.5 What this design changes, and what it leaves alone

- **Changes:** the `cert_tolerance_seconds` default (RF-7), the two refusal strings and their delta reporting
  (RF-7 server, RF-8 CLI), the fraction-assertion test cell (RF-7), and the ops-doc NTP note (RF-11).
- **Does not change:** `token_tolerance_seconds` (60 s, `config.py:242-247`) — it governs sessions/tokens, not the
  cert window, and its consumer set is different (§5.2). Do not "unify the knobs" as a drive-by: one value serving
  two policies is how §5.3's inherited default happened in the first place.
- **Not a fix:** relying on `ssl_verify_client optional` at nginx to police expiry. The app is the gate
  (`auth.py:182-185`) and stays the gate; per-plane anchoring already refuses cross-plane certs there
  (`admin_cas` `:377`, executor path `:688`).
- **Config surface stays as-is and is already reachable:** `VENYA_CLOCK_SKEW__CERT_TOLERANCE_SECONDS` via
  `env_prefix="VENYA_"` + `env_nested_delimiter="__"` (`config.py:330-332`), file `/opt/venya/.env`
  (`docs/ease-of-use.md:208`). The installer does **not** write it today (no `VENYA_CLOCK_SKEW*` in
  `MANAGED_ENV_KEYS`, `install-venya-core.sh:555`) — which is correct: the default is the policy, and a
  per-deployment raise is an explicit operator act, not something an install script should be deciding.

### 5.6 Negative tests (truth-table law)

| Case | Expected |
|---|---|
| Cert expired, `now - not_after` < tolerance | admitted (documented leniency, bounded by §5.1) |
| Cert expired, delta > tolerance | refused, text names expiry + drift + renew (§5.4.1-4) |
| Fresh cert, verifier clock ahead by > tolerance | refused as **not yet valid**, text names drift — **and must NOT tell the user to re-mint** |
| Fresh cert, verifier clock ahead by < tolerance | admitted |
| Tolerance raised above lifetime/20 | the §5.3 assertion cell goes red |
| Tolerance set to 0 (`ge=0`) | strict window, still no crash and no 500 — and the refusal text still names drift as a cause |
| Local `status` on a 10-minutes-behind workstation | prints the lifetime it computed **and** labels the clock as local (§4.5) — the lie must be visible |

### 5.7 Inheritance — what later legs take from this section

- **RF-7:** the fraction bound plus the **assertion cell** (§5.1, §5.3), the two new refusal strings with
  delta/direction (§5.4), and the "don't unify the token knob" rule (§5.5).
- **RF-8:** its local lifetime display must label the clock as local (§4.5 × §5.3), and its pre-dial expiry
  refusal (§4.4) must not contradict the server's tolerance window — the CLI refuses at `not_after`, the server
  admits until `not_after + tol`; that gap is **intentional** (the CLI is advising, the server is deciding) and the
  strings must not imply the other layer is broken.
- **RF-9:** a service identity on the machine plane has the same clock dependency but no ceremony to re-run — its
  renewal must survive transient verifier-side skew (§9).
- **RF-10:** nothing to write in the installer — the knob is deliberately unmanaged (§5.5); the ops text is RF-11's.
- **RF-11:** **the NTP mass-lockout note is a first-class ops statement** (§5.4): core-side clock drift is an
  admin-plane outage mechanism at minutes-scale lifetimes. Also the deployment-sizing/time-sync guidance for
  HA cores, where each core's clock judges every admin's request.

---

## 6. Disposition of `sign_admin_cert`

Ruling 3 orders a disposition — **fix or remove, stated explicitly, with the test cells handled in the same
breath** — and forbids leaving it unused-and-unreviewed. The premise the ruling was written on ("dead production
code; zero callers outside `packages/server/tests/`") does not hold at the tip this dossier is written against, so
the disposition below is built on the live caller rather than on the premise. Flag 1 restates it.

### 6.1 The live caller — re-verified at `d8a5cda`

The grep that produced ruling 3's premise was scoped to `packages/`. The installer is outside that scope and calls
the function:

| Fact | Verbatim line | Site |
|---|---|---|
| The mint call itself | `cert, key_pem, cert_pem = cm.sign_admin_cert(sys.argv[1])` | `install-venya-core.sh:420` |
| It is the abort point on a re-run | `# undecryptable and aborts the run at sign_admin_cert. Precedence:` | `install-venya-core.sh:341` |
| The block's own purpose comment | `# Generate first admin cert. sign_admin_cert loads the CA key — now` | `install-venya-core.sh:408` |

Definition and key material, re-grepped at `d8a5cda`:

| Item | Site |
|---|---|
| `def sign_admin_cert(self, admin_identity: str) -> tuple[x509.Certificate, bytes, bytes]` | `packages/server/src/server/ca.py:732` |
| Keypair generated **by the signer** | `ca.py:749` (`ec.generate_private_key(ec.SECP256R1())`) |
| Lifetime from the constant | `ca.py:766` (`ADMIN_CERT_VALIDITY_DAYS = 90`, `ca.py:566`) |
| Private key serialized unencrypted | `ca.py:815` (`serialization.NoEncryption()`) |
| Returns `(cert, key_pem, cert_pem)` | `ca.py:819` |

And the reachability check that bounds the risk: the symbol appears in **no** server route, and in
`backend.py` / `app.py` — the count from
`grep -rn 'sign_admin_cert' packages/server/src/server/routes/ packages/server/src/server/backend.py packages/server/src/server/app.py`
is **0**. So it is not an HTTP-reachable key export; it is a library entry point whose only production caller is
the installer's local `python -c` block (`install-venya-core.sh:411-429`), running **on the core**, as user
`venya`, reading the CA passphrase on stdin.

### 6.2 What the bootstrap actually needs (this is what makes the disposition possible)

The function's output is not only the human handoff. It serves **two consumers on two different planes**, and
only one of them is the credential this program retires:

1. **The machine-plane / loopback credential.** The installer writes the pair to `/etc/venya/admin/admin.crt` +
   `admin.key` (`:423-426`, modes `0644`/`0600`), records the identity into `known_admin_ids`
   (`VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS` is written from `$ADMIN_IDENTITY` at `:584`, key enumerated at `:555`),
   and the default identity is hostname-shaped — `admin@${CORE_HOSTNAME}` (`:368`). The install banner then
   documents the **on-core headless** use of that same pair: `VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt` +
   `VENYA_ADMIN_KEY=/etc/venya/admin/admin.key` with the CLI (`:1001-1007`), with the honest note that a plain
   `venya admin ...` "falls back to an interactive FIDO2 login and dies without a workstation key".
   Under ruling 1 that credential is the **machine plane**: long-lived, slot-shaped, checked against
   `known_admin_ids`, stays on the core. **It is not retired by this design.**
2. **The human handoff.** The `scp` instruction at `:978-981` is the exposure this program exists to close, and
   the only part of the bootstrap that is about a person.

That split is the whole disposition: the mint survives as the machine-plane bootstrap; the human handoff dies.

### 6.3 Disposition: **fix** (narrow to the bootstrap/machine plane), not remove

**Ruled design, stated explicitly:** keep a single server-side mint on the core, narrowed so that it can only
produce a machine-plane credential, and delete the human handoff instead of the function. Concretely:

1. **`AdminCAManager.sign_admin_cert` is retired as a public entry point and replaced by
   `AdminCAManager.sign_admin_csr(csr, identity, lifetime_seconds, crl_url=None)`** (§2.5b) for the human plane,
   and by a **bootstrap-only** signer for the machine plane. The bootstrap signer may keep generating its own
   keypair — the key is created and consumed in the same process on the same machine, it never crosses the
   network — but its contract changes to name that fact: machine plane, hostname-shaped identity, no human
   session, and the plane marker written at mint (§3.2).
2. **The unencrypted return at `ca.py:815` stays, and is ruled.** That site *is* the Q4a question: the core-side
   admin key. Ruling 4d scopes Q4a to exactly this key, and the owner's bydesign word is carried in the carrier
   verbatim — *"leave admin.key unencrypted on the core"* — with filesystem permission as the control (the
   installer's `0600` write, `:426`). What was never acceptable is the **delivery** of that key to a home
   directory, and that is item 4 below, not this line.
3. **A caller interlock cell replaces the deleted premise.** The design does not trust "nobody calls this": it
   asserts it. Precedent in-repo, both shapes:
   - **attribute-shape**: `packages/server/tests/test_ca_key_accessor_retired_539.py:31-49` — the negative half
     (the key accessor is gone) paired with the positive half (the certificate accessors remain), so the cell
     cannot pass on a diff that deleted the wrong thing.
   - **source-scan**: `packages/server/tests/test_header_trust_interlock.py:44-57` — `_iter_source()` over
     shipped source, asserting a retired surface does not creep back.
   The new cell scans `packages/server/src/` (and the installer, if RF-10 wants it) for calls to the
   key-exporting mint and allows **only** the bootstrap call site, with its own plane marker. A route that ever
   reaches it is a red suite, not a review finding.
4. **The human handoff retires in the installer, not in `packages/`.** The `scp` lines (`:978-981`) and the
   copy-to-workstation framing become a ceremony instruction. **That edit is owner-ok-gated** (this program's
   standing rule on the git-tracked root installer copies; the RF-6 carrier's mission line says the same), this
   leg holds no ok and does not ask for one. RF-10 owns it.

Why not the other option: **remove outright.** Removal is *possible* but it is not a `packages/`-only edit, and
the order is load-bearing:

- The bootstrap needs *a* mint on the core (item 1 of 6.2). If `sign_admin_cert` goes without a replacement in
  place, every fresh install aborts inside the `python -c` block at `install-venya-core.sh:411-429`, and every
  re-run aborts at the documented point (`:341`) — a broken installer, not a hardened one.
- The safe sequence is therefore: (i) RF-7 lands the replacement signer plus the bootstrap mint's narrowed
  contract; (ii) RF-10 lands the installer change against it (**owner's ok, per specific change, per
  `## Installer scripts`** — the gate is owned by the owner, and no lane may treat the standing provisioning
  grant or the standing-approval amendment as an installer ok for an unnarrived change); (iii) only then does
  the old signature come out. A delete commit must never precede the installer commit that stops calling it.
- Ruling 3's "standing temptation" argument is answered by the interlock in item 3, which is enforceable, rather
  than by deletion, which in this shape would only relocate the problem into the installer.

**What is NOT the design** (stated so a later lane does not try it): exposing the bootstrap mint over HTTP
"just for first setup"; returning a private key from `sign_admin_csr`; or having the server generate the human
keypair and POST it back. Each reintroduces the server-side key export that ruling 3 exists to close.

### 6.4 The CLI twin — `admin generate-admin-cert` dispositioned in the same breath

The same mint exists a second time, outside the server, and ruling 3's "must not be left as a temptation" applies
to it equally. Re-derived at `d8a5cda`:

| Item | Site |
|---|---|
| `cmd_admin_generate_admin_cert(args)` | `packages/cli/src/venya_cli/commands.py:3888` |
| Keypair generated locally | `commands.py:3944` |
| Lifetime **hardcoded literal**, not the constant | `commands.py:3963` (`not_valid_after(now + timedelta(days=90))`) |
| SAN built DNS-only, no RFC822 branch | `commands.py:3987` (`x509.SubjectAlternativeName([x509.DNSName(identity)])`) |
| Key written unencrypted | `commands.py:4000` (`NoEncryption()`) |
| Identity shape guard | `_identity_forgery_error` (`commands.py:3872`), refuses RDN/SAN structural characters |
| Registered surface | `cli.py:435-446`, dispatched at `commands.py:688-689` |

Consequences for this design:

- **Authorization is absent by construction, and that is honest only for an offline operator.** The command takes
  the admin CA key from a local path (`VENYA_ADMIN_CA_DIR`, default `/var/lib/venya/ca/admin-ca`,
  `commands.py:3911`) and needs `VENYA_ADMIN_CA_KEY_PASSPHRASE` (`:3929-3936`). Whoever holds those two things is
  the CA. That is acceptable for a break-glass/offline bootstrap and **not** acceptable as the human admin path,
  because ruling 2's attribution and the per-use role check (§3) both start at the ceremony.
- **Plane marker is mandatory here too**: a cert minted by this command after §3.2 lands, with no marker, is
  refused on the human path (403 naming the re-issue requirement). So the command becomes machine-plane-only by
  documentation and by the marker it writes; RF-8/RF-10 own the text.
- **The `days=90` literal is a drift hazard** — the server reads `ADMIN_CERT_VALIDITY_DAYS` (`ca.py:566`), the CLI
  hardcodes it. Do not fix this with an import from `server` in the CLI; §4.1's capability-isolation rule
  (`tests/test_capability_isolation.py`) says duplicate the literal, cite the source, and **bind it with a
  contract test** that compares the two numbers, which is the same treatment the canonical-serial duplication
  already gets (`commands.py:4005-4008` region). RF-8's cell, RF-11's docs.
- The server-side mint has **no** identity-forgery guard (a grep for forgery/`_IDENTITY_FORGERY_CHARS` in
  `ca.py` returns 0) while the CLI twin does. After §2.6 (identity derived from the session, never from the
  caller) the human path no longer needs that guard, but the bootstrap mint still takes a caller-supplied
  identity string from the installer (`$ADMIN_IDENTITY`, gated only by `venya_guard_injection` for shell
  safety — `install-venya-core.sh:244`, `:372`). RF-7: carry the structural-character check to the bootstrap
  signer; it is the cheap half of closing problem 3.

### 6.5 The first-human chicken-and-egg (finding F-3; input to RF-7)

Section 2.2 anchors issuance on **bearer session + elevation**, not on a cert — which is right, and which hits a
middleware wall that chunk 1 did not record. Re-derived at `d8a5cda`:

- `_is_admin_route(path)` is a prefix test: `path.startswith("/api/v1/admin/")` (`middleware/auth.py:313-322`).
- When `admin_mtls.enabled`, an admin route goes through `_validate_admin_mtls(request)` (`:583-590`) with
  `deny_on_missing_cert: bool = True` (`:328`) — so a **cert-less bearer session on an `/api/v1/admin/` path is
  refused 403 before the handler runs** (`:378` shows the non-denying variant is opt-in).
- The product already solves this shape twice, and RF-7 should use one of those mechanisms rather than invent a
  third: `BOOTSTRAP_PATHS` (`:273`, used at `:565-578` with `deny_on_missing_cert=False` plus explicit token
  validation — the #450 pre-init treatment), or `SESSION_REQUIRED_ADMIN_PATHS` (`:285-289`, the #340-A
  cert-opens-the-channel/session-is-the-second-credential treatment).

**Design position:** the issuance endpoint must not be reachable only behind an admin certificate — the first
human has none. Either name it outside the `/api/v1/admin/` prefix, or classify it as a bootstrap path with the
`deny_on_missing_cert=False` + session-must-validate shape already proven at `:565-578`. The choice is RF-7's, the
requirement is not optional, and §2.7's rate-limit prefix question (§2.7) is decided by the same answer: a path
that is *not* under `/api/v1/admin/` still has to be added to the DB-backed middleware's classified set
(`middleware/rate_limit.py:268-274`) or it ships unlimited.

If the design instead keeps the installer mint for the first human (6.3 item 1's narrower reading — machine plane
minted by the installer, first human cert minted the same way and handed over once), then F-3 dissolves but the
original exposure survives one install, and §10's age-out accounting has to count that cert too. Stated both
ways so the owner can pick with the trade-off visible; this dossier's recommendation is the ceremony path plus
the bootstrap fix.

### 6.6 Test cells — the ones that exercise the retiring surface

No suites were run for this leg (markdown only, per the dispatch). The cell inventory below is from grep at
`d8a5cda`; RF-7 owns the rewrite.

| Cell group | Count / site | Disposition |
|---|---|---|
| `TestAdminSignCert` (`packages/server/tests/test_admin_mtls.py:196`) | **12** cells, `:196-342`; 11 references to `sign_admin_cert` in the file | Positive-structure cells (CN, SAN RFC822 vs DNS branch, CLIENT_AUTH EKU, not-a-CA, signed-by-CA, P-256 key) migrate onto the narrowed bootstrap signer. `test_admin_cert_validity_90_days` becomes a **lifetime-parameter** cell, not a 90-day pin — the human plane lives in minutes (§5), the machine plane keeps the long lifetime (§1.2 R1) |
| The key-return assertions in the same class | `test_admin_mtls.py:205`, `:321` (`_cert, key_pem, _ = …`) | `key_pem` keeps meaning for the bootstrap signer only; the human-path signer's cells must assert **no key in the return**, which is the pair to §2.5's rule |
| SKI/AKI placement | `packages/server/tests/test_admin_cert_ski_aki_504.py:87, :106, :153, :199` (4 references) | Carried unchanged onto the new signer — the #504 placement law does not care who generated the key. `:152` (`test_incumbent_admin_ca_without_ski_still_signs_valid_leaves`) is the incumbent-deployment cell and is the template for §10's dual-path honesty |
| New: caller interlock | does not exist | §6.3 item 3; both halves required (retired surface absent **and** the accessors that must remain, present) |
| New: first-human reachability | does not exist | a session-only caller can obtain a first human cert with no admin certificate presented (§6.5); paired negative: a **cert-only** caller with no session must be refused, which is the #340-A ruling carried to the mint |

### 6.7 Inheritance — what later legs take from this section

- **RF-7:** the narrowed bootstrap contract (§6.3 item 1), the caller-interlock cell with both halves (§6.3 item
  3), "no private key in the human-path return" (§6.3 not-the-design), the forgery-guard carry-over (§6.4 last
  bullet), and the F-3 decision on first-human reachability (§6.5).
- **RF-8:** the CLI twin's machine-plane-only framing and the `days=90` ↔ `ADMIN_CERT_VALIDITY_DAYS` contract
  test (§6.4), plus its error text naming `venya admin init-admin-ca` as the prerequisite (already live at
  `commands.py:3919`, `:3924`).
- **RF-9:** the machine-plane credential's origin is this section — the loopback pair the core uses headlessly
  (`install-venya-core.sh:1001-1007`) is what a service identity falls back on when it has no ceremony (§9).
- **RF-10:** owns the two installer edits — the `scp` handoff text (`:978-981`) and the bootstrap call site
  (`:411-429`) — and **both are owner-ok-gated per specific change**; the ordering law in §6.3 (installer commit
  before the delete commit) is its acceptance criterion.
- **RF-11:** the docs must say the core-side admin key stays unencrypted *because Q4a ruled it* (4d scope, the
  carrier's verbatim word), must not let that sentence be quoted as cover for the seven other sites (§7), and
  must carry the first-human story (§6.5) so an operator with a fresh install knows how a person gets a cert.

<!-- SECTIONS 7-10 FOLLOW IN THIS DISPATCH. -->

---

## 7. The `NoEncryption()` audited list and the Q4a boundary

**This section is mandatory statement 5.** The carrier's instruction is that the count be **audited, not
remembered**, published with the enclosing function per site, with the ref it was measured at stated, and closed
with the Q4a boundary sentence word-for-word. Ruling 4d scopes Q4a to the **core-side admin key ONLY**; that
scope is law here and is not re-opened.

### 7.1 The measurement

Ref measured: **dev `d8a5cda`** (the `origin/dev` tip this dispatch fast-forwarded to; also the tip the KEK design
note merged at). Command, verbatim:

```
grep -rn 'NoEncryption()' packages/ --include=*.py | grep -v '/tests/' | grep -v __pycache__
```

Result: **8 live non-test sites.** Test-file hits are a separate population (39 lines across 27 test files, plus
`packages/executor/tests/conftest.py` and `helpers/cert_factory.py`) and are excluded from the boundary by
classification, not by silence — see 7.4.

| # | File:line | Enclosing function (`def` line) | What key it serializes | Classification |
|---|---|---|---|---|
| 1 | `packages/server/src/server/ca.py:815` | `AdminCAManager.sign_admin_cert` (`:732`) | the **core-side admin key** it generates at `:749` | **IN Q4a scope** (ruling 4d) |
| 2 | `packages/cli/src/venya_cli/commands.py:2573` | `executor_register` (`:2389`) | executor keypair, workstation-built | outside the admin-path boundary |
| 3 | `packages/cli/src/venya_cli/commands.py:2969` | `executor_cert_renew` (`:2799`) | executor keypair, renewal | outside the admin-path boundary |
| 4 | `packages/cli/src/venya_cli/commands.py:3780` | `cmd_admin_init_admin_ca` (`:3737`) | **admin CA** key, no-passphrase branch | outside Q4a (CA key, not admin key) — #537 territory |
| 5 | `packages/cli/src/venya_cli/commands.py:4000` | `cmd_admin_generate_admin_cert` (`:3888`) | admin keypair, CLI-side mint | outside Q4a as scoped (4d is core-side only) — flagged, 7.5 |
| 6 | `packages/cli/src/venya_cli/at_rest_key.py:87` | `unwrap_at_rest` (`:53`) | decrypts to plaintext in memory | outside — #538 envelope territory |
| 7 | `packages/executor/src/executor/daemon.py:594` | `register` (`:410`) | executor keypair at registration | outside the admin-path boundary |
| 8 | `packages/executor/src/executor/daemon.py:774` | `rotate` (`:692`) | executor keypair at rotation | outside the admin-path boundary |

Count by class: **1 in Q4a scope**, **7 outside the admin-path boundary** (sites 2-8), 0 test-file sites admitted
into the product posture.

### 7.2 Reconciliation — three counts, and which one this dossier measured

The carrier orders the difference stated rather than smoothed, so it is stated three ways:

| Claim | Source | Count | Status |
|---|---|---|---|
| **Nine** sites, two of them "this admin path" (9 − 2 = 7 outside) | `features/admin-key-short-lived-certs.md` scope guard | 9 | a **pin, not a measurement**; two of its nine are gone from the tree (7.3) |
| **Eight** live non-test sites, one in `server/ca.py` | lead re-derivation at `d0bfbb4`, carried in the RF-6 carrier | 8 | matches this dossier's count, not all its line numbers |
| **Eight** live non-test sites, one in `server/ca.py:815` | **this dossier, at `d8a5cda`** | **8** | the measurement this file publishes |

**This dossier measured 8, at `d8a5cda`, and the 7-outside-the-boundary destination is reached by the live count
(8 − 1 site in scope = 7), not by the pin's arithmetic (9 − 2 = 7).** Same destination, different route — exactly
the divergence the carrier ordered kept visible.

### 7.3 Why the pin's nine is not in the tree

| Pin's site | What happened |
|---|---|
| `ca.py:94` — the `_serialize_key_encrypted` plaintext branch | **removed by #537** (`e3a760d`, "a set passphrase now refuses to write an unencrypted CA key"). At `d8a5cda` the else-branch is `raise RuntimeError(_unencrypted_key_refusal(passphrase_env))` (`ca.py:148`); the function's own docstring says the plaintext branch is gone and nothing is written (`ca.py:136-139`) |
| `ca.py:747` / `:827` — the `sign_admin_cert` admin-key serialization | **still present, moved to `:815`** as `ca.py` shrank above it (the #539 accessor retirement, `d0d3d0d`) |
| `get_ca_key_pem` (`CAManager`) | **retired by #539** (`d0d3d0d`); it is pinned-gone by `packages/server/tests/test_ca_key_accessor_retired_539.py:33` |

The KEK design note (`docs/design-secure-memory-kek.md`, OPEN 3, merged at `d8a5cda`) still carries the older pin
set — `ca.py:94`, `ca.py:747`, `commands.py:2551 / :2947 / :3758 / :3978`, `daemon.py:565 / :745`. **All of those
line numbers are stale at `d8a5cda`** (the CLI sites moved to `:2573 / :2969 / :3780 / :4000`, the executor sites
`:565 → :594` and `:745 → :774`). That note states its own non-correction policy — it does not amend docs outside
itself — so this section is where the correction lands for the RF-6 series, and **RF-11 owns the note's OPEN 3
pins** (finding F-5).

**One more consumer of the same numbers, for the assembly pass:** §1.6 (chunk 1) published its table at
`d0d3d0d`, and six of its eight pins moved between that tip and `d8a5cda` — `commands.py:2551 → :2573`,
`:2947 → :2969`, `:3758 → :3780`, `:3978 → :4000` (carried by `bf1a462`, the #509 CLI change) and
`daemon.py:573 → :594`, `:753 → :774` (carried by `0cfe661`/`e16c26b`, the #479 executor change). The count (8),
the `ca.py:815` site, and `at_rest_key.py:87` did **not** move. §1.6 was correct when it was measured;
**7.1 is the table that is correct at this tip**, and chunk 3's assembly pass should reconcile §1.6 to 7.1 rather
than leave two pin sets in one file.

### 7.4 The test-file population

39 `NoEncryption()` hits live under `packages/*/tests/` (plus `conftest.py` and
`packages/executor/tests/helpers/cert_factory.py`). They are test fixtures building executor/admin keypairs for
assertions, not product delivery paths, and they are **not** in Q4a's scope or anyone's posture claim. They are
listed here so that a future lane running an unfiltered `grep -rn 'NoEncryption()' packages/` gets 47 hits and does
not conclude the audited count is 47, or start "fixing" fixtures. If a later change moves a product site into a
helper, the count in 7.1 — not this paragraph — is the one that has to be updated.

### 7.5 What Q4a does and does not cover (the boundary, stated for checkability)

**In scope — one site.** `ca.py:815`, inside `AdminCAManager.sign_admin_cert`: the **core-side admin key**, which
is the key the ruling `bydesign` speaks about ("leave admin.key unencrypted on the core", filesystem permission as
the control). §6 dispositions that function; the disposition does not re-open the ruling — under §6.3 the pair
stays core-side and stays `0600` (`install-venya-core.sh:426`), so the posture holds regardless of which
disposition is chosen.

**Out of scope — seven sites.** Everything else in 7.1. Two are worth naming because a reviewer may reach for the
wrong cover:

- **`commands.py:3780` (`cmd_admin_init_admin_ca`)** writes the **admin CA key**, not an admin key. The CA-key
  posture question is #537 (write half) / #541 (load half), already live: the server-side equivalent now refuses
  plaintext (`ca.py:148`) while this CLI branch still has a no-passphrase `else` that writes unencrypted. That
  asymmetry is **a real gap and it is not Q4a's to cover** — RF-6 records it for the CA cluster as finding F-6.
- **`commands.py:4000` (`cmd_admin_generate_admin_cert`)** writes an admin key, but **CLI-side**, in the
  `venya admin generate-admin-cert` offline path (§6.4). Ruling 4d scopes Q4a to the *core-side* admin key, so
  this site does not inherit the ruling. RF-10/RF-11 should treat the two admin-key paths together for operator
text, and must not extend the `bydesign` word to this call site without a new ruling.

**Test files** are out of scope by classification (7.4).

### 7.6 The boundary sentence, verbatim (mandatory statement 5)

> **The other sites are #537/#538 CA-cluster territory and must not be read as blanket-approved.**

Carried word-for-word from ruling 4d as the carrier requires. Its purpose is specific and it is the reason 7.1
exists as a table rather than a number: no future lane may cite the Q4a `bydesign` ruling as cover for any
`NoEncryption()` site other than the core-side admin key at `ca.py:815` as measured at `d8a5cda`. The checkable
form of the boundary is the enumerated list plus its ref: **re-run the 7.1 grep, and if the set differs from
eight sites with one at `server/ca.py`, this section is stale and must be re-measured before anyone quotes
it.**

Also carried forward from the input contract, unchanged and still binding: **Q4a SCOPE IS RULED 4d — core-side
admin key ONLY** (`features/admin-key-short-lived-certs.md`, "Rulings already made": *the core-side* `admin.key`
*stays unencrypted; filesystem permission is the control*). This section neither widens nor narrows it.

### 7.7 Inheritance — what later legs take from this section

- **RF-7:** nothing here is its code surface — the one in-scope site belongs to the function §6 dispositions, and
  RF-7 must not "fix" it as a drive-by; a CSR-path change leaves `ca.py:815` exactly as ruled.
- **RF-8:** its mint-adjacent text must not imply the CLI-side admin key site (`commands.py:4000`) is ruled
  (7.5); if RF-8 touches `init-admin-ca`/`generate-admin-cert`, the generated `docs/cli-reference.md` moves with
  it and the generator interlock applies (§4.1 lineage).
- **RF-9:** the executor-plane sites (2, 3, 7, 8) are the machine plane's own key handling — unchanged by this
  design, and outside Q4a (§3.2's machine plane does not become a Q4a claim). Relevant to §9's renewal story.
- **RF-10:** its installer edits must preserve the `0600` write behind the Q4a posture
  (`install-venya-core.sh:426`), and it owns the two installer-adjacent CLI paths 7.5 names.
- **RF-11:** publish **8, measured at `d8a5cda`** with the in-scope/out-of-scope split (1 + 7), never the
  remembered nine (the same rule §1.7 carried from chunk 1 now has its audited source); carry the boundary
  sentence in 7.6 into the docs where the posture question is discussed; and fix the KEK note's OPEN 3 pins
  (F-5) in the changeset that touches that doc.
- **CA cluster (#537 / #538 / #541):** F-6 — the `init-admin-ca` no-passphrase branch at `commands.py:3780` still
  writes an unencrypted **CA** key while the server-side path refuses since `e3a760d`. Filed here as a finding,
  not designed here: the envelope/CA-cluster legs own it, and RF-6 deliberately proposes no fix (4d boundary).

<!-- SECTIONS 8-10 FOLLOW. -->
