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

<!-- SECTIONS 2-5 FOLLOW IN THIS CHUNK; 6-10 ARE A LATER DISPATCH. -->
