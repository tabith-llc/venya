# Design note: FIDO2 key-wrap for at-rest key material (#565 mechanism, note-only)

**Ticket:** GitLab issue #565 `unencrypted-key-delivery-open3-ruled-defect` — the live enumeration
of six `serialization.NoEncryption()` paths. **This note writes the MECHANISM design and nothing
else.** It implements nothing, edits no other file, and rules nothing. Posture was ruled by the
owner; mechanism is not ruled, and the two forks left open at the end are the owner's.

**Base this note was measured at:** `origin/dev` = `d5cb3e79a811e936c9dbd138fabcb2b7677983b7`
(re-derived by `git rev-parse origin/dev` in the venue, not copied from any dispatch).
**Branch:** `feature/design-fido2-keywrap-565`. **Lane:** flash5 (work6), seat s86.

**Citation law observed throughout:** product paths are cited by SYMBOL, line numbers appear only as
a snapshot of the base above (`docs/design-secure-memory-kek.md` OPEN 3 states the same rule, and
this lane watched that count rot once — see `5d810e6` landing one merge after its last refresh).

---

## 1. Rulings this note works under (quoted, not restated)

Verbatim owner words, read at the source named in the dispatch
(`wave15-specs-20261009/owner-rulings-s85.md`, the `#547/#565 — api_client.py password handling`
entry, and the #565 body):

- **"B — unencrypted key delivery is a defect that needs fixing."** (14:51:59, relayed in the #565 body)
- **"passphrase shall extend to the admin's private key."** (14:54:02, same source)
- the same #547/#565 entry, as recorded: **"Plaintext is NOT ALLOWED. Passwords are encrypted using
  the admin FIDO2 key."**

What those three do NOT decide, and this note does not pretend to decide:

- **which mechanism** (this note's §3–§5 are candidates with evidence, not a choice);
- **whether site 1 is in the fix set at all** (§7, the RF-6 4d conflict — presented, unresolved);
- the per-site env var / flag / prompt, and the wording of each refusal (#565 AC2 — the lead specs
  it, the owner vetoes it).

One standing rule applies to every candidate below, so it is stated once here instead of per-site:
**the absent-key failure mode is a refusal BEFORE any filesystem work** — no directory, no staged
temp, no half-written key — which is the #537/#547/#541 rule as #565 AC3 words it, and #565 AC4
names the alternative for what it is: "a silent fallback to plaintext when the passphrase is
missing is the defect returning, not the fix."

---

## 2. Two structural facts that bound every candidate

Measured, not assumed.

**(F1) The fleet has no authenticator to touch.** `venya-provision-ubuntu.sh` builds every VM with a
single `virt-install` call whose device list is `--disk` (x2), `--network`, `--os-variant`,
`--import`, `--noautoconsole`, `--graphics none`, `--boot hd,uefi` (at that base, the function
around `create_vm`; no `--hostdev`, no `--usb`, no redirdev). Grepping the provisioning source for
`hostdev|<usb|redirdev` returns nothing. So **no core or executor VM can run a CTAP ceremony at
all** — not "not today", physically not in the current device model. The Windows venue note
(`info/reference-win11-venue.md`, Hard laws 1 and the migration warning) records the other half: a
ceremony needs a **locally attached** authenticator and a provably interactive desktop
(`fido2/client/windows.py` — `self.handle = handle or user32.GetForegroundWindow()`, and over
SSH/WinRM that handle is `0`). Any candidate that needs a ceremony *on a core or an executor* is
therefore a candidate for a fleet that does not exist yet.

**(F2) No shipped read path can answer a passphrase.** Product `load_cert_chain` call sites, all
five (at the base above):

| site | symbol | passes a password? |
|---|---|---|
| `packages/cli/src/venya_cli/api_client.py` | `_build_ssl_context` → `ctx.load_cert_chain(certfile=…, keyfile=…)` | no |
| `packages/executor/src/executor/daemon.py` | `ExecutorDaemon._create_mtls_client` → `ssl_ctx.load_cert_chain(cert, key)` | no |
| `packages/executor/src/executor/relay_listener.py` | `RelayListener._build_ssl_context` → `context.load_cert_chain(cert, key)` | no |
| `packages/executor/src/executor/audit.py` | `AuditLogger._build_forward_ssl_context` → `ctx.load_cert_chain(certfile=…, keyfile=…)` | no |
| `packages/server/src/server/routes/executors.py` | `_build_relay_ssl_context` → `ssl_ctx.load_cert_chain(mtls_cert, mtls_key)` | no |

`grep -rn "\.load_cert_chain(.*password" packages/*/src --include='*.py'` returns **0 lines**, and
`_build_ssl_context` has no passphrase parameter to pass: its signature is
`(cafile: str | None, certfile: str | None, keyfile: str | None) -> ssl.SSLContext`. Two more
consumers of the same fact:

- `httpx2.Client(cert=(cert_path, key_path))` — used by
  `packages/executor/src/executor/daemon.py::CertificateManager._verify_cert_recognized`, the boot
  identity probe — routes to the library's `ctx.load_cert_chain(*cert)` (httpx2 `_config.py`), where
  **no password argument exists on that path**, so a passphrase-protected executor key cannot be
  presented through `cert=` even with a ceremony. The same call also emits a `DeprecationWarning`
  in this pinned httpx2, so a Part B that has to pass a passphrase will move it to a context anyway.
- `packages/executor/src/executor/daemon.py::_cert_key_pair_matches` loads the key with
  `password=None`; that is the boot-time pair gate, so an encrypted executor key would also fail
  the #480 presence check, not only the dial.

The upstream API supports what these calls omit: `ssl.SSLContext.load_cert_chain` takes
`password=None`, and "The `password` argument may be a function to call to get the password for
decrypting the private key. It will only be called if the private key is encrypted and a password
is necessary." (see FETCH-LOG, §9, source S3). That callable is where a ceremony would live — and
today nothing in the product has one. **This is the Part B gap**, pinned as cell N4 in
`packages/cli/tests/test_cli_admin_leaf_key_passphrase_547a.py`
(`TestThePartBGapIsVisible::test_n4_a_key_written_by_p1_is_not_loadable_by_the_current_mtls_path`),
and Part A's own success line says "Not yet usable for admin mTLS".

**Consequence carried through the rest of this note:** the six sites are not one problem. **One**
of them (site 2) runs where an operator with a security key is sitting. One (site 1) runs in the
installer on the core. Four (sites 3-6) run **on the executor host** — two of them from install
scripts and a daemon loop, with no human and, per F1, no device. §5 tabulates it; §6 states the
fallback shape where hardware coverage is physically impossible rather than faking coverage.

---

## 3. Mechanism candidates

### C-1 — PRF-extension-derived secret used as the KEK  *(strongest fit; two real blockers)*

**What the upstream says (S1, S2).** The WebAuthn `prf` extension "allows a Relying Party to
evaluate outputs from a pseudo-random function (PRF) associated with a credential", its PRFs map
inputs of any length to **32-byte** outputs, and the document's own worked example is that "PRF
outputs could be used as symmetric keys to encrypt user data." Underneath, CTAP2 `hmac-secret` is
"used by the platform to retrieve a symmetric secret from the authenticator when it needs to
encrypt or decrypt data using that symmetric secret", the secret is **scoped to a credential**
(the authenticator holds `CredRandomWithUV`/`CredRandomWithoutUV`, and returns
`HMAC-SHA-256(CredRandom, salt)`), and the authenticator "waits for user consent" and, if asked,
user verification before producing it. WebAuthn exposes only the UV-bound PRF and says it
"overrides the `UserVerificationRequirement` if necessary" — i.e. requesting `prf` **forces** a
verified ceremony, which is exactly the property wanted here.

**Shape if chosen.** A dedicated *keywrap credential*, separate from the login credential. At
enrol: register with `extensions: {prf: {eval: {first: <random 32-64 B>}}}`. At write: the
ceremony yields the 32-byte PRF output → it is the KEK → the private key is wrapped with it → the
wrapped blob lands at 0600 next to the certificate. At use: ceremony again → same output →
unwrap into a `SecretHolder` (the #538/#472 scoped read-only view, "erased on release, not
pinned"), never a plaintext file. What is stored on disk: the wrapped blob, the public salt(s),
and the keywrap credential id. What never leaves the hardware: the CredRandom. Loss of the key =
loss of the material, which is a **custody decision, not a bug** (§8 Q4).

**Why it is not free.**

1. **We do not ask for any extension today.** `packages/server/src/server/fido2/manager.py::Fido2Manager.start_registration`
   builds an options dict with `challenge`, `rp`, `user`, `pubKeyCredParams`, `timeout`,
   `excludeCredentials`, `attestation` — and no `extensions` key. `packages/cli/src/venya_cli/fido2_client.py`
   contains **zero** occurrences of `extensions`; `normalize_webauthn_options` copies the named
   fields it knows. So the credentials already enrolled on every fleet core have no PRF association
   and cannot be used for this; it is a new credential class plus server+CLI+DB plumbing (and an
   assertion that today verifies `rpIdHash`, UP, optional UV, signature and counter — it does not
   read extension output at all, `finish_authentication`).
2. **The library offers the surface but the fleet cannot reach it.** `fido2` 2.2.1 is the pinned
   version (`uv.lock` — `name = "fido2"`, `version = "2.2.1"`; declared `fido2>=2.0.0` in
   `packages/cli/pyproject.toml`), and `HmacSecretExtension` **is** in `_DEFAULT_EXTENSIONS`, so
   `prf` is available on the CTAP2 path — but only with a `pin_protocol` (the implementation
   performs a `ClientPin` key agreement, encrypts the salts to the shared secret, and requires a
   PIN/UV-auth param), and per F1 the only machines that could run it are the ones with no device
   attached. The Windows platform path also maps `prf` to the `hmac-secret` WebAuthN extension
   (`fido2/client/windows.py`), and that path is interactive-desktop-only.

**Fit worth noting, not a claim:** a PRF output is 32 bytes and the shipped KEK machinery already
wants exactly that — `packages/core/src/core/engine/encryption.py` defines `KEK_SIZE = 32`,
`derive_kek` (Argon2id, `ARGON2_HASH_LEN = 32`) and `wrap_key`/`unwrap_key` (AES-256-KW, 40-byte
envelope over a 32-byte DEK). A PRF output drops into `wrap_key` as the KEK with no new primitive.
That is a type-fit observation from shipped source; it is **not** evidence the owner wants C-1.

### C-2 — Ceremony-gated release of a passphrase; PKCS#8 stays the envelope  *(least new crypto)*

Keep `BestAvailableEncryption(passphrase)` — the scheme Part A already ships
(`packages/cli/src/venya_cli/commands.py::cmd_admin_generate_admin_cert`,
`::cmd_admin_cert_renew`) and the scheme the server CA path is built on
(`packages/server/src/server/ca.py::_serialize_key_encrypted`, which **raises** rather than write
plaintext when the passphrase is empty — the refusal-before-write rule, already implemented). The
FIDO2 ceremony does not wrap the key; it gates the *release* of the passphrase, delivered to
`load_cert_chain(password=<callable>)` at the five sites in §2(F2). Two sub-shapes, both needing a
ruling:

- **C-2a (local ceremony):** the ceremony happens on the workstation that holds the key; the
  passphrase is unsealed locally (the seal being a C-1-style wrap, or a Shamir shard — see the
  existing `packages/cli/src/venya_cli/shamir.py` and the CA-key backup/restore custody paths in
  `commands.py`). Hardware guards the secret; crypto is unchanged.
- **C-2b (server-gated ceremony):** the core releases the passphrase over an authenticated
  channel only after `finish_authentication` sees a verified assertion for the operator. No new
  crypto either, but the **core becomes the custody point for the key passphrase**, which sits
  badly against RF-6 ruling 3 — "The workstation generates the admin keypair; the server only
  signs the request. The private key never transits the server" (restated in
  `docs/design/rf6-shortcert-dossier-20261007.md` §1.2). Flagged, not adjudicated: the sentence is
  about the *private key*, and a passphrase is not the key, but a reader will hear it that way and
  only the owner can say whether the distinction holds.

**Why this matters more than C-1 for the four daemon sites:** C-2 keeps the envelope format the
product already writes, so it does not require a ceremony *inside* a daemon; it requires one where
a human already is, and the daemon reads its passphrase from the same place it reads
`VENYA_ADMIN_CA_KEY_PASSPHRASE` today (an `EnvironmentFile`, `install-venya-core.sh`, 0640
`root:venya`). That is the honest shape for unattended boot — but it is **not** hardware custody,
and calling it that would be a lie. See §6.

### C-3 — Challenge/response envelope (authenticator signs, wrapped key is released by a server)

**Rejected, with the reason on the record.** It moves plaintext key material across the network to
a daemon that needs it at boot, which contradicts the RF-6 ruling-3 boundary quoted above and buys
nothing over C-2b; and it makes availability of the key a function of reachability of the core,
which is already a live design worry on the authorization side (RF-6 §3.5, "DB reachability
becomes an AUTHORIZATION dependency"). Recorded so the next reader does not re-raise it.

### C-4 — Store the wrapped blob ON the authenticator (`credBlob` / `largeBlob`)

**Rejected for this ticket.** `credBlob` guarantees only "at least 32 bytes" of per-credential
storage (S2), which is smaller than a wrapped PKCS#8 admin key, and it is credential-scoped with
"Authenticator MUST support it for discoverable credentials"; `largeBlob` needs
`maxSerializedLargeBlobArray` ≥ 1024 bytes on supporting authenticators (S2) and the WebAuthn
document itself calls it useful only "in specific cases" because "authenticators can only store
small amounts of data" (S1). Both are authenticator-model-dependent — no YubiKey 5 / TrustKey T120
support measurement exists in this repo for either extension, so this would be reasoning from
memory (§8 Q5). Also: a wrapped key living only on the hardware is a self-immolating custody model
for a fleet credential. Rejected on evidence and on shape.

### C-5 — Out-of-scope alternative named for completeness: OS/TPM-sealed passphrase

An unattended daemon *can* unseal a passphrase from a TPM-backed keystore without any ceremony, and
that is the shape most fleet products reach for. It is **not** the owner's word ("Passwords are
encrypted using the admin FIDO2 key"), it is not implemented here, and it is not proposed here —
listed only because §6 needs to say what an unattended site's realistic custody options are, and
leaving this out would make the option set look smaller than it is.

---

## 4. Read path: where a ceremony would actually land (proposal, not ruling)

The candidate home is the RF-8c choke point, exactly as the dispatch framed it:
`packages/cli/src/venya_cli/api_client.py::APIClient._http` (the property) already does three
things in the right order — expiry guard (`admin_cert_expiry_refusal`), fingerprint of the material
about to be loaded (`_admin_cert_fingerprint`, sha256 of the **certificate** bytes, path pinned at
build time), and one `_build_ssl_context(...)` call that is the only place the CLI presents an
admin pair. The rebuild-on-fingerprint change is described in
`docs/design/rf6-shortcert-dossier-20261007.md` §4.3 ("fingerprint-triggered context rebuild at
the existing choke point", with the content-hash-not-mtime rationale).

**Proposed shape (owner's to accept or reject):** add a passphrase source to `_build_ssl_context`
and pass it as the `password=` **callable** documented in S3, invoked from `_http` at the same
point where the fingerprint is taken. The callable is the ceremony seam; it is called only if the
key is encrypted, which is precisely the property that makes C-2 composable with Part A's shipped
writes.

Two measured constraints on that proposal, stated because they are the part that gets missed:

- **The certificate-only boundary is real and would have to move.** `_admin_cert_fingerprint` reads
  the certificate and never the private key ("Reads the CERTIFICATE only — never the private key"),
  and the RF-8a dial guard is built on the same reading. A key that is now encrypted changes what
  a *ceremony-failure* refusal has to say, without changing what the fingerprint reads. Nothing
  here asks to widen the fingerprint to the key.
- **`load_cert_chain` copies the material at build time** (dossier §4.3: "`load_cert_chain` copies
  the chain into the OpenSSL context at build time, and the built client is cached … until
  `close()`. Rewriting the file under a live process changes nothing"), so a ceremony-gated read is
  a *context-rebuild* event, not a per-request event. A 60-minute admin leaf with an explicit-renew
  ruling (RF-6 4b, "Never an automatic ceremony mid-run") and a ceremony-gated passphrase collide
  on purpose: renew writes a new encrypted key → fingerprint differs → rebuild → **the rebuild now
  needs a ceremony inside a long-running script**. That is an owner question (§8 Q2), not a detail
  an implementer may smooth over.

The executor/server side has no choke point of that shape: `ExecutorDaemon._create_mtls_client`,
`RelayListener._build_ssl_context`, `AuditLogger._build_forward_ssl_context` and
`_build_relay_ssl_context` (`routes/executors.py`) each build their own at different times, and a
server-side `ssl.SSLContext` for a *listening* socket (`PROTOCOL_TLS_SERVER`, built once in
`RelayListener.start()` → `_build_ssl_context`) cannot re-ceremony per connection at all. Note also
that the executor's dial to the core uses a DIFFERENT builder, `CertificateManager._server_ssl_context`,
which loads no client certificate at all (anchors only) — it is not a passphrase consumer, so listing
it here would have been an error.

---

## 5. Per-site table — six sites, ceremony class, absent-key mode

Sites are named by symbol per the citation law. Write/read columns are **proposals under C-1/C-2**,
never claims of current behaviour; the "today" column is the measured fact.

| # | site (symbol) | today (measured) | write mechanism proposed | read mechanism | ceremony class | absent-key failure mode | platform constraint |
|---|---|---|---|---|---|---|---|
| 1 | `packages/server/src/server/ca.py::AdminCAManager.sign_admin_cert` | generates the keypair in-process and returns `key_pem` with `NoEncryption()`; caller today is the installer's bootstrap `python -c` block (`install-venya-core.sh`, the `sign_admin_cert` unpack), which writes `admin.crt`/`admin.key` at 0644/0600 | **BLOCKED ON §7** — if 4d survives, nothing changes; if B supersedes, wrap the returned PEM under a keywrap credential minted at install time | none in-process (the caller writes the file); the *consumer* is the workstation/`admin.key` reader | **write-time-only**, at install; runs in the installer as root on a VM with **no device** (F1) | refuse before any write (AC3) — but see §7: AC1 blocks site 1 alone | installer ceremony would have to be driven from the workstation and handed in, i.e. it is an *owner-presence* question, not a code question; #565 AC7 is already marked DO-NOT-RUN until an owner-present fleet session |
| 2 | `packages/cli/src/venya_cli/at_rest_key.py::unwrap_at_rest` | re-serializes the decrypted CA key to **plaintext PEM in memory** with `NoEncryption()` after opening the at-rest envelope with the server passphrase (`acquire_server_passphrase` — getpass primary, env override) | not a hardware-wrap site: the fix is to stop materializing plaintext — return the loaded key object, or keep the wrapped bytes and hand the `SecretHolder` a scoped view (#538's contract, rung 1 read-only view, zeroize on release) | already passphrase-gated; becomes ceremony-gated only if the passphrase itself is sealed (C-2a) | **needed-at-use**, interactive workstation — a human is running an export/custody command, so class **A** (admin) or **B** (auditor) per the owner's key vocabulary | already refuses loudly (`ValueError` when the envelope is encrypted and no passphrase was supplied) | none new: this is a CLI path on a machine with a desktop and a USB key. Interlocks to read before touching: the two cells in `packages/cli/tests/test_secret_holder_538.py::TestParityContract` and the source-scan symbols list in `packages/cli/tests/test_capability_isolation.py` |
| 3 | `packages/cli/src/venya_cli/commands.py::executor_register` | generates the executor keypair **on the executor host** and writes `executor.key` at 0600 (`NoEncryption()`), staged temp + `os.replace`, dirs at 0700, chowned to the service account (`_executor_service_ids`) | wrap under a **machine** keywrap credential (C-1) or a sealed passphrase (C-2) — both refuse-before-write with no dir and no temp when the ceremony is unavailable | the executor daemon at boot (see sites 5/6): **this is where hardware custody stops working**, because the reader is unattended | **write-time, but NOT interactive as shipped** — the command is `venya exec register`, and `install-venya-executor.sh` runs it on the executor itself (`…venya exec register --executor-id … --output-dir /etc/venya/executor`, token carried in `VENYA_EXECUTOR_ENROLLMENT_TOKEN`, never argv). The admin ceremony happens elsewhere and earlier: `venya admin executor-enroll` mints the token on an admin workstation. So no operator with a key is standing at the machine that writes this key | refuse before any filesystem work; the enrollment token stays unconsumed (the install guidance already says a failed attempt does NOT consume it) and the error names the re-mint command | **same venue problem as sites 5/6.** Register writes the key on a device-less VM. C-1 cannot close this site without either (i) minting the keywrap credential somewhere the operator can reach and shipping the wrapped result to the executor, or (ii) a device-bearing fleet (§6c) |
| 4 | `packages/cli/src/venya_cli/commands.py::executor_cert_renew` | same write shape as site 3 (`NoEncryption()`, 0600) for a renewed executor key — reached by `venya exec cert renew` (`executor_cert` dispatches `cert_command == "renew"`), run on the executor host | identical to site 3 — **sites 3, 4, 5 and 6 are one mechanism on one machine; this row is not duplicated to look exhaustive** | as site 3 | as site 3 | as site 3 | as site 3 |
| 5 | `packages/executor/src/executor/daemon.py::CertificateManager.register` | generates the keypair in the daemon, POSTs the CSR, writes `ca_cert`/`cert`/`key` via `_atomic_write` (0644/0644/0600) | **no FIDO2 ceremony is available** (F1, and the call site is `ExecutorDaemon` startup at `self.cert_manager.register(...)`, which reaches `CertificateManager.register`). Honest shape: passphrase envelope written under a passphrase the daemon is *given* — the installer's `EnvironmentFile` pattern the CA keys already use — or a machine credential unsealed from an OS keystore (C-5, off the owner's current word) | `_create_mtls_client`, `relay_listener._build_ssl_context`, `AuditLogger._build_forward_ssl_context`, `_build_relay_ssl_context`, **and** the module-level `_cert_key_pair_matches` (`password=None`) — five readers plus the boot pair gate, all passphrase-blind today (§2 F2) | **needed-at-use, unattended** — hardware cannot guard it as shipped | must refuse **without** burning server state: `rotate()`'s existing comment records that a doomed write after a POST "would burn server state and lose the freshly generated keypair every retry", and #480 made `register()` re-enroll on a mismatched pair. A ceremony-gated write that fails post-POST is the same class of bug | the real decision is **where the second factor for a machine credential is** (file permissions + `EnvironmentFile` today; hardware is physically absent) |
| 6 | `packages/executor/src/executor/daemon.py::CertificateManager.rotate` | same as site 5 from the daemon main loop (`needs_rotation()` → `rotate()`), staged-then-replaced in KEY→CERT→CA order so a kill leaves a detectable mismatch | as site 5 (identical mechanism) | as site 5 | **needed-at-use, unattended, periodic** — rotation happens on a timer with nobody there | as site 5, plus the pair gate | as site 5. This is the clearest of the six: a timer cannot touch a key |

**Class count that falls out of the table:** **one** of the six (site 2) runs on a machine where an
operator with a security key is actually sitting — it is a workstation CLI custody path. Site 1 runs
in the installer on the core; sites 3-6 run **on the executor host**, unattended, and that host has
no authenticator to touch (F1). So the honest headline is that a FIDO2 ceremony is physically absent
from five of the six write paths as the product is deployed, and the one that is reachable is the
one whose fix is probably not a wrap at all (§5, site 2).

---

## 6. Where a hardware key CANNOT guard the site, and the fallback shape

Stated plainly, per the dispatch instruction not to fake coverage.

**Unattended boot is not ceremony-compatible.** A daemon that must come up with no operator cannot
evaluate a PRF, cannot answer `password=<callable>` from a desktop prompt, and cannot touch a USB
authenticator it has no device for (F1). Any design that requires it produces one of two outcomes:
the service crash-loops until a human appears, or it falls back to plaintext — and the second is
the ruled defect, not a mitigation (#565 AC4). So for sites 3-6 the honest option set is:

- **(a) passphrase ceremony at write-time only** — the human who enrolls/renews supplies the
  passphrase, the daemon is handed it out-of-band (today that is an `EnvironmentFile` at 0640
  `root:venya`, the pattern `install-venya-core.sh` already uses for
  `VENYA_ADMIN_CA_KEY_PASSPHRASE`), and the *disk* copy is encrypted. The FIDO2 key protects the
  enrolment ceremony, not the running key. This is what Part A's shape already implies for the
  admin leaf key, and it is the minimum change that makes the shipped writes satisfy "plaintext is
  NOT ALLOWED" while a boot still succeeds. **It is not hardware custody and must not be sold as
  such** in commit text, docs or operator banner.
- **(b) machine credential sealed to the platform (C-5)** — a TPM/OS keystore, no ceremony, real
  at-rest encryption, but off the owner's word today. If the owner ever wants a machine-plane
  answer, this is the shape, and it should be a *separate ruling*, not a quiet implementation
  choice inside a #565 leg.
- **(c) a device-bearing fleet** — sites 5/6 become ceremony-guardable only if the VMs get a
  passthrough authenticator (F1's fix is a provisioning change, which is owner-ok-gated per
  Important Rule 1, and `info/reference-win11-venue.md` already records that a key is a physical
  object living on one host's bus). Until then, a design that needs it is describing a fleet that
  does not exist.

**And the read side has to be fixed in the same breath** whatever is chosen: today no reader can
answer a passphrase (§2 F2), so a write-side change alone leaves sites 1, 3, 4, 5, 6 producing
files that their own consumers cannot load. Part A already says this out loud ("Not yet usable for
admin mTLS", pinned by cell N4); the difference is that #565's remedy must not stop at saying it.

---

## 7. Site 1 — the ruling conflict. PRESENTED, NOT RESOLVED.

Site 1 is `AdminCAManager.sign_admin_cert`, and it is the RF-6 **Q4a** site. Two owner words point
in different directions and this note takes neither, exactly as #565 AC1 requires ("a leg must not
pick").

**The older word, carried by RF-6.** Ruling 4d — "Q4a scoped to the core-side admin key ONLY"
(`docs/design/rf6-shortcert-dossier-20261007.md` §1.2, Ruling 4) — and §1.2's closing caution:
"the other sites are #537/#538 CA-cluster territory and **must not be read as blanket-approved**".
The bydesign word itself, quoted in that dossier §6 (Ruled design, item 2) and again in §7.5:
*"leave admin.key unencrypted on the core"*, with filesystem permission as the control (the
installer's 0600 write). §7.5 is the checkable boundary statement — "In scope — one site … the
**core-side** admin key … **Out of scope — seven sites**" (at that base; the count is now six, per
the OPEN 3 refresh, which is itself the reminder to cite by symbol).

**The newer word.** #565's 14:51:59 "B — unencrypted key delivery is a defect that needs fixing",
plus 14:54:02 extending the passphrase requirement to the admin's own private key.

**Reading 1 — compatible as scoped.** 4d spoke about a key at **rest** on the core, controlled by
0600; B speaks about **delivery**. The dossier itself draws the line: "What was never acceptable is
the **delivery** of that key to a home directory, and that is item 4 below, not this line" (§6). On
this reading site 1 is *out* of the fix set (the core-side resting key keeps its ruled posture), and
what gets fixed is the installer's `scp`-to-home handoff (item 4 → RF-10) plus sites 2-6.

**Reading 2 — B supersedes 4d.** "Passwords are encrypted using the admin FIDO2 key" names the
admin key with no scope carve-out, and Part A's own commit message reads the passphrase rule as
extending to the admin's private key **everywhere it is written**. On this reading site 1 is *in*
the fix set, the bydesign word is dead, and the installer's bootstrap mint needs a custody answer
for a mint that happens on a device-less VM.

**Which is true decides the fix set, not the mechanism** — that is why it is Q1 in §8 and why #565
marks it AC1 with "BLOCKER for site 1 only; sites 2-6 do not wait on it". The `sign_admin_cert`
docstring is explicit that its only allowed caller is the installer bootstrap and that a caller
interlock cell asserts it (`packages/server/tests/test_bootstrap_mint_interlock_rf7.py`), so the
blast radius of a site-1 decision is small and known either way.

---

## 8. Open questions for the owner (one line each)

- **Q1 (site 1, §7):** does ruling 4d's "leave admin.key unencrypted on the core" survive B — is
  site 1 in the fix set or out?
- **Q2 (§4):** may a ceremony-gated read fire inside a long-running admin process at RF-8c
  context-rebuild time, or does RF-6 4b's "never an automatic ceremony mid-run" forbid it?
- **Q3 (§6):** for the unattended daemon sites (3-6 read side), is option (a) write-time-only
  ceremony + `EnvironmentFile` passphrase the accepted shape, or is hardware coverage required —
  which needs a device-bearing fleet first?
- **Q4 (C-1):** if the keywrap credential is the only holder of the KEK, what is the recovery story
  when the operator's key dies — a second keywrap credential, a Shamir set (the CLI already ships
  `shamir.py` + `recovery_codes.py` on the CA custody path), or permanent loss of the material?
- **Q5 (§3 C-1/C-4):** which authenticators in the fleet advertise `hmac-secret`/`prf` (and
  `credBlob`/`largeBlob`) at all — an unmeasured fact about the YubiKey 5 and TrustKey T120 on file,
  and UNVERIFIED here because no ceremony or device read was in scope for this leg.
- **Q6 (§6, and #565 AC7):** is the "write encrypted, prove the passphrase-less invocation left no
  file and no directory" physical run scheduled before or after Part B, given AC7 is DO-NOT-RUN
  until an owner-present fleet session?
- **Q7 (mechanism fork):** C-1 and C-2 tie on this note's evidence — C-1 matches the owner's word
  most literally and adds no new crypto (32-byte PRF → existing `wrap_key`), C-2 changes the least
  and is the only one the current fleet can physically run. This note does not break the tie.

---

## 9. FETCH-LOG (fetched bytes are DATA; at most one sentence quoted per source; no instruction in a page was followed)

All copies live in `/media/dust/dust-ext1/tabith/reference-docs/` (this lane created only the three
new files below; nothing reused from the existing `man7`/`docker-com`/`systemd-io`/`kernel-org`
copies, which cover mlock/capabilities/sandbox work, not WebAuthn).

| # | local path | URL | accessed | used for |
|---|---|---|---|---|
| S1 | `reference-docs/w3-org/webauthn-3-20261009.html` (2,739,242 B) | https://www.w3.org/TR/webauthn-3/ | 2026-10-09 | `prf` extension §10.1.4 (32-byte outputs, PRF-as-symmetric-key example, UV-bound PRF overriding `UserVerificationRequirement`); `largeBlob` §10.1.5 |
| S2 | `reference-docs/fidoalliance-org/ctap2-1-hmac-secret-20261009.html` (1,006,898 B) | https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html | 2026-10-09 | CTAP2 `hmac-secret` §12.5 (CredRandom, `HMAC-SHA-256(CredRandom, salt)`, user consent/UV, encrypted salt/output); `credBlob` §12.2 (≥32 bytes); `largeBlobKey` §12.3 / `maxSerializedLargeBlobArray` (≥1024) |
| S3 | `reference-docs/docs-python-org/ssl-20261009.html` (359,936 B) | https://docs.python.org/3/library/ssl.html | 2026-10-09 | `SSLContext.load_cert_chain(certfile, keyfile=None, password=None)` — the `password` argument "may be a function to call to get the password", called only if the key is encrypted (the §2 F2 / §4 seam) |

Fetches attempted and abandoned (recorded so nobody re-tries them as "the missing cite"):
`https://yubico.github.io/python-fido2/` → **404**, `https://fido2.readthedocs.io/en/stable/` →
**404**, `https://raw.githubusercontent.com/Yubico/python-fido2/{main,master}/README.md` → **404**,
`https://learn.microsoft.com/.../WebAuthNAuthenticatorMakeCredential` → **fetched**
(`reference-docs/learn-ms/webauthn-make-credential-20261009.html`) but **not used** — the page's
own text says "Access to this page requires authorization", and it carries the API shape the
installed library already gives me verbatim. **Nothing in this note loses a claim because of those
failures**: every library statement here is cited to the installed copy under the venue's
`.venv/lib/python3.14/site-packages/fido2/` at the pinned version (2.2.1), not to a docs site.

**UNVERIFIED list (kept, not smoothed):** per-authenticator extension support (Q5); whether the
live fleet's enrolled credentials could ever yield a PRF output without re-enrolment (stated as
"no, given the options dict carries no extensions key" — that is measured, the *conclusion* that a
re-enrolment is required is design inference, not measurement); anything about customer hardware.

---

## 10. Scope statement for the intake read

One new file. Zero product code, zero test edits, zero other docs, zero ticket mutations (anna owns
those), zero installer edits — §11 text below is PROPOSE-ONLY and the installer rule plus #565 AC8
both put it behind an owner ok that this leg did not ask for. No VM, no SSH, no sudo, no boot, no
ceremony, no device read. No credential-shaped text anywhere in this note: no example passphrase, no
key byte, no token literal — mechanisms and env-var NAMES only, which is also why `VENYACA1` appears
as a format name and never as content.

## 11. Proposed operator text for #565 AC5 coupling (PROPOSAL ONLY — do not apply)

Part A made the write side correct and the documented read side unusable, so two shipped operator
documents now describe a broken procedure: `install-venya-core.sh` (the "Copy these to your
workstation" banner with its two `scp` lines for `admin.crt`/`admin.key`) and
`docs/installation.md` (the headless admin pattern
`VENYA_ADMIN_CERT=… VENYA_ADMIN_KEY=…`, in both the CLI-shape and the enroll-examples blocks), and
`docs/installation.md` also tells the operator to keep `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY` "from
the current core install". Propose, in the changeset that ships an encrypted admin key — not before,
because this text is only true once a passphrase exists on the other side of the file:

```
# install-venya-core.sh banner — proposed replacement for the scp pair
# (installer edit is owner-ok-gated separately; AC8. Do not apply in this leg.)
  The admin key at $ADMIN_CERT_DIR/admin.key is now ENCRYPTED at rest with the
  admin-CA passphrase held in /etc/venya/venya-core.env (0640 root:venya).
  Copying it to a workstation does NOT make it usable yet: the CLI cannot yet
  answer a passphrase when it loads an admin key for mTLS (Part B). Until Part
  B lands, use the session path — `venya login <user-id>` then the elevation
  ceremony — instead of a handed-over admin pair.

# docs/installation.md headless pattern — proposed status line to add under it
  Heads up: an admin key written by the current installer is encrypted at rest,
  and the headless `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY` pair below does not load
  through it yet — the CLI has no passphrase path for that key. This is Part B
  (#565); until it lands the pattern works only for an unencrypted key, which is
  the posture this ticket rules out. Part A's own success line says the same
  thing: "Not yet usable for admin mTLS".
```

Both blocks keep Part A's discipline: they state the gap where the operator will hit it, they carry
no severity language, and they do not quietly delete the workflow they invalidate — the RF-6 §6 item
4 disposition (the human handoff retires in the installer, not in `packages/`) is RF-10's, and this
note does not pre-empt it.
