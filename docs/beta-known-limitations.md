# Beta known limitations

**Applies to:** `v0.1.0beta*` releases of Venya.
**Provenance:** every entry below names the tracked issue it comes from, and each was
read against the shipped source at the anchor noted at the foot of this file. Nothing here
is a summary of intent — if a limitation stops being true, the entry comes out. One entry
names no row, and says so in the entry itself: the root-CA expiry limit has no tracked issue
yet, so it is disclosed here rather than pointed at a number that does not exist.

This is an accuracy document, not a marketing one. It says what works, what does not yet,
and what you have to do about it. Where a limitation is being fixed, the entry says so;
where a fix has landed, the entry is deleted rather than softened.

**What this list is not.** It does not hold defects that were meant to land, and it does not
hold documentation that says something the product does not do — a wrong instruction is a
document bug and gets corrected, not disclosed here. Two things that are settled elsewhere
and only pointed at:

- **The re-run contract** (what a version-changing installer re-run guarantees to preserve,
  and where it refuses) lives in [UPGRADE.md](UPGRADE.md) and
  [installation.md](installation.md) §1–§2. This file does not restate it, so there is only
  one place that contract is written.
- **Certificate handling and rotation procedure** lives in
  [cert-rotation-runbook.md](cert-rotation-runbook.md). Entries below that touch a
  credential name the symptom an operator sees, not the ceremony.

---

## Revocation

### The relay checks revocation on the core's dial; the executor's listener refuses a revoked peer from the registry and the revocation list, and consults no CRL at all

Status: known limitation in beta · Target: no date set · Tracked as: #676 (open, HIGH — this entry
is its documented half; the row names the narrow gap: the listener door has now been seen refusing a
revoked peer on a served fleet, and the core's own dial-side refusal never has — that is the residue),
discharging the physical half of #597 AC6(b), and #586
(open on its **physical** half only — the dial landed, and the listener door now names a revoked
peer in BOTH populations: the core-relay registry via #597 and the executor-serial list via Gap A
at `c7a4075`. Both listener populations have now been refused on a served fleet: the executor-serial
arm twice, and the core-relay registry arm once. What has never been seen refused is the core's dial,
and this entry does not claim it was)

**What is enforced today.** One door: the DIAL, which is the core connecting OUT to an
executor. The relay context is built by `_build_relay_ssl_context`
(`packages/server/src/server/routes/executors.py:628`) and, since `54457a6`, that builder
consults a certificate revocation list at the TLS handshake —
`ssl_ctx.load_verify_locations(capath=crl_capath)` then
`ssl_ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF`
(`packages/server/src/server/routes/executors.py:675-676`). The list is minted fresh for
every dial by `_ensure_dial_crl_store` (`.../executors.py:702`), which the relay path calls
at `.../executors.py:1979`, and the context carrying it is built at
`.../executors.py:1994`. In operator language: when the core is about to send a command to
an executor, it will not complete that handshake against a credential the list says is
revoked, and it will not complete it against a list it cannot refresh either. The three
answers are distinct and deliberately named apart — a revoked leaf is refused with 403 and
says so (`.../executors.py:789`); a stale or unavailable list is refused with 503 whose text
says **"no revocation asserted"** (`.../executors.py:699`) and never claims a revocation that
did not happen; a missing CA anchor keeps the pre-existing TLS-misconfiguration wording
(`.../executors.py:1987`, and the same wording again at `:1997` for a context that cannot be
built) rather than being relabelled as a revocation event.

**What is NOT enforced.** The other door — the LISTENER, the executor's `:8443` side that
ACCEPTS a connection — does no **list** consultation at all. Its TLS context is built by
`RelayListener._build_ssl_context`
(`packages/executor/src/executor/relay_listener.py:505`) and sets the TLS floor, the
executor's own leaf, the CA anchor and `verify_mode = ssl.CERT_REQUIRED`
(`packages/executor/src/executor/relay_listener.py:509-520`). There is **no CRL load and no
`VERIFY_CRL` flag anywhere in the executor's shipped source** — re-derivable with
`git grep -i crl -- packages/executor/src`, which returns nothing at this tip, and
`git grep VERIFY_CRL -- packages/`, whose only hits in the product are the dial line above and
the unit cell that asserts it. Its published re-derivation command is deliberately a call shape and
not the bare word — `git grep -n 'VERIFY_CRL_CHECK' -- packages/executor/src` and
`git grep -n 'load_verify_locations(capath' -- packages/executor/src` both return **nothing** at this
tip, while `git grep -i crl -- packages/executor/src` now returns the #586 Gap A docstring that
*disclaims* the flag, so a seat re-deriving with the loose pattern must read the hit, not count it.
The two relay surfaces are also **not symmetric in any verify
flag**: the file sets no `verify_flags` line at all, so it lacks the
`VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` the dial sets deliberately
(`packages/server/src/server/routes/executors.py:663`). Chain handling differs between the two
doors, not just list handling. **Since #597 and #586 Gap A this door is not blind — it refuses a
revoked core-relay peer by registry match and a revoked executor-class peer by revocation-list match,
both after the handshake and before any request byte: `peer_revocation_refusal` and
`peer_executor_revocation_refusal`, `packages/executor/src/executor/relay_listener.py`.**

What the listener DOES have is a post-handshake accept gate
(`revocation_accept_reason`, `packages/executor/src/executor/relay_listener.py:311`, fired at
`packages/executor/src/executor/relay_listener.py:387`). Read it precisely, because it is not
a peer check: it consults the ONE answer this daemon holds about **itself** —
`DaemonState.revoked` and `revocation_answered`
(`DaemonState.__init__`, `packages/executor/src/executor/daemon.py:249`,
`packages/executor/src/executor/daemon.py:255`)
as written by `ExecutorDaemon._main_loop` (`packages/executor/src/executor/daemon.py:2122`,
`packages/executor/src/executor/daemon.py:2134`, and the consecutive-failure cutoff at
`packages/executor/src/executor/daemon.py:2148`). So it refuses every new connection when THIS
executor has been revoked or has received no revocation answer since boot; it holds no copy of
any list and does no serial or identity matching of the peer in front of it **at this gate** — and its own
contract comment says why — at `:8443` the peer is the core's relay-client credential, which
the executor-serial list never describes
(`packages/executor/src/executor/relay_listener.py:319`). **TWO further gates now sit beside this one
and do match the peer** — `peer_revocation_refusal` (the #597 registry population) and
`peer_executor_revocation_refusal` (#586 Gap A, the executor-serial population),
`packages/executor/src/executor/relay_listener.py` — both reading the ONE serial already taken off the
established connection; the reason this paragraph still says "at this gate" is that it describes the
self-only arm, which is exactly what it is.

The shape of the exposure, stated plainly: **a credential the CA has revoked can still
complete a TLS handshake at an executor listener.** Nothing on that side asks the list. What
stops such a peer today is the CN allowlist — `relay_client_ids`, compared in
`ExecuteHandler.do_POST` (`packages/executor/src/executor/relay_listener.py:116`) — which is an
IDENTITY test, not a revocation test, and is answered after the handshake has already
succeeded.

And the stronger thing, which the page has to say rather than imply: **at this surface the listener
can name a revoked peer today, from two populations and from no CRL at all.** The service CA that signs the core's
relay-client credential
(`-CA /var/lib/venya/ca/ca.crt`, `install-venya-core.sh:1020`) is the same CA that signs executor
leaves (`CAManager.ca_cert_path`, `packages/server/src/server/ca.py:394`, leaf mint at
`packages/server/src/server/ca.py:621`), and the CRL that CA mints is populated from
`ExecutorCertRevocation` alone (`CAManager.generate_crl`,
`packages/server/src/server/ca.py:715`, query at `packages/server/src/server/ca.py:749`; the model
is titled "Revoked executor certificate serial numbers",
`packages/core/src/core/iam/models.py:380`). The consequence for a **core relay** credential is that
this list can never name it — and that is no longer a hole in the door, because #597 gave that class
its own registry (`CoreRelayCredential`, `packages/core/src/core/iam/models.py:665`) and the door
matches against it (`peer_revocation_refusal`). For an **executor-class** peer the list already named
the serial; what was missing was anyone at `:8443` asking, and #586 Gap A added that ask
(`peer_executor_revocation_refusal`, fed by `revoked_executor_serials` on the daemon state, carried on
the same poll branch that answers the executor's own revocation question). **So a
`VERIFY_CRL_CHECK_LEAF` bolted onto the listener would still enforce nothing new** — a green test
could be written for the flag and the refusals it claims to add are already made, by a route that
does not need a distribution point the default install never advertises. The honest residue here is
not a missing mechanism but a missing **observation**, and the missing observation sits at ONE door,
not two. A physical revoke-then-refuse **has** now been observed on a served fleet at the **listener
door**, in both of its populations: the executor-serial arm refused twice, with the journal line
captured and the paired negatives counted (an admitted credential still transacted; the self-arm and
cooperation arms read zero; the listener stayed up), and the core-relay registry arm refused once,
where the durable record is an audit row naming registry membership as the reason rather than a
journal line, and the paired same-tick probe shows a non-revoked sibling leaf admitted while the
revoked one is refused with no application byte back. Propagation at that door was measured across
the poll interval the daemon already runs.

**What has never been observed is the refusal at the core's dial.** The code is real —
`_build_relay_ssl_context` sets `VERIFY_CRL_CHECK_LEAF` on the peer leaf and
`_ensure_dial_crl_store` mints the list per dial, and the refusal sentence exists — and a served
core does carry live revocations, so nothing is missing in order to revoke something. What is
missing is a run that saw that door refuse, and on the present fixture no reachable trigger produces
one: the dial target is taken from the enrolled `executor_url`, so a stand-in listener cannot be
dialed. This entry names that half as unobserved and does not claim the dial was ever seen refusing.

**Who is affected in the shipped posture.** Reachability, not theory. The listener binds
`:8443` (`RELAY_PORT`, `packages/executor/src/executor/relay_listener.py:46`) on the executor
and takes connections from the core network (default `host="0.0.0.0"` in `RelayListener.__init__`,
`packages/executor/src/executor/relay_listener.py:462`, and the inbound `8443/tcp` rule for an
executor in [FIREWALL.md](FIREWALL.md):50). The peer that presents at that door is the
core's relay-client credential, signed by the core installer with a **365-day** validity
(`-days 365`, `install-venya-core.sh:1022`), CN `${CORE_HOSTNAME}-relay`
(`install-venya-core.sh:1013`). So: any core host that still holds a relay-client certificate
that was once signed by your CA, and whose CN is still in the executor's `relay_client_ids`,
completes the handshake at that executor. **Retiring the machine is no longer silently ignored —
since #597 a revoked serial of that credential is refused at the accept point — but the handshake
itself still succeeds, and a credential that was never ingested (a core not booted since the
migration) stays unrevocable and completes it exactly as before.** Executor leaves are dual-purpose,
`SERVER_AUTH` and `CLIENT_AUTH`
(`packages/server/src/server/ca.py:51`), so an executor credential is also a credential that
can present as a client.

**One boundary is settled and is not on the plan: work already in flight is NOT terminated by a
revocation.** That is the owner's ruling, recorded in the shipped source
(`packages/server/src/server/routes/executors.py:705-710` and the scope note at
`packages/server/src/server/routes/executors.py:1975-1977`); fail-closed on a stale list applies
at the dial, and killing live sessions is ruled AGAINST, not deferred. The accept point already
matches that boundary: a refusal happens after the handshake and before any request byte
(`packages/executor/src/executor/relay_listener.py:387-409`), and the RF-3 admission permit is
taken later, inside the handler — so a refusal at accept can only ever deny new work.

**The proof that is half-run.** The physical revoke-then-refuse has now been executed on a served
fleet at the **listener door**, in both populations — the executor-serial arm twice, with the refusal
journalled by name and zero application bytes back, and the core-relay registry arm once, recorded by
audit row and by the same-tick admitted/refused pair — and it has **never been executed at the core's
dial**.
What exists in the tree beside those runs is unit-level: the dial
half is pinned by `packages/server/tests/test_relay_dial_crl_586.py`, which mints a real CA,
real leaves, a real CRL and a real loopback handshake but runs **no venya daemon on either
side** (its own module docstring, `packages/server/tests/test_relay_dial_crl_586.py:21-24`);
the listener accept gate is pinned by
`packages/executor/tests/test_relay_revocation_gate_586.py`. A unit that refuses a leaf in a
loopback handshake is not a revocation feature proved on a customer deployment. **The merged dial half must not be read as "revocation works at the handshake"** — it is one of two
doors, and the door whose physical refusal has never been observed is that same dial, so the unrun
proof is not covered by any run that was. **What the listener door does have now is a registry
match, not a list consult: `peer_revocation_refusal`
(`packages/executor/src/executor/relay_listener.py`) refuses a revoked core-relay serial after the
handshake and before any request byte, and that refusal has now been observed on a served fleet.**

**Plan — what is NOT planned.** This entry does not promise a listener CRL consult, and a reader
should not read one into it. What the row is still open on is no longer a mechanism: the dial landed,
the #597 registry match landed, and the executor-serial peer ask (#586 Gap A) landed at `c7a4075`, so
the two-door remedy this row describes is **built in both populations**. **What remains is the
physical certificate** — a revoke-then-refuse seen at the **core's dial** on a served pair. Both
listener arms have now been produced (the executor-serial arm twice, the core-relay registry arm once),
and that half of this sentence used to name the registry arm as the missing one. The dial half is not
produced because no non-terminal trigger is reachable on a served pair, not because a revocation could
not be made. Unit-green is necessary and not
sufficient, and #586 stays open past beta on that half, not on a missing consult.

One alternative exists and is **the owner's call, not this page's plan, and not a scheduled
item**: build the transport consult anyway. It would buy the wording "a CRL is consulted at every
relay handshake" while delivering, as its only real effect, a **stop clock** — a list lapse makes
the listener refuse new connections. The clock is an hour, not an abstraction: the minted list
carries `next_update = now + 1 hour` (`packages/server/src/server/ca.py:758`, and the same stamp
on the admin sibling at `packages/server/src/server/ca.py:1465`), while the listener's published
context is rebuilt only by `RelayListener.reload_ssl_context`
(`packages/executor/src/executor/relay_listener.py:582`) whose one production caller is the
daemon's rotation arm (`packages/executor/src/executor/daemon.py:2103`) — a 30-day cadence
(`EXECUTOR_VALIDITY_DAYS = 30`, `packages/server/src/server/ca.py:46`). A list baked in at boot is
therefore certain to lapse inside an hour, and under the ruled fail-closed posture a lapsed list
means the executor refusing every new relay connection. That is a fleet-wide availability trade,
it is the owner's to make, and it is named here as his rather than as a task.

**What is enforced at that door today, because it is enforceable without #597.** Two things, and
the page should not let the peer-revocation gap hide them. First, the core's own application gate
refuses a revoked EXECUTOR serial per request, on the inbound plane, in
`_validate_executor_mtls` → `executor_revocation_state` with the presented serial
(`packages/server/src/server/middleware/auth.py:748`, lookup at
`packages/server/src/server/middleware/auth.py:863`). Second, the executor daemon stops
cooperatively on a bounded outage rather than serving on an unanswered question —
`max_revocation_failures`, default 3
(`packages/executor/src/executor/config.py`, `CertificateRotationConfig.max_revocation_failures`), fed at
`packages/executor/src/executor/daemon.py:2148`. The first of those is an application-plane gate on
the core's inbound side, not a peer refusal at `:8443`, and the second is a cooperative stop; neither
is claimed as peer revocation here. **They are the controls that were load-bearing while the peer arms
were being built, and they still are — the door's own refusals now sit beside them, not instead of
them.**

**What an operator can do now.** Four things are in the shipped product, and one common
assumption is not:

- **Remove the identity, not the credential.** `relay_client_ids` is the executor's allow-list
  of core client CNs (`ExecutorConfig.relay_client_ids`,
  `packages/executor/src/executor/config.py:416`); drop a retired core's CN
  and `ExecuteHandler.do_POST` refuses it with 403
  (`packages/executor/src/executor/relay_listener.py:116`). It fails closed when the
  list is empty — the listener does not bind at all
  (`packages/executor/src/executor/relay_listener.py:524-529`, and the same guard in
  `ExecutorDaemon.start` at `packages/executor/src/executor/daemon.py:1899`). Caveat that
  matters: the executor installer
  **rewrites** this key on every run (`relay_client_ids = ["${CORE_HOSTNAME}-relay"]`,
  `install-venya-executor.sh:558`), so a hand-edit there is not durable across a re-run — the
  rewrite is documented in its own entry below (#598).
- **Re-mint the core's relay pair, and know what that does NOT do.** A completing run of
  `install-venya-core.sh` regenerates the relay key and re-signs the credential with no
  existence guard on the files (`openssl ecparam -genkey ... relay-client.key`,
  `install-venya-core.sh:1005`, then the sign at `install-venya-core.sh:1022`), while the run
  preserves the certificate authority — the same re-run behaviour named in the `#588` entry
  below. So a re-run rotates what the core presents. **Since #597 the previous credential is not
  invisible either — it is in `core_relay_credentials` and is revocable by serial**
  (`venya admin core-relay-cert revoke`), so the old pair no longer has to age out: revoke its serial
  and the executor's door refuses it. What a re-run still does not do is revoke it **for** you — the
  old row stays live until an operator revokes it, and a copy of the old pair keeps completing the
  handshake until either that revoke lands or the credential expires at its 365th day.
- **Contain reachability**, per [FIREWALL.md](FIREWALL.md):50 — inbound `8443/tcp` on an
  executor restricted to your core host(s).
- **Retire everything derived from the CA** by rotating the certificate authority —
  [cert-rotation-runbook.md](cert-rotation-runbook.md), whose custody path
  (`venya admin split-ca-key`, `packages/cli/src/venya_cli/cli.py:381`) is the break-glass
  half. This is the heavy, fleet-wide answer, not the routine one.

**A revoked core relay-client credential is refused at this door, and do not read short-lived
certificates as the mechanism.** The 30-day short lifetime that exists is the
EXECUTOR leaf (`EXECUTOR_VALIDITY_DAYS = 30`, `packages/server/src/server/ca.py:46`); the
core relay-client credential is minted at 365 days (`install-venya-core.sh:1022`). **This bullet used to
say the opposite — that no revoked serial of this class existed and that the cell proving a refusal
could not be written against today's product. Both halves became false at `1033c2d`:** the serial is
nameable now, the door refuses it, and the cell is written
(`test_revoked_peer_is_refused_at_the_real_door_before_any_request`,
`packages/executor/tests/test_relay_peer_revocation_597.py`). What remains un-run is the **physical**
certificate **at the core's dial**: the served-fleet revoke-then-refuse at the **listener door** has now
been produced in BOTH populations (the executor-serial arm twice, the core-relay registry arm once), so
the missing observation is the dial-side refusal, and on the present fixture no reachable non-terminal
trigger produces one — see the #597 entry for the three shapes that are
still limited. #586's acceptance criterion 1 depends on that
physical proof, not on the registry.

### A core's own relay credential is revocable — the entry this page carried said it was not, and that is corrected here

Status: **no longer a limitation on the revocation path** · Remedy landed at `1033c2d` (live face
`1033c2d006e170817cabc100b49a909ad35c7eb5`) · Tracked as: #597 (row **stays open**, and honestly so —
its remaining physical observation is the revoke-then-refuse seen at the **core's dial** on a served
pair; the physical revoke-then-refuse at the **listener door** has now been produced on a served
fleet, in both populations, and this entry does not claim the dial half was seen; that is a different
obligation from the one this entry disclosed)

**Why this entry is here instead of deleted.** The page's rule is that an entry comes **out** when its
fix lands. The fix landed, so the old entry — *"A core's own relay credential cannot be revoked"* —
is gone. What replaces it is not a softening of that claim but the record that the claim became false,
plus the three shapes that are genuinely still limited (below). A design partner who read the earlier
edition was told something the product does not do; that is a document bug, and this page's own rule
is that a document contradicting the product is corrected in the document.

**What the old entry asserted, and what is true now.** It said the credential has "no row for it in any
table", that "there is no command, endpoint or runbook step that can revoke it", and that retiring a
core's relay credential "does not" work. All three are false at this tip:

- **a row exists** — `CoreRelayCredential`, table `core_relay_credentials`
  (`packages/core/src/core/iam/models.py`), created by the Alembic migration
  `040_core_relay_credential_registry` (`packages/core/alembic/versions`), written at core startup by
  `ingest_relay_credential` (`packages/server/src/server/relay_registry.py`, called from `app.py`) so
  the invariant is "exists on disk ⇒ exists here", held by the process that uses the credential.
- **a command and an endpoint exist** — `venya admin core-relay-cert` with `list`, `register` and
  `revoke` (`packages/cli/src/venya_cli/cli.py`), served by `admin_revoke_core_relay_cert`
  (`packages/server/src/server/routes/core_relay_certs.py`).
- **a runbook step exists** — `venya admin core-relay-cert revoke --serial <hex-serial>` and the
  `--cert-file` form, in docs/cert-rotation-runbook.md.
- **the door refuses a revoked peer** — `peer_revocation_refusal`
  (`packages/executor/src/executor/relay_listener.py`) matches the serial the peer actually presented
  against `revoked_relay_serials` on the daemon state (`packages/executor/src/executor/daemon.py`),
  carried on the same poll that answers the executor's own revocation question, and the refusal lands
  after the handshake and **before any request byte**.

**What is still limited — three shapes, and this is the live disclosure.** The peer door is keyed on
**registry membership and nothing else**, by ruling, so:

1. **a credential the registry never ingested cannot be revoked.** The row is written at boot, not by
   the mint step. Boot the core once after the migration before trying to retire a relay credential.
   The verb refuses an unregistered serial by name (`REFUSE_UNREGISTERED`,
   `packages/server/src/server/routes/core_relay_certs.py`) rather than recording a revocation that
   would name nothing — the operator sees a refusal instead of a false success, which is the right
   failure and still a failure.
2. **an empty peer population admits.** No revoked relay serial means the door lets the connection
   through, deliberately: refusing on "nothing to match" would stop every healthy executor. The door
   can only ever remove a connection the registry has already named dead.
3. **an unreadable peer serial admits.** Where the listener cannot read a serial off the established
   connection the refusal returns None. That is the one true fail-open on this surface; turning it
   into a refusal would lock out cores whose certificates this host cannot parse. **The same three
   shapes apply unchanged to the executor-population arm added at `c7a4075`
   (`peer_executor_revocation_refusal`) — it is deliberately the same discipline, not a second
   policy: an empty population admits and an unreadable serial admits, so the arm can only ever
   remove a connection the list has already named dead.**

**And the short-lifetime assumption is still wrong, in the opposite direction from before.** The 30-day
lifetime is the EXECUTOR leaf (`EXECUTOR_VALIDITY_DAYS = 30`,
`packages/server/src/server/ca.py`); the core relay-client credential is still minted at **365 days**
(`install-venya-core.sh`, the `-CAcreateserial -out "$RELAY_DIR/relay-client.crt" -days 365` line). So
expiry is not the mechanism here — revocation is, and it now works.

**What is NOT claimed.** No CRL is consulted at `:8443`, and none is promised; the executor package
carries no `VERIFY_CRL` flag at all — re-derive with the call shapes
(`git grep -n 'VERIFY_CRL_CHECK' -- packages/executor/src` and
`git grep -n 'load_verify_locations(capath' -- packages/executor/src`), both of which return nothing
at this tip. Do **not** re-derive with the bare word: `git grep -i crl -- packages/executor/src` now
returns the #586 Gap A docstring, which names the flag in order to **disclaim** it — a seat counting
that hit would read a shipped CRL consult where there is none. The freshness of this door is the
~30-second poll, not a handshake-time fetch. And a **physical** revoke-then-refuse **has** now been
observed on a served fleet **at the listener door** — in both populations, the executor-serial arm twice
and the core-relay registry arm once — while the refusal at the **core's dial** has never been observed,
because no non-terminal trigger is reachable on a served pair. What sits beside those runs in the tree
is unit-level
(`packages/executor/tests/test_relay_peer_revocation_597.py` for the relay population and
`packages/executor/tests/test_relay_peer_executor_serial_586.py` for the executor population, each
driving a real loopback handshake at the accept point but running no daemon). Unit-green is not a
fleet result, and the fleet result this surface now has covers the listener only — that is why this row
and #586 both stay open.

**Workaround for the never-ingested shape:** boot the core once after the migration before trying to
retire a relay credential, so the ingest has a chance to write the row. If the serial you hold is
refused as unregistered, contain the host and the network, or rotate the certificate authority, which
retires every derived credential including this one.

### A copied administrator credential stays usable until it expires — up to one hour — while revocation itself lands within about a minute

Status: known limitation in beta · Target: no date set · Tracked as: #586 (open — that row owns
only the list-freshness sentences below; the one-hour credential window is a ruled design
property of the short-lived-admin-cert program (RF-7), and there is deliberately **no defect
row for it** — it is the commitment beta makes, not a bug beta has)

**First, plainly: revocation works today.** An operator who revokes an administrator certificate
or an executor credential sees it take effect through the shipped poll-and-heartbeat mechanism —
this entry is about the one window the product keeps open on purpose, and how fast everything
else lands, not about a capability that is missing.

**The committed hour is a theft window, and it is enforced by expiry.** Every short-lived
administrator credential this product issues is minted with a lifetime of one hour — the single
value `ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600` (`packages/server/src/server/ca.py:803`),
consumed at signing time as `lifetime_seconds` by the admin-cert route
(`packages/server/src/server/routes/admin_certs.py:317`) and pinned by an interlock test so the
number cannot drift unremembered (`packages/server/tests/test_clock_skew_fraction_rf7.py:55`,
`assert ADMIN_SHORT_CERT_LIFETIME_SECONDS == 3600`). Read the number for what it is, in the
owner's own reframe behind the design: because a revoked role is refused at the next request,
**certificate lifetime is not the revocation mechanism — it is purely the theft window.** So the
enforceable claim is this: a stolen or copied administrator credential stops working on its own
within 60 minutes, because the certificate expires. Enforced by expiry, at the minute scale for
legitimate use, and by revocation checks the moment they are asked about — not by anyone waiting
on a list.

**Internal verifiers never wait on a list's expiry — and we will not quote you an hour for this
plane, because it is not true.** Three shipped mechanisms, all tighter than the theft window:
the core re-mints the revocation list fresh at every relay connection and refuses outright if a
current list cannot be produced (`_ensure_dial_crl_store`,
`packages/server/src/server/routes/executors.py:702` — its docstring carries the owner's ruled
posture, "refuse everything until a properly refreshed list arrives", 2026-10-13); a stale or
missing list is answered as a refusal with 503 that asserts no revocation
(`_STALE_LIST_DETAIL`, `executors.py:699`, routed by `_dial_crl_verdict_for`, `executors.py:775`
— of the three handshake codes, only `CERT_REVOKED` (23) is ever reported as revoked; "unable to
get CRL" (3) and "CRL expired" (12) are staleness, deliberately never relabelled revocations);
and on the administrator plane, revocation is a per-request serial lookup at the front door
(`_validate_admin_mtls`, `packages/server/src/server/middleware/auth.py:493`: "nginx has no
`ssl_crl`, so this lookup is the enforcement point"). Immediate, both directions.

**Mentioned once, so it is not mistaken for the mechanism: the `next_update` stamp.** The
revocation lists this product signs carry a stated validity of one hour
(`builder = builder.next_update(now + timedelta(hours=1))`, `CAManager.generate_crl`,
`packages/server/src/server/ca.py:758`, and `AdminCAManager.generate_crl`, `ca.py:1465`). That
field is a signature-horizon on the published artifact for whatever consumes it off-box. **No
shipped verifier reads it as a trust tolerance** — the code above re-mints per dial and refuses
at staleness — so its one-hour number is a coincidence with the theft window's one hour, not the
same commitment. A future seat must not anchor the owner's 60 minutes here.

**The executor's own stop, which is the operational plane.** A revoked executor
that is still reporting to its core stops itself on its next heartbeat — the shipped cadence is a
beat every 30 seconds: `ExecutorDaemon._main_loop`,
`packages/executor/src/executor/daemon.py:2163` (`self._shutdown_event.wait(30.0)`, heartbeat and
revocation poll on the same tick); the core's heartbeat route states the same cadence ("Executors
POST to this endpoint every 30s", `packages/server/src/server/routes/executors.py`, `heartbeat`),
and server-side changes reach each executor "on each executor's next heartbeat (~30 s)"
(`packages/server/src/server/routes/admin.py:1071`). The core's fleet view marks a credential
no-longer-online once 60 seconds pass without a beat (`list_executors`,
`packages/server/src/server/routes/executors.py:1571`), so about a minute is the outer edge of
what an operator waits to SEE the stop. These figures are better than the "roughly five minutes"
this bound was described as while this page was being drafted — the shipped number is the one
above, and nothing here is a regression against it. They remain properties of the reporting
mechanism, not a second window: the numbers have different jobs and neither rules the other.
Separately, an executor that cannot reach its core at all keeps a bounded failure counter of
its own; that counter is an operational safeguard and carries no timing commitment — it is named
here only so no reader prices it as one.

**Workaround:** none is needed for revocation itself — it lands in about a minute, and the
administrator lookup is immediate. Where an operator wants a copied credential dead RIGHT NOW
without waiting on expiry, revoke it: the per-request lookup refuses it from the next request,
and a still-reporting executor self-stops on its next beat.

**What changes at beta+:** shortening the theft window is an owner ruling with its own cost
(re-issue cadence against long jobs), and is not scheduled here. The entry comes out if the
shipped lifetime value changes — the interlock test pins it, so a change is a deliberate, checked
event — and the list-freshness sentences retire with their #586 follow-on, not before.

---

## Certificates and credentials

### An administrator certificate issued before the marker fix is still refused at the proxy

Status: known limitation in beta · Target: none — this is a back-population limit, not a defect · Tracked as: #588 (closed with both the proxy-facing cell and the old-credential cell proved on a served install, at zero key ceremonies; recorded here because a closed row stops being read as a live limit)

**Who is affected:** an operator holding an administrator credential that was issued before
the fix that carried the two-plane marker non-critical. Both shapes are present in real
deployments at once — the installed code is fixed, the credential on the desk may not be —
which is why this needs a line here rather than only a closed issue. Nothing about a
certificate issued *after* the fix is limited: on a served install, the machine-plane pair the
core installer creates for itself is admitted at the front door and reaches the application,
and an administrator credential minted through the certificate-signing-request path has been
proven to do the same.

**What you get today:** a freshly minted administrator certificate is accepted by the proxy and
served by the application; a certificate minted before that change still carries the marker as
critical, and a verifier that does not recognise the marker rejects it, so the request is
answered at the proxy before it reaches any Venya code. Nothing about the certificate is
invalid — the fix is in how the marker is carried, and old bytes keep the old carrying.

**Workaround:** re-mint the credential. For the core's own machine-plane pair, re-run the core
installer: a re-run preserves the certificate authority and issues that pair again
unconditionally, so the new leaf carries the marker the accepted way. To mint one directly,
the same call the installer makes is

```bash
venya admin generate-admin-cert <identity> --output-dir /etc/venya/admin
```

which needs the admin CA passphrase and the leaf-key passphrase in its environment and refuses
before writing anything if either is missing or too short — run it the way the installer runs
it, on the core, as the `venya` user, with the stored passphrase delivered from
`/etc/venya/venya-core.env` rather than typed into a shell history.

For a person's short-lived workstation certificate the path is `venya admin cert renew`, and
one thing about it belongs in the same breath: the renewed key is written **encrypted at rest**,
and the command-line opens it for administrator mutual-TLS with the passphrase from
`VENYA_ADMIN_CA_KEY_PASSPHRASE` (#565 Part B) — that variable has to be in the environment of
every admin command that presents the pair, or the dial refuses before anything is sent. So a
renewed pair fixes the proxy refusal and serves the admin commands on that condition; see
[installation.md](installation.md) §3, which states that pairing rule once.

**What changes at beta+:** nothing further is planned for this one. Every certificate issued
from here carries the marker the accepted way, so the limit ages out credential by credential
as they are renewed — one re-mint per affected credential, not a fleet-wide action.

### Bootstrap is trust-on-first-use: whoever completes the key ceremony first on a newly initialized core becomes its administrator

Status: known limitation in beta · Target: none — it is a ruled bootstrap design, disclosed not
slated · Tracked as: GitLab **#668**, closed on the owner's DOCUMENT ruling (2026-10-19); this entry
is that ruling's text.

**Who is affected:** anyone who initializes a core on a network where another party can reach the
`/init` + ceremony path first.

**What the limitation is:** Bootstrap is trust-on-first-use: whoever completes the key ceremony first on a newly initialized core becomes its administrator — no prior act reserves the role, and there is no second claimant once the ceremony is done.
Initialize a new core on a network you control before you expose it.
This is a separate trust anchor from the first CA fetch disclaimed
elsewhere in this document: there, trust pins to a fetched certificate; here, trust pins to
whoever arrives first with the ceremony complete. The safe-initialization procedure lives in
[installation.md](installation.md) §2.

**What changes at beta+:** nothing is scheduled; the disclosure is the posture. If a reservation
capability is ever ruled, this entry is replaced by its own row rather than softened.

### The root certificate authority expires on a fixed day, ten years out, and nothing warns before it

Status: known limitation in beta · Target: no date set · Tracked as: `features/root-ca-ten-year-expiry-alarm-and-reroot.md` (s132 filing — warn-before-expiry and rotate-in-place, a capability item on a defects-only board, so it correctly has no GitLab row) · and GitLab **#661** (`root-ca-validity-duplicated-installer-literal-vs-constant`, `severity/medium`), which is the one *shipped* defect in this area: the same lifetime number is written at four mint sites with no interlock

**Who is affected:** every deployment, on a day that is set the moment the certificate authority
is first minted. It is not an edge case and it is not rare — it is only far away, and it is the
one limit on this page whose date an operator can and should write in a calendar today.

**What you get today:** the root CA is minted with a **3,650-day** validity
(`CA_VALIDITY_DAYS = 3650  # 10 years`, `packages/server/src/server/ca.py:45`, applied at the
signing call `.not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))`,
`packages/server/src/server/ca.py:478`), and the Admin CA carries the same span
(`ADMIN_CA_VALIDITY_DAYS = 3650`, `packages/server/src/server/ca.py:796`, applied at
`packages/server/src/server/ca.py:1060`). So the expiry day is your install day plus 3,650: a root
minted on 2026-10-03 00:48:37 GMT reads `notAfter=Sep 30 00:48:37 2036 GMT`, which is the shipped
constant rather than a rounded decade. Read your own with
`openssl x509 -in /var/lib/venya/ca/ca.crt -noout -startdate -enddate`.

Two facts belong in the same breath, because each one is the reason the other matters:

- **Everything under the root stops validating on that day, at once.** Server leaves, executor
  leaves, administrator leaves and the relay client credential all chain to it. There is no
  per-credential age-out that saves a deployment from its own root: the root is the oldest object
  in the system and it is the one nothing can renew in place.
- **Nothing in the product warns as the day approaches.** There is no expiry alarm, no health
  field carrying the root's `notAfter`, and no scheduled job. The `ca` probe in
  `/api/v1/health` (`_check_ca`, `packages/server/src/server/routes/health.py:78`) asks only
  whether the CA loads. What exists is a loud failure at the end: the executor's CA probe refuses
  an expired anchor by name (`"CA certificate expired"`, inside `validate_ca_certificate`,
  `packages/executor/src/executor/daemon.py:1357`), and the core's own verification fails closed
  past `not_valid_after` (inside `_verify_forwarded_cert`, the two lifetime checks at
  `packages/server/src/server/middleware/auth.py:203-206`). So the failure is a named refusal, not
  silent acceptance — but it arrives on the day, with no runway.

**Workaround:** read the date the day you install and calendar the rotation ceremony well before
it. The retirement path is the certificate-authority rotation in
[cert-rotation-runbook.md](cert-rotation-runbook.md) §5, which is break-glass and operator-present,
so it is a scheduled maintenance event, not something to reach for on the afternoon the root dies.
Plan against your own install date, not against any date written here.

**What changes at beta+:** the capability filing now exists —
`features/root-ca-ten-year-expiry-alarm-and-reroot.md` carries the alarm and the rotate-before-the-date
expectation, with four owner decisions left unruled and no target date. **No GitLab issue row was created for
that alarm capability, and none is owed**: the board takes defects only, and a decade-horizon maintenance gap is a
capability item. One adjacent thing *does* have a row, and it is not this limitation: GitLab **#661**
(`root-ca-validity-duplicated-installer-literal-vs-constant`) tracks the lifetime value being duplicated across
mint sites with no interlock, so changing the constant moves some roots and not others. The two are different
questions — #661 is about which value a mint uses today, this entry is about nobody warning you a decade out —
and closing #661 does not retire this limitation. The limit is still disclosed on this page rather than left to the
filing alone, so the day is not discovered by a partner first.

### Two paths still handle private key material without a passphrase

Status: known limitation in beta · Target: no date set · Tracked as: #565 (open on the API label
face, `severity/high`; the row title quotes "six `NoEncryption()` sites remain", which is a line
count of every match in product source, not a count of live writers — see the census below)

**Who is affected:** anyone reading a private key off an executor host, off the core, or
out of the command that unwraps a stored CA key — that is, the backup, disaster-recovery and
key-custody paths, not day-to-day use. The stored files are `0600` and root- or
`venya`-owned.

**What you get today:** most key writers now encrypt at rest, and two paths do not, for
different reasons. The count is live call sites, not grep hits —
`git grep -n 'NoEncryption()' <ref> -- 'packages/*/src/*'` returns **six lines** at this anchor,
and four of them are comments, not calls: three sit inside writers that now encrypt
(`cmd_admin_cert_renew`, `packages/cli/src/venya_cli/commands.py:2103`; `executor_register`,
`commands.py:3241`; `executor_cert_renew`, `commands.py:3678`, each describing the shape the
writer replaced) and one is the `key_passphrase` module docstring
(`packages/executor/src/executor/key_passphrase.py:10`), which says outright that the executor leaf
key *used to* be serialized that way. The two that remain are the pair below. Re-derive it that
way, because a row title quoting "six sites" is quoting that line count. And note the pathspec —
the trailing `/*` is load-bearing: the same search with `-- 'packages/*/src'` returns zero bytes
and rc 1 on a tree that plainly has hits, which is how a count of "no sites" gets reported for a
tree full of them.

- the core's own machine-plane admin key, returned unencrypted by
  `AdminCAManager.sign_admin_cert` (`packages/server/src/server/ca.py:1130`, the call at
  `:1244-1247`) — this one is
  **a ruled exemption, not an oversight**: the file mode is the control, the key stays on
  the core, and the exemption is retired only by the certificate-signing-request or
  TPM-sealing work that replaces it. It is listed here so a reader who finds it does not
  conclude it was missed;
- the command-line unwrap helper (`unwrap_at_rest`,
  `packages/cli/src/venya_cli/at_rest_key.py:55`, the call at `:86-89`) hands back plaintext key
  bytes **in memory**,
  never as a file — that is the form the CA-key export and restore commands need in order to
  re-encrypt under a passphrase you supply. The exposure to know about is a key sitting
  readable in a running process, not an extra file on disk.

**Workaround:** treat the core's machine-plane pair as key material wherever you handle it —
the backup set in [BACKUPS.md](BACKUPS.md) already does, and that pair is not copied off its
core — and run the export/restore custody commands on the core itself rather than on a host
whose process memory you do not control. An administrator credential that renews into an
encrypted key is opened at dial time with `VENYA_ADMIN_CA_KEY_PASSPHRASE` (#565 Part B),
documented once in
[installation.md](installation.md) §3.

**Scope of the word "paths", so this entry is not read as an inventory of every unencrypted key
on a host.** The two above are the Python writers of CA and leaf key material — the class #565
governs. Separately, the core installer mints three TLS machine keys with `openssl ecparam` and
leaves them unencrypted at rest, each guarded by mode and ownership rather than a passphrase:
the server leaf key (`install-venya-core.sh:965`, `chmod 600` at `:967`), the relay client key
(`:1005`, `:1007`) and the inner-listener key (`:1063`, `:1065`). Those are not #565 sites — no
`NoEncryption()` call is involved, and a daemon must read them unattended at start — but a partner
sweeping a core for readable private keys will find them, so they are named here rather than left
for someone to discover. The service-key posture is the subject of
[cert-rotation-runbook.md](cert-rotation-runbook.md) and is not ruled against disclosure anywhere
else on this page.

**What changes at beta+:** the open half of #565 closes the remaining writers, and the ruled
exemption above changes only when the work that replaces the core-held key lands.

### The database password carries no length rule at all

Status: known limitation in beta · Target: none until the owner rules a number · Tracked as: #675

**Who is affected:** anyone setting `VENYA_DB_PASSWORD` — the PostgreSQL password the core
database authenticates with — on a served install. It is the only password variable the installer ships.

**What the limitation is:** the database password has no length rule anywhere in shipped source.
The installer prompt for the database password runs through `venya_read_secret_confirm`,
which retries only on an empty entry and on a mismatch between the two entries — there is
no length test of any kind — and no shipped reader measures the value's length either. A
one-character database password is accepted, stored, and used by a real deployment. The
15-character floor documented on [`db.passphrase`](#dbpassphrase-production-only) and
enforced by the core at boot governs the **server encryption passphrase**
(`VENYA_DB_PASSPHRASE`) and the key-protection passphrases; it does not reach that
variable, and the one prompt in this family — `venya_read_secret_confirm` in `install-venya-core.sh` — bounds nothing.

**What is NOT claimed here:** that a floor is missing by oversight and any number will do.
The owner ruled the passphrase floor at 15 characters on the passphrase plane and has not
ruled a number for the password plane. A leg inventing one is a worse defect than the
silence it fixes — the documented development-test value for this variable is
shorter than 15 characters, so an unruled floor would make the installer refuse its own
documented inputs. The rule is therefore **stated as absent**, in this entry and in the
prompt text proposed in #675, which is a closed outcome under that row's AC2 rather than
an open one.

**What changes at beta+:** a floor on this variable lands only with an owner-ruled
number, applied at the installer prompt and at every reader together, with the documented
test values re-checked against it in the same change.

### The secret-length bounds are proven at unit and source level and have never been observed at a real terminal prompt

Status: known limitation in beta · Target: the owner-present fleet window (`AC8`) · Tracked as: #675
(open, HIGH — its code half is merged to `dev`; this entry discloses the missing physical half)

**Who is affected:** anyone who types a server encryption passphrase at an installer prompt and
wants the printed bound to be the bound that actually governs, at the terminal, not only in tests.

**What the limitation is:** the ruled length bounds on the passphrase plane — the enforced floor
(`MIN_PASSPHRASE_CODE_POINTS`, in `packages/core/src/core/engine/backend.py`) and the stated
ceiling (`MAX_PASSPHRASE_CODE_POINTS`, a documented permit and deliberately never a refusal door,
as that file's own comment states) — are proven by unit and source cells and have **never been
observed at a real TTY prompt**. The enforcement and disclosure sites exist and are source-verified
across both planes: the core DB-key-material door refuses a below-floor passphrase via
`is_passphrase_below_floor` in `packages/core/src/core/engine/backend.py`; the CA plane keeps its
own floor (`MIN_PASSPHRASE_CODE_POINTS` and `_passphrase_is_below_floor` in
`packages/server/src/server/ca.py`); the CLI states the same pair as its own named constants in
`packages/cli/src/venya_cli/commands.py`; and the installer-side floor and prompt live in
`install-venya-core.sh` (`DB_PASSPHRASE_FLOOR`). The declarations are guarded against drift by
`packages/core/tests/test_passphrase_length_declarations_agree_675.py`, the prompt disclosure by
`packages/cli/tests/test_prompt_length_disclosure_675.py`, the installer blank-entry face by
`packages/server/tests/test_installer_db_passphrase_blank_570.py`, and the installer floor gate by
`packages/core/tests/test_installer_db_passphrase_floor_gate_615.py`. The physical confirmation
cell — an operator-facing served install driven to those prompts by hand — is `#675`'s `AC8`, it is
gated on an owner-present fleet session, and it has not run.

**What is NOT claimed here:** that the bounds are unproven in code. They are not — the enforcement
sites above exist and are source-verified, and the shipped cells cover the floor, the per-character
(counting) rule, and the declaration-agreement census. What is not claimed beyond that is only this:
the at-terminal operator experience has **no physical capture yet**. This entry also does not touch
the separate password-plane rule stated by the entry **"The database password carries no length
rule at all"** in this document, and it does not revisit the ruling that the ceiling stays a permit.

**What changes at beta+:** the `AC8` run lands in the owner's fleet window and the physical face is
captured; this entry is **deleted** at that point, not softened.

### The operator can disable TLS verification by explicit configuration; the product never does it to make a connection succeed

Status: known limitation in beta · Target: none — it is a ruled development hatch, not a defect ·
Tracked as: no row of its own. The `verify=False` strike against the MCP client was closed on the
owner's read of the shipped tree (2026-10-19) without becoming a defect row, and he ruled this
entry as the disclosure for the hatch instead.

**Who is affected:** anyone who has copied `VENYA_TLS_VERIFY=false` out of a development note, and
anyone auditing a workstation, an executor or an MCP server that dials a core.

**What the limitation is:** the switch exists, it is honoured, and it is off unless you turn it on.
Four readers take it: `register_executor` in `packages/cli/src/venya_cli/api_client.py`, the
certificate-renewal dial in `packages/cli/src/venya_cli/commands.py`, the register and heartbeat
dials in `packages/executor/src/executor/daemon.py`, and `_bootstrap_tls_verify` in
`packages/mcp/src/venya_mcp/client.py`. Each one steps around verification only on the literal
`false`, and each says so out loud — a logged or printed warning naming the knob. Unset, empty or
`true` all verify; the two registration readers additionally refuse any other value outright rather
than guessing at it. Nothing in the product sets it for you, and no dial reaches `false` because a
handshake failed.

**What the knob never reaches.** Its ruled meaning is *distrust this certificate over https*, never
*no TLS*, and the four readers above are the whole of its reach. The scheme guard
`_require_https_server_url` — the gate behind `venya setup`, `venya config set-server` and the
register and renewal POSTs — does not consult it, so it cannot re-open plaintext. The CLI's own
`executor_heartbeat` command carries no branch that skips verification at all. And on the MCP side a
resolved anchor wins first: with `VENYA_CA_CERT` set the knob is never read, and with no anchor
resolving and the knob not `false` it raises rather than dialing unverified — the anchor-or-refuse
shape the #530 / #533 / #536 / #540 work built into the CLI dials is the same shape here.

**What is NOT claimed here:** that this entry covers the first CA fetch. Trust-on-first-use on the
`/.well-known/venya-ca.crt` fetch is a separate, judged bootstrap tradeoff and it is documented in
[installation.md](installation.md) (the two CA-trust paths); it is not this knob and not softened by
this entry. And the other trust anchor this page disclaims — the bootstrap ceremony one — is the
separate entry **"Bootstrap is trust-on-first-use"** in this document; "separate" there means that
named entry, not an abstraction.

**What changes at beta+:** nothing is scheduled. Retiring the knob would be a ruling about the
development fleet, not a fix, and the verifying path it steps around is the path every production
dial takes.

---

### The age-out date this product publishes for administrator credentials is computed from shipped constants, and has never been observed on a running guest

Status: known limitation in beta · Target: an owner-present window, no date set · Tracked as: the
workspace carrier `features/RF-11-rollout-ageout-docs.md`, whose own status line reads *landed in
part — not proven, not closed*.

**What the limitation is:** the age-out date an operator can read for an administrator credential is
**derived, not measured**. It comes from the shipped lifetimes — `EXECUTOR_VALIDITY_DAYS` (30) and
`ADMIN_CERT_VALIDITY_DAYS` (90) in `ca.py`, against a root authority minted for `CA_VALIDITY_DAYS`
(3,650) — and the arithmetic is sound. What has not happened is the physical read: no served,
re-installed guest has been observed refusing a credential after it passed `not_valid_after`. So the
date is a computed date standing in for an observed one, and beta ships it as that.

**What is NOT claimed here:** not that the check is missing — verification fails closed past
`not_valid_after` inside `_verify_forwarded_cert`, and an expired authority anchor is refused by name
(`"CA certificate expired"` in `validate_ca_certificate`), so the failure is a named refusal rather
than silent acceptance. And not any specific calendar day: the computed date depends on the day your
own authority was first minted, which differs per deployment, so this entry deliberately prints no
date. The gap is the **observation**, not the mechanism.

**What changes at beta+:** the cell runs in an owner-present window against a served guest, and this
entry is **deleted**, not softened, when it does.

---

## Installing and upgrading

### An executor setting you put in the config file disappears the next time the installer re-runs

Status: known limitation in beta · Target: no date set · Tracked as: #598 (row closed on the API
label face 2026-10-16, `status/merged`, with the precedence contract; **its AC6, the installer
half, did not ship**, and this entry is the live carrier for that half — the whole-file rewrite is
still shipped bytes at `install-venya-executor.sh:573` and the environment-file rewrite at
`:586-587`)

**Who is affected:** an operator who tunes an executor by editing
`/etc/venya/executor.toml` — which is exactly what the config reference and the precedence
page tell you to do — and later re-runs `install-venya-executor.sh` on that host. Re-runs are
the supported upgrade path, so this is not an edge case.

**What you get today:** the installer rebuilds that file from nothing on every run — the
write in `install-venya-executor.sh` redirects the whole generated block over the file
(`} > /etc/venya/executor.toml`), so afterwards the only lines in it are the ones that run
printed: `server_url`, `executor_id`, `log_level`, `daemonize`, `injection_method`,
`secret_base_fd`, `ca_bundle`, `dns_resolver`, `relay_client_ids`, the `[mtls]` trio
(`ca_cert`, `cert`, `key`), a conditional `[audit]` section carrying `remote_url` and
`ca_cert_path`, and nothing else. **A key you added there is gone.**

One key is deliberately rescued before that rewrite: `dns_resolver` is read back out of the
existing file when the environment does not supply it
(`venya_resolve_dns_resolver`, `venya-common.sh`), so a configured resolver survives.
Everything else does not.

**The service environment file is rewritten too, and harder.** The same installer removes
and rewrites `/etc/venya/venya-executor.env` with one line — the `rm -f` followed by the
single `printf 'VENYA_EXECUTOR_KEY_PASSPHRASE=…'` — so any executor setting an operator
added to that file is destroyed on the next re-run as well. Both file-based carriers are
installer-owned.

There is a second consequence worth naming, because it changes behavior rather than merely
losing it. The executor's precedence is config file, then environment, then the field default.
So a knob that only ever lived in the file — `sandbox_memory_mb`, or `max_concurrent_commands`
under its `[executor]` table — reverts to whatever the environment or the shipped default
gives after a re-run, with no message saying your tuning was replaced. The change is silent
because nothing was wrong: the file simply no longer carries the key.

**Workaround:** put executor tuning where the installer does not reach, and re-check it after
any re-run. One carrier survives: a systemd drop-in of your own name. The installer creates
the `.d` directory but removes and rewrites **only its own** `10-sandboxd.conf`, so an
override you add under a different name is untouched by a re-run:

```bash
sudo systemctl edit venya-executor        # writes /etc/systemd/system/venya-executor.service.d/override.conf
# add:
#   [Service]
#   Environment=VENYA_EXECUTOR_SANDBOX_MEMORY_MB=1024
sudo systemctl restart venya-executor
journalctl -u venya-executor -n 50
```

That works because the environment spelling wins wherever the file does not carry the key —
which, after a re-run, it no longer does. (The installer's own `10-sandboxd.conf` carries no
`Environment=` line, so it does not compete with yours.)

Read the boot lines after a restart rather than trusting the file you edited: the daemon names
any key that both spellings carry to different values, and a re-run that dropped your key shows
up as the setting you expect no longer taking effect.

**What changes at beta+:** #598 AC6 — the re-run preserving an operator's set value the way
`dns_resolver` reuse already does, instead of overwriting it. Until that lands, treat
`/etc/venya/executor.toml` as installer-owned: safe to read, not safe to hand-edit.

---

### Beta1's installers need internet: air-gapped installation is marked "coming soon", and no release is scheduled to carry it

Status: known limitation in beta · Target: not scheduled — the carrying version is the owner's to
rule, and this entry names no version for it · Tracked as: the workspace feature row
`features/air-gapped-installation.md` (class `critical`), with GitLab **#5** as its closed
predecessor history (the original "Fully offline installation method" row, `status/deferred`).

**What the limitation is:** a beta1 install needs an outbound network path on the installing
host — the installers fetch a Python 3.14 toolchain and package dependencies at install time
(see [installation.md](installation.md), "Air-gapped networks"). Customers on air-gapped
networks are served by a future release, marked **coming soon**; the interim answer for a
beta site is the local-mirror procedure behind info@tabith.com, which exists but is not
packaged.

**What is NOT claimed here:** not that the capability is abandoned — it is a critical-class
feature row on the owner's board; and not that any specific release carries it — the ruling of
2026-10-20 says "not beta1" and stopped there, and the version that does carry it has not been
named by the owner.

**What changes at beta+:** when the owner schedules the carrying release, this entry is deleted,
not softened — the page's own maintenance rule.

---

## Running commands

### Administrator commands that issue no request asked for a security-key ceremony

Status: known limitation in beta, for installs predating the fix · Target: landed in `dev` · Tracked as: #590 (row CLOSED on the API label face 2026-10-13, `status/closed` + `status/merged`; the entry stays because installs built before the fix still show the behavior)

**Who is affected:** an operator on a served core whose administrator credential does not
exist yet — a first initialisation, or a disaster recovery where the certificate authority
is the thing being restored — **running a build from before this fix shipped.** On a current
build the six commands below are recognised as local and no longer asked for a ceremony; the
limit that remains is the older install, and this entry stays here so a partner on one is not
left guessing. This is the path where those commands matter most.

**What you get today, on an install from before the fix:** `venya admin export-ca-key`,
`restore-ca-key`, `split-ca-key`, `export-ca-cert`, `init-admin-ca` and `generate-admin-cert`
touch no network — they read and write files on the core and prompt the operator. The command
dispatcher asked for a security-key ceremony before it would run any administrator command, so
on a host with no credential pair and no workstation key attached, these six were refused
before their own code ran. The transcript looked like this, and it is the message that misleads
rather than the behaviour:

```
Authenticating with security key...
Authentication failed: <reason naming the transport, not the file operation>
```

**Workaround:** the ceremony is skipped when the command-line already holds an administrator
credential — set both `VENYA_ADMIN_CERT` and `VENYA_ADMIN_KEY` (the headless pattern in
[installation.md](installation.md) §3), or supply a bearer token from a signed-in session —
and with either one these six commands run on the core. That covers the ordinary case.
Where it does not reach is the case the row is really about: the credential is the thing you
cannot present because the certificate authority it chains to is the thing being recovered.
There, work from the file backup instead — restore the saved
`/var/lib/venya/ca/` and `/etc/venya/` material with the ownership and modes intact
([BACKUPS.md](BACKUPS.md) §restore, the drill-proven path) and use the custody commands
afterwards, from a host holding a working credential. A ceremony needs a person's security
key and a physical touch, which a headless core does not have; on Windows it opens only from
an interactive desktop session, so a remote or scheduled shell is not a place one can be
done.

**What changes at beta+:** landed in `dev` at `e8d5a22` (live face `022bc588e0`) — the commands that issue no request no
longer require a ceremony for themselves, while commands that do talk to the core keep requiring
it, unchanged, and the administrator-pair raises that catch a half-configured pair are
preserved. The row **is** closed — 2026-10-13, `status/merged` on the label face read through
`glab api` at this tip — and this entry stays for one reason only: a build cut before that merge
still demands the ceremony, so a partner on an older install is still in scope. Nothing on this
page claims the served-core recovery proof was run; that ask belongs to the tracker, not here.

---

### Beta publishes no sizing table: the concurrency default is 1, and the load curve that would justify any higher number has not been run

Status: known limitation in beta · Target: not scheduled — the bench needs an owner-present window ·
Tracked as: the workspace carrier `features/RF-5-capacity-benchmark.md` (`class: REFACTOR — owner-present
bench`), whose publishable sizing table was declared out of beta scope by the owner on 2026-10-14.

**What the limitation is:** the shipped default is `max_concurrent_commands = 1` — one relayed command
at a time per executor, which is the sequential posture beta ships. **The mechanism above that value is
real and is not refused by anything in the product:** the config validator only rejects a cap **below 1**
(`_at_least_one_slot`), and the shipped field text says the class "deliberately carries no ceiling", so an
operator can set 2, 4 or 8 today and the executor honors it — the value sizes the admission permits
themselves, and the reader returns the cap unchanged for any value at or above 1. What beta does **not**
have is any characterization of that setting: the load curve at caps 2/4/8 has never been run, and the
field's own text conditions values above 1 on the RF-3 acceptance cells passing on the bench VM — a
documented condition that **no shipped code enforces**. So the honest statement is: concurrency above 1
is supported by the shipped mechanism but uncharacterized, and there is no beta answer to "how many
executors, how many guests, how many commands at once." This entry is the disclosure that the number
does not exist, and no document in this release supplies one.

**What is NOT claimed here:** **no capacity figure of any kind is stated, implied, or rounded to a
rule of thumb** — the carrier's standing rule bars a capacity claim, and that bar is unchanged; not that a
high cap is safe, and not that it is unsafe either, because nothing has been measured to support either
word; and not that memory is the binding ceiling on a shipping build — today the binding limit is the
default plus the absence of data, since the admission knob enforces no upper bound at all. What *is*
measured is the per-sandbox footprint default, and it is not a sizing table.

**What changes at beta+:** the curve runs, the owner rules the default on that data rather than on
local observation, and the sizing table becomes a document of its own — at which point this entry
leaves with it.

---

## How to read an entry, and how this list is maintained

Each entry gives: what you will hit, whether it is fixed-targeted or open, the issue that
tracks it, the specific posture that puts you in scope, what to do instead, and what has to
change for the entry to leave.

An entry is **removed**, never softened, when its fix lands — and a limitation that stays
true after a fix is a different limitation, so it gets its own entry (that is why the
certificate entry above sits under a closed issue). Where an entry names a merge, it names the
merge **that carries the change it describes**, and that sha is read from the history rather
than written from memory — the page's whole value is that a reader can go and look. A document
that contradicts the product is corrected in the document. Entries marked *pending owner
disposition* are the ones where the choice between "fix it" and "disclose it" is still open;
if the choice comes out as fix, the entry comes out before the release — and it comes out when
the fix is in a build, not when the ruling is announced.

**Exception to the symbols-only rule, and why it is here.** The three `Revocation` entries above
(`#586`, `#597`, and the propagation-window entry) carry `file:line` cites rather than symbol-only
cites, because the claim being
disclosed is *the absence of a control at a specific place* — "no CRL load and no `VERIFY_CRL`
flag anywhere in the executor package" is only checkable if the reader is pointed at the
context builder and at the one `VERIFY_CRL` line that exists elsewhere, at a named commit. The
anchor below is that commit; if the tree has moved, re-derive the numbers by the symbol named
alongside each one before repeating them — and since 2026-10-18 you no longer have to trust that
anyone did: every coordinate on this page is now declared in a machine manifest with the symbol it
means, and a suite cell reddens if a symbol stops existing in the file it cites. The numbers are
re-pinned by that manifest, by generator, at the release commit — never by hand at whatever tip a
seat happened to be sitting on, which is how the stale ones got published. The propagation-window entry cites two more things the
same way, because its claim is a shipped cadence rather than a fixed number: the hour is read at
the two `generate_crl` stamps in `ca.py`, and the 30-second beat at the daemon's main-loop tick.

**Cite integrity, machine-checked as of 2026-10-18.** Every coordinate on this page is declared once,
by hand, in `packages/server/scripts/beta_terms_cites.py` — path, the symbol the claim is about, and
which occurrence of that symbol it means. Two cells in
`packages/server/tests/test_beta_terms_cite_interlock.py` then hold it: a cite whose symbol stops
existing in the named file is RED, and a coordinate that appears on this page without being declared
there is RED. Prose is not machine-checked and never will be — whether a limitation still describes
the shipped tree is a person re-deriving it against behaviour, and a guard that interprets sentences
gets switched off inside a week.

**The numbers on this page are currently UNVERIFIED, and that is the honest face, not an oversight.**
The owner's ruling (2026-10-18) is *"claim-truth now, numbers re-pinned at the cut commit with a
checked assertion."* So the claim halves were re-derived today, and the coordinates were deliberately
**not** re-pinned at any development tip — this branch's base moved twice while the page was being
corrected, and a number pinned at a face that has already moved is the exact mechanism that published
the stale ones. At the release commit, run
`uv run -p 3.14 --directory packages/server python scripts/gen_beta_terms_pins.py --write`, set
`PINNED_AT` in the same changeset from the sha the generator prints, and the strict cell becomes live:
from then on a merge that moves a cited symbol reddens the suite instead of quietly publishing a wrong
line. **Until that has been done at the commit you are reading, treat every `:N` on this page as a
pointer to a symbol, not as a coordinate** — grep the symbol, and you get the right line at your tree.

**Source anchor:** the statements above were read against the shipped source at `dev`
`2e0e751` and the `#590` entry against `dev` `e8d5a22`; the two `Revocation` entries (`#586`,
`#597`) were written against `dev` `4543eb5` and **every cite in them was re-read at
`dev` `29beb1b`** — with `#586`'s dial half read at the
merge that carries it (`54457a6`) and the listener accept gate at the merge that carries *that*
(`5b0dd31`); those two shas are history cites for the merges that landed the code, so they do not
move when the tree moves. **`dev` `7b055e4` is the anchor this page carried** (the three
`Revocation` entries were re-derived there by symbol on 2026-10-14 and the numbers moved to
what that tip actually reads). The moves it recorded were between its old anchor and itself —
`install-venya-core.sh` took 59 insertions and 2 deletions since `29beb1b` (net +57, which is
exactly the relay block's shift), `daemon.py` +22/-6 and `relay_listener.py` +7/-1 (the accept
gate and the main-loop tick), `config.py` +2/-1 (the `relay_client_ids` field). The
propagation-window entry was re-read the same way: one number moved, the daemon tick, and it is
restated below.
`29beb1b` moved no file either entry cites (its face is `routes/audit.py` and two
test files), so the numbers are unchanged between the two tips. Two entries came out of this
page on 2026-10-13 after being re-read against `dev` `3268081` — the `#598` precedence entry (the
direction is ruled, the silence is removed, and the contract is written once in
[deployment-config.md](deployment-config.md)) and the `#589` memory-setting entry (that merge
ships the per-sandbox default). The **executor-config-file rewrite** entry above replaces the
first of those: it is a different limitation that survived the fix (`#598` row AC6, not landed —
the fix touches no installer file), and this page's rule is that a limitation staying true after a
fix gets its own entry rather than a softened one. Both shas are the merges that carry the change,
read from the history. When a fix listed here merges, re-read the entry against your tip before
editing — the entry, not the memory of it. Symbols are the citations here on purpose, because
the numbers rot within a day or two on this tree; the three `Revocation` entries above are the
named exception, for the reason stated just before the anchor. The propagation-window entry was
written and every cite in it re-read against `dev` `583d902` — after the s108 anchor correction the
carrying cites are `ca.py:803` `ADMIN_SHORT_CERT_LIFETIME_SECONDS` (with its consumer
`routes/admin_certs.py:317` and its interlock `tests/test_clock_skew_fraction_rf7.py:55`), the
stale-vs-revoked routing at `executors.py:687`/`:779` (`_dial_crl_verdict_for`), the per-request
admin lookup comment at `middleware/auth.py:493` (`_validate_admin_mtls`), the per-dial mint at
`executors.py:690` `_ensure_dial_crl_store`, the 30 s beat at `daemon.py:2163`
(`ExecutorDaemon._main_loop`, re-read at `7b055e4` — it sat at `:2147` at `583d902`), the online window at `executors.py:1525` (`list_executors`), the
~30 s propagation note at `routes/admin.py:1064`, and the `next_update` stamp itself at
`ca.py:758`/`ca.py:1470` — named in the entry as a signature field only, because no shipped
verifier honours it.

**`dev` `c36439b` was the anchor this page carried** until the 2026-10-18 terms-cite audit — re-derived by symbol on 2026-10-17
(the beta-terms truth audit), and **nineteen numbers moved**. The direction of the damage matters:
everything in the entries above is still true of the tree, but the page's coordinates were last
re-anchored at `90f2bcb`, and two merges since then inserted lines above cited code —
`git diff --numstat 009661593 c36439b` (the live face of that old anchor) reads
`routes/executors.py` **+68/−19**, `middleware/auth.py` **+39/−1**, `ca.py` **+47/−52**,
`routes/admin.py` **+11/−4** and `venya_cli/cli.py` **+66/−2**, which is where the moves come from.
Those numbers were recorded as read off the symbol at that anchor. **That is a dated record of what a
past pass measured, not a claim that any number below is current** — a 2026-10-18 audit found the
majority of the page's coordinates stale at a tip two days past the anchor it was pinned at, which is
why the numbers are re-pinned by generator at the release commit and never by hand:
`_build_relay_ssl_context` `:622`→`:628`; the `VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` line
`:657`→`:663`; the CRL `load_verify_locations(capath=…)` + `VERIFY_CRL_CHECK_LEAF` pair
`:669-670`→`:675-676`; `_STALE_LIST_DETAIL` `:687`→`:699`; `_ensure_dial_crl_store` `:690`→`:702`;
the owner's ruled-posture paragraph `:695-698`→`:705-710`; the revoked-with-403 return
`:777`→`:789`; `_dial_crl_verdict_for` `:779`→`:775`; `is_online = 0.0 <= delta.total_seconds() < 60`
`:1525`→`:1571`; the ruled-boundary scope note `:1926-1928`→`:1975-1977`; the per-dial mint call
`:1930`→`:1979`; the two `"Server TLS misconfiguration"` raises `:1938`/`:1948`→`:1987`/`:1997`;
the context-build call `:1945`→`:1994`. In the other files: the admin CRL `next_update` stamp
`ca.py:1470`→`:1465`; `_validate_executor_mtls` `auth.py:731`→`:748` and its
`executor_revocation_state(...)` lookup `:833`→`:863`; `venya admin split-ca-key` in `cli.py`
`:379`→`:381`; the ~30 s propagation note `admin.py:1064`→`:1071`. The cites that were re-read and
**did not move**: `ca.py:45`/`:46`/`:51`/`:394`/`:621`/`:715`/`:749`/`:758`/`:803`/`:1060`/`:796`,
`models.py:379`/`:380`/`:613`, every `relay_listener.py` and `daemon.py` number, the two
`executor/config.py` numbers, `admin_certs.py:317`, `test_clock_skew_fraction_rf7.py:55`,
`test_relay_dial_crl_586.py:21-24`, `install-venya-core.sh:965`/`:1005`/`:1013`/`:1020`/`:1022`
(its +18 landed at `:1122`, below every cite), and `install-venya-executor.sh:558`.

**Two entries changed state on this pass, and both are removals of a claim the tree no longer
makes.** The `#587` re-run entry came **out**: `install-venya-core.sh:1385-1389` now stops
`venya-core.service` before `Running database migrations...` (the comment at `:1381` records the
owner's disposition as `LAND — stop before migration`), so the interval the entry disclosed is
closed, and the page's own rule is that an entry is removed, never softened, when its fix lands —
the residual (a deliberate seconds-long interruption) is written in [UPGRADE.md](UPGRADE.md) and
[installation.md](installation.md) §1, where the re-run contract lives. The `#590` entry stays but
its `Tracked as:` line was wrong about the tracker: the row is closed on the label face, not open.
And a new entry went in above — the root CA's own 3,650-day expiry, which the page did not carry
at all (`grep -c '2036'` over the page at `90f2bcb` returned 0; at this anchor the new entry is
where that number lives).

**SHA FACE — every pre-2026-10-16 merge sha on this page is a dated face, not a dead pointer.** The
identity rewrite moved `dev` while preserving trees, so `54457a6`, `5b0dd31`, `e8d5a22`, `2e0e751`,
`4543eb5`, `29beb1b`, `7b055e4`, `583d902`, `3268081`, `90f2bcb`, `0467a31`, `1be04da` and `7a003ad`
all resolve in a clone that still holds the old objects, but **none is an ancestor of the live tip**
— a reader who clones fresh and `git show`s one of them finds nothing. Their live faces, read from
`wave29-specs-20261016/moved-sha-map-s129.tsv` (1,835 rows) and each re-proved an ancestor of
`c36439b` in the same turn: `54457a6`→`fc92bc15d0b818eae6a1602af46d1e80bf1b1db3`,
`5b0dd31`→`1edc50d4652f2317118a4829506caae8f71e8709`, `e8d5a22`→`022bc588e087e87b35447f286d2f9b61c1f537ff`,
`90f2bcb`→`009661593de4f4fc1557ae25d7ee23b09a4349df`, `2e0e751`→`167b64b1ae2aa8dd776bc134fc8e4ecfa53be4d0`,
`4543eb5`→`89dc9029d150ea7a66466352cf0edd03db03b251`, `29beb1b`→`3ce31024db2390cd278471b7d074a4f2cc335960`,
`7b055e4`→`5ec92834516fe8d51d02837067627b7ceadee459`, `583d902`→`76cc1dd930acad5cdab0d1e7b2bec5547a842242`,
`3268081`→`b6899f53ba689a43d18562bdd0dc15b6f30870b3`, `0467a31`→`365de9b8a7007e07536588d0ba571652990b7a65`,
`1be04da`→`8f58e83ffc6c284efb1fb23951831dde8371e0bb`, `7a003ad`→`45cd91292f0803aba8f662ff14ab2d2acbcaf671`.
The three entries that name a merge now carry the live face beside the old one, in the same
parenthesis; the historical paragraphs above this one keep their dated digits, because they are
dated observations and the rule is to translate them, not rewrite them.

**`dev` `90f2bcb` was the anchor this page carried** (live face `009661593…`) — re-derived by symbol on 2026-10-15, and
nine numbers moved. The arithmetic is recorded so the pass self-documents instead of just
restating digits: between the two anchors exactly three cited source files changed —
`routes/executors.py` +23/-10 (`0467a31`, the snapshot-served revocation list: net **+13** for
lines below its `:1240` hunk), `middleware/auth.py` +24/-1 (`1be04da`, reserved liveness
connections: net **+23** below its `:795` hunk), and `executor/config.py` +18/-44 (`7a003ad`, the
#620 dead-key removal: net **−31** above `:447`). So the dial-path call site moved
`:1917`→`:1930`, the context build `:1932`→`:1945`, the two TLS-misconfiguration raises
`:1925`/`:1935`→`:1938`/`:1948`, the ruled scope note `:1913-1915`→`:1926-1928`, the online-window
lookup `:1512`→`:1525` (twice — the entry and this note), the executor-mTLS serial lookup
`:810`→`:833`, and `relay_client_ids` `:447`→`:416`. Those numbers were likewise recorded as read off the line, at
that anchor. Dated record, same caveat as the pass above — the digits below are what was measured then,
not what a reader today should open: `:1930` is `crl_capath = _ensure_dial_crl_store(request, db)`,
`:1945` is the `_build_relay_ssl_context(...)` call, `:1938` and `:1948` are the two
`"Server TLS misconfiguration"` 503 raises, `:1926-1928` is the scope note, `:1525` is
`is_online = 0.0 <= delta.total_seconds() < 60`, `:833` is the `executor_revocation_state(...)`
call, `:416` is the `relay_client_ids: list[str] = Field(` declaration.

Every other numeric cite on this page was re-read at this tip too, and lands: the eight
`executors.py` cites whose line numbers sit before the `:1240` change point (`:622`, `:657`,
`:669-670`, `:687`, `:690`, `:695-698`, `:777`, `:779`), `middleware/auth.py:493` and `:731`, and
`config.py:149-152`. The rest of the
page's targets are files whose `git diff --numstat 7b055e4 90f2bcb` is **empty** — `ca.py`,
`daemon.py`, `relay_listener.py`, `core/iam/models.py`, `routes/admin.py`, `routes/admin_certs.py`,
`venya_cli/cli.py`, `tests/test_clock_skew_fraction_rf7.py`, `tests/test_relay_dial_crl_586.py`,
`install-venya-core.sh`, `install-venya-executor.sh` — so those numbers cannot have moved, and the
four source files that did change in range but are never cited by number here (`backend.py`,
`app.py`, `filter.py`, `revocation_snapshot.py`) carry no cite to fix.
