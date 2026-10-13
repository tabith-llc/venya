# Beta known limitations

**Applies to:** `v0.1.0beta*` releases of Venya.
**Provenance:** every entry below names the tracked issue it comes from, and each was
read against the shipped source at the anchor noted at the foot of this file. Nothing here
is a summary of intent — if a limitation stops being true, the entry comes out.

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

### The relay checks revocation on the core's dial only; the executor's listener cannot assert peer revocation at all

Status: known limitation in beta · Target: no date set · Tracked as: #586 (open — the remedy
is BOTH doors and only one landed)

**What is enforced today.** One door: the DIAL, which is the core connecting OUT to an
executor. The relay context is built by `_build_relay_ssl_context`
(`packages/server/src/server/routes/executors.py:622`) and, since `54457a6`, that builder
consults a certificate revocation list at the TLS handshake —
`ssl_ctx.load_verify_locations(capath=crl_capath)` then
`ssl_ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF`
(`packages/server/src/server/routes/executors.py:669-670`). The list is minted fresh for
every dial by `_ensure_dial_crl_store` (`.../executors.py:690`), which the relay path calls
at `.../executors.py:1917`, and the context carrying it is built at
`.../executors.py:1932`. In operator language: when the core is about to send a command to
an executor, it will not complete that handshake against a credential the list says is
revoked, and it will not complete it against a list it cannot refresh either. The three
answers are distinct and deliberately named apart — a revoked leaf is refused with 403 and
says so (`.../executors.py:777`); a stale or unavailable list is refused with 503 whose text
says **"no revocation asserted"** (`.../executors.py:687`) and never claims a revocation that
did not happen; a missing CA anchor keeps the pre-existing TLS-misconfiguration wording
(`.../executors.py:1925`, and the same wording again at `:1935` for a context that cannot be
built) rather than being relabelled as a revocation event.

**What is NOT enforced.** The other door — the LISTENER, the executor's `:8443` side that
ACCEPTS a connection — does no revocation consultation at all. Its TLS context is built by
`RelayListener._build_ssl_context`
(`packages/executor/src/executor/relay_listener.py:499`) and sets the TLS floor, the
executor's own leaf, the CA anchor and `verify_mode = ssl.CERT_REQUIRED`
(`packages/executor/src/executor/relay_listener.py:503-514`). There is **no CRL load and no
`VERIFY_CRL` flag anywhere in the executor's shipped source** — re-derivable with
`git grep -i crl -- packages/executor/src`, which returns nothing at this tip, and
`git grep VERIFY_CRL -- packages/`, whose only hits in the product are the dial line above and
the unit cell that asserts it. The two relay surfaces are also **not symmetric in any verify
flag**: the file sets no `verify_flags` line at all, so it lacks the
`VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` the dial sets deliberately
(`packages/server/src/server/routes/executors.py:657`). Chain handling differs between the two
doors, not just list handling.

What the listener DOES have is a post-handshake accept gate
(`revocation_accept_reason`, `packages/executor/src/executor/relay_listener.py:311`, fired at
`packages/executor/src/executor/relay_listener.py:381`). Read it precisely, because it is not
a peer check: it consults the ONE answer this daemon holds about **itself** —
`DaemonState.revoked` and `revocation_answered`
(`DaemonState.__init__`, `packages/executor/src/executor/daemon.py:249`,
`packages/executor/src/executor/daemon.py:255`)
as written by `ExecutorDaemon._main_loop` (`packages/executor/src/executor/daemon.py:2114`,
`packages/executor/src/executor/daemon.py:2125`, and the consecutive-failure cutoff at
`packages/executor/src/executor/daemon.py:2133`). So it refuses every new connection when THIS
executor has been revoked or has received no revocation answer since boot; it holds no copy of
any list and does no serial or identity matching of the peer in front of it, and its own
contract comment says why — at `:8443` the peer is the core's relay-client credential, which
the executor-serial list never describes
(`packages/executor/src/executor/relay_listener.py:319`).

The shape of the exposure, stated plainly: **a credential the CA has revoked can still
complete a TLS handshake at an executor listener.** Nothing on that side asks the list. What
stops such a peer today is the CN allowlist — `relay_client_ids`, compared in
`ExecuteHandler.do_POST` (`packages/executor/src/executor/relay_listener.py:116`) — which is an
IDENTITY test, not a revocation test, and is answered after the handshake has already
succeeded.

And the stronger thing, which the page has to say rather than imply: **at this surface the listener
cannot assert peer revocation at all today, and bolting a list consult onto it would not change
that.** The service CA that signs the core's relay-client credential
(`-CA /var/lib/venya/ca/ca.crt`, `install-venya-core.sh:963`) is the same CA that signs executor
leaves (`CAManager.ca_cert_path`, `packages/server/src/server/ca.py:394`, leaf mint at
`packages/server/src/server/ca.py:621`), and the list that CA mints is populated from
`ExecutorCertRevocation` alone (`CAManager.generate_crl`,
`packages/server/src/server/ca.py:715`, query at `packages/server/src/server/ca.py:749`; the model
is titled "Revoked executor certificate serial numbers",
`packages/core/src/core/iam/models.py:380`). The only peer that legitimately dials `:8443` is the
core's relay-client credential, and that credential is recorded in no registry (#597), so it has
no row in that list. Same issuer, different population: the gap is at serial level, not at chain
level. **A `VERIFY_CRL_CHECK_LEAF` added to the listener today would be a no-op against the peer
it is aimed at** — a green test could be written for the flag and no revocation would be enforced
by it. That is why #597 is the sequenced prerequisite for this half, and not a detail of it.

**Who is affected in the shipped posture.** Reachability, not theory. The listener binds
`:8443` (`RELAY_PORT`, `packages/executor/src/executor/relay_listener.py:46`) on the executor
and takes connections from the core network (default `host="0.0.0.0"` in `RelayListener.__init__`,
`packages/executor/src/executor/relay_listener.py:456`, and the inbound `8443/tcp` rule for an
executor in [FIREWALL.md](FIREWALL.md):50). The peer that presents at that door is the
core's relay-client credential, signed by the core installer with a **365-day** validity
(`-days 365`, `install-venya-core.sh:965`), CN `${CORE_HOSTNAME}-relay`
(`install-venya-core.sh:956`). So: any core host that still holds a relay-client certificate
that was once signed by your CA, and whose CN is still in the executor's `relay_client_ids`,
completes the handshake at that executor — whether or not the CA has retired the machine it
came from. Executor leaves are dual-purpose, `SERVER_AUTH` and `CLIENT_AUTH`
(`packages/server/src/server/ca.py:51`), so an executor credential is also a credential that
can present as a client.

**One boundary is settled and is not on the plan: work already in flight is NOT terminated by a
revocation.** That is the owner's ruling, recorded in the shipped source
(`packages/server/src/server/routes/executors.py:695-698` and the scope note at
`packages/server/src/server/routes/executors.py:1913-1915`); fail-closed on a stale list applies
at the dial, and killing live sessions is ruled AGAINST, not deferred. The accept point already
matches that boundary: a refusal happens after the handshake and before any request byte
(`packages/executor/src/executor/relay_listener.py:381-403`), and the RF-3 admission permit is
taken later, inside the handler — so a refusal at accept can only ever deny new work.

**The proof that has not been run.** No physical revoke-then-refuse test has ever been executed on
a served fleet, for either door. What exists in the tree is unit-level: the dial
half is pinned by `packages/server/tests/test_relay_dial_crl_586.py`, which mints a real CA,
real leaves, a real CRL and a real loopback handshake but runs **no venya daemon on either
side** (its own module docstring, `packages/server/tests/test_relay_dial_crl_586.py:21-24`);
the listener accept gate is pinned by
`packages/executor/tests/test_relay_revocation_gate_586.py`. A unit that refuses a leaf in a
loopback handshake is not a revocation feature proved on a customer deployment. **The merged
dial half must not be read as "revocation works at the handshake"** — it is one of two doors,
and the unrun physical proof covers neither.

**Plan — what is NOT planned.** This entry does not promise a listener CRL consult, and a reader
should not read one into it. The half that is open here cannot be closed by adding two flags at
the listener, for the population reason above: **the enforcement gap is #597's, and #597 is the
sequenced prerequisite.** #586 stays open past beta on this half.

One alternative exists and is **the owner's call, not this page's plan, and not a scheduled
item**: build the transport consult anyway. It would buy the wording "a CRL is consulted at every
relay handshake" while delivering, as its only real effect, a **stop clock** — a list lapse makes
the listener refuse new connections. The clock is an hour, not an abstraction: the minted list
carries `next_update = now + 1 hour` (`packages/server/src/server/ca.py:758`, and the same stamp
on the admin sibling at `packages/server/src/server/ca.py:1470`), while the listener's published
context is rebuilt only by `RelayListener.reload_ssl_context`
(`packages/executor/src/executor/relay_listener.py:576`) whose one production caller is the
daemon's rotation arm (`packages/executor/src/executor/daemon.py:2095`) — a 30-day cadence
(`EXECUTOR_VALIDITY_DAYS = 30`, `packages/server/src/server/ca.py:46`). A list baked in at boot is
therefore certain to lapse inside an hour, and under the ruled fail-closed posture a lapsed list
means the executor refusing every new relay connection. That is a fleet-wide availability trade,
it is the owner's to make, and it is named here as his rather than as a task.

**What is enforced at that door today, because it is enforceable without #597.** Two things, and
the page should not let the peer-revocation gap hide them. First, the core's own application gate
refuses a revoked EXECUTOR serial per request, on the inbound plane, in
`_validate_executor_mtls` → `executor_revocation_state` with the presented serial
(`packages/server/src/server/middleware/auth.py:731`, lookup at
`packages/server/src/server/middleware/auth.py:810`). Second, the executor daemon stops
cooperatively on a bounded outage rather than serving on an unanswered question —
`max_revocation_failures`, default 3
(`packages/executor/src/executor/config.py:149-152`), fed at
`packages/executor/src/executor/daemon.py:2133`. Neither of those is peer revocation at `:8443`
and neither is claimed as such here; they are the controls that exist while #597 is open.

**What an operator can do now.** Four things are in the shipped product, and one common
assumption is not:

- **Remove the identity, not the credential.** `relay_client_ids` is the executor's allow-list
  of core client CNs (`ExecutorConfig.relay_client_ids`,
  `packages/executor/src/executor/config.py:446`); drop a retired core's CN
  and `ExecuteHandler.do_POST` refuses it with 403
  (`packages/executor/src/executor/relay_listener.py:116`). It fails closed when the
  list is empty — the listener does not bind at all
  (`packages/executor/src/executor/relay_listener.py:518-523`, and the same guard in
  `ExecutorDaemon.start` at `packages/executor/src/executor/daemon.py:1891`). Caveat that
  matters: the executor installer
  **rewrites** this key on every run (`relay_client_ids = ["${CORE_HOSTNAME}-relay"]`,
  `install-venya-executor.sh:558`), so a hand-edit there is not durable across a re-run — the
  rewrite is documented in its own entry below (#598).
- **Re-mint the core's relay pair, and know what that does NOT do.** A completing run of
  `install-venya-core.sh` regenerates the relay key and re-signs the credential with no
  existence guard on the files (`openssl ecparam -genkey ... relay-client.key`,
  `install-venya-core.sh:948`, then the sign at `install-venya-core.sh:965`), while the run
  preserves the certificate authority — the same re-run behaviour named in the `#588` entry
  below. So a re-run rotates what the core presents. It does **not** retire what the core used
  to present: the previous credential is not recorded anywhere and is not on any list, so a
  copy of the old pair keeps completing the handshake at every executor listener until it
  expires at its 365th day.
- **Contain reachability**, per [FIREWALL.md](FIREWALL.md):50 — inbound `8443/tcp` on an
  executor restricted to your core host(s).
- **Retire everything derived from the CA** by rotating the certificate authority —
  [cert-rotation-runbook.md](cert-rotation-runbook.md), whose custody path
  (`venya admin split-ca-key`, `packages/cli/src/venya_cli/cli.py:379`) is the break-glass
  half. This is the heavy, fleet-wide answer, not the routine one.

**There is no revocation path for a core's relay-client credential, and do not read
short-lived certificates as one.** The 30-day short lifetime that exists is the
EXECUTOR leaf (`EXECUTOR_VALIDITY_DAYS = 30`, `packages/server/src/server/ca.py:46`); the
core relay-client credential is minted at 365 days (`install-venya-core.sh:965`). And the cell
that would prove a revoked peer is refused at `:8443` **cannot be written against today's
product** — see #597 below: there is no registry and therefore no revocation record for any
machine-client credential, so there is no revoked serial in existence that a listener could be
shown refusing. #586's acceptance criterion 1 depends on #597 for exactly that reason.

### A core's own relay credential cannot be revoked

Status: known limitation in beta · Target: no date set · Tracked as: #597

**Who is affected:** an operator who needs to retire a core's relay client certificate — a
host being decommissioned, a relay key that may have been read by someone who should not have
had it, or a fleet being re-pointed at a new core. It also reaches anyone who assumes the
word *revoke* covers every certificate the product issues: for this one class of credential it
does not, yet.

**What you get today:** the certificate the core presents when it calls an executor's relay
listener is created by the installer, on the core, and lives only as two files on that host —
`/etc/venya/relay/relay-client.crt` and its key. It is trusted by every executor's listener for
its whole validity year (chain to your CA, plus the configured relay client name), but the
core keeps **no record of it**: there is no row for it in any table, so there is no command,
endpoint or runbook step that can revoke it. The two credential registries that do exist serve
executor leaves and administrator leaves; this class has neither a registry nor a revocation
list beside it. Revoking an *executor* works, and revoking an *administrator* certificate
works; retiring a core's relay credential does not.

**Workaround:** contain it the way you contain a host, not the way you contain a credential.
The certificate is useless to a caller that cannot reach `:8443`, so: restrict reachability to
the relay network (the private network and host firewall rules described in
[FIREWALL.md](FIREWALL.md)), and when decommissioning a core, stop its `venya-core` service and
take the relay key material with it. Rotating the certificate authority does retire every
derived credential, including this one — that is the heavy, fleet-wide answer in
[cert-rotation-runbook.md](cert-rotation-runbook.md), not the routine one. **Do not mistake two existing verbs for a path here.** `venya admin revoke-executor` names an
*executor*, and `venya admin revoke-admin-cert` names an *administrator* certificate; neither
takes a machine-client credential. Worse, the serial form of the executor command will record
any well-formed hex value without checking that it belongs to anything — so the operator can
appear to succeed at revoking a relay certificate, and nothing about the relay changes, because
no verifier consults a list for this class of credential. If you need the credential dead,
contain the host and the network, or rotate the certificate authority.

**What changes at beta+:** #597 is the registry-and-verb row — a store for machine-client
credentials and a revocation operation that reaches them. Its companion, the consultation half
(#586), landed in `dev` at `5b0dd31`: the executor's accept point now refuses for the one
credential it can legitimately know about — its own. What remains open there is the fact that
nothing on the core records *this* credential to be consulted about. Until #597 lands, the
accurate description of the surface is: revocation exists for the credentials that are
recorded, and not for this one.

**Read this entry together with #586, which depends on it — structurally, not by scheduling.** The
dial door of #586 landed at `54457a6` and consults a real list (`_build_relay_ssl_context`,
`packages/server/src/server/routes/executors.py:622`), and that list is populated from the
revocation tables this product actually has — `ExecutorCertRevocation`
(`packages/core/src/core/iam/models.py:379`, described in the model itself as "Revoked executor
certificate serial numbers" at `packages/core/src/core/iam/models.py:380` and read by
`CAManager.generate_crl`, `packages/server/src/server/ca.py:715` with the query at
`packages/server/src/server/ca.py:749`) and `AdminCertRevocation`
(`packages/core/src/core/iam/models.py:613`). A core relay-client credential has **no row in
either**, because it has no registry at all — and that is not "not added yet": a serial of this
class cannot appear in an executor-serial list. So today there is no revoked serial of this class
in existence for any verifier to consult, and the test that would show a listener refusing a
revoked machine-client credential cannot be written until this row lands. That is #586's
dependency on #597, and it is the reason #586 stays open after its dial half merged: adding a CRL
check at the listener would enforce nothing over the peer that actually dials it.

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
and the command-line cannot yet load an encrypted administrator key for administrator
mutual-TLS. So a renewed pair fixes the proxy refusal and lands in the separate, already
documented read-side limit — see [installation.md](installation.md) §2, which states that
pairing rule once. Use the machine-plane pair for headless work until that read-side work
lands.

**What changes at beta+:** nothing further is planned for this one. Every certificate issued
from here carries the marker the accepted way, so the limit ages out credential by credential
as they are renewed — one re-mint per affected credential, not a fleet-wide action.

### Two paths still handle private key material without a passphrase

Status: known limitation in beta · Target: no date set · Tracked as: #565

**Who is affected:** anyone reading a private key off an executor host, off the core, or
out of the command that unwraps a stored CA key — that is, the backup, disaster-recovery and
key-custody paths, not day-to-day use. The stored files are `0600` and root- or
`venya`-owned.

**What you get today:** most key writers now encrypt at rest, and two paths do not, for
different reasons:

- the core's own machine-plane admin key, returned unencrypted by
  `AdminCAManager.sign_admin_cert` (`packages/server/src/server/ca.py`) — this one is
  **a ruled exemption, not an oversight**: the file mode is the control, the key stays on
  the core, and the exemption is retired only by the certificate-signing-request or
  TPM-sealing work that replaces it. It is listed here so a reader who finds it does not
  conclude it was missed;
- the command-line unwrap helper (`unwrap_at_rest`,
  `packages/cli/src/venya_cli/at_rest_key.py`) hands back plaintext key bytes **in memory**,
  never as a file — that is the form the CA-key export and restore commands need in order to
  re-encrypt under a passphrase you supply. The exposure to know about is a key sitting
  readable in a running process, not an extra file on disk.

**Workaround:** treat the core's machine-plane pair as key material wherever you handle it —
the backup set in [BACKUPS.md](BACKUPS.md) already does, and that pair is not copied off its
core — and run the export/restore custody commands on the core itself rather than on a host
whose process memory you do not control. An administrator credential that renews into an
encrypted key is a separate, known read-side gap, documented once in
[installation.md](installation.md) §2.

**What changes at beta+:** the open half of #565 closes the remaining writers, and the ruled
exemption above changes only when the work that replaces the core-held key lands.

---

## Installing and upgrading

### A version-changing installer re-run leaves the previous service running until its last steps

Status: known limitation in beta · Target: no date set — **pending owner disposition** · Tracked as: #587

**Who is affected:** an operator re-running `install-venya-core.sh` over an existing install
**with a different version**, on a migration that touches a table the running build uses.
First installs are unaffected, and a same-version re-run applies migrations that change
nothing.

**What you get today:** the new packages are deployed and the database migrations are
applied while the previous `venya-core` process is still serving, and the running service is
brought onto the new bytes in the last steps of the run. For that interval the core answers
requests with older code against a newer schema — the combination the installer itself
declines to reason about when it refuses a downgrade. No data loss was observed, no incident
is recorded, and the length of the interval has never been measured. It needs a
version-changing re-run: a same-version re-run applies migrations that change nothing, and a
first install has no old process to serve from.

The run does not hide the interesting part of this. Two transcript lines are yours to read:

```
NOTICE: running venya-core process started <time> — BEFORE the bytes just deployed (<time>)
PROOF-OF-FRESH-BYTES: venya-core started <time> >= deploy stamp <time> — verification probes the NEW process
```

The first says the window was real on this run; the second says the checks at the end were
aimed at the new process rather than the old one.

**Workaround:** treat a version-changing re-run as a short maintenance window: keep
administration on the host itself instead of working through the service being replaced, and
don't send real commands until the run finishes. If a re-run aborts partway, the service is
not rolled back with the rest of the install — compare `systemctl status venya-core` (its
start time) against the deploy stamp in the log, then settle it with a re-run (idempotent) or
`systemctl restart venya-core`.

**What changes at beta+:** either the run stops the service before the migrations (the
interval disappears and this entry comes out), or the interval stays and the run prints how
long it lasted as well as when it began. The owner has not yet chosen which; this entry is
marked pending that decision, and comes out entirely if he rules that it lands.

### An executor setting you put in the config file disappears the next time the installer re-runs

Status: known limitation in beta · Target: no date set · Tracked as: #598 (the precedence
contract landed; this is row AC6, the installer half, which did not)

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

## Running commands

### Administrator commands that issue no request asked for a security-key ceremony

Status: known limitation in beta, for installs predating the fix · Target: landed in `dev` · Tracked as: #590 (row stays open — the served-core recovery proof is still owed)

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
[installation.md](installation.md) §2), or supply a bearer token from a signed-in session —
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

**What changes at beta+:** landed in `dev` at `e8d5a22` — the commands that issue no request no
longer require a ceremony for themselves, while commands that do talk to the core keep requiring
it, unchanged, and the administrator-pair raises that catch a half-configured pair are
preserved. The row is **not** closed by that merge: the physical proof of the recovery path on a
served core is still owed, so treat this entry as current for any install older than the release
that carries the fix.

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

**Exception to the symbols-only rule, and why it is here.** The two `Revocation` entries above
(`#586`, `#597`) carry `file:line` cites rather than symbol-only cites, because the claim being
disclosed is *the absence of a control at a specific place* — "no CRL load and no `VERIFY_CRL`
flag anywhere in the executor package" is only checkable if the reader is pointed at the
context builder and at the one `VERIFY_CRL` line that exists elsewhere, at a named commit. The
anchor below is that commit; if the tree has moved, re-derive the numbers by the symbol named
alongside each one before repeating them.

**Source anchor:** the statements above were read against the shipped source at `dev`
`2e0e751` and the `#590` entry against `dev` `e8d5a22`; the two `Revocation` entries (`#586`,
`#597`) were written against `dev` `4543eb5` and **every cite in them was re-read at
`dev` `29beb1b`**, which is the anchor this page carries — with `#586`'s dial half read at the
merge that carries it (`54457a6`) and the listener accept gate at the merge that carries *that*
(`5b0dd31`). `29beb1b` moved no file either entry cites (its face is `routes/audit.py` and two
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
the numbers rot within a day or two on this tree; the two `Revocation` entries above are the
named exception, for the reason stated just before the anchor.
