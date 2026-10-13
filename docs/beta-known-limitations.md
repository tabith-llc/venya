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

### A revoked executor certificate is not checked during the TLS handshake

Status: known limitation in beta · Target: no date set · Tracked as: #586

**Who is affected:** any deployment where an executor's credential has been revoked and
something on the relay network can still open a connection to that executor's `:8443`.
That includes a host you expected to be quiet: a revoked executor keeps listening until its
own daemon finds out, and it finds out on the daemon's schedule, not yours.

**What you get today:** revocation is enforced where the request is handled, not where the
connection opens. Three controls are real and are doing the work — the core's own dial gates
refuse to route a command to a revoked executor, the executor's inbound API paths refuse a
revoked identity, and the executor daemon stops itself when it learns it has been revoked.
What is absent is a check *of the certificate*: the handshake verifies the chain to the
configured certificate authority, and the client-name allowlist is applied afterwards, when
the request is handled. Neither one asks whether the certificate was revoked.

**Workaround:** revoke the executor with the identity form, `venya admin revoke-executor
<executor-id>`, which the core's dial gates honour on the next attempt; if you need the
executor unreachable at the network rather than merely unserved, stop its service
(`systemctl stop venya-executor`) or remove it from the network. There is **no
CRL-based workaround — do not go looking for one**: the CRL this product mints and serves
has no reader inside the product, and issued certificates carry no distribution point
unless an operator configures one, which is not the default and does not change what Venya
enforces. Publishing a CRL would tell a third party about revocations; it would not make
this handshake check anything.

**What changes at beta+:** the enforcement point moves closer to the connection. A
post-handshake refusal at the listener's accept point is in review, and refusing *during*
the handshake is a separate design that needs its own decision first (it reaches the
certificate-authority shape, not just this code path). Until one of those lands, read this
entry as: revoked means unserved, not unreachable.

---

## Certificates and credentials

### An administrator certificate issued before the marker fix is still refused at the proxy

Status: known limitation in beta · Target: none — this is a back-population limit, not a defect · Tracked as: #588 (closed; recorded here because the closed row is no longer read as a live limit)

**Who is affected:** every install whose admin certificate was issued before the fix that
carried the two-plane marker non-critical. Both shapes are in the field at once — the
installed code is fixed, the credential on the desk may not be — which is why this needs a
line here rather than only a closed issue.

**What you get today:** a freshly minted admin certificate is accepted at the front door
and reaches the application; a certificate minted before that change still carries the
marker as critical, and a verifier that does not recognise the marker rejects it, so the
request is answered at the proxy before it reaches any Venya code. Nothing about the
certificate is wrong — the fix is in how the marker is carried, and old bytes keep the old
carrying.

**Workaround:** re-mint the credential. On a workstation leaf: `venya admin cert renew`.
On the core's own machine-plane pair, either re-run the core installer (the certificate
authority itself is preserved by a re-run, and the credential is minted again — see
[installation.md](installation.md) §1 for what a re-run guarantees to keep) or mint it
directly, the same way the installer does:

```bash
venya admin generate-admin-cert <identity> --output-dir /etc/venya/admin
```

That command needs the admin CA passphrase and the leaf-key passphrase in its environment,
and it refuses before writing anything if either is missing or too short — so run it the way
the installer runs it, from the core, as the `venya` user, with the stored passphrase
delivered from `/etc/venya/venya-core.env` rather than typed into a shell history.

**What changes at beta+:** nothing further is planned. Every certificate issued from here
carries the marker the accepted way, so this limit ages out on its own as credentials are
renewed — one re-mint per affected credential, not a fleet-wide action.

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

---

## Running commands

### A freshly installed executor needs one memory setting before it will run anything

Status: known limitation in beta · Target: no date set — **fix shape not yet ruled; disposition pending** · Tracked as: #589

**Who is affected:** every new executor installed with the shipped defaults. This is the
common path, not an edge case: a default install reaches this on its first command.

**What you get today:** the first sandbox creation is refused with a message naming the
setting it wants:

```
sandbox_memory_mb is not configured — sbx create refuses without an explicit cap.
```

The refusal is deliberate and is the correct half of the story: without a cap, the sandbox
tool inherits a vendor default of half the guest's memory, so two concurrent commands could
each claim the whole machine. What has not been shipped is a value — no installer, service
environment file or package sets one, and the sizing page the message points at does not
name the setting.

**Workaround:** set the cap explicitly on the executor, then restart it. Either form works:

```bash
# /etc/venya/executor.toml — a top-level key, above the first [section] header
sandbox_memory_mb = 1024
```

or in the executor's service environment: `VENYA_EXECUTOR_SANDBOX_MEMORY_MB=1024`.

The value is a real decision, not a formality: it is bounded below at 512 MiB by the sandbox
tool's own minimum and above at 75% of the executor's memory, and it multiplies by the
number of commands allowed at once. [deployment-sizing.md](deployment-sizing.md) is the page
for choosing it.

**What changes at beta+:** the shipped default, or the value being carried by the installer,
once the fix shape is ruled. It will not be closed by giving the knob an arbitrary default —
that would put back the cap-less claim this refusal exists to prevent.

### Some administrator commands cannot run on a core that has no credential of its own yet

Status: known limitation in beta · Target: fix in review · Tracked as: #590

**Who is affected:** an operator on a served core whose administrator credential does not
exist yet — a first initialisation, or a disaster recovery where the certificate authority
is the thing being restored. This is the path where those commands matter most.

**What you get today:** `venya admin export-ca-key`, `restore-ca-key`, `split-ca-key`,
`export-ca-cert`, `init-admin-ca` and `generate-admin-cert` touch no network — they read
and write files on the core and prompt the operator. The command dispatcher still asks for
a security-key ceremony before it will run any administrator command, so on a host with no
credential pair and no workstation key attached, these six are refused before their own code
runs. The transcript looks like this, and it is the message that misleads rather than the
behaviour:

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

**What changes at beta+:** the commands that issue no request stop requiring a ceremony for
themselves (commands that do talk to the core keep requiring it, unchanged). That fix is
built and awaiting merge review; once it ships in a release, this entry narrows to installs
predating it.

---

## How to read an entry, and how this list is maintained

Each entry gives: what you will hit, whether it is fixed-targeted or open, the issue that
tracks it, the specific posture that puts you in scope, what to do instead, and what has to
change for the entry to leave.

An entry is **removed**, never softened, when its fix lands — and a limitation that stays
true after a fix is a different limitation, so it gets its own entry (that is why the
certificate entry above sits under a closed issue). A document that contradicts the
product is corrected in the document. Entries marked *pending owner disposition* are the
ones where the choice between "fix it" and "disclose it" is still open; if the choice comes
out as fix, the entry comes out before the release.

**Source anchor:** the statements above were read against the shipped source at `dev`
`8621a83`. When a fix listed here merges, re-read the entry against your tip before editing —
the entry, not the memory of it.
