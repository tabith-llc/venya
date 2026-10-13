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

**Source anchor:** the statements above were read against the shipped source at `dev`
`2e0e751` and the `#590` entry against `dev` `e8d5a22`. Two entries came out of this page on
2026-10-13 after being re-read against `dev` `3268081` — the `#598` precedence entry (the
direction is ruled, the silence is removed, and the contract is written once in
[deployment-config.md](deployment-config.md)) and the `#589` memory-setting entry (that merge
ships the per-sandbox default). Both shas are the merges that carry the change, read from the
history. When a fix listed here merges, re-read the entry against your tip before editing — the
entry, not the memory of it. Symbols, not line numbers, are the citations here on purpose: the
numbers rot within a day or two on this tree.
