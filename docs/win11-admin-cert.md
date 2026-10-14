# Windows administrator certificate — check it, renew it, and the cells still owed

> **How to read this page.** Sections 1-5 are written from the product's own shipped
> surfaces: the CLI help text, the CLI refusal text, the Windows installer's printed
> warnings, and the server constants. Every command printed here was read in
> `packages/cli/src/venya_cli/cli.py` (`create_parser`, verified at `dev` `7b055e4`), and
> every quoted clause cites the file and symbol it came from.
> **Section 6 is different: those cells were DESIGNED, NOT RUN.** No Windows physical was
> performed for this page, and nothing in section 6 is evidence of anything.

## 1. What the credential is

A person's administrator certificate on a Windows workstation is a short-lived client
certificate. Three numbers describe it, and they are not interchangeable:

| Number | What it is | Where it is set |
|---|---|---|
| **60 minutes** | the lifetime of a person's certificate | `ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600`, `packages/server/src/server/ca.py:803` (module-level, the `# --- Admin CA constants ---` block) |
| **90 days** | the lifetime of the core's own machine-plane pair | `ADMIN_CERT_VALIDITY_DAYS = 90`, same module, consumed by `AdminCAManager.sign_admin_cert` |
| **15 code points** | the length floor on the passphrase that protects the key this page's renewal writes | `MIN_PASSPHRASE_CODE_POINTS = 15`, `packages/cli/src/venya_cli/commands.py:4497` |

The 60-minute value is not a remembered convention: it is consumed at signing time
(`packages/server/src/server/routes/admin_certs.py:317`, inside `async def
admin_issue_cert`, which calls `AdminCAManager.sign_admin_csr` with
`lifetime_seconds=ADMIN_SHORT_CERT_LIFETIME_SECONDS`), and a test pins the number so it
cannot drift unremembered — `packages/server/tests/test_clock_skew_fraction_rf7.py:55`,
`assert ADMIN_SHORT_CERT_LIFETIME_SECONDS == 3600` in
`TestToleranceFractionInterlock.test_lifetime_constant_is_the_ruled_60_minutes`.

**What the hour is for.** The owner's reframe behind the design is recorded once, in
[beta-known-limitations.md](beta-known-limitations.md): because a revoked role is refused
at the next request, **certificate lifetime is not the revocation mechanism — it is purely
the theft window.** This page does not restate that argument; read it there.

**What the renewed pair can serve today.** One limit travels with every successful renewal,
and the CLI prints it: `venya admin cert renew` writes the private key ENCRYPTED with
`VENYA_ADMIN_CA_KEY_PASSPHRASE`, and the CLI cannot yet load an encrypted administrator key
for admin mTLS (`_admin_leaf_key_encrypted_notice`,
`packages/cli/src/venya_cli/commands.py:4806-4816`). So a renewed pair authenticates the person
through their login session, not through certificate auth, until that read-side work lands
(#565 Part B). The full statement lives in the opening note of
[cert-rotation-runbook.md](cert-rotation-runbook.md) §0.

## 2. Check it — no key, no network, works from a remote shell

```
venya admin cert status
```

This is the read that never needs a desktop — the ruled reason it exists is that a headless
job must be able to pre-flight its own credential "without hiding a ceremony inside the
check" (`cmd_admin_cert_status` docstring, `packages/cli/src/venya_cli/commands.py:1754-1755`,
citing dossier §4.5). Its own shipped help says the same, quoted from
`packages/cli/src/venya_cli/cli.py:486-488` (`create_parser`, the `admin cert` group
description):

> `status` is read-local — it reads the certificate only, with no request, no security-key
> ceremony and no private key.

It works with `VENYA_ADMIN_KEY` unset, because the lifetime question needs only the public
half. Read the certificate from a remote session, decide whether the window is big enough
for the job, and renew at the console only if it is not.

Flags (all read from `cli.py:497-520`; full table in
[cli-reference.md](cli-reference.md), which is generated):

- `--cert-path` — the certificate to read (default `$VENYA_ADMIN_CERT`).
- `--within MINUTES` — also advise renewing if it dies inside that job window. The advisory
  never changes the exit code.

Three answers, and the order is the shipped one (`cmd_admin_cert_status`,
`packages/cli/src/venya_cli/commands.py:1751`):

1. no readable certificate, or one outside its validity window → one sentence on stderr
   naming `venya admin cert renew`, exit non-zero;
2. readable but dying inside `--within` → "renew before starting", exit 0;
3. readable and comfortably valid → the lifetime, then `STATUS: OK`, exit 0.

One honesty clause ships with the readout: every number is computed against **this
workstation's clock**, not the core's. A certificate that reads "not yet valid" locally
almost always means clock skew, and the refusal says so and tells you to fix the clock first
(`admin_cert_expiry_refusal`, `packages/cli/src/venya_cli/commands.py:1737-1746`).

## 3. Renew it — a session, then one ceremony at the desktop

Renewal takes two things in this order:

```
venya login <user-id>          # a session bearer, from a user enrolled on this core
venya admin cert renew         # one touch mints a fresh 60-minute certificate
```

Both lines are shipped surfaces: `login` is `cli.py:870`
(`subparsers.add_parser("login", help="Authenticate with a security key")`), `renew` is
`cli.py:523-535` (`admin_cert_sub.add_parser("renew", ...)`).

The renewal needs a **session, not a certificate**. Its help states it, quoted from
`cli.py:527-533`:

> Mint a fresh short-lived admin certificate from the core and write the certificate and its
> NEW private key locally, atomically. This needs a login session (run `venya login` first)
> and one security-key ceremony. The renewal never presents the old certificate: the mint is
> bound to the session, so an already-expired credential is not a credential this request can
> use.

So an expired certificate does not lock you out of renewing it — that is the point of the
design. And a renewal attempted with no session is refused locally before any dial
(`cmd_admin_cert_renew`, `packages/cli/src/venya_cli/commands.py:1902-1910`): *"`venya admin
cert renew` needs a login session, not an admin certificate — no session bearer is
available, so nothing was sent and the security key was not asked for."*

The refusal order is deliberately cheap-first (`commands.py:1889-1928`): nowhere to write →
no session → no passphrase → too-short passphrase → only then the ceremony and the mint. A
key touch is never spent on a request this workstation was not allowed to store.

Flags (`cli.py:536-572`):

- `--cert-path` / `--key-path` — **output** paths (defaults `$VENYA_ADMIN_CERT` /
  `$VENYA_ADMIN_KEY`). `renew` never reads a certificate from them.
- `--server-url` — dial a named core (default from config or `VENYA_SERVER_URL`).
- `--user-id` — authenticate as a named user for the login session (default from config).

There is no stdout escape for the pair on purpose: the certificate and its key are a matched
pair and the key never crosses the CLI boundary (`cli.py:561-566`, stated in the shipped
comment). Name both output paths if you do not want the configured pair overwritten.

## 4. The Windows limitation, in the product's own words

Two shipped surfaces say this, and this page quotes rather than rephrases them.

`packages/cli/src/venya_cli/cli.py:489-491` — `create_parser`, the `admin cert` group
description:

> on Windows that ceremony opens only from an interactive desktop session, not from a remote
> or scheduled shell.

`packages/cli/src/venya_cli/commands.py:1733-1734` — `admin_cert_expiry_refusal`, the text
printed on every expired-certificate refusal:

> Repair: run `venya admin cert renew`, then re-run this command. On Windows that ceremony
> opens only from an interactive desktop session, not from a remote or scheduled shell.

The installer prints the same rule before you ever need it
(`install-venya-cli.ps1:339-341`):

> FIDO2 ceremonies require an INTERACTIVE DESKTOP session: `venya init` / `venya login` /
> `venya credential add` — They cannot run over SSH or WinRM (the platform API needs a
> foreground window).

The mechanism behind it is in the CLI's own client factory (`_make_webauthn_client`,
`packages/cli/src/venya_cli/fido2_client.py:137-167`): on Windows the ceremony routes to the
platform WebAuthn API (`WindowsClient`), the OS owns device enumeration, the PIN dialog and
the presence prompt, and there is deliberately **no fallback** to the raw HID path — the raw
path is admin-only since Windows 10 1903 and would fail silently instead of telling you
anything. A machine without the platform API gets an explicit refusal naming the 1903 floor.

Two consequences that are not limitations, stated because they are often mistaken for ones:

- **The ceremony does not need elevation.** Install is elevated, use is not
  (`install-venya-cli.ps1:18` — "REQUIRES ADMINISTRATOR RIGHTS", and `:25` — "Standard users
  need no rights to USE the CLI"; same rule in [installation.md](installation.md) under the
  Windows workstation entry). Run every `venya` command, ceremonies included, from a standard
  terminal, and the OS dialog owns the PIN and the touch — the terminal never asks for a PIN
  in text (`_win_ceremony_hint` docstring, `commands.py:300-309` on the platform dialogs, and
  the shipped hint wording at `commands.py:312-317`).
- **Per-user state is per-profile.** `%APPDATA%\venya\config.json` and the core CA that
  `venya setup` installs beside it belong to the account that runs them
  (`default_config_dir`, `packages/cli/src/venya_cli/api_client.py:35-47`, win32 branch).
  Anything fixed under one account does nothing for another.

## 5. What to do, in order

Using only surfaces that exist at this tip:

1. **Preflight remotely, from wherever you already are:**
   `venya admin cert status --within <job-window-minutes>`. No key, no network, no desktop
   needed (§2). This is the step that tells you whether a trip to the console is required at
   all.
2. **If the read says it is expired or dying, go to the machine's own console** — the
   physical (or VM-console) desktop session, not SSH, not WinRM, not a scheduled task.
3. **Open a standard, non-elevated terminal there, in the same account that will use the
   credential.** A new terminal, so the machine PATH the installer wrote is in scope
   (`install-venya-cli.ps1:352-354`: "open a NEW terminal so the machine PATH refreshes").
4. **Bootstrap once per account, if that account has no profile yet:**
   `venya setup <core-host>` — saves the server URL and installs the core's CA as `ca.crt`
   beside `config.json`, and prints the certificate fingerprint for out-of-band confirmation
   (`cli.py:875-882`; `cmd_setup`). Use the product command, never a hand-copied CA file.
   Pin it when you can: `--ca-sha256`.
5. **Make sure the passphrase is in that environment before you start:**
   `VENYA_ADMIN_CA_KEY_PASSPHRASE` set to a value of at least 15 code points. `renew` refuses
   without it and refuses a short one, both BEFORE the ceremony (§3) — so the check costs you
   nothing if you do it first.
6. **Session, then ceremony:** `venya login <user-id>`, then `venya admin cert renew`. A
   Windows security dialog opens and owns the PIN and the touch; when the terminal prints its
   `Windows:` line, follow it — the renewal's elevation is an assertion, and the shipped hint
   for that kind tells you to use your REGISTERED key and to plug it in if the dialog asks
   (`_win_ceremony_hint`, `packages/cli/src/venya_cli/commands.py:312-317`; printed by the
   elevation step at `commands.py:1979-1981`).
7. **Confirm, then continue remotely:** `venya admin cert status` again. The renewed pair's
   limit in §1 applies — plan on the session for admin commands that need certificate auth
   today.

If you cannot reach a console and the job must run now: the machine-plane pair on the core
itself is the headless path, and it stays on that host — see
[installation.md](installation.md) §3, and the shipped refusal that stops the wrong move
(`packages/cli/src/venya_cli/api_client.py:453-458`, `APIClient.__init__`):

> `VENYA_ADMIN_CERT` points at …, which does not exist. **Do not copy the core's admin pair
> here — it names the core, not a person.** Run `venya setup <core>` and `venya login
> <user-id>`, then `venya admin cert renew` (see the installer banner) and retry.

That refusal is the answer to "can I just bring the core's credential to my laptop?" — no,
and the route forward is the ceremony above.

Authenticator reset and PIN set/change are not CLI operations on Windows; the vendor tool
owns them (`install-venya-cli.ps1:342-343`).

## 6. Physical cells — DESIGNED, NOT RUN

**Nothing in this section is evidence.** Every cell below was written from source and was
never executed. Each one carries its success criterion, the paired rejection it must also
prove, and the reason it is outstanding.

> **NOT RUN — requires the `win11` guest booted by the owner.** That guest is a montana
> domain, montana is frozen, and no lane boots, halts, defines or queries it. A ceremony also
> needs a security key attached to the machine the operator sits at — nothing that arrives
> over the network can stand in for one.

### Cell 1 — the installer's ACL gate on a path containing wildcards (#493)

**NOT RUN — requires the `win11` guest booted by the owner.**

- **Surface under test:** the protected-DACL enumeration and its counters in
  `install-venya-cli.ps1:248-277` — `Get-ChildItem -LiteralPath $Base -Recurse -Force -File`
  (`:254`), `Get-Acl -LiteralPath` (`:256`), the `$protected` / `$verified` / `$notChecked`
  counters (`:248-250`, `:257-263`), and the three report lines at `:273-277`.
- **Shape:** run the machine-wide install as the standard-user identity of the guest
  (`venyastd`, not the administrator account), with `VENYA_INSTALL_DIR` pointed at a path
  that contains PowerShell wildcard characters — a bracketed directory name is the shape that
  made the old positional `-Path` bind nothing.
- **Success:** the run prints `ACL check passed: N file(s) enumerated and ACL-read, 0
  protected DACLs` with **N greater than zero**, and the installed files are readable by a
  standard user afterwards.
- **Paired rejection (what must FAIL):**
  1. a run that enumerates zero files under an existing `$Base` must print
     `ACL check could not verify any file: 0 file(s) enumerated … Refusing to report a pass`
     and exit 1 — a gate that read nothing must never read as a pass
     (`install-venya-cli.ps1:270-272`);
  2. any file whose ACL reports `AreAccessRulesProtected` must fail the install with the
     shipped message naming `--link-mode copy` as the likely cause
     (`install-venya-cli.ps1:264-266`);
  3. an item that errors during enumeration or ACL-read must be disclosed as
     `ACL check INCOMPLETE: N item(s) … NOT checked`, not counted as verified
     (`install-venya-cli.ps1:273-277`).
- **Why this cell is not optional:** the `--link-mode copy` posture is what keeps hardlinked
  files from inheriting the installing administrator's security descriptor, and this gate is
  the only thing standing between a silent revert and an install standard users cannot read.

### Cell 2 — the ceremony from an interactive desktop

**NOT RUN — requires the `win11` guest booted by the owner**, plus a security key attached to
that machine and a person at its console.

- **Shape:** at the guest's own console, from a standard (non-elevated) terminal, in the
  standard-user profile: `venya setup <core>` once, then `venya login <user-id>`, then
  `venya admin cert renew`.
- **Success:** the OS opens its own dialog, the terminal prints its `Windows:` line and never
  asks for a PIN in text, `venya login` completes, and `venya admin cert renew` ends with
  `Admin certificate renewed` … `STATUS: OK` plus the encrypted-key note.
- **Paired rejection:** the same `venya login` / `renew` from an SSH or WinRM session into
  that same guest must NOT complete — no ceremony window opens, and the failure must surface
  as the CLI's own error text, never as a silent hang or a "No FIDO2 devices found" that
  points at the wrong cause.
- **Record the server-side half, not just the client-side claim:** the login is proven by the
  core's own `WebAuthnCredential` row (`packages/core/src/core/iam/models.py:583`, table
  `webauthn_credentials`) — `last_used_at` fresh (`:608`), `sign_count` advanced (`:595`) —
  beside the matching login-completion request, with the baseline re-read immediately before
  the attempt. `sign_count` is an authenticator counter, so read it as "the key signed and the
  server verified", never as a login count.

### Cell 3 — the renewal round trip

**NOT RUN — requires the `win11` guest booted by the owner.**

- **Success:** `venya admin cert status` before → renew at the console → `status` after shows
  a lifetime inside the committed hour, and the ceremony's refusal order holds: with no login
  session, renew refuses and sends nothing; with `VENYA_ADMIN_CA_KEY_PASSPHRASE` unset or
  shorter than 15 code points, renew refuses BEFORE any key touch.
- **Paired rejection:** an EXPIRED certificate must still be renewable (the mint is bound to
  the session, so the old leaf is not presented — `cli.py:530-532`), while an expired
  certificate presented to an ordinary admin command must be refused locally with the ONE
  expiry wording and no dial at all.

## 7. Where the same rule already lives

The Windows interactive-desktop limitation is not first stated here. It is already carried by
these surfaces, each in its own voice, and this page is the pointer that gathers them:

| Surface | What it covers |
|---|---|
| [installation.md](installation.md) | the Windows workstation install/use split and the ceremony rule under it; the four-command workstation sequence |
| [faq.md](faq.md) | "What platforms are supported?" and the expired-admin-credential answer |
| [FIREWALL.md](FIREWALL.md) | the local/no-network row for enrollment and login ceremonies |
| [full-lifecycle-test.md](full-lifecycle-test.md) | the Windows workstation variant inside the lifecycle run |
| [beta-known-limitations.md](beta-known-limitations.md) | the theft-window framing, and the no-request-ceremony entry |
| [cert-rotation-runbook.md](cert-rotation-runbook.md) | what a renewed pair can and cannot serve today |
| [cli-reference.md](cli-reference.md) | the flag tables (generated — never hand-edited) |
