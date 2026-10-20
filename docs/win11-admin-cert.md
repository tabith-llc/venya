# Windows administrator certificate — check it, renew it, and the cells still owed

> **How to read this page.** Sections 1-5 are written from the product's own shipped
> surfaces: the CLI help text, the CLI refusal text, the Windows installer's printed
> warnings, and the server constants. Every command printed here was read in
> `packages/cli/src/venya_cli/cli.py` (`create_parser`, verified at `dev` `7b055e4`), and
> every quoted clause cites the file and symbol it came from.
> **Section 6 is different: each cell carries its own run status, and cells 2 and 3 are now
> RUN AND PASSING.** The only Windows physical this page held when section 6 was written was a
> read-only guest preflight (section 6 says which reads and when); no install, ceremony, or
> renewal had run then. Both have since run on the Windows guest and passed — the evidence is
> commit `8c73fc0c` with its report at `wave27-specs-20261015/ultra-rf8-cells23-s124-report.md`
> (named, not restated here), against target **core-3**, identity **`venya-adm3`**. Cell 1 keeps
> the exception its own row states.

## 1. What the credential is

A person's administrator certificate on a Windows workstation is a short-lived client
certificate. Three numbers describe it, and they are not interchangeable:

| Number | What it is | Where it is set |
|---|---|---|
| **60 minutes** | the lifetime of a person's certificate | `ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600`, `packages/server/src/server/ca.py:803` (module-level, the `# --- Admin CA constants ---` block) |
| **90 days** | the lifetime of the core's own machine-plane pair | `ADMIN_CERT_VALIDITY_DAYS = 90`, same module, consumed by `AdminCAManager.sign_admin_cert` |
| **15 characters** | the length floor on the passphrase that protects the key this page's renewal writes | `MIN_PASSPHRASE_CODE_POINTS = 15`, `packages/cli/src/venya_cli/commands.py:4497` |

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

**What the renewed pair can serve today.** One requirement travels with every successful
renewal, and the CLI prints it: `venya admin cert renew` writes the private key ENCRYPTED with
`VENYA_ADMIN_CA_KEY_PASSPHRASE`, and the dial that presents that key opens it with the same
variable (`_admin_leaf_key_encrypted_notice` in
`packages/cli/src/venya_cli/commands.py`, and `api_client.py::_build_ssl_context`, #565 Part B).
So a renewed pair serves the certificate-authenticated admin commands wherever that variable is
set in the command's environment; where it is not set the dial refuses before anything is sent,
naming the key file. A login session alone does not either: with admin mTLS enabled (the
default) an admin request without a client certificate is refused 403. The other credential for
those commands is the core's own machine-plane pair on the core — see
[installation.md](installation.md) §2 and §3. The renewal call itself is the session-shaped
exception (§5 step 6 still works): `POST /api/v1/admin/certs/issue` is authorized by the
person's session by ruling, RF-6 §2.2. The full statement lives in the opening note of
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
   `VENYA_ADMIN_CA_KEY_PASSPHRASE` set to a value of at least 15 characters. `renew` refuses
   without it and refuses a short one, both BEFORE the ceremony (§3) — so the check costs you
   nothing if you do it first.
6. **Session, then ceremony:** `venya login <user-id>`, then `venya admin cert renew`. A
   Windows security dialog opens and owns the PIN and the touch; when the terminal prints its
   `Windows:` line, follow it — the renewal's elevation is an assertion, and the shipped hint
   for that kind tells you to use your REGISTERED key and to plug it in if the dialog asks
   (`_win_ceremony_hint`, `packages/cli/src/venya_cli/commands.py:312-317`; printed by the
   elevation step at `commands.py:1979-1981`).
7. **Confirm, then continue remotely:** `venya admin cert status` again. The renewed pair's
   limit in §1 applies — the core's own machine-plane pair is what carries admin commands
   that need certificate auth today.

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

## 6. Physical cells — status as run

**Each cell below carries its own run status; nothing here is evidence unless its status line
says it is.** Every cell was written from source. Each one carries its success criterion, the
paired rejection it must also prove, and, where it applies, the reason it is outstanding.

> **Where the verdicts on this page come from.** Cells 2 and 3 are recorded RUN AND PASSING on
> the lead's own scorecard correction (`beta-gate-scorecard.md`, commit `3aaeb169`) and its
> evidence commit `8c73fc0c`. This page was written by a docs seat that did not attend that run
> and did not open the report; it states the verdict, the target (**core-3**), the identity
> (**`venya-adm3`**) and the evidence path, and it deliberately does not restate the run itself.
> Anything finer — including which paired-negative arm of a cell was observed — belongs to that
> report, not to this page.

| Cell | Status (the preflight reads under Cell 1 are dated `dev` `f0a2c3a` and are no longer a blocker) |
|---|---|
| 1 — installer ACL gate on a wildcard path (#493) | **POSITIVE HALF RUN/PASS at `664f267` · ZERO-ENUMERATION ARM RUN/PASS IN HARNESS · PROTECTED-DACL ARM RUN/PASS IN HARNESS (the second rejection line this guard has ever been seen to print) · INCOMPLETE ARM RUN IN HARNESS, NOT PRODUCIBLE FROM AN ELEVATED BODY (measured: the applied deny lands and the walk cannot see it) · COUNT-COVERAGE ANSWERED, NOT A COVERAGE GAP · PAIRED venyastd READABILITY HALF NOT RUN (owner console)** |
| 2 — the ceremony from an interactive desktop | **RUN AND PASSING (s124, session 2)** — evidence `8c73fc0c`, report `wave27-specs-20261015/ultra-rf8-cells23-s124-report.md`, target **core-3**, identity **`venya-adm3`** |
| 3 — the renewal round trip | **RUN AND PASSING (s124, session 2)** — same evidence, same target and identity |

> **What the guest gives, and what it does not.** The `win11` guest is a montana domain and
> montana is frozen: no lane boots, halts, defines or queries it (`virsh` reads included) —
> that stays the owner's. Its booted state, its PowerShell version and its installed CLI were
> read over SSH as `win` (rc=0) from the agent box; that read is the preflight table under
> Cell 1. **That preflight is no longer the live face of the guest.** A current CLI has since
> been installed on it (installs are the owner's act on every box) — the deployed build on the
> target core carries the same version line, lead-corroborated, so **no reinstall is required
> to reach this page's renewal route**; and a ceremony still needs a security key attached to
> that machine and a person at its console — nothing that arrives over the network can stand in
> for one. Both of those owner acts were performed for the run that closed cells 2 and 3.

### Cell 1 — the installer's ACL gate on a path containing wildcards (#493)

**POSITIVE HALF — RUN, PASS at `664f267`.** The abort that blocked this cell was #628, and it is
fixed and merged: the installer's path probes now read `-LiteralPath`, so a base whose name
carries brackets is taken literally. The install then ran **elevated** at the guest against the
merged script, fetched over a scratch port because the served docroot copy is still pre-fix, and
its gate printed verbatim `ACL check passed: 4285 file(s) enumerated and ACL-read, 0 protected
DACLs.` with the run exiting 0. That is the PASS line this cell was blocked from observing.

**REJECTION ARMS — RUN IN A HARNESS ON A SCENARIO TREE, NOT BY THE INSTALLER.** The gate block —
byte-identical to `install-venya-cli.ps1:246-283` at `664f267` — was driven against five scenario
trees. A harness is the only way these arms get executed at all, and the page should say so
plainly: the class this guard exists to catch is hardlink mode, which a `copy`-mode install never
produces, so no ordinary install run can present a protected DACL to it. Of the three rejection
arms, two have now reached their rejection line and one has not, and each miss is measured rather
than assumed; two positive controls say the counter itself is live.
- Zero-enumeration arm — harness on a scenario tree whose base exists and holds no files: printed
  verbatim `[ERROR] ACL check could not verify any file: 0 file(s) enumerated under an existing
  C:\temp\s121h\case-C, so this check proved nothing. Refusing to report a pass - report this
  message with the install directory.` and the harness read exit 1. **This arm fired as designed**:
  a gate that read no file refuses rather than reporting a pass.
- Protected-DACL arm — **RUN, PASS in a harness on a scenario tree.** The scenario is one **file**
  whose own DACL is stripped of inheritance and re-granted to `*S-1-5-32-544` (the SID prefixed
  with `*`, which is the form `icacls` takes as a SID rather than a name; the bare form was the
  first run's miss, rc 1332, nothing applied). The landing is proven before the gate speaks:
  `PROTECT_RC=0` and `FILE_PROTECTED_BEFORE_GATE=True`. The guard then printed verbatim
  `[ERROR] 1 file(s) under C:\temp\s121h\case-B carry a protected DACL and would be unreadable by
  standard users. Likely cause: --link-mode copy was dropped. Refusing to leave a broken install.`
  and the harness read `GATE_EXIT=1`. The scenario was reversed in the same run and the reversal
  was proven: `RESET_RC=0`, `B_REVERSAL_PROTECTED=False`. **This is the second of the guard's three
  rejection lines to be observed executing, and it is still a harness on a scenario tree — not an
  installer run.** The directory-shaped version of the same scenario stays invisible to this gate:
  it walks files, and files under a protected directory still read
  `AreAccessRulesProtected=False`.
- INCOMPLETE arm — **RUN, NOT PRODUCIBLE FROM AN ELEVATED BODY.** First run's miss was the same
  bare-SID `icacls` refusal (rc 1332, nothing applied). Re-aimed at the arm's *other* input — the
  warning line counts enumeration failures as well as ACL-read failures — the scenario is a
  subdirectory carrying `icacls /deny '*S-1-1-0:(OI)(AD)'`, a deny on listing it. That deny lands
  (`DENY_RC=0`) and reads back as `Everyone | AppendData | ObjectInheritNone`, and the walk still
  sees straight through it: `cmd dir /b` returns the child name, `Get-ChildItem` on the subdirectory
  returns 1 item with no error, and the gate's own walk reports 0 enumeration errors, 1 file
  verified, 0 not checked — so the guard printed its PASS line, `[INFO]  ACL check passed: 1 file(s)
  enumerated and ACL-read, 0 protected DACLs.`, exit 0. **The honest verdict: the INCOMPLETE warning
  is not producible by an elevated body through a self-applied deny.** The reason is in the body, not
  the gate: this guest's SSH token is High Mandatory Level with `SeBackupPrivilege` and
  `SeRestorePrivilege` **Enabled**, so the walk's directory opens carry backup semantics and the DACL
  is bypassed for them; and the read-side half was already measured — a self-applied read-deny makes
  the *file contents* unreadable (`Get-Content` throws) while `Get-Acl` on the same file still
  succeeds, which is exactly why the ACL-read arm cannot throw either. Both inputs to that warning are
  out of reach from this body class, so no third scenario is offered here. Reversal proven: `RESET_RC=0`
  on both the subdirectory and its file.
- Two positive controls, harness — one readable file printed `ACL check passed: 1 file(s) ...`
  and two readable files printed `ACL check passed: 2 file(s) ...`, exit 0 each. The enumerator
  and the counter are live, so the numbers above are the gate's own and not a silent zero.

**COUNT-COVERAGE — ANSWERED, AND NOTHING RIDES ON IT.** The gate's count is a snapshot taken while
the installed tree is still gaining `__pycache__` files on first import. Measured on this installed
base: `--version` and `--help` together add **0** files (`NEW=0 GONE=0` under both enumerators), so
running the product does not move the number; the 4,715-vs-6,857 spread between two enumeration
methods is one directory junction double-counting 2,142 alias paths that all land on files the
gate's own walk already read, so it is **not** a coverage gap; and all 4,715 files read today report
`PROTECTED=0` with 0 ACL errors. 490 `__pycache__` files carry a write time later than the
installer's last non-`__pycache__` write, which places the gate's `4285` inside that first-import
burst — the honest limit being that the run log carries no timestamp, so the placement is derived
from file times, not measured. **No product defect and no ticket ride on this**: the gate's coverage
is sound and its number is a moment.

**PAIRED HALF — NOT RUN.** What still belongs to this cell is the standard-user readability check:
one `Get-Content` of an installed file typed by `venyastd` at the guest's own unelevated console. It
is an owner act at the desk and it is held there, not here. The `PROTECTED=0` reads above are
evidence about DACLs, and are named as corroboration — they are not that read. The guest preflight
and the #628 history follow.

> the shipped installer aborts at `install-venya-cli.ps1:163` (`uv.exe missing after
> extraction`) when `VENYA_INSTALL_DIR` contains PowerShell wildcard characters, because that
> check uses `-Path` semantics while #493's fix covered only the ACL-gate enumeration; filed
> as #628, whose fix merged at `664f267`; the sentence above is history — the gate messages have
> since been observed executing, once in the installer itself (the PASS line) and twice in a harness
> (the zero-file refusal and the protected-DACL refusal).

**Guest preflight (ran, rc=0; read-only, as `win` over SSH from the agent box):**

| Read | Result |
|---|---|
| `whoami` / `hostname` | `win11\win` / `win11` |
| `$PSVersionTable.PSVersion` | `5.1.26100.9444` |
| `(Get-Command venya).Source` | `C:\Program Files\Venya\bin\venya.exe` |
| `venya --version` | `0.1.0alpha16` |
| `Get-LocalUser venyastd` | present |
| `Test-Path ~\.venya\config.json` | `False` (no CLI config in the `win` profile) |
| `$env:VENYA_ADMIN_CERT` | empty |

- **Surface under test:** the protected-DACL enumeration and its counters in
  `install-venya-cli.ps1:246-283` (cites re-anchored at `dev` `664f267`, which is where the run
  below was made) —
  `Get-ChildItem -LiteralPath $Base -Recurse -Force -File` (`:260`), `Get-Acl -LiteralPath`
  (`:262`), the `$protected` / `$verified` / `$notChecked` counters (`:253-255`, `:263-266`),
  and the report lines at `:271`, `:277`, `:280` and `:282`.
- **Shape:** run the machine-wide install **elevated**, in an Administrator terminal, with
  `VENYA_INSTALL_DIR` pointed at a path that contains PowerShell wildcard characters — a
  bracketed directory name is the shape that made the old positional `-Path` bind nothing.
  The install is elevated **by design**, not as a workaround: Windows refuses junction
  traversal by a Medium-integrity process while `uv` needs a junction for its Python alias,
  so the install takes the admin token and only the *use* is unelevated — "Install =
  elevated, use = unelevated, and that is by design" (the Windows venue law 4, `ad2c2ab`; the
  same split is in [installation.md](installation.md): "Elevated **install**, unelevated
  **use**"). The installer says so itself — it refuses an unelevated run outright at
  `install-venya-cli.ps1:83-91` ("Administrator rights are REQUIRED to install the Venya CLI
  on Windows", the same junction reason). The standard-user half of this cell is therefore its
  paired assertion: it is proven **after** the install, at `venyastd`'s own console in a
  non-elevated terminal, that the installed files are readable there.
- **Run it this way:**

  ```powershell
  # elevated PowerShell on the guest (`win`), from the box that serves the tarballs:
  $env:VENYA_SKIP_PROMPT      = "yes"
  $env:VENYA_INSTALL_DIR      = "C:\temp[gate]"
  $env:VENYA_TARBALL          = "http://$BuildHost:8080/venya-cli-install.tar.gz"
  $env:VENYA_TARBALL_SHA256   = "$CliSha"
  # after the install succeeds, prove readability AS venyastd at ITS OWN console (unelevated):
  #   Get-Content "C:\temp[gate]\bin\venya.exe" -TotalCount 1
  ```

  **Neither value is written here, on purpose — derive both at use time.** `$BuildHost` is
  your installer host's serve root: the `:8080` docroot the tarballs were built into. `$CliSha`
  is the hash in the `<tarball>.sha256` sidecar lying beside that tarball, read the way it is
  read anywhere — `cut -d' ' -f1 venya-cli-install.tar.gz.sha256`. A served hash changes with
  every build, and an address written into a page goes stale the first time the server moves.
  This is the same derivation [full-lifecycle-test.md](full-lifecycle-test.md) already uses
  (`http://$BUILD_HOST_IP:8080/<tarball>` with `VENYA_TARBALL_SHA256=$CLI_SHA`), and it is not
  optional here either: on an `http` origin the installer **requires** that hash and aborts
  before any fetch or write without it (#375, #328).
  `venya.exe` is the install-root `bin` shim; the paths under `VENYA_INSTALL_DIR` are what the
  gate enumerates.
- **Success:** the run prints `ACL check passed: N file(s) enumerated and ACL-read, 0
  protected DACLs` with **N greater than zero**, and the installed files are readable by a
  standard user afterwards.
- **Paired rejection (what must FAIL) — driven in a harness; see the arms paragraph above for
  which of these three has been observed printing its own line and which has not.**
  1. a run that enumerates zero files under an existing `$Base` must print
     `ACL check could not verify any file: 0 file(s) enumerated … Refusing to report a pass`
     and exit 1 — a gate that read nothing must never read as a pass
     (`install-venya-cli.ps1:275-277`; **observed printing this line, in a harness, exit 1**);
  2. any file whose ACL reports `AreAccessRulesProtected` must fail the install with the
     shipped message naming `--link-mode copy` as the likely cause
     (`install-venya-cli.ps1:270-271`; **not yet observed** — the scenario that reached this arm
     never applied a protected DACL);
  3. an item that errors during enumeration or ACL-read must be disclosed as
     `ACL check INCOMPLETE: N item(s) … NOT checked`, not counted as verified
     (`install-venya-cli.ps1:279-280`; **not yet observed** — same reason, and a deny-on-read
     file does not fail an elevated `Get-Acl`, so the scenario needs to break enumeration).
- **Why this cell is not optional:** the `--link-mode copy` posture is what keeps hardlinked
  files from inheriting the installing administrator's security descriptor, and this gate is
  the only thing standing between a silent revert and an install standard users cannot read.

### Cell 2 — the ceremony from an interactive desktop

**RUN, PASS (s124, session 2).** Evidence `8c73fc0c`; report
`wave27-specs-20261015/ultra-rf8-cells23-s124-report.md`; target **core-3**, identity
**`venya-adm3`**; verdict carried by the lead's scorecard row at `3aaeb169`.

The two blockers this cell carried are **spent, and both were owner acts, not code work**:

1. the installed CLI. The preflight under Cell 1 read `C:\Program Files\Venya\bin\venya.exe` at
   **`0.1.0alpha16`**, a build with **no `admin cert` group** — `venya admin cert status` failed
   at the parser with `invalid choice: 'cert'`, so the surface this cell renews did not exist in
   the installed artifact (it is in the source: the `admin cert` group inside `create_parser`,
   `packages/cli/src/venya_cli/cli.py:481`, verified at `dev` `f0a2c3a`; re-derived at `dev`
   `59cf8ef`, where the `# admin cert — the readout …` group comment sits at `cli.py:483`, the
   pin having drifted by two lines). A current CLI has since
   been installed on the guest, which is the owner's act on every box;
2. the key was not attached to the domain and no person was at its console. Both have been
   supplied for this run.

**The owner acts this cell needed — attach the key, install a current CLI, be at that machine's
console — have all been performed.** They stay owner acts: no lane can do any of them, and a
re-image or a new core index puts them back on the list.

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

**RUN, PASS (s124, session 2).** Same evidence as Cell 2 — `8c73fc0c`, report
`wave27-specs-20261015/ultra-rf8-cells23-s124-report.md`, target **core-3**, identity
**`venya-adm3`** — and the same spent blocker: the read-below-and-renew-above sequence this cell
measures needs `venya admin cert status`, which the `0.1.0alpha16` build on the guest did not
carry (parser error quoted under Cell 2). It runs on the current installed CLI.

- **Success:** `venya admin cert status` before → renew at the console → `status` after shows
  a lifetime inside the committed hour, and the ceremony's refusal order holds: with no login
  session, renew refuses and sends nothing; with `VENYA_ADMIN_CA_KEY_PASSPHRASE` unset or
  shorter than 15 characters, renew refuses BEFORE any key touch.
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
