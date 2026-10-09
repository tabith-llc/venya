# Design note: secure memory for the KEK (GitLab #472)

Status: DESIGN NOTE ONLY -- no product code accompanies this file. The code leg and #538 are
built from this document. Any point marked OPEN is not decided here; those points belong to the
owner.

Verified against: `venya-dev` `dev` tip `7b22d78` (branch base for this note). Line numbers in
this file were re-grepped against that tip, not copied from a plan document. Where this note
cites a measurement, the measurement block is section 11.

Ruling this note implements: #472 note `3971383458` (owner, 2026-10-07) -- "IMPLEMENT, design
note first, reviewed, then the leg". Bar carried here: scoped read-only view, one owner for the
KEK cache, released buffer raises, objective zeroization attempt, startup log naming the ACTIVE
protections, the capability-isolation test REWRITTEN (never deleted), pinning attempted-and-
reported and never fatal, no pinning claim until physically proven on a served VM, and the
security ladder recorded as design items.

---

## 1. Where the KEK lives

**Ruled: a protected buffer, held by one owner, with a scoped read-only view for readers.** The
stored form of the KEK changes from an immutable `bytes` field to a `SecureBuffer` (the existing
type in `packages/core/src/core/engine/secure_memory.py`). No reader ever receives the buffer.

Rejected alternative -- re-derive on use:
- `derive_kek` is Argon2id with the shipped parameters (`time_cost=3`, `memory_cost=2**16` KiB,
  `parallelism=4`; `packages/core/src/core/engine/encryption.py:22-26`). One call measured
  48.5 ms in this venue (measurement [A]). The secret-read paths call unwrap once per secret, and
  the filter route decrypts per bound secret (`packages/server/src/server/routes/filter.py:245`
  loop, decrypt at `:263`), so per-use derivation costs whole seconds on a normal request.
- Worse: derivation needs the PASSPHRASE resident, which is strictly more sensitive than the KEK
  and is not protectable by this mechanism -- `argon2.low_level.hash_secret_raw` rejects
  `bytearray`/`memoryview` input (measurement [H]), and the passphrase arrives from pydantic
  config as an immutable `str`. Re-derivation moves the resident secret from a 32-byte derived
  value to the operator's actual passphrase.

Rejected alternative -- keep `bytes` and just scrub at shutdown: Python `bytes` cannot be erased
(immutable), so there is no objective zeroization attempt. The module's `secure_zero` writes
through a `bytearray` (`secure_memory.py:87`), which is the only shape that satisfies the ruling.

**Single owner.** `core.engine.secure_memory` gains one cache type -- written as
`KekCache` -- and the `Backend` holds exactly one instance of it.
- Intake: `BackendConfig` keeps a `kek` FIELD ONLY as a write-once intake slot
  (`packages/core/src/core/engine/backend.py:176`, and the raw-KEK intake at
  `packages/core/src/core/engine/factory.py:85-94` `with_kek`). On `Backend` construction the
  intake value is copied into the cache and the intake slot is cleared to `None`. After that
  point nothing reads `config.kek`; `filter.py:254` and `app.py:247` become cache readers.
- Population: `Backend.bootstrap_kek()` (`backend.py:287-323`, current cache write `:317`)
  fills the cache instead of the field. It remains the only derivation point; the C-11 rule
  (persisted salt, deterministic across restarts, `backend.py:172-175`) is unchanged.
- Consumers that currently hold a `bytes` copy must stop: `Core.__init__` (`core.py:72-76`
  `self.kek = kek`) becomes a reference to the cache, and the three guards
  (`core.py:301`, `:562`, `:586`) become "is the cache populated" instead of "is this None".
  `CoreFactory` likewise (`factory.py:28`, `:94`, `:107-112`, `:123` -- including the comment at
  `:110` "populates backend.config.kek", which the code leg updates).

**Lifetime: process.** One `Backend` is built in the server lifespan
(`packages/server/src/server/app.py:323` `init_db`) and disposed at shutdown (`app.py:443-444`,
`shutdown_backend.dispose()`). The cache's release point is `Backend.dispose()` -- an existing,
already-wired hook, which is why release does not need a new lifecycle concept. Release runs at
process exit only, never per request, never per session.

## 2. The reader contract

**Ruled: `with cache.view() as kek: ...` -- a read-only memoryview, valid only inside the block.**

- The cache exposes exactly one way to get key material: a context manager that yields
  `memoryview(buffer).toreadonly()`. It never returns `bytes` and never returns the
  `SecureBuffer` (owner's bar: the buffer itself is never handed to readers).
- Consumers widen their parameter type to `bytes | memoryview` and otherwise do not change:
  `wrap_key` (`encryption.py:74`), `unwrap_key` (`:95`), `encrypt_secret` (`:116`),
  `decrypt_secret` (`:145`), `ensure_kek_sentinel` (`backend.py:84`), `verify_kek_sentinel`
  (`backend.py:108`), and the two server readers (`filter.py:263`, `app.py:253`).
- This is not hypothetical: both crypto back-ends accept a read-only memoryview as the key.
  `ChaCha20Poly1305(mv)` and `AES.new(mv, ECB)` both work, and a full
  `wrap_key`/`unwrap_key` round trip through a read-only view is equal to the `bytes` result
  (measurement [B]). The existing length guards in `wrap_key`/`unwrap_key`
  (`encryption.py:87-88`, `:108-111`) operate on `len()`, which a memoryview answers correctly.
- The one call site that must be watched is the AES-KW loop: `AES.new(kek, MODE_ECB)` is created
  per round inside `_aes_kw_wrap`/`_aes_kw_unwrap` (`encryption.py:197`, `:242`), and the
  measurement covers the same view shape there (`[B]`).
- `derive_kek` is the one deliberate exception: its passphrase argument stays `bytes`, because
  the Argon2 binding rejects buffer objects (measurement [H]). The KEK it returns is copied into
  the cache immediately and is not otherwise retained.
- Views are not stashable. The code leg adds a cell asserting a view obtained outside the block
  cannot be used: after `release()` the same object raises `ValueError` from CPython
  (measurement [C]) and the accessor raises our own error first (section 3).

## 3. Touching a released buffer MUST RAISE

**Ruled: `SecureBufferReleasedError(RuntimeError)`, raised in exactly one place.**

- Name: `SecureBufferReleasedError`, defined in `secure_memory.py`, subclass of `RuntimeError`.
- The ONE raise site: `KekCache.view()` (the only accessor that hands out key material), when the
  cache is released or was never populated. Nothing else raises it. Subclasses are not permitted
  under `EncryptionError` on purpose -- see the negative below.
- Why not an `EncryptionError`/`DecryptionError` subclass: those are swallowed by the two existing
  handlers on the key paths -- `backend.py:127` (`except EncryptionError`) and
  `filter.py:264` (`except DecryptionError`). A release error of that family would be read as
  "wrong passphrase" and turn a bug into a quiet wrong verdict.
- The failure this prevents, stated plainly. After `clear()` the buffer reads as 32 zero bytes.
  A zero KEK is a perfectly valid AES-256 key: `unwrap_key` fails with a wrong-key
  `DecryptionError` (measurement [D]), but `wrap_key` SUCCEEDS and produces a 40-byte envelope
  bound to a key nobody holds (measurement [E]). So a silently-released cache would keep the
  service green while making every secret written after that moment undecryptable, and would
  report existing secrets as a passphrase mismatch. This is the exact mission risk the ruling
  names, and it is why the accessor raises rather than returning zeros.
- What proves it cannot happen to a live install:
  1. Release has one caller (`Backend.dispose()`), which runs after the lifespan `yield`, i.e.
     after the server stops serving (`app.py:433` yields, shutdown at `:443-444`). No request
     path can reach a released cache.
  2. The accessor raises before any bytes leave the cache, so no request can observe zeros even
     if (1) were broken.
  3. The boot-time sentinel is the existing belt and stays as it is: the resident KEK must unwrap
     a fixed known plaintext (`SENTINEL_KEY` / `SENTINEL_PLAINTEXT`, mint at
     `backend.py:84-105`, verify at `backend.py:108-141`, boot abort at `app.py:229-277`).
     A cache holding the wrong key therefore fails at startup, not at first customer read.
  These `kek_sentinel` shapes are also the precedent for decision 4 and for the code leg's own
  style: idempotent get-or-create, one row, `IntegrityError` means the winner already stored the
  equivalent value, value-free constants (`backend.py:56-63`).

## 4. Zeroization

**Ruled: best-effort attempt on release, and the attempt is reported, not assumed.**

- Where: `KekCache.release()` calls `SecureBuffer.clear()` -> `secure_zero(buffer)`
  (`secure_memory.py:87`, per-byte writes through the `bytearray` at `:98-100`), then attempts
  `secure_munlock` (`:62`) and ignores unlock failure the way `__exit__`/`__del__` already do
  (`:197-218`). Trigger points: `Backend.dispose()`, and `__del__` as a backstop only.
- Observable afterwards, and only this much: `is_zeroed` is true, the view accessor raises, and
  one log line records `zeroized=yes` plus the munlock outcome with its errno. Nothing in the
  process claims that key material is gone from the machine.
- Stated limits (all three are real, none are fixed by this leg):
  1. `secure_zero(memoryview)` is currently a SILENT NO-OP -- it returns without touching the
     buffer (`secure_memory.py:96-97`; measurement [F]). The code leg makes that raise
     `TypeError` instead of returning; a zeroizer that quietly does nothing is worse than no
     zeroizer, because the log would claim `zeroized=yes`.
  2. Immutable inputs are not erasable by us: the `bytes` returned by `hash_secret_raw`, the raw
     intake bytes from `with_kek`, and the passphrase `str` from configuration. Residual copies
     live until CPython collects them.
  3. C-level key material inside the crypto libraries is unreachable: `AES.new(...)` builds an
     internal key schedule per call, and it is created inside the AES-KW loop
     (`encryption.py:197`) -- we cannot zero or pin that copy from Python.
- GC-timing honesty: `__del__` is not a guarantee (reference cycles, interpreter teardown), which
  is why the explicit `dispose()` path is the primary mechanism and `__del__` is only a backstop.
- Two docstring inaccuracies in this module are corrected by the same changeset that wires it (the
  ticket names the false-protection claim as half the defect):
  1. the module docstring (`secure_memory.py:9-13`, the claim at `:11-12`) says mlock is used
     only in the core package, where secrets reside in trusted memory -- that becomes true only
     once the KEK cache exists. Leave the claim, make it true, do not soften it;
  2. `secure_zero`'s docstring (`secure_memory.py:90-91`) says "Uses ctypes to write zeros
     byte-by-byte" -- the implementation is a plain Python loop over `data[i] = 0` (`:98-100`), no
     ctypes. The docstring must describe the mechanism actually used.

## 5. Pinning policy

**Ruled: attempted and reported, NEVER fatal. Docs stay at "erased, not pinned" until a served VM
proves otherwise.**

- Attempt: the cache is created with `mlock=True` and the outcome is captured, not propagated.
  On failure the cache still works (unpinned, erasable) and startup continues. Raising here would
  break the core on hardened, containerised or memory-limited hosts -- the ruling forbids that.
- Startup log line, one line, naming what is ACTIVE on that host. Required forms (mechanism, not
  poetry; no key material, no passphrase, following the "never logs" rule at
  `app.py:241-243`):
  - pinned:   `kek cache: pin=active (mlock <n> bytes, page-rounded to <p> KiB, budget <b> KiB)`
  - unpinned: `kek cache: pin=inactive (mlock failed errno=<e> <text>) -- key material is
    erased on release but NOT pinned; grant CAP_IPC_LOCK or raise the locked-memory limit`
  The failure branch must be the actionable one: an operator reading the journal can tell which
  protection they have and what to change.
- Sizing constraint, and it is a real constraint. A served core runs with
  `Max locked memory 8388608 8388608 bytes` (8 MiB, live `/proc/<pid>/limits`, section 10).
  mlock cost is page-rounded: pinning the 32-byte KEK pins a full 4 KiB page. Measurement [I]:
  32 B, 4 KiB and 64 KiB locks succeed, and a request for exactly the whole 8 MiB budget fails
  `ENOMEM`. So: pin fixed small key buffers only (the KEK: one page). Pinning per-request data
  buffers, or one buffer per bound secret, is a budget plan, not a free flag, and any such
  extension needs its own sizing arithmetic in the leg that adds it.
- Never resize a pinned buffer. `SecureBuffer.write` uses equal-length slice assignment
  (`secure_memory.py:177`), which keeps the buffer address (measurement [G]); a resize may move
  it and silently un-pin the key while the cache still reports `is_locked`. The code leg adds a
  cell that a write of a different length raises instead.
- What pinning does NOT do: it is a swap defence. It does not stop a same-uid `ptrace`/
  `/proc/<pid>/mem` reader, and it does not stop the page being written into a core dump or a
  hibernation image. Those belong in the ladder (section 7), and the docstring for
  `secure_memory.py` must not imply more than "not swapped, and erased on release".

## 6. The isolation-test rewrite (a rewrite, not a deletion)

`packages/core/tests/test_capability_isolation.py` today asserts the module is NOT used --
`test_only_secure_memory_uses_mlock` (`:101`) scans every `core.engine` submodule for the symbol
set `{secure_mlock, secure_munlock, secure_zero, SecureBuffer, _load_system_lib}` (`:105`), plus
per-module cells: `test_core_class_does_not_use_secure_memory` (`:121`),
`test_backend_does_not_use_secure_memory` (`:132`), `test_encryption_does_not_use_secure_memory`
(`:143`), `test_rate_limiter_does_not_use_secure_memory` (`:154`),
`test_factory_does_not_use_secure_memory` (`:165`), and the three IAM cells (`:176`, `:187`,
`:209`). Two more stay as they are: `test_cli_does_not_import_secure_memory` (`:81`) and the
module-export cells (`:291`, `:299`).

After the change the assertions become:

1. **Allowlist with teeth.** The module-wide scan keeps running, but against an explicit
   allowlist of exactly two files: `secure_memory.py` (the primitives) and the cache owner.
   Anything else in `core.engine` naming `SecureBuffer`, `secure_mlock`, `secure_munlock` or
   `secure_zero` fails. The count of allowlisted files is asserted, so adding a third protected
   buffer is a deliberate edit to a test, not an accident.
2. **Direct-call ban stays.** `backend.py`, `core.py`, `encryption.py`, `factory.py`, the rate
   limiter and the IAM modules must still not call `secure_mlock`/`secure_zero` directly -- they
   go through the cache. The nine per-module cells are kept in this form (they do not become
   vacuous).
3. **Positive cell.** The protected path IS used for the KEK: after `bootstrap_kek()`, the cache
   reports a populated buffer, `config.kek` intake is `None`, and a reader gets a read-only
   memoryview. Paired with decision 1, this is the cell acceptance criterion 2 asks for.
4. **Paired negatives (the truth-table rule).** Release then view raises
   `SecureBufferReleasedError`; an unpinned cache (mlock mocked to fail with `EPERM`) still
   serves and still zeroizes; a wrong-key cache fails the sentinel at boot rather than serving;
   `secure_zero(memoryview)` raises instead of returning; a different-length `write` raises.
   Plus the existing "mlock failure stays graceful in the context manager" shape (`:63-80`).
5. **Capability cells stay, and get fixed.** `test_systemd_unit_has_cap_ipc_lock` (`:397`),
   `test_systemd_unit_no_cap_ipc_lock` (`:412`), `test_executor_no_bounding_caps` (`:426`) remain.
   All three of these, plus the two runtime cells (`test_core_running_has_cap_ipc_lock` `:437`,
   `test_executor_running_no_cap_ipc_lock` `:449`), are dead as written on every host:
   - the path finder (`:347-355`) walks a list with `/etc/systemd/system/...` first and
     `/lib/systemd/system/...` last, and OVERWRITES on each match without an existence check, so
     the `/lib` path always wins; the installer writes `/etc` (`install-venya-core.sh:1076`), and
     `_parse_unit_file` (`:328-345`) returns an empty dict for a missing file
     (`FileNotFoundError: pass`). Net effect on a correctly installed core: the positive cell
     (`:397`) reads a file that does not exist, sees no directives, and SKIPS -- it can never
     pass; and both executor negatives (`:412`, `:426`) read the same missing file, get an empty
     dict, and PASS VACUOUSLY. A grant added to `/etc/systemd/system/venya-executor.service`
     tomorrow would not be caught by either of them. That is the truth-table failure mode: the
     negative half checks nothing. (The served-VM outcome above is DERIVED from this code path --
     `/etc` is the install target (`install-venya-core.sh:1072` defines
     `SYSTEMD_DIR="/etc/systemd/system"`) and `/lib` is never written by the installer -- not
     observed on a VM in this leg.)
   - the runtime helper (`:358-376`) runs `pgrep -u <user> -x venya-core`, passing the SERVICE
     name as the USERNAME, while the unit uses `User=venya` and the process is `venya-server`
     (`systemd/venya-core.service:7,9`); `pgrep` on a non-existent user exits 2 (measurement [K]),
     so the pid lookup never succeeds and the cell skips.
   Observed in this venue: `pytest packages/core/tests/test_capability_isolation.py -rs` gives
   20 passed, 3 skipped, and the skip reasons are exactly these paths (`:407` "has no
   AmbientCapabilities", `:441`/`:453` "service is not running"). This matters for ruling item 5
   ("no pinning claim until physically proven"): the suite has never proven it, and no green run
   of this file can be read as proof. The code leg fixes the finder (prefer the path that
   EXISTS, `/etc` ahead of `/lib`, and FAIL rather than skip when the unit is installed but
   unreadable) and the helper (`pgrep -u venya -x venya-server`) so the cells can pass or
   FAIL for the right reason.
6. **The CLI half is unchanged.** `packages/cli/tests/test_capability_isolation.py` keeps
   forbidding `core.*` imports outright (`:25-36`) and secure-memory symbols in `venya_cli`
   sources (`:38-45`). The CLI must not import this module to get the contract (section 8).

## 7. The ladder beyond this rung (recorded design items -- NOT this leg)

1. Crash-dump and core-pattern policy: `MADV_DONTDUMP` on pinned pages, or
   `PR_SET_DUMPABLE=0`, or `kernel.core_pattern` to nothing on the core host. Today a pinned page
   can still land in a core dump.
2. Swap/hibernation policy for the core host: disable swap, or pin-and-forbid-hibernation, so the
   statement "not swapped" is a host property, not just a syscall. Related to this: the core's
   locked-memory budget (`Max locked memory` 8 MiB) is a host default the deployment guide should
   name.
3. OS keyring / hardware-backed storage for the passphrase itself (the residual named in
   section 4.2). This is the rung that addresses the `str`-shaped passphrase, which Python cannot
   erase.
4. A FIPS-validated crypto module in place of `pycryptodome` AES-KW + `cryptography`
   ChaCha20Poly1305 (`encryption.py:177-255` is hand-written RFC 5649; the loop re-creates the
   AES object per round at `:197`).
5. Anti-`ptrace` posture (`PR_SET_PTRACER`, or a seccomp rule) -- mlock does not defend against a
   same-uid reader.
6. Pinning more buffers (per-DEK scratch, filter-path plaintext) only with the budget arithmetic
   of section 5 done per addition.
7. The passphrase-to-KEK intake on the CLI/CA plane (#537/#538 cluster) -- same shape, different
   process and trust location.

## 8. What #538 consumes (one paragraph, so it does not invent a second contract)

#538 (`cli-ca-key-export-plaintext-process-memory`) consumes the SAME interface, not a new one:
one owner object holds exactly one `SecureBuffer` of the secret; every reader obtains key
material only through a scoped read-only `memoryview` accessor; that single accessor is the only
place a released/empty state raises `SecureBufferReleasedError`; zeroization runs best-effort at a
defined release point in the object's own lifetime, and the attempt is logged as an outcome
(`zeroized=yes|no`, `pin=active|inactive` with errno), never as an assumption; and pinning is
attempted-and-reported, never fatal. The placement question is #538's own and is a design choice
for that leg, not an owner question: the CLI is standalone and forbidden from importing `core.*`
(`packages/cli/tests/test_capability_isolation.py:25-36`), so the contract reaches that process
either as a second small module inside `venya_cli` or as a shared distribution -- either way the
interface above is the one contract, and the CLI's isolation cells stay exactly as they are.
Expectation that must also be written down there: a workstation CLI has no systemd unit and no
`CAP_IPC_LOCK` grant, so in that process pinning is expected-inactive, and only the erasure half
of the contract is what #538 actually buys.

## 9. Test plan for the code leg

Unit cells (core package unless stated), each with its paired negative:

| # | Cell | Negative half |
|---|------|---------------|
| 1 | `bootstrap_kek` fills the cache; `config.kek` intake is cleared to `None` | second `bootstrap_kek()` call does not re-derive or re-fill (persisted-salt path, C-11, unchanged) |
| 2 | `cache.view()` yields a read-only memoryview; wrap/unwrap round trip equals today's `bytes` result | view used after release raises `SecureBufferReleasedError`; assigning through it raises |
| 3 | release zeroes the buffer and reports it (`is_zeroed`, log fields) | a mocked `secure_zero` failure does not report `zeroized=yes` |
| 4 | `secure_zero(memoryview)` raises `TypeError` (fixes the silent no-op) | `secure_zero(bytearray)` still zeroes (existing behaviour) |
| 5 | mlock failure is non-fatal: unpinned cache still serves, log line names errno | existing graceful-context shape, `test_capability_isolation.py:63-80`, stays green |
| 6 | pin success path reports `pin=active` with page-rounded cost | `wrap_key` under an all-zero cache raises rather than producing an envelope (guards decision 3) |
| 7 | different-length `write` on a locked buffer raises (no silent un-pin) | equal-length write keeps the address and the lock |
| 8 | isolation allowlist (section 6.1) -- exactly two files may name the primitives | every other `core.engine` module, all IAM, the rate limiter, `encryption.py` fail the scan |
| 9 | `Core` guards: unpopulated cache -> the existing `CoreError("KEK not configured")` (`core.py:301,562,586`) | the sentinel boot check on a wrong-key cache aborts (`app.py:229-277` shapes) |
| 10 | capability + runtime cells fixed (section 6.5) so they can actually pass or fail on a served VM | executor negatives must FAIL when `/etc/systemd/system/venya-executor.service` carries `AmbientCapabilities=CAP_IPC_LOCK` (today they pass vacuously); executor runtime CapEff must NOT include bit 14 (`:449`, now reachable) |
| 11 | behaviour-preservation: `encrypt_secret`/`decrypt_secret`/`wrap_key`/`unwrap_key` envelope bytes unchanged for the same key and IV | a tampered envelope still fails closed (`DecryptionError`) |

Acceptance-criterion 4 of the ticket is carried by cell 11 -- the wire format does not change, so
stored envelopes on served installs remain readable; that is also why this leg has no migration.

Suites to run when the code leg lands: `core`, `server`, `mcp`, `cli`, `contract`, `executor` --
the widening of `wrap_key`/`unwrap_key` types is a cross-package surface, and the reference counts
in the repo workflow rules apply (unexplained delta at any gate = STOP).

**Physical cell -- DESIGN ONLY, DO NOT RUN in this leg.** On a served VM (venya-core-N, installed
from the tarball, `systemd` unit `venya-core.service`): restart the service, then read the journal
for the cache line and require `pin=active`, and confirm the grant and budget out of band --
`grep CapEff /proc/<pid>/status` shows bit 14, `/proc/<pid>/limits` shows `Max locked memory`
8388608, and `/proc/<pid>/smaps_rollup` shows a non-zero `Locked:` line for the pinned page.
Only that journal line + that `/proc` pair satisfies ruling item 5.
Until then, every doc says "erased, not pinned" (section 5).

## 10. Correction to ruling item 2 -- the capability grant ALREADY exists

Ruling item 2 (note `3971383458`) states that no `CAP_IPC_LOCK` grant exists today, so wiring
alone would yield "erasure-without-pinning". **That premise is false as written, and was corrected
by the lead on 2026-10-07 before this note.** The grant exists and works on served installs; the
missing half is the CALLER. Reproduced here so the code leg does not design an installer change:

- `venya-dev/systemd/venya-core.service:19` -> `AmbientCapabilities=CAP_IPC_LOCK`, with the
  comment at `:18` ("mlock requires CAP_IPC_LOCK"). Re-verified in this venue at `7b22d78`
  (grep: line 7 `User=venya`, line 9 `ExecStart=/opt/venya/.venv/bin/venya-server`, line 19 the
  capability).
- `install-venya-core.sh:1076` installs THAT unit verbatim
  (`sed "s|VENYA_ENV_DIR=/opt/venya|..." "$INSTALL_DIR/systemd/venya-core.service" >
  "$SYSTEMD_DIR/venya-core.service"`), after a delete-then-create at `:1075` and with `chmod 600`
  at `:1077`. So served installs carry the grant from the shipped unit.
- Live on venya-core-1 (pid 3521, user `venya`): `CapEff: 0000000000004000` = CAP_IPC_LOCK
  (bit 14) PRESENT; `/proc/3521/limits` -> `Max locked memory 8388608 8388608 bytes` (8 MiB).
  (Lead-verified live evidence, quoted from the assignment spec; not re-run in this leg -- fleet
  VMs are out of scope here.)
- `systemd/venya-executor.service:28` -- the executor deliberately has NO such grant
  ("Executor must NOT have CAP_IPC_LOCK -- jump host is untrusted"). The isolation rule holds and
  is not touched by this design.

Consequences the code leg must honour:
1. No installer or unit-file capability change is in scope. Any such change is owner-ok-gated and
   would need its own ruling; the note does not propose one.
2. The 8 MiB `RLIMIT_MEMLOCK` budget is the real sizing constraint on what gets pinned
   (section 5), and there is no `LimitMEMLOCK=` in either unit (grep across the tracked tree
   returns nothing).
3. The "erased, not pinned" under-claim is about PROOF, not about the grant: the grant is there,
   the pinning has never been observed on a served VM, and the runtime test that would have
   observed it silently skips (section 6.5). Ruling item 5 still binds.
4. Ruling item 2's authorisation of a core-only grant therefore needs no action -- it is already
   the shipped state.

## 11. Measurements (mechanism of verification, not result)

All run in the assigned venue (`work3`, branch base `origin/dev@7b22d78`) with the venue's own
interpreter (`.venv/bin/python`, the workspace venv), against the shipped constants. No product
binary was exec'd, no fleet VM touched.

| ID | Measurement |
|----|-------------|
| [A] | `derive_kek(passphrase, salt)` = 48.5 ms per call at the shipped Argon2id parameters |
| [B] | `wrap_key`/`unwrap_key` and `ChaCha20Poly1305`/`AES.new` all accept `memoryview(bytearray).toreadonly()`; wrap/unwrap round trip through such a view equals the `bytes`-key result; `encrypt_secret`/`decrypt_secret` too |
| [C] | Using a released memoryview raises `ValueError: operation forbidden on released memoryview object` |
| [D] | `unwrap_key` with an all-zero 32-byte key raises `DecryptionError` (wrong key) |
| [E] | `wrap_key` with an all-zero 32-byte key SUCCEEDS and returns a 40-byte envelope |
| [F] | `secure_zero(memoryview(bytearray))` is a silent no-op -- the bytes are unchanged |
| [G] | Equal-length slice assignment on a `bytearray` keeps its address (so a lock survives an in-place overwrite) |
| [H] | `argon2.low_level.hash_secret_raw` rejects `bytearray` and `memoryview` (`TypeError`); accepts `bytes`, `list`, `tuple` |
| [I] | `mlock` from the venue interpreter: 32 B / 4 KiB / 64 KiB succeed; 8 MiB (the whole budget) fails `errno=12 ENOMEM` |
| [J] | `ulimit -l` = 8192 KiB in this venue -- matches the served `Max locked memory` value |
| [K] | `pgrep -u <nonexistent-user> -x venya-core` exits 2 (`invalid user name`) -- the runtime capability cells cannot find the service and skip; observed here: 20 passed, 3 skipped in `test_capability_isolation.py`, all three skips being the dead capability cells |

## 12. OPEN -- owner-owned, not decided here

Per the owner law ("any questions surrounding any of it need to be answered by me") these are
left as questions. Each is a CA-trust-material cluster question about product posture, and this
note stops at the question.

- **OPEN 1 (backup/export capability).** The protected-buffer contract says key material may be
  read only through a scoped view and never copied out. Does the owner want a supported export of
  KEK-protected material at all (operator-facing backup/export capability), or is export
  permanently limited to the CA-key envelope path in #538? This note does not assume either.
- **OPEN 2 (the restore story).** `docs/BACKUPS.md` pairs the database with `VENYA_DB__PASSPHRASE`
  and states, at `:39-43`, that "a mismatched passphrase does NOT fail at boot" and that failure
  surfaces only at first decrypt -- which the shipped sentinel check (`backend.py:108-141`,
  `app.py:229-277`) contradicts today. The note deliberately does not correct that document (docs
  outside this file are not this leg's deliverable) and does not design against it. Ruling
  needed: which is the product's promise -- boot-time abort, or first-use failure -- and which
  document carries it.
- **OPEN 3 (the admin-key `NoEncryption()` delivery).** Several paths serialize private key
  material with `serialization.NoEncryption()` -- `ca.py:966` (the server admin-CA key material),
  `at_rest_key.py:87` (the CLI unwrap-to-plaintext path #538 sits on), the CLI sites at
  `commands.py:1972` (`cmd_admin_cert_renew`, added by RF-8b), `commands.py:3092`
  (`executor_register`), `commands.py:3488` (`executor_cert_renew`), `commands.py:4562`
  (`cmd_admin_generate_admin_cert`), and the executor daemon at `daemon.py:711` (`register`) and
  `daemon.py:891` (`rotate`). Is unencrypted in-process/on-disk delivery of those keys an accepted
  posture, a defect to be fixed in the #537/#538 legs, or in scope for this protected-buffer
  contract? This note does not extend the contract to them.
  **Pin refresh (2026-10-09, AC4 of issue #547, re-derived at dev `262527d`) — cite these by SYMBOL,
  the line numbers above are a snapshot of that one tree and they have moved twice already.** Two
  changes since the original enumeration: the `cmd_admin_init_admin_ca` no-passphrase branch is NO
  LONGER one of these sites (it now refuses before any filesystem work, per the owner's ruling
  "match server. no passphrase? then no key"), and `cmd_admin_cert_renew` ADDED one. The count is
  therefore still eight. The renew site matches the documented posture of its neighbours and of the
  installer's own `admin.key` (`0600` inside `0700`, passphrase-free at rest by design, because the
  operator's login session -- not the file -- is the second factor for an admin leaf), so it is
  listed rather than ruled; whether ANY of the eight should move onto the protected-buffer path
  remains the open question above and is the owner's to answer.
