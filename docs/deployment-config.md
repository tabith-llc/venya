# Deployment Configuration Requirements

Critical configuration fields that must be set before deployment. Missing these values causes hard failure at startup.

---

## Required Fields

### `recovery_code_pepper`

**Config key:** `recovery_code_pepper` (top-level field; env `VENYA_RECOVERY_CODE_PEPPER`)

**Requirement:** MUST be set to a non-empty value. A wholly missing value fails with a Pydantic `ValidationError` when `ServerConfig()` is constructed in `create_app()`; an empty value fails unconditionally (not debug-gated) during `lifespan()` startup.

**Purpose:** Server-side secret used to hash break-glass recovery codes before storing them in the database. Without a pepper, recovery code hashes are vulnerable to rainbow table attacks — an attacker with database access can precompute hashes for common recovery codes and match them against stored values.

**Error on missing (empty value; verbatim from `app.py`):**
```
RuntimeError: Recovery code pepper must be configured. Set VENYA_RECOVERY_CODE_PEPPER
in /opt/venya/.env (installer input variable: VENYA_RECOVERY_PEPPER)
or config.recovery_code_pepper. Recovery codes without a server-side
pepper are vulnerable to rainbow table attacks.
```

**Generation:** Use a CSPRNG to generate at least 32 bytes of randomness, encoded as hex or base64:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Key rotation limitation:** Currently only one pepper version is supported. If the pepper is rotated, old recovery codes hashed under the previous pepper will no longer verify. Future key rotation will require storing multiple peppers and trying them during recovery code verification.

---

### `db.passphrase` (production only)

**Config key:** `db.passphrase` (env `VENYA_DB__PASSPHRASE` — note the DOUBLE underscore: `db` is a nested config section)

**Requirement:** MUST be set, in every mode. The missing-passphrase check in `app.py` is unconditional — the former `not config.debug` exemption was a dead letter and was removed (`ae35ae3`, 2026-09-20): `init_db()` constructs `BackendConfig` earlier in `lifespan()`, and that raises `BackendConfigurationError` on a missing passphrase before any request is served. There is NO unencrypted-storage fallback path.

**Purpose:** Passphrase used to derive the Key Encryption Key (KEK) for encrypting secrets at rest (envelope encryption: KEK wraps a per-secret DEK via AES-256-KW; values are ChaCha20-Poly1305).

**Error on missing (production; verbatim from `app.py`):**
```
RuntimeError: VENYA_DB__PASSPHRASE is not set.
Core secrets cannot be encrypted without a passphrase.
Set VENYA_DB__PASSPHRASE in /opt/venya/.env and restart
(installer input variable: VENYA_DB_PASSPHRASE).
```

**Length floor (the installer input `VENYA_DB_PASSPHRASE`, and this server key with it):** a supplied passphrase carries a minimum of **15 characters**. Below the floor the core refuses at boot: `BackendConfig` (`packages/core/src/core/engine/backend.py`, `MIN_PASSPHRASE_CODE_POINTS`) raises `BackendConfigurationError` with that refusal on the write door and on the read door. `install-venya-core.sh` asks the identical question of its `VENYA_DB_PASSPHRASE` input and refuses **before it mutates anything**, including a re-run that would reuse a stored value under the floor — repairing such an install is a deliberate reinstall, never a silent rotation. Unset, empty and whitespace-only are NOT this rule: they answer the earlier "was a passphrase supplied?" test as *not supplied*, so the length door never runs on a blank. The 64-character length is the value Venya guarantees to support and is not enforced as a maximum — a longer passphrase is accepted and used.

---

### `dns_resolver` (executor)

**Config key:** `dns_resolver` (top-level field on the EXECUTOR config; toml key `dns_resolver` in `/etc/venya/executor.toml`; env `VENYA_EXECUTOR_DNS_RESOLVER` — read only when the file does not carry the key. Precedence is `file > env > default`, see [Executor configuration precedence](#executor-configuration-precedence-file--env--default), #598)

**Requirement:** MUST be set to a valid IPv4 address. With no value the executor daemon **refuses to start** — the check runs in `ExecutorDaemon.start()` before registration, so the one-shot enrollment token is never consumed on a doomed boot. This is a named, loud failure by design (owner ruling D1 option (a): "Venya never guesses your network"); there is no built-in default.

**Purpose:** The DNS resolver IP that is always allowed for sandbox egress. Hostname targets resolve only when the hostname itself is listed in the egress allowlist — the sandbox DNS proxy authorizes per domain. Without the resolver the egress policy cannot be built, so the executor refuses to start.

**Error on missing (named ERROR log then `exit 1`; verbatim from `daemon.py` `start()`):**
```
dns_resolver is not configured — refusing to start: the sandbox egress policy cannot be built without it. The resolver IP is always allowed for sandbox egress; hostname targets resolve only when the hostname itself is in the egress allowlist. Set `dns_resolver` in /etc/venya/executor.toml — that file's value is the one this daemon uses whenever the file carries the key, including as an empty value; VENYA_EXECUTOR_DNS_RESOLVER in the service environment is read only when the file does not carry `dns_resolver` at all (precedence: file > env > default, #598; find your resolver: resolvectl status or grep nameserver /etc/resolv.conf).
```

The instruction names the file first because on an installer-served host the file carries this key, so the environment
spelling cannot win there — including in the empty-value case, where the daemon refuses to start *and* the env form is
inert at once. Before #598 the sentence offered the two spellings as equals, which was true only on a host whose file
omits the key.

**How to find the value:** `resolvectl status` or `grep nameserver /etc/resolv.conf`.

**Installer knob:** `VENYA_DNS_RESOLVER` (required on fresh installs; re-runs reuse the stored `/etc/venya/executor.toml` value).

---

## Configuration Loading

The server config is a pydantic-settings `BaseSettings` class (`packages/server/src/server/config.py`). There is NO TOML config file for the server (the inert `/etc/venya/server.toml` written by old installers is actively removed; the sole file source is the env file). Sources, in precedence order:

1. Process environment variables — format `VENYA_<SECTION>__<KEY>` (single underscore after the `VENYA` prefix, DOUBLE underscore between section and key; top-level fields use `VENYA_<KEY>`)
2. The env file `$VENYA_ENV_DIR/.env` (default `/opt/venya/.env`, written by the installer)
3. Field defaults (where defined)

Unknown `VENYA_*` names are silently ignored (`extra="ignore"`) — a misspelled var is a no-op, so verify names against `config.py`.

### Executor configuration precedence (`file > env > default`)

The executor plane is **not** the server plane: it has a TOML file, `/etc/venya/executor.toml`, and that file is the
first source. Ruled 2026-10-13 (#598); stated in code at `ExecutorConfig.from_file`, which passes the parsed TOML as
explicit init arguments — the position in `pydantic-settings`' own order that makes the file outrank the environment.

Sources, in precedence order, for the executor daemon:

1. **The config file** `/etc/venya/executor.toml` — for every key it carries.
2. **Process environment variables** — format `VENYA_EXECUTOR_<KEY>` for a top-level field, `VENYA_EXECUTOR_<SECTION>__<KEY>`
   for a field inside a table. One exception is pinned by the owner's RF-3 ruling: the concurrency group is reached as
   `VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS`, because that section's field carries an alias pair; the
   `VENYA_EXECUTOR_EXECUTOR__…` and `VENYA_EXECUTOR_MAX_CONCURRENT_COMMANDS` shapes are **not** read.
3. **A `.env` in the daemon's working directory** — read below the process environment (a relative `env_file`, so it
   is not `/etc/venya/venya-executor.env`, which is a systemd `EnvironmentFile` and therefore arrives as source 2).
4. **Field defaults**, where one is defined.

**A key carried by both the file and the environment is announced at every start.** One WARNING line per key, naming the
key, both sources and which one won, before any command is served:

```
Config precedence: dns_resolver: set in the executor config file AND in the environment, to different values — file > env > default, so the file value is in use and the environment spelling is ignored (#598)
```

The line names no values, because this plane's key classes include certificate and enrollment material and the line is
emitted by the daemon, where it lands in the journal. Two spellings that ask for the **same** value produce no line:
nothing is defeated in that case, and a warning on every boot is how a real one stops being read.

**What that means for an operator:** to change a setting on an installer-served executor, edit
`/etc/venya/executor.toml`. The `VENYA_EXECUTOR_*` spelling is the way to set a key the file does **not** carry — which
is the normal shape of a container or a hand-written unit override — and it will not override a key the installer
already wrote. Read the boot lines after a restart: if the daemon reports a precedence conflict for the key you just
set, the file still owns it.

| Key class | File wins? | Environment spelling the daemon reads | Announced when both are set |
|---|---|---|---|
| top-level field (`dns_resolver`, `log_level`, `server_url`, `sandbox_memory_mb`, …) | yes | `VENYA_EXECUTOR_<KEY>` | yes, one line per key |
| `log_level` when `--log-level` is also on the command line | no — the flag wins (the built-in default no longer counts as given, so an unset flag leaves the file in charge — #647) | `VENYA_EXECUTOR_LOG_LEVEL`, still read below the file | yes — when the file and the environment differ, one further line names the flag as the actual winner |
| key inside a table (`[mtls] cert`, `[audit] remote_url`, …) | yes | `VENYA_EXECUTOR_<TABLE>__<KEY>` | yes |
| `[executor] max_concurrent_commands` (RF-3) | yes | `VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS` — the aliased form only | yes |
| key the file does not carry | n/a | environment (then `.env`, then default) | no — nothing is being overridden |
| `injection_method` | n/a | not read from either source | n/a |

The concurrency knob above has a floor and **no** ceiling: the code refuses `max_concurrent_commands` below 1 at config
load (`ConcurrencyConfig._at_least_one_slot`, `packages/executor/src/executor/config.py`) and checks no upper bound at
all, so nothing in the executor stops a large value — the first real wall is the **core's** shared database pool, 5
connections plus 10 overflow, in a process the executor cannot see, and each relayed command in flight can hold one of
those 15 for as long as its own relay timeout allows (the relay route dials with `timeout=300`, so up to 300 seconds:
`execute_command_on_executor`, `packages/server/src/server/routes/executors.py`). Setting the knob above that wall does
not damage correctness; it moves latency and throughput, because would-be queries then wait on the pool instead of
running. Re-derive both numbers rather than trusting this sentence, which is a snapshot of the tree at your checkout:

```bash
# the core's shared pool: expect pool_size=5 and max_overflow=10 in _create_engine
git -C <venya-dev> show origin/dev:packages/core/src/core/engine/backend.py | grep -n 'pool_size=\|max_overflow='
# and that the executor carries no pool of its own: expect zero
grep -rn 'pool_size' <venya-dev>/packages/executor/src | wc -l
```

### Environment Variable Mapping (examples)

**Every row in this table is a core/server-plane field**, read by the core's `ServerConfig`
(`packages/server/src/server/config.py`) from the process environment under the `VENYA_` prefix with the `__` section
delimiter, or from `$VENYA_ENV_DIR/.env` (default `/opt/venya/.env`). None of them is an executor setting: the executor is
a separate plane with its own model (`ExecutorConfig`), its own file (`/etc/venya/executor.toml`) and its own prefix
(`VENYA_EXECUTOR_`), so setting one of these names on an executor box does not change the value recorded here. Two rows
read as executor settings and are not — mapped below the table.

| Config field | Environment Variable |
|-----------|---------------------|
| `recovery_code_pepper` | `VENYA_RECOVERY_CODE_PEPPER` |
| `db.passphrase` | `VENYA_DB__PASSPHRASE` |
| `db.database_url` | `VENYA_DB__DATABASE_URL` |
| `session.session_timeout` | `VENYA_SESSION__SESSION_TIMEOUT` |
| `fido2.enrollment_token_ttl` (minutes) | `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` |
| `fido2.user_verification` (discouraged\|preferred\|required) | `VENYA_FIDO2__USER_VERIFICATION` |
| `executor_enrollment.token_ttl_seconds` | `VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS` |
| `executor_enrollment.require_token` | `VENYA_EXECUTOR_ENROLLMENT__REQUIRE_TOKEN` |

`executor_enrollment.require_token` defaults to **true** (landed at `f1a6486`,
2026-09-20; the pre-GitLab ticket slug was `executor-rotation-require-token-400`,
which is **not** issue #400): `POST /api/v1/executors/register`
without a valid enrollment token is rejected 400. Setting it `false` restores open
enrollment — any host reaching the core can mint an executor identity (physically
proven); do not disable outside deliberately open test networks. Rotation interaction:
see `cert-rotation-runbook.md` §1 (tokenless `rotate()` is exempt for the verified
incumbent credential — clean revocation state plus serial == current record).
| `cors.origins` (JSON list) | `VENYA_CORS__ORIGINS` |

**Plane map for the two rows an operator misreads as executor settings:**

| Row above | What it actually is | Why the spelling misleads |
|---|---|---|
| `executor_enrollment.token_ttl_seconds`, `executor_enrollment.require_token` | **Core/server plane.** `ExecutorEnrollmentConfig` is a section of `ServerConfig`; it governs how the CORE admits executors (`POST /api/v1/executors/register`). | `VENYA_EXECUTOR_ENROLLMENT__*` is the core's `VENYA_` prefix plus the `EXECUTOR_ENROLLMENT__` section — not the executor's `VENYA_EXECUTOR_` prefix. The executor model has no `executor_enrollment` field; its own registration secret is the separate `bootstrap.enrollment_token`. |
| `session.session_timeout` | **Core/session plane.** A `ServerConfig` section field, enforced by the session manager (`core/iam/session_manager.py`) and the auth middleware (`server/middleware/auth.py`), both fed from `server_config.session` by `build_core_session_config` (`server/session_gate_config.py`). | **Core-only.** The executor plane carries no session fields: #620 removed them, so `VENYA_EXECUTOR_SESSION__SESSION_TIMEOUT` and a `[session]` block in `/etc/venya/executor.toml` are unknown keys that load and change nothing (`ExecutorConfig.model_config` uses `extra="ignore"`; pinned by `packages/executor/tests/test_config.py`, which asserts `not hasattr(cfg, "session")`). What an operator CAN set is the core spelling above — `VENYA_SESSION__SESSION_TIMEOUT` in the server env file — read by the core's `ServerConfig` and fed to the two enforcers named in the middle column. Nothing on the executor side changes it: the two planes are read by different processes from different models, and no executor path feeds `build_core_session_config`. |

Installer-level input variables (e.g. `VENYA_DB_PASSWORD`, `VENYA_DB_PASSPHRASE`, `VENYA_RECOVERY_PEPPER`, `CORE_HOSTNAME`) are consumed by `install-venya-core.sh`, which writes the correctly-named server variables into `/opt/venya/.env`. Setting an installer var in the server's environment does nothing. `VENYA_DB_PASSPHRASE` is checked on the way in: the installer refuses a value under the **15-character floor** named in [`db.passphrase`](#dbpassphrase-production-only) before it mutates anything, so a short passphrase never reaches `.env`.

### Metrics scrape port — `VENYA_METRICS_PORT` (not a `ServerConfig` field)

One core-side name is deliberately **outside** the table above: `VENYA_METRICS_PORT`. It is read
straight off the process environment by `start_metrics_server` in
`packages/server/src/server/app.py` (`os.environ.get(METRICS_PORT_ENV_VAR)`), not by
`ServerConfig`, and that difference is what decides where you set it.

| Field | Value |
|---|---|
| What it opens | The Prometheus scrape endpoint that publishes the shipped `venya_*` counters, histograms and gauge. Without it the metrics exist in the process and no one outside can read them. |
| Shipped default | **`10011`**, set by `Environment=VENYA_METRICS_PORT=10011` in `systemd/venya-core.service` (#653), so a freshly installed core answers a scrape with no operator step. The number is derived, not habitual: it is unprivileged, it is unassigned on both tcp and udp in the IANA port registry, it sits below the Linux ephemeral floor, and it is outside the Prometheus/Grafana/Kubernetes bands a co-tenant on a monitoring host is likely to hold. The earlier default was `9091`, which is a Prometheus pushgateway's own port. |
| Bind address | **`127.0.0.1` only, hardcoded.** The endpoint is plain unauthenticated HTTP; it is listed with the other localhost-only listens in [FIREWALL.md](FIREWALL.md). |
| Reachable from | The core host itself. A remote Prometheus scrapes it by running on that host or through a collector placed there — not by opening the port. |
| Read the counters | On the core: `curl -s http://127.0.0.1:10011/metrics` (pipe to `grep venya_` to see the families). |
| Change the port | `sudo systemctl edit venya-core` and set a different `Environment=VENYA_METRICS_PORT=<port>` in the `[Service]` drop-in, then `sudo systemctl daemon-reload && sudo systemctl restart venya-core`. Never edit `/etc/systemd/system/venya-core.service` by hand: the core installer rewrites that file from the shipped template on every re-run, and your edit is gone the next time it runs. |
| Close the door | Same drop-in, set it empty (`Environment=VENYA_METRICS_PORT=`). An empty or absent value binds nothing and logs nothing — the pre-#653 default, kept working on purpose. |

**Do not put this name in `$VENYA_ENV_DIR/.env`.** A `pydantic-settings` env file is loaded into
the model, never into `os.environ`, so `VENYA_METRICS_PORT` sitting in `/opt/venya/.env` is read
by nobody: the variable has to be in the service's actual environment, which is what the unit's
`Environment=` line (or a drop-in) provides. A port set in a file nothing binds to looks
configured and is not (#653 is exactly that failure — the code path was always there, and until
the unit carried the name no default install ever opened it).

**A value that is not a usable port number aborts startup.** `int()` on the variable is not
wrapped, and an out-of-range or negative one raises before the bind: a typo in the drop-in makes
the service exit rather than serve quietly without telemetry. That is the shipped posture, not a
bug, and `packages/server/tests/test_metrics_bind_failsoft_653.py` pins it from both sides.

**A port the host will not give up does NOT abort startup.** Two failures are a fact about the
machine, not about your value — `EADDRINUSE` (something else already holds the port) and `EACCES`
(a port below 1024, which the unit cannot grant because it adds only `CAP_IPC_LOCK`) — and the
service carries `Restart=always`, so a refused bind that raised would put the whole core into a
crash loop over an observability surface. It is instead logged at `ERROR` on every boot that hits
it, naming the port, the OS reason, what you lose (`venya_*` counters unreadable) and the drop-in
above that fixes it, and the core serves with the door dark. `packages/server/tests/test_metrics_bind_failsoft_653.py`
pins the loud-and-serving half; the cell that drives a negative value pins that the `except` was
not widened to swallow the misconfiguration with it.

The executor plane has **no** equivalent endpoint: nothing in `packages/executor/src` reads
`VENYA_METRICS_PORT` and `systemd/venya-executor.service` sets none. This asymmetry is a recorded
scope boundary (#653 AC5), pinned by that same test, not an oversight to fill in quietly.

---

## Bounded Executor Knobs

### `cert_rotation.max_revocation_failures` (executor)

**Config key:** `[cert_rotation] max_revocation_failures` in `/etc/venya/executor.toml`; env
`VENYA_EXECUTOR_CERT_ROTATION__MAX_REVOCATION_FAILURES` (read only when the file does not carry the key — precedence is
`file > env > default`, #598). Field: `CertificateRotationConfig.max_revocation_failures` in
`packages/executor/src/executor/config.py`.

| | |
|---|---|
| Shipped default | **`3`** — consecutive revocation checks that get no answer before the executor stops serving. A fault, never a revocation: the core has neither confirmed nor revoked the credential (#442, #603). |
| Valid range | **`1`–`1000`, inclusive.** Set by `ge=1` / `le=1000` on the field (#660). |
| Out of range | **Refused at config load** with a Pydantic `ValidationError` naming the field and the bound it broke — for either spelling, the TOML file and the environment. Never clamped, never silently accepted, never a traceback at the daemon. |

**Why a floor at 1.** The daemon's threshold test is `>=` (`packages/executor/src/executor/daemon.py`, in `_main_loop`)
against a failure counter that starts at `0`. A setting of `0` therefore trips that comparison on a **healthy**
executor's very first tick, before any revocation answer has had a chance to arrive — the outage stop becomes a
self-stop, and the fleet halts with a core that is answering fine. Before #660 nothing refused that value.

**Why a ceiling at 1000.** The same main loop beats once every 30 s, so 1000 unanswered checks is roughly **8.3 hours**
of serving on an credential nobody has confirmed — long past the point where the ruled outage stop means anything. An
operator who needs more than that does not have a tuning request, they have a typo, a copy-paste, or a hostile TOML.

**Pinned by:** `packages/executor/tests/test_config.py`, `TestCertificateRotationConfig` — both bounds loadable, both
ends refused, and the refusal reached through `ExecutorConfig.from_file` on a real TOML shape, not only by building the
model in a test.

---

## Validation Timing

Two layers:

- **Construction time** (`ServerConfig()` inside `create_app()`): fields declared without defaults — `recovery_code_pepper` — raise a Pydantic `ValidationError` before the app exists.
- **`lifespan()` startup** (before the first request is served): empty-pepper and missing-passphrase checks raise `RuntimeError`.

Together these ensure:

- Developers learn about misconfiguration early (during local deployment)
- Production deployments never start with missing critical config
- Failed startups exit immediately with a clear error message (no partial initialization)

---

## Database Identity

The core server holds **two** PostgreSQL roles, split by trust boundary:

| Role | Identity | Authentication | Rights |
|------|----------|----------------|--------|
| `venya` | **owner / ops / migrations** | password (SCRAM, TCP loopback) — installer `VENYA_DB_PASSWORD` | full DDL + DML, database owner |
| `venya_audit` | **server runtime** | **peer over the local Unix socket, no password** | DML on all tables **except** `UPDATE, DELETE` on `audit_events` |

**How it works.** The installer creates `venya_audit LOGIN` with **no password** and maps the OS service user to it: a `pg_ident.conf` line (`venya_map venya venya_audit`) plus a `pg_hba.conf` line (`local venya venya_audit peer map=venya_map`). The server's runtime `VENYA_DB__DATABASE_URL` is the socket URL `postgresql://venya_audit@/venya?host=/var/run/postgresql` — it carries **no password**, so `/opt/venya/.env` holds no credential for the runtime DB identity. Migrations and ops work still connect as the owner role `venya` over TCP with the installer password.

**Trust boundary:** authentication relies on the OS kernel verifying the `venya` user identity — the connection is trusted exactly as far as "this process runs as the `venya` service account on this host". There is no stored secret to steal, rotate, or leak: removing the trust anchor means changing the OS user, which changes the whole service.

**Failure mode:** if the application runs as the wrong OS user, it will fail to start (peer authentication refuses the connection). This is a security feature, not a bug — a misconfigured identity must not silently fall back to a weaker one.

**Audit trail:** because every server connection presents as `venya_audit`, PostgreSQL's own logs attribute each statement to the runtime role, making it easy to trace actions back to the specific service instance. The owner role's activity (ops, migrations) is distinctly visible as `venya`.

**Append-only enforcement.** Migration `031_audit_append_only_grants` grants `venya_audit` `SELECT, INSERT, UPDATE, DELETE, REFERENCES` on all current tables (REFERENCES is mandatory — the schema is FK-dense and INSERTs into a referencing table check REFERENCES on the referenced table), and sets `ALTER DEFAULT PRIVILEGES` so tables/sequences created by future migrations are granted automatically. It finishes with `REVOKE UPDATE, DELETE ON audit_events` — the app can INSERT audit events (logging) and SELECT them (audit API) but can never modify or delete them; only the owner role can. This is what makes the published "append-only audit log" guarantee a database-enforced property rather than a code convention (issue #66, G9). The grant surface is pinned by `packages/core/tests/test_migration_031_audit_append_only.py`; the behavioral proof is the post-deploy bench (INSERT/SELECT allowed, UPDATE/DELETE refused for `venya_audit`; both allowed for the owner).

**Upgrading an existing install:** re-run the installer — it creates the role, appends the peer-map lines (marker-guarded), rewrites the runtime URL, and the 031 migration applies the grants. The uninstaller drops the role and removes the pg config lines.

---

## Related

- `cli-reference.md` — complete CLI command/argument reference (generated from the parser)
- `cert-rotation-runbook.md` — Executor certificate rotation procedures
- `bandit-nosec-suppressions.md` — Security scanner suppression list
