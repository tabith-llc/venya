# Revocation-Table Operations Runbook

> **Provenance:** written 2026-10-17 against the working tree at `96e6167` on the
> `bug/603-heartbeat-revocation-read-s130` branch, as acceptance criterion 4 of the #603 AC1
> shape-A ruling (`wave29-specs-20261016/wren-603-shapeA-ruling-flash2-s130.md` §3.4). Every
> lock-behavior claim below is a MEASUREMENT taken on a live core (PostgreSQL 16.15, `venya-core-3`)
> at the anchor face `81bf43692a1fe493858090cfa1b455c033d5aa7c2eac7adc4034db165c2fb601`, not a
> quotation from documentation. The measurement commands and their raw output are mirrored in
> `wave29-specs-20261016/evidence/`.

This document exists because the #603 investigation found that a lock on one small table can stop
the whole fleet's liveness plane, and that the operations which do that are all **deliberate,
routine, and currently undocumented**.

---

## 1. What is at risk, in one paragraph

`executor_cert_revocations` is read on the executor request path — the per-request mTLS
revocation check, the heartbeat route, the two dial gates, register, audit ingest, the admin
lists, and the **public** CRL route. Those reads run in a single-worker process, so the table is
not just a data dependency: it is a liveness dependency. Any statement that holds, or merely
**queues for**, `ACCESS EXCLUSIVE` on that table stops every executor heartbeat against that
core. This is a fleet-wide outage wearing a migration's clothing.

## 2. The measured lock facts — read this before running any DDL

| # | Statement shape against `executor_cert_revocations` | Readers blocked? | Measured |
|---|---|---|---|
| 1 | `INSERT` / `DELETE` (the revoke path; the retention purge is gone — see §2a) — takes `ROW EXCLUSIVE` | **NO** | 20 s `ROW_EXCLUSIVE` hold: poll `200`, health `200` at every sample, 22 journal lines, **no silence** |
| 2 | `LOCK TABLE … IN ACCESS EXCLUSIVE MODE` — held | **YES** | 30 s hold: read waited **27,058 ms**; poll/health/ready `000`; **57 s of zero access-log lines** |
| 3 | `ACCESS EXCLUSIVE` — **queued, never granted** (blocked behind a reader) | **YES** | read waited **16,048 ms**; ungranted lock requests went 1 → 3; a route died at t=12 s |

Fact 3 is the one that surprises people and it is the reason §3 is written the way it is: **the
hazard is not holding the lock, it is ASKING for it.** PostgreSQL places new `ACCESS SHARE`
requests (plain `SELECT`s) behind a waiting `ACCESS EXCLUSIVE`, so a DDL that is itself stuck
keeps starving the liveness plane for as long as it waits. "It will only take a second" does not
bound the damage, because the queue is upstream of the grant.

Fact 1 is the reason this is a runbook and not a code prohibition: ordinary revocation activity —
re-enrolling, rotating — does **not** stall readers under MVCC and needs no window.

## 2a. There is no retention purge on this table any more (#685)

Up to and including the anchor this runbook was written against, a maintenance-loop pass
(`maintenance.py` → `CAManager.purge_expired_revocations`, 5-minute schedule) DELETEd
`executor_cert_revocations` rows older than `crl.crl_retention_days` (default 90). **That pass and
that method are removed** by the owner's ruling of 2026-10-20 on ticket #685: the table is the
membership population for credential validity, so truth about a revoked credential is not aged out
on a timer. It now matches `ExecutorCert`, which was never purged.

Three operational consequences, all of them intended:

- **The table grows.** Rows are permanent for the life of the core's DB. Size is now bounded only
  by how many executor credentials have ever been revoked, so the §5 scan-cost guidance reads
  differently: the population is not trimmed any more, and the `DELETE` that used to trim it is not
  available as a lock-class answer to a slow scan either.
- **Do not hand-delete history.** `TRUNCATE` and a targeted `DELETE` are the same act the code was
  removed for: they drop the assertion that a serial is revoked. If the population really must be
  reduced, that is a ruling to ask for, not an operation to run.
- **`crl.crl_retention_days` is no longer a knob you can use to shrink this table.** The field is
  still shipped and still validated — and the validator now REFUSES to start the core on any value
  below the longest leaf-certificate lifetime whose revocations live in the two revocation tables,
  `max(EXECUTOR_VALIDITY_DAYS=30, ADMIN_CERT_VALIDITY_DAYS=90)` = **90**. A value like `1` used to
  be accepted by `ge=1` and would have deleted rows for credentials still inside their own validity
  window; it now aborts startup, and so does anything from 1 through 89. (The shipped default is 90
  and sits exactly on that bound, which is why the comparison is `>=` and not `>` — see
  `test_crl.py::test_shipped_default_retention_sits_on_the_anchor_and_loads`.) The admin half of
  the anchor is deliberate: `AdminCAManager.purge_expired_revocations` is not wired today, and the
  guard covers it anyway, so the day someone wires it there is no window that can age out a live
  credential. That bound is defense-in-depth: it holds even if the exemption is ever reverted.

## 3. Doing DDL on the revocation table

Order of preference. Every step is idempotent-safe and reversible.

1. **Prefer not to take `ACCESS EXCLUSIVE` at all.**
   - Add an index with `CREATE INDEX CONCURRENTLY` (no transaction block — see §4).
   - Add a constraint as `… NOT VALID`, then `ALTER TABLE … VALIDATE CONSTRAINT` in a separate
     statement (validate takes `SHARE UPDATE EXCLUSIVE`, which does not block readers).
   - `ALTER TABLE … ADD COLUMN … NULL` (no default) is metadata-only on PostgreSQL 11+; it still
     takes the lock class, so keep it brief and still follow step 2.
2. **Bound the WAIT, on the DDL side, before you run it.** This is the mitigation fact 3 demands —
   a deadline on the asker, so a blocked DDL gives up instead of starving the fleet:

   ```sql
   SET lock_timeout = '5s';
   SET statement_timeout = '30s';
   -- then the DDL
   ```

   If it times out, **the DDL did not run.** Re-run in a maintenance window (§5) or with the
   daemons stopped. Never "just retry it in a loop" without the timeout — an unbounded retry is an
   unbounded starvation generator.
3. **Confirm what you are about to join.** Run this first and look for anything that would block
   you or that you would queue behind:

   ```sql
   SELECT pid, state, wait_event_type, wait_event, backend_start, left(query,120) AS q
   FROM pg_stat_activity
   WHERE datname = 'venya' AND pid <> pg_backend_pid()
   ORDER BY backend_start;
   ```

   A `state = 'active'` row whose `wait_event_type` is `Lock` means a convoy is already forming —
   do not add to it.
4. **Afterwards, verify the fleet answered through it.** On the core:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' --cacert /var/www/.well-known/venya-ca.crt \
     https://<core-hostname>/api/v1/executors/certs/revocation-list
   sudo journalctl -u venya-core --since '-2 minutes' | grep -c 'INFO:'
   ```

   A `200` and a non-zero line count is healthy. A gap in the access log is the incident in §2
   row 2 — check `venya_revocation_read_refusals_total` to see how many liveness reads were
   refused during it, on the core host itself (§6 names the endpoint):

   ```bash
   curl -s http://127.0.0.1:10011/metrics | grep '^venya_revocation_read_refusals_total'
   ```

## 4. Alembic migrations — the specific rule this repo needs

`packages/core/alembic/env.py` runs migrations inside `with context.begin_transaction():` at both
`:49` (offline) and `:78` (online). `CREATE INDEX CONCURRENTLY` **cannot run inside a transaction
block**, so a migration that wants it must break out explicitly:

```python
def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction block (alembic env.py begins one per
    # migration at :78), so this step opts out for the duration of the statement only.
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_executor_cert_revocations_match_key "
            "ON executor_cert_revocations (ltrim(upper(serial_number), '0'))"
        )
```

**Scope, stated because it is easy to over-read:** this expression index is a *cost* change, not a
lock change. The beat predicate `ltrim(upper(serial_number),'0') = <key>` is non-sargable against
the plain `serial_number` indexes and is measured as a **Seq Scan** (`EXPLAIN`, 6 rows, 80 kB
table). An index makes the read cheaper; it does **not** make the read immune to a waiting
`ACCESS EXCLUSIVE`. Do not record an index as the mitigation for this hazard.

No migration took `ACCESS EXCLUSIVE` on this table **until revision `043`**: it was created in
`002_executor_cert_revocations.py` (table + `UniqueConstraint` on `serial_number` + two indexes)
and no revision through `042` touches it. **`043_revocation_epoch_597t2.py` is the first exception, and
it is a `CREATE TRIGGER`** — which takes that lock class on every relation it watches, including this one
and the heartbeat table `executors`. The revision therefore runs its DDL under
`SET LOCAL lock_timeout = '5s'` / `statement_timeout = '30s'` exactly as §3 step 2 prescribes, so a
blocked upgrade gives up on the DDL side instead of joining a convoy; when it times out the revision
aborts and the trigger did not appear, and the fix is a maintenance window or halted daemons (§5, §7) —
never a retry loop without the bound. §3 step 1 is how every *later* revision keeps this a fact about its
own day rather than a surprise. §9 records what `043` does and the residual it cannot close.

## 5. Maintenance statements that take the blocking class

These are the realistic villains named in the ruling. None of them are in the shipped product code
— verified by grep across `packages/*/src`, `install-venya-core.sh` and `venya-common.sh` for
`VACUUM`, `REINDEX`, `TRUNCATE`, `LOCK TABLE`, `ALTER TABLE` (no hits against this table) — so all
of them arrive from an operator, a backup tool, or a scheduler:

| Statement | Lock class | Blocks readers? | Guidance |
|---|---|---|---|
| `VACUUM FULL executor_cert_revocations` | `ACCESS EXCLUSIVE` | **YES** | Do not run on this table in-service. Plain `VACUUM` takes `SHARE UPDATE EXCLUSIVE` and is fine. |
| `CLUSTER executor_cert_revocations` | `ACCESS EXCLUSIVE` | **YES** | Avoid entirely; there is no reason to cluster this table. |
| `REINDEX TABLE executor_cert_revocations` | `ACCESS EXCLUSIVE` | **YES** | Use `REINDEX INDEX CONCURRENTLY` per index instead. |
| `TRUNCATE executor_cert_revocations` | `ACCESS EXCLUSIVE` | **YES** | Never. It destroys revocation history, which is a security fact, not just data — and there is no retention purge to point at as the sanctioned alternative any more (#685): the rows are permanent by ruling. |
| `ALTER TABLE executor_cert_revocations …` (most forms) | `ACCESS EXCLUSIVE` | **YES** | §3. |
| plain `VACUUM` / `ANALYZE` | `SHARE UPDATE EXCLUSIVE` | no | Safe. |
| an operator-run `DELETE` against this table | `ROW EXCLUSIVE` | no | Lock-safe, **ruled wrong**: the retention purge that used to be the sanctioned `DELETE` was removed (#685, §2a). Do not substitute your own. |

**Long transactions** are the other half of the hazard, via fact 3: a transaction that holds
`ACCESS SHARE` and stays open lets a DDL queue up behind it, and then everyone else queues behind
the DDL. The shipped tables of consequence are `statement_timeout = '300s'` on both the shared and
the reserved liveness engine (`backend.py:510` and `:481`) and **no**
`idle_in_transaction_session_timeout` anywhere in the product — so an interactive session that
does `BEGIN;` and goes to lunch is, on this box, a starvation weapon. If you open a transaction
against `venya` by hand, keep it short and end it with `ROLLBACK`, and set
`SET idle_in_transaction_session_timeout = '60s'` for your own session.

## 6. What the product now does on its own (shape A, this branch)

- Request-path revocation reads carry a bounded **lock** deadline —
  `crl.revocation_read_lock_timeout_ms`, default **300 ms**, env
  `VENYA_CRL__REVOCATION_READ_LOCK_TIMEOUT_MS`. That is the lock wait. The read's own execution time
  is bounded separately by `crl.revocation_read_scan_timeout_ms` (#654, below), and the two are
  different failures with different names, different counters and different things to fix.
- A read that cannot answer in time is **refused**, in the shipped stale-class `503` whose detail
  names list state and never a revocation. It is never a `403` (the daemon reads `403` as
  permanent rejection) and never an "all clear".
- The refusal is counted, cumulatively, per site: `venya_revocation_read_refusals_total{site=…}`.
  The log line is latched to one per process; **the counter is the alerting surface** — alert on
  its rate, not on the log. **That sentence is now true of both arms of the shipped 503 (#657):**
  before it, only the lock-deadline arm counted, and the stale-snapshot arm — what a starved pool
  or a dead publisher actually produces — raised the same refusal with no increment at all. Read
  the `site` label to tell the causes apart. A lock-deadline refusal carries the path that asked
  (`heartbeat`, `crl`, `dial/execute`, `admin/list-executors`, `register/…`, `audit-ingest`,
  `executor-session`, `executor-mtls`); a snapshot-stale refusal carries
  **`site="poll/revocation-list"`**. A rate climbing on that label is not a DDL convoy — it is the
  publisher or the pool, so escalate on §5 and §7 (look for the publisher's own exit line in
  `journalctl -u venya-core`) instead of hunting for a held lock. One series, one alert rule, two
  causes, distinguishable — and a Counter, never a gauge, because the question an operator asks
  afterwards is how much was lost, not only whether something is losing right now. Read it from
  the scrape endpoint, which is loopback-only and open by default on an installed core
  (`Environment=VENYA_METRICS_PORT=10011` in the shipped unit; #653):
  `curl -s http://127.0.0.1:10011/metrics`, run **on the core** — the endpoint binds `127.0.0.1` only
  and is plain unauthenticated HTTP, so a remote Prometheus reads it through a collector on that
  host rather than over the network. The port, the override procedure, and the listens are in
  [deployment-config.md](deployment-config.md) and [FIREWALL.md](FIREWALL.md). Before #653 landed
  nothing set that variable on a default install, so the endpoint never bound and this instruction
  could not be followed — on an older installed core, check first with
  `systemctl cat venya-core | grep VENYA_METRICS_PORT`.
- The deadline is scoped to the read inside a savepoint, never to the connection or the engine,
  because a blanket engine deadline was measured refusing a legitimate beat write at 2,033 ms that
  shipped completes at 4,037 ms. Both deadlines are set that way and both are reverted the same way,
  with one asymmetry worth knowing before you tune either: reverting `lock_timeout` to `0` restores
  the session value, while reverting `statement_timeout` to `0` would REMOVE the bound, so the seam
  restores whatever the session actually reported instead (#654).
- A revocation read that is merely SLOW — no lock held, the table just expensive to scan — now gets
  refused too, by its own execution deadline: `crl.revocation_read_scan_timeout_ms`, default
  **2 000 ms**, env `VENYA_CRL__REVOCATION_READ_SCAN_TIMEOUT_MS`. Before this, the only ceiling on
  execution time was the session-wide `statement_timeout = '300s'` both engines set: five hundred
  times the read's budget, and long enough that the executor polling the route had already given up
  at its own 10 s timeout — the caller recorded a failure while the core recorded a 200, and the
  event loop was parked for the whole time with nothing to show for it. Read the ceiling literally:
  a value above 10 s re-creates that disagreement, and a value at or below the lock deadline makes
  every lock convoy read as a slow scan, so the pair is checked when the core starts.
- The slow-scan refusal is the **same** `503` with the **same** "no revocation asserted" wording, and
  it is counted on its own cumulative series, `venya_revocation_read_scan_refusals_total{site=…}` —
  never merged into `venya_revocation_read_refusals_total`, because a slow scan and a lock convoy are
  two different diagnoses. If the SCAN counter is what is moving, the table is being read too slowly:
  the fix is the size of the population — which since #685 is NOT reducible by any purge (see §2a: the
  retention window is no longer consumed, and the rows are permanent by ruling), so the live options
  are the unindexed `executors.revoked_at` scan the poll fallback performs, and an index, not a
  bigger number here.
- A slow read that still ANSWERS is visible rather than silent: `venya_revocation_read_duration_seconds{site=…}`,
  bucketed up to 300 s. `venya_request_duration_seconds` tops out at a 10 s bucket, so a 12 s read and
  a 300 s read were one observation there — which is exactly how this row stayed undiscovered.
- Two more reads are inside the seam (#656): the CRL mint the **dial** performs on its own path
  (`site=dial/crl-mint`) and the whole-population read the public poll falls back to when the snapshot
  publisher is not running (`site=poll/fallback-read`). Both were unbonded, and the second one sits on a
  public, unauthenticated endpoint every executor polls.

**The admin plane carries the same bound, on its own table (#658).**
`_validate_admin_mtls` reads `admin_cert_revocations` — a different table, whose own retention
purge (`AdminCAManager.purge_expired_revocations`, a `DELETE`, so `ROW EXCLUSIVE` and safe as
shipped) is NOT wired into the maintenance loop and was NOT touched by #685 — and that read used to
be synchronous and unbonded inside an `async def` on the ordinary pool. It now runs through the
SAME seam and the SAME knob (`crl.revocation_read_lock_timeout_ms`); there is no second deadline
mechanism and no second config key. It is labelled separately, so a
stall on one plane is never misread as a stall on the other:
`venya_revocation_read_refusals_total{site="admin-mtls"}` against the executor plane's
`{site="heartbeat"|"executor-mtls"|"audit-ingest"|"executor-session"|"crl"|"register/…"|"dial/…"}`.

Three arms on that path, and **all three refuse**:

| What happened | Answer | Detail the operator reads |
|---|---|---|
| the serial is on the admin list | `403` | `Admin certificate revoked` — unchanged by #658 |
| the read could not answer inside the deadline | `503` | the shared list-state sentence, `… request refused (no revocation asserted)` |
| any other backend/lookup fault | `403` | `Admin access requires valid client certificate` — unchanged by #658 |

The middle row is the only new arm, and it is availability, not policy: a stalled check reports
itself as unavailable rather than as a revocation, and rather than as a credential problem the
operator would "fix" by re-issuing a good certificate. Nothing about a lock stall admits a caller.

Why `admin_cert_revocations` is not in §2's measured table: those numbers were taken against
`executor_cert_revocations` on `venya-core-3`, and this seat did not re-run a lock cell on the admin
table. The lock classes are the same for any PostgreSQL table (§2 facts 1–3 are about `ACCESS
EXCLUSIVE` and the queue, not about that one relation), so treat §3–§5 as applying here too —
including fact 3, that merely **asking** for the exclusive lock is the hazard.

## 7. Deciding to stop the daemons for a window

If you must take an unavoidable `ACCESS EXCLUSIVE`, stop the executors first
(`sudo systemctl stop venya-executor` on each executor, or halt the fleet), run the DDL, restart.
Stopped executors serve nothing, which is a smaller harm than a core that answers `000` to
everything while keeping nominally-live state. The executor's own fault tri-state means a stalled
core costs retries up to `max_revocation_failures` (default 3, valid range 1-1000, `config.py`,
`CertificateRotationConfig`) and then the executor **stops serving** rather than proceeding
unverified — so a long window converts into a
fleet that has to be brought back, not a fleet that kept working. Plan for the recovery, not just
the outage.

## 8. Related documents

- `cert-rotation-runbook.md` — the credential ceremonies that write to this table (§3, §4 there).
- `beta-known-limitations.md` — record any window you could not make non-blocking.
- `wave29-specs-20261016/wren-603-shapeA-ruling-flash2-s130.md` — the ruling that requested this.

## 9. The revocation epoch counter (PB-597T2, revision `043`)

Revision `043` adds a one-row table, `revocation_epoch`, and eight PostgreSQL triggers that advance its
counter whenever ANY revocation state is written. Revocation state is not one table — it is
`executor_cert_revocations` and `admin_cert_revocations` (a row *is* the revocation), plus the
`revoked_at` columns of `executors` and `core_relay_credentials` (a column flip *is* the revocation) — so
the counter spans all four, and one number answers "has revocation state changed since my last read"
without enumerating writers. #597 closed conceding that "raw SQL or out-of-band revocations were not
exhaustively searched"; that enumeration is not finishable, and this replaces the question.

**Why a trigger and not a privilege.** `031_audit_append_only_grants.py` is the nearest precedent and it
is not one — its append-only guarantee is made of `GRANT`/`REVOKE`, not of a trigger, and there was no
`CREATE TRIGGER` anywhere in `packages/core/alembic/versions/` before `043`. Privileges bind *who* may
write; enforcing them here would mean revoking `UPDATE`/`INSERT` from the runtime role, which forbids the
very product writes the counter exists to count, and they bind nobody at `psql` — the out-of-band writer
is precisely the one #597 could not find. A trigger runs whatever the writer's identity, so the
instrument changed because the property needed changed.

**Measured behaviour, on PostgreSQL 17.11** — each row was run, not reasoned; the cells live in
`packages/core/tests/test_migration_043_revocation_epoch_597t2.py`:

| statement | epoch |
|---|---|
| `SELECT` against any watched relation (five, including a CRL-shaped read) | **unchanged** |
| raw `INSERT` into `executor_cert_revocations` / `admin_cert_revocations` via `psql`, zero ORM | **+1 each** |
| `UPDATE … SET revoked_at = now()` on `executors` / `core_relay_credentials` | **+1** |
| `UPDATE … SET revoked_at = NULL` (an un-revoke) | **+1** — a change is a change |
| `DELETE` from any watched relation | **+1** |
| **`TRUNCATE`** on either row-table | **+1** — no row trigger fires on `TRUNCATE`, so `043` installs a statement-level `AFTER TRUNCATE` trigger on both; without it this row would read "unchanged", and that is the gap §5 calls the worst maintenance statement |
| `UPDATE executors SET last_heartbeat = now()` (a heartbeat) | **unchanged** |
| `UPDATE executors SET hostname = …` | **unchanged** |
| the product's own ORM write (`ExecutorCertRevocation` insert, committed) | **+1** |

**The heartbeat pair is load-bearing.** `executors` is written on every beat by every daemon, so the two
`revoked_at`-column triggers carry `AFTER UPDATE OF revoked_at` plus
`WHEN (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)`. Without the guard the counter becomes a traffic
meter: "has revocation state changed?" would answer yes continuously, and the first consumer learns to
ignore it.

**Fail-closure, measured twice because the first version got it wrong.** The bump is
`UPDATE revocation_epoch SET epoch = epoch + 1 … WHERE id = 1`. With the seed row deleted, that UPDATE
matches nothing and, with no further clause, raises nothing — an early build let a real revocation
`INSERT` answer `INSERT 0 1` while the counter stood still, which is the #597 hole reopened by the thing
meant to close it. The shipped function therefore checks `GET DIAGNOSTICS … ROW_COUNT` and raises:

```
ERROR:  revocation_epoch row 1 is missing — revocation state cannot be counted, so this write is refused.
HINT:  This is deliberate fail-closure (PB-597T2). Do not soften the trigger to let the write through.
```

The consequence, stated because it is an outage shape: **with that row gone — deleted, or the table
emptied by a `TRUNCATE` — revocation writes are REFUSED until it is restored**, and the restore is the one
`INSERT` the error text names. The row is guarded by `chk_revocation_epoch_single_row` (`id = 1`), so a
second row cannot exist to be read by mistake. Never make the trigger tolerant to unblock a write; restore
the row.

### The residual — what this mechanism cannot bound

**A DBA who drops a trigger wins, and nothing in the schema says so.** Measured: after
`DROP TRIGGER trg_revocation_epoch_exec_cert_rev ON executor_cert_revocations`, a revocation `INSERT`
**succeeded** and the epoch **did not move**. No error, no log line, no readback — the credential is
revoked, the counter is stale, and the only way to notice is that the counter stopped moving on a table
that is being written. This is the stated limit of the design ("the last writer that can evade a trigger
is the DBA who drops the trigger"), and it is why PB-597T2 is a *floor* under an admission check rather
than a proof of an unchanged table.

Two partial protections, both measured, and neither one claimed away:

- **The function cannot be removed quietly.** `DROP FUNCTION venya_revocation_epoch_bump()` is REFUSED —
  `cannot drop function … because other objects depend on it`, with the eight dependent triggers named,
  `HINT: Use DROP ... CASCADE`. Taking it that way prints `drop cascades to 8 other objects`, which is
  visible in the operator's own output. Dropping the eight triggers individually stays silent, so the
  quiet path remains the common one.
- **The downgrade is not a residual.** `alembic downgrade 042` drops all eight triggers, the function and
  the table, leaves the watched relations and their rows alone, and revocation writes keep working
  against the pre-`043` schema. Measured both ways, and `upgrade head` re-applies cleanly onto a schema
  with live revocation rows (the guarded seed `INSERT` re-creates row 1, counters restart at 0).

**What to watch.** `select epoch, updated_at from revocation_epoch where id = 1` on the core's database.
An `updated_at` that stops moving while `executor_cert_revocations` / `admin_cert_revocations` gain rows is
the signature of a dropped guard, and it is the only signature there is. The counter restarts at 0 across
a downgrade/upgrade round trip, so a *decreasing* epoch is a schema event, not a rewind of history.
