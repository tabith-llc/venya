# Venya Deployment Sizing Guide

How to size a Venya deployment: how many executors you need, what each component
costs in CPU / RAM / disk, and when to scale. Venya measures capacity by
**concurrent active agent sessions**, not total enrolled users — this reflects how
the system actually operates and keeps planning honest.

The performance figures below are **measured**, not estimated: they come from a
benchmark on the serial execution path (the shipped behavior). Environment
for the measured numbers: Ubuntu 24.04, 2 vCPU / 5 GB per VM, sandbox runtime
`sbx` 0.45.1, single executor, warm agent template. Figures labeled *estimate*
are not yet load-tested and are marked as such.

## Capacity philosophy

Each executor handles **one command at a time** (serial execution). This is a
deliberate architectural choice, not a limitation:

- **Complete per-command isolation** — secrets, filter state, and execution
  contexts never interleave between commands.
- **Simpler audit trails and debugging** — one command, one sandbox, one record.
- **Predictable resource usage** — no contention spikes.

Serial execution is a security property. At typical scale, queueing is rare and
scaling is a matter of adding executors.

## Sizing rules

| Component | Capacity | Scaling method |
|-----------|----------|----------------|
| Core server | Hundreds of enrolled users on a modest VM (2 vCPU / 4–8 GB) — *estimate; user-count ceiling not load-tested*. Measured: the core is **not** the serial-path bottleneck (~0.1 CPU-s per relayed command, RAM flat). | Not the bottleneck; scale throughput via executors |
| Executor | One command at a time; measured **~7.2 s per warm command → ~8.3 commands/min** sustained per executor | Add executors linearly as concurrent sessions grow |
| Secret storage | Bounded by PostgreSQL disk | Extendable; not a practical constraint at typical scale |

## Measured performance

Single executor, warm agent template, serial path:

| Metric | Measured |
|--------|----------|
| Warm-command latency (end-to-end, n=25) | mean **7.2 s**, median 7.4 s, p95 7.8 s (stdev 0.54 s) |
| Sustained throughput (serial, one executor) | **8.3 commands/min** |
| Queue delay (concurrent clients → one executor) | ≈ (position − 1) × 7.2 s; the **300 s relay budget is reached at ~41 queued commands** |
| Executor RAM | idle ~620 MB; **~527 MB per active sandbox**; serial floor ~1.2 GB |
| Executor disk (post-install, warm template) | **7.0 GB used** (≈ 3.7 GB is the warm sandbox template) |
| Per-command steady-state disk growth | ~0 (zero-leak verified: sandboxes, workspaces, and secret files all cleaned up after each run) |
| Audit growth | **~1.6 KB per command** (2 audit events each) |
| Core load (serial relay) | ~0.1 CPU-s/command; RAM flat — the core is not the bottleneck |
| Install wall-clock | core ~45 s; executor **~3–5 min** (network-dominated — the warm-template pull; varies with link speed) |

Latency assumes an instantaneous command; a real command adds its own execution
time on top of the ~7.2 s sandbox lifecycle. The serial path runs **one
concurrent command per executor by design** — per-executor concurrency is a
future option, not shipped.

## Estimating executor count

Most teams operate at a **5–10% concurrent-session rate** during normal use.
Use this formula:

```
Peak concurrent sessions = Total users × Assumed concurrency rate × 1.5 (headroom)
Executor count = Peak concurrent sessions (round up)
```

### Examples

| Scenario | Users | Concurrency assumption | Executors recommended |
|----------|-------|------------------------|-----------------------|
| Single admin team | 10 | 20% (high-touch) | 3 |
| Mid-size engineering | 25 | 10% (typical) | 4 |
| Large org pilot | 50 | 10% (typical) | 8 |
| Minimal single-session deployment | N/A | 1 concurrent session | 1 |

## When to scale

Watch for these signals that you need more executors:

1. Commands queuing behind long-running commands.
2. Queue depth approaching the 300-second relay budget (measured: ~41 queued
   commands on one executor).
3. Multiple agents regularly issuing parallel tool calls.

Scaling is operationally simple: deploy another executor VM and enroll it with a
new enrollment token. No code changes required.

## Resource requirements

| Role | CPU / RAM | Disk | Notes |
|------|-----------|------|-------|
| Core server | 2 vCPU / 4–8 GB | 10 GB class | nginx + PostgreSQL + core service |
| Executor | 2 vCPU / 5 GB | 60 GB provisioned; ~7 GB used post-install (warm template ~3.7 GB) | needs `/dev/kvm`; ~1.2 GB RAM floor measured on the serial path (one active sandbox); concurrent-sandbox RAM on this shape is **unmeasured beyond 2** |

Both: Ubuntu 24.04 LTS. The "5–8 GB RAM" sizing figure is **headroom**, not a
floor — the measured serial floor is ~1.2 GB per executor (OS + services + one
~527 MB sandbox); the extra room covers OS overhead and safety margin.

### Per-sandbox memory cap — `sandbox_memory_mb` (#578, #589)

**Config key:** `sandbox_memory_mb` (top-level field on the executor config; env
`VENYA_EXECUTOR_SANDBOX_MEMORY_MB`; toml key `sandbox_memory_mb` in
`/etc/venya/executor.toml`). **Shipped default: 1024 MiB.** It is a code default,
not a value written into the installer's toml — see the precedence note below.

This is the cap handed to `sbx create --memory` for every sandbox the executor
makes, and it is the number that decides how many sandboxes a guest can hold.

**Why 1024, measured on the shipped shape** (`venya-exec-5`, 2026-10-13 — a
2 vCPU / 5 GB executor guest as delivered):

| figure | value | note |
|---|---|---|
| guest `MemTotal` | **4898 MiB** | what `/proc/meminfo` reports and what our own `host_total_memory_mib()` returns — the same number |
| declared shape | 5120 MiB | 222 MiB (4.34 %) above `MemTotal`; **the declared shape is the wrong denominator** — a fraction of it describes a machine that does not exist |
| **vendor** default (50 % of host memory) | **2449 MiB** | Docker's own `sbx create` default, quoted from https://docs.docker.com/reference/cli/sbx/create/ (read 2026-10-13) |
| 2 × vendor default | 4898 MiB = **100.0 % of the guest** | two sandboxes alone claim the whole machine — the #578 defect, in numbers |
| 3 × vendor default | 7347 MiB = **2449 MiB OVER** | predicts the RF-1 / #567 three-sandbox out-of-memory by arithmetic |
| 2 × **1024** | 2048 MiB, leaving **~2850 MiB** | room for the daemon, the OS, and one more sandbox |
| 1024 vs measured footprint | ~527 MB per active sandbox | ≈ 1.9 × the measured need — headroom, not a guess |

**Why the vendor's own limits do not make this number safe.** `sbx` enforces the
band it documents — observed on our own bench (Docker's docs state the band but
not the enforcement: a 48 GiB `--memory` value was refused outright), and the
512 MiB floor is the vendor's floor as well as ours. Our config-load guard
(`_sandbox_memory_within_vendor_bounds`) checks the same band earlier, so a bad
value is refused with a Venya-named reason instead of a vendor one. But **both**
checks are per-sandbox, and that is the gap: 2449 MiB is an in-band value, so
nothing — vendor or Venya — rejects it, yet two sandboxes at that figure are
100.0 % of this guest and three are 2449 MiB over it, which is exactly the RF-1 /
#567 out-of-memory. No in-band per-sandbox cap can see the **sum** of several
in-band sandboxes. 1024 MiB is chosen on that basis: three sandboxes at 1024 are
3072 MiB, inside `MemTotal`, so the shipped number survives a concurrency raise
instead of needing one.

**Precedence — read this before telling anyone to set the env spelling.**
`ExecutorConfig.from_file` passes the toml as init kwargs, so **a
`sandbox_memory_mb` key present in `/etc/venya/executor.toml` silently outranks
`VENYA_EXECUTOR_SANDBOX_MEMORY_MB`** (file > env > default; no comparison and no
log line — the #598 precedence inversion). The env spelling wins over the shipped
default **only when no toml key exists**. On a default install there is no such
key: the installer does not write `sandbox_memory_mb`, so 1024 applies until an
operator sets it in either carrier.

Every figure above is a **serial** measurement — one active sandbox per executor
at a time — and each carries that method basis where it appears. Concurrency on
the shipped 5 GB executor shape is **unmeasured beyond 2**. The one spike that
probed it (RF-1, 2026-10-09, #567) ran three concurrent sandboxes on a 5 GB
executor guest and ran that guest out of memory, which ended the sandbox daemon;
the same three- and four-sandbox runs completed cleanly on a larger test guest.
That guest is a probe condition above every shape this product ships, not a
deployment recommendation, and a clean pass on it says nothing about the 5 GB row
above. So this guide publishes **no** concurrency capacity. The carrier that
owns that number is RF-5 — the capacity benchmark and the publishable sizing
table — and RF-5 is blocked on RF-4, so no concurrency figure exists yet and
none is scheduled to be published before that gate clears. The earlier benchmark
rows — #186 and its duplicate #124 — are closed, and what they measured was the
serial path; they are named here as history, not as open work.

## Reference deployment

A minimal deployment is one core server + one executor, which serves unlimited
enrolled users running single-session agent workflows. Target hosts for testing
are optional.

One executor is a starting default, not a ceiling — scale by adding executors as
concurrent sessions grow (see "Estimating executor count" above). No code change
is involved; each additional executor just enrolls with a new token. If you
expect multi-agent concurrency from day one, size the executor count up front.

## See also

- [Installation Guide](installation.md) — step-by-step core + executor install
- [Architecture](architecture.md) — how the relay, sandbox, and redaction fit together
- [FAQ](faq.md) — technical questions on the security model
