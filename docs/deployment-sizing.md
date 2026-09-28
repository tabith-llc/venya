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
| Executor | 2 vCPU / 5 GB | 60 GB provisioned; ~7 GB used post-install (warm template ~3.7 GB) | needs `/dev/kvm`; ~1.2 GB RAM floor on the serial path, 5 GB gives headroom |

Both: Ubuntu 24.04 LTS. The "5–8 GB RAM" sizing figure is **headroom**, not a
floor — the measured serial floor is ~1.2 GB per executor (OS + services + one
~527 MB sandbox); the extra room covers OS overhead, concurrent-session growth,
and safety margin.

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
