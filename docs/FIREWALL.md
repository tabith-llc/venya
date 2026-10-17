# Venya Firewall & Network Requirements

> **ALPHA DOCUMENTATION — UNTESTED.** This guide describes the venya alpha and has
> **not** been validated end-to-end against a hardened production deployment. The ports,
> paths, and directions below are derived from the alpha source tree (installer templates,
> the relay listener, and `docs/architecture.md`) and may change. Verify every rule in your
> own environment before relying on it. Where this document and a live `nginx -T` /
> `ss -ltnp` on your host disagree, the host wins — re-derive, do not trust this page.

This page lists the ports and protocols each type of venya host needs, and the direction
of each connection. Venya is **default-deny friendly**: with the rules below, nothing else
needs to be open. For the component overview see [architecture.md](architecture.md); for
install steps see [installation.md](installation.md).

## Host roles

| Role | What runs | Installer |
|------|-----------|-----------|
| **Core server** | nginx (TLS terminator) → FastAPI server, PostgreSQL, root/admin CA | `install-venya-core.sh` |
| **Executor host** | `venya-executor` daemon (relay listener, sbx sandboxes, redaction filter), `venya-sandboxd` | `install-venya-executor.sh` |
| **Target host** | nothing — venya installs no agent on targets | none |
| **Operator workstation** | `venya` CLI + `venya-mcp` (FIDO2 key attached here) | `install-venya-cli.sh` / `.ps1` |

---

## Core server

| Dir | Port | Proto | From / To | Purpose |
|-----|------|-------|-----------|---------|
| **inbound** | **443/tcp** | HTTPS (the installer-generated site config floors the handshake at TLS 1.2/1.3 — `ssl_protocols TLSv1.2 TLSv1.3`, so the protocol floor is ours, not inherited) | workstations, executors, admins | The only inbound service. nginx terminates TLS and proxies to the local backend. Admin API paths additionally require an mTLS **client certificate** (`ssl_verify_client optional` at the listener; enforced per-path) chained to the per-install Admin CA. |
| **outbound** | **8443/tcp** | HTTPS (mTLS) | core → each executor | The relay: the core **dials** the executor's relay listener to run a command, presenting its `<core-host>-relay` client certificate. |

**Localhost-only — never expose these:**

| Port | Proto | Binding | Why it stays local |
|------|-------|---------|--------------------|
| 8080/tcp | HTTPS | `127.0.0.1` | The uvicorn/FastAPI backend. Installer-installed cores serve it over the inner-mTLS channel (`VENYA_INNER_MTLS__ENABLED=true` written at install; `InnerTLSConfig` in `server/config.py`, env `VENYA_INNER_MTLS__*` — the bare config default remains disabled): uvicorn terminates TLS on this loopback bind and requires the nginx client certificate, and nginx proxies to it over HTTPS with `proxy_ssl_verify on`. Exposing this port would still bypass the outer nginx TLS + admin-mTLS layer. |
| 10011/tcp | HTTP (plain, no TLS, no auth) | `127.0.0.1` | The Prometheus metrics scrape endpoint (#653). `GET /metrics` returns the `venya_*` counters, histograms and gauges — request counts and durations by endpoint/method/status, executor registration and heartbeat totals, token and CA operation totals, rate-limit hits, CRL truncations, and the #603 revocation-read refusal counter. It carries telemetry, never payload or identity: no emails, no token values, no passwords (pinned by `packages/server/tests/test_metrics.py`), and the high-cardinality labels (`executor_id`, `user_id`, `ip`, `session_id`) are absent by design. **The address is hardcoded to loopback and is not configurable** — the endpoint is unauthenticated, so publishing it onto a routable interface would hand a host's operational picture to anyone who can route to the core. A remote Prometheus scrapes it by running on the core host, or through a collector you place there. The port comes from `Environment=VENYA_METRICS_PORT` in `systemd/venya-core.service`; change it with `systemctl edit venya-core`, unset it there to close the door. **A port this host already gives to something else does not stop the core**: the bind is refused, one `ERROR` line says so on every boot that hits it, and the scrape surface stays dark until you name a free port. | It carries telemetry, never payload or identity: no emails, no token values, no passwords (pinned by `packages/server/tests/test_metrics.py`), and the high-cardinality labels (`executor_id`, `user_id`, `ip`, `session_id`) are absent by design. **The address is hardcoded to loopback and is not configurable** — the endpoint is unauthenticated, so publishing it onto a routable interface would hand a host's operational picture to anyone who can route to the core. A remote Prometheus scrapes it by running on the core host, or through a collector you place there. The port comes from `Environment=VENYA_METRICS_PORT` in `systemd/venya-core.service`; change it with `systemctl edit venya-core`, unset it there to close the door. |
| 5432/tcp | PostgreSQL | `localhost` | The `venya` database (connection string `postgresql://venya:…@localhost/venya`). Stock Ubuntu PostgreSQL listens on loopback; keep it that way. |

A host firewall on the core needs **443/tcp inbound** (from workstations, executors, and
admin hosts) and **8443/tcp outbound** (to executors). Loopback (8080, 10011, 5432) needs no
external rule and must not be forwarded.

---

## Executor host

| Dir | Port | Proto | From / To | Purpose |
|-----|------|-------|-----------|---------|
| **inbound** | **8443/tcp** | HTTPS (mTLS, `CERT_REQUIRED`) | core → executor | The relay listener. Accepts connections **only** from client certificates whose CN is in `relay_client_ids` (derived from the core hostname, e.g. `venya-core-1-relay`). An empty allowlist makes the listener refuse to bind (fail-closed). Restrict the source to your core host(s) if your firewall can. |
| **outbound** | **443/tcp** | HTTPS (TLS, executor client cert) | executor → core | Registration/enrollment, the ~30 s heartbeat, and the revocation-list poll. The executor's `server_url` must be an `https://` URL to the core host — operator-supplied (`VENYA_SERVER_URL`, required; the installer has no hardcoded default). |
| **outbound** | **443/tcp** | HTTPS | executor → Docker Hub | sbx pulls its agent template on first sandbox create (and `sbx login` authenticates a Docker account). Steady-state only on a cold/uncached template; see `sbx-cold-start-prepull`. The pull is **executor-side** — the core never talks to Docker Hub; the install-time cache pre-pull is the "sbx agent-template warm" block in `install-venya-executor.sh`. |
| **outbound** | **22/tcp** (and any allowlisted port) | SSH | sandbox → target | Command execution against targets. **See the sandbox-egress note below — this is governed by the sbx allowlist, not the host firewall.** |

**Localhost / host-local (no external rule):** `venya-sandboxd` (the sbx daemon) is a
local user daemon; it exposes no inbound network service that needs to be reachable from
other hosts.

### Sandbox egress is NOT host-firewall traffic — important

Commands run inside sbx microVMs. Sandbox network egress is handled by an **in-daemon
user-mode egress proxy**, not the host kernel network stack: it does **not** traverse the
executor host's interfaces, and a host-side `tcpdump` / iptables / nftables / ufw rule
will neither see nor filter it. Sandbox egress is **deny-by-default** against the
operator-owned allowlist at `/etc/venya/egress-allowlist.txt`. The installer writes that
file **empty by default** (`venya_write_egress_allowlist` in `venya-common.sh` — Venya
never guesses the operator's network; entries are seeded only via the explicit
`VENYA_EGRESS_ALLOW` install knob). The DNS resolver is **not** in the file — it is
auto-allowed at runtime by the code (`get_allowed_hosts()` in
`packages/executor/src/executor/egress_filter.py`). To permit an executor to reach a
target on 22/tcp, you add the target to that **allowlist** — opening 22/tcp in the
executor's *host* firewall does nothing for sandbox traffic. (Conversely, the executor's
own daemon traffic to the core on 443 *is* host-stack traffic and *is* subject to the
host firewall.)

**Host firewall on an executor:** **8443/tcp inbound** from the core, **443/tcp outbound**
to the core (and to Docker Hub for template pulls). Target reachability is configured in
the sbx egress allowlist, not the host firewall.

---

## Target host

| Dir | Port | Proto | From / To | Purpose |
|-----|------|-------|-----------|---------|
| **inbound** | **22/tcp** | SSH | executor sandbox → target | Venya runs commands on targets over SSH using operator-provided credentials (which are themselves secrets, injected per-command). **Nothing is installed on a target.** |

Open 22/tcp to the executor host(s) and nowhere else if you can scope it. The SSH
credentials are injected per-command and redacted from output; they never persist on the
target.

---

## Operator workstation

| Dir | Port | Proto | From / To | Purpose |
|-----|------|-------|-----------|---------|
| **outbound** | **443/tcp** | HTTPS (TLS; admin ops add an mTLS client cert) | workstation → core | The `venya` CLI and `venya-mcp` talk to the core API. Bearer-token auth for user sessions; admin commands present the admin client certificate. |
| local | — | USB HID | FIDO2 key | Enrollment/login ceremonies use a locally-attached FIDO2 security key. No network. On Windows, ceremonies go through the platform WebAuthn API and require an interactive desktop. |
| local | — | stdio | LLM client ↔ `venya-mcp` | The MCP server is a local stdio subprocess of the LLM client (Claude Code, Cursor, opencode). No inbound port. |

Workstations need **443/tcp outbound** to the core only. No inbound.

---

## Install-time egress (all hosts)

During installation the host fetches the installer script + tarball. In production these
come from **GitHub Releases over 443/tcp** (`github.com` / `objects.githubusercontent.com`).
In a dev/air-gapped setup they may come from a local tarball server (the reference dev
environment uses `http://<build-host>:8080`) — that is a build-host service, **not** a
venya runtime port, and should not exist in production. Installers pointed at
such an http mirror must pass `VENYA_TARBALL_SHA256` — non-https origins
without the pin abort before any fetch or write (#375, #328). sbx additionally needs Docker Hub
(443/tcp) at executor install for the agent template, plus `apt`/package mirrors unless
you install from a local package cache.

---

## Consolidated matrix

| Source | Dest | Port | Proto | Note |
|--------|------|------|-------|------|
| Workstation | Core | 443 | HTTPS (+mTLS for admin) | user + admin plane |
| Executor | Core | 443 | HTTPS (executor client cert) | heartbeat, registration, revocation poll |
| Core | Executor | 8443 | HTTPS (mTLS) | relay — **core dials executor** |
| Executor (sandbox) | Target | 22 | SSH | via sbx egress allowlist, **not** host firewall |
| Executor | Docker Hub | 443 | HTTPS | agent-template pull (cold start) |
| Core / Executor / WS | GitHub Releases | 443 | HTTPS | install-time artifact fetch |
| (local) | Core backend | 8080 | HTTPS (inner-mTLS, loopback only — nginx presents the relay client cert) | loopback only — never expose |
| (local) | Core metrics | 10011 | HTTP (plain, loopback only) | Prometheus scrape endpoint (#653) — loopback only, never expose. Not bound at all if the host will not give the port up; the core serves either way. |
| (local) | Core PostgreSQL | 5432 | TCP | loopback only — never expose |

**Default-deny summary:** core inbound = 443 only; executor inbound = 8443 (from core) only;
target inbound = 22 (from executors) only; workstation inbound = none. Everything else is
outbound or loopback.

---

## Related

- [architecture.md](architecture.md) — component topology, trust/CA layout, relay CN contract
- [installation.md](installation.md) — install steps + host requirements
- [deployment-config.md](deployment-config.md) — required config fields + env mapping
- [BACKUPS.md](BACKUPS.md) — what to back up (the CA + KEK material that protects this traffic)
