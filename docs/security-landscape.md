# Security Landscape — How Venya's Combination Compares

Venya's headline is a **combination claim**, not a single-trick claim: zero-knowledge
injection, FIDO2-elevated single-use disclosure, sandboxed execution with
fail-closed egress, database-enforced append-only audit, and self-hosted
offline-capable operation — all five, in one platform. To our knowledge, no
other platform combines all five. We publish the comparison so you can check
that "to our knowledge" yourself.

This page lists named products we examined and what each one ships today.
It is a research snapshot, not a permanent fact — see Caveats.

**Legend**

- ✅ — the capability is present
- ◐ — partial / adjacent (scoped in the cell)
- ✖ — not a feature of this product as far as we could establish
- `claimed` — the vendor or project states it (their docs/README; we did not
  audit their internals)
- `doc-verified` — we read primary documentation for this specific point

| Product | 1. Zero-knowledge injection | 2. FIDO2-elevated single-use disclosure | 3. Sandbox + fail-closed egress execution | 4. DB-enforced append-only audit | 5. Self-hosted / offline | All five? |
|---|---|---|---|---|---|---|
| **HashiCorp Vault + Agent** | ✖ `doc-verified` — Agent templates render secret values to files/env the app reads | ✖ `doc-verified` — MFA gates logins/API calls, not a per-value human ceremony | ✖ `doc-verified` — no command-execution plane | ✖ `doc-verified` — audit devices are HMAC'd files/syslog; no separate-role grant story | ✅ `claimed` — Vault runs in your infra; air-gap specifics not re-checked | ✖ |
| **CyberArk (Conjur / Secrets Manager SH)** | ✖ `doc-verified` — Secrets Provider pushes values into K8s Secrets/env/files | ✖ `claimed` — FIDO2 is login authentication; no per-disclosure elevation captured | ✖ `doc-verified` — credential broker, no execution sandbox | ◐ `doc-verified` — dedicated internal audit Postgres, but documented 30-day file deletion and ~2-week UI-DB retention | ✅ `doc-verified` — self-hosted edition documented (offline not checked) | ✖ |
| **Teleport** | ✖ — no claim found that a workload/agent never sees injected values (their Secrets service not examined — see Caveats) | ◐ `doc-verified` — per-SESSION hardware-key MFA (WebAuthn/PIV), not per-value single-use tokens | ✖ `doc-verified` — proxied access plane; no microVM sandbox + fail-closed egress in captured docs | ◐ `doc-verified` — session recordings require immutable-by-versioning S3; `dir` backend never deletes, but HA backends expire events by TTL | ✅ `doc-verified` — self-managed clusters | ✖ |
| **AWS Secrets Manager** | ✖ `doc-verified` — "Secrets Manager decrypts the secret value before returning it to the caller" | ✖ — IAM-token model; FIDO2 per-disclosure not a concept here | ✖ — no execution plane | ◐ — CloudTrail integrity is AWS-managed; not a customer DB-grant pattern | ✖ `doc-verified` — managed cloud service | ✖ |
| **Google Cloud Secret Manager** | ✖ `doc-verified` — `versions.access` returns the payload (samples print "Plaintext:") | ✖ — IAM model | ✖ — no execution plane | ◐ — Cloud Audit Logs; not customer-grant-enforced | ✖ `doc-verified` — cloud service | ✖ |
| **Azure Key Vault** | ✖ `claimed`† — `GetSecret` returns the value to the caller | ✖ — Entra FIDO2 is login-MFA; per-value elevation not a feature | ✖ — no execution plane | ◐† — Azure monitor logs; not customer-grant-enforced | ✖ — cloud service | ✖ |
| **OpenAI Agents API — Vaults + hosted sandbox** | ✅ `doc-verified` — sandbox receives an opaque placeholder; a proxy substitutes the real secret at egress for allow-listed hosts | ✖ — no hardware-key ceremony gates a disclosure | ◐ `doc-verified` — hosted sandbox with domain allow-lists (`allowed_domains`); we did not verify fail-closed defaults or a per-element command gate | ✖ — no append-only audit claim captured | ✖ `doc-verified` — hosted workflow ("requires an `openai_hosted` environment"; self-hosted environments get no vault injection) | ✖ |
| **Anthropic Managed Agents — Vaults + MCP** | ✅ `doc-verified` — "The agent never sees the token"; env-var secrets are placeholders substituted at egress | ✖ — approval patterns are webhooks/custom tools, not FIDO2 per-disclosure | ◐ `doc-verified` — sandboxed cloud sessions with environment network policy | ✖ — vault-tied attribution described; no append-only claim | ✖ `doc-verified` — Anthropic-hosted managed agents | ✖ |
| **Wundervault** | ✅ `claimed` — client-side crypto; local daemon injects, agent "never receives the secret at all" | ◐ `claimed` — Tier-2 WebAuthn gate: human biometric unlock before use, once- or window-scoped; not per-value audited-elevation as a product primitive | ✖ — no sandbox or egress control captured (hosted service + local MCP server) | ◐ `claimed` — "append-only audit" stated; no DB-grant mechanism described; internals closed | ✖ `claimed` — managed-only; project states self-hosting is not offered and air-gapped setups don't fit | ✖ |
| **MCPFence Agent-Credential-Vault (ACV)** | ✅ `claimed` — credentials injected into subprocesses the agent can't read; output scrubbed | ✖ — human approval is dashboard HITL; no FIDO2 ceremony | ◐ `claimed` — deny-first policy engine + auto-revoke; no sandbox or egress control captured | ✖ — full audit trail claimed; nothing about append-only enforcement | ✅ `claimed` — local-first, no cloud | ✖ |
| **AgentSecrets** | ✅ `claimed` — values resolved outside the agent, injected at transport; SDK has no `get()` | ✖ — interactive approvals exist; no FIDO2 elevation captured | ✖ — HTTP-proxy allow-listing/SSRF checks, no sandbox/egress at execution level | ◐ `claimed` — SHA-256 chained audit log; chain ≠ DB-grant-enforced append-only, server is inspectable but unaudited by us | ✅ `claimed` — self-hostable OSS server | ✖ |
| **ZeroCreds** | ✅ `claimed` — local vault; proxy injects into browser/API calls, worker sees result not password | ✖ — TOTP/2FA listed, no WebAuthn elevation | ✖ — no sandbox/egress captured | ◐ `claimed` — "tamper-proof SHA-256 audit chain"; mechanism not verified | ✅ `claimed` — MIT, self-hosted | ✖ |
| **Composio** | ✅ `claimed` — Proxy Execute: credential decrypted in an isolated runtime, injected into the outbound call; never in LLM context | ✖ — approval flows exist; no FIDO2 per-disclosure | ✖ — action-level API gating; not an OS execution sandbox with fail-closed egress | ✖ — metadata-only audit with configurable retention (retention-configurable implies deletable) | ◐ `claimed` — self-host under Enterprise tier | ✖ |
| **AgentValet** | ✅ `claimed` — proxy injects the real credential in memory; agent holds a 60-second signed JWT, never the platform credential | ✖ — magic-link human approval, not FIDO2 elevation | ✖ — MCP/HTTP proxy plane; no sandbox/egress captured | ◐ `claimed` — "immutable, append-only audit log" stated; managed store, mechanism not verified | ◐ `claimed` — says "self-hostable (PostgreSQL)" while listing the proxy self-host reference as roadmap | ✖ |
| **VaultMCP (Axiler-Lab)** | ✅ `claimed` — server-side injection only; write-only vault; agents and config files "never see the raw keys" | ✖ — no FIDO2 concept captured | ✖ — MCP gateway; no sandbox/egress | ◐ `claimed` — envelope encryption + audit logs that never return values; no append-only mechanism stated | ✅ `claimed` — Docker self-host, AGPL-3.0 | ✖ |
| **agent-vault (mvplab-ai)** | ✅ `claimed` — reference-by-name; value injected outside model context; output scrubbed | ✖ — no FIDO2 concept captured | ◐ `claimed` — per-secret host allowlists + routed-header rejection (documented honestly as no sandbox: "it is not a sandbox") | ◐ `claimed` — append-only JSONL log with HMAC auth; documented limitation: detects tampering, not rollback | ✅ `claimed` — local CLI + MCP | ✖ |
| **Venya** | ✅ — value sentinel-wrapped server-side, relayed over mTLS, unwrapped only in the sandbox; two-stage output redaction | ✅ — FIDO2 session authorization; unmask requires a single-use elevation token, denied attempts audit-logged | ✅ — sbx microVM, deny-by-default egress allowlist, per-element command validator | ✅ — migration `031`: dedicated `venya_audit` runtime role, `UPDATE`/`DELETE` revoked on `audit_events` by the database | ✅ — installers + packages run offline-capable; your infra, your CA | — |

† Azure row is `claimed`/partially documented: we captured AWS and GCP primary
docs this pass but did not re-pull the Azure GetSecret page; the mark follows
the same request-and-receive-plaintext model but is one verification short.
See Caveats.

## Attestation depth (hardware-key trust, honestly scoped)

Several products already verify authenticator attestation at enrollment:
Teleport supports allow/deny lists of attestation **certificate authorities**
(devices outside the list are rejected during registration). What Venya has
planned (and does **not** ship today) is verification against **FIDO Alliance
metadata** — the authenticator's make, model, and certification level — which
is a depth question, not an existence gap. No product we captured performs
metadata-depth attestation; several perform CA-level checks. We describe our
roadmap item as depth, never as uniqueness.

## Caveats — read before quoting this table

1. **`claimed` is the ceiling for many cells.** Open-source READMEs and vendor
   pages describe behavior; we audited none of their code. A `claimed` ✅ can
   regress; a `claimed` ✖ can miss a feature they announced later.
2. **Snapshot date.** Everything here was captured 2026-10-01/02 from public
   pages. This space moves fast — six agent-credential tools we list appeared
   within months of each other.
3. **Search-surface bias.** The agent-credential space is young and unranked;
   products exist that our sweep did not find. The claim this table supports is
   "to our knowledge", not "in the world".
4. **Scope edges not examined:** Teleport's dedicated Secrets product, the
   CyberArk FIDO2 *finish-registration* verification step, Azure's
   documentation pages, and OpenAI/Anthropic runtime internals beyond their
   published docs.
5. **This table backs exactly one sentence** in our copy: the combo-level
   "to our knowledge, no other platform combines all five" claim. Element-level
   firsts are explicitly NOT claimed here — Wundervault, AgentSecrets,
   ZeroCreds, ACV, VaultMCP, agent-vault, Composio, AgentValet, and both
   OpenAI and Anthropic vault primitives each ship zero-knowledge injection at
   their layer.
