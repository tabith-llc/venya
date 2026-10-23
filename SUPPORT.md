# Support

Where to take a problem, what to send with it, and what a pre-release partner can honestly expect
us to do about it.

## Where to get help

| Need | Channel | The page that owns the answer |
|------|---------|-------------------------------|
| A security vulnerability | **security@tabith.com** | [SECURITY.md](SECURITY.md) — how to report, what is in scope, the safe-harbor position, and the response times we commit to. **Read it rather than paraphrasing it here: SECURITY.md is where this repository's response-time commitments are stated, and this page repeats none of them.** |
| A bug, a rough edge, a wrong doc page, or a question about running Venya | **info@tabith.com** | This page. Best effort — see below. |
| Access, licensing, or a commercial question | **info@tabith.com** | [LICENSE](LICENSE) and the FAQ in [README.md](README.md) for the terms; [docs/faq.md](docs/faq.md) for access. |
| Whether what you hit is already known | [docs/beta-known-limitations.md](docs/beta-known-limitations.md) | The tracked list of what does not work yet in a pre-release build, what an operator does about each, and which issue owns it. It is maintained entry by entry — **read it there**. A copy of one of those sentences here would be a second version of it the day the first is corrected. |
| A contribution, or a design you want to build | [CONTRIBUTING.md](CONTRIBUTING.md) | It names both `info@tabith.com` and GitHub Discussions, and says when to reach out before investing significant time. |

## What to include in a report

The exact command you ran, its full output, and the log of the side that failed:
`journalctl -u venya-core` on a core, `journalctl -u venya-executor` on an executor. Paste-ready
logs beat descriptions, because what the product prints is itself the diagnosis — a refusal names
the thing it refused rather than reporting a bare failure.

Send no secret material with the report: no passphrase, no private key file, no
`/opt/venya/.env`. If a value has to travel at all, rotate it first and say that you rotated it.

## What to expect, and what not to

Venya is pre-release. Outside the security reports, nothing in this repository commits to a
response time, and this page creates no such commitment: the commitments that exist are the ones
[SECURITY.md](SECURITY.md) states, and they govern vulnerability reports. Elsewhere the tree only
points at them — [docs/faq.md](docs/faq.md) names the acknowledgment as SECURITY.md's rather than
setting a clock of its own, so this page points at the same place and copies no number from it.

- **Fair to expect:** that a confirmed defect is treated as ours to fix, and never by asking you to
  weaken a security control — the shipped rule is that the CA is provisioned and verification is
  never disabled ([docs/installation.md](docs/installation.md), §*Troubleshooting*).
- **Not fair to expect yet:** a support queue with timers, or a guaranteed first-response window
  for anything that is not a vulnerability report. Those are commercial-program items, not
  pre-release items.
- **No schedule for any version is promised here.** To know where you stand, ask the product:
  `venya --version` reports the version of the distribution actually installed, and
  [docs/beta-known-limitations.md](docs/beta-known-limitations.md) is what is available to you
  now. A date in a support email is neither.

## Before you contact us

Two ordinary causes of friction, each answered where it belongs rather than here:

1. **TLS or certificate errors, or a workstation that no longer trusts its core** —
   [docs/installation.md](docs/installation.md), §*Troubleshooting*, which carries the shipped
   remedy and why it works; the rule behind it is that the CA is provisioned and verification is
   never disabled.
2. **"`venya --version` printed something I did not expect"** — that is the installed
   distribution's own version, read from its metadata: there is no hard-coded version string in
   that code path to be stale (`cli_version` in `packages/cli/src/venya_cli/api_client.py`). When
   the CLI and the core it is talking to disagree, the CLI says so once per process before your
   command runs, and names which side is out of date and what to re-run (`version_advisory` in
   `packages/cli/src/venya_cli/commands.py`) — warn-only, and silent when the core cannot be
   reached. So if that line printed, act on it. Silence does not by itself mean the two sides
   agree: `version_advisory` returns without printing whenever either version cannot be read
   (`get_server_version` reports unknown for an unreachable core, an older core that does not
   publish the field, or a value it cannot parse). A suspected mismatch is still worth reporting —
   put both version strings in the report and let the logs settle which side is behind.

If neither of those matches your symptom, that is exactly what support is for — write it up and
send it.
