# Security Policy

Venya is a security-critical system. We take responsible disclosure seriously.

## Reporting Vulnerabilities

**Do not file public issues for security vulnerabilities.** Instead, contact us directly:

- **Email:** security@tabith.com (preferred)
- **Alternate:** info@tabith.com

Include the following in your report:
1. Description of the vulnerability (what component, what attack surface)
2. Steps to reproduce (minimal if possible)
3. Impact assessment (who could be affected, what data/action at risk)
4. Any mitigation or workaround you've identified

## Response Timeline

We commit to the following:

| Step | Timeline |
|------|----------|
| Initial acknowledgment | Within 48 hours |
| Triage and severity assessment | Within 5 business days |
| Fix development (if accepted) | As soon as feasible |
| Public advisory | Coordinated release within 30 days of acceptance |

We will keep you informed throughout the process and coordinate on disclosure timing.

## Scope

Vulnerabilities in the following are in scope:
- Authentication and authorization mechanisms (FIDO2, mTLS, role checks)
- Secret encryption, storage, and injection
- Command execution sandboxes and redaction filters
- Audit logging integrity

Out of scope:
- Weak passwords or social engineering (use stronger keys)
- Physical access attacks
- Third-party dependencies (report upstream, CC us if critical)

## Access Control & Audit Integrity

Database access uses a split-identity model: the server runtime connects as a
dedicated passwordless role (`venya_audit`, peer-authenticated over the local
socket) that is `REVOKE`d `UPDATE, DELETE` on `audit_events` — the append-only
audit trail is enforced by PostgreSQL privileges, not application convention.
See `docs/deployment-config.md` § Database Identity for the full model.

Installer edge case (intentional fail-safe): the installer inserts the
`venya_audit` peer-auth line into `pg_hba.conf` before the stock
`local all all peer` line. If `pg_hba.conf` has been customized and that
anchor line is missing, the installer ABORTS with an error and requires
manual insertion — deliberately, so a non-stock configuration can never be
silently misconfigured into a weaker auth state.

## Safe Harbor

We consider research and reporting done in good faith as authorized testing.
If you act in accordance with this policy, we will not pursue legal action
against you.

---

© 2026 Tabith LLC
