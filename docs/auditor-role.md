# The Auditor Role

Venya has three permission tiers for human callers — `read`, `read-write`,
and `auditor` — plus the seeded `admin` role (which holds `read-write`).
Roles are created with `venya role create <name> --permissions <tier>` and
assigned to users by an admin.

## What the tiers mean

| Capability | read | auditor | read-write |
|------------|------|---------|------------|
| List secrets, roles, executors (metadata) | yes | yes | yes |
| Read secret values (elevation-gated unmask) | yes | **no** | yes |
| Query the audit log (`GET /api/v1/audit`) | **no** | yes | yes |
| Create/delete secrets, create sessions, run commands | no | no | yes |
| Admin routes (`/admin/*`) | no | no | no (admin role only) |

`auditor` is a compliance tier: broad read visibility plus audit-log query
access, with an **affirmative deny on secret values**. It does not imply
`read-write`, and it never reaches admin routes.

## Secret values: an affirmative, audited deny

Reading a secret value requires a single-use elevation token (WebAuthn
re-verification). An auditor-only caller is refused at the plaintext
chokepoint — `GET /api/v1/secrets/{key}?unmask=true` returns **403 even
with a valid elevation token**, and the refusal happens *before* the token
is consumed, so a denied attempt never burns the token.

Every such refusal is written to the append-only audit log as an
`auditor_secret_read_denied` event (actor, secret key, outcome — never a
secret value). A failure of the audit write itself never turns the denial
into an allow: the request still gets 403.

A read that succeeds is written too, as a `secret_value_disclosed` event
(actor, secret key, session id, outcome — again never a secret value, and
never the elevation token). The row is added only once the value is in hand
and it commits with the token's single-use burn, so a disclosure the caller
never received is never recorded and one that happened is never lost. An
auditor asking "who read a value, when, of which key?" therefore gets an
answer on both arms of the same route — the denial and the disclosure.

## Elevation issuance is refused to auditor-only callers

Both elevation-assert endpoints (CLI/API and browser) return 403 — logged
as `auditor_elevation_denied` — before an elevation token is created.

Consequence by design: the same token gates self-service security-key
registration, so an **auditor-only user cannot add their own FIDO2
credential**. An administrator must provision their credential.

## Union math, and why the auditor tier is exclusive

Permission checks are union-based: the value-deny fires only when **every**
role a user holds is `auditor`-tier. That math is the last line of defense
(defense-in-depth).

The first line is prevention (separation of duties): the auditor tier is
**exclusive by construction**. Granting an auditor-tier role to a user who
already holds any other tier — or the reverse — is refused with HTTP 409,
and so is any role tier-flip that would create the mixture for a current
member. Every refusal is audit-logged (`auditor_sod_denied`). A user can
hold two auditor-tier roles (the tier-set stays auditor-only); because the
tier ships for the first time with this rule, no mixed state can exist.

So an auditor's audit-log visibility and value-deny cannot be diluted by a
later role grant — independence is enforced by the system, not left to
role-assignment discipline.

## Compliance mapping

The behavior above maps to named audit controls. This is an
**alignment** mapping, not a certification: attestation requires an
assessor, not a changeset.

| Venya behavior | Control it supports |
|----------------|---------------------|
| Auditor tier exclusive by construction; mixed grants and tier-flips refused AND audit-logged | NIST SP 800-53 Rev 5 **AC-5** Separation of Duties |
| Denials (value-read, elevation issuance, SoD) audit-logged with actor, target, outcome, timestamp | NIST **AU-3** audit-record content (incl. outcomes); PCI DSS **10.2.1** failed-access-attempt logging |
| Auditor tier sees the full audit trail — including its own denials | NIST **AU-6** review/analysis (attempted-bypass visibility) |
| DB-enforced append-only audit log (`venya_audit` role, migration `031` — existing guarantee) | NIST **AU-9/AU-10**, cited as already shipped |

## Audit-log visibility

Auditors (and read-write) pass the audit-log gate; plain `read`-tier users
no longer do — audit access is auditor-scoped. Visibility inside the log:
an auditor-tier caller sees the **full** log, including other users'
events — the same breadth the `admin` role holds (the ruling: an auditor
who can only see their own events is not an auditor). All other non-admin
callers see only events attributed to their own user.

## Migration note

The audit-log route moved from the `read` tier to the `auditor` tier.
Existing users with only a `read` role who queried `GET /api/v1/audit`
must be granted an `auditor` (or read-write) role to keep that access.
