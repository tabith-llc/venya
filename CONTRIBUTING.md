# Contributing

Thanks for considering a contribution to Venya. This document covers the basics.

## Before You Start

**Please understand the license.** Venya is source available under the
Business Source License 1.1, not an Open Source license. By submitting a
contribution, you agree it will be licensed under the same terms as the
repository.

If you're contributing because you believe Venya should be OSI-compliant,
please open a discussion first — we want to hear that feedback, even if
the outcome is "no, we're keeping BUSL."

## How to Contribute

### Small fixes

Typo corrections, doc improvements, minor bug fixes:
1. Fork the repo
2. Make your change
3. Run relevant tests (`uv run -p <version> pytest <path>`)
4. Submit a PR with a clear description

### Feature requests

Open an issue with:
- The use case you're solving for
- Why existing Venya features don't meet it
- Proposed design (code sketches welcome)

### Larger contributions

Reach out to info@tabith.com before investing significant time. We may:
- Not have capacity to review/merge immediately
- Have design decisions that affect your approach
- Be able to help unblock blockers

## Coding Standards

- **Python 3.14+**, mypy type hints preferred
- **Rust filter** must compile with stable toolchain
- Tests required for new functionality
- No secrets/passwords in code or test fixtures (use env vars)

## Git Workflow

1. Create feature branch from `main`
2. Commit early and often with descriptive messages
3. Squash WIP commits before PR
4. Update `CHANGELOG.md` if user-facing

## Questions?

Email us at info@tabith.com or open a GitHub Discussion.

---

© 2026 Tabith LLC
