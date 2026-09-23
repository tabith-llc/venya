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

## Development setup

Prerequisites: Python 3.14, [uv](https://docs.astral.sh/uv/), and a stable
Rust toolchain >= 1.80 (`rustup`; see `packages/executor/Cargo.toml`
`rust-version`).

Sync the workspace once (creates the root `.venv` every suite runs
against):

```bash
uv sync --python 3.14
```

`uv.lock` is **versioned** — sync resolves to the committed lock, and lock
changes are committed like any other source change. The installers'
host-requirements files (`venya-{core,executor}-requirements.txt`) are
`uv export --frozen` output pinned to that lock: if you touch a `pyproject`
or the lock, run `scripts/pin-requirements.sh` and commit the regenerated
files — the pre-commit `requirements-pinned` hook fails otherwise (ticket
`installer-deps-not-lock-pinned`).

**Build the Rust filter extension (required).** The `venya_filter` pyo3
extension is gitignored and normally built by the executor installer; a
fresh clone does NOT have it. Without this step the executor suite exits
with a collection error (`ModuleNotFoundError: No module named
'venya_filter'`) and the server suite fails
`tests/test_executor_id_validation.py` (it imports the executor package,
which imports `venya_filter`).

All suites resolve `executor` EDITABLE from the workspace-root `.venv`, so
one copy under `packages/executor/src/` serves every package:

```bash
VENV_PY="$(git rev-parse --show-toplevel)/.venv/bin/python"
cd packages/executor
PYO3_PYTHON="$VENV_PY" cargo build --release
EXT_SUFFIX=$("$VENV_PY" -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
cp target/release/libvenya_filter.so "src/venya_filter${EXT_SUFFIX}"
cd ../..
```

Both pins matter (they mirror the installer's tagged-copy mechanism,
`install-venya-executor.sh`): `PYO3_PYTHON` builds against the workspace
3.14 interpreter — a `.so` built against the wrong CPython segfaults at
import — and `EXT_SUFFIX` must come from that same interpreter or the
import never finds the file.

Verify (both must be green):

```bash
uv run -p 3.14 --directory packages/executor pytest tests/ -q
uv run -p 3.14 --directory packages/server pytest tests/ -q
```

The remaining suites run the same way
(`uv run -p 3.14 --directory packages/<pkg> pytest tests/`). Rebuild and
re-copy after changing anything under `packages/executor/src/rust/`.

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
