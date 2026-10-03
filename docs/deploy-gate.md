# Deploy gate — clean tree or recorded sha256

**Ticket:** GitLab `tabith-llc-group/venya-dev` #16 (deploy-from-dirty-tree)

Deployed bytes must be traceable to committed source. There are two deploy
paths and each has a different guarantee:

## Release path (structural, already closed)

`create-tarball-and-serve.sh --ref <git-ref>` builds every served byte from
`git archive` of the ref. The working tree is never consulted, so no dirty
state can reach a published asset. This landed with v0.1.0-alpha.6; use it
for anything that leaves the dev fleet.

## Dev-deploy path (procedural — this doc)

Hand-deploys (tarball from the working tree, or `scp`/`rsync` of changed
files to fleet VMs) are only traceable if the tree state is captured at
deploy time. Rule:

1. **Deploy only from a clean committed tree**, OR
2. **Record the deploy-time state** before building/copying anything:

   ```bash
   scripts/deploy-record.sh record /path/to/venya-checkout >> <run-results-file>
   ```

   The record pins `HEAD`, and lists every dirty/untracked file with its
   `sha256` (untracked files included — `git status` clean-tree checks
   cannot catch untracked bytes shipped by hand).

3. When verifying deployed runtime files against source, classify every
   hash difference:

   ```bash
   scripts/deploy-record.sh classify <repo-dir> <record-file> <repo-relative-path> <observed-sha256>
   ```

   Verdicts: `MATCH-COMMITTED` (deployed bytes equal the committed blob),
   `ATTRIBUTED-DIRTY` (deployed bytes equal a recorded dirty file), or
   `STOP-UNEXPLAINED` (exit 1 — stop the run per the stop-and-report rule;
   the difference is neither committed state nor recorded drift).

The deploy-vs-source comparison that motivated this gate (2026-09-10,
`f6bb60a`, `server/fido2/manager.py`) was cosmetic drift that only a
read-only diff could re-classify. With the record, that attribution is one
command.

Self-check: `scripts/deploy-record.sh selftest` (positive: committed match,
dirty attribution; negative: unexplained bytes abort with exit 1).
