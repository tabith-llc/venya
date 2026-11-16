# Fixture captures — the vendor's own bytes, from two real sbx faces

These files are the answers `sbx policy log <sandbox> --json` printed on an **executor test guest**
during leg 1440, on 2026-11-16 (the guest is named in the leg report, not in product bytes). They
are not transcribed, not trimmed, and not
hand-written: each is the stdout of one command, run as the account the sandbox daemon signs in
under, after a genuine refused egress from a sandbox this leg created.

| file | vendor face | refused destination this run earned | capture window |
|---|---|---|---|
| `sbx-policy-log-f2-1440-denyprobe-v0.46.0.json` | `sbx version: v0.46.0 991967dc90ce0d9a440cd1df1bdf3e395c5a2693` | `example.com:80`, `count_since 1`, `last_seen 2026-11-16T21:55:00.006241974Z` | 2026-11-16T21:54:59Z → 21:55:00Z |
| `sbx-policy-log-f2-1440-denyprobe-b501-v0.50.1.json` | `sbx version v0.50.1 ddb0268d7124b9cf98955d0b08ffd71a0dfcebe4` | `example.com:80`, `count 1`, `last_seen 2026-11-16T21:57:13.66900777Z` | 2026-11-16T21:57:13Z |

The two faces differ in **names, not meaning**: the refusal list sits under `blocked_hosts` at
v0.46.0 and under `blocked` at v0.50.1, and the sandbox is named `vm_name` on one and
`sandbox_id` on the other. `egress_filter` reads both through
`sandbox_shape.rows_from_any_face`, and nothing in the product branches on a version number —
the installer requires a vendor version **floor** (`SBX_MIN_VERSION="0.39.0"`) and no ceiling, and
the vendor repository on that guest offered **0.51.0** the same afternoon, so an unseen release is
the normal case, not the exception.

## How each capture was produced (the whole sequence, in order)

```bash
# on the test guest, as its login account; everything below runs as the daemon account:
sudo -n -u venya bash -lc 'sbx create --name f2-1440-denyprobe shell'
sudo -n -u venya bash -lc 'sbx exec f2-1440-denyprobe -- curl -sS -m 8 http://example.com'
   # → "Approval required for example.com:80." and exit code 0 — the completed-refusal face
sudo -n -u venya bash -lc 'sbx policy log f2-1440-denyprobe --json'      # → the v0.46.0 file

sudo -n apt-get install -y docker-sbx=0.50.1-1~ubuntu.24.04~noble
sudo -n -u venya bash -lc 'echo y | sbx daemon restart'   # the client refuses an auto-restart off a TTY
sudo -n -u venya bash -lc 'sbx create --name f2-1440-denyprobe-b501 shell'
sudo -n -u venya bash -lc 'sbx exec f2-1440-denyprobe-b501 -- curl -sS -m 8 http://example.com'
sudo -n -u venya bash -lc 'sbx policy log f2-1440-denyprobe-b501 --json' # → the v0.50.1 file
```

The v0.50.1 capture reproduces, byte-for-byte in **key names**, the estate face an independent seat
measured at leg 1435 (`allowed` / `blocked`, rows keyed `sandbox_id … count … first_seen … last_seen`),
and it was taken without touching that estate: the same vendor build sha, `ddb0268d`, on a test guest.

## Integrity, re-derive

```bash
cd packages/executor/tests/fixtures && sha256sum *.json
# c5a92efaf54e99e489932124fabc4c6e836ef1a9884e6796ce14586d52c6ce46  sbx-policy-log-f2-1440-denyprobe-v0.46.0.json
# bab15e3e94c3b57a793215c925f48771bfcb986287b2e5a9261a5718fc0ca8c0  sbx-policy-log-f2-1440-denyprobe-b501-v0.50.1.json
```

`test_egress_denial_two_faces_1440.py` pins both digests, so an edited fixture goes red instead of
quietly becoming a memory of a face.

## Adding a third face later

Capture it here the same way, and add the new list-name to `egress_filter.POLICY_LOG_LIST_KEYS` (and
the sandbox-name key to `POLICY_LOG_SANDBOX_KEYS`) with a paired negative beside it. The rule this
directory exists to hold: **a fixture typed from a room line, a report, or a model is not a
fixture** — it must come out of the tool.
