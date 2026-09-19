# Venya CLI Reference

<!-- GENERATED FILE — DO NOT HAND-EDIT.
     Source of truth: packages/cli/src/venya_cli/cli.py create_parser().
     Regenerate: uv run -p 3.14 --directory packages/cli python scripts/gen_cli_reference.py
     Enforced by packages/cli/tests/test_cli_reference_doc.py (drift = RED,
     every example argv is parse-validated, every leaf command has >=1 example). -->

Complete reference for the `venya` workstation CLI. Every command, argument, default, and
constraint below is generated from the live argument parser — it cannot disagree with the
shipped binary. Examples use placeholder values and are parse-validated by the test suite.

**Global options** (before the command): `-v` / `--verbose` (tracebacks on error), `-h` / `--help`.

**Exit codes:** `0` success · `1` runtime/command error (details also tee'd to `venya.log` in the
config dir) · `2` argparse usage error (bad/missing arguments). No command given prints help
and exits `1`.

**Config:** `venya config show|set-server|clear-token` manage the per-user config file
(server URL, access token) under `~/.config/venya` (Linux), `~/Library/Application Support/venya` (macOS), `%APPDATA%\venya` (Windows).

## Contents

- [`venya init`](#venya-init)
- [`venya store`](#venya-store)
- [`venya get`](#venya-get)
- [`venya list`](#venya-list)
- [`venya delete`](#venya-delete)
- [`venya update-metadata`](#venya-update-metadata)
- [`venya audit`](#venya-audit)
- [`venya admin`](#venya-admin) *(group)*
  - [`venya admin enroll`](#venya-admin-enroll)
  - [`venya admin remove`](#venya-admin-remove)
  - [`venya admin configure-user`](#venya-admin-configure-user)
  - [`venya admin list`](#venya-admin-list)
  - [`venya admin create-user`](#venya-admin-create-user)
  - [`venya admin set-command-policy`](#venya-admin-set-command-policy)
  - [`venya admin get-command-policy`](#venya-admin-get-command-policy)
  - [`venya admin add-allowed-command`](#venya-admin-add-allowed-command)
  - [`venya admin key-version`](#venya-admin-key-version) *(group)*
    - [`venya admin key-version list`](#venya-admin-key-version-list)
    - [`venya admin key-version deactivate`](#venya-admin-key-version-deactivate)
    - [`venya admin key-version revoke`](#venya-admin-key-version-revoke)
    - [`venya admin key-version rotate-status`](#venya-admin-key-version-rotate-status)
    - [`venya admin key-version rollback`](#venya-admin-key-version-rollback)
  - [`venya admin rotate-key`](#venya-admin-rotate-key)
  - [`venya admin revoke-executor`](#venya-admin-revoke-executor)
  - [`venya admin executor-enroll`](#venya-admin-executor-enroll)
  - [`venya admin list-tokens`](#venya-admin-list-tokens)
  - [`venya admin issue-token`](#venya-admin-issue-token)
  - [`venya admin revoke-token`](#venya-admin-revoke-token)
  - [`venya admin re-enroll`](#venya-admin-re-enroll)
  - [`venya admin export-ca-cert`](#venya-admin-export-ca-cert)
  - [`venya admin export-ca-key`](#venya-admin-export-ca-key)
  - [`venya admin split-ca-key`](#venya-admin-split-ca-key)
  - [`venya admin restore-ca-key`](#venya-admin-restore-ca-key)
  - [`venya admin init-admin-ca`](#venya-admin-init-admin-ca)
  - [`venya admin generate-admin-cert`](#venya-admin-generate-admin-cert)
  - [`venya admin revoke-admin-cert`](#venya-admin-revoke-admin-cert)
- [`venya role`](#venya-role) *(group)*
  - [`venya role create`](#venya-role-create)
  - [`venya role list`](#venya-role-list)
  - [`venya role get`](#venya-role-get)
  - [`venya role delete`](#venya-role-delete)
  - [`venya role members`](#venya-role-members)
  - [`venya role add-member`](#venya-role-add-member)
  - [`venya role remove-member`](#venya-role-remove-member)
- [`venya recovery`](#venya-recovery)
- [`venya run`](#venya-run)
- [`venya exec`](#venya-exec) *(group)*
  - [`venya exec register`](#venya-exec-register)
  - [`venya exec cert`](#venya-exec-cert) *(group)*
    - [`venya exec cert status`](#venya-exec-cert-status)
    - [`venya exec cert renew`](#venya-exec-cert-renew)
    - [`venya exec cert revoke`](#venya-exec-cert-revoke)
  - [`venya exec heartbeat`](#venya-exec-heartbeat)
  - [`venya exec audit`](#venya-exec-audit)
  - [`venya exec status`](#venya-exec-status)
- [`venya config`](#venya-config) *(group)*
  - [`venya config show`](#venya-config-show)
  - [`venya config set-server`](#venya-config-set-server)
  - [`venya config clear-token`](#venya-config-clear-token)
- [`venya credential`](#venya-credential) *(group)*
  - [`venya credential list`](#venya-credential-list)
  - [`venya credential add`](#venya-credential-add)
  - [`venya credential remove`](#venya-credential-remove)
- [`venya enroll`](#venya-enroll)
- [`venya login`](#venya-login)

---

## `venya init`

Bootstrap the core

```
venya init <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID for first admin |
| `--installation-reset` | no | flag | false (flag) | Reset core to pre-initialization state before starting (only allowed when no users are enrolled) |

*Hidden / deprecated (accepted but not shown in `--help`):*

- `--skip-migrations` — deprecated no-op, accepted for compatibility (prints a warning). Hidden via `argparse.SUPPRESS`.

**Examples**

```bash
venya init jsmith  # bootstrap the core; jsmith becomes the first admin
venya init jsmith --installation-reset  # re-init after wiping users but not roles (avoids uq_roles_name violation)
```

## `venya store`

Store a secret

```
venya store <KEY> [VALUE] --roles ROLES [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `KEY` (positional) | **yes** | string | — | Secret key |
| `VALUE` (positional, nargs=?) | no | string | — | Secret value; '-' or omitted reads stdin (interactive TTY: hidden prompt) |
| `--roles` | **yes** | repeatable/space-separated list | — | Role(s) to scope the secret to |
| `--key-version` | no | string | — | Key version ID to encrypt with (default: server's active key version) |
| `--metadata`, `-m` | no | repeatable (accumulates) | — | Metadata key=value pair (can be specified multiple times) |

**Examples**

```bash
venya store db/password --roles app  # value omitted -> read from stdin (hidden prompt on a TTY)
venya store db/password sekrit --roles app readers  # value inline, scoped to two roles
venya store db/password - --roles app -m purpose=ci  # '-' also reads stdin; -m adds metadata
```

## `venya get`

Retrieve a secret

```
venya get <KEY> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `KEY` (positional) | **yes** | string | — | Secret key |
| `--unmask` | no | flag | false (flag) | Return plaintext (requires re-authentication) |

**Examples**

```bash
venya get db/password  # masked value (secrets are masked by default)
venya get db/password --unmask  # plaintext — requires re-authentication with a security key
```

## `venya list`

List secrets

```
venya list [PREFIX] [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `PREFIX` (positional, nargs=?) | no | string | — | Optional key prefix filter |
| `--user-id` | no | string | — | User ID for authentication (required if no token stored) |
| `--executor` | no | string | — | Filter by executor metadata field |
| `--purpose` | no | string | — | Filter by purpose metadata field |
| `--username` | no | string | — | Filter by username metadata field |

**Examples**

```bash
venya list  # all secrets visible to you
venya list db/  # keys under the db/ prefix
venya list --purpose ci  # filter by a metadata field
```

## `venya delete`

Delete a secret

```
venya delete <KEY>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `KEY` (positional) | **yes** | string | — | Secret key to delete |

**Examples**

```bash
venya delete db/password  # delete a secret (fails if still referenced by an execution session)
```

## `venya update-metadata`

Update metadata for a secret

```
venya update-metadata <KEY> --metadata METADATA
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `KEY` (positional) | **yes** | string | — | Secret key to update |
| `--metadata`, `-m` | **yes** | repeatable (accumulates) | — | Metadata key=value pair (can be specified multiple times) |

**Examples**

```bash
venya update-metadata db/password -m purpose=ci -m owner=team-a  # replace metadata key=value pairs
```

## `venya audit`

Query audit log

```
venya audit [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--user` | no | string | — | Filter by user ID |
| `--key` | no | string | — | Filter by secret key |
| `--start-date` | no | string | — | Start date (ISO format) |
| `--end-date` | no | string | — | End date (ISO format) |
| `--days` | no | int | — | Query last N days |
| `--hours` | no | int | — | Query last N hours |
| `--limit` | no | int | `100` | Max results (default 100) |
| `--offset` | no | int | `0` | Result offset |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya audit --days 7  # last 7 days of audit events
venya audit --key db/password --json  # events for one secret, machine-readable
venya audit --user jsmith --limit 50  # filter by user, cap results
```

## `venya admin`

Admin operations

```
venya admin
```

Subcommands:

- [`venya admin enroll`](#venya-admin-enroll) — Enroll a new user
- [`venya admin remove`](#venya-admin-remove) — Remove a user
- [`venya admin configure-user`](#venya-admin-configure-user) — Configure user settings
- [`venya admin list`](#venya-admin-list) — List all registered users
- [`venya admin create-user`](#venya-admin-create-user) — Create a new user and issue an enrollment token
- [`venya admin set-command-policy`](#venya-admin-set-command-policy) — Set executor command policy
- [`venya admin get-command-policy`](#venya-admin-get-command-policy) — Get current executor command policy
- [`venya admin add-allowed-command`](#venya-admin-add-allowed-command) — Add a command to the strict allowlist
- [`venya admin key-version`](#venya-admin-key-version) — Key version management
- [`venya admin rotate-key`](#venya-admin-rotate-key) — Rotate the key encryption key
- [`venya admin revoke-executor`](#venya-admin-revoke-executor) — Revoke an executor certificate
- [`venya admin executor-enroll`](#venya-admin-executor-enroll) — Generate an enrollment token for an executor
- [`venya admin list-tokens`](#venya-admin-list-tokens) — List all enrollment tokens for a user
- [`venya admin issue-token`](#venya-admin-issue-token) — Revoke old tokens and issue a new enrollment token
- [`venya admin revoke-token`](#venya-admin-revoke-token) — Revoke a single enrollment token
- [`venya admin re-enroll`](#venya-admin-re-enroll) — Deactivate credentials and issue a new enrollment token
- [`venya admin export-ca-cert`](#venya-admin-export-ca-cert) — Export the CA certificate (for distribution to executors)
- [`venya admin export-ca-key`](#venya-admin-export-ca-key) — Export the CA private key (encrypted with passphrase)
- [`venya admin split-ca-key`](#venya-admin-split-ca-key) — Split CA key using Shamir's Secret Sharing
- [`venya admin restore-ca-key`](#venya-admin-restore-ca-key) — Restore CA key from shares or encrypted backup
- [`venya admin init-admin-ca`](#venya-admin-init-admin-ca) — Initialize the admin CA (create key/cert pair)
- [`venya admin generate-admin-cert`](#venya-admin-generate-admin-cert) — Sign an admin client certificate
- [`venya admin revoke-admin-cert`](#venya-admin-revoke-admin-cert) — Revoke an admin certificate by serial number

### `venya admin enroll`

Enroll a new user

```
venya admin enroll <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID to enroll |
| `--mode` | no | one of: `security-key`, `platform` | `security-key` | Auth mode (default: security-key) |

**Examples**

```bash
venya admin enroll jsmith  # issue an enrollment token for a new user (security-key mode)
venya admin enroll jsmith --mode platform  # enroll for a platform authenticator (e.g. Windows Hello)
```

### `venya admin remove`

Remove a user

```
venya admin remove <USER_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID to remove |

**Examples**

```bash
venya admin remove jsmith  # remove a user
```

### `venya admin configure-user`

Configure user settings

```
venya admin configure-user <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID to configure |
| `--mode` | no | one of: `security-key`, `platform` | — | Auth mode |
| `--timeout` | no | int | — | Session timeout in seconds |

**Examples**

```bash
venya admin configure-user jsmith --timeout 1800  # session timeout in seconds
venya admin configure-user jsmith --mode platform  # switch the user's auth mode
```

### `venya admin list`

List all registered users

```
venya admin list [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin list  # all registered users
venya admin list --json  # machine-readable
```

### `venya admin create-user`

Create a new user and issue an enrollment token

```
venya admin create-user <USERNAME> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USERNAME` (positional) | **yes** | string | — | User ID (e.g. 'jsmith') |
| `--display-name` | no | string | — | Human-readable display name |
| `--roles` | no | string | — | Comma-separated list of role names to assign |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin create-user jsmith --display-name 'Jane Smith' --roles app,devs  # create a user, assign roles, and issue an enrollment token
venya admin create-user jsmith --json  # machine-readable (token included)
```

### `venya admin set-command-policy`

Set executor command policy

```
venya admin set-command-policy {strict|balanced|permissive} [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `PRESET` (positional) | **yes** | one of: `strict`, `balanced`, `permissive` | — | Policy preset |
| `--custom` | no | string | — | Path to custom policy file |

**Examples**

```bash
venya admin set-command-policy strict  # allowlist-only execution policy
venya admin set-command-policy balanced  # default middle tier
venya admin set-command-policy permissive --custom policy.toml  # custom policy file
```

### `venya admin get-command-policy`

Get current executor command policy

```
venya admin get-command-policy [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin get-command-policy  # show the active executor command policy
```

### `venya admin add-allowed-command`

Add a command to the strict allowlist

```
venya admin add-allowed-command <COMMAND_PATH>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `COMMAND_PATH` (positional) | **yes** | string | — | Full path to allowed command |

**Examples**

```bash
venya admin add-allowed-command /usr/sbin/apache2ctl  # add a binary to the strict allowlist
```

### `venya admin key-version`

Key version management

```
venya admin key-version
```

Subcommands:

- [`venya admin key-version list`](#venya-admin-key-version-list) — List all key versions
- [`venya admin key-version deactivate`](#venya-admin-key-version-deactivate) — Deactivate a key version
- [`venya admin key-version revoke`](#venya-admin-key-version-revoke) — Revoke a key version
- [`venya admin key-version rotate-status`](#venya-admin-key-version-rotate-status) — Show rotation job progress
- [`venya admin key-version rollback`](#venya-admin-key-version-rollback) — Roll back a failed rotation job

#### `venya admin key-version list`

List all key versions

```
venya admin key-version list [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin key-version list --json  # all key-encryption-key versions and their states
```

#### `venya admin key-version deactivate`

Deactivate a key version

```
venya admin key-version deactivate <VERSION_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `VERSION_ID` (positional) | **yes** | string | — | Version ID |

**Examples**

```bash
venya admin key-version deactivate 3  # deactivate a version (existing secrets stay decryptable until re-encrypted)
```

#### `venya admin key-version revoke`

Revoke a key version

```
venya admin key-version revoke <VERSION_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `VERSION_ID` (positional) | **yes** | string | — | Version ID |

**Examples**

```bash
venya admin key-version revoke 3  # revoke a key version by ID (compromise path; irreversible)
```

#### `venya admin key-version rotate-status`

Show rotation job progress

```
venya admin key-version rotate-status
```

*Takes no arguments.*

**Examples**

```bash
venya admin key-version rotate-status  # progress of the running rotation job
```

#### `venya admin key-version rollback`

Roll back a failed rotation job

```
venya admin key-version rollback <JOB_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `JOB_ID` (positional) | **yes** | string | — | Rotation job ID |

**Examples**

```bash
venya admin key-version rollback JOB_ID  # roll back a failed rotation job by ID
```

### `venya admin rotate-key`

Rotate the key encryption key

```
venya admin rotate-key [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--new-key` | no | string | — | Path to new KEK file |

**Examples**

```bash
venya admin rotate-key  # rotate the key-encryption key (server generates the new KEK)
venya admin rotate-key --new-key /secure/kek.bin  # rotate to a specific KEK file
```

### `venya admin revoke-executor`

Revoke an executor certificate

```
venya admin revoke-executor <EXECUTOR_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `EXECUTOR_ID` (positional) | **yes** | string | — | Executor ID to revoke |

**Examples**

```bash
venya admin revoke-executor venya-exec-1  # revoke an executor certificate; the server then refuses to relay to it
```

### `venya admin executor-enroll`

Generate an enrollment token for an executor

```
venya admin executor-enroll <EXECUTOR_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `EXECUTOR_ID` (positional) | **yes** | string | — | Executor ID to enroll |
| `--output-dir` | no | string | — | Directory to write token and CA certs (creates token, core-server-ca.crt, admin-ca.crt) |

**Examples**

```bash
venya admin executor-enroll venya-exec-1  # print a bootstrap enrollment token for an executor
venya admin executor-enroll venya-exec-1 --output-dir /secure/enroll  # write token + CA certs to a directory for transfer
```

### `venya admin list-tokens`

List all enrollment tokens for a user

```
venya admin list-tokens <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin list-tokens jsmith  # all enrollment tokens for a user
```

### `venya admin issue-token`

Revoke old tokens and issue a new enrollment token

```
venya admin issue-token <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin issue-token jsmith  # revoke old tokens and issue a fresh one
```

### `venya admin revoke-token`

Revoke a single enrollment token

```
venya admin revoke-token <TOKEN_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `TOKEN_ID` (positional) | **yes** | string | — | Token ID to revoke |

**Examples**

```bash
venya admin revoke-token TOKEN_ID  # revoke a single enrollment token
```

### `venya admin re-enroll`

Deactivate credentials and issue a new enrollment token

```
venya admin re-enroll <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID to re-enroll |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya admin re-enroll jsmith  # deactivate a user's credentials and issue a new enrollment token (lost-key path)
```

### `venya admin export-ca-cert`

Export the CA certificate (for distribution to executors)

```
venya admin export-ca-cert [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--output`, `-o` | no | string | — | Output file path (default: stdout) |
| `--ca-dir` | no | string | — | CA directory path (default: /var/lib/venya/ca) |

**Examples**

```bash
venya admin export-ca-cert  # CA certificate to stdout (distribute to executors)
venya admin export-ca-cert -o /secure/venya-ca.crt  # write to a file
```

### `venya admin export-ca-key`

Export the CA private key (encrypted with passphrase)

```
venya admin export-ca-key --output OUTPUT [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--output`, `-o` | **yes** | string | — | Output file path for encrypted key |
| `--ca-dir` | no | string | — | CA directory path (default: /var/lib/venya/ca) |

**Examples**

```bash
venya admin export-ca-key -o /secure/admin-ca.key.enc  # export the CA key, encrypted with the CA passphrase
```

### `venya admin split-ca-key`

Split CA key using Shamir's Secret Sharing

```
venya admin split-ca-key --threshold THRESHOLD --shares SHARES --output-dir OUTPUT_DIR [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--threshold`, `-t` | **yes** | int | — | Minimum shares needed to reconstruct (K) |
| `--shares`, `-s` | **yes** | int | — | Total number of shares to create (N) |
| `--output-dir`, `-d` | **yes** | string | — | Directory to write share files |
| `--ca-dir` | no | string | — | CA directory path (default: /var/lib/venya/ca) |

**Examples**

```bash
venya admin split-ca-key -t 2 -s 3 -d /secure/shares  # Shamir split: any 2 of 3 shares reconstruct the key
```

### `venya admin restore-ca-key`

Restore CA key from shares or encrypted backup

```
venya admin restore-ca-key --mode {shares|backup} [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--mode` | **yes** | one of: `shares`, `backup` | — | Restore mode: from shares (SSS) or from encrypted backup file |
| `--shares` | no | repeatable/space-separated list | — | Share files for SSS restore (e.g., share-1 share-2 share-3) |
| `--backup-file` | no | string | — | Encrypted backup file for backup restore mode |
| `--ca-dir` | no | string | — | CA directory path (default: /var/lib/venya/ca) |

**Examples**

```bash
venya admin restore-ca-key --mode shares --shares share-1 share-2  # reconstruct from SSS shares
venya admin restore-ca-key --mode backup --backup-file /secure/admin-ca.key.enc  # restore from the encrypted backup
```

### `venya admin init-admin-ca`

Initialize the admin CA (create key/cert pair)

```
venya admin init-admin-ca --output-dir OUTPUT_DIR
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--output-dir` | **yes** | string | — | Directory to create admin CA key/cert in |

**Examples**

```bash
venya admin init-admin-ca --output-dir /var/lib/venya/ca/admin-ca  # create the admin CA key/cert pair
```

### `venya admin generate-admin-cert`

Sign an admin client certificate

```
venya admin generate-admin-cert <IDENTITY> --output-dir OUTPUT_DIR [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `IDENTITY` (positional) | **yes** | string | — | Admin identity (used as CN and SAN DNS name) |
| `--ca-dir` | no | string | — | Admin CA directory path (default: $VENYA_ADMIN_CA_DIR or /var/lib/venya/ca/admin-ca) |
| `--output-dir` | **yes** | string | — | Directory to write admin cert/key to |

**Examples**

```bash
venya admin generate-admin-cert admin1 --output-dir /etc/venya/admin  # sign an admin client certificate (identity = CN + SAN DNS name)
```

### `venya admin revoke-admin-cert`

Revoke an admin certificate by serial number

```
venya admin revoke-admin-cert --serial SERIAL [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--serial` | **yes** | string | — | Hex serial number of certificate to revoke |
| `--reason` | no | string | `unspecified` | Revocation reason (default: unspecified) |
| `--server-url` | no | string | — | Core server URL (default: from config or VENYA_SERVER_URL) |

**Examples**

```bash
venya admin revoke-admin-cert --serial 1A2B3C  # revoke by hex serial; mTLS bundle then rejects it
```

## `venya role`

Role management

```
venya role
```

Subcommands:

- [`venya role create`](#venya-role-create) — Create a role
- [`venya role list`](#venya-role-list) — List all roles
- [`venya role get`](#venya-role-get) — Get role details
- [`venya role delete`](#venya-role-delete) — Delete a role
- [`venya role members`](#venya-role-members) — List role members
- [`venya role add-member`](#venya-role-add-member) — Add user to role
- [`venya role remove-member`](#venya-role-remove-member) — Remove user from role

### `venya role create`

Create a role

```
venya role create <NAME> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `NAME` (positional) | **yes** | string | — | Role name |
| `--permissions` | no | one of: `read`, `read-write` | `read` | Permission tier |
| `--description` | no | string | — | Role description |

**Examples**

```bash
venya role create app  # read-only role (default tier)
venya role create app --permissions read-write --description 'App secrets'  # read-write tier with a description
```

### `venya role list`

List all roles

```
venya role list [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya role list  # all roles
```

### `venya role get`

Get role details

```
venya role get <ROLE_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `ROLE_ID` (positional) | **yes** | string | — | Role ID or name |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya role get app  # role details by name or ID
```

### `venya role delete`

Delete a role

```
venya role delete <ROLE_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `ROLE_ID` (positional) | **yes** | string | — | Role ID or name |

**Examples**

```bash
venya role delete app  # delete a role
```

### `venya role members`

List role members

```
venya role members <ROLE_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `ROLE_ID` (positional) | **yes** | string | — | Role ID or name |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya role members app  # users and executors in the role
```

### `venya role add-member`

Add user to role

```
venya role add-member <ROLE_ID> <USER_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `ROLE_ID` (positional) | **yes** | string | — | Role ID or name |
| `USER_ID` (positional) | **yes** | string | — | User ID to add |

**Examples**

```bash
venya role add-member app jsmith  # grant a user the role
```

### `venya role remove-member`

Remove user from role

```
venya role remove-member <ROLE_ID> <USER_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `ROLE_ID` (positional) | **yes** | string | — | Role ID or name |
| `USER_ID` (positional) | **yes** | string | — | User ID to remove |

**Examples**

```bash
venya role remove-member app jsmith  # revoke the role from a user
```

## `venya recovery`

Break-glass recovery

```
venya recovery <CODE> <NEW_USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `CODE` (positional) | **yes** | string | — | Recovery code |
| `NEW_USER_ID` (positional) | **yes** | string | — | New user ID |
| `--force` | no | flag | false (flag) | Force operation |
| `--confirm` | no | flag | false (flag) | Confirm recovery action |

**Examples**

```bash
venya recovery RECOVERY-CODE newadmin  # break-glass: restore admin access with the one-shot recovery code
venya recovery RECOVERY-CODE newadmin --confirm  # skip the interactive confirmation prompt
```

## `venya run`

Execute a command via executor (Stage 1 + Stage 2 filtering)

```
venya run [-- <command> ...] [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `COMMAND_ARGS` (positional, remainder) | no | remainder (see note) | — | Command to execute (a leading -- separator is consumed, not sent to the executor) |
| `--secret` | no | repeatable (accumulates) | — | Secret key to inject (can be specified multiple times) |
| `--executor-id` | no | string | — | Executor ID to target (default: from config or 'default') |
| `--server-url` | no | string | — | Server URL override (default: from config) |

> **REMAINDER semantics (`run` only):** everything after the first command token belongs to
> the remote command — including tokens that look like venya flags (`venya run ssh -o ...` sends
> `-o` to ssh, not to venya). A leading `--` separator is accepted and stripped before sending
> (`venya run -- /usr/bin/true`). Venya's own options (`--secret`, `--executor-id`,
> `--server-url`) must come BEFORE the command.

**Examples**

```bash
venya run -- /usr/bin/true  # smoke-test an executor round trip
venya run --secret db/password -- /usr/bin/ssh tier1@t1 systemctl status apache2  # inject a secret into a sandboxed remote command; the agent never sees the value
venya run --executor-id venya-exec-1 -- /bin/echo hello  # target a specific executor
```

## `venya exec`

Executor lifecycle operations

```
venya exec
```

Subcommands:

- [`venya exec register`](#venya-exec-register) — Register this machine as an executor with the core
- [`venya exec cert`](#venya-exec-cert) — Certificate management
- [`venya exec heartbeat`](#venya-exec-heartbeat) — Send heartbeat to core
- [`venya exec audit`](#venya-exec-audit) — View executor audit log
- [`venya exec status`](#venya-exec-status) — Show executor registration status

### `venya exec register`

Register this machine as an executor with the core

```
venya exec register [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--executor-id` | no | string | `venya-exec` | Executor ID (default: venya-exec) |
| `--core-url` | no | string | — | Core server URL (default: from config) |
| `--output-dir` | no | string | `/etc/venya/executor` | Directory to save cert and key (default: /etc/venya/executor) |
| `--enrollment-token` | no | string | — | Enrollment token for bootstrap registration (from admin executor-enroll) |
| `--ca-bundle` | no | string | — | Path to CA bundle for verifying core server TLS |

**Examples**

```bash
venya exec register  # register this machine as an executor (mTLS cert from config)
venya exec register --executor-id venya-exec-1 --enrollment-token TOKEN --core-url https://venya-core-1  # bootstrap registration with an enrollment token from admin executor-enroll
```

### `venya exec cert`

Certificate management

```
venya exec cert
```

Subcommands:

- [`venya exec cert status`](#venya-exec-cert-status) — Show certificate expiry status
- [`venya exec cert renew`](#venya-exec-cert-renew) — Renew executor certificate
- [`venya exec cert revoke`](#venya-exec-cert-revoke) — Revoke an executor certificate (admin action)

#### `venya exec cert status`

Show certificate expiry status

```
venya exec cert status [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--cert-path` | no | string | `/etc/venya/executor/executor.crt` | Path to executor certificate (default: /etc/venya/executor/executor.crt) |

**Examples**

```bash
venya exec cert status  # expiry status of the local executor certificate
venya exec cert status --cert-path /etc/venya/executor/executor.crt  # explicit cert path
```

#### `venya exec cert renew`

Renew executor certificate

```
venya exec cert renew [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--cert-path` | no | string | `/etc/venya/executor/executor.crt` | Path to executor certificate (default: /etc/venya/executor/executor.crt) |
| `--key-path` | no | string | — | Path to executor private key (default: derive from --cert-path) |

**Examples**

```bash
venya exec cert renew  # renew the executor certificate before expiry
```

#### `venya exec cert revoke`

Revoke an executor certificate (admin action)

```
venya exec cert revoke [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--executor-id` | no | string | — | Executor ID to revoke (default: read from local cert file) |
| `--cert-path` | no | string | `/etc/venya/executor/executor.crt` | Path to executor certificate file (used for ID fallback, default: /etc/venya/executor/executor.crt) |

**Examples**

```bash
venya exec cert revoke  # revoke own cert (ID read from the local cert file)
venya exec cert revoke --executor-id venya-exec-1  # admin action against another executor
```

### `venya exec heartbeat`

Send heartbeat to core

```
venya exec heartbeat [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--core-url` | no | string | — | Core server URL (default: from config) |
| `--cert-path` | no | string | `/etc/venya/executor/executor.crt` | Path to executor certificate (default: /etc/venya/executor/executor.crt) |
| `--key-path` | no | string | — | Path to executor private key (default: derive from --cert-path) |

**Examples**

```bash
venya exec heartbeat  # one heartbeat to the core (the daemon sends these automatically)
```

### `venya exec audit`

View executor audit log

```
venya exec audit [EXECUTOR_ID] [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `EXECUTOR_ID` (positional, nargs=?) | no | string | — | Executor ID to audit (default: read from local cert file) |
| `--cert-path` | no | string | `/etc/venya/executor/executor.crt` | Path to executor certificate file (used for ID fallback, default: /etc/venya/executor/executor.crt) |
| `--hours` | no | int | — | Query last N hours |
| `--days` | no | int | — | Query last N days |
| `--limit` | no | int | `100` | Max results (default: 100) |
| `--offset` | no | int | `0` | Result offset (default: 0) |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya exec audit  # audit trail for this executor (ID from the local cert)
venya exec audit venya-exec-1 --days 7 --json  # another executor, last 7 days, machine-readable
```

### `venya exec status`

Show executor registration status

```
venya exec status
```

*Takes no arguments.*

**Examples**

```bash
venya exec status  # registration status of this executor
```

## `venya config`

Manage CLI configuration

```
venya config
```

Subcommands:

- [`venya config show`](#venya-config-show) — Show current configuration
- [`venya config set-server`](#venya-config-set-server) — Set the server URL
- [`venya config clear-token`](#venya-config-clear-token) — Clear stored access token (forces re-auth)

### `venya config show`

Show current configuration

```
venya config show
```

*Takes no arguments.*

**Examples**

```bash
venya config show  # current CLI config (server URL, stored token state)
```

### `venya config set-server`

Set the server URL

```
venya config set-server <URL>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `URL` (positional) | **yes** | string | — | Server URL |

**Examples**

```bash
venya config set-server https://venya-core-1  # point the CLI at a core server
```

### `venya config clear-token`

Clear stored access token (forces re-auth)

```
venya config clear-token
```

*Takes no arguments.*

**Examples**

```bash
venya config clear-token  # drop the stored access token (forces re-auth on next call)
```

## `venya credential`

Manage credentials (security keys)

```
venya credential
```

Subcommands:

- [`venya credential list`](#venya-credential-list) — List own credentials
- [`venya credential add`](#venya-credential-add) — Add a new credential (requires security key)
- [`venya credential remove`](#venya-credential-remove) — Remove a credential (requires security key)

### `venya credential list`

List own credentials

```
venya credential list [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya credential list  # your registered security-key credentials
```

### `venya credential add`

Add a new credential (requires security key)

```
venya credential add <LABEL> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `LABEL` (positional) | **yes** | string | — | Label for the new credential |
| `--json` | no | flag | false (flag) | Output in JSON format |

**Examples**

```bash
venya credential add yubikey-office  # register an additional security key (touch required)
```

### `venya credential remove`

Remove a credential (requires security key)

```
venya credential remove <CREDENTIAL_ID>
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `CREDENTIAL_ID` (positional) | **yes** | string | — | Credential ID to remove |

**Examples**

```bash
venya credential remove 3  # remove a credential by ID (touch required)
```

## `venya enroll`

Enroll with a security key using an enrollment token

```
venya enroll <TOKEN> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `TOKEN` (positional) | **yes** | string | — | Enrollment token |
| `--label` | no | string | — | Label for the new credential |
| `--json` | no | flag | false (flag) | — |

**Examples**

```bash
venya enroll TOKEN  # enroll with an enrollment token; binds your security key
venya enroll TOKEN --label yubikey-office  # label the new credential
```

## `venya login`

Authenticate with a security key

```
venya login <USER_ID> [OPTIONS]
```

| Argument | Required | Type / choices | Default | Description |
|----------|----------|----------------|---------|-------------|
| `USER_ID` (positional) | **yes** | string | — | User ID to authenticate as |
| `--json` | no | flag | false (flag) | — |

**Examples**

```bash
venya login jsmith  # authenticate with your security key; stores a session token
venya login jsmith --json  # machine-readable result
```
