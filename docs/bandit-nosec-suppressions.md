# Bandit `# nosec` Suppressions

<!-- GENERATED FILE — DO NOT HAND-EDIT.
     Source of truth: every `nosec` marker in the files the pre-commit
     bandit hook scans — all of packages/ minus the hook's own -x exclusions,
     parsed from .pre-commit-config.yaml; git-tracked files only.
     Regenerate: uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py
     Enforced by packages/core/tests/test_bandit_suppressions_doc.py (drift = RED). -->

Every suppression in the scanned source, verbatim. All entries are intentional —
false positives or deliberate design decisions; the comment on each line carries its
justification. Rows are keyed on file + line content (line numbers drift and are
deliberately not recorded). Scope = the bandit hook's own file set: `packages/` minus
the hook's `-x` exclusions, parsed from `.pre-commit-config.yaml` — one definition,
so the register and the hook cannot drift apart. If a marker is ever legitimately
needed in a non-src file (e.g. an alembic version or a script), it must land with
this register regenerated in the SAME commit — the drift interlock is RED until it is.

**83 suppression lines across 28 files.**

| File | Source line (verbatim) |
|------|------------------------|
| `packages/cli/src/venya_cli/at_rest_key.py` | `return "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # noqa: S110  # nosec B110 — logging must never break the command` |
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # noqa: S110  # nosec B110` |
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # nosec B110 — unwritable config dir must not break the CLI` |
| `packages/cli/src/venya_cli/commands.py` | `resp = httpx2.get(url, verify=False, timeout=5.0)  # nosec B403 -- scoped TOFU bootstrap; see docstring` |
| `packages/cli/src/venya_cli/commands.py` | `except Exception:  # nosec B110  # noqa: S110` |
| `packages/cli/src/venya_cli/executor_key.py` | `EXECUTOR_KEY_PASSPHRASE_ENV = "VENYA_EXECUTOR_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/cli/src/venya_cli/fido2_client.py` | `except Exception:  # noqa: S110  # nosec B110 — deliberate: parse failure keeps raw status text` |
| `packages/cli/src/venya_cli/webauthn.py` | `except Exception:  # nosec B110  # noqa: S110` |
| `packages/core/alembic/versions/043_revocation_epoch_597t2.py` | `"""  # nosec B608 — DDL text; every interpolation is a module literal, no argument reaches it` |
| `packages/core/alembic/versions/043_revocation_epoch_597t2.py` | `f"WHERE NOT EXISTS (SELECT 1 FROM {TABLE_NAME} WHERE id = {EPOCH_ROW_ID})"  # nosec B608 — seed-row INSERT built only from module literals; no argument reaches it` |
| `packages/core/scripts/gen_bandit_suppressions.py` | `import subprocess  # nosec B404 — git ls-files provides the tracked set; fixed argv, no shell` |
| `packages/core/scripts/gen_bandit_suppressions.py` | `raw = subprocess.run(  # nosec B603 B607 — git ls-files with fixed argv list, no shell, no external input` |
| `packages/core/src/core/engine/encryption.py` | `from Crypto.Cipher import AES as PyCryptoAES  # nosec B413 — AES-KW per RFC 5649 requires pycryptodome` |
| `packages/core/src/core/engine/encryption.py` | `cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB` |
| `packages/core/src/core/engine/encryption.py` | `cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB` |
| `packages/core/src/core/engine/secure_memory.py` | `except Exception:  # nosec B110 — best-effort unlock in __del__, no stack to unwind  # noqa: S110` |
| `packages/core/src/core/utils/sensitive_log.py` | `def token(value: Any, token_type: str = "UNKNOWN") -> Token:  # nosec B107 — not a password, just a type label` | <!-- pragma: allowlist secret -->
| `packages/core/src/core/version.py` | `import subprocess  # nosec B404 — the build-face answer reads `git` beside the artifact; same system-tool seam as utils/disk_encryption.py` |
| `packages/core/src/core/version.py` | `subprocess.run(  # nosec B603 B607 — fixed argv, shell disabled, constant "git" on PATH, bounded by timeout` |
| `packages/executor/src/executor/executor.py` | `import subprocess  # nosec B404 — executor requires subprocess to run commands` |
| `packages/executor/src/executor/executor.py` | `os.killpg(os.getpgid(process.pid), 9)  # nosec B606 — no shell string; a pid we own` |
| `packages/executor/src/executor/executor.py` | `shell=False,  # nosec B603 — shell explicitly disabled for security` |
| `packages/executor/src/executor/key_passphrase.py` | `EXECUTOR_KEY_PASSPHRASE_ENV = "VENYA_EXECUTOR_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/relay_listener.py` | `host: str = "0.0.0.0",  # nosec B104 — private relay net; mTLS CERT_REQUIRED + CN allowlist is the access control` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `import subprocess  # nosec B404 — sandbox strategy requires subprocess for sbx commands` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"  # nosec` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `WORKSPACE_BASE = str(Path.home() / ".venya-workspaces")  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `probe = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `# nosec B108: /tmp here is inside the sandbox's own` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `["sbx", "exec", "-i", sandbox_name, "tee", "/tmp/sshpass"],  # nosec B108` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `["sbx", "exec", sandbox_name, "chmod", "+x", "/tmp/sshpass"],  # nosec B108` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `mkdir_result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `chmod_result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `mkdir_result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `os.fchmod(fh.fileno(), 0o555)  # nosec B103 — read+exec for the` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `cp_result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec B603 B607` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/server/scripts/gen_beta_terms_pins.py` | `import subprocess  # nosec B404 — own git reads, fixed argv` |
| `packages/server/scripts/gen_beta_terms_pins.py` | `r = subprocess.run(  # nosec B603 B607 — fixed argv, git on PATH` |
| `packages/server/scripts/gen_beta_terms_pins.py` | `return eval(compile(ast.Expression(v), "<manifest-value>", "eval"), vars(mod))  # nosec B307 — own AST nodes` |
| `packages/server/scripts/gen_beta_terms_pins.py` | `key = eval(compile(ast.Expression(k), "<manifest-key>", "eval"), vars(mod))  # nosec B307 — own AST nodes` |
| `packages/server/scripts/gen_beta_terms_pins.py` | `key = eval(compile(ast.Expression(k), "<k>", "eval"), vars(mod))  # nosec B307 — own AST nodes` |
| `packages/server/scripts/gen_install_script_hashes.py` | `import subprocess  # nosec B404 — own git reads, fixed argv` |
| `packages/server/scripts/gen_install_script_hashes.py` | `out = subprocess.run(  # nosec B603 B607 — fixed argv, git on PATH, own repo` |
| `packages/server/src/server/audit_lifecycle.py` | `ENROLLMENT_TOKEN_ISSUED = "enrollment_token_issued"  # nosec B105 — audit event name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/audit_lifecycle.py` | `ENROLLMENT_TOKEN_REVOKED = "enrollment_token_revoked"  # nosec B105 — audit event name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/audit_lifecycle.py` | `EXECUTOR_ENROLLMENT_TOKEN_CREATED = "executor_enrollment_token_created"  # nosec B105 — audit event name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/ca.py` | `self._key_passphrase_env = "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/ca.py` | `self._key_passphrase_env = "VENYA_ADMIN_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/middleware/auth.py` | `ACCESS_TOKEN_COOKIE = "venya_access_token"  # nosec B105 — cookie name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/rate_limit.py` | `except Exception:  # nosec B110 — best-effort JSON parse, None falls through  # noqa: S110` |
| `packages/server/src/server/routes/admin.py` | `"enrollment_token_created": True,  # nosec B105 — audit bool flag, not a token value` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/routes/admin.py` | `"enrollment_token_created": True,  # nosec B105 — audit bool flag, not a token value` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/routes/auth_browser.py` | `except Exception:  # nosec B110 — rollback best-effort before raising HTTPException` |
| `packages/server/src/server/routes/executors.py` | `import subprocess  # nosec B404 — CRL capath bootstrap uses `openssl rehash`; same system-tool seam as utils/disk_encryption.py` |
| `packages/server/src/server/routes/executors.py` | `subprocess.run(  # nosec B603 B607 — fixed argv, no shell, constant 'openssl' on PATH; same seam as utils/disk_encryption.py` |
| `packages/server/src/server/routes/executors.py` | `token_audit_fields = {"with_token": True, "token_verified": True, "token_id": token.id}  # nosec B105 — bools` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/routes/executors.py` | `token_audit_fields = {"with_token": False, "incumbent_exempt": True}  # nosec B105 — two bools` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/routes/executors.py` | `token_audit_fields = {"with_token": False}  # nosec B105 — one bool` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/routes/secrets.py` | `SECRET_KEY_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"  # nosec B105 — charset pattern, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/utils/disk_encryption.py` | `import subprocess  # nosec B404 — disk encryption check requires subprocess for system commands` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec B603 — fixed argv, no shell, constant tool name on PATH` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/venya-contract/src/venya_contract/relay.py` | `CONTAINER_SECRET_DIR = "/run/secrets/venya"  # nosec` | <!-- pragma: allowlist secret -->
