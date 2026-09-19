# Bandit `# nosec` Suppressions

<!-- GENERATED FILE — DO NOT HAND-EDIT.
     Source of truth: every `nosec` marker under packages/*/src.
     Regenerate: uv run -p 3.14 --directory packages/core python scripts/gen_bandit_suppressions.py
     Enforced by packages/core/tests/test_bandit_suppressions_doc.py (drift = RED). -->

Every suppression in the scanned source, verbatim. All entries are intentional —
false positives or deliberate design decisions; the comment on each line carries its
justification. Rows are keyed on file + line content (line numbers drift and are
deliberately not recorded). Scope = `packages/*/src` — the same tree the pre-commit
bandit hook scans (tests dirs are hook-excluded).

**56 suppression lines across 19 files.**

| File | Source line (verbatim) |
|------|------------------------|
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # noqa: S110  # nosec B110 — logging must never break the command` |
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # noqa: S110  # nosec B110` |
| `packages/cli/src/venya_cli/cli.py` | `except Exception:  # nosec B110 — unwritable config dir must not break the CLI` |
| `packages/cli/src/venya_cli/commands.py` | `except Exception:  # nosec B110  # noqa: S110 — ignore optional config parse errors` |
| `packages/cli/src/venya_cli/commands.py` | `except Exception:  # nosec B110  # noqa: S110` |
| `packages/cli/src/venya_cli/fido2_client.py` | `except Exception:  # noqa: S110  # nosec B110 — deliberate: parse failure keeps raw status text` |
| `packages/cli/src/venya_cli/webauthn.py` | `except Exception:  # nosec B110  # noqa: S110` |
| `packages/core/src/core/engine/encryption.py` | `from Crypto.Cipher import AES as PyCryptoAES  # nosec B413 — AES-KW per RFC 5649 requires pycryptodome` |
| `packages/core/src/core/engine/encryption.py` | `cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB` |
| `packages/core/src/core/engine/encryption.py` | `cipher = PyCryptoAES.new(kek, PyCryptoAES.MODE_ECB)  # nosec B305 — AES-KW per RFC 5649 requires ECB` |
| `packages/core/src/core/engine/secure_memory.py` | `except Exception:  # nosec B110 — best-effort unlock in __del__, no stack to unwind  # noqa: S110` |
| `packages/core/src/core/utils/sensitive_log.py` | `def token(value: Any, token_type: str = "UNKNOWN") -> Token:  # nosec B107 — not a password, just a type label` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/executor.py` | `import subprocess  # nosec B404 — executor requires subprocess to run commands` |
| `packages/executor/src/executor/executor.py` | `shell=False,  # nosec B603 — shell explicitly disabled for security` |
| `packages/executor/src/executor/injector.py` | `tmpfs_dir: str = "/tmp/venya_secrets",  # nosec B108 — tmpfs, not persistent disk` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/injector.py` | `secret_id="",  # nosec B106 — placeholder set by caller` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/injector.py` | `sentinel_hash="",  # nosec B106 — placeholder set by caller` |
| `packages/executor/src/executor/injector.py` | `secret_id="",  # nosec B106 — placeholder set by caller` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/injector.py` | `sentinel_hash="",  # nosec B106 — placeholder set by caller` |
| `packages/executor/src/executor/injector.py` | `secret_id="",  # nosec B106 — placeholder set by caller` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/injector.py` | `sentinel_hash="",  # nosec B106 — placeholder set by caller` |
| `packages/executor/src/executor/relay_listener.py` | `host: str = "0.0.0.0",  # nosec B104 — private relay net; mTLS CERT_REQUIRED + CN allowlist is the access control` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `import subprocess  # nosec B404 — sandbox strategy requires subprocess for sbx commands` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `SECRET_TMPFS_BASE = "/dev/shm/venya-secrets"  # nosec` | <!-- pragma: allowlist secret -->
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `WORKSPACE_BASE = str(Path.home() / ".venya-workspaces")  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `CONTAINER_SECRET_DIR = "/run/secrets/venya"  # nosec` | <!-- pragma: allowlist secret -->
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
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec B603 B607` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/executor/src/executor/strategies/sbx_strategy.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/ca.py` | `self._key_passphrase_env = "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/ca.py` | `self._key_passphrase_env = "VENYA_ADMIN_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/fido2/cli_enroll.py` | `except Exception:  # nosec B110  # noqa: S110 — skip devices that fail to open` |
| `packages/server/src/server/fido2/manager.py` | `except Exception:  # nosec B110 — db cleanup in finally block, outer scope handles error  # noqa: S110` |
| `packages/server/src/server/fido2/manager.py` | `except Exception:  # nosec B110` |
| `packages/server/src/server/middleware/auth.py` | `ACCESS_TOKEN_COOKIE = "venya_access_token"  # nosec B105 — cookie name, not a password` | <!-- pragma: allowlist secret -->
| `packages/server/src/server/rate_limit.py` | `except Exception:  # nosec B110 — best-effort JSON parse, None falls through  # noqa: S110` |
| `packages/server/src/server/rate_limit.py` | `except Exception:  # nosec B110 — best-effort DB query, None falls through  # noqa: S110` |
| `packages/server/src/server/routes/auth.py` | `pass  # nosec B110 — intentional, transaction rolled back by get_db finally` |
| `packages/server/src/server/routes/auth_browser.py` | `except Exception:  # nosec B110 — rollback best-effort before raising HTTPException` |
| `packages/server/src/server/utils/disk_encryption.py` | `import subprocess  # nosec B404 — disk encryption check requires subprocess for system commands` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
| `packages/server/src/server/utils/disk_encryption.py` | `result = subprocess.run(  # nosec` |
