# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""At-rest CA-key envelope helpers (ticket #297 ca-key-export-blind-to-at-rest).

The server stores ca.key / admin-ca.key as OpenSSL PKCS#8 encrypted PEM
(``BestAvailableEncryption``) keyed by VENYA_CA_KEY_PASSPHRASE /
VENYA_ADMIN_CA_KEY_PASSPHRASE — the spec is server/ca.py (_serialize_key_encrypted
/_deserialize_key/_load_passphrase). The CLI has no core/server dependency —
the same rule that keeps the CA-key BACKUP envelope CLI-side, one implementation
(the server pair was retired by `b7d814d`, #336 ruling A; #609 corrected the
comment that still claimed a twin) — so these are library-level ALIGNED
COPIES of that codec, pinned by tests/test_cli_ca_key_at_rest.py against the
same cryptography calls the server makes.

Auto-detect order (owner ruling Q1b): try plaintext PEM parse FIRST (legacy
pre-at-rest files pass through untouched), else decrypt PKCS#8 with the server
passphrase, else fail LOUD. There is no third form — bytes that are neither
parse plaintext nor passphrase-openable PKCS#8 abort every custody path with
zero writes and zero shards. Plaintext key material is never persisted by this
module (except as the at-rest envelope output of rewrap) and never echoed.
"""

import getpass
import os
import sys
import tempfile
from pathlib import Path


def server_passphrase_env_for(key_path: Path) -> str:
    """Env var NAME (never value) that carries the server passphrase for this key file."""
    if key_path.name.startswith("admin-ca"):
        return "VENYA_ADMIN_CA_KEY_PASSPHRASE"
    return "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password


def resolve_ca_key_path(ca_dir: str | Path) -> Path:
    """Resolve the at-rest key file inside a CA directory (Q4 key-agnostic).

    Prefers ca.key, falls back to admin-ca.key; when neither exists returns
    the ca.key path so callers print the traditional not-found error.
    """
    directory = Path(ca_dir)
    for name in ("ca.key", "admin-ca.key"):
        candidate = directory / name
        if candidate.exists():
            return candidate
    return directory / "ca.key"


def unwrap_at_rest(data: bytes, server_passphrase: str | None = None) -> bytes:
    """Return the PLAINTEXT PEM bytes behind an at-rest key file, in memory.

    Plaintext-parseable data is returned as-is (legacy pass-through). PKCS#8
    encrypted data is decrypted with the server passphrase and re-serialized
    unencrypted. Everything else raises ValueError — loud, never silent.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption,
        PrivateFormat,
    )

    try:
        serialization.load_pem_private_key(data, password=None)
        return data
    except (ValueError, TypeError):
        # ValueError: unparseable bytes. TypeError: encrypted PEM with no
        # password ("Password was not given but private key is encrypted").
        # Both mean "not plaintext" — decided (or failed LOUD) below.
        pass

    if not server_passphrase:
        raise ValueError(
            "at-rest key is not a plaintext PEM private key — the server passphrase is "
            "required (enter it when prompted or set the environment variable)"
        )
    try:
        key = serialization.load_pem_private_key(data, password=server_passphrase.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("failed to decrypt at-rest CA key with the provided server passphrase") from exc
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def rewrap_at_rest(plaintext_pem: bytes, server_passphrase: str | None) -> bytes:
    """Re-encrypt plaintext PEM into the at-rest envelope.

    No passphrase (legacy install / disaster restore): the plaintext is
    returned unchanged — that IS the legacy at-rest format (pre-4218ec1/
    3667c6e installs); the server keeps its own unencrypted-at-rest warning.
    """
    if not server_passphrase:
        return plaintext_pem
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        PrivateFormat,
    )

    key = serialization.load_pem_private_key(plaintext_pem, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(server_passphrase.encode("utf-8")),
    )


def acquire_server_passphrase(env_var: str) -> str:
    """Interactive getpass primary; env-var override for automation (Q1).

    The env var wins when set (mirrors the server's os.environ-only load);
    otherwise hidden prompt on a TTY; headless without env fails LOUD. The
    value is never echoed or logged — only the var NAME appears in prompts.
    """
    value = os.environ.get(env_var)
    if value:
        return value
    if not sys.stdin.isatty():
        raise ValueError(f"server passphrase required but {env_var} is not set and stdin is not a TTY")
    return getpass.getpass(f"Server CA key passphrase ({env_var}, hidden): ")


def restore_at_rest_bytes(key_path: Path, plaintext_pem: bytes) -> bytes:
    """Decide the at-rest envelope for a restore write (Q3b/Q5).

    Target encrypted  -> acquire + PROBE against the current file (a wrong
                          server passphrase aborts LOUD with zero writes;
                          byte-identity of the current file is preserved).
    Target plaintext  -> plaintext pass-through (legacy installs keep legacy
                          format — no-regression half of the fixture matrix).
    Target absent     -> disaster restore: encrypt when a passphrase is known
                          (env override, or TTY prompt; empty input declines),
                          else plaintext with a loud stderr warning.
    """
    env_var = server_passphrase_env_for(key_path)
    passphrase = None
    if key_path.exists():
        existing = key_path.read_bytes()
        try:
            unwrap_at_rest(existing)  # plaintext/legacy target
        except ValueError:
            passphrase = acquire_server_passphrase(env_var)
            try:
                unwrap_at_rest(existing, passphrase)
            except ValueError as exc:
                raise ValueError(
                    f"server passphrase does not decrypt the current at-rest key — nothing was written ({exc})"
                ) from exc
        return rewrap_at_rest(plaintext_pem, passphrase)

    passphrase = os.environ.get(env_var)
    if not passphrase and sys.stdin.isatty():
        passphrase = getpass.getpass(
            f"Server CA key passphrase for the restored key ({env_var}, hidden, Enter=leave unencrypted): "
        )
    if passphrase:
        return rewrap_at_rest(plaintext_pem, passphrase)
    print(
        f"warning: restoring key UNENCRYPTED at rest — set {env_var} to keep the "
        "server's encrypt-at-rest invariant (the server also warns at boot)",
        file=sys.stderr,
    )
    return plaintext_pem


def atomic_write_key(key_path: Path, data: bytes) -> None:
    """Atomic at-rest key write: temp file in the same dir, fsync, 0600,
    ownership per installer precedent (inherit the current file's, else the
    directory's — the CA dirs are owned by the ``venya`` service account),
    then os.replace. On any failure the temp file is removed and the original
    is untouched (the byte-identity property that saved drill R6-b).
    """
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    ensure_secret_dir(key_path.parent)
    stat_src = key_path if key_path.exists() else key_path.parent
    uid, gid = stat_src.stat().st_uid, stat_src.stat().st_gid
    fd, tmp_name = tempfile.mkstemp(prefix=f"{key_path.name}.", suffix=".tmp", dir=str(key_path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        try:
            os.chown(tmp_name, uid, gid)
        except (PermissionError, OSError):
            pass  # best-effort: non-root cannot chown; mode+atomicity still hold
        os.replace(tmp_name, str(key_path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def ensure_secret_dir(dir_path: Path) -> None:
    """Normalize a secret-bearing directory toward owner-only 0700 (#317).

    mkdir(..., mode=0o700, exist_ok=True) never touches a PRE-EXISTING dir,
    so upgraded installs kept looser config/log/at-rest dirs. Run after the
    mkdir at every creation site. Tightens only, never loosens:

    - 0700 or stricter: silent no-op.
    - world bits set and dir owned by the current euid: chmod to 0700.
    - group-only bits (deliberate shared-custody channel; the 0600 files
      inside already guard contents): warn, leave intact.
    - looser but not owner-owned: warn LOUD, attempt no chmod — a
      service-account-owned dir must not turn every CLI command into a
      traceback.

    The ladder is a POSIX-only concept: on non-POSIX platforms the function
    is a no-op (no mode bits, no ownership semantics, no os.geteuid()).
    """
    try:
        st = os.stat(str(dir_path))
    except OSError:
        return  # raced away / unstatable: the mkdir call site reports it
    if os.name != "posix":
        # Windows has no POSIX mode bits, no ownership semantics, and no
        # os.geteuid(): the tightening ladder below is a POSIX-only concept.
        # Skip silently — a per-command warning would be noise, and NTFS ACLs
        # are the real control on that platform.
        return
    mode = st.st_mode & 0o777
    if not (mode & ~0o700):
        return  # already 0700-or-stricter
    owned = st.st_uid == os.geteuid()
    if owned and (mode & 0o007):
        try:
            os.chmod(str(dir_path), 0o700)
        except OSError as e:
            print(f"WARNING: cannot tighten {dir_path} (mode {mode:03o}): {e}", file=sys.stderr)
        return
    if owned:
        reason = "group bits look deliberate — left intact"
    else:
        reason = "not owned by the current user — secure it manually"
    print(
        f"WARNING: {dir_path} mode {mode:03o} is looser than 0700 ({reason})",
        file=sys.stderr,
    )
