# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Workstation/executor-host copy of the executor-key passphrase envelope (#565).

The CLI writes ``executor.key`` from two commands — ``venya exec register`` and
``venya exec cert renew`` — and reads it from three (``cert renew``, ``cert
status``-adjacent dials and ``heartbeat``). Those keys are consumed by the
executor daemon, so the envelope must be byte-identical to the daemon's own
(``packages/executor/src/executor/key_passphrase.py``), and this module is the
aligned copy: the CLI carries no dependency on the executor or server package
(the same rule that puts ``at_rest_key.py`` beside it), so the codec is repeated
here and pinned from the other side by
``packages/cli/tests/test_executor_key_envelope_parity_565.py``.

Posture, in one line, from R7-Q3 (`decisions.md` commit `1bf25ae`, quoted in
``docs/design-fido2-keywrap-565.md`` §6): a file passphrase is DISK PROTECTION,
not hardware custody — the retirement trigger is a fleet host with authenticator
attachment or a CSR lifecycle in which private material never lands on the host.
Nothing here may be described as a hardware key.
"""

import os
import sys
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization

#: Env var NAME (never value) carrying the executor key passphrase. Must equal
#: the executor package's constant — the parity cell checks it, because two
#: names drifting apart means a key one half of the product can write and the
#: other half cannot read.
EXECUTOR_KEY_PASSPHRASE_ENV = "VENYA_EXECUTOR_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

#: #573 floor and stated ceiling, same numbers as every other plane in the
#: product (server `ca.py`, this file). Counted in Unicode code points on the
#: decoded string before any encode.
MIN_PASSPHRASE_CODE_POINTS = 15
MAX_PASSPHRASE_CODE_POINTS = 64

#: The value a hidden prompt asks for has no variable name to point at, so the
#: blessed #573 block's subject slot carries this phrase instead.
_TYPED_PROMPT_SUBJECT = "the passphrase you enter at this prompt"


def configured_passphrase(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str | None:
    """The env-carried passphrase, or None when there is no real one (#554 shape).

    Unset, empty and whitespace-only all read as "no passphrase"; an acceptable
    value is returned byte-for-byte — DENY, never TRIM.
    """
    passphrase = os.environ.get(env_var)
    if passphrase and passphrase.strip():
        return passphrase
    return None


def is_below_floor(passphrase: str | None) -> bool:
    """True when a SUPPLIED passphrase carries material but is under the #573 floor."""
    return passphrase is not None and len(passphrase) < MIN_PASSPHRASE_CODE_POINTS


def short_passphrase_refusal(subject: str, *, read_path: bool = False) -> str:
    """#573 refusal text, same block as the executor/server planes.

    Interpolates only the SUBJECT (an env-var NAME, or the typed-prompt phrase) —
    never the value, never its length. The read door deletes exactly one clause,
    ``Nothing was written.``
    """
    written_clause = "" if read_path else " Nothing was written."
    return (
        f"REFUSED: {subject} is set to a passphrase shorter than Venya's minimum.{written_clause}\n"
        "Why it matters: this passphrase is the only thing between a copied key file and the\n"
        "executor's mTLS identity, and short passphrases are what an attacker tries first.\n"
        "To fix it:\n"
        f"  1. Replace the value of {subject} with a passphrase of at least "
        f"{MIN_PASSPHRASE_CODE_POINTS} characters.\n"
        "     Spaces count as characters, but a passphrase made only of spaces counts as no passphrase.\n"
        f"  2. There is no rule about which characters appear — length is the only requirement, and\n"
        f"     Passphrases longer than {MAX_PASSPHRASE_CODE_POINTS} characters are accepted too — "
        f"{MAX_PASSPHRASE_CODE_POINTS} is the length Venya guarantees to support, not a maximum it enforces.\n"
        "  3. Provide the passphrase through the service environment (the systemd EnvironmentFile\n"
        "     the executor installer maintains), never as a command-line argument — command-line\n"
        "     values are visible to other processes on the machine.\n"
        "Your existing executor certificate and key were not modified by this refusal.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def unencrypted_key_refusal(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str:
    """The write-side refusal: this command would have produced a plaintext key."""
    return (
        "REFUSED: the executor private key must never be stored unencrypted. Nothing was written.\n"
        "Why it matters: anyone who can read an unencrypted executor key can impersonate this\n"
        "executor on the control channel and run commands under its identity.\n"
        "To fix it:\n"
        f"  1. Set {env_var} before running this command. On an installed host the value lives\n"
        "     in the root-only EnvironmentFile the executor installer maintains\n"
        "     (/etc/venya/venya-executor.env, mode 0640 root:venya).\n"
        "  2. If this executor was installed before this requirement, its key is plaintext on disk\n"
        "     and still READS normally; the refusal is on the next write (registration or\n"
        "     rotation). Set the passphrase, then renew once.\n"
        "  3. Provide the passphrase through the service environment, never as a command-line\n"
        "     argument (command-line values are visible to other processes on the machine).\n"
        "Your existing executor certificate and key were not modified by this refusal.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def decrypt_refusal(key_path: Any = None, env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str:
    """Read-side refusal: the file is an encrypted envelope this host cannot open."""
    where = f" at {key_path}" if key_path else ""
    return (
        f"REFUSED: the executor private key{where} is encrypted and {env_var} did not open it.\n"
        "Nothing was sent and no file was changed.\n"
        "Why it matters: without the passphrase the executor cannot present its mTLS identity,\n"
        "so it cannot reach the core — a stopped executor is honest, a re-minted identity is not.\n"
        "To fix it:\n"
        f"  1. Set {env_var} in the root-only EnvironmentFile the executor installer maintains\n"
        "     (/etc/venya/venya-executor.env) and restart the service.\n"
        "  2. If the passphrase is genuinely lost, re-enroll: mint a fresh enrollment token on an\n"
        "     admin workstation (`venya admin executor-enroll`) and re-run the executor installer.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def acquire_write_passphrase(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str:
    """The write-time ceremony: env var primary, hidden prompt on a TTY, LOUD otherwise.

    ``venya exec register`` and ``venya exec cert renew`` both run from
    ``install-venya-executor.sh`` on a host with no operator at a keyboard, so
    the environment is the shipped path and the prompt is the interactive one.
    A headless invocation with no env var fails HERE — before the caller has
    generated a keypair, opened a socket, created a directory or staged a temp
    (#565 AC3, and AC4: no silent fallback to plaintext).
    """
    value = os.environ.get(env_var)
    if value and value.strip():
        if is_below_floor(value):
            raise RuntimeError(short_passphrase_refusal(env_var))
        return value
    if not sys.stdin.isatty():
        raise RuntimeError(unencrypted_key_refusal(env_var))
    import getpass

    typed = getpass.getpass(
        f"Executor private key passphrase ({env_var}, hidden) — at least "
        f"{MIN_PASSPHRASE_CODE_POINTS} characters required; longer than "
        f"{MAX_PASSPHRASE_CODE_POINTS} is accepted too: "
    )
    if not typed.strip():
        raise RuntimeError(unencrypted_key_refusal(env_var))
    if is_below_floor(typed):
        raise RuntimeError(short_passphrase_refusal(_TYPED_PROMPT_SUBJECT))
    return typed


def serialize_key_encrypted(private_key: Any, passphrase: str) -> bytes:
    """PKCS#8 + BestAvailableEncryption — the ONE envelope this CLI writes.

    Takes the already-resolved passphrase (see ``acquire_write_passphrase``):
    resolution happens once, at the top of the command, so the refusal fires
    before any work and the value never has to be read twice.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def ssl_password_callback(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> Callable[[], bytes]:
    """A ``password=`` callback for ``ssl.SSLContext.load_cert_chain``.

    OpenSSL invokes it ONLY for an encrypted key, so a legacy plaintext key on
    an existing host still dials with zero configuration; an encrypted key
    without a usable passphrase raises the named refusal instead of the bare
    OpenSSL ``PEM lib`` text.
    """

    def _password() -> bytes:
        passphrase = configured_passphrase(env_var)
        if passphrase is None:
            raise RuntimeError(decrypt_refusal(None, env_var))
        if is_below_floor(passphrase):
            raise RuntimeError(short_passphrase_refusal(env_var, read_path=True))
        return passphrase.encode("utf-8")

    return _password
