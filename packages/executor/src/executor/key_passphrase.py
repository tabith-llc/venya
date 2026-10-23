# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Executor mTLS private-key passphrase envelope (ticket #565, sites 5-6 of the body list).

The executor's own leaf key (`mtls.key`) used to be serialized with
``serialization.NoEncryption()`` at every writer — the daemon's
``CertificateManager.register``/``rotate`` and the workstation CLI's
``venya exec register``/``venya exec cert renew`` — so the private half of the
identity sat in the clear on the executor host. The owner's option-B word
(2026-10-09, "unencrypted key delivery is a defect that needs fixing") keeps
those writers in the fix set, and R7-Q3 (`decisions.md`, booked at commit
`1bf25ae`) rules the shape for these unattended sites: a **write-time ceremony
plus a file passphrase delivered by a root-only systemd `EnvironmentFile`**.

Read this module's posture out of `docs/design-fido2-keywrap.md` §6 before
editing it. Two of its clauses bind the code here:

* **"This is NOT hardware custody."** The passphrase lives on the host. The
  model is disk protection with an honest label, and the label discipline is
  the control that keeps the model from drifting into a claim it does not
  support — no comment, refusal or log line in here may imply a hardware key.
* **Interim, with a written retirement trigger.** It retires when a
  production-capable fleet host has authenticator attachment (USB passthrough),
  or when a CSR-shaped lifecycle means private material never lands on the host.
  Do not "improve" this into a permanent design; open the ruling instead.

The codec is an ALIGNED COPY of the server's CA-plane shape
(``packages/server/src/server/ca.py``: ``_configured_passphrase`` /
``_load_passphrase`` / ``_serialize_key_encrypted``), repeated here because the
executor package must not import the server package (the same #466
server-absent rule the test conftest carries). ``#554``'s blank-is-no-
passphrase answer and the ``#573`` length floor are the same numbers, on this
plane, for the same reason: a secret that carries no material is decoration.
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

#: Env var NAME (never value) that carries the executor key passphrase on an
#: installed host — the systemd `EnvironmentFile` twin of the core's
#: `VENYA_CA_KEY_PASSPHRASE`. The name is a constant so a refusal can print it
#: and an operator can set it without reading source.
EXECUTOR_KEY_PASSPHRASE_ENV = "VENYA_EXECUTOR_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

#: #573 floor, counted in Unicode CODE POINTS on the decoded string before any
#: encode (NIST SP 800-63B-4 counts what the operator typed, not its UTF-8
#: length). 15 passes, 14 refuses. The ceiling is STATED only: research clause
#: C2 requires verifiers to permit at least 64 characters, so nothing here
#: refuses above it.
MIN_PASSPHRASE_CODE_POINTS = 15
MAX_PASSPHRASE_CODE_POINTS = 64


def configured_passphrase(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str | None:
    """The configured executor-key passphrase, or None when there is no real one.

    #554's answer, applied on this plane: unset, empty and whitespace-only all
    read as "no passphrase", and an acceptable value is returned byte-for-byte
    — DENY, never TRIM, so a passphrase whose spaces are content still opens
    the key it wrote. This is the ONE place that decides it; no caller strips.
    """
    passphrase = os.environ.get(env_var)
    if passphrase and passphrase.strip():
        return passphrase
    return None


def is_below_floor(passphrase: str | None) -> bool:
    """True when a SUPPLIED passphrase carries material but is under the #573 floor.

    ``None`` is the already-answered "no passphrase" shape (see
    ``configured_passphrase``), never "too short" — the floor runs after that
    question and does not replace it.
    """
    return passphrase is not None and len(passphrase) < MIN_PASSPHRASE_CODE_POINTS


def short_passphrase_refusal(subject: str, *, read_path: bool = False) -> str:
    """#573 refusal text for a passphrase under the floor, on the executor-key plane.

    One builder for both doors, interpolating only the SUBJECT (an env-var NAME,
    or the typed-prompt phrase) — never the value, never its length. The read
    door carries exactly one deletion, the ``Nothing was written.`` clause; no
    sentence is added on either side.
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
    """#537-shaped refusal: a writer that would have produced a plaintext key.

    The plaintext branch is not a fallback, it is the defect (#565 AC4), so
    every writer in this package refuses here with zero filesystem work done.
    """
    return (
        "REFUSED: the executor private key must never be stored unencrypted. Nothing was written.\n"
        "Why it matters: anyone who can read an unencrypted executor key can impersonate this\n"
        "executor on the control channel and run commands under its identity.\n"
        "To fix it:\n"
        f"  1. Set {env_var} for the venya-executor service. On an installed host the value lives\n"
        "     in the root-only EnvironmentFile the executor installer maintains\n"
        "     (/etc/venya/venya-executor.env, mode 0640 root:venya); re-running the installer\n"
        "     reuses the stored value and PRESERVES your existing key — it is not replaced.\n"
        "  2. If this executor was installed before this requirement, its key is plaintext on disk\n"
        "     and still READS normally; the refusal is on the next write (registration or\n"
        "     rotation). Set the passphrase, then rotate once.\n"
        "  3. Provide the passphrase through the service environment, never as a command-line\n"
        "     argument (command-line values are visible to other processes on the machine).\n"
        "Your existing executor certificate and key were not modified by this refusal.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def decrypt_refusal(key_path: Any = None, env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> str:
    """Read-side refusal for a key this host cannot open (no passphrase / wrong one).

    Deliberately does NOT claim a passphraseless file is corrupt: legacy
    installs hold a plaintext key and load it normally (see
    ``load_private_key``). Reaching this text means the file IS an encrypted
    envelope and the passphrase was absent or did not open it. ``key_path`` is
    optional because the ssl callback learns the path only from its caller's
    log line, and a refusal must never invent one.
    """
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


def _refuse_if_below_floor(passphrase: str | None, subject: str, *, read_path: bool = False) -> None:
    """Raise the #573 floor refusal for an already-resolved passphrase."""
    if is_below_floor(passphrase):
        raise RuntimeError(short_passphrase_refusal(subject, read_path=read_path))


def passphrase_or_refuse(env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> bytes:
    """The passphrase BYTES a writer must encrypt with, or a loud refusal.

    Raises:
        RuntimeError: no passphrase configured (``unencrypted_key_refusal``),
            or one under the #573 floor (``short_passphrase_refusal``). Both
            fire before any filesystem work; nothing is written.
    """
    passphrase = configured_passphrase(env_var)
    if passphrase is None:
        raise RuntimeError(unencrypted_key_refusal(env_var))
    _refuse_if_below_floor(passphrase, env_var)
    return passphrase.encode("utf-8")


def serialize_key_encrypted(private_key: EllipticCurvePrivateKey, passphrase: bytes) -> bytes:
    """Serialize an executor private key into the at-rest encrypted envelope.

    PKCS#8 + ``BestAvailableEncryption``, the same call the server makes for its
    CA keys. The passphrase is the ALREADY-RESOLVED bytes from
    ``passphrase_or_refuse()`` — callers resolve once, at the top of the write
    path, so the refusal fires before the POST that would burn server state and
    before the first byte that would touch the disk. There is no plaintext
    branch here (#565 AC4: a silent fallback to plaintext is the defect
    returning, not the fix).
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def ssl_password_callback(
    env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV,
) -> Callable[[], bytes]:
    """A `password=` callback for ``ssl.SSLContext.load_cert_chain``.

    OpenSSL asks the callback ONLY when the key file is actually encrypted
    (measured: a plaintext key loads with zero callback invocations), so legacy
    installs keep booting on their existing plaintext key while a new encrypted
    key opens with the passphrase. A refusal raised here surfaces as the boot
    error naming the fix, never as a silent fallback — and never as the raw
    OpenSSL ``PEM lib`` text, which names no file and no repair.
    """

    def _password() -> bytes:
        passphrase = configured_passphrase(env_var)
        if passphrase is None:
            raise RuntimeError(decrypt_refusal(None, env_var))
        _refuse_if_below_floor(passphrase, env_var, read_path=True)
        return passphrase.encode("utf-8")

    return _password


def read_passphrase_or_none(key_path: Any, env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> bytes | None:
    """The passphrase THIS host should hand a reader, or None when the file needs none.

    Exists for the readers that take a positional password (httpx's
    ``cert=(cert, key, password)`` triple in the boot identity probe) rather than
    a callback. The decision is made by parsing, not by string-sniffing the PEM:

    * the file opens with no password → ``None`` — a legacy plaintext host hands
      its reader exactly what it handed it before #565, with nothing set;
    * the file is an encrypted envelope → the passphrase, or the named refusal
      when this host has none (a passphrase problem must not be reported to the
      operator as a TLS handshake failure or a ghost identity);
    * the file is unparseable → ``None``, so the existing handshake-classification
      path stays the one that answers (that shape is #480's recovery, not this
      module's question).
    """
    try:
        data = Path(key_path).read_bytes()
    except OSError:
        return None
    try:
        serialization.load_pem_private_key(data, password=None)
        return None
    except ValueError:
        return None  # unparseable — not this module's verdict to give
    except TypeError:
        pass
    passphrase = configured_passphrase(env_var)
    if passphrase is None:
        raise RuntimeError(decrypt_refusal(key_path, env_var))
    _refuse_if_below_floor(passphrase, env_var, read_path=True)
    return passphrase.encode("utf-8")


def load_private_key(data: bytes, key_path: Any = None, env_var: str = EXECUTOR_KEY_PASSPHRASE_ENV) -> Any:
    """Load an executor key PEM in either at-rest form — plaintext-first (Q1b order).

    Three outcomes, deliberately different, because the callers branch on them:

    * plaintext parse succeeds → returned. Every host installed before this
      change holds such a file, and it must keep opening with nothing set.
    * the file IS an encrypted envelope (OpenSSL answers ``TypeError`` to a
      ``password=None`` attempt) but this host has no usable passphrase →
      ``RuntimeError`` carrying ``decrypt_refusal``. A passphrase problem is not
      a key mismatch, and the boot pair gate must not treat it as one — that
      would re-mint an identity the core already knows (the #480 recovery is for
      broken material, not for a missing secret).
    * the bytes are neither → ``ValueError``, unchanged, so
      ``_cert_key_pair_matches`` still returns False and #480's re-enroll
      recovery still fires for a half-written PEM.

    ``cryptography`` takes a concrete password, never a callback, so the order is
    explicit here; a WRONG passphrase collapses into the same ``decrypt_refusal``
    — one repair either way.
    """
    try:
        return serialization.load_pem_private_key(data, password=None)
    except ValueError:
        # Unparseable bytes: not plaintext, not an envelope we can judge.
        # Propagate unchanged — this is the #480 "unusable pair" shape.
        raise
    except TypeError:
        # "Password was not given but private key is encrypted" — an envelope.
        pass

    passphrase = configured_passphrase(env_var)
    if passphrase is None:
        raise RuntimeError(decrypt_refusal(key_path, env_var))
    _refuse_if_below_floor(passphrase, env_var, read_path=True)
    try:
        return serialization.load_pem_private_key(data, password=passphrase.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(decrypt_refusal(key_path, env_var)) from exc


# NOTE: no interactive prompt lives here. The daemon's writers are unattended
# (systemd hands it the EnvironmentFile), and the only site with a human
# standing at a keyboard is the workstation CLI — which carries its own
# aligned copy plus prompt path in `venya_cli/executor_key.py`. An executor
# package that asked for input would hang the unit, which is the failure
# §6 of the design note says must not be produced.
