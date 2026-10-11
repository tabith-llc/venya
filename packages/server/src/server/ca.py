# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CA (Certificate Authority) management for executor mTLS.

Generates CA key/cert during initialization and signs executor CSRs.
The CA keypair itself is ECDSA P-256; a submitted CSR may carry any public key
on the accepted-curve list (``accepted_csr_curve_names()`` — P-256/P-384/P-521,
refs #503 option A). Supports passphrase-based encryption for CA private key
storage.
"""

import hashlib
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import CASecurityConfig
from .utils.ca_key_probe import encrypted_key_is_parseable

logger = logging.getLogger("venya.ca")


class CAExistsError(RuntimeError):
    """CA keypair already exists on disk."""


# Certificate validity periods
CA_VALIDITY_DAYS = 3650  # 10 years
EXECUTOR_VALIDITY_DAYS = 30  # 30 days

# EKU for executor leaf certs. Dual-purpose: the leaf serves as a TLS client
# (registration/heartbeat toward core) AND a TLS server (relay listener :8443).
# This is the single source of truth — do not inline the OIDs elsewhere.
EXECUTOR_LEAF_EKU = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]

# Accepted CSR public-key curves. SINGLE SOURCE OF TRUTH (refs #503 option A):
# both CAManager.sign_csr (the vault) and
# routes/executors.validate_csr_key_strength (the promise the registration
# endpoint makes in its 400 text) read accepted_csr_curve_names(), so the two
# cannot drift apart. The mapping carries the human label used in the hint text.
# Read at CALL time (not snapshot into a tuple at import) so the dict below is
# the only place the list exists.
ACCEPTED_CSR_CURVE_LABELS: dict[str, str] = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}


def accepted_csr_curve_names() -> tuple[str, ...]:
    """Return the curve names a CSR public key may use."""
    return tuple(ACCEPTED_CSR_CURVE_LABELS)


def csr_curve_hint() -> str:
    """Return the actionable text naming every curve the CA accepts.

    Built from the same dict the signer checks, so the wording can never
    advertise a list that differs from the one the vault enforces.
    """
    labels = [f"{ACCEPTED_CSR_CURVE_LABELS[name]} ({name})" for name in accepted_csr_curve_names()]
    if len(labels) == 1:
        joined = labels[0]
    else:
        joined = ", ".join(labels[:-1]) + ", or " + labels[-1]
    return f"Use ECDSA {joined}."


# --- #573: the passphrase LENGTH floor, CA plane (carrier features/passphrase-length-floor-n15.md) ---
#
# Owner ruling (s85 batch, verbatim): "Deny whitespace-only passphrases and enforce a
# proper length passcode." The whitespace half shipped in #554; this is the length half,
# ruled from the research in wave14-specs-20261009/passphrase-length-flash3-s84.md and
# counted in Unicode CODE POINTS on the decoded string before any encode (NIST SP
# 800-63B-4 counts each code point as one character, so an accented phrase is never
# measured by its UTF-8 byte length).
#
# The FLOOR is enforced; the CEILING is only STATED. Research clause C2 requires verifiers
# to PERMIT at least 64 characters, and the owner's correction to the blessed wording asks
# for a plain statement of the 64-character supported maximum — no code path here refuses
# a longer passphrase, so MAX_PASSPHRASE_CODE_POINTS exists to interpolate that sentence
# and for no other reason.
MIN_PASSPHRASE_CODE_POINTS = 15  # inclusive: 15 passes, 14 refuses
MAX_PASSPHRASE_CODE_POINTS = 64  # stated in the refusal text; never a refusal door


def _configured_passphrase(env_var: str) -> str | None:
    """The configured CA passphrase as a DECODED string, or None when there is no real one.

    #554's decision, unchanged: unset, empty and whitespace-only all read as "no
    passphrase", and the value is returned exactly as set — DENY, never TRIM. This is the
    one place that makes that call, which is why no call site strips.

    It lives apart from ``_load_passphrase()`` because the length floor below counts
    Unicode code points, and a code point is a property of the decoded string: once the
    value is encoded, ``len()`` reports bytes and an accented passphrase would be measured
    against a number nobody typed. Encoding stays on the way out.
    """
    passphrase = os.environ.get(env_var)
    if passphrase and passphrase.strip():
        return passphrase
    return None


def _load_passphrase(env_var: str) -> bytes | None:
    """Load the configured CA passphrase from its environment variable.

    #554 (owner ruling 2026-10-09, verbatim: "whitespace-only passphrase should not
    be acceptable"): a value that is empty or made only of whitespace is read as
    UNSET here, exactly like no value at all. A key must not be "protected" by a
    secret that carries no material — one space opened every set-passphrase test in
    this module while protecting nothing.

    This is the ONE place that decides it, which is why no call site strips. Every
    CA decision in this module already routes through this function —
    ``CAManager.initialize``/``AdminCAManager.initialize`` (write), ``CAManager.load_ca``
    and ``AdminCAManager._load_ca_key`` (read), and ``_serialize_key_encrypted`` via the
    value returned here — so normalising once here makes all of them agree. Stripping
    at each ``if passphrase:`` instead would leave the same question answered four times
    and invite the next caller to forget one.

    The ruled shape is DENY, not TRIM: the operator's value is never rewritten. A
    passphrase that merely begins or ends with a space is delivered to the crypto
    layer byte-for-byte, so a key written before this change still opens with the
    same characters. Only an all-whitespace value changes meaning, and it changes to
    "no passphrase" — which the #537 write-side refusal already covers, word for word.

    Returns:
        Passphrase as bytes, or None if unset, empty, or whitespace-only.
    """
    passphrase = _configured_passphrase(env_var)
    if passphrase is None:
        return None
    return passphrase.encode("utf-8")


def _passphrase_is_below_floor(passphrase: str | None) -> bool:
    """True when a SUPPLIED passphrase carries material but is shorter than the floor (#573).

    The blank shapes are not this question: an unset, empty or whitespace-only value is
    "no passphrase" (the #554 answer, still given by ``_configured_passphrase``) and the
    floor runs AFTER that shape, never replaces it. Counted in code points, never bytes.
    """
    return passphrase is not None and len(passphrase) < MIN_PASSPHRASE_CODE_POINTS


def _short_passphrase_refusal(passphrase_env: str, *, read_path: bool = False) -> str:
    """Owner-blessed refusal text for a passphrase under the length floor (ticket #573).

    The wording is the blessed block (flash1's §6, ruled in as R5(a) of the s87 owner
    ruling set) with only the two authorized corrections applied: the supported maximum
    stated plainly instead of "no maximum below 64 characters", and the floor number
    interpolated from ``MIN_PASSPHRASE_CODE_POINTS`` — the same constant the check uses,
    so the sentence and the door cannot disagree.

    One builder for both doors, interpolating only the env-var NAME (never the value,
    never its length). The read door takes the same block with exactly one clause
    deleted — ``Nothing was written.`` — because that door is not writing anything; no
    other sentence is added or removed on either side.
    """
    written_clause = "" if read_path else " Nothing was written."
    return (
        f"REFUSED: {passphrase_env} is set to a passphrase shorter than Venya's minimum.{written_clause}\n"
        "Why it matters: this passphrase is the only thing between a copied key file and the root\n"
        "of trust for this deployment, and short passphrases are what an attacker tries first.\n"
        "To fix it:\n"
        f"  1. Replace the value of {passphrase_env} with a passphrase of at least "
        f"{MIN_PASSPHRASE_CODE_POINTS} characters. Characters are\n"
        "     counted as you type them, not as bytes, so a passphrase in any alphabet counts the same.\n"
        "     Spaces count as characters, but a passphrase made only of spaces counts as no passphrase.\n"
        f"  2. There is no rule about which characters appear — length is the only requirement, and\n"
        f"     Venya supports passphrases up to {MAX_PASSPHRASE_CODE_POINTS} characters.\n"
        "  3. Provide the passphrase through the environment, never as a command-line argument\n"
        "     (command-line values are visible to other processes on the machine).\n"
        "Your existing CA was not modified by this refusal.\n"
        "Reference: docs/cert-rotation-runbook.md and docs/BACKUPS.md (CA file locations and rotation)."
    )


def _refuse_if_below_floor(passphrase_env: str, *, read_path: bool = False) -> None:
    """Refuse a supplied passphrase under the floor, naming the variable this caller reads.

    Raises: RuntimeError with the blessed floor text — never the #537 "stored
    unencrypted" sentence, which is false for a passphrase that IS set but is short, and
    whose repair step would send the operator to set the same weak value again.
    """
    passphrase = _configured_passphrase(passphrase_env)
    if _passphrase_is_below_floor(passphrase):
        raise RuntimeError(_short_passphrase_refusal(passphrase_env, read_path=read_path))


def _unencrypted_key_refusal(passphrase_env: str) -> str:
    """Owner-approved refusal text for the write path (ticket #537).

    The wording is final; only the env-var NAME interpolates, because the caller may read a
    different variable (admin CA vs root/executor CA) and the repair step must name the real one.
    """
    return (
        "REFUSED: the Venya root CA key must never be stored unencrypted. Nothing was written.\n"
        "Why it matters: anyone who can read an unencrypted root CA key can mint certificates that\n"
        "this entire deployment trusts.\n"
        "To fix it:\n"
        f"  1. Set {passphrase_env} for the venya-core service. On an installed system it lives\n"
        "     in /etc/venya/venya-core.env.\n"
        "  2. If this machine was set up with the Venya installer, the value is already there. Re-running\n"
        "     the installer reuses it and PRESERVES your existing CA key - it is not replaced.\n"
        "  3. Provide the passphrase through that file or the service environment, never as a command-line\n"
        "     argument (command-line values are visible to other processes on the machine).\n"
        "Your existing CA was not modified by this refusal.\n"
        "Reference: docs/cert-rotation-runbook.md and docs/BACKUPS.md (CA file locations and rotation)."
    )


def _serialize_key_encrypted(
    key: ec.EllipticCurvePrivateKey,
    passphrase: bytes | None,
    passphrase_env: str,
) -> bytes:
    """Serialize a private key, encrypted with a passphrase.

    Args:
        key: The private key to serialize.
        passphrase: Passphrase for encryption; None means no passphrase is configured.
        passphrase_env: Name of the env var that should carry the passphrase, used in
            the refusal text so it names the var the caller actually reads (admin vs
            executor CA differ).

    Returns:
        PEM-encoded key bytes, always encrypted.

    Raises:
        RuntimeError: If no passphrase is available (#537) — an unencrypted CA key at
            rest lets anyone who reads it mint certificates the whole deployment trusts,
            so the plaintext branch is gone: nothing is written and the caller fails.
    """
    if passphrase:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(passphrase),
        )
    else:
        raise RuntimeError(_unencrypted_key_refusal(passphrase_env))


def _ca_key_decrypt_refusal(key_path: str | Path | None) -> str:
    """#574 — the wrong-passphrase-on-a-CA-key refusal, in our words, at one home.

    The shape is the owner's ruling (R8-ADDENDUM, decisions.md commit dd1de4c): our own words, no
    mechanism named, the key path substituted, plus a next-step pointer (#569). Exact bytes are the
    implementing lane's draft and the review's accept — "the rule is the shape, not this string".

    Two things the pointer must not do, both ruled:
      * it must not imply a backup always exists — backup enrollment is OPTIONAL (Q4-AMENDMENT), so
        the restore verbs are offered "when either was made for this key", with the always-true
        alternative (re-run the CA setup) stated next;
      * it must name machinery that exists. Both verbs are shipped at this tip — `admin split-ca-key`
        (cli.py:379) and `admin restore-ca-key` (cli.py:406, "Restore CA key from shares or encrypted
        backup"), the latter resolving ca.key / admin-ca.key inside --ca-dir (at_rest_key.py:39).

    The library's own sentence is NOT interpolated here; it stays on the chained cause, which the
    caller raises with ``from e``. Support still reads the mechanism in the traceback — it just no
    longer lands on the operator's screen behind our colon (#541's blanket rule).

    Args:
        key_path: The key file the caller tried to open, when the caller has one. None is the shape
            ``_deserialize_key`` takes when called without a path, so the fallback headline names the
            key without a path rather than printing ``None``.

    Returns:
        The refusal text: headline (path substituted or omitted) plus the conditional remedy pointer.
    """
    if key_path:
        headline = f"The CA key at {key_path} could not be decrypted — the passphrase did not match."
    else:
        headline = "The CA key could not be decrypted — the passphrase did not match."
    return (
        f"{headline} Retry with the correct passphrase; if the passphrase is lost, this key can be "
        "restored with `venya admin restore-ca-key` from Shamir shares or from an encrypted backup, "
        "when either was made for this key (`venya admin split-ca-key` creates the shares); "
        "otherwise re-run the CA setup."
    )


def _ca_key_damaged_refusal(key_path: str | Path | None) -> str:
    """#577 — the damaged-CA-key-file refusal, in our words, at one home.

    Fire this INSTEAD of the wrong-passphrase refusal above when the probe says the bytes are not a
    parseable encrypted key at all. The defect #577 filed is a blame error, not a wording error: the
    branch chose its sentence by whether a passphrase was SUPPLIED, so a truncated key file, or armor
    kept over a body that no longer decodes, was answered with "the passphrase did not match" — and an
    operator who re-types a correct passphrase forever is the outcome the refusal family exists to
    prevent. The subject of this sentence is the FILE.

    Same ruled class shape as #574 (R8-ADDENDUM, decisions.md commit dd1de4c): our own words, no
    mechanism named, the key path substituted, plus a next-step pointer (#569) that stays conditional
    under the AMENDED Q4 custody ladder (backup enrollment is OPTIONAL, so the restore verbs are
    offered "when either was made for this key") and names only machinery that ships —
    `admin split-ca-key` and `admin restore-ca-key`. The repair is deliberately different from the
    decrypt repair: nothing about a passphrase opens a damaged file, so the pointer says where an
    intact copy comes from instead of telling the operator to retry a password.

    Args:
        key_path: The key file the caller tried to open, when the caller has one. None is the shape
            ``_deserialize_key`` takes when called without a path, so the fallback headline names the
            key without a path rather than printing ``None``.

    Returns:
        The refusal text: headline (path substituted or omitted) plus the conditional repair pointer.
    """
    if key_path:
        headline = f"The CA key at {key_path} could not be read — the file is damaged."
    else:
        headline = "The CA key could not be read — the file is damaged."
    return (
        f"{headline} No passphrase can open it, so re-typing the passphrase will not help; the file is "
        "the problem, not the password. Replace the file with an intact copy, or restore this key with "
        "`venya admin restore-ca-key` from Shamir shares or from an encrypted backup, when either was "
        "made for this key (`venya admin split-ca-key` creates the shares); otherwise re-run the CA setup."
    )


def _deserialize_key(
    data: bytes,
    passphrase: bytes | None,
    key_path: str | Path | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Deserialize a private key from PEM, optionally decrypting.

    Args:
        data: PEM-encoded key data.
        passphrase: Optional passphrase for decryption.
        key_path: Optional path of the key file being opened, used only to make the
            wrong-passphrase refusal name the real file (#574). Defaulted, so callers
            that do not have a path — including the #541 suite — keep working unchanged.

    Raises:
        RuntimeError: If decryption fails or key cannot be loaded. The library's sentence is
            carried as the chained cause (``from e``), never in the operator-facing text.
            A failure is blamed on the FILE when the probe says the bytes are not a parseable
            encrypted key (#577), and on the passphrase only when the file is intact and the
            passphrase did not open it (#574). The no-passphrase arm is #541's shipped text,
            untouched by this row.
    """
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except ValueError as e:
        if passphrase:
            # #577 — the blame is chosen by whether the BYTES PARSE, not by whether an input was
            # supplied. The probe re-reads the same bytes with no password: a TypeError means the
            # structure is intact and only the secret is in question (the #574 arm below); a
            # ValueError means the file itself is broken and the passphrase sentence would send the
            # operator down the wrong repair path. Branch is on the exception CLASS, never a message.
            if not encrypted_key_is_parseable(data):
                raise RuntimeError(_ca_key_damaged_refusal(key_path)) from e
            raise RuntimeError(_ca_key_decrypt_refusal(key_path)) from e
        else:
            raise RuntimeError(
                "Failed to load CA key (may be encrypted but no passphrase provided). "
                "Set the passphrase environment variable."
            ) from e


class CAManager:
    """Manages the CA keypair, certificates, and signing operations.

    The CA is generated once during initialization and stored on disk.
    All executor certificates are signed by this CA.

    Supports passphrase-based encryption for the CA private key via
    the VENYA_CA_KEY_PASSPHRASE environment variable.
    """

    def __init__(self, ca_dir: str, ca_security: CASecurityConfig | None = None) -> None:
        self.ca_dir = Path(ca_dir)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.crt"

        # CA security config
        if ca_security is not None:
            self._key_passphrase_env = ca_security.key_passphrase_env
        else:
            self._key_passphrase_env = "VENYA_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

    @property
    def has_ca(self) -> bool:
        """Check if CA key/cert pair exists on disk."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize(self) -> None:
        """Generate a new CA keypair and self-signed certificate.

        Creates the CA directory (if needed), generates an ECDSA P-256
        keypair, and creates a self-signed CA certificate. The key is always
        stored encrypted: the passphrase comes from VENYA_CA_KEY_PASSPHRASE
        (or the configured ``ca_security.key_passphrase_env``).

        Raises:
            RuntimeError: If no passphrase is set — nothing is created (#537).
            CAExistsError: If CA already exists.
        """
        if self.has_ca:
            raise CAExistsError(f"CA already exists at {self.ca_dir}")

        # #537: refuse before ANY filesystem work. The serializer below is the
        # backstop for the bytes, but a key it never produced still leaves the
        # 0700 CA directory behind, which would make "Nothing was written." untrue.
        # An empty value counts as unset — and since #554 so does a whitespace-only
        # one; both are decided in _load_passphrase(), not here.
        if not _load_passphrase(self._key_passphrase_env):
            raise RuntimeError(_unencrypted_key_refusal(self._key_passphrase_env))
        # #573: a passphrase that IS set but is under the length floor is a different
        # refusal, and it lands here — before the mkdir below — so "Nothing was written."
        # is true of this door rather than merely inherited from the write-side sentence.
        _refuse_if_below_floor(self._key_passphrase_env)

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_dir), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = _load_passphrase(self._key_passphrase_env)

        # Store private key (encrypted — see the guard above and #537)
        key_pem = _serialize_key_encrypted(private_key, passphrase, self._key_passphrase_env)
        # #499: create-time mode via os.open(..., 0o600) — the house idiom of
        # sbx_strategy.py's env-file write. write_bytes() creates the inode at
        # 0666 & ~umask and the chmod below lands only after the full key body
        # is on disk; under a permissive umask the bytes are observable at a
        # wider mode in that window. The chmod stays as the exact final-state
        # pin (unchanged outcome: 0600).
        key_fd = os.open(str(self.ca_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Venya Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Root CA"),
            ]
        )

        # #522: SKI + self-AKI, matching the installer's root-CA block
        # (install-venya-core.sh) and the admin CA fix (#504) — every CA in
        # this product carries them, so a root minted by the server stays
        # acceptable to strict verifiers (openssl -x509_strict, error 86).
        root_ca_ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(root_ca_ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ca_ski),
                critical=False,
            )
        )

        cert = builder.sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.ca_cert_path.write_bytes(cert_pem)
        os.chmod(str(self.ca_cert_path), 0o644)

        logger.info("CA initialized at %s (encrypted=%s)", self.ca_dir, passphrase is not None)

    def load_ca(self) -> tuple[x509.Certificate, Any]:
        """Load the CA certificate and private key from disk.

        If the key is encrypted, attempts to decrypt using the passphrase
        from VENYA_CA_KEY_PASSPHRASE.

        Returns:
            Tuple of (certificate, private_key).

        Raises:
            RuntimeError: If the key cannot be decrypted, if the key is encrypted
                and no passphrase is set, or — #541 — if the key on disk is
                plaintext while a passphrase is configured. That last case refuses
                with the approved #537 text instead of loading; the key is never
                re-wrapped or migrated.
        """
        passphrase = _load_passphrase(self._key_passphrase_env)
        # #573 read door: the floor asks the same question the write door asks, in the
        # read wording (the `Nothing was written.` clause dropped — this door is not
        # writing). Refusing here loads nothing, re-wraps nothing and changes no state.
        _refuse_if_below_floor(self._key_passphrase_env, read_path=True)
        try:
            key_data = self.ca_key_path.read_bytes()
        except FileNotFoundError:
            raise RuntimeError(f"CA key file not found at {self.ca_key_path}")

        # Check if key appears encrypted
        is_encrypted = b"ENCRYPTED" in key_data

        if is_encrypted and not passphrase:
            raise RuntimeError(
                f"CA key is encrypted but {self._key_passphrase_env} is not set. "
                "Set the environment variable before starting the server."
            )

        if not is_encrypted and passphrase:
            # A passphrase is configured but the key on disk is plaintext: refuse loudly (#541).
            # Handing it to the loader anyway raises TypeError ("Password was given but private
            # key is not encrypted"), which escapes the manager, the boot path and the health
            # check. The owner ruled this case REFUSE LOUDLY, NO REWRAP — nothing is loaded,
            # nothing is re-encrypted, nothing is migrated. The wording is #537's approved
            # refusal, shared, naming the variable this manager actually reads.
            raise RuntimeError(_unencrypted_key_refusal(self._key_passphrase_env))

        private_key = _deserialize_key(key_data, passphrase, self.ca_key_path)
        try:
            cert_pem = self.ca_cert_path.read_bytes()
        except FileNotFoundError:
            raise RuntimeError(f"CA cert file not found at {self.ca_cert_path}")
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert, private_key

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        executor_id: str,
        crl_url: str | None = None,
    ) -> x509.Certificate:
        """Sign a CSR with the CA, producing an executor certificate.

        Args:
            csr: The certificate signing request to sign.
            executor_id: Unique executor identifier (used as CN).
            crl_url: Optional CRL Distribution Point URL for CDP extension.

        Returns:
            Signed X.509 certificate.

        Raises:
            ValueError: If the CSR self-signature does not verify, or its public
                key is not an accepted ECDSA curve. Callers map ValueError to a
                client error (400) — it is bad input, not a CA fault. A
                RuntimeError from load_ca() means the CA material itself is
                unusable and stays a service fault (503).
        """
        ca_cert, ca_key = self.load_ca()
        now = datetime.now(UTC)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Validate CSR
        if not csr.is_signature_valid:
            raise ValueError("CSR signature verification failed")

        pub_key = csr.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            # ValueError, not TypeError (#503): this is caller-supplied CSR material, and
            # the registration route maps ValueError to a clean 400. A TypeError here was
            # the defect — it escaped the route's `except RuntimeError` block as a 500.
            raise ValueError(  # noqa: TRY004 — CA input validation; ValueError → 400 at caller
                f"Unsupported CSR key type: {type(pub_key).__name__}. {csr_curve_hint()}"
            )
        if pub_key.curve.name not in accepted_csr_curve_names():
            raise ValueError(f"Unsupported curve: {pub_key.curve.name}. {csr_curve_hint()}")

        # Extract subject from CSR, replacing CN with executor_id
        csr_name = csr.subject
        # Build new name with executor_id as CN
        common_name_oid = NameOID.COMMON_NAME
        attrs = [a for a in csr_name if a.oid != common_name_oid]
        attrs.append(x509.NameAttribute(common_name_oid, executor_id))
        subject = x509.Name(attrs)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=EXECUTOR_VALIDITY_DAYS))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(EXECUTOR_LEAF_EKU),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(executor_id)]),
                critical=False,
            )
        )

        # Add CRL Distribution Point if URL is provided
        if crl_url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(crl_url)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            )

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert

    def get_ca_cert_pem(self) -> bytes:
        """Get the CA certificate in PEM format.

        Returns:
            PEM-encoded CA certificate bytes.
        """
        return self.ca_cert_path.read_bytes()

    @staticmethod
    def compute_fingerprint(cert: x509.Certificate) -> str:
        """Compute the SHA-256 fingerprint of a certificate.

        Args:
            cert: The certificate to fingerprint.

        Returns:
            Lowercase hex fingerprint string.
        """
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def compute_serial_hex(serial: int) -> str:
        """Convert a serial number to a hex string.

        The ONE serial representation is `core.utils.cert_serial.canonical_serial`
        (ticket cert-serial-canonicalization-mismatch #481); this is the padded
        precedent that shape was named after, kept as the server-side writer so
        call sites and this method's mocks keep working unchanged.

        Args:
            serial: The serial number integer.

        Returns:
            Lowercase hex, zero-padded to a minimum of 16 digits.
        """
        return canonical_serial(serial)

    def generate_crl(self, db_session, max_entries: int = 1000, revocations=None) -> bytes:
        """Generate a DER-encoded Certificate Revocation List.

        Queries the database for revoked certificate serial numbers,
        builds a CRL signed by the CA, and returns it in DER format.

        Args:
            db_session: SQLAlchemy session for querying revocations.
            max_entries: Maximum number of revocations to include.
            revocations: Pre-fetched revocation rows to embed (ticket
                crl-cap-etag-divergence #337, ruled A). The CRL endpoint fetches
                the capped rows ONCE and passes them here so the served body and
                the conditional-GET ETag describe the SAME population — a second
                internal query would re-open the snapshot gap the cap fix closes.
                None keeps the historical self-queried behavior.

        Returns:
            DER-encoded CRL bytes.
        """
        from core.iam.models import ExecutorCertRevocation
        from sqlalchemy import asc, desc

        ca_cert, ca_key = self.load_ca()
        now = datetime.now(UTC)

        if revocations is None:
            # #463: revoked_at is NOT unique (a bulk revoke stamps one `now` per
            # request), so ordering on it alone left the CAPPED population
            # undetermined — at the max_entries boundary a tie decides which
            # serial is listed, and a listed serial is signed into the DER.
            # asc(serial_number) makes the order total; it is the same secondary
            # key the sibling production fetch already uses
            # (routes/executors.py:1109), so this is drift-to-precedent.
            revocations = (
                db_session.query(ExecutorCertRevocation)
                .order_by(desc(ExecutorCertRevocation.revoked_at), asc(ExecutorCertRevocation.serial_number))
                .limit(max_entries)
                .all()
            )

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + timedelta(hours=1))

        for rev in revocations:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(rev.serial_number, 16))
                .revocation_date(rev.revoked_at)
                .build(hashes.SHA256())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.DER)

    def purge_expired_revocations(self, db_session, retention_days: int) -> int:
        """Delete revocation records older than retention_days.

        Args:
            db_session: SQLAlchemy session.
            retention_days: Keep records for this many days.

        Returns:
            Number of deleted records.
        """
        from core.iam.models import ExecutorCertRevocation

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted_count = (
            db_session.query(ExecutorCertRevocation)
            .filter(ExecutorCertRevocation.revoked_at < cutoff)
            .delete(synchronize_session=False)
        )
        db_session.commit()
        return deleted_count


# --- Admin CA constants ---

ADMIN_CA_VALIDITY_DAYS = 3650  # 10 years
ADMIN_CERT_VALIDITY_DAYS = 90  # 90 days — bootstrap/machine-plane legacy path (RF-6 §10.5)

# The ruled short-cert lifetime (RF-6 §1.2 ruling 4a — 60 minutes). The
# human-plane signer takes lifetime_seconds per request; this constant is the
# pairing value for the clock-skew fraction interlock (RF-6 §5.3): a lane that
# changes either number trips the assertion cell, never a remembered ratio.
ADMIN_SHORT_CERT_LIFETIME_SECONDS = 3600

# EKU for admin leaf certs — CLIENT_AUTH only (RF-6 §2.5: an admin leaf is a
# client credential; carrying SERVER_AUTH would let it impersonate a core
# endpoint). Single source of truth, shared by sign_admin_csr and the
# narrowed bootstrap mint (refs RF-7).
ADMIN_LEAF_EKU = [ExtendedKeyUsageOID.CLIENT_AUTH]

# --- Two-plane marker (RF-6 §3.2, refs RF-7) ---
#
# A dedicated X.509 extension carrying the credential plane, written by the
# CA's own signer and NEVER taken from a CSR. The bit is critical: a verifier
# that does not know the OID must refuse to parse the certificate rather than
# silently drift past the plane statement (measured at this tip: stock
# ``openssl verify`` rejects such a leaf with error 34, and -ignore_critical
# is what lets the rest of the chain still verify — see
# tests/test_admin_cert_ski_aki_504.py for the re-scoped cells).
#
# OID home: RFC 6996 private-use experimental arc (1.3.6.1.4.1.64496-64511),
# provisional until a registered Private Enterprise Number exists for Tabith
# LLC; swapping the number is a one-constant change plus its cells (flagged
# to the lead in the RF-7 chunk-1 report).
VENYA_PLANE_MARKER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.64496.1.1")
PLANE_MACHINE = "machine"
PLANE_HUMAN = "human"
_VENYA_PLANES: tuple[str, ...] = (PLANE_MACHINE, PLANE_HUMAN)


def _plane_marker_extension(plane: str) -> x509.UnrecognizedExtension:
    """Build the signer-written plane-marker extension for one plane.

    The value is a DER-encoded UTF8String (tag 0x0C, short-form definite
    length). Only the two ruled plane values are accepted at mint time —
    a lane asking for a third plane fails loudly here.

    Args:
        plane: PLANE_MACHINE or PLANE_HUMAN.

    Returns:
        The extension value to add with ``critical=True``.
    """
    if plane not in _VENYA_PLANES:
        raise ValueError(f"Unknown credential plane {plane!r}; accepted: {_VENYA_PLANES}")
    body = plane.encode("ascii")
    return x509.UnrecognizedExtension(VENYA_PLANE_MARKER_OID, bytes([0x0C, len(body)]) + body)


def parse_plane_marker(cert: x509.Certificate) -> str:
    """Return the plane a CA-signed admin certificate carries (RF-6 §3.2).

    Fails closed — every miss raises ValueError and the caller refuses the
    certificate; nothing in this parser defaults into a plane:

    * no marker at all (a certificate predating the two-plane model),
    * an unparseable marker value (not a short-form DER UTF8String, a length
      mismatch, or a non-ASCII body),
    * a value outside the accepted set {machine, human}.

    The middleware consumption of this result is RF-7 chunk 2; the parser
    ships and is tested with the signer (chunk 1).

    Args:
        cert: The certificate to read.

    Returns:
        PLANE_MACHINE or PLANE_HUMAN.

    Raises:
        ValueError: Missing / unparseable / out-of-set marker (see above).
    """
    try:
        ext = cert.extensions.get_extension_for_oid(VENYA_PLANE_MARKER_OID)
    except x509.ExtensionNotFound:
        raise ValueError(
            "certificate carries no Venya plane marker — it predates the "
            "two-plane model and must be re-issued (RF-6 §3.2)"
        ) from None
    raw = ext.value
    if not isinstance(raw, x509.UnrecognizedExtension):
        # TRY004 would prefer TypeError, but this parser's contract is
        # fail-closed ValueError on every miss (§3.2) — a defensive guard for
        # a shape the library does not produce today.
        raise ValueError("plane marker is not the shipped unrecognized type — refusing")  # noqa: TRY004
    content = raw.value
    # Expect exactly one short-form DER UTF8String: tag 0x0C, definite
    # short-form length (< 0x80), no trailing bytes.
    if len(content) < 2 or content[0] != 0x0C or content[1] >= 0x80:
        raise ValueError("unparseable plane marker (not a short-form DER UTF8String)")
    if len(content) != 2 + content[1]:
        raise ValueError("unparseable plane marker (length mismatch)")
    try:
        plane = content[2:].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("unparseable plane marker (non-ASCII body)") from None
    if plane not in _VENYA_PLANES:
        raise ValueError(f"plane marker {plane!r} is outside the accepted set {_VENYA_PLANES}")
    return plane


def _build_san_for_identity(identity: str) -> x509.SubjectAlternativeName:
    """Build a SubjectAlternativeName extension for the given identity.

    Uses RFC822Name (email SAN) for email-style identities containing '@',
    and DNSName for hostname-style identities.

    Args:
        identity: The admin identity string.

    Returns:
        A SubjectAlternativeName extension value.
    """
    if "@" in identity:
        return x509.SubjectAlternativeName([x509.RFC822Name(identity)])
    else:
        return x509.SubjectAlternativeName([x509.DNSName(identity)])


class AdminCAManager:
    """Manages the admin CA keypair, certificates, and signing operations.

    Separate from CAManager (executor CA). The admin CA is used exclusively
    for signing admin client certificates used in mTLS authentication of
    admin endpoints.

    The admin CA key is encrypted on disk using a passphrase from the
    VENYA_ADMIN_CA_KEY_PASSPHRASE environment variable.
    """

    def __init__(self, ca_path: Path, ca_security: CASecurityConfig | None = None) -> None:
        self.ca_path = ca_path
        self.ca_key_path = self.ca_path / "admin-ca.key"
        self.ca_cert_path = self.ca_path / "admin-ca.crt"

        if ca_security is not None:
            self._key_passphrase_env = ca_security.key_passphrase_env
        else:
            self._key_passphrase_env = "VENYA_ADMIN_CA_KEY_PASSPHRASE"  # nosec B105 — env var name, not a password

    @property
    def has_ca(self) -> bool:
        """Check if admin CA key/cert pair exists on disk."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize(self) -> None:
        """Generate a new admin CA keypair and self-signed certificate.

        Creates the admin CA directory (if needed), generates an ECDSA P-256
        keypair, and creates a self-signed admin CA certificate. The key is
        always stored encrypted: the passphrase comes from
        VENYA_ADMIN_CA_KEY_PASSPHRASE (or the configured admin passphrase env).

        Raises:
            RuntimeError: If admin CA already exists, or if no passphrase is
                set — nothing is created (#537).
        """
        if self.has_ca:
            raise RuntimeError(f"Admin CA already exists at {self.ca_path}")

        # #537: refuse before ANY filesystem work — see CAManager.initialize.
        if not _load_passphrase(self._key_passphrase_env):
            raise RuntimeError(_unencrypted_key_refusal(self._key_passphrase_env))
        # #573: floor refusal before any filesystem work — see CAManager.initialize.
        _refuse_if_below_floor(self._key_passphrase_env)

        self.ca_path.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.ca_path), 0o700)

        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = _load_passphrase(self._key_passphrase_env)

        # Store private key (encrypted — see the guard above and #537)
        key_pem = _serialize_key_encrypted(private_key, passphrase, self._key_passphrase_env)
        # #499: create-time mode via os.open(..., 0o600) — see CAManager.initialize;
        # write_bytes() + chmod leaves the key body at 0666 & ~umask until the
        # chmod lands. The chmod stays as the exact final-state pin.
        key_fd = os.open(str(self.ca_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_pem)
        os.chmod(str(self.ca_key_path), 0o600)

        # Create self-signed admin CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
            ]
        )

        # #504: SKI + self-AKI, matching the installer's root-CA block
        # (install-venya-core.sh) — every CA in this product carries them.
        admin_ca_ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ADMIN_CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(admin_ca_ski, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(admin_ca_ski),
                critical=False,
            )
        )

        cert = builder.sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.ca_cert_path.write_bytes(cert_pem)
        os.chmod(str(self.ca_cert_path), 0o644)

        logger.info("Admin CA initialized at %s (encrypted=%s)", self.ca_path, passphrase is not None)

    def _load_ca_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the admin CA private key from disk.

        Decrypts using the passphrase from VENYA_ADMIN_CA_KEY_PASSPHRASE.

        Returns:
            ECDSA private key instance.

        Raises:
            RuntimeError: If the key cannot be decrypted or passphrase not set, or
                — #541 — if the key on disk is plaintext while a passphrase is
                configured. That last case refuses with the approved #537 text
                instead of loading; the key is never re-wrapped or migrated.
        """
        passphrase = _load_passphrase(self._key_passphrase_env)
        # #573 read door, admin twin: same floor, same read wording, nothing loaded.
        _refuse_if_below_floor(self._key_passphrase_env, read_path=True)
        key_data = self.ca_key_path.read_bytes()

        is_encrypted = b"ENCRYPTED" in key_data

        if is_encrypted and not passphrase:
            raise RuntimeError(
                f"Admin CA key is encrypted but {self._key_passphrase_env} is not set. "
                "Set the environment variable before starting the server."
            )

        if not is_encrypted and passphrase:
            # Twin of CAManager.load_ca (#541): a configured passphrase against a plaintext key
            # on disk refuses loudly instead of logging and handing the passphrase to the loader,
            # which raised TypeError. Owner ruling: REFUSE LOUDLY, NO REWRAP — nothing is loaded,
            # re-encrypted or migrated. Shares #537's approved wording, naming the admin variable.
            raise RuntimeError(_unencrypted_key_refusal(self._key_passphrase_env))

        return _deserialize_key(key_data, passphrase, self.ca_key_path)

    def sign_admin_cert(self, admin_identity: str) -> tuple[x509.Certificate, bytes, bytes]:
        """Mint the bootstrap/machine-plane admin certificate (RF-6 §6.3, refs RF-7).

        This is the BOOTSTRAP path and nothing else. Its contract:

        * machine plane — the loopback/service credential the core uses
          against its own admin routes; no human session is involved, the
          identity is hostname-shaped (the installer's ``ADMIN_IDENTITY``),
          and the two-plane marker (RF-6 §3.2) is written at mint as
          ``machine``;
        * the keypair is generated and consumed in the same process on the
          same machine — the returned private key never crosses the network
          (ruling 4d scopes the unencrypted-on-disk question to exactly this
          key; the filesystem control is the installer's ``0600`` write);
        * what this mint OWNS is the returned bytes and nothing else: it opens
          no file, chooses no destination and sets no mode. The delivered
          leaf's destination, its enforced modes and the backup-exclusion
          statement are the caller's, and the ruled remedy for that delivery
          path is RF-10's installer commit, not this function (#565 site 1,
          ruling ``cdcde4e`` — the generation and the plaintext return stay as
          they are; tests/test_site1_destination_seam_565.py holds that line);
        * the only allowed caller is the installer bootstrap
          (``install-venya-core.sh``, the ``sign_admin_cert`` unpack). A
          caller-interlock cell asserts it — a route reaching this mint is
          a red suite, not a review finding
          (tests/test_bootstrap_mint_interlock_rf7.py);
        * the signature and return shape ``(cert, key_pem, cert_pem)`` stay
          byte-compatible with that unpack until RF-10's installer commit
          retires the key handoff. Changing the arity here breaks every
          fresh install.

        Human-plane certificates are NOT minted here — the elevation path is
        ``sign_admin_csr`` below (RF-6 §2.5b), which takes a caller-supplied
        CSR and returns a certificate and no private key.

        Args:
            admin_identity: The admin identity (used as CN and SAN DNS name).

        Returns:
            Tuple of (certificate, key_pem, cert_pem).
        """
        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(UTC)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Generate new keypair for this admin cert
        admin_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, admin_identity),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(admin_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ADMIN_CERT_VALIDITY_DAYS))
            # #504: SKI + AKI referencing the admin CA — same placement and
            # from_issuer_public_key idiom as CAManager.sign_csr (executor
            # leaves), so admin leaves match the rest of the product's PKI.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(admin_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(ADMIN_LEAF_EKU),
                critical=False,
            )
            .add_extension(
                _build_san_for_identity(admin_identity),
                critical=False,
            )
            # Bootstrap/machine plane, CA-written (RF-6 §3.2): this mint is
            # the marker's machine half, landed with the change itself so a
            # cert this path produces is never marker-less.
            .add_extension(
                _plane_marker_extension(PLANE_MACHINE),
                critical=True,
            )
        )

        cert = builder.sign(ca_key, hashes.SHA256())

        key_pem = admin_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        return cert, key_pem, cert_pem

    def sign_admin_csr(
        self,
        csr: x509.CertificateSigningRequest,
        identity: str,
        lifetime_seconds: int,
        crl_url: str | None = None,
    ) -> x509.Certificate:
        """Sign a CSR with the admin CA, producing a human-plane leaf (RF-6 §2.5b, §2.6).

        The admin variant of ``CAManager.sign_csr`` — same behavior table, with
        the two deltas that table names: EKU is CLIENT_AUTH only (an admin leaf
        is a client credential; SERVER_AUTH would let it impersonate a core
        endpoint), and the SAN comes from ``_build_san_for_identity`` (RFC822
        for ``@``-bearing identities, DNS otherwise) instead of a bare
        ``DNSName(executor_id)``. Lifetime is the caller's minutes-scale value
        — never a days-scale constant.

        The mint is not self-described (§2.6): every attribute of the CSR
        subject is discarded and the subject is rebuilt from the server-derived
        identity (O=Venya, OU=Admin, CN=identity), the SAN is built from that
        identity, and the two-plane marker (§3.2) is CA-written as ``human`` —
        a marker a CSR claims is never copied. The caller's public key is the
        only thing taken from the request.

        No private key is returned, and none is generated here — the keypair
        lives on the workstation that produced the CSR (ruling 3).

        Args:
            csr: The certificate signing request to sign (workstation-generated).
            identity: Server-derived admin identity (used as CN and SAN).
            lifetime_seconds: Leaf validity in seconds (minutes-scale by design;
                the authorization layer that chooses the value is chunk 2).
            crl_url: Optional CRL Distribution Point URL for CDP extension.

        Returns:
            Signed X.509 certificate — certificate only, never a key.

        Raises:
            ValueError: If the CSR self-signature does not verify, its public
                key is not an accepted ECDSA curve, or the identity/lifetime is
                not usable. Same error-class contract as ``sign_csr``: callers
                map ValueError to a client error (400) — it is bad input, not a
                CA fault. A RuntimeError from ``_load_ca_cert_and_key`` means
                the CA material itself is unusable and stays a service fault
                (503).
        """
        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(UTC)
        serial = int.from_bytes(secrets.token_bytes(8), "big")

        # Validate CSR — the shared contract with sign_csr, same error texts.
        if not csr.is_signature_valid:
            raise ValueError("CSR signature verification failed")

        pub_key = csr.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            # ValueError, not TypeError (#503): this is caller-supplied CSR material,
            # and the caller maps ValueError to a clean 400. A TypeError here would
            # escape the route's error handling as a 500.
            raise ValueError(  # noqa: TRY004 — CA input validation; ValueError → 400 at caller
                f"Unsupported CSR key type: {type(pub_key).__name__}. {csr_curve_hint()}"
            )
        if pub_key.curve.name not in accepted_csr_curve_names():
            raise ValueError(f"Unsupported curve: {pub_key.curve.name}. {csr_curve_hint()}")

        # Server-derived identity and caller-supplied lifetime, both checked here
        # because both are part of what the mint binds (§2.6).
        if not identity:
            raise ValueError("identity must be a non-empty server-derived string")
        if lifetime_seconds <= 0:
            raise ValueError(f"lifetime_seconds must be positive, got {lifetime_seconds}")

        # Subject rebuilt from the server-supplied identity; the CSR subject
        # carries no authority (§2.6.1) — no CN passthrough, no O/OU copy.
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, identity),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(seconds=lifetime_seconds))
            # #504 placement rule, mirrored from sign_csr and sign_admin_cert:
            # SKI from the leaf public key, AKI from_issuer_public_key.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(ADMIN_LEAF_EKU),
                critical=False,
            )
            .add_extension(
                _build_san_for_identity(identity),
                critical=False,
            )
            # Human plane, CA-written (RF-6 §3.2) — critical: a verifier that
            # cannot see it must refuse the certificate, not infer a plane.
            .add_extension(
                _plane_marker_extension(PLANE_HUMAN),
                critical=True,
            )
        )

        # Add CRL Distribution Point if URL is provided (same optional wiring as
        # sign_csr; informational here — the real revocation point is the
        # in-process serial check, RF-6 §2.9).
        if crl_url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(crl_url)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            )

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert

    def _load_ca_cert_and_key(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        """Load the admin CA certificate and private key.

        Returns:
            Tuple of (certificate, private_key).

        Raises:
            FileNotFoundError if a CA file is missing (pre-existing behavior —
                chunk 2's route is expected to check ``has_ca`` and map it to
                the service-fault class); RuntimeError when the key is present
                but unusable. Neither path is a ValueError: a CA that cannot
                load is never client input (RF-6 §2.5/§2.7 error-class contract).
        """
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        ca_key = self._load_ca_key()
        return ca_cert, ca_key

    def get_admin_ca_cert_pem(self) -> bytes:
        """Get the admin CA certificate in PEM format.

        Returns:
            PEM-encoded admin CA certificate bytes.
        """
        return self.ca_cert_path.read_bytes()

    def generate_crl(self, db_session, max_entries: int = 1000) -> bytes:
        """Generate a DER-encoded Certificate Revocation List for admin certs.

        Args:
            db_session: SQLAlchemy session for querying revocations.
            max_entries: Maximum number of revocations to include.

        Returns:
            DER-encoded CRL bytes.
        """
        from core.iam.models import AdminCertRevocation
        from sqlalchemy import asc, desc

        ca_cert, ca_key = self._load_ca_cert_and_key()
        now = datetime.now(UTC)

        # #463: same non-unique revoked_at class as the executor CRL above — the
        # admin family gets the identical tiebreaker, mirroring the executors.py
        # precedent so both CRL populations are determined by a total order.
        revocations = (
            db_session.query(AdminCertRevocation)
            .order_by(desc(AdminCertRevocation.revoked_at), asc(AdminCertRevocation.serial_number))
            .limit(max_entries)
            .all()
        )

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + timedelta(hours=1))

        for rev in revocations:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(rev.serial_number, 16))
                .revocation_date(rev.revoked_at)
                .build(hashes.SHA256())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.DER)

    def purge_expired_revocations(self, db_session, retention_days: int) -> int:
        """Delete admin cert revocation records older than retention_days.

        Args:
            db_session: SQLAlchemy session.
            retention_days: Keep records for this many days.

        Returns:
            Number of deleted records.
        """
        from core.iam.models import AdminCertRevocation

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted_count = (
            db_session.query(AdminCertRevocation)
            .filter(AdminCertRevocation.revoked_at < cutoff)
            .delete(synchronize_session=False)
        )
        db_session.commit()
        return deleted_count
