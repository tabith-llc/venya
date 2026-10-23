# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Boot-time ingest of the core's own relay client credential into the registry (#597).

The credential the core presents when it dials an executor relay listener is minted
outside the product: ``install-venya-core.sh:1005-1023`` runs ``openssl ecparam`` +
``openssl req`` + ``openssl x509 -req`` straight to
``/etc/venya/relay/relay-client.crt``. Before #597 it appeared in no table, so it had
no revocation path, and the CRL that the same CA mints could never name it
(``server/ca.py:generate_crl`` draws from ``ExecutorCertRevocation`` alone).

THE INVARIANT THIS MODULE HOLDS: a relay credential that exists on disk exists in
``core_relay_credentials``. It is enforced here, at core startup, rather than by
editing the mint step, for two reasons that are not stylistic:

  1. ``install-venya-core.sh`` is owner-ok-gated per specific change (root AGENTS.md,
     "Installer scripts"), so the write cannot ship in this changeset. It is drafted
     as a proposal in the leg report instead.
  2. An installer-only write would cover only credentials minted by a NEW installer.
     Every core already on the network holds a relay cert that no table names —
     exactly the population the gap is about. Boot-ingest registers them on the next
     start of the product, with no reinstall and no operator step.

Upsert is keyed on ``serial_number`` (unique in migration 040), so a boot is
idempotent and a re-mint that changes the serial creates a second row rather than
silently rewriting the history of the first — the old serial stays revocable, which
is the whole point of the registry.

Revocation is TERMINAL and never inferred here: this module writes registration
facts and nothing else. It will not clear ``revoked_at`` on a row it re-sees, so a
rebooted core cannot un-revoke itself (``revoke`` is the only writer of that column,
and there is no un-revoke in alpha — same law as ``Executor.revoked_at``).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

logger = logging.getLogger("venya.server")

#: Default location the core installer writes the relay client credential to
#: (``install-venya-core.sh:1000`` ``RELAY_DIR="/etc/venya/relay"``).
DEFAULT_RELAY_CERT_PATH = "/etc/venya/relay/relay-client.crt"

#: Suffix the installer appends to the core hostname for the relay CN
#: (``install-venya-core.sh:1013`` ``-subj "/O=Venya/CN=${CORE_HOSTNAME}-relay"``).
RELAY_CN_SUFFIX = "-relay"


@dataclass(frozen=True)
class RelayCredentialFacts:
    """What one relay client certificate on disk says about itself.

    Every field is READ from the certificate, never supplied by a caller, so a
    registry row cannot be made to claim a serial or a CN the credential does not
    carry. Timestamps are aware (repo datetime law: no naive datetimes).
    """

    serial_number: str
    common_name: str
    hostname: str | None
    cert_fingerprint: str
    public_key_hash: str
    signing_ca_subject: str | None
    signing_ca_aki: str | None
    issued_at: Any
    not_after: Any


def _subject_common_name(name: x509.Name) -> str | None:
    for attr in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = attr.value
        return value if isinstance(value, str) else None
    return None


def _authority_key_id(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    key_id = ext.value.key_identifier
    return key_id.hex() if key_id else None


def read_relay_credential(path: str | Path) -> RelayCredentialFacts:
    """Parse the registry facts out of one relay client certificate file.

    Raises:
        FileNotFoundError / OSError: the file is not there or not readable — the
            caller decides whether that is a warning or a fault (the core's relay
            material is already validated as functionally mandatory by
            ``app.py:_validate_relay_mtls_config`` before this runs).
        ValueError: the bytes are not a parseable PEM/DER certificate. Named rather
            than propagated as a bare cryptography exception so the startup log says
            "this credential is unreadable" and not a library internal.
    """
    p = Path(path)
    raw = p.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except Exception as pem_exc:
        try:
            cert = x509.load_der_x509_certificate(raw)
        except Exception as der_exc:
            raise ValueError(
                f"{p} is not a parseable certificate (pem: {type(pem_exc).__name__}, der: {type(der_exc).__name__})"
            ) from der_exc

    cn = _subject_common_name(cert.subject)
    if cn is None:
        raise ValueError(f"{p} has no CommonName in its subject — cannot register a nameless credential")

    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    aki = _authority_key_id(cert)
    try:
        issuer_cn = _subject_common_name(cert.issuer)
    except Exception:
        issuer_cn = None

    return RelayCredentialFacts(
        # WRITE form is canonical_serial (lowercase, zero-padded to >=16) per the #481
        # ruling in core/utils/cert_serial.py. serial_match_key is the COMPARE key
        # (uppercase, unpadded) and must never be what a row stores — storing it here
        # would put this table's write in the other module's vocabulary.
        serial_number=canonical_serial(cert.serial_number),
        common_name=cn,
        hostname=cn[: -len(RELAY_CN_SUFFIX)] if cn.endswith(RELAY_CN_SUFFIX) else None,
        cert_fingerprint=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        public_key_hash=hashlib.sha256(spki).hexdigest(),
        signing_ca_subject=issuer_cn,
        signing_ca_aki=aki,
        issued_at=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )


def register_relay_credential(session: Any, facts: RelayCredentialFacts) -> str:
    """Insert-or-touch one credential's registry row. Returns ``"created"`` or ``"present"``.

    ``"present"`` on a row that already exists for this serial — and the existing
    ``revoked_at`` is LEFT EXACTLY AS IT IS. That is the load-bearing half: a boot
    must never be able to un-revoke a credential by re-registering it.
    """
    from core.iam.models import CoreRelayCredential
    from core.utils.cert_serial import serial_match_clause

    # Matched with the tolerant clause, not by string equality: the caller may hand us a
    # serial spelled any way (#481 is exactly the class where a differently-spelled
    # serial meant a revocation that recorded green and never took effect).
    existing = (
        session.query(CoreRelayCredential)
        .filter(serial_match_clause(CoreRelayCredential.serial_number, facts.serial_number))
        .one_or_none()
    )
    if existing is not None:
        return "present"

    session.add(
        CoreRelayCredential(
            serial_number=facts.serial_number,
            common_name=facts.common_name,
            hostname=facts.hostname,
            cert_fingerprint=facts.cert_fingerprint,
            public_key_hash=facts.public_key_hash,
            signing_ca_subject=facts.signing_ca_subject,
            signing_ca_aki=facts.signing_ca_aki,
            issued_at=facts.issued_at,
            not_after=facts.not_after,
        )
    )
    session.commit()
    return "created"


def ingest_relay_credential(config: Any, backend: Any) -> RelayCredentialFacts | None:
    """Boot step: read the core's relay credential and make sure the registry names it.

    Returns the parsed facts, or None when there is nothing to register. A None here
    is NOT a silent pass: every refusal path logs, and the caller in the lifespan
    treats an unreadable credential as a startup WARNING naming the file, never as
    "no revocation needed".

    Deliberately does not raise into the lifespan for a missing file — the relay
    material is already hard-validated earlier in startup
    (``app.py:_validate_relay_mtls_config``), so by the time this runs a missing
    credential means something changed under us, which is worth a line, not a second
    abort of the same condition.
    """
    mtls = getattr(config, "mtls", None)
    configured = getattr(mtls, "cert", None) if mtls else None
    # The relay CLIENT cert is config.mtls_cert (app.py:111 binds VENYA_MTLS_CERT);
    # config.mtls.cert is the server leaf. Ask for the relay path first, and never
    # register the server leaf as if it were the relay credential.
    path = _resolve_relay_cert_path(config, configured)
    if path is None:
        logger.warning(
            "Relay credential registry NOT updated this boot: no relay client certificate found at "
            "%s or in config — a core that relays with no registered credential has no revocation "
            "path for it (#597).",
            DEFAULT_RELAY_CERT_PATH,
        )
        return None

    try:
        facts = read_relay_credential(path)
    except (OSError, ValueError) as exc:
        logger.warning(
            "Relay credential registry NOT updated this boot: %s could not be read as a certificate (%s) "
            "— this credential stays unrevocable until it is (#597).",
            path,
            exc,
        )
        return None

    session = backend.get_session()
    try:
        outcome = register_relay_credential(session, facts)
    finally:
        session.close()

    logger.info(
        "Relay credential registry: %s serial=%s CN=%s not_after=%s (%s)",
        outcome,
        facts.serial_number,
        facts.common_name,
        facts.not_after.date() if facts.not_after is not None else "unknown",
        path,
    )
    return facts


def _resolve_relay_cert_path(config: Any, fallback: str | None) -> str | None:
    """Where the relay client credential lives, in the order the shipped product uses.

    ``config.mtls_cert`` is the authoritative answer when the operator set it (that is
    the exact value the relay dial presents, ``routes/executors.py:1977``); the installer
    default path is the fallback for a core configured the normal way.
    """
    candidates: list[str] = []
    if config is not None:
        explicit = getattr(config, "mtls_cert", None)
        if explicit:
            candidates.append(str(explicit))
    candidates.append(DEFAULT_RELAY_CERT_PATH)
    for c in candidates:
        try:
            if Path(c).is_file():
                return c
        except OSError:
            continue
    return fallback if fallback and Path(fallback).is_file() else None
