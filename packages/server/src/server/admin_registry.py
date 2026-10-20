# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Population of the admin-credential registry — the thing #684's check was missing.

THE DEFECT THIS SUPPLIES THE CURE FOR. ``admin_revoke_admin_cert`` validated the FORMAT of
the operator's string, found no row in ``AdminCertRevocation``, and blind-inserted one —
so ``venya admin revoke-admin-cert --serial <any hex>`` exited 0 and wrote a revocation
naming a serial no credential ever held, while the live admin credential kept transacting
(#684, measured physically by ``flash6`` at leg 232 against the sibling relay route, which
refuses the identical string with ``REFUSE_UNREGISTERED``). A membership check needs
something to be a member OF, and on this plane nothing existed: ``AdminCertRevocation`` is
the OUTPUT of that verb, so consulting it would be circular. This module supplies the
population.

THE SHAPE IS #597'S, NOT A THIRD SCHEME. ``relay_registry.py`` + migration ``040`` solved
the identical population gap for the core's relay client credential, and this file copies
it deliberately: facts are READ from the certificate (never supplied by a caller), upsert
is keyed on the canonical serial so a boot is idempotent, ``revoked`` state is NOT stored
here, and this module never infers or clears a revocation.

ONE DELIBERATE DIFFERENCE FROM THE RELAY MODULE, stated because a reader who knows #597
will look for it: the relay registry carries ``revoked_at`` because the relay plane had no
revocation table at all, so the registry row IS the revocation record. The admin plane
already has one — ``AdminCertRevocation``, which ``AdminCAManager.generate_crl`` draws
from — so this table stores registration facts only. Two columns named ``revoked_at`` on
one plane would be two sources of truth for one fact, and the CRL builder would read the
wrong one.

Boot ingest (``ingest_admin_credential``) covers the machine-plane bootstrap leaf the
installer mints out-of-product, when the operator points ``VENYA_ADMIN_CERT`` at it (the
server deliberately names NO path — see the note on ``ADMIN_CERT_PATH_ENV``, this is the
#565 site-1 destination seam, not a style choice); the mint-side write in
``routes/admin_certs.py`` covers every human-plane issuance from here on; every credential
the admin-mTLS middleware VERIFIES and admits is recorded at that moment
(``observed-admission``), which is what makes the population complete for a credential the
boot never saw and nobody held a PEM for; and ``admin_register_admin_cert`` is the explicit
remedy a refusal names (facts read off the submitted PEM, so a caller cannot enroll an
arbitrary serial). A credential that is in no table here is NOT treated as live-by-default
and NOT treated as revoked — it is refused loudly, which is what keeps this store from
becoming an allowlist.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("venya.server")

#: Where the core's own machine-plane admin credential lives, in the ONE way server source is
#: allowed to speak of it: the ``VENYA_ADMIN_CERT`` environment variable, which the product
#: already uses for exactly this file (the CLI's admin-mTLS dial reads it; the installer prints
#: it for headless admin calls). NO PATH LITERAL APPEARS HERE, and that is not stylistic —
#: ``tests/test_site1_destination_seam_565.py::test_shipped_server_source_names_no_leaf_destination``
#: forbids any file under ``packages/server/src`` from naming a delivered-leaf path, because the
#: destination and its enforced modes are RF-10's installer obligations and must not become
#: expressible from the server (#565 site 1, ruling ``cdcde4e``). So the operator states the
#: path; the server never assumes one, and a core that does not set the variable gets a named
#: warning rather than a guessed default.
ADMIN_CERT_PATH_ENV = "VENYA_ADMIN_CERT"

#: ``source`` values, one per writer. Names the writer, so an operator reading the
#: registry can tell a boot-registered machine leaf from an elevation-path human mint.
SOURCE_BOOT_DISK = "boot-disk"
SOURCE_ISSUE_ROUTE = "issue-route"
SOURCE_REGISTER_ROUTE = "register-route"
#: The fourth writer, and the one that makes the population COMPLETE rather than merely
#: seeded: an admin credential that has just been CRYPTOGRAPHICALLY VERIFIED at an admin
#: route is recorded there and then by ``middleware/auth.py``. The other three each need
#: something the server may not have — a path (boot), a spent ceremony (mint), or a PEM in
#: hand (register) — and this one needs only the certificate the caller is already
#: presenting. Without it a core that never set ``VENYA_ADMIN_CERT`` would refuse to revoke
#: its own operator's working credential, which is the exact failure this row's shape exists
#: to avoid, and the reason the dispatch calls it out as worse than the bug.
SOURCE_OBSERVED_ADMISSION = "observed-admission"


@dataclass(frozen=True)
class AdminCredentialFacts:
    """What one admin certificate says about itself, read OFF the certificate.

    Every field is parsed, never supplied by a caller, so a registry row cannot be made to
    claim a serial or an identity the credential does not carry. Timestamps are aware
    (repo datetime law: no naive datetimes).
    """

    serial_number: str
    common_name: str
    cert_fingerprint: str
    public_key_hash: str
    issued_at: Any
    not_after: Any


def facts_from_certificate(cert: x509.Certificate) -> AdminCredentialFacts:
    """Parse the registry facts out of one loaded admin certificate."""
    cn = None
    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        cn = attr.value if isinstance(attr.value, str) else None
        break
    if cn is None:
        raise ValueError("certificate has no CommonName — cannot register a nameless credential")

    der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return AdminCredentialFacts(
        # WRITE form is canonical_serial (lowercase, zero-padded to >=16) per #481. The
        # COMPARE key (serial_match_key) must never be what a row stores — same rule and
        # the same reason as relay_registry.read_relay_credential.
        serial_number=canonical_serial(cert.serial_number),
        common_name=cn,
        cert_fingerprint=hashlib.sha256(der).hexdigest(),
        public_key_hash=hashlib.sha256(spki).hexdigest(),
        issued_at=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )


def read_admin_credential(path: str | Path) -> AdminCredentialFacts:
    """Parse the registry facts out of one admin certificate FILE (the boot reader)."""
    raw = Path(path).read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except Exception as pem_exc:
        try:
            cert = x509.load_der_x509_certificate(raw)
        except Exception as der_exc:
            raise ValueError(
                f"{path} is not a parseable certificate (pem: {type(pem_exc).__name__}, der: {type(der_exc).__name__})"
            ) from der_exc
    return facts_from_certificate(cert)


def register_admin_credential(session: Any, facts: AdminCredentialFacts, source: str) -> str:
    """Insert-or-touch one credential's registry row. Returns ``"created"`` or ``"present"``.

    Matched with the tolerant ``serial_match_clause``, not string equality: the caller may
    hand us a serial spelled any way, and #481 is exactly the class where a differently
    spelled serial meant a revocation that recorded green and never took effect.

    ``"present"`` on a row that already exists is a NO-OP — this function never updates an
    existing row, so neither a reboot nor a re-register can rewrite who put a credential in
    the population, and (unlike a naive upsert) it cannot clear anything either. Revocation
    is not this table's business at all: there is no ``revoked_at`` column here, and
    ``AdminCertRevocation`` remains the single revocation record the CRL builder reads.
    """
    from core.iam.models import AdminCredential
    from core.utils.cert_serial import serial_match_clause

    existing = (
        session.query(AdminCredential)
        .filter(serial_match_clause(AdminCredential.serial_number, facts.serial_number))
        .one_or_none()
    )
    if existing is not None:
        return "present"

    session.add(
        AdminCredential(
            serial_number=facts.serial_number,
            common_name=facts.common_name,
            source=source,
            cert_fingerprint=facts.cert_fingerprint,
            public_key_hash=facts.public_key_hash,
            issued_at=facts.issued_at,
            not_after=facts.not_after,
        )
    )
    return "created"


def ingest_admin_credential(
    config: Any,
    backend: Any,
    cert_path: str | None = None,
) -> AdminCredentialFacts | None:
    """Boot step: make sure the registry names the admin credential this core presents.

    The path comes from the caller (tests, and any future explicit wiring) or from
    ``VENYA_ADMIN_CERT`` — never from a literal baked into server source, which the #565
    site-1 destination seam forbids. Returns the parsed facts, or ``None`` when there is
    nothing to register, and a ``None`` is NOT a silent pass: every refusal path logs a
    warning naming the variable and the outcome.

    Non-fatal by design, exactly like #597's relay ingest: a missing registry row is a lost
    revocation path for that one credential, not a reason to take a working core down.
    """
    path = cert_path or os.environ.get(ADMIN_CERT_PATH_ENV)
    if not path:
        logger.warning(
            "Admin credential registry NOT updated this boot: %s is not set, so this core has no "
            "admin credential on disk to register — an admin credential the store does not name "
            "cannot be revoked until it is enrolled (POST /api/v1/admin/certs/register) (#684).",
            ADMIN_CERT_PATH_ENV,
        )
        return None
    if not Path(path).is_file():
        logger.warning(
            "Admin credential registry NOT updated this boot: no readable file at the %s path — that "
            "credential cannot be revoked until it is registered (#684).",
            ADMIN_CERT_PATH_ENV,
        )
        return None

    try:
        facts = read_admin_credential(path)
    except (OSError, ValueError) as exc:
        logger.warning(
            "Admin credential registry NOT updated this boot: %s could not be read as a certificate (%s) "
            "— this credential stays unrevocable until it is (#684).",
            path,
            exc,
        )
        return None

    session = backend.get_session()
    try:
        outcome = register_admin_credential(session, facts, SOURCE_BOOT_DISK)
        session.commit()
    finally:
        session.close()

    logger.info(
        "Admin credential registry: %s serial=%s CN=%s not_after=%s (%s)",
        outcome,
        facts.serial_number,
        facts.common_name,
        facts.not_after.date() if facts.not_after is not None else "unknown",
        path,
    )
    return facts
