# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""PostgreSQL backend for the core."""

import enum
import os
from dataclasses import dataclass
from typing import Any, Final, Self

from sqlalchemy import (
    Engine,
    create_engine,
    event,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .encryption import KEK_SIZE, derive_kek
from .secure_memory import KekCache


class BackendError(Exception):
    """Base backend error."""


class BackendConnectionError(BackendError):
    """Failed to connect to the database."""


class BackendConfigurationError(BackendError):
    """Invalid backend configuration."""


class KekSaltMissingError(BackendError):
    """The persisted KEK salt is missing while secrets already exist.

    Unrecoverable data loss: the passphrase-derived KEK cannot be reproduced
    without the salt, so previously-stored secrets cannot be unwrapped. The
    deployment must be restored from a pre-restart backup.
    """


class KekPassphraseMismatchError(BackendError):
    """The configured encryption passphrase does not match stored key material (#304).

    A wrong passphrase derives a working KEK for NEW wrappings but can never
    unwrap existing envelopes — left unchecked, secrets stored during the
    wrong-passphrase window are permanently unrecoverable. The startup check
    raises this instead of booting: loud, before any new wrapping can happen.
    """


SENTINEL_KEY: Final[str] = "kek_sentinel"
# Fixed known plaintext wrapped under the KEK at mint and unwrapped at every
# boot. Exactly DEK_SIZE so it reuses the AES-256-KW envelope verbatim — no
# new crypto format (wrap_key/unwrap_key are the same primitives secret DEKs
# use). Value-free: this is a public constant, not secret material.
SENTINEL_PLAINTEXT: Final[bytes] = b"kek-sentinel-known-plaintext-v1!"
LEGACY_SAMPLE_LIMIT: Final[int] = 5

# --- #573: the passphrase LENGTH floor, DB-KEK plane -------------------------
# Owner ruling (s85 batch, item #554, verbatim): "Deny whitespace-only passphrases
# and enforce a proper length passcode." The whitespace half shipped as #554 and the
# length half landed on the CA plane in b50bc9e; this is the same ruled number on the
# Argon2id side, which is the "same number for BOTH KDFs" clause of the ruling
# (decisions.md:282). One named constant per plane, and the refusal text below reads
# the number from it — a literal 15 in the sentence is the defect the owner named.
#
# 15 Unicode CODE POINTS, INCLUSIVE (14 refuses, 15 passes), counted on the decoded
# value before any encode. The ceiling is STATED and never enforced: research clause
# C2 requires verifiers to PERMIT at least 64, and the owner ruled OPTION 1, so a
# longer passphrase is accepted and used and MAX_PASSPHRASE_CODE_POINTS exists only to
# interpolate that sentence.
MIN_PASSPHRASE_CODE_POINTS: Final[int] = 15
MAX_PASSPHRASE_CODE_POINTS: Final[int] = 64

# The env names an operator sets this value under — server var first, installer input
# second, exactly as ``server/app.py`` already names them side by side.
DB_PASSPHRASE_ENV: Final[str] = "VENYA_DB__PASSPHRASE"


def _passphrase_code_points(passphrase: bytes | str) -> int:
    """The floor's unit: Unicode CODE POINTS, never bytes.

    This plane's intake carries both typing conventions — ``server/dependencies.py``
    ``init_db()`` hands a ``str`` straight to ``BackendConfig``, while
    ``Backend.get_core()`` encodes first and ``CoreFactory.from_dict()`` encodes before
    constructing — so the count decodes what arrived and measures the string, exactly as
    ``server/ca.py`` and ``executor/key_passphrase.py`` do on their planes. Value-free:
    the count is returned, the value is never logged or echoed.

    A value that is not valid UTF-8 has no decoded string to count, so its byte length
    is the measure — that can only be stricter than a code-point count, never looser.
    """
    if isinstance(passphrase, str):
        return len(passphrase)
    try:
        return len(passphrase.decode("utf-8"))
    except UnicodeDecodeError:
        return len(passphrase)


def is_passphrase_below_floor(passphrase: bytes | str | None) -> bool:
    """True when a SUPPLIED passphrase carries material but is shorter than the floor (#573).

    The blank shapes are NOT this function's question and never become it: unset, empty
    and whitespace-only are answered upstream by the shipped #570 materiality test as
    "not supplied", with that gate's own sentence. The floor runs AFTER that decision.
    DENY, never TRIM — a legal passphrase whose spaces are content is measured as it
    arrived and delivered byte-for-byte to the KDF.
    """
    if passphrase is None:
        return False
    if not passphrase.strip():
        # The shipped #570 materiality answer, asked first: blank is "not supplied", and
        # that gate's own sentence belongs to it. `.strip()` is defined on both bytes and
        # str, so neither typing convention reaches the length question as a blank.
        return False
    return _passphrase_code_points(passphrase) < MIN_PASSPHRASE_CODE_POINTS


def short_passphrase_refusal(subject: str = DB_PASSPHRASE_ENV, *, read_path: bool = False) -> str:
    """Owner-blessed refusal text for a passphrase under the floor, on the DB-KEK plane.

    The block is the one ruled in as R5(a) (flash1's §6, with the two authorized
    corrections applied) — the same bytes ``server/ca.py`` and ``venya_cli.commands``
    ship, with only the SUBJECT and the plane's ARTIFACT nouns varied, exactly as
    ``executor/key_passphrase.py`` did for its plane in #565. Both numbers interpolate
    from the constants the door measures with. The read door drops exactly one clause,
    ``Nothing was written.``; nothing else differs, and no sentence is invented here.
    """
    written_clause = "" if read_path else " Nothing was written."
    return (
        f"REFUSED: {subject} is set to a passphrase shorter than Venya's minimum.{written_clause}\n"
        "Why it matters: this passphrase is the only thing between a copy of this host and every\n"
        "secret this deployment stores, and short passphrases are what an attacker tries first.\n"
        "To fix it:\n"
        f"  1. Replace the value of {subject} with a passphrase of at least "
        f"{MIN_PASSPHRASE_CODE_POINTS} characters. Characters are\n"
        "     counted as you type them, not as bytes, so a passphrase in any alphabet counts the same.\n"
        "     Spaces count as characters, but a passphrase made only of spaces counts as no passphrase.\n"
        f"  2. There is no rule about which characters appear — length is the only requirement, and\n"
        f"     Venya supports passphrases up to {MAX_PASSPHRASE_CODE_POINTS} characters.\n"
        "  3. Provide the passphrase through the environment, never as a command-line argument\n"
        "     (command-line values are visible to other processes on the machine).\n"
        "Your existing database and its stored secrets were not modified by this refusal.\n"
        "Reference: docs/BACKUPS.md (the DB + passphrase pairing, and what a backup needs to\n"
        "restore) and docs/cert-rotation-runbook.md (CA file locations and rotation)."
    )


def _refuse_if_below_floor(passphrase: bytes | str | None, *, read_path: bool = False) -> None:
    """Raise the blessed refusal for a supplied passphrase under the floor.

    ``BackendConfigurationError``, the same class this gate already raises for "no
    passphrase at all" — so no caller gains a new exception arm to handle.
    """
    if is_passphrase_below_floor(passphrase):
        raise BackendConfigurationError(short_passphrase_refusal(read_path=read_path))


class SentinelStatus(enum.Enum):
    """Outcome of the boot-time passphrase proof (#304)."""

    MATCH = "match"  # sentinel present and unwraps under the configured KEK
    MISMATCH = "mismatch"  # sentinel present, unwrap failed -> hard exit
    LEGACY_OK = "legacy_ok"  # no sentinel, >=1 sampled DEK envelope unwraps -> boot
    LEGACY_MISMATCH = "legacy_mismatch"  # no sentinel, ALL sampled envelopes fail -> hard exit
    FRESH_EMPTY = "fresh_empty"  # no sentinel, no secrets: nothing to verify, nothing to corrupt


@dataclass(frozen=True)
class SentinelCheck:
    """Result of verify_kek_sentinel: status plus legacy sampling tallies."""

    status: SentinelStatus
    samples: int = 0
    failures: int = 0


def ensure_kek_sentinel(session: Session, kek: bytes | memoryview) -> None:
    """Idempotent get-or-create of the single sentinel row.

    Minted at the one convergence point every KEK-wrapped envelope funnels
    through (Core.encrypt) — first successful crypto use after boot/store
    lands it, legacy and fresh installs alike. The ``key`` primary key
    resolves the concurrent-mint race exactly like ensure_kek_salt does:
    the loser's IntegrityError means the winner already stored an equivalent
    envelope, so the rollback-and-ignore IS the correct outcome.
    """
    from core.iam.models import KekSentinel

    from .encryption import wrap_key

    existing = session.query(KekSentinel).filter(KekSentinel.key == SENTINEL_KEY).first()
    if existing is not None:
        return
    session.add(KekSentinel(key=SENTINEL_KEY, wrapped_sentinel=wrap_key(kek, SENTINEL_PLAINTEXT)))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()


def verify_kek_sentinel(session: Session, kek: bytes | memoryview) -> SentinelCheck:
    """Prove the configured passphrase against stored key material.

    Sentinel-first (the ruling's posture: anything else leaves the
    wrong-KEK-wraps-new-DEKs window): unwrap the sentinel envelope and compare
    against the fixed plaintext. Legacy installs (sentinel absent but secrets
    present) fall back to sampling up to LEGACY_SAMPLE_LIMIT stored DEK
    envelopes — the wrong-passphrase verdict requires ALL samples to fail, so
    one corrupt row cannot brick boot. Fresh empty installs report
    FRESH_EMPTY: there is nothing stored to corrupt yet.
    """
    from core.iam.models import KekSentinel, Secret

    from .encryption import EncryptionError, unwrap_key

    row = session.query(KekSentinel).filter(KekSentinel.key == SENTINEL_KEY).first()
    if row is not None:
        try:
            ok = unwrap_key(kek, row.wrapped_sentinel) == SENTINEL_PLAINTEXT
        except EncryptionError:
            ok = False
        return SentinelCheck(SentinelStatus.MATCH if ok else SentinelStatus.MISMATCH)

    envelopes = [r[0] for r in session.query(Secret.wrapped_dek).limit(LEGACY_SAMPLE_LIMIT).all()]
    if not envelopes:
        return SentinelCheck(SentinelStatus.FRESH_EMPTY)

    failures = 0
    for wrapped_dek in envelopes:
        try:
            unwrap_key(kek, wrapped_dek)
        except EncryptionError:
            failures += 1
    status = SentinelStatus.LEGACY_MISMATCH if failures == len(envelopes) else SentinelStatus.LEGACY_OK
    return SentinelCheck(status, samples=len(envelopes), failures=failures)


class BackendConfig:
    """Configuration for the PostgreSQL backend.

    Attributes:
        database_url: PostgreSQL connection URL (e.g. postgresql+psycopg2://user:pass@host/db).
        passphrase: Master passphrase for key derivation (used to derive KEK).
        kek: Write-once INTAKE slot for a raw 32-byte KEK. If provided,
            passphrase is ignored for key derivation. ``Backend`` copies this
            value into its KEK cache on construction and clears the slot to
            ``None`` — the stored form of the key is the protected buffer, not
            a ``bytes`` field on this object (#472).
        wal_mode: Whether to enable WAL mode (default True, PostgreSQL default).
        audit_enabled: Whether to enable audit event logging (default True).
    """

    def __init__(
        self,
        database_url: str,
        passphrase: bytes | None = None,
        kek: bytes | None = None,
        wal_mode: bool = True,
        audit_enabled: bool = True,
    ) -> None:
        # #570: a passphrase made only of whitespace carries no material, so it answers
        # the same question unset answers — "not provided". This is the predicate shape
        # the tree already ships for the CA plane (``server/ca.py`` ``_load_passphrase()``
        # and the CLI's ``_admin_ca_passphrase_or_none()``, both #554/#547), applied to the
        # DB KEK plane, where the stakes are the ones ``KekPassphraseMismatchError``
        # states: a value of one space derives a WORKING KEK for new wrappings and can
        # never unwrap what is already stored. The refusal reuses the sentence already on
        # the line below — no new wording, same message as unset.
        #
        # DENY, never TRIM: only the SUPPLIED? decision looks at the stripped form. A
        # passphrase whose spaces are content is stored byte-for-byte and still derives
        # the key it always derived, so an existing encrypted database keeps opening.
        if passphrase is not None and not passphrase.strip():
            passphrase = None
        # #573: the length floor, asked AFTER the materiality decision above and never
        # instead of it — blank stays "not supplied" and keeps that gate's own shipped
        # sentence. This is the boot gate the ticket names, and it is the one place on
        # this plane that decides the question, so the refusal happens before any
        # BackendConfig object exists: no engine, no session, no salt read, no write.
        # DENY, never TRIM — what passes is stored byte-for-byte below.
        _refuse_if_below_floor(passphrase)
        if passphrase is None and kek is None:
            raise BackendConfigurationError("Either passphrase or kek must be provided")
        if kek is not None and len(kek) != KEK_SIZE:
            raise BackendConfigurationError(f"KEK must be {KEK_SIZE} bytes, got {len(kek)}")

        self.database_url = database_url
        self.passphrase = passphrase
        # NOTE: for a passphrase-only config, kek stays None until
        # Backend.bootstrap_kek() resolves it from the persisted salt. Deriving
        # here with a random salt (the old behavior) produced a non-reproducible
        # KEK across restarts (C-11) and must not be done. This field is the
        # intake slot only: Backend moves the value into the KEK cache and
        # clears it, so nothing reads it afterwards.
        self.kek = kek
        self.wal_mode = wal_mode
        self.audit_enabled = audit_enabled

    @property
    def engine_url(self) -> str:
        """Get the SQLAlchemy engine URL."""
        return self.database_url


def ensure_kek_salt(session: Session) -> bytes:
    """Return the persisted KEK salt, generating and persisting it on first boot.

    - Salt present: returned as-is (normal restart).
    - Salt absent and no secrets: first boot -> generate a random salt,
      persist it, and return it.
    - Salt absent and secrets present: raise KekSaltMissingError. Those secrets
      are wrapped under an unknown KEK and cannot be recovered.

    The concurrent first-boot race (two processes both generating a salt) is
    resolved by the ``key`` primary key: the loser re-reads the winner's salt.
    """
    from core.iam.models import Secret, VenyaConfig

    from .encryption import ARGON2_SALT_LEN

    row = session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first()
    if row is not None:
        return row.value

    existing_secret = session.query(Secret).first()
    if existing_secret is not None:
        raise KekSaltMissingError(
            "KEK salt missing from venya_config but secrets already exist. "
            "Previously stored secrets are unrecoverable with the lost salt. "
            "Restore from a pre-restart backup and retry."
        )

    salt = os.urandom(ARGON2_SALT_LEN)
    session.add(VenyaConfig(key="kek_salt", value=salt))
    try:
        session.flush()
    except IntegrityError:
        # Concurrent first boot: another process inserted a salt first.
        session.rollback()
        winner = session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first()
        if winner is None:
            raise
        return winner.value
    session.commit()
    return salt


class Backend:
    """PostgreSQL backend wrapper.

    Provides database engine creation, session management, and connection
    setup, and owns the one KEK cache for this process (#472): the key lives
    in a protected buffer, and readers get a scoped read-only view of it.
    """

    #: #603 AC2 step 1 (a′-i) — capacity PARTITION, not capacity growth. The
    #: shared pool (``pool_size=5, max_overflow=10`` below) is what ordinary request
    #: traffic consumes; a starved pool used to make the executor-mTLS revocation read
    #: wait behind command traffic, which reads to the caller as a fault. These three
    #: connections are held back for that read so it cannot be starved. Deliberately
    #: NOT derived from ``ConcurrencyConfig.max_concurrent_commands`` — sizing that
    #: tracks shipped concurrency is the capacity-raise route #603 AC6 / RF-4 forbid.
    #: Headroom only: an ``ACCESS EXCLUSIVE`` lock on the revocation table still stalls
    #: this read (same table), which is why step 1 does not close AC2.
    LIVENESS_POOL_SIZE = 1
    LIVENESS_MAX_OVERFLOW = 1
    #: Short by design: if the reserved connections are all held, the revocation read
    #: must fail LOUD and fast (the shipped raise → 500 path) rather than queue for
    #: the 30 s QueuePool default behind the traffic it was carved out to escape.
    LIVENESS_POOL_TIMEOUT = 2.0

    def __init__(self, config: BackendConfig) -> None:
        self.config = config
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None
        # #603 AC2 step 1: the reserved liveness pair. Same database URL as the
        # shared engine — it acquires NO new credential and owns no key material.
        self._liveness_engine: Engine | None = None
        self._liveness_session_factory: sessionmaker[Session] | None = None
        # One owner, one buffer. Pinning is attempted here and reported; the
        # outcome never decides whether the core starts.
        self._kek_cache = KekCache(KEK_SIZE)
        intake = config.kek
        if intake is not None:
            self._kek_cache.populate(intake)
            # Write-once: the intake slot stops being the stored form.
            config.kek = None

    @property
    def kek_cache(self) -> KekCache:
        """The KEK cache this backend owns.

        Readers use ``cache.view()`` for scoped key access; nothing hands out
        the buffer or a ``bytes`` copy of the key.
        """
        return self._kek_cache

    @property
    def engine(self) -> Engine:
        """Get the SQLAlchemy engine, creating it if necessary."""
        if self._engine is None:
            self._create_engine()
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Get the session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(bind=self.engine)
        return self._session_factory

    def get_session(self) -> Session:
        """Create a new database session."""
        return self.session_factory()

    @property
    def liveness_engine(self) -> Engine:
        """The reserved engine for the liveness/revocation read (#603 AC2 step 1).

        A second engine on the SAME ``config.database_url`` — no new credential, no
        new permission, no key material — with its own small bounded pool, so the
        revocation read cannot be starved by ordinary request traffic.
        """
        if self._liveness_engine is None:
            self._create_liveness_engine()
        return self._liveness_engine

    @property
    def liveness_session_factory(self) -> sessionmaker[Session]:
        """Session factory bound to the reserved liveness engine."""
        if self._liveness_session_factory is None:
            self._liveness_session_factory = sessionmaker(bind=self.liveness_engine)
        return self._liveness_session_factory

    def get_liveness_session(self) -> Session:
        """Open a session on the reserved liveness connections.

        Fail-closed contract: if the reserved engine cannot be built, or no reserved
        connection can be checked out within ``LIVENESS_POOL_TIMEOUT``, this RAISES.
        It never returns a session bound to the shared pool, because falling back
        there is the starvation this step removes — a caller that catches the raise
        must refuse the request, never allow it. The executor-mTLS path lets it
        propagate (the shipped raise → 500 shape), which refuses without asserting a
        revocation that never happened.
        """
        return self.liveness_session_factory()

    def _create_liveness_engine(self) -> None:
        """Create the reserved liveness engine (#603 AC2 step 1, shape (a′-i)).

        Mirrors the shared engine's connection settings — same URL, same
        ``pool_pre_ping``, same PRAGMA listener body — differing ONLY in pool size,
        so a reserved connection is not a second, weaker rulebook for the read.
        """
        self._liveness_engine = create_engine(
            self.config.database_url,
            pool_pre_ping=True,
            pool_size=self.LIVENESS_POOL_SIZE,
            max_overflow=self.LIVENESS_MAX_OVERFLOW,
            pool_timeout=self.LIVENESS_POOL_TIMEOUT,
        )

        # Same connection-level settings as the shared engine: the revocation read
        # must run under the identical statement timeout, or the reserved path would
        # be a different (more forgiving) plan than the path it replaces.
        @event.listens_for(self._liveness_engine, "connect")
        def set_liveness_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                if self.config.wal_mode:
                    cursor.execute("SET synchronous_commit = ON")
                cursor.execute("SET statement_timeout = '300s'")
                cursor.execute("SET enable_partition_pruning = ON")
                cursor.close()
            except Exception:
                cursor.close()
                raise

    def _create_engine(self) -> None:
        """Create the PostgreSQL engine."""
        self._engine = create_engine(
            self.config.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )

        # Set PostgreSQL PRAGMAs (connection-level settings)
        @event.listens_for(self._engine, "connect")
        def set_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                # Enable WAL (PostgreSQL default, but be explicit)
                if self.config.wal_mode:
                    cursor.execute("SET synchronous_commit = ON")

                # Set statement timeout (5 minutes)
                cursor.execute("SET statement_timeout = '300s'")

                # Enable prepared statements
                cursor.execute("SET enable_partition_pruning = ON")

                cursor.close()
            except Exception:
                cursor.close()
                raise

    def bootstrap_kek(self, passphrase: bytes | None = None) -> KekCache:
        """Resolve the KEK from the passphrase using the persisted salt (C-11).

        Reads the Argon2 salt from ``venya_config`` (generating and persisting
        it on first boot) and derives the KEK deterministically. The resolved
        key is copied into this backend's KEK cache, which is the one place
        the key is kept: every consumer (the core facade, the filter endpoint,
        the startup sentinel check) shares that single cache.

        Calling it again with no passphrase neither re-derives nor re-fills —
        an already-populated cache is returned as it is.

        Args:
            passphrase: Passphrase bytes; falls back to ``config.passphrase``.

        Returns:
            The populated KEK cache.

        Raises:
            KekSaltMissingError: if the salt is missing but secrets exist
                (unrecoverable data loss).
            BackendConfigurationError: if no passphrase or KEK is available.
        """
        if passphrase is None and self._kek_cache.is_populated:
            return self._kek_cache
        if passphrase is None:
            passphrase = self.config.passphrase
        if passphrase is None:
            if self._kek_cache.is_populated:
                return self._kek_cache
            raise BackendConfigurationError("bootstrap_kek: no passphrase or KEK available")

        # #573 read/derive door. The override argument is the one path that reaches the
        # KDF WITHOUT passing the config gate above (``Backend.get_core(passphrase)``
        # hands it straight here), so the same predicate asks here too — otherwise the
        # floor would be a sign on the door and no lock. Refusing here opens no session,
        # reads no salt, derives nothing and writes nothing: this line sits above
        # ``get_session()``, so the persisted ``kek_salt`` row and every envelope under it
        # are untouched. The text is the read variant (the blessed block minus the
        # ``Nothing was written.`` clause), because this door is not writing.
        _refuse_if_below_floor(passphrase, read_path=True)

        session = self.get_session()
        try:
            salt = ensure_kek_salt(session)
            kek, _ = derive_kek(passphrase, salt)
            self._kek_cache.populate(kek)
            return self._kek_cache
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_core(self, passphrase: str | None = None) -> Any:
        """Create and return a configured Core instance.

        The KEK is resolved via ``bootstrap_kek()`` (persisted salt) whenever a
        passphrase is in play; a raw KEK given to the backend (for example
        ``CoreFactory.with_kek()``) is already in the cache when no passphrase
        is involved. Either way the Core receives the cache, not the key.

        Args:
            passphrase: Optional passphrase override for key derivation.

        Returns:
            Configured Core instance.
        """
        from .core import Core
        from .rate_limiter import RateLimiter

        if passphrase is not None:
            self.bootstrap_kek(passphrase.encode("utf-8"))
        elif self.config.passphrase is not None:
            self.bootstrap_kek()
        # else: raw-KEK intake already filled the cache, or nothing is
        # configured and the Core guards report that.

        return Core(
            backend=self,
            rate_limiter=RateLimiter(),
            kek=self._kek_cache,
        )

    def dispose(self) -> None:
        """Dispose of the engine and release the KEK cache.

        The cache release runs here, at process lifetime — never per request
        and never per session. What the buffer was holding is erased on the
        way out; see ``kek cache: released`` in the log for the report.
        """
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
        # #603 AC2 step 1: the reserved pair is disposed on the same process-lifetime
        # boundary as the shared engine — a held-back connection must not outlive it.
        if self._liveness_engine is not None:
            self._liveness_engine.dispose()
            self._liveness_engine = None
            self._liveness_session_factory = None
        self._kek_cache.release()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.dispose()
