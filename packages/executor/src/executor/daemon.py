"""Executor daemon process management.

Manages the persistent executor daemon lifecycle:
  - Registration with server (mTLS certificate)
  - Certificate rotation
  - Heartbeat protocol
  - Revocation polling
  - Reaper loop for orphaned resources
  - Signal handling
"""

import hashlib
import logging
import os
import signal
import ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2

# tomli_w is required for clearing enrollment tokens after registration.
# Failing fast at import time is correct — a security-critical dependency
# must not be silently unavailable at runtime.
import tomli_w  # type: ignore[import-not-found]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .audit import AuditLogger
from .command_validator import (
    DEFAULT_DANGEROUS_PATTERNS,
    DEFAULT_TRUSTED_PATHS,
    CommandPolicy,
    CommandValidator,
)
from .config import ExecutorConfig
from .executor import Executor
from .relay_listener import RelayListener
from .strategies.sbx_strategy import SbxStrategy, sweep_workspace_base

logger = logging.getLogger("venya.executor.daemon")

CLOCK_SKEW_TOLERANCE = timedelta(seconds=300)


class CertificateValidationError(Exception):
    """Raised when an executor certificate fails validation."""


class DaemonState:
    """Tracks daemon runtime state."""

    def __init__(self) -> None:
        self.running = False
        self.session_id: str | None = None
        self.executor_id: str = "default"
        self.command_policy: Any = None
        self.revoked = False
        self.cert_serial: str | None = None
        self.cert_not_after: datetime | None = None
        self._consecutive_revocation_failures: int = 0


class CertificateManager:
    """Manages executor mTLS certificate lifecycle.

    Handles registration, rotation, revocation checking, and fingerprint
    computation. Uses ECDSA P-256 for all keypairs and certificates.
    """

    def __init__(self, config: ExecutorConfig) -> None:
        self.config = config
        self.client: httpx2.Client | None = None
        self.cert_path = config.mtls.cert
        self.key_path = config.mtls.key
        self.ca_cert_path = config.mtls.ca_cert
        self.serial: str | None = None
        self._not_after: datetime | None = None
        self._last_revocation_etag: str | None = None

    @property
    def not_after(self) -> datetime | None:
        """Certificate expiry time."""
        return self._not_after

    def register(self, executor_id: str, enrollment_token: str | None = None) -> None:
        """Register executor with server, obtain signed certificate.

        Always uses full TLS verification. To disable verification in
        development, set VENYA_TLS_VERIFY=false before running.

        Args:
            executor_id: Unique executor identifier.
            enrollment_token: Optional enrollment token for bootstrap auth.

        Raises:
            RuntimeError: If the server returns an error or the certificate
                fails CA validation.
            httpx2.HTTPError: If the network request fails.
        """
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            logger.info("Certificate already exists — skipping registration for: %s", executor_id)
            self._load_metadata()
            return

        # Fail before the HTTP call if a cert directory is not writable (e.g.
        # ReadOnlyPaths=/etc/venya with install-time registration skipped):
        # registering remotely and then failing the local write burns the
        # enrollment token and crash-loops the daemon on EROFS.
        for cert_dir in {
            Path(self.ca_cert_path).parent,
            Path(self.cert_path).parent,
            Path(self.key_path).parent,
        }:
            if not os.access(cert_dir, os.W_OK):
                msg = (
                    f"Cannot write mTLS certificates: {cert_dir} is not writable "
                    "(read-only mount or permissions). The executor cannot register at "
                    "runtime. Reinstall with a non-empty VENYA_EXECUTOR_ENROLLMENT_TOKEN "
                    "so registration completes at install time, or make the certificate "
                    "directory writable by the daemon user."
                )
                logger.error(msg)
                raise RuntimeError(msg)

        logger.info("Registering executor: %s", executor_id)

        # Generate ECDSA P-256 keypair
        private_key = _generate_ecdsa_p256_keypair()

        # Create CSR with executor_id as CN
        csr_pem = _create_csr(private_key, executor_id)

        # Build payload
        payload = {
            "csr_pem": csr_pem.decode(),
            "executor_id": executor_id,
        }
        if enrollment_token:
            payload["enrollment_token"] = enrollment_token

        url = f"{self.config.server_url}/api/v1/executors/register"

        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env == "" or tls_verify_env.lower() == "true":
            tls_verify = True
        elif tls_verify_env.lower() == "false":
            tls_verify = False
            logger.warning("VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)")
        else:
            raise RuntimeError(f"Invalid VENYA_TLS_VERIFY value: '{tls_verify_env}'. " "Must be 'true' or 'false'.")

        # Build SSL context for TLS verification
        if tls_verify:
            ssl_ctx = ssl.create_default_context()
            ca_bundle = self.config.ca_bundle
            if ca_bundle and Path(ca_bundle).exists():
                ssl_ctx.load_verify_locations(ca_bundle)
            verify_param: object = ssl_ctx
        else:
            verify_param = False

        try:
            with httpx2.Client(verify=verify_param, timeout=self.config.network.registration_timeout_seconds) as client:
                response = client.post(url, json=payload)
            response.raise_for_status()
        except httpx2.ConnectError as e:
            # Log full traceback in debug mode for deep diagnostics
            if os.environ.get("VENYA_DEBUG"):
                import traceback

                logger.error("Full exception chain:\n%s", traceback.format_exc())

            # Determine if this is a TLS failure by inspecting the exception chain
            # httpx2 wraps ssl.SSLError as ConnectError — check the message for TLS keywords
            err_str = str(e).lower()
            if any(t in err_str for t in ("ssl", "certificate", "tls", "verif")):
                raise RuntimeError(
                    f"Registration failed: TLS verification error — {e}. " "Verify server CA is trusted."
                ) from e
            raise RuntimeError(
                f"Registration failed: cannot reach server — {e}. "
                "Check: DNS resolution, network connectivity, and core service status."
            ) from e

        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()
        self.serial = data["serial_number"]
        self._not_after = datetime.fromisoformat(data["not_after"]).replace(tzinfo=UTC)

        # Validate certificate before saving
        validate_executor_certificate(cert_pem, ca_cert_pem, executor_id)

        # Save CA certificate, signed certificate, and private key
        try:
            Path(self.ca_cert_path).write_bytes(ca_cert_pem)
            logger.info("Saved CA certificate to %s", self.ca_cert_path)

            Path(self.cert_path).write_bytes(cert_pem)
            os.chmod(self.cert_path, 0o644)

            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            Path(self.key_path).write_bytes(key_pem)
            os.chmod(self.key_path, 0o600)
        except OSError as e:
            msg = (
                f"mTLS certificate write failed: {e}. The server accepted the "
                "registration but certificates could not be saved locally. Fix the "
                "read-only mount or permissions on the certificate directory, mint a "
                "fresh enrollment token, and reinstall."
            )
            logger.error(msg)
            raise RuntimeError(msg) from e

        logger.info(
            "Registration complete: serial=%s, expires=%s",
            self.serial,
            self._not_after.isoformat(),
        )

    def needs_rotation(self) -> bool:
        """Check if the certificate needs rotation.

        Returns True if:
        - No certificate exists on disk
        - Certificate expires within ``rotate_before_days`` of now

        Returns:
            True if certificate needs renewal.
        """
        if not os.path.exists(self.cert_path):
            return True

        cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
        now = datetime.now(UTC)
        expiry = cert.not_valid_after_utc
        threshold = timedelta(days=self.config.cert_rotation.rotate_before_days)

        if expiry < now:
            logger.warning("Certificate expired at %s", expiry.isoformat())
            return True

        return expiry - now <= threshold

    def rotate(self) -> None:
        """Request and install a new certificate.

        Submits a fresh CSR to the server, validates the returned certificate
        against the CA, and replaces the on-disk cert and key.

        Raises:
            RuntimeError: If no certificate exists, CA validation fails, or
                the server returns an error.
            httpx2.HTTPError: If the network request fails.
        """
        logger.info("Rotating executor certificate")

        if not os.path.exists(self.cert_path):
            raise RuntimeError("Cannot rotate: no existing certificate (must register first)")

        # Generate new keypair and CSR
        private_key = _generate_ecdsa_p256_keypair()
        executor_id = _extract_executor_id_from_cert(self.cert_path)
        csr_pem = _create_csr(private_key, executor_id)

        # Re-register with server (same endpoint, replaces old cert)
        response = self.client.post(  # type: ignore[union-attr]
            "/api/v1/executors/register",
            json={
                "executor_id": executor_id,
                "csr_pem": csr_pem.decode(),
            },
            timeout=self.config.network.registration_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()
        self.serial = data["serial_number"]
        self._not_after = datetime.fromisoformat(data["not_after"]).replace(tzinfo=UTC)

        # Validate certificate
        validate_executor_certificate(cert_pem, ca_cert_pem, executor_id)

        # Replace on disk
        Path(self.cert_path).write_bytes(cert_pem)
        os.chmod(self.cert_path, 0o644)

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        Path(self.key_path).write_bytes(key_pem)
        os.chmod(self.key_path, 0o600)

        # Update CA cert from server response
        Path(self.ca_cert_path).write_bytes(ca_cert_pem)

        logger.info(
            "Certificate rotated: serial=%s, expires=%s",
            self.serial,
            self._not_after.isoformat(),
        )

    def get_fingerprint(self) -> str:
        """Compute the SHA-256 fingerprint of the current certificate.

        Returns:
            Lowercase hex fingerprint string, or empty string if no cert
            exists.
        """
        if not os.path.exists(self.cert_path):
            return ""

        cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def check_revocation(self) -> bool:
        """Check if this executor's certificate has been revoked.

        Polls the server's revocation list endpoint and checks whether the
        current serial number appears in the list. Supports conditional GET
        via ETag to avoid unnecessary network traffic when the list hasn't
        changed.

        Returns:
            True if the certificate is revoked. False if not revoked or if
            the server is unreachable (graceful degradation — the daemon
            will retry on the next loop iteration).
        """
        if self.serial is None:
            return False

        try:
            headers = {}
            if self._last_revocation_etag:
                headers["If-None-Match"] = self._last_revocation_etag

            response = self.client.get(  # type: ignore[union-attr]
                "/api/v1/executors/certs/revocation-list",
                headers=headers,
                timeout=self.config.network.request_timeout_seconds,
            )

            if response.status_code == 304:
                logger.debug("Revocation list unchanged, skipping check")
                return False

            response.raise_for_status()
            self._last_revocation_etag = response.headers.get("etag")

            data = response.json()
            revoked_serials = set(data.get("revoked_serials", []))
            is_revoked = self.serial in revoked_serials

            if is_revoked:
                logger.warning("Executor certificate REVOKED (serial=%s)", self.serial)
            else:
                logger.debug("Certificate not revoked (serial=%s)", self.serial)

            return is_revoked
        except httpx2.RequestError:
            logger.debug("Failed to check revocation status (will retry)")
            return False

    def _load_metadata(self) -> None:
        """Load serial and expiry from the on-disk certificate."""
        if not os.path.exists(self.cert_path):
            return

        try:
            cert = x509.load_pem_x509_certificate(Path(self.cert_path).read_bytes())
            self._not_after = cert.not_valid_after_utc
            self.serial = format(cert.serial_number, "016x")
        except Exception:
            # Corrupted or invalid cert — metadata unavailable but cert
            # still exists, so registration is still skipped.
            logger.warning("Could not parse existing certificate for metadata")


# --- Helper functions ---


def _generate_ecdsa_p256_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private keypair.

    Returns:
        Private key instance.
    """
    return ec.generate_private_key(ec.SECP256R1())


def _create_csr(private_key: ec.EllipticCurvePrivateKey, executor_id: str) -> bytes:
    """Create a Certificate Signing Request for the given executor.

    Args:
        private_key: The ECDSA P-256 private key.
        executor_id: Unique executor identifier (used as CN).

    Returns:
        PEM-encoded CSR bytes.
    """
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _extract_common_name(cert: x509.Certificate) -> str | None:
    """Extract the CN from a certificate.

    Args:
        cert: The X.509 certificate.

    Returns:
        The CN value, or None if not found.
    """
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value.decode() if isinstance(value, bytes) else value


def _verify_ca_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """Verify that cert is signed by ca_cert's ECDSA public key.

    Args:
        cert: The certificate to verify.
        ca_cert: The CA certificate.

    Raises:
        CertificateValidationError: If the signature is invalid or key type unsupported.
    """
    from cryptography.exceptions import InvalidSignature

    ca_public_key = ca_cert.public_key()

    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        raise CertificateValidationError(f"Unsupported CA key type: {type(ca_public_key).__name__}")

    try:
        hash_algo = cert.signature_hash_algorithm
        if hash_algo is None:
            raise CertificateValidationError("Certificate has no signature hash algorithm")
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hash_algo),
        )
    except InvalidSignature:
        raise CertificateValidationError("Certificate not signed by trusted CA")


def validate_executor_certificate(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    expected_executor_id: str,
) -> None:
    """Validate an executor certificate against all security requirements.

    Checks are ordered by cost — cheapest first so most rejections
    short-circuit before expensive crypto operations.

    Args:
        cert_pem: PEM-encoded executor certificate.
        ca_cert_pem: PEM-encoded CA certificate.
        expected_executor_id: The expected executor ID (matches CN).

    Raises:
        CertificateValidationError: If any check fails.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    now = datetime.now(UTC)

    # 1. Validity period (cheapest — no extension parsing)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now + CLOCK_SKEW_TOLERANCE < not_before:
        raise CertificateValidationError("Certificate not yet valid")
    if now - CLOCK_SKEW_TOLERANCE > not_after:
        raise CertificateValidationError("Certificate expired")

    # 2. CN matches executor_id (string comparison)
    cn = _extract_common_name(cert)
    if cn != expected_executor_id:
        raise CertificateValidationError(f"CN mismatch: expected {expected_executor_id!r}, got {cn!r}")

    # 3. BasicConstraints CA=False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise CertificateValidationError("Certificate has CA=True (must be leaf cert)")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing BasicConstraints extension")

    # 4. KeyUsage includes digitalSignature
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.digital_signature:
            raise CertificateValidationError("KeyUsage missing digitalSignature")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing KeyUsage extension")

    # 5. ExtendedKeyUsage includes clientAuth
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if x509.ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            raise CertificateValidationError("EKU missing clientAuth")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Missing ExtendedKeyUsage extension")

    # 6. CA signature verification (most expensive — do last)
    _verify_ca_signature(cert, ca_cert)


def _extract_executor_id_from_cert(cert_path: str) -> str:
    """Extract the executor ID (CN) from an existing certificate.

    Args:
        cert_path: Path to the PEM-encoded certificate file.

    Returns:
        The CN value from the certificate subject.

    Raises:
        ValueError: If the CN is not found in the certificate.
    """
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    try:
        cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attributes:
            raise ValueError("Certificate has no CN (Common Name)")
        value = cn_attributes[0].value
        return value.decode() if isinstance(value, bytes) else value
    except Exception as e:
        raise ValueError(f"Failed to extract executor ID from certificate: {e}")


class ReaperLoop:
    """Background loop for cleaning up orphaned resources.

    Scans for orphaned secret files and stale tokens.
    """

    def __init__(
        self,
        config: ExecutorConfig,
        state: DaemonState,
        tmpfs_dir: str = "/tmp/venya_secrets",  # nosec B108 — tmpfs, not persistent disk
        http_client: Any | None = None,
        session_id: str | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.tmpfs_dir = tmpfs_dir
        self.http_client = http_client
        self.session_id = session_id
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the reaper loop in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="venya-reaper",
            daemon=True,
        )
        self._thread.start()
        logger.info("Reaper loop started (interval=%.1fs)", self.config.reaper.check_interval)

    def stop(self) -> None:
        """Stop the reaper loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10.0)
            logger.info("Reaper loop stopped")

    def _run(self) -> None:
        """Main reaper loop."""
        while not self._stop_event.is_set():
            try:
                self._check_orphaned()
            except Exception:
                logger.exception("Error in reaper loop")
            self._stop_event.wait(self.config.reaper.check_interval)

    def _check_orphaned(self) -> None:
        """Check for and clean up orphaned resources.

        Scans tmpfs_dir for secret files older than secret_ttl_seconds.
        Deletes orphaned files and revokes tokens via server API.
        """
        import time

        ttl_seconds = self.config.reaper.secret_ttl_seconds
        now = time.time()
        orphaned_files: list[str] = []
        orphaned_secret_ids: list[str] = []

        # Scan tmpfs_dir for venya secret files
        try:
            if not os.path.exists(self.tmpfs_dir):
                return

            for filename in os.listdir(self.tmpfs_dir):
                if not filename.startswith("venya_") or not filename.endswith(".secret"):
                    continue

                filepath = os.path.join(self.tmpfs_dir, filename)
                try:
                    file_stat = os.stat(filepath)
                    file_age = now - file_stat.st_mtime

                    if file_age > ttl_seconds:
                        orphaned_files.append(filepath)
                        # Extract secret_id from filename if possible
                        # Format: venya_<secret_id>_<random>.secret
                        # or just venya_<random>.secret
                        parts = filename.replace(".secret", "").split("_")
                        if len(parts) >= 2:
                            orphaned_secret_ids.append(parts[1])
                except OSError:
                    continue
        except OSError:
            logger.exception("Failed to scan tmpfs_dir for orphaned files")
            return

        if not orphaned_files:
            return

        # Delete orphaned files
        for filepath in orphaned_files:
            try:
                os.unlink(filepath)
                logger.info("Deleted orphaned secret file: %s", filepath)
            except OSError:
                logger.exception("Failed to delete orphaned file: %s", filepath)

        # Revoke tokens for orphaned secrets via server
        if orphaned_secret_ids and self.http_client and self.session_id:
            try:
                self.http_client.post(
                    f"/api/v1/sessions/{self.session_id}/secrets/revoke",
                    json={"secret_ids": orphaned_secret_ids},
                    timeout=self.config.network.request_timeout_seconds,
                )
                logger.info(
                    "Revoked tokens for %d orphaned secrets in session %s",
                    len(orphaned_secret_ids),
                    self.session_id,
                )
            except Exception:
                logger.exception("Failed to revoke orphaned secret tokens")


def build_command_policy(cv: Any) -> CommandPolicy:
    """Build a CommandPolicy from the executor config's command_validator section.

    Presets and their trusted_paths behavior:
      - balanced: DEFAULT_TRUSTED_PATHS (operator cannot override; no config field)
      - strict: empty (uses allowed_commands allowlist instead)
      - permissive: empty (no path check; dangerous patterns still apply)
    """
    trusted = frozenset(DEFAULT_TRUSTED_PATHS) if cv.preset == "balanced" else frozenset()
    return CommandPolicy(
        preset=cv.preset,
        allowed_commands=frozenset(cv.allowed_commands) if cv.allowed_commands else frozenset(),
        trusted_paths=trusted,
        dangerous_patterns=(
            frozenset(cv.dangerous_patterns) if cv.dangerous_patterns else frozenset(DEFAULT_DANGEROUS_PATTERNS)
        ),
        match_word_boundaries=cv.match_word_boundaries,
    )


class ExecutorDaemon:
    """Main executor daemon.

    Manages the full executor lifecycle including:
      - Server connection and authentication
      - Command reception and execution
      - Certificate management
      - Heartbeat and revocation polling
      - Reaper loop
    """

    def __init__(self, config: ExecutorConfig | None = None) -> None:
        if config is None:
            config = ExecutorConfig()

        self.config = config
        self._config_path = self.config.config_path or Path("/etc/venya/executor.toml")
        self.state = DaemonState()
        self.state.executor_id = config.executor_id

        # Command validator
        cv = self.config.command_validator

        self.command_validator = CommandValidator(
            policy=build_command_policy(cv),
        )

        # Certificate manager — client created after registration
        self.cert_manager = CertificateManager(config)

        # Reaper loop
        self.reaper = ReaperLoop(
            config,
            self.state,
            tmpfs_dir=config.secret_tmpfs_dir,
        )

        # Relay listener (B0) — wired to the existing execution engine. The
        # factory is the bound create_executor; it reads self.client at call
        # time, so it is safe to stash here before the client exists.
        self.relay = RelayListener(config, self.create_executor, config.relay_client_ids)

        # Signal handling
        self._shutdown_event = threading.Event()

        # HTTP thread pool — keeps network calls off the main loop
        self._http_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="http")

        # HTTP client — initialized in start() after registration
        self.client: httpx2.Client | None = None

    def _create_mtls_client(self) -> httpx2.Client:
        """Create HTTP client with mTLS after certificate registration."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_cert_chain(self.config.mtls.cert, self.config.mtls.key)
        ssl_ctx.load_verify_locations(self.config.mtls.ca_cert)
        return httpx2.Client(
            base_url=self.config.server_url,
            verify=ssl_ctx,
            timeout=self.config.network.request_timeout_seconds,
        )

    def _clear_enrollment_token(self) -> None:
        """Remove the consumed enrollment token from the config file.

        The token should only be on disk for the one-time registration.
        After registration, it's cleared to prevent exposure.
        """
        import tomllib

        config_path = self._config_path
        if not config_path.exists():
            return

        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            logger.warning("Could not read config file to clear enrollment token")
            return

        # Remove bootstrap section if it exists and contains enrollment_token
        if "bootstrap" in data and "enrollment_token" in data["bootstrap"]:
            del data["bootstrap"]["enrollment_token"]
            # Remove entire bootstrap section if it's now empty
            if not data["bootstrap"]:
                del data["bootstrap"]

            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, "w") as f:
                tomli_w.dump(data, f)
            logger.info("Cleared enrollment token from config")

    def create_executor(self, session_id: str) -> Executor:
        """Create an Executor instance with mTLS client.

        Args:
            session_id: The session ID for this executor instance.

        Returns:
            Configured Executor instance with HTTP client for server API calls.
        """
        strategy = SbxStrategy()
        audit_logger = AuditLogger(self.config.audit, session_id)
        return Executor(
            command_validator=self.command_validator,
            session_id=session_id,
            injection_strategy=strategy,
            audit_logger=audit_logger,
            http_client=self.client,
            config=self.config,
        )

    def start(self) -> None:
        """Start the executor daemon."""
        logger.info("Starting executor daemon: %s", self.config.executor_id)

        # /dev/shm survives daemon kills and reboots but sandboxes never do:
        # any ws_* directory present now is an orphan from a dead run. Sweep
        # once, at process start, before any execution can create new ones.
        swept = sweep_workspace_base()
        logger.info("Swept %d orphaned workspace dir(s) from previous run(s)", swept)

        # Register with server (creates cert/key if not present)
        # register() uses throwaway httpx2.Client instances internally —
        # never self.client. After registration, certs are on disk.
        enrollment_token = self.config.bootstrap.enrollment_token
        self.cert_manager.register(self.state.executor_id, enrollment_token=enrollment_token)

        # Clear enrollment token from config after successful registration
        if enrollment_token:
            self._clear_enrollment_token()

        # Create mTLS client — takes over for all subsequent communication
        self.client = self._create_mtls_client()
        self.cert_manager.client = self.client

        # Configure reaper with mTLS client and session info
        self.reaper.http_client = self.client
        self.reaper.session_id = self.state.session_id or "default"

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Start reaper loop
        self.reaper.start()

        # Start the mTLS relay listener (certs already on disk after registration)
        self.relay.start()

        # Mark as running
        self.state.running = True
        self.state.cert_serial = self.cert_manager.serial
        self.state.cert_not_after = self.cert_manager.not_after

        # Write PID file
        self._write_pidfile()

        # Main loop
        try:
            self._main_loop()
        finally:
            self.stop()

    def _main_loop(self) -> None:
        """Main daemon loop.

        Checks certificate rotation, revocation status, and sends heartbeats.
        Network calls run in a background thread pool to keep the main loop
        responsive to shutdown signals.
        """
        logger.info("Daemon main loop started")

        while self.state.running and not self.state.revoked:
            # Check certificate rotation (synchronous — rare operation)
            if self.cert_manager.needs_rotation():
                try:
                    self.cert_manager.rotate()
                    # Recreate client with new cert
                    self.client = self._create_mtls_client()
                    self.cert_manager.client = self.client
                    self.state.cert_serial = self.cert_manager.serial
                    self.state.cert_not_after = self.cert_manager.not_after
                    logger.info(
                        "Certificate rotated in main loop, new expiry: %s",
                        self.state.cert_not_after,
                    )
                except Exception:
                    logger.exception("Certificate rotation failed")

            # Check revocation status — run in thread pool
            revocation_future = self._http_executor.submit(self.cert_manager.check_revocation)
            try:
                if revocation_future.result(timeout=self.config.network.request_timeout_seconds):
                    logger.warning("Executor certificate revoked — shutting down")
                    self.state.revoked = True
                    break
                else:
                    self.state._consecutive_revocation_failures = 0
            except TimeoutError:
                logger.debug("Revocation check timed out")
                self.state._consecutive_revocation_failures += 1
            except httpx2.RequestError:
                logger.debug("Revocation check failed (server unreachable)")
                self.state._consecutive_revocation_failures += 1

            if self.state._consecutive_revocation_failures >= self.config.cert_rotation.max_revocation_failures:
                logger.warning(
                    "Consecutive revocation check failures (%d) reached threshold (%d) — "
                    "treating certificate as revoked",
                    self.state._consecutive_revocation_failures,
                    self.config.cert_rotation.max_revocation_failures,
                )
                self.state.revoked = True
                break

            # Heartbeat — fire and forget in thread pool
            self._http_executor.submit(self._send_heartbeat)

            # Wait before next iteration (interruptible by signals)
            self._shutdown_event.wait(30.0)

    def _send_heartbeat(self) -> None:
        """Send heartbeat to server.

        POST /api/v1/heartbeat with current cert fingerprint.
        """
        try:
            fingerprint = self.cert_manager.get_fingerprint()
            self.client.post(  # type: ignore[union-attr]
                "/api/v1/heartbeat",
                json={
                    "executor_id": self.state.executor_id,
                    "cert_fingerprint": fingerprint,
                },
                timeout=self.config.network.request_timeout_seconds,
            )
        except httpx2.RequestError:
            logger.debug("Heartbeat failed (server unreachable)")

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.info("Received signal %s — initiating shutdown", sig_name)
        self.state.running = False
        self._shutdown_event.set()

    def stop(self) -> None:
        """Stop the executor daemon."""
        logger.info("Stopping executor daemon")

        for cleanup in (
            self._stop_http_pool,
            self.reaper.stop,
            self.relay.stop,
            self._remove_pidfile,
            self._close_client,
        ):
            try:
                cleanup()
            except Exception:
                logger.exception("Cleanup step failed: %s", cleanup.__name__)

        logger.info("Executor daemon stopped")

    def _stop_http_pool(self) -> None:
        """Stop the HTTP thread pool."""
        self._http_executor.shutdown(wait=True)

    def _close_client(self) -> None:
        """Close the HTTP client if it exists."""
        if self.client is not None:
            self.client.close()

    def _write_pidfile(self) -> None:
        """Write PID file."""
        pid_file = self.config.pid_file
        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))

    def _remove_pidfile(self) -> None:
        """Remove PID file."""
        pid_file = self.config.pid_file
        try:
            os.unlink(pid_file)
        except FileNotFoundError:
            pass


def main() -> None:
    """Entry point for venya-executor CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="Venya Executor Daemon")
    parser.add_argument(
        "--config",
        type=str,
        default="/etc/venya/executor.toml",
        help="Path to config file",
    )
    parser.add_argument(
        "--daemonize",
        action="store_true",
        help="Run as daemon (fork to background)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Logging level",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        metavar="HOST:PORT",
        help="Allow egress to HOST:PORT (can be specified multiple times)",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Disable all network access (overrides --allow-host)",
    )

    args = parser.parse_args()

    # Load config
    try:
        config = ExecutorConfig.from_file(args.config)
    except FileNotFoundError:
        print(f"Config file not found: {args.config}", file=sys.stderr)
        print("Using defaults (may not work without server connection)", file=sys.stderr)
        config = ExecutorConfig()

    # Apply CLI overrides
    config.log_level = args.log_level
    if args.daemonize:
        config.daemonize = True

    # Setup logging
    from core.utils.sensitive_log import RedactingFormatter

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    # Create and start daemon
    daemon = ExecutorDaemon(config)

    if config.daemonize:
        # First fork — detach from parent
        pid = os.fork()
        if pid > 0:
            # Parent — exit
            print(f"Daemon started with PID {pid}")
            sys.exit(0)
        # Child — create new session
        os.setsid()
        os.umask(0)

        # Second fork — prevent reacquiring controlling terminal
        pid = os.fork()
        if pid > 0:
            os._exit(0)

        # Change to root directory
        os.chdir("/")

        # Redirect stdin/stdout/stderr to /dev/null
        devnull_fd = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull_fd, 0)
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)
        if devnull_fd > 2:
            os.close(devnull_fd)

    daemon.start()
