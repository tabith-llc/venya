"""Executor daemon process management.

Manages the persistent executor daemon lifecycle:
  - Registration with server (mTLS certificate)
  - Certificate rotation
  - Heartbeat protocol
  - Revocation polling
  - Reaper loop for orphaned resources
  - Signal handling
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .audit import AuditLogger
from .command_validator import CommandValidator
from .config import ExecutorConfig
from .executor import Executor
from .strategies.factory import create_strategy

logger = logging.getLogger("venya.executor.daemon")


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


class CertificateManager:
    """Manages executor mTLS certificate lifecycle.

    Handles registration, rotation, revocation checking, and fingerprint
    computation. Uses ECDSA P-256 for all keypairs and certificates.
    """

    def __init__(self, config: ExecutorConfig, client: httpx.Client) -> None:
        self.config = config
        self.client = client
        self.cert_path = config.mtls.cert
        self.key_path = config.mtls.key
        self.ca_cert_path = config.mtls.ca_cert
        self.serial: str | None = None
        self._not_after: datetime | None = None

    def register(self, executor_id: str) -> None:
        """Register executor with server, obtain signed certificate.

        Generates an ECDSA P-256 keypair, creates a CSR, submits it to the
        server's ``/executors/register`` endpoint, validates the returned
        certificate against the CA, and persists both cert and key to disk.

        If a certificate already exists on disk, registration is skipped.

        Args:
            executor_id: Unique executor identifier.

        Raises:
            RuntimeError: If the server returns an error or the certificate
                fails CA validation.
            httpx.HTTPError: If the network request fails.
        """
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            logger.info("Certificate already exists — skipping registration for: %s", executor_id)
            self._load_metadata()
            return

        logger.info("Registering executor: %s", executor_id)

        # Generate ECDSA P-256 keypair
        private_key = _generate_ecdsa_p256_keypair()

        # Create CSR with executor_id as CN
        csr_pem = _create_csr(private_key, executor_id)

        # Register with server
        response = self.client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": executor_id,
                "csr_pem": csr_pem.decode(),
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()
        self.serial = data["serial_number"]
        self._not_after = datetime.fromisoformat(data["not_after"]).replace(tzinfo=UTC)

        # Validate CA signature before saving
        _validate_ca_signature(cert_pem, ca_cert_pem)

        # Save CA certificate
        Path(self.ca_cert_path).write_bytes(ca_cert_pem)
        logger.info("Saved CA certificate to %s", self.ca_cert_path)

        # Save signed certificate and private key
        Path(self.cert_path).write_bytes(cert_pem)
        os.chmod(self.cert_path, 0o644)

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        Path(self.key_path).write_bytes(key_pem)
        os.chmod(self.key_path, 0o600)

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
            httpx.HTTPError: If the network request fails.
        """
        logger.info("Rotating executor certificate")

        if not os.path.exists(self.cert_path):
            raise RuntimeError("Cannot rotate: no existing certificate (must register first)")

        # Generate new keypair and CSR
        private_key = _generate_ecdsa_p256_keypair()
        executor_id = _extract_executor_id_from_cert(self.cert_path)
        csr_pem = _create_csr(private_key, executor_id)

        # Re-register with server (same endpoint, replaces old cert)
        response = self.client.post(
            "/api/v1/executors/register",
            json={
                "executor_id": executor_id,
                "csr_pem": csr_pem.decode(),
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()

        cert_pem = data["cert_pem"].encode()
        ca_cert_pem = data["ca_cert_pem"].encode()
        self.serial = data["serial_number"]
        self._not_after = datetime.fromisoformat(data["not_after"]).replace(tzinfo=UTC)

        # Validate CA signature
        _validate_ca_signature(cert_pem, ca_cert_pem)

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
        current serial number appears in the list.

        Returns:
            True if the certificate is revoked. False if not revoked or if
            the server is unreachable (graceful degradation — the daemon
            will retry on the next loop iteration).
        """
        if self.serial is None:
            return False

        try:
            response = self.client.get(
                "/api/v1/executors/certs/revocation-list",
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()
            revoked_serials = set(data.get("revoked_serials", []))
            is_revoked = self.serial in revoked_serials

            if is_revoked:
                logger.warning("Executor certificate REVOKED (serial=%s)", self.serial)
            else:
                logger.debug("Certificate not revoked (serial=%s)", self.serial)

            return is_revoked
        except httpx.RequestError:
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
        except Exception:  # noqa: BLE001
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
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _validate_ca_signature(cert_pem: bytes, ca_cert_pem: bytes) -> None:
    """Validate that a certificate was signed by the given CA.

    Args:
        cert_pem: PEM-encoded certificate to validate.
        ca_cert_pem: PEM-encoded CA certificate.

    Raises:
        RuntimeError: If the certificate was not signed by the CA.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    try:
        ca_public_key = ca_cert.public_key()
        # CA uses ECDSA P-256 (enforced by server CAManager)
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey

        if not isinstance(ca_public_key, EllipticCurvePublicKey):
            raise TypeError(
                f"CA public key is {type(ca_public_key).__name__}, expected ECDSA"
            )
        hash_algo = cert.signature_hash_algorithm
        if hash_algo is None:
            raise RuntimeError("Certificate has no signature hash algorithm")
        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(hash_algo))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"Certificate CA validation failed: {e}")


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
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Failed to extract executor ID from certificate: {e}")


class ReaperLoop:
    """Background loop for cleaning up orphaned resources.

    Scans for orphaned secret files and stale tokens.
    """

    def __init__(
        self,
        config: ExecutorConfig,
        state: DaemonState,
        tmpfs_dir: str = "/tmp/venya-secrets",
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
                    timeout=10.0,
                )
                logger.info(
                    "Revoked tokens for %d orphaned secrets in session %s",
                    len(orphaned_secret_ids),
                    self.session_id,
                )
            except Exception:
                logger.exception("Failed to revoke orphaned secret tokens")


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
        self.state = DaemonState()
        self.state.executor_id = config.executor_id

        # Command validator
        self.command_validator = CommandValidator()

        # Certificate manager (client created after registration)
        self.cert_manager = CertificateManager(config, self._create_initial_client())

        # Reaper loop
        self.reaper = ReaperLoop(
            config,
            self.state,
            tmpfs_dir="/tmp/venya-secrets",
        )

        # Signal handling
        self._shutdown_event = threading.Event()

    def _create_initial_client(self) -> httpx.Client:
        """Create HTTP client for initial registration.

        Used before certificate registration when we don't yet have the
        CA cert. After registration, the client is recreated with mTLS.
        """
        return httpx.Client(
            base_url=self.config.server_url,
            verify=False,  # No CA cert yet — registration only
            timeout=30.0,
        )

    def _create_mtls_client(self) -> httpx.Client:
        """Create HTTP client with mTLS after certificate registration."""
        return httpx.Client(
            base_url=self.config.server_url,
            cert=(self.config.mtls.cert, self.config.mtls.key),
            verify=self.config.mtls.ca_cert,
            timeout=30.0,
        )

    def create_executor(self, session_id: str) -> Executor:
        """Create an Executor instance with mTLS client.

        Args:
            session_id: The session ID for this executor instance.

        Returns:
            Configured Executor instance with HTTP client for server API calls.
        """
        strategy = create_strategy(self.config.injection_method, self.config.secret_base_fd)
        audit_logger = AuditLogger(self.config.audit, session_id)
        return Executor(
            command_validator=self.command_validator,
            session_id=session_id,
            injection_strategy=strategy,
            audit_logger=audit_logger,
            http_client=self.client,
        )

    def start(self) -> None:
        """Start the executor daemon."""
        logger.info("Starting executor daemon: %s", self.config.executor_id)

        # Register with server (creates cert/key if not present)
        self.cert_manager.register(self.state.executor_id)

        # Recreate HTTP client with mTLS now that we have a certificate
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

        # Mark as running
        self.state.running = True
        self.state.cert_serial = self.cert_manager.serial
        self.state.cert_not_after = self.cert_manager._not_after

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
        """
        logger.info("Daemon main loop started")

        while self.state.running and not self.state.revoked:
            # Check certificate rotation
            if self.cert_manager.needs_rotation():
                try:
                    self.cert_manager.rotate()
                    # Recreate client with new cert
                    self.client = self._create_mtls_client()
                    self.cert_manager.client = self.client
                    self.state.cert_serial = self.cert_manager.serial
                    self.state.cert_not_after = self.cert_manager._not_after
                    logger.info(
                        "Certificate rotated in main loop, new expiry: %s",
                        self.state.cert_not_after,
                    )
                except Exception:
                    logger.exception("Certificate rotation failed")

            # Check revocation status
            if self.cert_manager.check_revocation():
                logger.warning("Executor certificate revoked — shutting down")
                self.state.revoked = True
                break

            # Heartbeat
            self._send_heartbeat()

            # Wait before next iteration
            self._shutdown_event.wait(30.0)

    def _send_heartbeat(self) -> None:
        """Send heartbeat to server.

        POST /api/v1/heartbeat with current cert fingerprint.
        """
        try:
            fingerprint = self.cert_manager.get_fingerprint()
            self.client.post(
                "/api/v1/heartbeat",
                json={
                    "executor_id": self.state.executor_id,
                    "cert_fingerprint": fingerprint,
                },
                timeout=10.0,
            )
        except httpx.RequestError:
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

        # Stop reaper
        self.reaper.stop()

        # Clean up PID file
        self._remove_pidfile()

        # Close HTTP client
        self.client.close()

        logger.info("Executor daemon stopped")

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
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Create and start daemon
    daemon = ExecutorDaemon(config)

    if config.daemonize:
        # Fork to background
        pid = os.fork()
        if pid > 0:
            # Parent — exit
            print(f"Daemon started with PID {pid}")
            sys.exit(0)
        # Child — continue as daemon
        os.setsid()

    daemon.start()
