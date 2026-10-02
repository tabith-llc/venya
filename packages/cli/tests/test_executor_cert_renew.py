# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for executor_cert_renew CLI command.

Tests cover:
- Success case (new key, CSR, mTLS auth, atomic file save)
- Not registered (missing cert)
- Missing key file
- mTLS authentication failure (401/403)
- Server rejects CSR (400)
- Network error (connection refused)
- Invalid cert file
- Atomic write failure preserves original files
"""

import json
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _generate_test_keypair():
    """Generate an ECDSA P-256 keypair for testing."""
    return ec.generate_private_key(ec.SECP256R1())


def _generate_test_cert(private_key, executor_id="venya-exec", validity_days=30):
    """Generate a self-signed certificate for testing."""
    now = datetime.now(UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(private_key, hashes.SHA256())
    )
    return cert


def _setup_cert_files(tmp_path, executor_id="test-exec", validity_days=30):
    """Generate and write cert+key files, return (cert_path, key_path, private_key)."""
    private_key = _generate_test_keypair()
    cert = _generate_test_cert(private_key, executor_id, validity_days)

    cert_path = tmp_path / "executor.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    key_path = tmp_path / "executor.key"
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    return cert_path, key_path, private_key


def _make_renew_response():
    """Create a mock server response for certificate renewal."""
    now = datetime.now(UTC)
    return {
        "executor_id": "test-exec",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL..." + "X" * 100 + "\n-----END CERTIFICATE-----\n",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL..." + "Y" * 100 + "\n-----END CERTIFICATE-----\n",
        "serial_number": "AB:CD:EF:12:34:56",
        "not_after": (now + timedelta(days=365)).isoformat(),
    }


def _make_mock_httpx_response(status_code=200, json_data=None):
    """Create a mock httpx2 response."""
    import httpx2

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.content = json.dumps(json_data).encode() if json_data else b""
    mock_resp.json.return_value = json_data or {}
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=mock_resp,
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


def _make_mock_httpx_client(post_response=None, post_error=None, get_response=None, get_error=None):
    """Create a mock httpx2.Client for mTLS calls."""

    mock_post_resp = post_response or _make_mock_httpx_response(status_code=200, json_data=_make_renew_response())
    if post_error:
        mock_post_resp.raise_for_status.side_effect = post_error

    mock_get_resp = get_response or _make_mock_httpx_response(status_code=200, json_data={"revoked_serials": []})
    if get_error:
        mock_get_resp.raise_for_status.side_effect = get_error

    mock_client = MagicMock()
    mock_client.post = MagicMock(return_value=mock_post_resp)
    mock_client.get = MagicMock(return_value=mock_get_resp)
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# Success cases
# ---------------------------------------------------------------------------


class TestRenewSuccess:
    """Tests for successful certificate renewal."""

    def test_renew_success(self, tmp_path, capsys):
        """Renewal succeeds: new key+CSR, mTLS auth, files saved, correct output."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"

        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Certificate renewed successfully" in captured.out
        assert "test-exec" in captured.out
        assert str(cert_path) in captured.out
        assert str(key_path) in captured.out

        # Verify new key was written (different from original)
        new_key_data = key_path.read_bytes()
        assert new_key_data != b""
        assert b"PRIVATE KEY" in new_key_data

        # Verify new cert was written
        new_cert_data = cert_path.read_bytes()
        assert b"CERTIFICATE" in new_cert_data

        # Verify CA cert was saved
        ca_cert_path = tmp_path / "ca.crt"
        assert ca_cert_path.exists()

    def test_renew_env_server_url_honored(self, tmp_path, capsys):
        """Per-command env cell (ticket cli-core-url-server-url-naming-split):
        renew POSTs to the VENYA_SERVER_URL-resolved server when no
        --core-url/--server-url flag is given (was: env silently skipped,
        'unknown' gate or config-only chain)."""
        cert_path, _key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = None

        mock_client = _make_mock_httpx_client()

        with (
            patch.dict(os.environ, {"VENYA_SERVER_URL": "https://env-core.example.com"}),
            patch("venya_cli.commands.httpx2.Client", return_value=mock_client),
        ):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 0
        assert mock_client.post.call_args[0][0] == "https://env-core.example.com/api/v1/executors/register"

    def test_renew_success_with_custom_paths(self, tmp_path, capsys):
        """Renewal respects custom --cert-path and --key-path for output."""
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_cert = custom_dir / "my-cert.pem"
        custom_key = custom_dir / "my-key.key"

        # Create original cert at custom path
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "custom-exec", 30)
        custom_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        custom_key.write_bytes(key_pem)
        custom_key.chmod(0o600)

        args = MagicMock()
        args.cert_path = str(custom_cert)
        args.key_path = str(custom_key)
        args.core_url = "https://venya-core"

        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 0

        # Verify files were written to custom paths
        assert custom_cert.exists()
        assert custom_key.exists()
        assert custom_key.stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestRenewErrors:
    """Tests for certificate renewal error handling."""

    def test_renew_not_registered(self, tmp_path, capsys):
        """Missing cert file returns exit code 1."""
        nonexistent = tmp_path / "nonexistent.pem"

        args = MagicMock()
        args.cert_path = str(nonexistent)
        args.key_path = None

        from venya_cli.commands import executor_cert_renew

        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "certificate not found" in captured.err

    def test_renew_unknown_url_message_names_alias_and_env(self, tmp_path, capsys):
        """Ruling fold-in: the unknown-gate guidance names --server-url
        (alias --core-url) AND VENYA_SERVER_URL — same terminology as the
        register error (ticket cli-core-url-server-url-naming-split)."""
        cert_path, _key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = None
        args.config_path = "/nonexistent/executor.toml"

        with patch("venya_cli.api_client.Config") as MockConfig:
            mock_config = MagicMock()
            mock_config.server_url = "http://localhost:8000"
            MockConfig.return_value = mock_config

            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 1
        err = capsys.readouterr().err
        assert "server URL not configured" in err
        assert "--server-url" in err
        assert "--core-url" in err
        assert "VENYA_SERVER_URL" in err

    def test_renew_missing_key(self, tmp_path, capsys):
        """Cert exists but key missing returns exit code 1."""
        private_key = _generate_test_keypair()
        cert = _generate_test_cert(private_key, "test-exec", 30)

        cert_path = tmp_path / "executor.crt"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        # Intentionally do NOT create the key file

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(cert_path.with_suffix(".key"))
        args.core_url = "https://venya-core"

        from venya_cli.commands import executor_cert_renew

        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "private key not found" in captured.err

    def test_renew_mtls_failure_401(self, tmp_path, capsys):
        """Server returns 401 — mTLS auth failed."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        mock_resp = _make_mock_httpx_response(status_code=401, json_data={"detail": "Invalid certificate"})
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "mTLS authentication failed" in captured.err

    def test_renew_mtls_failure_403(self, tmp_path, capsys):
        """Server returns 403 — mTLS forbidden."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        mock_resp = _make_mock_httpx_response(status_code=403, json_data={"detail": "Certificate revoked"})
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "mTLS authentication failed" in captured.err

    def test_renew_csr_rejected(self, tmp_path, capsys):
        """Server returns 400 — CSR rejected."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        mock_resp = _make_mock_httpx_response(
            status_code=400,
            json_data={"detail": "Weak key — ECDSA P-256 required"},
        )
        mock_client = _make_mock_httpx_client(
            post_response=mock_resp,
        )

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Renewal failed" in captured.err

    def test_renew_network_error(self, tmp_path, capsys):
        """Connection failure returns exit code 1."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        import httpx2

        mock_client = _make_mock_httpx_client(
            post_error=httpx2.ConnectError("Connection refused"),
        )

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Connection failed" in captured.err

    def test_renew_invalid_cert(self, tmp_path, capsys):
        """Corrupt cert file returns exit code 1."""
        cert_path = tmp_path / "executor.crt"
        cert_path.write_text("this is not a valid certificate")
        key_path = tmp_path / "executor.key"
        key_path.write_text("not a key either")

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)

        from venya_cli.commands import executor_cert_renew

        result = executor_cert_renew(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "certificate not found" in captured.err or "Error:" in captured.err


# ---------------------------------------------------------------------------
# Atomic write tests
# ---------------------------------------------------------------------------


class TestRenewAtomicWrite:
    """Tests for atomic cert/key replacement."""

    def test_atomic_write_failure_preserves_original(self, tmp_path, capsys):
        """If write fails, original cert/key remain intact."""
        cert_path, key_path, _original_key = _setup_cert_files(tmp_path)
        original_cert_data = cert_path.read_bytes()
        original_key_data = key_path.read_bytes()

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        # Mock the server response as successful
        mock_client = _make_mock_httpx_client()

        # Patch os.replace to fail on the key publish (atomic-create-0600
        # house pattern: the key is staged in a random-named temp, then
        # os.replace'd — injecting there simulates "write fails after the
        # cert temp file is written").
        original_replace = os.replace

        def failing_replace(src, dst, *a, **kw):
            if str(dst) == str(key_path):
                raise OSError("Disk full")
            return original_replace(src, dst, *a, **kw)

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            with patch("venya_cli.commands.os.replace", side_effect=failing_replace):
                from venya_cli.commands import executor_cert_renew

                result = executor_cert_renew(args)

        assert result == 1

        # Original files must be preserved
        assert cert_path.read_bytes() == original_cert_data
        assert key_path.read_bytes() == original_key_data

        # Temp files should be cleaned up (cert tmp + staged key temp)
        assert not cert_path.with_suffix(".pem.tmp").exists()
        assert not list(key_path.parent.glob(".venya-key-*"))

    def test_atomic_rename_order_key_before_cert(self, tmp_path):
        """Key is renamed before cert — key_tmp should not persist on success."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)

        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"

        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            result = executor_cert_renew(args)

        assert result == 0

        # No temp files should remain
        assert not cert_path.with_suffix(".pem.tmp").exists()
        assert not key_path.with_suffix(".key.tmp").exists()

        # Files should be valid
        cert_data = cert_path.read_bytes()
        assert b"CERTIFICATE" in cert_data

        key_data = key_path.read_bytes()
        assert b"PRIVATE KEY" in key_data


class TestRenewSecretFileModes:
    """#317: the renewed key lands 0600 at creation via the atomic-create
    house pattern (random-named temp, no post-write chmod)."""

    @staticmethod
    def _renew(cert_path, key_path):
        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = str(key_path)
        args.core_url = "https://venya-core"
        mock_client = _make_mock_httpx_client()
        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            from venya_cli.commands import executor_cert_renew

            return executor_cert_renew(args)

    def test_key_created_0600_under_umask022(self, tmp_path):
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        old = os.umask(0o022)
        try:
            assert self._renew(cert_path, key_path) == 0
        finally:
            os.umask(old)
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert serialization.load_pem_private_key(key_path.read_bytes(), password=None) is not None
        assert not list(tmp_path.glob(".venya-key-*"))
        assert not key_path.with_suffix(".key.tmp").exists()

    def test_preexisting_key_target_replaced_not_merged(self, tmp_path):
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        original_key_data = key_path.read_bytes()
        key_path.chmod(0o644)  # pre-existing target in the loose mode
        old = os.umask(0o022)
        try:
            assert self._renew(cert_path, key_path) == 0
        finally:
            os.umask(old)
        data = key_path.read_bytes()
        assert data != original_key_data  # whole new key, not merged/extended
        assert serialization.load_pem_private_key(data, password=None) is not None
        # temp's 0600 wins over the target's old 0644 — os.replace semantics
        assert key_path.stat().st_mode & 0o777 == 0o600

    def test_planted_legacy_key_tmp_collision_fails_safe(self, tmp_path):
        """Old mechanism used the deterministic name <key>.key.tmp — the new
        random-named temp must neither write nor follow a planted file there."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        planted = key_path.with_suffix(".key.tmp")
        planted.write_bytes(b"ATTACKER-PLANTED")
        old = os.umask(0o022)
        try:
            assert self._renew(cert_path, key_path) == 0
        finally:
            os.umask(old)
        assert planted.read_bytes() == b"ATTACKER-PLANTED"  # untouched
        assert serialization.load_pem_private_key(key_path.read_bytes(), password=None) is not None


class TestRenewTempHygiene352:
    """#352 ruling: cert/CA staging uses random-name temp files + os.replace
    (the #317 pattern, second application). The predictable '<cert>.pem.tmp'
    name + rename let a symlink planted in a co-writable dir hijack the
    rename target."""

    def _renew_args(self, cert_path):
        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"
        return args

    def test_symlink_at_predictable_tmp_name_is_not_followed(self, tmp_path):
        cert_path, _key_path, _ = _setup_cert_files(tmp_path)
        victim = tmp_path / "pwn-target"
        victim.write_text("original")
        planted = cert_path.with_suffix(".pem.tmp")  # the old predictable name
        planted.symlink_to(victim)

        with patch("venya_cli.commands.httpx2.Client", return_value=_make_mock_httpx_client()):
            from venya_cli.commands import executor_cert_renew

            rc = executor_cert_renew(self._renew_args(cert_path))

        assert rc == 0  # paired positive: the renewal itself lands
        assert victim.read_text() == "original"  # the planted symlink is never used
        assert b"CERTIFICATE" in cert_path.read_bytes()  # real file, not the symlink

    def test_staging_sources_are_random_names_across_runs(self, tmp_path):
        # NOTE: the mock renew response carries a NOT-parsable PEM blob (harness
        # fixture), so each run gets its own fresh cert dir — the pre-check
        # re-parses the on-disk cert at entry.
        srcs: list[str] = []
        real_replace = os.replace

        def spy_replace(src, dst):
            srcs.append(str(src))
            return real_replace(src, dst)

        for run in range(2):
            run_dir = tmp_path / f"run{run}"
            run_dir.mkdir()
            cert_path, _key_path, _ = _setup_cert_files(run_dir)
            with (
                patch("venya_cli.commands.httpx2.Client", return_value=_make_mock_httpx_client()),
                patch("venya_cli.commands.os.replace", side_effect=spy_replace),
            ):
                from venya_cli.commands import executor_cert_renew

                assert executor_cert_renew(self._renew_args(cert_path)) == 0

        cert_srcs = [s for s in srcs if "cert" in os.path.basename(s)]
        assert len(cert_srcs) == 2  # cert staging went through os.replace both runs
        assert cert_srcs[0] != cert_srcs[1]  # names unpredictable (random suffix)
        assert all(not s.endswith(".pem.tmp") for s in srcs)
        leftovers = [p for d in tmp_path.iterdir() for p in d.iterdir() if p.name.startswith(".venya-cert-")]
        assert leftovers == []

    def test_failure_path_leaves_no_temp_files(self, tmp_path):
        cert_path, _key_path, _ = _setup_cert_files(tmp_path)
        with (
            patch("venya_cli.commands.httpx2.Client", return_value=_make_mock_httpx_client()),
            patch("venya_cli.commands.os.replace", side_effect=OSError("disk full")),
        ):
            from venya_cli.commands import executor_cert_renew

            rc = executor_cert_renew(self._renew_args(cert_path))

        assert rc == 1
        leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith((".venya-cert-", ".venya-key-"))]
        assert leftovers == []


class TestRenewHardening373:
    """#373 paired: a root-context renew hands the credential dir and every
    staged temp to the venya service account before os.replace publishes them;
    a user-context renew attempts no chown at all (paired control)."""

    @staticmethod
    def _renew_args(tmp_path):
        cert_path, _key_path, _ = _setup_cert_files(tmp_path)
        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"
        return cert_path, args

    def test_root_renew_hands_dir_and_temps_to_service_account(self, tmp_path):
        from types import SimpleNamespace

        cert_path, args = self._renew_args(tmp_path)
        chown_calls: list = []
        fchown_calls: list = []

        def spy_chown(path, uid, gid):
            chown_calls.append((str(path), uid, gid))

        def spy_fchown(fd, uid, gid):
            fchown_calls.append((uid, gid))

        mock_client = _make_mock_httpx_client()
        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client), patch(
            "venya_cli.commands.os.geteuid", return_value=0
        ), patch("venya_cli.commands.os.chown", side_effect=spy_chown), patch(
            "venya_cli.commands.os.fchown", side_effect=spy_fchown
        ), patch(
            "pwd.getpwnam", return_value=SimpleNamespace(pw_uid=4444)
        ), patch(
            "grp.getgrnam", return_value=SimpleNamespace(gr_gid=5555)
        ):
            from venya_cli.commands import executor_cert_renew

            assert executor_cert_renew(args) == 0

        assert (str(cert_path.parent), 4444, 5555) in chown_calls
        # cert, key and ca temps each handed over BEFORE os.replace (#317 window)
        assert fchown_calls == [(4444, 5555)] * 3

    def test_user_renew_leaves_ownership_unchanged(self, tmp_path):
        cert_path, args = self._renew_args(tmp_path)
        chown_calls: list = []
        fchown_calls: list = []

        def spy_chown(path, uid, gid):
            chown_calls.append((str(path), uid, gid))

        def spy_fchown(fd, uid, gid):
            fchown_calls.append((uid, gid))

        mock_client = _make_mock_httpx_client()
        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client), patch(
            "venya_cli.commands.os.geteuid", return_value=1000
        ), patch("venya_cli.commands.os.chown", side_effect=spy_chown), patch(
            "venya_cli.commands.os.fchown", side_effect=spy_fchown
        ):
            from venya_cli.commands import executor_cert_renew

            assert executor_cert_renew(args) == 0

        assert chown_calls == []
        assert fchown_calls == []
        assert cert_path.exists()  # renew completed as before; only ownership is untouched
