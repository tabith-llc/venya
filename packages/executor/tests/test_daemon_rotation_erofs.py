# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket executor-cert-rotation-erofs (ruling 2026-09-19: option (a) + ordering fix).

Deployed units set ReadOnlyPaths=/etc/venya without /etc/venya/executor in
ReadWritePaths, so CertManager.rotate() died EROFS on the disk write — AFTER
POSTing the CSR (server record already replaced) and AFTER updating the
in-memory serial. Consequences: lost keypair every 30s retry, memory/disk
serial divergence (revocation becomes restart-dependent), day-30 hard death.

Fix contract pinned here:
1. rotate() refuses BEFORE any network call when the cert dir is unwritable
   (server state never burned on a doomed attempt);
2. in-memory serial/expiry update only AFTER all disk writes succeed
   (memory can never claim an identity disk doesn't hold);
3. the deployed unit is writable at /etc/venya/executor — asserted on BOTH
   the repo template AND the installer's copy step (user ruling: assert the
   installer-generated unit too, not just the template).

Note (ticket, corrected per review): the ordering fix narrows but does NOT
close the structural revocation gap — a write failure between POST and disk
still leaves record(new serial)/disk(old serial) diverged. That gap is
tracked separately (revocation-by-identity ticket), not solved here.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestRotateErofsGuard:
    """rotate() must fail loudly BEFORE burning server state, and must never
    update in-memory identity ahead of durable disk state."""

    def _initial_identity(self, cert_manager, tmp_ca_dir):
        from tests.test_daemon import _make_ca_pair, _make_executor_cert, _make_mock_response

        ca_key, ca_cert = _make_ca_pair()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        initial_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        Path(cert_manager.cert_path).write_bytes(initial_cert.public_bytes(serialization.Encoding.PEM))
        Path(cert_manager.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        new_cert = _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30)
        mock_response = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)
        return new_cert, mock_response

    def test_unwritable_dir_refuses_before_post(self, cert_manager, tmp_ca_dir):
        """RED pre-fix: the old order POSTed first and died on the write."""
        _new_cert, mock_response = self._initial_identity(cert_manager, tmp_ca_dir)
        cert_dir = Path(cert_manager.cert_path).parent
        old_mode = cert_dir.stat().st_mode
        cert_dir.chmod(0o500)  # r-x: os.access(W_OK) False for non-root
        try:
            with patch.object(cert_manager.client, "post", return_value=mock_response) as mock_post:
                with pytest.raises(RuntimeError, match="not writable"):
                    cert_manager.rotate()
                mock_post.assert_not_called()  # server state never burned
        finally:
            cert_dir.chmod(old_mode)

    def test_write_failure_leaves_serial_untouched(self, cert_manager, tmp_ca_dir):
        """POST succeeded but persist failed -> memory must NOT adopt the new
        serial (pre-fix: serial was updated before the write, diverging from disk)."""
        _new_cert, mock_response = self._initial_identity(cert_manager, tmp_ca_dir)
        cert_manager.serial = "old-serial-000000"
        Path(cert_manager.cert_path).chmod(0o400)  # dir writable, file not -> precheck passes, write fails
        try:
            with patch.object(cert_manager.client, "post", return_value=mock_response):
                with pytest.raises(PermissionError):
                    cert_manager.rotate()
            assert cert_manager.serial == "old-serial-000000"
        finally:
            Path(cert_manager.cert_path).chmod(0o600)


class TestUnitFileInterlock:
    """The deployed unit must grant write access to the identity dir."""

    def test_repo_unit_has_rw_identity_dir(self):
        unit = (REPO_ROOT / "systemd" / "venya-executor.service").read_text()
        rw_lines = [ln for ln in unit.splitlines() if ln.startswith("ReadWritePaths=")]
        assert rw_lines, "unit lost its ReadWritePaths directive"
        assert "/etc/venya/executor" in " ".join(rw_lines)
        # pairing: the RO parent hardening must stay (RW subpath under RO parent
        # is the intended systemd mechanism, not a reason to drop the parent)
        assert any(ln.strip() == "ReadOnlyPaths=/etc/venya" for ln in unit.splitlines())

    def test_installer_deploys_the_repo_unit(self):
        """Assert the installer-generated unit == repo template (it copies it)."""
        installer = (REPO_ROOT / "install-venya-executor.sh").read_text()
        assert 'cp "$INSTALL_DIR/systemd/venya-executor.service" "$SYSTEMD_DIR/"' in installer
