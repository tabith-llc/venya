# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for disk encryption check utility."""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.utils.disk_encryption import (
    _find_mount_point,
    _get_fstype_via_lsblk,
    _get_pg_data_directory,
    _has_crypt_target,
    check_disk_encryption,
)


class TestGetPgDataDirectory:
    """Tests for PG data directory inference."""

    def test_returns_none_for_no_url(self):
        """Returns None when db_url is None."""
        assert _get_pg_data_directory(None) is None

    def test_returns_none_for_remote_host(self):
        """Returns None for remote hosts (can't determine local dir)."""
        result = _get_pg_data_directory("postgresql://user@10.0.0.5:5432/venya")
        assert result is None

    def test_returns_none_for_localhost_no_existing_path(self):
        """Returns last fallback path even if it doesn't exist (fresh install)."""
        # Patch all candidates to not exist
        with patch("server.utils.disk_encryption.Path") as mock_path_cls:
            mock = MagicMock()
            mock.exists.return_value = False
            mock_path_cls.side_effect = lambda p: mock
            result = _get_pg_data_directory("postgresql://user@localhost/venya")
            # Returns the last fallback (/var/lib/postgresql)
            assert result == mock


class TestFindMountPoint:
    """Tests for mount point detection."""

    def test_returns_root_for_deep_path(self):
        """Walks up to root when no findmnt available."""
        with patch("server.utils.disk_encryption.subprocess.run", side_effect=FileNotFoundError):
            result = _find_mount_point("/var/lib/postgresql/16/main/data")
            assert result == "/"


class TestGetFstypeViaLsblk:
    """Tests for lsblk FSTYPE detection."""

    def test_returns_crypto_luks(self):
        """Returns crypto_LUKS when lsblk shows it."""
        lsblk_output = "sda   crypto_LUKS  /var/lib/postgresql\nsdb   ext4         /"
        mock_result = MagicMock(returncode=0, stdout=lsblk_output, stderr="")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            result = _get_fstype_via_lsblk("/var/lib/postgresql")
            assert result == "crypto_LUKS"

    def test_returns_none_when_not_found(self):
        """Returns None when lsblk doesn't match mount point."""
        lsblk_output = "sda   ext4         /var/lib/postgresql\nsdb   xfs          /"
        mock_result = MagicMock(returncode=0, stdout=lsblk_output, stderr="")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            result = _get_fstype_via_lsblk("/var/lib/other")
            assert result is None

    def test_returns_none_on_lsblk_failure(self):
        """Returns None when lsblk fails."""
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            result = _get_fstype_via_lsblk("/var/lib/postgresql")
            assert result is None

    def test_returns_none_when_lsblk_not_installed(self):
        """Returns None when lsblk command not found."""
        with patch("server.utils.disk_encryption.subprocess.run", side_effect=FileNotFoundError):
            result = _get_fstype_via_lsblk("/var/lib/postgresql")
            assert result is None


class TestHasCryptTarget:
    """Tests for dmsetup crypt target detection."""

    def test_returns_true_for_crypt_target(self):
        """Returns True when dmsetup shows a crypt target."""
        dmsetup_output = "sda1_crypt: 0 10485760 crypt aes-xts-plain64 ..."
        mock_result = MagicMock(returncode=0, stdout=dmsetup_output, stderr="")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            assert _has_crypt_target("/var/lib/postgresql") is True

    def test_returns_false_without_crypt(self):
        """Returns False when no crypt target found."""
        dmsetup_output = "sda1: 0 10485760 linear /dev/sda1 4096"
        mock_result = MagicMock(returncode=0, stdout=dmsetup_output, stderr="")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            assert _has_crypt_target("/var/lib/postgresql") is False

    def test_returns_false_on_dmsetup_failure(self):
        """Returns False when dmsetup fails."""
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")

        with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
            assert _has_crypt_target("/var/lib/postgresql") is False

    def test_returns_false_when_dmsetup_not_installed(self):
        """Returns False when dmsetup command not found."""
        with patch("server.utils.disk_encryption.subprocess.run", side_effect=FileNotFoundError):
            assert _has_crypt_target("/var/lib/postgresql") is False


class TestCheckDiskEncryption:
    """Integration tests for check_disk_encryption()."""

    def test_logs_info_when_luks_detected(self, caplog):
        """Logs INFO when LUKS encryption is detected."""
        caplog.set_level(logging.INFO)
        lsblk_output = "sda   crypto_LUKS  /var/lib/postgresql\nsdb   ext4         /"
        mock_result = MagicMock(returncode=0, stdout=lsblk_output, stderr="")

        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
                    check_disk_encryption("postgresql://user@localhost/venya")

        assert any("Disk encryption verified" in record.message for record in caplog.records)

    def test_logs_warning_when_no_encryption(self, caplog):
        """Logs WARNING when no encryption detected."""
        lsblk_output = "sda   ext4         /var/lib/postgresql\nsdb   ext4         /"
        mock_result = MagicMock(returncode=0, stdout=lsblk_output, stderr="")

        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
                    check_disk_encryption("postgresql://user@localhost/venya")

        assert any("No disk encryption detected" in record.message for record in caplog.records)

    def test_logs_info_when_dmsetup_crypt_detected(self, caplog):
        """Logs INFO when dmsetup shows crypt target."""
        caplog.set_level(logging.INFO)
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value=None):
                    with patch("server.utils.disk_encryption._has_crypt_target", return_value=True):
                        check_disk_encryption("postgresql://user@localhost/venya")

        assert any("Disk encryption verified" in record.message for record in caplog.records)

    def test_logs_warning_when_no_data_dir(self, caplog):
        """Logs WARNING when data directory can't be determined."""
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=None):
            check_disk_encryption("postgresql://user@10.0.0.5/venya")

        assert any("Could not determine PostgreSQL data directory" in record.message for record in caplog.records)
