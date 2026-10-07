# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for disk encryption check utility."""

import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.utils import disk_encryption as disk_encryption_module
from server.utils.disk_encryption import (
    _find_crypt_backing_device,
    _find_mount_point,
    _get_fstype_via_lsblk,
    _get_pg_data_directory,
    _has_crypt_target,
    check_disk_encryption,
)

# /proc/self/mountinfo fixtures. Format:
# <id> <parent> <maj:min> <root> <mount> <opts> [optional -] - <fstype> <source> <super>
MOUNTINFO_PLAIN_PGDATA_OTHER_CRYPT = (
    "21 0 8:1 / / ext4 rw,relatime - ext4 /dev/sda1 rw\n"
    "36 21 253:0 / /backup4 ext4 rw,relatime - ext4 /dev/mapper/backup4_crypt rw\n"
    "42 21 253:1 / /var/lib/postgresql ext4 rw,relatime - ext4 /dev/mapper/pgdata rw\n"
)
MOUNTINFO_CRYPT_PGDATA = (
    "21 0 8:1 / / ext4 rw,relatime - ext4 /dev/sda1 rw\n"
    "42 21 253:1 / /var/lib/postgresql ext4 rw,relatime - ext4 /dev/mapper/pgdata_crypt rw\n"
)
MOUNTINFO_LVM_OVER_CRYPT = (
    "21 0 8:1 / / ext4 rw,relatime - ext4 /dev/sda1 rw\n"
    "42 21 253:3 / /var/lib/postgresql ext4 rw,relatime - "
    "ext4 /dev/mapper/vg--pgdata-lv--main rw\n"
)
MOUNTINFO_TMPFS_MOUNT = (
    "21 0 8:1 / / ext4 rw,relatime - ext4 /dev/sda1 rw\n" "36 21 0:41 / /var/lib/postgresql rw - tmpfs tmpfs rw\n"
)

TABLE_PLAIN_PGDATA = "pgdata: 0 20971520 linear 8:16 2048\n"
TABLE_CRYPT = (
    "pgdata_crypt: 0 4194304000 crypt aes-xts-plain64 0123456789abcdef 0 8 4096 " "1024 0 2 sha256 2 : LUKS_2\n"
)
TABLE_LV = "vg--pgdata-lv--main: 0 20971520 linear 253:1 2048\n"
TABLE_VG = "vg--pgdata: 0 41943040 striped 2 32 253:0 0 8:32 4096\n"


def _write_mountinfo(tmp_path: Path, content: str) -> str:
    path = tmp_path / "mountinfo"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _dmsetup_fixture(info=None, table=None, deps=None):
    """Build a subprocess.run side_effect for the scoped dmsetup calls.

    Each mapping keys the device argument (last token of the command) to
    stdout for returncode 0. Any unmapped call gets returncode 1 with empty
    stdout — the real dmsetup answer for a plain (non-dm) partition, and a
    tripwire if the code ever queries a device outside the mount's lineage.
    """
    info = info or {}
    table = table or {}
    deps = deps or {}

    def _run(cmd, *args, **kwargs):
        sub = cmd[1]
        # Unscoped whole-system query (exactly the #444 bug shape): every
        # device's line is present, so a substring match over this output
        # cannot pass the negative cells.
        if len(cmd) == 2 and sub in ("info", "table", "deps"):
            whole = "".join(mapping_all[sub])
            return MagicMock(returncode=0, stdout=whole, stderr="")
        device = cmd[-1]
        mapping = {"info": info, "table": table, "deps": deps}[sub]
        if device not in mapping:
            return MagicMock(returncode=1, stdout="", stderr=f"no fixture for {' '.join(cmd)}")
        return MagicMock(returncode=0, stdout=mapping[device], stderr="")

    mapping_all = {"info": [], "table": [], "deps": []}
    for mapping, key in ((info, "info"), (table, "table"), (deps, "deps")):
        mapping_all[key] = list(mapping.values())
    return _run


class TestGetPgDataDirectory:
    """Tests for PG data directory inference."""

    def test_returns_none_for_no_url(self):
        """Returns None when db_url is None."""
        assert _get_pg_data_directory(None) is None

    def test_returns_none_for_remote_host(self):
        """Returns None for remote hosts (can't determine local dir)."""
        result = _get_pg_data_directory("postgresql://user@203.0.113.5:5432/venya")
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


class TestGetFstypeViaLsblkMountMatch488:
    """Ticket lsblk-mountcheck-matches-any-mount #488: the MOUNTPOINT column
    is matched EXACTLY.  The old containment test (`mount_point in
    parts[-1]`) let "/" answer for every mounted row, so one unrelated
    crypto_LUKS volume falsely certified an unencrypted data directory."""

    # Real-shaped `lsblk -d -b -n -o NAME,FSTYPE,MOUNTPOINT` body (three
    # columns): the FIRST row is a crypto_LUKS volume mounted at /boot, the
    # root filesystem is plain ext4.  Ordering matters — the old code returned
    # the first row whose mountpoint merely CONTAINED the query, so "/" took
    # the /boot row's answer and the check short-circuited on crypto_LUKS.
    LUKS_AT_BOOT_ROOT_PLAIN = "sda2 crypto_LUKS /boot\n" "sda1 vfat /boot/efi\n" "sda3 ext4 /\n"

    def _patch_lsblk(self, output: str):
        return patch(
            "server.utils.disk_encryption.subprocess.run",
            return_value=MagicMock(returncode=0, stdout=output, stderr=""),
        )

    def test_root_query_does_not_answer_with_luks_from_another_mount(self):
        """N (the bug case): "/" with a crypto_LUKS row at /boot → the answer
        is the ROOT row's fstype (ext4), never crypto_LUKS. RED pre-fix."""
        with self._patch_lsblk(self.LUKS_AT_BOOT_ROOT_PLAIN):
            assert _get_fstype_via_lsblk("/") == "ext4"

    def test_root_query_does_not_answer_at_all_when_root_row_is_absent(self):
        """N: a /boot-only LUKS listing with NO root row answers None — the
        containment test returned crypto_LUKS for this same output because
        "/" is a substring of "/boot"."""
        output = "sda2 crypto_LUKS /boot\n"
        with self._patch_lsblk(output):
            assert _get_fstype_via_lsblk("/") is None

    def test_efi_mount_is_not_confused_with_boot(self):
        """N: querying /boot must not take the /boot/efi row (the prefix
        collision the containment test had in the other direction)."""
        with self._patch_lsblk(self.LUKS_AT_BOOT_ROOT_PLAIN):
            assert _get_fstype_via_lsblk("/boot") == "crypto_LUKS"
            assert _get_fstype_via_lsblk("/boot/efi") == "vfat"

    def test_exact_match_still_verifies_luks_on_the_mount_itself(self):
        """P (AC-2): a crypto_LUKS row whose mountpoint EQUALS the requested
        mount point still answers crypto_LUKS — the fix does not blind the
        check to a genuinely encrypted mount."""
        output = "sda3 crypto_LUKS /\n"
        with self._patch_lsblk(output):
            assert _get_fstype_via_lsblk("/") == "crypto_LUKS"

    def test_trailing_slash_forms_same_mount(self):
        """P: /var/lib/postgresql and /var/lib/postgresql/ are one mount —
        normalization, not substring freedom."""
        output = "dm-0 ext4 /var/lib/postgresql/\n"
        with self._patch_lsblk(output):
            assert _get_fstype_via_lsblk("/var/lib/postgresql") == "ext4"

    def test_header_row_never_answers(self):
        """N: the `lsblk` HEADING line (NAME FSTYPE MOUNTPOINT) is not a row;
        with -n it is absent, and a listing that still carries it must not
        answer for any mount."""
        output = "NAME FSTYPE MOUNTPOINT\nsda3 ext4 /\n"
        with self._patch_lsblk(output):
            assert _get_fstype_via_lsblk("/var/lib/postgresql") is None
            assert _get_fstype_via_lsblk("/") == "ext4"

    def test_row_without_mountpoint_column_does_not_answer(self):
        """N: a one-column row (device with no FSTYPE and no MOUNTPOINT) is
        skipped — it cannot answer a mount-point question."""
        output = "sr0\nsda3 ext4 /\n"
        with self._patch_lsblk(output):
            assert _get_fstype_via_lsblk("/") == "ext4"

    def test_device_name_lookup_names_the_mounted_device(self):
        """P: the log-side helper names the NAME column of the exact row."""
        name_for_mount = disk_encryption_module._get_lsblk_device_for_mount
        with self._patch_lsblk(self.LUKS_AT_BOOT_ROOT_PLAIN):
            assert name_for_mount("/boot") == "sda2"
            assert name_for_mount("/nope") is None

    def test_check_warns_and_lineage_runs_when_luks_is_on_another_mount(self, caplog):
        """N (AC-1, end to end): data dir on an unencrypted root with a LUKS
        /boot → verify_disk-encryption check does NOT claim success, it
        warns, and the dmsetup lineage path RUNS (pre-fix it short-circuited
        before #444's lineage walk ever executed)."""
        caplog.set_level(logging.INFO)
        lineage = MagicMock(return_value=None)
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/"):
                with patch("server.utils.disk_encryption._find_crypt_backing_device", lineage):
                    with self._patch_lsblk(self.LUKS_AT_BOOT_ROOT_PLAIN):
                        check_disk_encryption("postgresql://user@localhost/venya")

        assert not any("Disk encryption verified" in r.message for r in caplog.records)
        assert any("No disk encryption detected" in r.message for r in caplog.records)
        lineage.assert_called_once_with("/")

    def test_check_success_log_names_the_device_it_verified(self, caplog):
        """P: when lsblk answers crypto_LUKS for the mount itself, the INFO
        line names that device (falsifiable claim, same law as #444)."""
        caplog.set_level(logging.INFO)
        output = "sda3 crypto_LUKS /\n"
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/"):
                with self._patch_lsblk(output):
                    check_disk_encryption("postgresql://user@localhost/venya")

        verified = [r.message for r in caplog.records if "Disk encryption verified" in r.message]
        assert verified and "sda3" in verified[0]


class TestHasCryptTarget:
    """Tests for crypt-target detection, scoped to the mount's OWN device
    lineage (ticket disk-encryption-mount-check-ignores-argument #444).
    Every test fakes subprocess.run and a mountinfo file — never real
    dmsetup, never /proc of the test host."""

    # ---- (a) the bug case, and (e) its regression-lock twin ----

    def test_unrelated_crypt_line_does_not_satisfy_check(self, tmp_path):
        """#444 the bug case: dmsetup output contains a crypt target for a
        DIFFERENT device while our mount sits on a plain linear target →
        must be False. RED on the old whole-table substring match."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_PLAIN_PGDATA_OTHER_CRYPT)
        side = _dmsetup_fixture(
            info={
                "/dev/mapper/pgdata": "pgdata\n",
                "/dev/mapper/backup4_crypt": "backup4_crypt\n",
            },
            table={
                "pgdata": TABLE_PLAIN_PGDATA,
                # The unrelated device's crypt line EXISTS, exactly as it
                # would in a real whole-system `dmsetup table`. Our code
                # must never consult it — querying backup4_crypt's table
                # would return rc 1 (unmapped tripwire) and prove drift.
                "backup4_crypt": TABLE_CRYPT.replace("pgdata_crypt", "backup4_crypt"),
            },
            deps={"pgdata": "pgdata: 1 dependencies: (8,16) [ sda2 ]\n"},
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/var/lib/postgresql") is False

    def test_same_host_two_mounts_give_different_answers(self, tmp_path):
        """(e) Regression lock against "matches any line": on ONE host with
        root plain, backup4 encrypted, PGDATA plain — the crypt-backed
        mount verifies True and the plain mount verifies False from the
        SAME dmsetup fixtures. The old code returned True for both."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_PLAIN_PGDATA_OTHER_CRYPT)
        side = _dmsetup_fixture(
            info={
                "/dev/mapper/pgdata": "pgdata\n",
                "/dev/mapper/backup4_crypt": "backup4_crypt\n",
            },
            table={
                "pgdata": TABLE_PLAIN_PGDATA,
                "backup4_crypt": TABLE_CRYPT.replace("pgdata_crypt", "backup4_crypt"),
            },
            deps={
                "pgdata": "pgdata: 1 dependencies: (8,16) [ sda2 ]\n",
                "backup4_crypt": "backup4_crypt: 1 dependencies: (8,32) [ sdb1 ]\n",
            },
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/backup4") is True
                assert _has_crypt_target("/var/lib/postgresql") is False

    # ---- (b) the mount's own device IS crypt-backed ----

    def test_direct_crypt_mapping_returns_true(self, tmp_path):
        """Our mount's own device is a crypt mapping → True."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        side = _dmsetup_fixture(
            info={"/dev/mapper/pgdata_crypt": "pgdata_crypt\n"},
            table={"pgdata_crypt": TABLE_CRYPT},
            deps={"pgdata_crypt": "pgdata_crypt: 1 dependencies: (8,16) [ sda2 ]\n"},
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/var/lib/postgresql") is True

    def test_parent_crypt_under_lvm_stack_returns_true(self, tmp_path):
        """crypt lives on a PARENT device (LV → VG → crypt → partition):
        the lineage walk must find it and report True."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_LVM_OVER_CRYPT)
        side = _dmsetup_fixture(
            info={
                "/dev/mapper/vg--pgdata-lv--main": "vg--pgdata-lv--main\n",
                "vg--pgdata": "vg--pgdata\n",
                "pgdata_crypt": "pgdata_crypt\n",
            },
            table={
                "vg--pgdata-lv--main": TABLE_LV,
                "vg--pgdata": TABLE_VG,
                "pgdata_crypt": TABLE_CRYPT,
            },
            deps={
                "vg--pgdata-lv--main": "vg--pgdata-lv--main: 1 dependencies: (253,1) [ vg--pgdata ]\n",
                "vg--pgdata": "vg--pgdata: 2 dependencies: (253,0) [ pgdata_crypt ] (8,32) [ sdb1 ]\n",
                "pgdata_crypt": "pgdata_crypt: 1 dependencies: (8,16) [ sda2 ]\n",
            },
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/var/lib/postgresql") is True

    # ---- (c) fail-closed: dmsetup missing / failing / timing out ----

    def test_returns_false_when_dmsetup_not_installed(self, tmp_path):
        """Missing dmsetup → False (not verified), never a silent pass."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch(
                "server.utils.disk_encryption.subprocess.run",
                side_effect=FileNotFoundError,
            ):
                assert _has_crypt_target("/var/lib/postgresql") is False

    def test_returns_false_on_dmsetup_failure(self, tmp_path):
        """Non-zero rc from dmsetup info → False."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        failing = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", return_value=failing):
                assert _has_crypt_target("/var/lib/postgresql") is False

    def test_returns_false_on_dmsetup_timeout(self, tmp_path):
        """Timeout from dmsetup → False (fail-closed, same polarity as the
        original except-pass)."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch(
                "server.utils.disk_encryption.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="dmsetup", timeout=5),
            ):
                assert _has_crypt_target("/var/lib/postgresql") is False

    # ---- (d) unresolvable mount point ----

    def test_returns_false_for_unresolvable_mount(self, tmp_path):
        """No mountinfo entry with a block-device source for the path →
        False."""
        mi = _write_mountinfo(tmp_path, "")
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run") as run:
                assert _has_crypt_target("/var/lib/postgresql") is False
                run.assert_not_called()

    def test_returns_false_when_mountinfo_unreadable(self, tmp_path):
        """/proc/self/mountinfo not readable (non-Linux, sandbox) → False
        (fail-closed), never True."""
        missing = str(tmp_path / "no-such-mountinfo")
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", missing):
            with patch("server.utils.disk_encryption.subprocess.run") as run:
                assert _has_crypt_target("/var/lib/postgresql") is False
                run.assert_not_called()

    def test_pseudo_filesystem_mount_is_not_crypt_backed(self, tmp_path):
        """A tmpfs-backed mount has no dm device → False."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_TMPFS_MOUNT)
        side = _dmsetup_fixture()  # every dmsetup call answers rc=1
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/var/lib/postgresql") is False

    # ---- device-name keying, not substring ----

    def test_crypt_word_in_params_column_does_not_count(self, tmp_path):
        """Our device's table line has a NON-crypt target type but carries
        crypt-ish text in the parameter columns → False. The old code's
        whole-line substring match said True."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        tricky = "pgdata_crypt: 0 20971520 linear 8:16 4096 # encrypted-at-rest-elsewhere\n"
        side = _dmsetup_fixture(
            info={"/dev/mapper/pgdata_crypt": "pgdata_crypt\n"},
            table={"pgdata_crypt": tricky},
            deps={"pgdata_crypt": "pgdata_crypt: 1 dependencies: (8,16) [ sda2 ]\n"},
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _has_crypt_target("/var/lib/postgresql") is False

    def test_find_crypt_backing_device_returns_verified_device_name(self, tmp_path):
        """_find_crypt_backing_device names the crypt device it verified, so
        the caller's log line is falsifiable."""
        mi = _write_mountinfo(tmp_path, MOUNTINFO_CRYPT_PGDATA)
        side = _dmsetup_fixture(
            info={"/dev/mapper/pgdata_crypt": "pgdata_crypt\n"},
            table={"pgdata_crypt": TABLE_CRYPT},
        )
        with patch("server.utils.disk_encryption._MOUNTINFO_PATH", mi):
            with patch("server.utils.disk_encryption.subprocess.run", side_effect=side):
                assert _find_crypt_backing_device("/var/lib/postgresql") == "pgdata_crypt"


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
                with patch("server.utils.disk_encryption._find_crypt_backing_device", return_value=None):
                    with patch("server.utils.disk_encryption.subprocess.run", return_value=mock_result):
                        check_disk_encryption("postgresql://user@localhost/venya")

        assert any("No disk encryption detected" in record.message for record in caplog.records)

    def test_logs_info_when_dmsetup_crypt_detected(self, caplog):
        """Logs INFO when the mount's own dm lineage shows a crypt target."""
        caplog.set_level(logging.INFO)
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value=None):
                    with patch("server.utils.disk_encryption._find_crypt_backing_device", return_value="pgdata_crypt"):
                        check_disk_encryption("postgresql://user@localhost/venya")

        assert any("Disk encryption verified" in record.message for record in caplog.records)

    def test_dmsetup_success_message_names_verified_device(self, caplog):
        """The success line states WHICH device was verified, so a reader of
        the health output can falsify it (fix-leg spec step 2.4)."""
        caplog.set_level(logging.INFO)
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value=None):
                    with patch("server.utils.disk_encryption._find_crypt_backing_device", return_value="pgdata_crypt"):
                        check_disk_encryption("postgresql://user@localhost/venya")

        verified = [r.message for r in caplog.records if "Disk encryption verified" in r.message]
        assert verified and "pgdata_crypt" in verified[0]

    def test_logs_warning_when_only_unrelated_device_is_crypt(self, caplog):
        """#444 end-to-end polarity: mount's lineage NOT crypt-backed
        (unrelated volume is) → WARNING, never the verified claim."""
        caplog.set_level(logging.INFO)
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=Path("/var/lib/postgresql")):
            with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
                with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value=None):
                    with patch("server.utils.disk_encryption._find_crypt_backing_device", return_value=None):
                        check_disk_encryption("postgresql://user@localhost/venya")

        assert any("No disk encryption detected" in record.message for record in caplog.records)
        assert not any("Disk encryption verified" in record.message for record in caplog.records)

    def test_logs_warning_when_no_data_dir(self, caplog):
        """Logs WARNING when data directory can't be determined."""
        with patch("server.utils.disk_encryption._get_pg_data_directory", return_value=None):
            check_disk_encryption("postgresql://user@203.0.113.5/venya")

        assert any("Could not determine PostgreSQL data directory" in record.message for record in caplog.records)
