# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-8a CP-A — `venya admin cert status`: the read-local lifetime check (dossier §4.5).

The owner's ruling on 4b is that a headless job must be able to pre-flight its own
credential WITHOUT a ceremony hiding inside the check. So this command reads ONE file
(the admin certificate), prints minutes remaining, and stops. The load-bearing
property is not the printing — it is that nothing else happens: no request, no
security-key ceremony, no read of the private key, no file write.

Truth-table law (AGENTS.md): every gate gets its rejection half. Each positive cell
here is paired with the case that must NOT be answered the same way — missing file,
unreadable file, expired file, future-dated file, no path configured, and the
`--within` advisory that must never change the exit code.

Design record: docs/design/rf6-shortcert-dossier-20261007.md §4.4-§4.6, §5.6.
"""

import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli.cli import create_parser
from venya_cli.commands import cmd_admin_cert_status, run_command

UTC = datetime.UTC


def _cert(tmp_path: Path, name: str, not_before_offset: datetime.timedelta, not_after_offset: datetime.timedelta):
    """Write a real PEM admin cert with an EXPLICIT validity window. Returns (path, key_path)."""
    now = datetime.datetime.now(UTC)
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin-bot@workstation")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x1234_ABCD)
        .not_valid_before(now + not_before_offset)
        .not_valid_after(now + not_after_offset)
        .sign(key, None)
    )
    path = tmp_path / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / f"{name}.key"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path, key_path


def _args(cert_path=None, within=None) -> SimpleNamespace:
    return SimpleNamespace(cert_path=cert_path, within=within)


class TestParserSurface:
    """The argparse contract for the new leaf: it parses, and the flags land right."""

    def test_status_parses_with_defaults(self):
        ns = create_parser().parse_args(["admin", "cert", "status"])
        assert ns.command == "admin"
        assert ns.admin_command == "cert"
        assert ns.admin_cert_command == "status"
        assert ns.cert_path is None
        assert ns.within is None

    def test_flags_reach_the_namespace(self):
        ns = create_parser().parse_args(["admin", "cert", "status", "--cert-path", "/tmp/a.crt", "--within", "10"])
        assert ns.cert_path == "/tmp/a.crt"
        assert ns.within == 10

    def test_within_rejects_non_integer(self):
        """Paired negative: MINUTES is typed, not free text."""
        with pytest.raises(SystemExit) as excinfo:
            create_parser().parse_args(["admin", "cert", "status", "--within", "soon"])
        assert excinfo.value.code == 2


class TestValidCertificate:
    def test_valid_cert_prints_minutes_expiry_serial_subject(self, tmp_path, capsys):
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-5), datetime.timedelta(minutes=40))
        rc = cmd_admin_cert_status(_args(str(path)))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Minutes remaining:" in out
        assert "40" in out or "39" in out  # floor division: 39 or 40 depending on the second
        assert "Expires:" in out
        assert "Serial:" in out
        assert "00001234abcd" in out  # canonical: lowercase, zero-padded to 16
        assert "Subject:" in out
        assert "CN=admin-bot@workstation" in out

    def test_serial_is_canonical_lowercase_padded(self, tmp_path, capsys):
        """The value an operator pastes into `admin revoke-admin-cert --serial`."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        cmd_admin_cert_status(_args(str(path)))
        out = capsys.readouterr().out
        line = next(l for l in out.splitlines() if "Serial:" in l)
        assert line.split("Serial:")[1].strip() == "000000001234abcd"

    def test_local_clock_honesty_line_present(self, tmp_path, capsys):
        """§4.5 honesty clause: the figure is LOCAL-clock computed, in one line."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        cmd_admin_cert_status(_args(str(path)))
        out = capsys.readouterr().out
        assert "local" in out.lower()
        assert "this workstation's clock" in out

    def test_expiry_instant_carries_offset(self, tmp_path, capsys):
        """ISO-8601 WITH offset (§4.4 property 2) — a naked naive stamp is not honest."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        cmd_admin_cert_status(_args(str(path)))
        out = capsys.readouterr().out
        expires = next(line for line in out.splitlines() if "Expires:" in line)
        assert "+00:00" in expires


class TestZeroMutation:
    """THE requirement, not a nicety: a status command that can trigger a mint kills 4b."""

    def test_zero_requests_zero_ceremony(self, tmp_path):
        """APIClient is NEVER constructed for status, so no /health advisory fetch either."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        ns = SimpleNamespace(
            command="admin",
            admin_command="cert",
            admin_cert_command="status",
            cert_path=str(path),
            within=None,
            verbose=False,
        )
        with (
            patch("venya_cli.commands.APIClient") as client_cls,
            patch("venya_cli.commands.cmd_admin") as cmd_admin,
        ):
            rc = run_command(ns)
        assert rc == 0
        client_cls.assert_not_called()
        cmd_admin.assert_not_called()

    def test_no_file_write_and_no_key_read(self, tmp_path):
        """Read-only in the strongest sense: the key file is never opened."""
        path, key_path = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        before = path.stat().st_mtime_ns
        key_path.chmod(0o000)  # any read attempt fails LOUDLY, not silently
        try:
            rc = cmd_admin_cert_status(_args(str(path)))
        finally:
            key_path.chmod(0o600)
        assert rc == 0
        assert path.stat().st_mtime_ns == before
        assert list(tmp_path.iterdir())  # nothing removed out from under the test

    def test_status_works_with_no_admin_key_env_at_all(self, tmp_path, monkeypatch):
        """The locked-out operator shape: VENYA_ADMIN_KEY absent, cert readable -> still answers."""
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        assert cmd_admin_cert_status(_args(str(path))) == 0


class TestThreeAnswers:
    """§4.5 three-answers law: no-file, expiring-soon, valid — each with its own exit code."""

    def test_missing_file_is_nonzero_and_names_the_repair(self, tmp_path, capsys):
        rc = cmd_admin_cert_status(_args(str(tmp_path / "nope.crt")))
        err = capsys.readouterr().err
        assert rc == 1
        assert "`venya admin cert renew`" in err
        assert "VENYA_ADMIN_CERT" in err

    def test_unreadable_garbage_is_nonzero(self, tmp_path, capsys):
        """Paired negative: a file that exists but is not a certificate is NOT read as expired."""
        junk = tmp_path / "admin.crt"
        junk.write_text("not a certificate\n", encoding="utf-8")
        rc = cmd_admin_cert_status(_args(str(junk)))
        assert rc == 1
        assert "not a PEM certificate" in capsys.readouterr().err

    def test_no_path_configured_is_nonzero(self, monkeypatch, capsys):
        monkeypatch.delenv("VENYA_ADMIN_CERT", raising=False)
        rc = cmd_admin_cert_status(_args(None))
        err = capsys.readouterr().err
        assert rc == 1
        assert "--cert-path" in err
        assert "VENYA_ADMIN_CERT" in err

    def test_default_path_comes_from_env(self, tmp_path, monkeypatch, capsys):
        path, _key = _cert(tmp_path, "from-env.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(path))
        assert cmd_admin_cert_status(_args(None)) == 0
        assert "from-env.crt" in capsys.readouterr().out

    def test_expiring_soon_advises_and_keeps_exit_zero(self, tmp_path, capsys):
        """Advisory is information, not failure: rc stays 0 (§3 ruling)."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=20))
        rc = cmd_admin_cert_status(_args(str(path), within=30))
        captured = capsys.readouterr()
        assert rc == 0
        assert "ADVISORY" in captured.err
        assert "renew before starting" in captured.err.lower() or "venya admin cert renew" in captured.err
        assert captured.out.endswith("STATUS: OK\n")

    def test_comfortably_valid_with_within_prints_no_advisory(self, tmp_path, capsys):
        """Paired negative: --within set but the cert outlives the window -> no advisory."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=90))
        rc = cmd_admin_cert_status(_args(str(path), within=10))
        captured = capsys.readouterr()
        assert rc == 0
        assert "ADVISORY" not in captured.err

    def test_within_advisory_goes_to_stderr_stdout_stays_machine_shaped(self, tmp_path, capsys):
        """modewarn discipline: a script's captured stdout does not change shape."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=5))
        cmd_admin_cert_status(_args(str(path), within=60))
        captured = capsys.readouterr()
        assert "ADVISORY" in captured.err
        assert [line.split(":")[0].strip() for line in captured.out.splitlines() if line.strip()]


class TestExpiredAndFutureDated:
    """§4.5 + §5: the two clock faults are DIFFERENT sentences, and neither dials."""

    def test_expired_cert_refusal_styled_nonzero_stdout_clean(self, tmp_path, capsys):
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(days=-1), datetime.timedelta(minutes=-12))
        rc = cmd_admin_cert_status(_args(str(path)))
        captured = capsys.readouterr()
        assert rc == 1
        assert captured.out == ""  # everything on stderr (§4.4 property 5)
        assert "EXPIRED" in captured.err
        assert "12 minutes ago" in captured.err
        assert "`venya admin cert renew`" in captured.err
        assert "+00:00" in captured.err

    def test_future_dated_cert_says_skew_never_a_silent_negative(self, tmp_path, capsys):
        """§5.4 / §4.5: not-yet-valid points at the clock story, it is not reported as lifetime."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=25), datetime.timedelta(minutes=85))
        rc = cmd_admin_cert_status(_args(str(path)))
        captured = capsys.readouterr()
        assert rc == 1
        assert captured.out == ""
        assert "NOT YET VALID" in captured.err
        assert "CLOCK SKEW" in captured.err
        assert "Minutes remaining:" not in captured.out
        # The skew case must not order a re-mint as its FIRST repair.
        assert "fix the clock" in captured.err

    def test_negative_within_is_refused(self, tmp_path):
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        assert cmd_admin_cert_status(_args(str(path), within=-5)) == 1

    def test_within_zero_is_accepted(self, tmp_path):
        """Boundary: 0 is a legal window (it can only ever mean 'no advisory')."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        assert cmd_admin_cert_status(_args(str(path), within=0)) == 0


class TestWindowsCarrierLine:
    """§6 carrier: one honest line about the interactive-desktop ceremony limitation."""

    def test_status_advisory_and_refusal_carry_no_windows_lie(self, tmp_path, capsys):
        """POSIX output stays byte-identical: the Windows caveat rides the renewal pointer."""
        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(days=-1), datetime.timedelta(minutes=-3))
        cmd_admin_cert_status(_args(str(path)))
        err = capsys.readouterr().err
        assert "interactive desktop session" in err


class TestDirectDispatch:
    """`admin cert` reached through cmd_admin (not the pre-gate) still answers sensibly."""

    def test_cmd_admin_cert_dispatches_status(self, tmp_path):
        from venya_cli.commands import cmd_admin_cert

        path, _key = _cert(tmp_path, "admin.crt", datetime.timedelta(minutes=-1), datetime.timedelta(minutes=30))
        args = SimpleNamespace(admin_cert_command="status", cert_path=str(path), within=None)
        assert cmd_admin_cert(MagicMock(), args) == 0

    def test_bare_admin_cert_asks_for_a_subcommand(self, capsys):
        from venya_cli.commands import cmd_admin_cert

        assert cmd_admin_cert(MagicMock(), SimpleNamespace(admin_cert_command=None)) == 1
        assert "admin cert subcommand required" in capsys.readouterr().err

    def test_unknown_cert_subcommand_names_what_exists(self, capsys):
        """RF-8b updated this cell honestly.

        It used to pass `renew` as the unknown name, because that was the one
        subcommand that genuinely did not exist. `renew` landed with RF-8b, so the
        negative half now uses a name that is really absent — the point of the cell
        is the unknown-subcommand branch, not a placeholder that rotted.
        """
        from venya_cli.commands import cmd_admin_cert

        assert cmd_admin_cert(MagicMock(), SimpleNamespace(admin_cert_command="rotate")) == 1
        err = capsys.readouterr().err
        assert "rotate" in err
        assert "status" in err
        assert "renew" in err
