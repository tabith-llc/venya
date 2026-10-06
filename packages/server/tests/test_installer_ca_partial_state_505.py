# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#505 installer-ca-partial-state-wedge — embedded CA block cells.

The core installer's provisioning block used to decide CA existence on the
KEY FILE ALONE: a re-install whose CA directory lost ``ca.crt`` but kept
``ca.key`` printed "preserved", wrote no certificate, and the relay-cert
guard aborted the install — a stable wedge, since re-running walks into the
same branch. The ruled shape: existence is BOTH files; when the key survives
and the certificate does not, re-issue the certificate FROM THE INCUMBENT
KEY (never regenerate the key — that invalidates every fleet certificate).

Cells run the REAL extracted block (no re-implementation) against a fixture
directory: the payload of ``python -c "..."`` is lifted from
``install-venya-core.sh`` between the unique ``<<<"$CA_KEY_PASSPHRASE"``
terminator and its opening quote, the pinned ``ca_dir`` literal is rewritten
to the fixture, and the interpreter is the test venv's python — the same
role the installer's venv python plays. The CA key passphrase here is a
synthetic dev-test value, never a live secret.
"""

import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID

_ROOT = Path(__file__).resolve().parents[3]

_TERM = '" <<<"$CA_KEY_PASSPHRASE"'
_CA_DIR_LITERAL = "/var/lib/venya/ca"
_PASSPHRASE = "test-ca-passphrase-505"


def _core() -> str:
    return (_ROOT / "install-venya-core.sh").read_text()


def _ca_block_source() -> str:
    """Extract the embedded CA provisioning block as runnable Python."""
    core = _core()
    assert core.count(_TERM) == 1, "block terminator no longer unique — re-anchor"
    end = core.index(_TERM)
    open_q = core.rindex('python -c "', 0, end) + len("python -c ")
    payload = core[open_q + 1 : end]
    # The block lives inside a bash double-quoted string; this payload is
    # backslash-free in the script, so the file text IS the interpreter text
    # (no unescaping step to drift from).
    assert "\\" not in payload, "escaped quotes appeared in the block — extraction needs a new anchor"
    assert f"Path('{_CA_DIR_LITERAL}')" in payload
    return payload


def _run_block(tmp_path: Path, passphrase: str = _PASSPHRASE) -> subprocess.CompletedProcess:
    """Run the extracted block against <tmp_path>/ca; returns the process."""
    ca_dir = tmp_path / "ca"
    script = tmp_path / "ca_block_under_test.py"
    script.write_text(_ca_block_source().replace(_CA_DIR_LITERAL, str(ca_dir)))
    return subprocess.run(
        [sys.executable, str(script)],
        input=passphrase + "\n",
        capture_output=True,
        text=True,
        check=False,
    )


def _load_key(ca_dir: Path, passphrase: str = _PASSPHRASE):
    return serialization.load_pem_private_key(ca_dir.joinpath("ca.key").read_bytes(), password=passphrase.encode())


class TestInstallerCaPartialState505:
    def test_source_pinned_both_file_existence(self):
        """Existence test is BOTH files; the incumbent key is LOADED, not reminted."""
        payload = _ca_block_source()
        assert "key_exists = ca_key_path.exists()" in payload
        assert "cert_exists = ca_cert_path.exists()" in payload
        assert "if key_exists and cert_exists:" in payload
        assert "serialization.load_pem_private_key(ca_key_path.read_bytes()" in payload
        # The old single-file decision must be gone.
        assert "if not ca_key_path.exists():" not in payload

    def test_ac2_partial_state_reissues_from_incumbent_key(self, tmp_path):
        """AC2 (RED at HEAD): key present + cert absent -> cert re-issued from the
        SAME key, key bytes untouched, run succeeds so the install continues."""
        run = _run_block(tmp_path)
        assert run.returncode == 0, run.stderr
        ca_dir = tmp_path / "ca"
        key_path, cert_path = ca_dir / "ca.key", ca_dir / "ca.crt"
        key_bytes_before = key_path.read_bytes()
        pub_before = _load_key(ca_dir).public_key().public_numbers()

        cert_path.unlink()  # the wedge state: key survived, certificate lost
        second = _run_block(tmp_path)
        assert second.returncode == 0, second.stderr
        assert "CA certificate re-issued from existing key" in second.stdout
        assert cert_path.exists(), "no certificate re-issued — install aborts at the relay-cert guard"
        assert key_path.read_bytes() == key_bytes_before, "incumbent CA key rewritten — fleet certs invalidated"
        cert = load_pem_x509_certificate(cert_path.read_bytes())
        assert cert.public_key().public_numbers() == pub_before, "re-issued cert does not match the incumbent key"

    def test_ac3_both_present_preserved_bytes_unchanged(self, tmp_path):
        """AC3: both present -> preserved line, neither file touched (bytes + mtime)."""
        assert _run_block(tmp_path).returncode == 0
        ca_dir = tmp_path / "ca"
        key_path, cert_path = ca_dir / "ca.key", ca_dir / "ca.crt"
        before = [(p, (p.read_bytes(), p.stat().st_mtime_ns)) for p in (key_path, cert_path)]
        again = _run_block(tmp_path)
        assert again.returncode == 0, again.stderr
        assert "CA already exists - preserved" in again.stdout
        after = [(p, (p.read_bytes(), p.stat().st_mtime_ns)) for p in (key_path, cert_path)]
        assert before == after, "preserved branch touched CA files"

    def test_ac4_absent_pair_generates_fresh_encrypted_key(self, tmp_path):
        """AC4 paired negative: neither present -> fresh key+cert, as today."""
        run = _run_block(tmp_path)
        assert run.returncode == 0, run.stderr
        assert "CA generated (key encrypted)" in run.stdout
        ca_dir = tmp_path / "ca"
        key_path, cert_path = ca_dir / "ca.key", ca_dir / "ca.crt"
        assert key_path.exists() and cert_path.exists()
        # Encrypted at rest: the PEM is an ENCRYPTED PRIVATE KEY block and the
        # correct passphrase loads it.
        assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()
        _load_key(ca_dir)
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert cert_path.stat().st_mode & 0o777 == 0o644

    def test_ac5_reissued_cert_carries_ski_and_aki(self, tmp_path):
        """AC5: the re-issued certificate keeps the installer's F1 rule —
        SKI + AKI present (Python 3.14 ssl rejects AKI-less chains)."""
        assert _run_block(tmp_path).returncode == 0
        ca_dir = tmp_path / "ca"
        (ca_dir / "ca.crt").unlink()
        assert _run_block(tmp_path).returncode == 0
        cert = load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes())
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        key = _load_key(ca_dir)
        assert ski.digest == x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest
        assert aki.key_identifier == ski.digest
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is True

    def test_cert_without_key_regenerates_pair(self, tmp_path):
        """Remaining partial state (cert present, key absent) keeps the old
        behaviour: a fresh key+cert pair is minted (the cert is re-signed by
        the new key, so the incumbent cert is replaced)."""
        assert _run_block(tmp_path).returncode == 0
        ca_dir = tmp_path / "ca"
        pub_old = load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes()).public_key().public_numbers()
        (ca_dir / "ca.key").unlink()
        run = _run_block(tmp_path)
        assert run.returncode == 0, run.stderr
        assert "CA generated (key encrypted)" in run.stdout
        pub_new = load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes()).public_key().public_numbers()
        assert pub_new != pub_old

    def test_empty_passphrase_refuses_plaintext_key(self, tmp_path):
        """Fail-closed guard survives the restructure: empty passphrase never
        yields an unencrypted CA key."""
        run = _run_block(tmp_path, passphrase="")
        assert run.returncode != 0
        assert "refusing to write a plaintext CA key" in run.stderr + run.stdout
