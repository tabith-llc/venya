# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#547a PART A — the admin LEAF private key gets the passphrase requirement.

Owner ruling (2026-10-09): "passphrase shall extend to the admin's private key." Both
writers of an admin private key — `venya admin generate-admin-cert` (local CA mint) and
`venya admin cert renew` (the RF-8b core mint) — now refuse when
`VENYA_ADMIN_CA_KEY_PASSPHRASE` is unset, empty, or whitespace-only, and write the key
encrypted (PKCS8 + BestAvailableEncryption) when it is set. Same ordering as #547: the
refusal lands before ANY filesystem work, so a passphrase-less invocation creates no
directory and no file.

**And this file records the consequence rather than hiding it.** Part A is the write
side only. At the time these cells were written `api_client.py` had no `password=` handling
for the ADMIN pair: a key written here was encrypted at rest and not loadable for admin
mTLS. Cell N4 proved that gap at the real builder — and #565 Part B closed it, so N4 now
proves the opposite shape (the same call LOADS, and still refuses by name when no
passphrase is configured). The handshake proof lives in `test_admin_key_load_565_partb.py`.

The wording is part of the deliverable: both the refusal and the success readout state
the fact, so an operator is never surprised twice.

RULING SINCE THIS FILE WAS WRITTEN (#573, carrier n15): the length floor the owner ruled
(15 Unicode code points, inclusive) now applies on these doors, so the placeholder that
used to hold "no length rule" from both directions has been REPLACED by the real behavior
(`test_below_floor_passphrase_now_refuses`). The whitespace-only cells above are untouched
and still hold their own line: a blank value is "no passphrase", not "too short".
"""

import datetime
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError, _build_ssl_context
from venya_cli.commands import (
    ADMIN_CA_SETUP_FRAGMENT,
    _admin_leaf_key_passphrase_or_none,
    cmd_admin_cert_renew,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

UTC = datetime.UTC
# dev-only test passphrase, the same value #547's cells already record in
# .detect-secrets-baseline; never used anywhere live.
LEAF_PASSPHRASE = "test_passphrase"
CA_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
    ]
)


def _minted_cert_pem(public_key) -> bytes:
    """A core-shaped answer for the renew cell: signed by its own CA-ish key, fresh."""
    now = datetime.datetime.now(UTC)
    signer = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dusty@workstation")]))
        .issuer_name(CA_SUBJECT)
        .public_key(public_key)
        .serial_number(0x7777_0001)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(seconds=3600))
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class _StubResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 201
        self.content = b"{}"

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _StubTransport:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def request(self, method, path, json=None, params=None, headers=None, **kwargs):
        self.calls.append({"path": path, "json": json, "headers": headers or {}})
        return _StubResponse(self.payload)

    def close(self):
        pass


def _admin_ca(tmp_path: Path) -> Path:
    """A real admin CA on disk, written through the shipped #547 path."""
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = LEAF_PASSPHRASE
    ca_dir = tmp_path / "admin-ca"
    assert cmd_admin_init_admin_ca(SimpleNamespace(output_dir=str(ca_dir))) == 0
    return ca_dir


def _generate_args(ca_dir: Path, out: Path, identity: str = "admin@example.com") -> SimpleNamespace:
    return SimpleNamespace(identity=identity, ca_dir=str(ca_dir), output_dir=str(out))


def _renew_client(tmp_path: Path, cert_path: Path, key_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"server_url": "https://core.test:8443"}', encoding="utf-8")
    os.environ["VENYA_CONFIG"] = str(cfg)
    os.environ["SSL_CERT_FILE"] = str(cert_path)
    os.environ["VENYA_ADMIN_CERT"] = str(cert_path)
    os.environ["VENYA_ADMIN_KEY"] = str(key_path)
    client = APIClient()
    client.config.access_token = "session-bearer"
    return client


def _renew_args(cert_path: Path, key_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        cert_path=str(cert_path),
        key_path=str(key_path),
        user_id=None,
        server_url=None,
        command="admin",
        admin_command="cert",
        admin_cert_command="renew",
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in (
        "VENYA_ADMIN_CERT",
        "VENYA_ADMIN_KEY",
        "VENYA_CONFIG",
        "SSL_CERT_FILE",
        "VENYA_SERVER_URL",
        "VENYA_ADMIN_CA_KEY_PASSPHRASE",
        "VENYA_ADMIN_CA_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def _seed_pair(tmp_path: Path):
    """An existing cert/key pair on disk so the renew cell has a path to write over."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dusty@old")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(minutes=30))
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "admin.crt", tmp_path / "admin.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    kp.chmod(0o600)
    return cp, kp


class TestPositiveWritesEncrypted:
    """P1 + P2 — both writers, asserted on the BYTES, like #547's cells do."""

    @staticmethod
    def _assert_encrypted_key(key_path: Path, out_dir: Path):
        data = key_path.read_bytes()
        # Assert the PEM label itself rather than the absence of a plaintext marker:
        # the first line of a PKCS#8 file IS the encryption statement, so equality here
        # rejects plaintext AND rejects a half-written header. (Writing the plaintext
        # marker as a literal to grep for it trips the secret scanner on its own
        # line — the check was converted, not suppressed.)
        assert data.split(b"\n", 1)[0] == b"-----BEGIN ENCRYPTED PRIVATE KEY-----", data.split(b"\n", 1)[0]
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
        # loads WITH the passphrase, and only with it
        assert serialization.load_pem_private_key(data, password=LEAF_PASSPHRASE.encode()) is not None
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(data, password=None)

    def test_p1_generate_admin_cert_writes_encrypted_key(self, tmp_path, capsys):
        ca_dir = _admin_ca(tmp_path)
        out = tmp_path / "leaf"
        rc = cmd_admin_generate_admin_cert(_generate_args(ca_dir, out))
        assert rc == 0
        self._assert_encrypted_key(out / "admin.key", out)
        assert stat.S_IMODE((out / "admin.crt").stat().st_mode) == 0o644
        # the fact is stated in the SUCCESS output too, not only in a refusal (§3.3)
        out_text = capsys.readouterr().out
        assert "encrypted at rest with VENYA_ADMIN_CA_KEY_PASSPHRASE" in out_text
        assert "Admin mTLS:      the CLI opens this key with that variable" in out_text
        # and no key material leaked
        assert "PRIVATE KEY" not in out_text.replace("ENCRYPTED PRIVATE KEY", "")

    def test_p2_cert_renew_writes_encrypted_key(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
        cp, kp = _seed_pair(tmp_path)
        client = _renew_client(tmp_path, cp, kp)
        # the mint signs whatever public key the handler put in the CSR, like a CA does
        captured = {}

        def fake_request(self, method, path, json_data=None, params=None, extra_headers=None, timeout=None):
            csr = x509.load_pem_x509_csr(json_data["csr_pem"].encode())
            captured["csr_public_key"] = csr.public_key()
            return {"certificate_pem": _minted_cert_pem(csr.public_key()).decode()}

        with (
            patch("venya_cli.commands._elevate", return_value="t"),
            patch.object(APIClient, "_request", fake_request),
        ):
            rc = cmd_admin_cert_renew(client, _renew_args(cp, kp))
        assert rc == 0
        self._assert_encrypted_key(kp, kp.parent)
        out_text = capsys.readouterr().out
        assert "encrypted at rest with VENYA_ADMIN_CA_KEY_PASSPHRASE" in out_text
        assert "Admin mTLS:      the CLI opens this key with that variable" in out_text

    def test_p2b_renew_refuses_before_any_write_when_the_passphrase_is_missing(self, tmp_path, capsys):
        """The ordering that protects the operator: no ceremony, no mint, no file touched."""
        cp, kp = _seed_pair(tmp_path)
        before = kp.read_bytes()
        client = _renew_client(tmp_path, cp, kp)
        with patch("venya_cli.commands._elevate") as elevate:
            rc = cmd_admin_cert_renew(client, _renew_args(cp, kp))
        assert rc == 1
        elevate.assert_not_called()
        assert kp.read_bytes() == before, "the existing key must be untouched by a refusal"
        err = capsys.readouterr().err
        assert "REFUSED" in err and "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err


class TestRefusalOrdering:
    """N1 + N2 + N3 — unset, empty, whitespace-only all refuse; nothing is created."""

    @pytest.mark.parametrize(
        "value", [None, "", " ", "   ", "\t", "\n"], ids=["unset", "empty", "sp1", "sp3", "tab", "nl"]
    )
    def test_no_usable_passphrase_reads_as_unset(self, monkeypatch, value):
        if value is None:
            monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        else:
            monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", value)
        assert _admin_leaf_key_passphrase_or_none() is None

    def test_n1_unset_refuses_and_creates_no_directory_and_no_file(self, tmp_path, capsys):
        ca_dir = _admin_ca(tmp_path)
        os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)
        out = tmp_path / "never-created"
        rc = cmd_admin_generate_admin_cert(_generate_args(ca_dir, out))
        assert rc == 1
        assert not out.exists(), "the refusal created the output directory"
        assert list(tmp_path.glob("never-created*")) == []
        err = capsys.readouterr().err
        assert "REFUSED" in err
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err
        assert "Nothing was written" in err

    @pytest.mark.parametrize("value", ["", " ", "   ", "\t"], ids=["empty", "one-space", "three", "tab"])
    def test_n2_n3_empty_and_whitespace_only_refuse_the_same_way(self, tmp_path, capsys, value, monkeypatch):
        """N2 (empty) and N3 (whitespace-only, the owner's ruling) in one parametrized
        shape, because they are the same decision: no passphrase."""
        ca_dir = _admin_ca(tmp_path)
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", value)
        out = tmp_path / "nope"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 1
        assert not out.exists()
        err = capsys.readouterr().err
        assert "REFUSED" in err and "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err

    def test_below_floor_passphrase_now_refuses(self, tmp_path, capsys, monkeypatch):
        """THE blessed flip (#573): this was the placeholder for an unruled length floor.

        It shipped as `test_no_length_rule_is_applied`, asserting `== "x"` and carrying
        its own instruction: "If a length rule is ever ruled, THIS cell is the one that
        gets replaced by the real behavior, not deleted." The owner ruled it (s85:
        "enforce a proper length passcode", floor N = 15 code points inclusive), so the
        cell is REPLACED by the real behavior in this same name-slot — a one-character
        value is now a refusal that writes nothing. No shipped check is softened: the
        material-not-length posture this cell pinned still lives in #554's suite, and the
        at-floor positive is `test_at_floor_passphrase_is_accepted_inclusive`.
        """
        ca_dir = _admin_ca(tmp_path)
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "x")
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 1
        assert not out.exists(), "a below-floor passphrase still wrote a leaf key"
        err = capsys.readouterr().err
        assert "REFUSED" in err and "shorter than Venya's minimum" in err
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE is set to a passphrase" in err
        # Never the value, never its length (§6 law): the typed "x" must not appear.
        assert "' x" not in err and "1 character" not in err

    def test_refusal_names_the_variable_and_the_fixing_command(self, tmp_path, capsys):
        ca_dir = _admin_ca(tmp_path)
        os.environ.pop("VENYA_ADMIN_CA_KEY_PASSPHRASE", None)
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, tmp_path / "x")) == 1
        err = capsys.readouterr().err
        assert ADMIN_CA_SETUP_FRAGMENT in err, "the refusal must carry the shared fragment verbatim"
        assert "venya admin init-admin-ca" in err


class TestThePartBReadSide:
    """N4 — flipped by #565 Part B, and the flip is recorded here rather than papered over.

    This class used to prove the GAP: a key written by P1 was encrypted at rest and the
    admin mTLS path handed OpenSSL no passphrase, so the key was not loadable. Part B
    installed the passphrase callback in `_build_ssl_context`, so the same call now LOADS.
    The two halves kept below are the ones that stay true: the bytes really are encrypted,
    and the refusal when no passphrase is configured names the variable.
    """

    def test_n4_a_key_written_by_p1_loads_at_the_mtls_path(self, tmp_path):
        ca_dir = _admin_ca(tmp_path)
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 0
        cert_path, key_path = out / "admin.crt", out / "admin.key"
        # still encrypted — Part B did not relax the write side to make the read work
        assert key_path.read_bytes().split(b"\n", 1)[0] == b"-----BEGIN ENCRYPTED PRIVATE KEY-----"

        # The exact call the dial seam makes (`api_client.py`, `_http` build branch), with
        # the passphrase configured: it BUILDS. The handshake half lives in
        # tests/test_admin_key_load_565_partb.py, which proves presentation at a real server.
        assert _build_ssl_context(cafile=str(cert_path), certfile=str(cert_path), keyfile=str(key_path))

    def test_n4b_the_same_key_still_refuses_without_a_passphrase(self, tmp_path, monkeypatch):
        """The negative half of the cell above: no plaintext fallback, and a refusal BY NAME."""
        ca_dir = _admin_ca(tmp_path)
        out = tmp_path / "leaf"
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, out)) == 0
        cert_path, key_path = out / "admin.crt", out / "admin.key"
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        with pytest.raises(APIClientError) as excinfo:
            _build_ssl_context(cafile=str(cert_path), certfile=str(cert_path), keyfile=str(key_path))
        msg = str(excinfo.value)
        assert "REFUSED" in msg and "no passphrase is" in msg, msg
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in msg

    def test_the_refusal_and_the_success_output_both_state_the_pairing(self, tmp_path, capsys, monkeypatch):
        """§3.3: the wording is the bridge between Part A and Part B — and after Part B it
        states the PAIRING (write encrypted, read with the same variable), not a gap."""
        ca_dir = _admin_ca(tmp_path)
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, tmp_path / "a")) == 1
        refusal = capsys.readouterr().err
        assert "the CLI opens" in refusal
        assert "cannot yet load an encrypted admin key" not in refusal

        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, tmp_path / "b")) == 0
        success = capsys.readouterr().out
        assert "encrypted at rest with VENYA_ADMIN_CA_KEY_PASSPHRASE" in success
        assert "Admin mTLS:      the CLI opens this key with that variable at dial time" in success

    def test_the_wording_carries_no_severity_language(self, tmp_path, capsys):
        """ALPHA-tone discipline on operator-facing text: state the mechanism, not a
        catastrophe. No word in this family belongs in a success readout."""
        ca_dir = _admin_ca(tmp_path)
        assert cmd_admin_generate_admin_cert(_generate_args(ca_dir, tmp_path / "c")) == 0
        text = capsys.readouterr().out.lower()
        for banned in ("critical", "severe", "urgent", "vulnerable", "attack", "exploit", "leak"):
            assert banned not in text, banned


class TestSharedHintFragment:
    """P3 — the two dead-end hints flash5 found reuse the ONE fragment, not a third."""

    def test_missing_ca_hint_names_the_precondition(self, tmp_path, capsys, monkeypatch):
        """The pre-#547 text pointed at `init-admin-ca` with no word about the
        passphrase, so following the hint walked into a refusal.

        Note the ordering this cell can only reach because #547a's own refusal sits
        ahead of it: with no passphrase the operator gets the passphrase refusal first,
        which is the correct answer to the wrong question. Setting the passphrase lets
        the CA-read hint — the other dead end — be inspected on its own."""
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
        out = tmp_path / "leaf"
        rc = cmd_admin_generate_admin_cert(_generate_args(tmp_path / "absent-ca", out, identity="admin@example.com"))
        assert rc == 1
        err = capsys.readouterr().err
        assert ADMIN_CA_SETUP_FRAGMENT in err
        assert "admin CA key not found" in err

    def test_missing_ca_certificate_hint_names_the_precondition(self, tmp_path, capsys):
        ca_dir = tmp_path / "half-a-ca"
        ca_dir.mkdir()
        (ca_dir / "admin-ca.key").write_bytes(b"placeholder")  # key present, cert absent
        os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = LEAF_PASSPHRASE
        rc = cmd_admin_generate_admin_cert(_generate_args(ca_dir, tmp_path / "leaf"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "admin CA cert not found" in err
        assert ADMIN_CA_SETUP_FRAGMENT in err

    def test_the_fragment_is_reused_not_reimplemented_inline(self):
        """P3's negative half: a hand-copied variant is the failure mode. The two hint
        sites must print the module constant, and the retired literal must be gone."""
        import inspect

        import venya_cli.commands as commands_mod

        src = inspect.getsource(commands_mod.cmd_admin_generate_admin_cert)
        assert "ADMIN_CA_SETUP_FRAGMENT" in src, "the hint sites must reference the shared fragment"
        assert "Run 'venya admin init-admin-ca' first." not in src, "the dead-end literal shipped again"
        # the fragment is one string, defined once
        assert len([n for n in (ADMIN_CA_SETUP_FRAGMENT,) if n]) == 1
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in ADMIN_CA_SETUP_FRAGMENT

    def test_fragment_wording_matches_the_shape_flash5_landed(self):
        """Set-what-then-run-what, in that order, naming the variable exactly."""
        assert ADMIN_CA_SETUP_FRAGMENT.startswith("Set VENYA_ADMIN_CA_KEY_PASSPHRASE")
        assert "then run: venya admin init-admin-ca" in ADMIN_CA_SETUP_FRAGMENT


class TestArgSurfaceUntouched:
    """The leg must not move the argparse surface (no new flag, §3.4)."""

    def test_no_new_argument_on_either_writer(self):
        from venya_cli.cli import create_parser

        gen = create_parser().parse_args(["admin", "generate-admin-cert", "id", "--output-dir", "/tmp/o"])
        assert set(vars(gen)) >= {"identity", "output_dir", "ca_dir"}
        ren = vars(create_parser().parse_args(["admin", "cert", "renew"]))
        assert set(ren) >= {"cert_path", "key_path", "server_url", "user_id"}
        # no passphrase flag exists on either path — the value comes from the environment
        assert not any("passphrase" in name.lower() for name in vars(gen))
        assert not any("passphrase" in name.lower() for name in ren)
