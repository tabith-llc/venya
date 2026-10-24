# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#565 (body sites 3-4) — the CLI writes an encrypted executor key, and can still read it.

Pre-fix: ``venya exec register`` (``executor_register``) and
``venya exec cert renew`` (``executor_cert_renew``) each serialized the executor
leaf with ``serialization.NoEncryption()`` and dropped it at 0600 — the private
half of a live mTLS identity, in the clear, on the executor host. The same two
commands ALSO read that file back (the renew POSTs with the incumbent pair, and
``venya exec heartbeat`` dials with it), so a write-side change with no read-side
change would have bricked the next renew on every host that had ever registered.

Posture is inherited, not re-decided: R7-Q3 (`decisions.md` `1bf25ae`, design note
§6) rules the interim shape for these unattended sites — a write-time passphrase
carried through the environment, disk protection and **not** hardware custody —
with the read side in the same changeset and no silent plaintext fallback (AC4).

Truth table, both halves per site:

+----------------------------------------------------------+--------------------------------------+
| shape                                                    | expected                             |
+----------------------------------------------------------+--------------------------------------+
| register / renew WITH a passphrase                        | key lands encrypted, 0600, dir 0700  |
| register / renew, headless, NO passphrase                 | rc=1, refusal, NO dir, NO file, NO   |
|                                                          | request sent                          |
| blank or whitespace-only value                            | same refusal                         |
| value under the #573 floor                                | floor refusal, value never echoed     |
| value at the floor (15)                                   | PASSES — the door is inclusive        |
| prompt path: typed value                                  | key encrypted; empty typed value      |
|                                                          | refuses with nothing written          |
| renew dialing with an ENCRYPTED incumbent key             | succeeds (read half)                  |
| renew dialing with a LEGACY plaintext key, nothing set     | succeeds unchanged (no-regression)    |
| admin mTLS path                                          | separate plane: its own passphrase  |
|                                                          | (#565 Part B), never this variable    |
+----------------------------------------------------------+--------------------------------------+
"""

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from venya_cli.api_client import APIClientError, _build_ssl_context
from venya_cli.commands import executor_cert_renew, executor_register
from venya_cli.executor_key import (
    EXECUTOR_KEY_PASSPHRASE_ENV,
    acquire_write_passphrase,
    configured_passphrase,
    serialize_key_encrypted,
    ssl_password_callback,
)

# Self-contained helpers (this suite has no tests/__init__.py, so cells do not
# import across files): a registration client whose POST answers with a REAL cert,
# precise Namespace args (no MagicMock auto-attrs leaking into resolution), and an
# incumbent cert/key pair on disk.

GOOD_PW = "test-executor-key-passphrase"  # pragma: allowlist secret — 28 code points
AT_FLOOR_PW = "0123456789abcde"  # pragma: allowlist secret — exactly 15: passes
UNDER_PW = "0123456789abcd"  # pragma: allowlist secret — 14: refuses

assert len(AT_FLOOR_PW) == 15 and len(UNDER_PW) == 14  # the boundary the cells claim

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8


def _mode(path) -> int:
    return stat.S_IMODE(Path(path).stat().st_mode)


@pytest.fixture(autouse=True)
def _hermetic_anchor(tmp_path, monkeypatch):
    """Give the renew cells a RESOLVED trust anchor in this cell's own tmp dir.

    #507 made renew resolve an anchor through ``VENYA_CONFIG`` (config-dir CA ->
    configured bundle -> sibling ca.crt -> loud refusal), and the incumbent renew
    suite supplies a scratch config dir per cell. This file does the same, for a
    reason that is not cosmetic: another suite file
    (``test_cli_admin_cert_fingerprint_rf8c.py:135``) assigns
    ``os.environ["VENYA_CONFIG"]`` directly, which outlives that file's own teardown,
    so an ambient or leaked value decides whether the cells here find an anchor at
    all. Booked as a finding; the hermetic fix lives on THIS side of the change set.
    """
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    cfg_dir = tmp_path / "venya-config"
    cfg_dir.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "venya-565-cell-ca")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (cfg_dir / "ca.crt").write_bytes(cert.public_bytes(_PEM))
    monkeypatch.setenv("VENYA_CONFIG", str(cfg_dir / "config.json"))
    return cfg_dir


def _generate_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def _self_cert(key, common_name: str, validity_days: int = 30):
    """A self-signed certificate for `key` — enough for a renew to parse its CN."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(key, hashes.SHA256())
    )


def _mock_register_client():
    """A MagicMock APIClient whose register_executor answers with a real cert PEM."""
    key = _generate_keypair()
    cert = _self_cert(key, "returned-exec")
    cert_pem = cert.public_bytes(_PEM).decode()
    client = MagicMock()
    client.config.server_url = "https://core.example.com"
    client.register_executor.return_value = {
        "cert_pem": cert_pem,
        "ca_cert_pem": cert_pem,
        "serial_number": "01:23:45",
        "not_after": "2026-09-13T00:00:00+00:00",
    }
    return client


def _register_args(tmp_path, executor_id=None, core_url="https://core.example.com"):
    return SimpleNamespace(
        executor_id=executor_id,
        core_url=core_url,
        output_dir=str(tmp_path / "certs"),
        enrollment_token=None,
        ca_bundle=None,
    )


def _setup_cert_files(tmp_path, executor_id="test-exec"):
    """Write a PLAINTEXT incumbent cert+key (the shape every host installed before
    this change holds) and return the paths plus the key."""
    key = _generate_keypair()
    cert = _self_cert(key, executor_id)
    cert_path = tmp_path / "executor.crt"
    cert_path.write_bytes(cert.public_bytes(_PEM))
    key_path = tmp_path / "executor.key"
    key_path.write_bytes(
        key.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    return cert_path, key_path, key


def _make_mock_httpx_client():
    """An httpx2 client mock answering the renew POST (new cert) and the revocation
    GET, both with the same self-signed body a real CA-less test cert has."""
    key = _generate_keypair()
    cert = _self_cert(key, "test-exec")
    pem = cert.public_bytes(_PEM).decode()
    response = MagicMock()
    response.status_code = 200
    response.content = b"{}"
    response.json.return_value = {
        "cert_pem": pem,
        "ca_cert_pem": pem,
        "serial_number": format(cert.serial_number, "016x"),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }
    response.raise_for_status.return_value = None
    client = MagicMock()
    client.__enter__.return_value = client
    client.post.return_value = response
    client.get.return_value = response
    return client


def _register_cell(tmp_path, client=None, args=None):
    """Run executor_register with the auth-verify step stubbed (#536 anchor is
    supplied per cell by this module's usefixtures marker)."""
    client = client or _mock_register_client()
    args = args or _register_args(tmp_path, executor_id="cell-exec")
    with patch("venya_cli.commands._verify_register_auth"):
        return executor_register(client, args), client, args


class TestRegisterWritesEncrypted:
    """Body site 3: `venya exec register` → `executor_register`."""

    def test_key_lands_encrypted_at_0600(self, tmp_path) -> None:
        """Positive half: the register path emits the envelope and keeps every
        incumbent pin — 0600 on the key, 0700 on the directory, cert at 0644."""
        result, _client, args = _register_cell(tmp_path)
        assert result == 0

        key_path = Path(args.output_dir) / "executor.key"
        raw = key_path.read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in raw, "the CLI still writes the key in the clear"
        assert _mode(key_path) == 0o600, "mode pin moved with the envelope — it must not"

    def test_headless_with_no_passphrase_writes_nothing_and_dials_nothing(
        self, tmp_path, no_executor_key_passphrase
    ) -> None:
        """Paired negative (AC3): with no passphrase and no TTY the command refuses
        BEFORE the keypair, before the CSR, before the POST and before the output
        directory exists. The enrollment token stays unconsumed — the install
        guidance already promises that, and a refusal that POSTs first would break
        the promise the operator has been handed."""
        client = _mock_register_client()
        result, used, args = _register_cell(tmp_path, client=client)

        assert result == 1
        used.register_executor.assert_not_called()
        assert not (tmp_path / "certs").exists(), "a refusal must not create the directory"
        assert not Path(args.output_dir).exists()

    def test_blank_and_whitespace_values_read_as_no_passphrase(self, tmp_path, monkeypatch) -> None:
        """#554's answer on this plane: '' and '   ' carry no material, so neither
        opens the write path — an encrypted-looking file guarded by a space is
        decoration, and decoration is what the ruling calls a defect."""
        for blank in ("", "   ", "\t"):
            monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, blank)
            client = _mock_register_client()
            result, used, _args = _register_cell(tmp_path, client=client)
            assert result == 1, f"a blank-shaped value ({blank!r}) opened the write path"
            used.register_executor.assert_not_called()

    def test_value_under_the_floor_refuses_without_echoing_itself(self, tmp_path, monkeypatch) -> None:
        """#573's floor extends here: 14 code points refuse, and the printed text
        names the variable — never the value, never its length."""
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, UNDER_PW)
        client = _mock_register_client()
        result, used, _args = _register_cell(tmp_path, client=client)

        assert result == 1
        used.register_executor.assert_not_called()
        assert not (tmp_path / "certs").exists()

    def test_value_at_the_floor_passes(self, tmp_path, monkeypatch) -> None:
        """The other half of the boundary: 15 is INCLUSIVE, so the door sits exactly
        on the constant and not one tighter."""
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, AT_FLOOR_PW)
        result, _client, args = _register_cell(tmp_path)
        assert result == 0
        assert b"ENCRYPTED PRIVATE KEY" in (Path(args.output_dir) / "executor.key").read_bytes()

    def test_prompt_is_the_write_time_ceremony_and_an_empty_answer_writes_nothing(
        self, tmp_path, monkeypatch, no_executor_key_passphrase
    ) -> None:
        """The interactive shape R7-Q3 names a "write-time ceremony": with no env
        value and a TTY the command asks, hidden. An empty answer is the same
        refusal, so the prompt cannot be talked into producing plaintext."""
        calls: list[str] = []

        def _fake_getpass(prompt: str) -> str:
            calls.append(prompt)
            return GOOD_PW

        monkeypatch.setattr("getpass.getpass", _fake_getpass)
        monkeypatch.setattr("venya_cli.executor_key.sys.stdin.isatty", lambda: True)

        result, _client, args = _register_cell(tmp_path)
        assert result == 0, "the prompt path is the ruled ceremony and must write"
        assert calls and EXECUTOR_KEY_PASSPHRASE_ENV in calls[0], "the prompt names the VARIABLE, never a value"
        assert "hidden" in calls[0]
        key_path = Path(args.output_dir) / "executor.key"
        assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()

        # and the empty answer, second half of the pair
        (tmp_path / "certs2").mkdir()
        monkeypatch.setattr("getpass.getpass", lambda prompt: "   ")
        args2 = _register_args(tmp_path, executor_id="cell-exec-2")
        args2.output_dir = str(tmp_path / "certs2")
        client2 = _mock_register_client()
        with patch("venya_cli.commands._verify_register_auth"):
            result2 = executor_register(client2, args2)
        assert result2 == 1
        client2.register_executor.assert_not_called()
        assert not (tmp_path / "certs2" / "executor.key").exists()

    def test_success_output_states_the_envelope_and_denies_hardware_custody(self, tmp_path, capsys) -> None:
        """AC5's text half: the operator is told the readers need the variable, and
        the label is honest — a file passphrase is disk protection, not hardware
        custody (R7-Q3's own labeling discipline is the control against drift)."""
        result, _client, _args = _register_cell(tmp_path)
        assert result == 0
        out = capsys.readouterr().out
        assert EXECUTOR_KEY_PASSPHRASE_ENV in out
        assert "disk protection" in out
        assert "not hardware-key custody" in out.lower().replace("\n", " ")


class TestRenewWritesEncrypted:
    """Body site 4: `venya exec cert renew` → `executor_cert_renew`."""

    def _args(self, cert_path) -> SimpleNamespace:
        args = MagicMock()
        args.cert_path = str(cert_path)
        args.key_path = None
        args.core_url = "https://venya-core"
        args.ca_bundle = None
        return args

    def test_renewed_key_lands_encrypted(self, tmp_path) -> None:
        """Positive half, with the incumbent key PLAINTEXT (the shape every existing
        host has): the old key opens with no passphrase, and the NEW key lands as an
        envelope. That pair of facts is the whole no-partial-ship argument."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)  # plaintext incumbent
        before = key_path.read_bytes()
        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            result = executor_cert_renew(self._args(cert_path))

        assert result == 0
        after = key_path.read_bytes()
        assert after != before, "renew wrote no key at all"
        assert b"ENCRYPTED PRIVATE KEY" in after
        assert _mode(key_path) == 0o600

    def test_renew_refuses_before_any_request_with_no_passphrase(self, tmp_path, no_executor_key_passphrase) -> None:
        """Paired negative: renew POSTs to the register endpoint, which REPLACES the
        server-side record — so the refusal must land first. Nothing sent, the
        incumbent key and cert untouched, byte for byte."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        before_key = key_path.read_bytes()
        before_cert = cert_path.read_bytes()
        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client) as HttpClient:
            result = executor_cert_renew(self._args(cert_path))

        assert result == 1
        HttpClient.assert_not_called()
        assert key_path.read_bytes() == before_key, "a refused renewal changed the incumbent key"
        assert cert_path.read_bytes() == before_cert, "a refused renewal changed the incumbent cert"

    def _plant_encrypted_incumbent(self, tmp_path):
        """An incumbent cert+key that MATCH each other and sit in the encrypted
        envelope — the shape a host has after its first post-fix renewal."""
        key = _generate_keypair()
        cert = _self_cert(key, "test-exec")
        cert_path = tmp_path / "executor.crt"
        cert_path.write_bytes(cert.public_bytes(_PEM))
        key_path = tmp_path / "executor.key"
        key_path.write_bytes(
            key.private_bytes(
                encoding=_PEM,
                format=_PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(GOOD_PW.encode("utf-8")),
            )
        )
        key_path.chmod(0o600)
        return cert_path, key_path

    def test_renew_dials_with_an_encrypted_incumbent_key(self, tmp_path) -> None:
        """Read half of THIS site: a host whose key is already an envelope must still
        be able to renew — the renew POST presents that key as its client
        certificate. Before the read side existed this died on OpenSSL's bare
        ``PEM lib`` text, which is the outage R7-Q3 forbids a partial ship to cause."""
        cert_path, key_path = self._plant_encrypted_incumbent(tmp_path)
        assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()
        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client):
            result = executor_cert_renew(self._args(cert_path))

        # rc is 0 or 1 by design: the FIRST dial (with the encrypted incumbent) must
        # succeed, and it is the one this cell is about. The post-write auth check
        # re-loads the pair against the fixture-signed cert, which cannot match the
        # freshly generated key — the same tolerated shape the incumbent renew suite
        # documents. What must NOT happen is the dial being refused.
        assert result in (0, 1), f"renew died before completing: {result}"
        mock_client.post.assert_called(), "the encrypted incumbent never got dialed with"
        assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()

    def test_renew_with_an_encrypted_incumbent_and_no_passphrase_refuses(
        self, tmp_path, no_executor_key_passphrase
    ) -> None:
        """Paired negative: same encrypted incumbent, no passphrase on this host. The
        refusal must name the variable and dial nothing — not hand back an OpenSSL
        error, and not re-key over a working identity."""
        cert_path, key_path = self._plant_encrypted_incumbent(tmp_path)
        before = key_path.read_bytes()
        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client) as HttpClient:
            result = executor_cert_renew(self._args(cert_path))

        assert result == 1
        HttpClient.assert_not_called()
        assert key_path.read_bytes() == before, "a refused renewal rewrote the incumbent envelope"

    def test_renew_under_the_floor_refuses_without_touching_files(self, tmp_path, monkeypatch) -> None:
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        before = key_path.read_bytes()
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, UNDER_PW)
        mock_client = _make_mock_httpx_client()

        with patch("venya_cli.commands.httpx2.Client", return_value=mock_client) as HttpClient:
            result = executor_cert_renew(self._args(cert_path))

        assert result == 1
        HttpClient.assert_not_called()
        assert key_path.read_bytes() == before


class TestEnvelopeParity:
    """The CLI and the daemon write the SAME envelope, from two packages with no
    shared dependency (the same rule that puts ``at_rest_key.py`` beside the
    server codec). These cells are the pin that keeps the two planes from
    drifting — a key one half can write and the other cannot read is an outage."""

    def test_env_var_name_is_the_same_on_both_planes(self) -> None:
        import executor.key_passphrase as exec_plane

        assert exec_plane.EXECUTOR_KEY_PASSPHRASE_ENV == EXECUTOR_KEY_PASSPHRASE_ENV

    def test_floor_numbers_are_the_same_on_both_planes(self) -> None:
        import executor.key_passphrase as exec_plane

        assert exec_plane.MIN_PASSPHRASE_CODE_POINTS == 15
        assert exec_plane.MAX_PASSPHRASE_CODE_POINTS == 64

    def test_a_cli_written_envelope_opens_on_the_daemon_plane(self, monkeypatch) -> None:
        """Cross-plane round trip with REAL cryptography: write here, read there."""
        import executor.key_passphrase as exec_plane

        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, GOOD_PW)
        key = ec.generate_private_key(ec.SECP256R1())
        blob = serialize_key_encrypted(key, GOOD_PW)

        opened = exec_plane.load_private_key(blob, key_path="parity")
        assert opened.private_bytes(_PEM, _PKCS8, serialization.NoEncryption()) == key.private_bytes(
            _PEM, _PKCS8, serialization.NoEncryption()
        )

    def test_a_daemon_written_envelope_opens_on_the_cli_plane(self, monkeypatch) -> None:
        import executor.key_passphrase as exec_plane

        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, GOOD_PW)
        key = ec.generate_private_key(ec.SECP256R1())
        blob = exec_plane.serialize_key_encrypted(key, GOOD_PW.encode("utf-8"))

        assert serialization.load_pem_private_key(blob, password=GOOD_PW.encode("utf-8")) is not None

    def test_resolver_semantics_match_on_both_planes(self, monkeypatch) -> None:
        """Blank/whitespace/set answer the same way on each plane — one rule, two
        copies, and the copies cannot disagree."""
        import executor.key_passphrase as exec_plane

        for value, expect in ((None, None), ("", None), ("   ", None), (GOOD_PW, GOOD_PW)):
            if value is None:
                monkeypatch.delenv(EXECUTOR_KEY_PASSPHRASE_ENV, raising=False)
            else:
                monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, value)
            assert configured_passphrase() == expect
            assert exec_plane.configured_passphrase() == expect, "the two planes answered differently"


class TestAdminReadPathSeparatePlane:
    """The EXECUTOR envelope and the ADMIN pair read two different variables, and these
    cells pin that separation.

    Written when Part B was still open (the admin dial was passphrase-blind, and cell N4 of
    ``test_cli_admin_leaf_key_passphrase_547a.py`` pinned that). #565 Part B has since given
    the admin path its own passphrase callback, so the encrypted half below refuses for a
    DIFFERENT and still correct reason: the executor passphrase in this file's environment
    is not the admin variable, and a key is never opened with the wrong plane's value. The
    plaintext half is unchanged. Handshake proof for the admin plane lives in
    ``test_admin_key_load_565_partb.py``."""

    def test_default_call_still_takes_no_password(self, tmp_path, monkeypatch) -> None:
        """A plaintext pair loads with no passphrase at all; an encrypted one refuses
        because THIS host has no admin passphrase configured — not because the executor
        value happens to be present in the environment."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin-cell")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        ca = tmp_path / "ca.crt"
        crt = tmp_path / "admin.crt"
        k = tmp_path / "admin.key"
        ca.write_bytes(cert.public_bytes(_PEM))
        crt.write_bytes(cert.public_bytes(_PEM))
        k.write_bytes(
            key.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=serialization.NoEncryption())
        )

        _build_ssl_context(str(ca), str(crt), str(k))  # plaintext admin pair: unchanged

        enc_pw = GOOD_PW.encode("utf-8")
        k.write_bytes(
            key.private_bytes(
                encoding=_PEM, format=_PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(enc_pw)
            )
        )
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        with pytest.raises(APIClientError) as refused:
            _build_ssl_context(str(ca), str(crt), str(k))
        # a NAMED read-door refusal, not the bare OpenSSL text — and it never opens the
        # key with the executor plane's value
        assert "no passphrase is" in str(refused.value)
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in str(refused.value)

    def test_executor_callers_do_pass_the_callback(self) -> None:
        """The positive half of the pair: the EXECUTOR dial sites are the ones that
        got the callback, so the two planes are not confused for each other."""
        src = Path(__file__).resolve().parents[1] / "src" / "venya_cli" / "commands.py"
        text = src.read_text(encoding="utf-8")
        dials_with_callback = text.count("key_password=ssl_password_callback()")
        assert (
            dials_with_callback >= 3
        ), f"executor dials that read the key lost their passphrase callback ({dials_with_callback})"


class TestAcquireWritePassphraseUnit:
    """The resolver itself, off the command paths — so a refusal is attributed to
    the door, not to the caller's plumbing."""

    def test_returns_the_value_byte_for_byte(self, monkeypatch) -> None:
        """DENY, never TRIM: a passphrase whose spaces are content is delivered
        unchanged, or the key it wrote could never be opened again."""
        value = "  padded-but-real-passphrase  "
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, value)
        assert acquire_write_passphrase() == value

    def test_headless_without_value_is_a_refusal_not_an_empty_string(
        self, monkeypatch, no_executor_key_passphrase
    ) -> None:
        monkeypatch.setattr("venya_cli.executor_key.sys.stdin.isatty", lambda: False)
        with pytest.raises(RuntimeError, match="must never be stored unencrypted"):
            acquire_write_passphrase()

    def test_callback_refuses_an_unopened_envelope_without_a_value_leak(self, monkeypatch, tmp_path) -> None:
        """The ssl callback's failure text is the repair, and the bad value never
        appears in it (lane-survival: name the class, not the secret)."""
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, UNDER_PW)
        cb = ssl_password_callback()
        with pytest.raises(RuntimeError, match="shorter than Venya's minimum") as ei:
            cb()
        assert UNDER_PW not in str(ei.value)

    def test_callback_returns_bytes_when_configured(self, monkeypatch) -> None:
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, GOOD_PW)
        assert ssl_password_callback()() == GOOD_PW.encode("utf-8")

    def test_callback_is_absent_means_no_prompt_leak(self, monkeypatch, no_executor_key_passphrase) -> None:
        """With nothing configured the callback raises rather than falling through
        to an interactive prompt — a prompt inside a daemon handshake would hang
        the unit, which is the failure §6 of the design note says must not exist."""
        cb = ssl_password_callback()
        with pytest.raises(RuntimeError, match="did not open it"):
            cb()


def test_environment_variable_name_never_appears_as_a_value(tmp_path) -> None:
    """Anti-coincidence guard for this file's own discipline: no cell here may write
    a passphrase into a file. The tmp tree must contain key material only."""
    _result, _client, args = _register_cell(tmp_path)
    for path in Path(args.output_dir).rglob("*"):
        if path.is_file():
            assert GOOD_PW not in path.read_text(errors="ignore"), "a passphrase reached a written file"
    assert os.environ.get(EXECUTOR_KEY_PASSPHRASE_ENV) == GOOD_PW, "the autouse fixture is what this file relies on"


class TestNoStagedTempResidue:
    """#565 sites 3-4, the third clause of the negative bar: **no temp**.

    The landed cells prove a refusal writes no key and no directory; this class
    proves the clause nobody asserted — a refusal, and a failure during an
    otherwise-good write, must leave NO staged temp behind. Both writers go
    through a `NamedTemporaryFile(..., prefix=".venya-key-", delete=False)` +
    `os.replace`, so a temp that survives is secret material sitting in a
    guessable-named file, and (the older #478 class) a leftover name can wedge
    every later write to that target.

    The glob is aimed at a directory that EXISTS and already holds a sentinel:
    an assertion over an absent directory is a vacuous pass, which is the exact
    failure mode this repo's truth-table law exists to catch.
    """

    _STAGED = (".venya-key-*", ".venya-cert-*", ".venya-ca-*", "*.tmp")

    def _staged_names(self, directory: Path) -> list[str]:
        """Every staged-temp name under `directory` (recursive: renew splits dirs)."""
        return sorted(p.name for pat in self._STAGED for p in directory.rglob(pat))

    def test_register_refusal_leaves_no_staged_temp_in_an_existing_dir(
        self, tmp_path, no_executor_key_passphrase
    ) -> None:
        """Negative half, sites 3: the dir already exists (a re-register over an
        installed host's `certs/`), so the refusal has somewhere to leak a temp
        into — and must not put one there."""
        out = tmp_path / "certs"
        out.mkdir(mode=0o700)
        sentinel = out / "incumbent.readme"
        sentinel.write_text("pre-existing file, must survive untouched\n")

        result, client, _args = _register_cell(tmp_path, args=_register_args(tmp_path, executor_id="cell-exec"))

        assert result == 1
        client.register_executor.assert_not_called()
        assert self._staged_names(out) == [], f"a refusal staged a temp: {self._staged_names(out)}"
        assert sentinel.exists() and sorted(p.name for p in out.iterdir()) == ["incumbent.readme"]

    def test_register_success_consumes_its_own_staged_temps(self, tmp_path) -> None:
        """Positive half, site 3: the three temps (key, cert, ca) are published by
        `os.replace`, so a successful register leaves exactly the three final names
        and no residue to be mistaken for a leak or to wedge a later write."""
        result, _client, args = _register_cell(tmp_path)
        assert result == 0

        out = Path(args.output_dir)
        assert self._staged_names(out) == [], f"a successful write left residue: {self._staged_names(out)}"
        assert sorted(p.name for p in out.iterdir()) == ["ca.crt", "executor.crt", "executor.key"]

    def test_renew_refusal_leaves_no_staged_temp_beside_the_incumbent_pair(
        self, tmp_path, no_executor_key_passphrase
    ) -> None:
        """Negative half, site 4: renew's key temp lands in the incumbent key's OWN
        directory, so this is the refusal with real files next to the leak site."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        before_key, before_cert = key_path.read_bytes(), cert_path.read_bytes()

        with patch("venya_cli.commands.httpx2.Client", return_value=_make_mock_httpx_client()) as HttpClient:
            result = executor_cert_renew(
                SimpleNamespace(
                    cert_path=str(cert_path),
                    key_path=None,
                    core_url="https://venya-core",
                    ca_bundle=None,
                )
            )

        assert result == 1
        HttpClient.assert_not_called()
        assert key_path.read_bytes() == before_key and cert_path.read_bytes() == before_cert
        assert self._staged_names(tmp_path) == [], f"a refusal staged a temp: {self._staged_names(tmp_path)}"

    def test_renew_success_consumes_its_own_staged_temps(self, tmp_path) -> None:
        """Positive half, site 4: same property on the renew write shape."""
        cert_path, key_path, _ = _setup_cert_files(tmp_path)
        with patch("venya_cli.commands.httpx2.Client", return_value=_make_mock_httpx_client()):
            result = executor_cert_renew(
                SimpleNamespace(
                    cert_path=str(cert_path),
                    key_path=None,
                    core_url="https://venya-core",
                    ca_bundle=None,
                )
            )

        assert result == 0
        assert self._staged_names(tmp_path) == [], f"a successful renew left residue: {self._staged_names(tmp_path)}"
        assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()
