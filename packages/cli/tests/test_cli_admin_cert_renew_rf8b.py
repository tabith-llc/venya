# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-8b — `venya admin cert renew`: mint a fresh short-lived admin certificate (client side).

Two facts decide the shape of this command, and the cells below are built around them.

1. The mint route is SESSION-shaped. `routes/admin_certs.py::_require_human_session`
   refuses a certificate-shaped caller with a 403, and RF-6 §2.2 makes authorizing
   issuance with the caller's existing admin certificate "not an option". So renew
   forces a session bearer (the headless admin-mTLS exemption is narrowed for this one
   subcommand at the `run_command` chokepoint) and refuses LOUDLY, client-side, if no
   session exists — a cert-only renewal is never shipped as a request the core would
   only deny.
2. The mint must NOT present the admin pair. `APIClient.use_session_only_transport()`
   rebuilds the transport with no client credential. That is the hole that STOPPED this
   leg: the RF-8a dial guard refuses any admin-pair request whose certificate has
   lapsed, and its refusal text tells the operator to run *this* command — so without
   the seam, the primary case (a cert that died mid-session) could not renew at all.

The seam is DEFAULT OFF and that is proved, not asserted: the paired cells show a
normal admin dial still presents the pair and still trips the expiry guard.

Truth-table law (AGENTS.md): every positive half here is paired with the shape that
must be rejected — no session, no output path, a declined ceremony, an empty response,
a failed write, and key material that must never appear in output.

No network, no VM, no ceremony: the transport factory is stubbed at its build seam and
FIDO2 elevation is patched at `_elevate`.
"""

import datetime
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientAuthenticationError, APIClientError
from venya_cli.cli import create_parser
from venya_cli.commands import (
    ADMIN_CSR_CURVE_NAMES,
    admin_cert_expiry_refusal,
    cmd_admin_cert,
    cmd_admin_cert_renew,
    run_command,
)

UTC = datetime.UTC
# dev-only test passphrase (#547a); value is not secret and not used anywhere live
LEAF_PASSPHRASE = "test_passphrase"
ISSUER = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
    ]
)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pair(tmp_path: Path, name: str, lifetime_min: int) -> tuple[Path, Path, x509.Certificate]:
    """Write a real admin-shaped cert/key pair. lifetime_min < 0 -> already expired."""
    now = datetime.datetime.now(UTC)
    if lifetime_min < 0:
        # Expired: the WHOLE window has to sit in the past, or the builder refuses
        # (not_valid_after must be after not_valid_before).
        not_before = now + datetime.timedelta(minutes=lifetime_min - 30)
        not_after = now + datetime.timedelta(minutes=lifetime_min)
    else:
        not_before = now - datetime.timedelta(minutes=5)
        not_after = now + datetime.timedelta(minutes=lifetime_min)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(f"admin-bot@{name}"))
        .issuer_name(ISSUER)
        .public_key(key.public_key())
        .serial_number(0x2222_3333)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    kp.chmod(0o600)
    return cp, kp, cert


def _minted_cert(cn: str = "admin-bot@workstation") -> bytes:
    """A plausible core-signed answer: fresh window, server-built subject, its own key."""
    now = datetime.datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP384R1())  # deliberately NOT the request's key
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ISSUER)
        .public_key(key.public_key())
        .serial_number(0xAAAA_BBBB)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(seconds=3600))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class _StubResponse:
    def __init__(self, payload: dict, status_code: int = 201) -> None:
        self._payload = payload
        self.status_code = status_code
        self.content = b"{}"

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx2

            raise httpx2.HTTPStatusError(
                f"HTTP {self.status_code}", request=MagicMock(), response=self  # type: ignore[arg-type]
            )

    def json(self) -> dict:
        return self._payload


class _StubTransport:
    """Stand-in for the dial transport — records what the client would have put on the wire."""

    def __init__(self, payload: dict | None = None, error: Exception | None = None) -> None:
        self.payload = payload if payload is not None else {"certificate_pem": _minted_cert().decode()}
        self.error = error
        self.calls: list[dict] = []

    def request(self, method, path, json=None, params=None, headers=None, **kwargs):
        self.calls.append({"method": method, "path": path, "json": json, "headers": headers or {}})
        if self.error is not None:
            raise self.error
        return _StubResponse(self.payload)

    def close(self) -> None:
        pass


def _dialing(stub: _StubTransport):
    """Stub the transport BUILD rather than the `_http` field.

    `use_session_only_transport()` deliberately drops any staged transport, because an
    earlier request in the process (the `/health` advisory) may have built a context
    that DOES carry the pair. A test that injected `client._http = stub` would have the
    stub discarded and then dial for real; patching the factory keeps the production
    build path in play and still records the request.
    """
    return patch("venya_cli.api_client.httpx2.Client", return_value=stub)


def _never_dial():
    """The zero-network guarantee, enforced: any transport build fails the cell."""
    return patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("a transport was built"))


def _client(tmp_path: Path, cert_path: Path, key_path: Path, *, token: str | None = "session-bearer") -> APIClient:
    """A REAL APIClient, so headers, the anchor check and the TLS seam are production code."""
    cfg = tmp_path / "config.json"
    cfg.write_text('{"server_url": "https://core.test:8443"}', encoding="utf-8")
    os.environ["VENYA_CONFIG"] = str(cfg)
    os.environ["SSL_CERT_FILE"] = str(cert_path)  # satisfy the anchor check without a real CA
    os.environ["VENYA_ADMIN_CERT"] = str(cert_path)
    os.environ["VENYA_ADMIN_KEY"] = str(key_path)
    client = APIClient()
    if token is None:
        client.config._data.pop("access_token", None)
    else:
        client.config.access_token = token
    return client


def _args(cert_path: object, key_path: object, **overrides: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "cert_path": str(cert_path) if cert_path is not None else None,
        "key_path": str(key_path) if key_path is not None else None,
        "user_id": None,
        "server_url": None,
        "command": "admin",
        "admin_command": "cert",
        "admin_cert_command": "renew",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("VENYA_ADMIN_CERT", "VENYA_ADMIN_KEY", "VENYA_CONFIG", "SSL_CERT_FILE", "VENYA_SERVER_URL"):
        monkeypatch.delenv(var, raising=False)
    # #547a: an admin private key is now only written encrypted, so every cell here that
    # exercises the write path supplies the passphrase. Converted by ADDING the variable
    # — no assertion in this file was deleted or relaxed. (The refusal halves, including
    # the proof that the written key is not mTLS-loadable yet, live in
    # tests/test_cli_admin_leaf_key_passphrase_547a.py.)
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
    yield


class TestParserSurface:
    """T1 — the leaf exists, parses, and `--help` advertises it."""

    def test_renew_parses_into_the_expected_namespace(self):
        ns = create_parser().parse_args(["admin", "cert", "renew"])
        assert ns.command == "admin"
        assert ns.admin_command == "cert"
        assert ns.admin_cert_command == "renew"
        assert ns.cert_path is None and ns.key_path is None and ns.server_url is None

    def test_renew_flags_reach_the_namespace(self):
        ns = create_parser().parse_args(
            ["admin", "cert", "renew", "--cert-path", "/tmp/n.crt", "--key-path", "/tmp/n.key", "--user-id", "jd"]
        )
        assert (ns.cert_path, ns.key_path, ns.user_id) == ("/tmp/n.crt", "/tmp/n.key", "jd")

    def test_help_lists_renew_with_the_windows_clause(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            create_parser().parse_args(["admin", "cert", "renew", "--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "renew" in out
        assert "interactive desktop session" in out  # the Windows carrier line (§4)

    def test_group_help_names_both_leaves(self, capsys):
        with pytest.raises(SystemExit):
            create_parser().parse_args(["admin", "cert", "--help"])
        out = capsys.readouterr().out
        assert "status" in out and "renew" in out


class TestHappyPath:
    """T2 — bearer + elevation header, `csr_pem` only, the pair written at ruled modes."""

    def test_mint_writes_pair_with_ruled_modes_and_headers(self, tmp_path, capsys):
        old_crt, old_key, _ = _pair(tmp_path, "old", 30)
        out_crt, out_key = tmp_path / "renewed.crt", tmp_path / "renewed.key"
        client = _client(tmp_path, old_crt, old_key)
        stub = _StubTransport()

        with _dialing(stub), patch("venya_cli.commands._elevate", return_value="elev-token") as elevate:
            rc = cmd_admin_cert_renew(client, _args(out_crt, out_key))

        assert rc == 0
        elevate.assert_called_once_with(client)
        mint = stub.calls[-1]
        assert mint["path"] == "/api/v1/admin/certs/issue"
        assert set(mint["json"]) == {"csr_pem"}  # the mint body is a CSR and nothing else
        assert mint["headers"]["Authorization"] == "Bearer session-bearer"
        assert mint["headers"]["X-Elevation-Token"] == "elev-token"
        # modes: key 0600 is the installer's admin.key posture; cert 0644 is the
        # #376/#388 pinned posture for public material.
        assert out_key.stat().st_mode & 0o777 == 0o600
        assert out_crt.stat().st_mode & 0o777 == 0o644
        assert x509.load_pem_x509_certificate(out_crt.read_bytes())
        out = capsys.readouterr().out
        assert "STATUS: OK" in out
        assert "aaaabbbb" in out  # canonical serial: lowercase, zero-padded to 16
        assert "+00:00" in out  # offset-aware expiry
        assert "this workstation's clock" in out  # the honesty clause
        assert "not revoked" in out  # renew is not a revoke, said out loud

    def test_write_is_atomic_and_leaves_no_temp_behind(self, tmp_path):
        crt, key, _ = _pair(tmp_path, "old", 30)
        out_dir = tmp_path / "pair"
        client = _client(tmp_path, crt, key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            rc = cmd_admin_cert_renew(client, _args(out_dir / "a.crt", out_dir / "a.key"))
        assert rc == 0
        assert sorted(p.name for p in out_dir.iterdir()) == ["a.crt", "a.key"]
        assert out_dir.stat().st_mode & 0o777 == 0o700

    def test_default_paths_come_from_the_env_pair(self, tmp_path, capsys):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            rc = cmd_admin_cert_renew(client, _args(None, None))
        assert rc == 0
        assert str(crt) in capsys.readouterr().out

    def test_expiry_is_read_back_from_the_cert_not_computed_locally(self, tmp_path, capsys):
        """§4: the core's clock is the authority — the printed window is the PEM's."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        issued = _minted_cert()
        client = _client(tmp_path, crt, key)
        stub = _StubTransport(payload={"certificate_pem": issued.decode()})
        with _dialing(stub), patch("venya_cli.commands._elevate", return_value="t"):
            assert cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 0
        expires_line = next(line for line in capsys.readouterr().out.splitlines() if "Expires:" in line)
        assert x509.load_pem_x509_certificate(issued).not_valid_after_utc.isoformat() in expires_line

    def test_mint_happens_once_one_ceremony(self, tmp_path):
        """The elevation token is spent server-side; a second POST would re-present it."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        stub = _StubTransport()
        with _dialing(stub), patch("venya_cli.commands._elevate", return_value="t"):
            assert cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 0
        assert [c["path"] for c in stub.calls] == ["/api/v1/admin/certs/issue"]


class TestSessionIsTheCredential:
    """T3 + the §5.3 half: a cert-shaped caller is refused LOUDLY, client-side."""

    def test_no_session_bearer_refuses_locally_with_zero_requests(self, tmp_path, capsys):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key, token=None)
        with _never_dial(), patch("venya_cli.commands._elevate") as elevate:
            rc = cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key"))
        assert rc == 1
        elevate.assert_not_called()  # nobody was asked to touch a key
        err = capsys.readouterr().err
        assert "venya login" in err
        assert "login session" in err

    def test_run_command_narrows_the_mtls_exemption_for_renew_only(self, tmp_path):
        """The chokepoint half: a configured pair must NOT let renew skip authentication."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        os.environ["VENYA_ADMIN_CERT"] = str(crt)
        os.environ["VENYA_ADMIN_KEY"] = str(key)
        ns = SimpleNamespace(
            command="admin",
            admin_command="cert",
            admin_cert_command="renew",
            cert_path=str(tmp_path / "n.crt"),
            key_path=str(tmp_path / "n.key"),
            server_url=None,
            user_id=None,
        )
        with (
            patch("venya_cli.commands.APIClient") as client_cls,
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.commands.cmd_admin_cert", return_value=0) as dispatched,
        ):
            inst = client_cls.return_value
            inst.has_admin_mtls = True
            inst.config.access_token = None
            rc = run_command(ns)
        assert rc == 0
        dispatched.assert_called_once()
        inst.authenticate.assert_called_once_with(user_id=None)  # ceremony FORCED, not skipped

    def test_other_admin_commands_keep_the_headless_exemption(self, tmp_path):
        """Paired negative: `admin list` with a pair configured still skips the ceremony."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        os.environ["VENYA_ADMIN_CERT"] = str(crt)
        os.environ["VENYA_ADMIN_KEY"] = str(key)
        ns = SimpleNamespace(command="admin", admin_command="list", server_url=None, user_id=None)
        with (
            patch("venya_cli.commands.APIClient") as client_cls,
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.commands.cmd_admin", return_value=0),
        ):
            inst = client_cls.return_value
            inst.has_admin_mtls = True
            inst.config.access_token = None
            assert run_command(ns) == 0
        inst.authenticate.assert_not_called()


class TestSessionOnlyTransport:
    """The pair to the STOP: the mint carries NO client credential, and the default is
    byte-identical for every other request."""

    @staticmethod
    def _spy(monkeypatch) -> list:
        import venya_cli.api_client as api

        real = api._build_ssl_context
        seen: list[tuple] = []

        def spy(cafile, certfile, keyfile):
            seen.append((certfile, keyfile))
            return real(cafile, certfile, keyfile)

        monkeypatch.setattr(api, "_build_ssl_context", spy)
        return seen

    def test_mint_transport_presents_no_client_cert(self, tmp_path, monkeypatch):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        seen = self._spy(monkeypatch)
        client.use_session_only_transport()
        client._http = None
        assert client._http is not None  # building it IS the assertion target
        assert seen[-1] == (None, None), seen
        client.close()

    def test_default_transport_still_presents_the_pair(self, tmp_path, monkeypatch):
        """DEFAULT OFF, proved: nothing was asked for, nothing changed."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        seen = self._spy(monkeypatch)
        client._http = None
        assert client._http is not None
        assert seen[-1] == (str(crt), str(key)), seen
        client.close()

    def test_the_seam_drops_a_staged_transport(self, tmp_path):
        """The rebuild is the point: a transport built earlier DID carry the pair."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        seen = []
        import venya_cli.api_client as api

        real = api._build_ssl_context
        monkeypatch_pair = patch.object(
            api,
            "_build_ssl_context",
            side_effect=lambda cafile, certfile, keyfile: seen.append((certfile, keyfile))
            or real(cafile, certfile, keyfile),
        )
        with monkeypatch_pair:
            assert client._http is not None  # an earlier request built it WITH the pair
            client.use_session_only_transport()
            assert client._http is not None  # and the mint rebuilds without it
        assert seen == [(str(crt), str(key)), (None, None)], seen
        client.close()

    def test_expired_pair_renews_rather_than_hitting_the_dial_guard(self, tmp_path, capsys):
        """THE cell that closes the STOP: expired pair configured + session bearer →
        renew dials (the guard has no certificate to check) and mints."""
        dead_crt, dead_key, _ = _pair(tmp_path, "dead", -10)
        refusal = admin_cert_expiry_refusal(str(dead_crt), site="this admin request")
        assert refusal is not None and "venya admin cert renew" in refusal  # 8a's own text
        out_crt, out_key = tmp_path / "new.crt", tmp_path / "new.key"
        client = _client(tmp_path, dead_crt, dead_key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            rc = cmd_admin_cert_renew(client, _args(out_crt, out_key))
        assert rc == 0
        assert out_crt.exists() and out_key.exists()
        assert "STATUS: OK" in capsys.readouterr().out

    def test_without_the_seam_the_guard_still_refuses_an_expired_pair(self, tmp_path):
        """Paired negative — the landed RF-8a behavior is UNCHANGED for every other
        command: an expired admin pair still refuses before any transport exists."""
        dead_crt, dead_key, _ = _pair(tmp_path, "dead", -10)
        client = _client(tmp_path, dead_crt, dead_key)
        with _never_dial(), pytest.raises(APIClientError) as excinfo:
            client.get("/api/v1/health")
        assert "venya admin cert renew" in str(excinfo.value)
        client.close()


class TestServerRefusalsAndCeremony:
    """T4/T5/T7/T8 — readable refusals, and NOTHING written."""

    @pytest.mark.parametrize(
        "detail",
        [
            "Admin certificate issuance requires a login session, not an admin certificate. Repair: venya login.",
            "A login session is required to issue an admin certificate. Repair: venya login.",
        ],
    )
    def test_403_and_401_shapes_surface_as_refusals_with_no_writes(self, tmp_path, capsys, detail):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        out_crt, out_key = tmp_path / "n.crt", tmp_path / "n.key"
        client = _client(tmp_path, crt, key)
        with (
            _dialing(_StubTransport(error=APIClientError(detail))),
            patch("venya_cli.commands._elevate", return_value="t"),
        ):
            rc = cmd_admin_cert_renew(client, _args(out_crt, out_key))
        assert rc == 1
        err = capsys.readouterr().err
        assert "venya login" in err
        assert detail in err  # the server's own cause is relayed, not swallowed
        assert not out_crt.exists() and not out_key.exists()

    def test_declined_ceremony_means_zero_mints_and_zero_writes(self, tmp_path, capsys):
        """T7 — the operator does not touch the key: no mint POST, nothing on disk."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        out_crt, out_key = tmp_path / "n.crt", tmp_path / "n.key"
        client = _client(tmp_path, crt, key)
        stub = _StubTransport()
        with (
            _dialing(stub),
            patch("venya_cli.commands._elevate", side_effect=APIClientError("Please touch your security key")),
        ):
            rc = cmd_admin_cert_renew(client, _args(out_crt, out_key))
        assert rc == 1
        assert stub.calls == []
        assert "touch your security key" in capsys.readouterr().err
        assert not out_crt.exists() and not out_key.exists()

    def test_authentication_error_subclass_lands_on_the_same_arm(self, tmp_path):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        with (
            _dialing(_StubTransport()),
            patch("venya_cli.commands._elevate", side_effect=APIClientAuthenticationError("key rejected")),
        ):
            assert cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 1

    def test_missing_certificate_pem_is_a_failure_with_no_writes(self, tmp_path, capsys):
        """T8 — an answer with no certificate is not a silent success."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        with (
            _dialing(_StubTransport(payload={"something_else": "x"})),
            patch("venya_cli.commands._elevate", return_value="t"),
        ):
            rc = cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key"))
        assert rc == 1
        assert "no certificate" in capsys.readouterr().err
        assert not (tmp_path / "n.crt").exists() and not (tmp_path / "n.key").exists()


class TestRefusalsBeforeAnyNetwork:
    """T6 — no output path named: refuse before the ceremony and before any request."""

    def test_no_cert_path_and_no_env_refuses_locally(self, tmp_path, monkeypatch, capsys):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        # Unset AFTER the client exists: the handler resolves the output path from the
        # environment at call time, which is the moment this refusal belongs to.
        monkeypatch.delenv("VENYA_ADMIN_CERT")
        with _never_dial(), patch("venya_cli.commands._elevate") as elevate:
            rc = cmd_admin_cert_renew(client, _args(None, tmp_path / "k.key"))
        assert rc == 1
        elevate.assert_not_called()
        assert "VENYA_ADMIN_CERT" in capsys.readouterr().err

    def test_no_key_path_refuses_and_names_the_key_repair(self, tmp_path, monkeypatch, capsys):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        monkeypatch.delenv("VENYA_ADMIN_KEY")
        with _never_dial(), patch("venya_cli.commands._elevate") as elevate:
            rc = cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", None))
        assert rc == 1
        elevate.assert_not_called()
        assert "VENYA_ADMIN_KEY" in capsys.readouterr().err

    def test_the_old_pair_is_never_deleted_or_revoked(self, tmp_path):
        """Ruling: renew must not revoke, delete or overwrite the old material."""
        dead_crt, dead_key, before = _pair(tmp_path, "dead", -10)
        client = _client(tmp_path, dead_crt, dead_key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            rc = cmd_admin_cert_renew(client, _args(tmp_path / "fresh.crt", tmp_path / "fresh.key"))
        assert rc == 0
        assert dead_crt.exists() and dead_key.exists()
        assert x509.load_pem_x509_certificate(dead_crt.read_bytes()).serial_number == before.serial_number


class TestWriteFailure:
    """T9 — a staged temp never survives, a partial file never lands, a mint is never
    discarded quietly."""

    def test_replace_failure_unlinks_temps_and_reports_the_mint(self, tmp_path, monkeypatch, capsys):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        out_crt, out_key = tmp_path / "n.crt", tmp_path / "n.key"
        client = _client(tmp_path, crt, key)
        monkeypatch.setattr(os, "replace", MagicMock(side_effect=OSError("disk gone")))
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            rc = cmd_admin_cert_renew(client, _args(out_crt, out_key))
        assert rc == 1
        err = capsys.readouterr().err
        assert "MINTED" in err and "could not be written" in err
        assert "aaaabbbb" in err  # the serial of the mint that could not be stored
        assert not out_crt.exists() and not out_key.exists()
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".venya-")] == []

    def test_unexpected_abort_also_leaves_no_plaintext_behind(self, tmp_path, monkeypatch):
        """The #476 shape: a non-OSError abort must not leave staged key material."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        monkeypatch.setattr(os, "replace", MagicMock(side_effect=KeyboardInterrupt))
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            with pytest.raises(KeyboardInterrupt):
                cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key"))
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".venya-")] == []
        assert not (tmp_path / "n.key").exists()


class TestCsrShape:
    """T10 + T11 — what gets built client-side, and what must never be printed."""

    @staticmethod
    def _run(tmp_path) -> _StubTransport:
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        stub = _StubTransport()
        with _dialing(stub), patch("venya_cli.commands._elevate", return_value="t"):
            assert cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 0
        return stub

    def test_csr_curve_is_admin_accepted(self, tmp_path):
        csr = x509.load_pem_x509_csr(self._run(tmp_path).calls[-1]["json"]["csr_pem"].encode())
        assert csr.public_key().curve.name == "secp256r1"
        assert csr.public_key().curve.name in ADMIN_CSR_CURVE_NAMES

    def test_the_mirrored_curve_list_matches_the_server_authority(self):
        """The CLI cannot import server, so parity is asserted HERE instead of by luck."""
        from server.ca import accepted_csr_curve_names

        assert ADMIN_CSR_CURVE_NAMES == tuple(accepted_csr_curve_names())

    def test_csr_subject_claims_no_identity(self, tmp_path):
        """The server discards the subject; the client must not pretend otherwise."""
        csr = x509.load_pem_x509_csr(self._run(tmp_path).calls[-1]["json"]["csr_pem"].encode())
        assert not any(attr.oid == NameOID.COMMON_NAME for attr in csr.subject)

    def test_no_private_key_material_ever_reaches_output(self, tmp_path, capsys):
        """T11 — the zero-plaintext negative."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            assert cmd_admin_cert_renew(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 0
        captured = capsys.readouterr()
        assert b"PRIVATE KEY" in (tmp_path / "n.key").read_bytes()  # the key exists...
        assert "PRIVATE KEY" not in captured.out  # ...on disk, never on a screen
        assert "PRIVATE KEY" not in captured.err


class TestNoNetworkGuarantee:
    """T12 — the RF-8a read-local gate still captures `status`, and only `status`."""

    def test_status_still_dispatches_before_the_client_exists(self, tmp_path):
        crt, _key, _ = _pair(tmp_path, "cfg", 30)
        ns = SimpleNamespace(
            command="admin", admin_command="cert", admin_cert_command="status", cert_path=str(crt), within=None
        )
        with patch("venya_cli.commands.APIClient") as client_cls:
            assert run_command(ns) == 0
        client_cls.assert_not_called()

    def test_status_with_no_admin_key_env_still_makes_no_request(self, tmp_path, monkeypatch):
        """8a regression, restated here because renew is the change that could break it."""
        monkeypatch.delenv("VENYA_ADMIN_KEY", raising=False)
        crt, _key, _ = _pair(tmp_path, "cfg", 30)
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(crt))
        ns = SimpleNamespace(
            command="admin", admin_command="cert", admin_cert_command="status", cert_path=None, within=None
        )
        with patch("venya_cli.commands.APIClient") as client_cls:
            assert run_command(ns) == 0
        client_cls.assert_not_called()

    def test_renew_is_not_swept_into_the_read_local_gate(self, tmp_path):
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        os.environ["VENYA_ADMIN_CERT"] = str(crt)
        os.environ["VENYA_ADMIN_KEY"] = str(key)
        ns = SimpleNamespace(
            command="admin",
            admin_command="cert",
            admin_cert_command="renew",
            cert_path=str(tmp_path / "n.crt"),
            key_path=str(tmp_path / "n.key"),
            server_url=None,
            user_id=None,
        )
        with (
            patch("venya_cli.commands.APIClient") as client_cls,
            patch("venya_cli.commands.version_advisory"),
            patch("venya_cli.commands.cmd_admin_cert", return_value=0),
        ):
            inst = client_cls.return_value
            inst.has_admin_mtls = False
            inst.config.access_token = "tok"
            assert run_command(ns) == 0
        client_cls.assert_called_once()  # it needs the network, so it got the client

    def test_direct_dispatch_reaches_the_renew_handler(self, tmp_path):
        """`cmd_admin_cert`'s own branch (not the pre-gate) answers renew."""
        crt, key, _ = _pair(tmp_path, "cfg", 30)
        client = _client(tmp_path, crt, key)
        with _dialing(_StubTransport()), patch("venya_cli.commands._elevate", return_value="t"):
            assert cmd_admin_cert(client, _args(tmp_path / "n.crt", tmp_path / "n.key")) == 0


class TestAdvertisedTextsResolve:
    """T13 — every operator-facing `venya admin cert renew` string names a real command."""

    def test_renew_argv_parses(self):
        ns = create_parser().parse_args(["admin", "cert", "renew"])
        assert (ns.command, ns.admin_command, ns.admin_cert_command) == ("admin", "cert", "renew")

    def test_the_expiry_refusal_points_at_a_subcommand_that_exists(self, tmp_path):
        """8a told operators to run this command; RF-8b is what makes that true."""
        dead_crt, _key, _ = _pair(tmp_path, "dead", -7)
        text = admin_cert_expiry_refusal(str(dead_crt), site="this admin request")
        assert text is not None and "venya admin cert renew" in text
        create_parser().parse_args(["admin", "cert", "renew"])  # argparse-level, not a grep

    def test_status_repairs_point_at_a_subcommand_that_exists(self, tmp_path, capsys):
        from venya_cli.commands import cmd_admin_cert_status

        assert cmd_admin_cert_status(SimpleNamespace(cert_path=str(tmp_path / "gone.crt"), within=None)) == 1
        err = capsys.readouterr().err
        assert "venya admin cert renew" in err
        create_parser().parse_args(["admin", "cert", "renew"])
