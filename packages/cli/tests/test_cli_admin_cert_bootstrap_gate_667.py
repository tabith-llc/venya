# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#667 — the constructor cannot demand output `admin cert renew` has not produced.

The defect: `APIClient.__init__` refused any `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY`
pair whose paths did not exist, for EVERY command — and `admin cert renew` names
that very pair as the OUTPUT paths it writes. So the command that CREATES the
first admin pair could never be the command that RUNS: a fresh workstation was
gated out by a check on files only it can produce. The refusal even told the
operator to run `renew` and retry, and the retry died the same way.

The fix is one default-OFF flag (`allow_missing_admin_pair`) passed at the
single dispatch site that already resolves argv — `run_command`, keyed on
`command/admin_command/admin_cert_command == admin/cert/renew`. It exempts
EXISTENCE only: the paired-set checks, the loose-key mode warning, the
`has_admin_mtls` semantics and every transport behavior are byte-identical when
the pair exists, and `cmd_admin_cert_renew`'s own guards (named output paths, a
login-session bearer, the #547a passphrase) still run first and unchanged.

Truth-table law (AGENTS.md): the positive half is one cell; the leg is the five
negatives — `admin cert status` still refuses (it never takes the flag), two
other admin verbs still refuse (the constructor gate stands for them), and the
three renew guards still refuse exactly where they did before. No network, no
VM, no ceremony: the transport BUILD is stubbed at its factory seam and
elevation is patched at `_elevate`; the APIClient itself is the real class in
every cell.
"""

import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClientError
from venya_cli.commands import run_command

UTC = datetime.UTC
LEAF_PASSPHRASE = "test_passphrase"  # dev-only test value, not used anywhere live
ISSUER = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
    ]
)

EXISTENCE_FIRST_SENTENCE = "VENYA_ADMIN_CERT points at {path!r}, which does not exist. "


def _minted_cert() -> bytes:
    now = datetime.datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP384R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin-bot@workstation")]))
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
    def __init__(self, payload: dict | None = None) -> None:
        self.payload = payload if payload is not None else {"certificate_pem": _minted_cert().decode()}
        self.calls: list[dict] = []

    def request(self, method, path, json=None, params=None, headers=None, **kwargs):
        self.calls.append({"method": method, "path": path, "json": json, "headers": headers or {}})
        return _StubResponse(self.payload)

    def close(self) -> None:
        pass


def _dialing(stub: _StubTransport):
    """Stub the transport BUILD (not the client): the mint seam stays production."""
    return patch("venya_cli.api_client.httpx2.Client", return_value=stub)


def _never_dial():
    return patch("venya_cli.api_client.httpx2.Client", side_effect=AssertionError("a transport was built"))


def _fresh_ws(tmp_path: Path, monkeypatch, *, token: bool = True) -> tuple[dict[str, str], Path, Path]:
    """A FRESH workstation: a config with (or without) a session bearer, an anchor CA,
    and the admin pair pointed at paths that DO NOT EXIST — the exact #667 state.

    Env is shaped through monkeypatch.setenv, never raw os.environ writes: a direct
    write is NOT undone at teardown (delenv of an ABSENT var records no undo), which
    leaked these dead paths into a later file's real-APIClient cell and poisoned
    tests/test_cli_dial_seam_https_521_site1.py — found by the full-suite run, not
    by the targeted one. The tuple's first slot stays an empty dict for call-site
    symmetry.

    Returns (unused-paths-dict, out_crt, out_key). The out paths are never created
    here; that is the point of the leg.
    """
    cfg = tmp_path / "config.json"
    data = '{"server_url": "https://core.test:8443"'
    data += ', "access_token": "session-bearer"}' if token else "}"
    cfg.write_text(data, encoding="utf-8")
    anchor = tmp_path / "anchor.pem"
    anchor.write_bytes(_minted_cert())  # any readable PEM satisfies the anchor read
    out_crt, out_key = tmp_path / "fresh-admin.crt", tmp_path / "fresh-admin.key"
    assert not out_crt.exists() and not out_key.exists()
    monkeypatch.setenv("VENYA_CONFIG", str(cfg))
    monkeypatch.setenv("SSL_CERT_FILE", str(anchor))
    monkeypatch.setenv("VENYA_ADMIN_CERT", str(out_crt))
    monkeypatch.setenv("VENYA_ADMIN_KEY", str(out_key))
    return {}, out_crt, out_key


def _ns(admin_cert_command: str | None = "renew", **overrides: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "command": "admin",
        "admin_command": "cert",
        "admin_cert_command": admin_cert_command,
        "cert_path": None,
        "key_path": None,
        "user_id": None,
        "server_url": None,
        "within": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "VENYA_ADMIN_CERT",
        "VENYA_ADMIN_KEY",
        "VENYA_CONFIG",
        "SSL_CERT_FILE",
        "VENYA_SERVER_URL",
        "VENYA_ADMIN_CA_KEY_PASSPHRASE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
    yield


class TestFreshWorkstationCanRunRenew:
    """The positive half: `run_command` constructs the REAL client with the pair
    absent and the mint proceeds — no `which does not exist` anywhere."""

    def test_renew_constructs_and_mints_with_pair_absent(self, tmp_path, monkeypatch, capsys):
        _out, out_crt, out_key = _fresh_ws(tmp_path, monkeypatch)
        stub = _StubTransport()
        with (
            _dialing(stub),
            patch("venya_cli.commands._elevate", return_value="elev-token"),
        ):
            rc = run_command(_ns())
        err = capsys.readouterr().err
        assert rc == 0, err
        assert "which does not exist" not in err
        assert out_crt.exists() and out_key.exists()
        mint_paths = [c["path"] for c in stub.calls if c["path"] == "/api/v1/admin/certs/issue"]
        assert mint_paths == ["/api/v1/admin/certs/issue"]


class TestEveryOtherGateStillRefuses:
    """The negative halves — the leg proper. The exemption is keyed to ONE
    resolved subcommand; everything else must refuse byte-identically."""

    def test_admin_cert_status_still_refuses_missing_pair(self, tmp_path, monkeypatch, capsys):
        """Same missing-pair state, subcommand `status`: the gate is NOT widened."""
        _out, _crt, _key = _fresh_ws(tmp_path, monkeypatch)
        with _never_dial():
            rc = run_command(_ns("status"))
        err = capsys.readouterr().err
        assert rc == 1
        # status reads the pair and must say the pair is not there. Which wording
        # it uses is status's own contract; what this cell pins is that it REFUSES.
        assert "admin certificate" in err.lower()
        assert "readable" in err.lower() or "does not exist" in err

    @pytest.mark.parametrize("admin_command", ["executor-enroll", "create-user"])
    def test_other_admin_verbs_still_refuse_missing_pair(self, tmp_path, monkeypatch, admin_command):
        """Constructor-level proof at the dispatch site: any other admin verb
        takes no flag, so the shipped existence refusal fires verbatim."""
        _out, _crt, _out_key = _fresh_ws(tmp_path, monkeypatch)
        ns = SimpleNamespace(
            command="admin",
            admin_command=admin_command,
            server_url=None,
            user_id=None,
        )
        with _never_dial(), pytest.raises(APIClientError) as excinfo:
            run_command(ns)
        text = str(excinfo.value)
        dead = str(tmp_path / "fresh-admin.crt")
        assert text.startswith(EXISTENCE_FIRST_SENTENCE.format(path=dead)), text

    def test_renew_still_refuses_missing_output_path(self, tmp_path, monkeypatch, capsys):
        """Guard order kept: no output path named -> the 'nowhere to write'
        refusal, rc=1, even though the constructor now lets the client exist."""
        _out, _crt, _key = _fresh_ws(tmp_path, monkeypatch)
        monkeypatch.delenv("VENYA_ADMIN_CERT")
        monkeypatch.delenv("VENYA_ADMIN_KEY")
        with _never_dial(), patch("venya_cli.commands._elevate") as elevate:
            rc = run_command(_ns(cert_path=None, key_path=None))
        err = capsys.readouterr().err
        assert rc == 1
        assert "nowhere to write" in err
        elevate.assert_not_called()

    def test_renew_still_refuses_without_session_bearer(self, tmp_path, monkeypatch, capsys):
        """Guard order kept: the mint is session-shaped (RF-8b). With no bearer
        the ceremony branch runs, yields no token, and the handler's own
        'needs a login session' refusal lands rc=1 — `_never_dial` proves no
        transport was ever built."""
        _out, _crt, _key = _fresh_ws(tmp_path, monkeypatch, token=False)
        with (
            _never_dial(),
            patch("venya_cli.api_client.APIClient.authenticate", return_value=None),
            patch("venya_cli.commands._elevate") as elevate,
        ):
            rc = run_command(_ns())
        err = capsys.readouterr().err
        assert rc == 1
        assert "needs a login session" in err
        elevate.assert_not_called()

    def test_renew_still_refuses_without_passphrase(self, tmp_path, monkeypatch, capsys):
        """#547a kept first: no passphrase -> refusal, rc=1, NOTHING written."""
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE")
        _out, out_crt, out_key = _fresh_ws(tmp_path, monkeypatch)
        with _never_dial(), patch("venya_cli.commands._elevate") as elevate:
            rc = run_command(_ns())
        err = capsys.readouterr().err
        assert rc == 1
        assert elevate.call_count == 0
        assert not out_crt.exists() and not out_key.exists()
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err
