# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#508 pins — `exec register` must refuse plaintext before it mints anything.

The register flow is the last anchor-installing CLI path that dials whatever
scheme the operator configured. It resolves the destination with no scheme check
(``commands.py`` ``# Determine server URL``), POSTs the CSR (plus the enrollment
token when supplied), and then writes the CA **from that response** to
``<output-dir>/ca.crt``. So over ``http://`` an on-path adversary picks the
anchor this executor trusts from now on, and reads the enrollment material in
transit — and the ``VENYA_TLS_VERIFY=false`` knob does not cover it, because that
knob means "distrust this certificate over https", never "no TLS".

The guard is the shared ``_require_https_server_url`` helper (#506), not a fifth
hand-copied check; the heartbeat's inline duplicate is folded into the same
helper here (that leg's AC5).

Scheme handling measured on this venue, not assumed (httpx2 ``build_request``):
``HTTP://core/…`` normalizes to scheme ``http`` — a plaintext dial, so the
case-sensitive ``https://`` whitelist in the guard refuses it (fail-closed);
``venya-core/…`` comes out with an EMPTY scheme (today's bare-hostname outcome at
register: a request that can never be served), so normalization is required.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient

# ---------------------------------------------------------------------------
# Helpers (house shapes from test_executor_register.py)
# ---------------------------------------------------------------------------


def _keypair_and_cert():
    """An ECDSA P-256 keypair + matching self-signed leaf (the CSR response shape)."""
    from datetime import UTC, datetime, timedelta

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "venya-exec"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert


def _register_payload():
    _private_key, cert = _keypair_and_cert()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return {
        "executor_id": "venya-exec",
        "cert_pem": cert_pem,
        "ca_cert_pem": cert_pem,
        "serial_number": "01:23:45",
        "not_after": "2027-09-13T00:00:00+00:00",
    }


def _mock_client_cls(payload):
    """A patched ``api_client.httpx2.Client`` that answers with ``payload``.

    Returns (MockClient, posted_urls) — the url list is what proves a POST did
    or did not leave for a given destination.
    """
    import httpx2

    resp = MagicMock()
    resp.status_code = 201
    resp.content = json.dumps(payload).encode()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None

    posted: list[str] = []
    inner = MagicMock()
    inner.__enter__.return_value = inner
    inner.__exit__.return_value = False

    def _post(url, *a, **k):
        posted.append(str(url))
        return resp

    inner.post = MagicMock(side_effect=_post)
    cls = MagicMock(return_value=inner)
    http2 = httpx2  # the module we are shadowing at the api_client boundary
    assert http2 is not None
    return cls, posted


def _register_args(tmp_path: Path, **over) -> MagicMock:
    args = MagicMock()
    args.executor_id = over.get("executor_id", "venya-exec")
    args.core_url = over.get("core_url")
    args.output_dir = str(tmp_path / "certs")
    args.enrollment_token = over.get("enrollment_token")
    args.ca_bundle = over.get("ca_bundle")
    return args


def _client_with_config(server_url: str | None):
    """A real APIClient whose config.json carries ``server_url`` (or is empty)."""
    config_file = Path(tempfile.mktemp(suffix=".json"))
    config_file.write_text(json.dumps({"server_url": server_url} if server_url else {}))
    client = APIClient(config_file=config_file)
    client._http = MagicMock()
    return client


# ---------------------------------------------------------------------------
# AC1 — http:// via the flag: refuse, write NOTHING, POST nothing
# ---------------------------------------------------------------------------


class TestRegisterPlaintextRefused:
    def test_http_flag_refuses_with_the_heartbeat_wording_class(self, tmp_path: Path, capsys):
        """RED at HEAD: HEAD minted a keypair, POSTed the CSR and wrote the
        response CA as the anchor. Now: rc=1 and the refusal class the heartbeat
        site has carried since #17."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == [], f"no POST may leave for a plaintext destination: {posted}"
        err = capsys.readouterr().err
        assert "must be https://" in err
        assert "Plaintext http is not supported" in err
        assert "registration" in err

    def test_http_flag_writes_no_files_at_all(self, tmp_path: Path):
        """The anchor half of the defect: the CA that would become this executor's
        trust material is written from the response, so the refusal must happen
        before the output dir exists — not after the write."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, _posted = _mock_client_cls(_register_payload())
        outdir = Path(args.output_dir)

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            assert executor_register(client, args) == 1

        assert not outdir.exists(), f"refusal created material: {sorted(p.name for p in outdir.iterdir())}"
        for name in ("ca.crt", "executor.crt", "executor.key"):
            assert not (outdir / name).exists()

    def test_http_flag_mints_no_keypair_or_csr(self, tmp_path: Path):
        """Ordering proof: the guard sits BEFORE the local crypto, so a refused
        run does not leave an orphan keypair/CSR either. Spied at the source the
        function imports from."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, _posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("cryptography.hazmat.primitives.asymmetric.ec.generate_private_key") as keygen,
            patch("venya_cli.commands._verify_register_auth"),
        ):
            assert executor_register(client, args) == 1

        keygen.assert_not_called()

    def test_enrollment_token_does_not_escape_the_guard(self, tmp_path: Path, capsys):
        """The other secret in the payload: a supplied enrollment token is the
        reason this POST is sensitive, and the refusal must still precede it."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="http://core.example.com", enrollment_token="tok-abc")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            assert executor_register(client, args) == 1

        assert posted == []
        assert "tok-abc" not in capsys.readouterr().err + capsys.readouterr().out


# ---------------------------------------------------------------------------
# AC2 — no URL source escapes: flag, VENYA_SERVER_URL, config.json
# ---------------------------------------------------------------------------


class TestEveryUrlSourceIsGuarded:
    def test_config_json_http_refused(self, tmp_path: Path, capsys):
        """The URL arrives via config.json (no flag at all)."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url=None)
        client = _client_with_config("http://core.example.com")
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == []
        assert "must be https://" in capsys.readouterr().err

    def test_env_server_url_refused_through_the_real_entry_point(self, tmp_path: Path, monkeypatch, capsys):
        """``executor_register`` itself does not read ``VENYA_SERVER_URL`` — the
        env reaches it through ``run_command``'s chokepoint (flag > env >
        config), which hands the command an APIClient whose transient
        ``config.server_url`` IS the env value. So this cell drives that entry
        point, not the leaf, otherwise it would pin a source that does not exist.
        """
        from venya_cli.commands import run_command

        monkeypatch.setenv("VENYA_SERVER_URL", "http://core.example.com")
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)

        ns = MagicMock()
        ns.command = "exec"
        ns.exec_command = "register"
        ns.executor_id = "venya-exec"
        ns.core_url = None
        ns.server_url = None
        ns.output_dir = str(tmp_path / "certs")
        ns.enrollment_token = None
        ns.ca_bundle = None
        ns.user_id = None
        cls, posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
            patch("venya_cli.commands.version_advisory"),
        ):
            result = run_command(ns)

        assert result == 1
        assert posted == []
        assert "must be https://" in capsys.readouterr().err
        assert not (Path(tmp_path) / "certs").exists()

    def test_env_and_config_agree_that_a_resolved_url_is_checked(self, tmp_path: Path, monkeypatch):
        """The guard sees the RESOLVED value, whichever way it got there: env
        wins over config.json at the chokepoint, and the refused string is the
        one the operator would have dialled."""
        from venya_cli.commands import run_command

        monkeypatch.setenv("VENYA_SERVER_URL", "http://env-core.example.com")
        ns = MagicMock()
        ns.command = "exec"
        ns.exec_command = "register"
        ns.executor_id = "venya-exec"
        ns.core_url = None
        ns.server_url = None
        ns.output_dir = str(tmp_path / "certs")
        ns.enrollment_token = None
        ns.ca_bundle = None
        ns.user_id = None
        cls, _posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
            patch("venya_cli.commands.version_advisory"),
        ):
            result = run_command(ns)

        assert result == 1


# ---------------------------------------------------------------------------
# AC3 — paired positives: https works, and a bare host normalizes to https
# ---------------------------------------------------------------------------


class TestRegisterStillWorks:
    def test_https_still_registers(self, tmp_path: Path, capsys):
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="https://core.example.com")
        client = _client_with_config(None)
        payload = _register_payload()
        cls, posted = _mock_client_cls(payload)

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
        ):
            result = executor_register(client, args)

        assert result == 0, capsys.readouterr().err
        assert posted and all(u.startswith("https://core.example.com/") for u in posted)
        outdir = Path(args.output_dir)
        assert (outdir / "executor.crt").exists() and (outdir / "ca.crt").exists()

    def test_bare_hostname_normalizes_to_https_and_registers(self, tmp_path: Path, capsys):
        """RED at HEAD in a specific way: HEAD passed the bare host through, so
        the request URL came out scheme-LESS (``venya-core/api/v1/...``) — the
        ticket calls this "normalized to https", but the normalization lived only
        at setup/config sites, never here. The guard needs a scheme to judge, so
        the register path adopts the same normalization (bare host => https)."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="venya-core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
        ):
            result = executor_register(client, args)

        assert result == 0, capsys.readouterr().err
        assert posted and all(u.startswith("https://venya-core.example.com/") for u in posted), posted

    def test_bare_hostname_never_dials_a_schemeless_url(self, tmp_path: Path):
        """The negative of the same fact: no request may go out with an empty
        scheme, because that is how "it worked on my machine" becomes a plaintext
        or unroutable dial in the field."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="venya-core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
        ):
            executor_register(client, args)

        for url in posted:
            assert url.startswith("https://"), url


# ---------------------------------------------------------------------------
# AC4 — the sanctioned knob does not re-open plaintext
# ---------------------------------------------------------------------------


class TestKnobDoesNotReopenPlaintext:
    def test_tls_verify_false_still_refuses_http(self, tmp_path: Path, monkeypatch, capsys):
        """The scheme check runs FIRST and never consults the knob: turning
        verification off must not become a way back to http."""
        from venya_cli.commands import executor_register

        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == []
        assert "must be https://" in capsys.readouterr().err

    def test_tls_verify_false_still_allows_https(self, tmp_path: Path, monkeypatch, capsys):
        """Paired: the knob keeps its ruled meaning on the https branch (this is
        the register path's own long-standing behaviour, unchanged here)."""
        from venya_cli.commands import executor_register

        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        args = _register_args(tmp_path, core_url="https://core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with (
            patch("venya_cli.api_client.httpx2.Client", cls),
            patch("venya_cli.commands._verify_register_auth"),
        ):
            result = executor_register(client, args)

        assert result == 0, capsys.readouterr().err
        assert posted and all(u.startswith("https://") for u in posted)

    def test_nonsense_knob_value_still_refuses_http(self, tmp_path: Path, monkeypatch):
        """register_executor validates the knob value; a typo must not be a hole
        under which the plaintext POST proceeds."""
        from venya_cli.commands import executor_register

        monkeypatch.setenv("VENYA_TLS_VERIFY", "maybe")
        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == []


# ---------------------------------------------------------------------------
# AC5 — one guard, four call sites (no hand-copied variants)
# ---------------------------------------------------------------------------


class TestOneSharedGuard:
    def test_hb_and_renew_and_setup_and_register_all_use_the_helper(self):
        """Structural pin for AC5: exactly ONE scheme-guard body exists in the
        module, and every one of the four flows calls it."""
        import inspect

        from venya_cli import commands as cmd

        src = inspect.getsource(cmd)
        # the guard's own body is the only place that tests the https prefix on a
        # server URL; a fifth hand-copied check would show up as a second site.
        assert src.count('if server_url.startswith("https://")') == 1
        for fn in (cmd.cmd_setup, cmd.executor_register, cmd.executor_cert_renew, cmd.executor_heartbeat):
            body = inspect.getsource(fn)
            assert "_require_https_server_url" in body, fn.__name__

    def test_heartbeat_refusal_wording_class_survives_the_conversion(self, tmp_path: Path, capsys):
        """AC3's operator-facing half: folding the heartbeat's inline check into
        the helper must not change what an operator reads. The #17 pin in
        test_executor_heartbeat.py asserts both substrings below."""
        from venya_cli.commands import executor_heartbeat

        cert = tmp_path / "executor.crt"
        key = tmp_path / "executor.key"
        private_key, x = _keypair_and_cert()
        cert.write_bytes(x.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key.chmod(0o600)

        args = MagicMock()
        args.core_url = "http://venya-core"
        args.cert_path = str(cert)
        args.key_path = None
        args.ca_bundle = None

        assert executor_heartbeat(args) == 1
        err = capsys.readouterr().err
        assert "https://" in err
        assert "sec-sweep-low-informational" in err

    def test_register_refusal_names_the_anchor_consequence(self, tmp_path: Path, capsys):
        """Diagnosability: the refusal says why this POST is sensitive — the CA
        that comes back becomes the executor's trust anchor."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="http://core.example.com")
        client = _client_with_config(None)
        cls, _posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            executor_register(client, args)

        assert "trust anchor" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Regression guards — the ticket's scope boundary
# ---------------------------------------------------------------------------


class TestScopeBoundary:
    def test_renew_does_not_write_the_anchor_from_the_response(self, tmp_path: Path):
        """The ticket says renew "does not perform the same way": renew re-saves a
        CA but does not install a NEW anchor for a different host, so #508 must
        not reach in and change renew's write path. Pin: renew's guard is the same
        helper, and renew still has no scheme-independent path."""
        import inspect

        from venya_cli import commands as cmd

        src = inspect.getsource(cmd.executor_cert_renew)
        assert "_require_https_server_url" in src

    def test_executor_id_validation_still_runs_before_the_network(self, tmp_path: Path, capsys):
        """A bad id must fail locally with its own message even when the URL is
        https — the new guard must not swallow the identity check."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url="https://core.example.com", executor_id="not/valid!")
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == []

    def test_missing_url_still_asks_for_one(self, tmp_path: Path, capsys):
        """The 'no URL at all' branch keeps its own message (it is guidance for a
        host with nothing configured), and must not become a scheme refusal."""
        from venya_cli.commands import executor_register

        args = _register_args(tmp_path, core_url=None)
        client = _client_with_config(None)
        cls, posted = _mock_client_cls(_register_payload())

        with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
            result = executor_register(client, args)

        assert result == 1
        assert posted == []
        assert "server URL required" in capsys.readouterr().err


@pytest.mark.parametrize("scheme", ["http://", "HTTP://", "HttPs://", "ftp://", "ws://"])
def test_only_lowercase_https_is_accepted(scheme: str, tmp_path: Path, capsys):
    """Truth-table half of AC1/AC3: everything that is not exactly ``https://``
    is refused. ``HTTP://`` matters because httpx2 case-folds the scheme and really
    does dial plaintext (measured: ``build_request('HTTP://core/x')`` → scheme
    ``http``), and ``HttPs://`` matters because it is the shape a normalization
    written as ``if not startswith(("http://","https://"))`` would silently turn
    into ``https://HttPs://core``. Refusing both is fail-closed: an operator who
    typed an uppercase scheme gets a clear line, never a silently re-shaped URL.
    """
    from venya_cli.commands import executor_register

    args = _register_args(tmp_path, core_url=f"{scheme}core.example.com")
    client = _client_with_config(None)
    cls, posted = _mock_client_cls(_register_payload())

    with patch("venya_cli.api_client.httpx2.Client", cls), patch("venya_cli.commands._verify_register_auth"):
        result = executor_register(client, args)

    assert result == 1
    assert posted == []
    assert "must be https://" in capsys.readouterr().err


def test_host_port_without_scheme_normalizes_to_https(tmp_path: Path, capsys):
    """The practical bare-host shape an operator actually types on an installer
    line — ``venya-core:8443`` — must become ``https://venya-core:8443``, matching
    what ``venya setup`` already does, not fail as a scheme-less request."""
    from venya_cli.commands import executor_register

    args = _register_args(tmp_path, core_url="venya-core:8443")
    client = _client_with_config(None)
    cls, posted = _mock_client_cls(_register_payload())

    with (
        patch("venya_cli.api_client.httpx2.Client", cls),
        patch("venya_cli.commands._verify_register_auth"),
    ):
        result = executor_register(client, args)

    assert result == 0, capsys.readouterr().err
    assert posted and all(u.startswith("https://venya-core:8443/") for u in posted), posted
