"""Leg 1361 — the admin-plane client text: 1A sentence, 1B 403 guidance, 1C per-site repair.

Three faces of the same walk-through finding, all CLIENT-side; the server's six 403
answers stay byte-identical (spec §1B: collapsing them or leaking which one fired is
the same enumeration door as 1A, and the operator's own machine already knows the two
locally-knowable cases without asking the core).

1C rule, ruled PER-SITE by the lead on the owner's directive ("fix all of them"):
a single shared sentence cannot be true at two call sites. The renewal site wants
"set the variable you are choosing now, re-run this command"; the dial site wants
"set the variable to the value that ENCRYPTED THIS STORED KEY, re-run the same
command" — and neither may ever name `init-admin-ca`, whose own docstring says it
creates a new Admin CA. The #547a refuse-before-any-filesystem-work ORDERING is not
part of this change and is not loosened: the refusal is correct, only its repair
text was wrong. Positive control for the one site where `init-admin-ca` IS the true
precondition (CA files absent under generate-admin-cert): TestSharedHintFragment in
test_cli_admin_leaf_key_passphrase_547a.py, unchanged.
"""

import inspect
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx2
import pytest
from venya_cli.api_client import (
    APIClient,
    APIClientAuthenticationError,
    APIClientError,
    _admin_key_no_passphrase_refusal,
)
from venya_cli.commands import (
    ADMIN_CA_SETUP_FRAGMENT,
    _admin_leaf_key_no_passphrase_refusal,
    cmd_admin_cert_renew,
    cmd_login,
)

RENEW_SITE = "venya admin cert renew"
GENERATE_SITE = "venya admin generate-admin-cert"


class Test1CLeafRefusalIsPerSite:
    def test_renewal_site_names_renew_not_init_admin_ca(self):
        err = _admin_leaf_key_no_passphrase_refusal(RENEW_SITE)
        assert "REFUSED" in err
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err
        assert RENEW_SITE in err, "the renewal site must route back to the renewal command"
        assert "init-admin-ca" not in err, "a renewal refusal may never name the CA mint"
        assert ADMIN_CA_SETUP_FRAGMENT not in err

    def test_generate_site_names_generate_not_init_admin_ca(self):
        """The leaf-key refusal under generate-admin-cert is ALSO a renewal-shaped site:
        the CA already exists there (the CA-absent hints are the other, correct sites),
        so naming a CA mint is the same dead end."""
        err = _admin_leaf_key_no_passphrase_refusal(GENERATE_SITE)
        assert GENERATE_SITE in err
        assert "init-admin-ca" not in err
        assert ADMIN_CA_SETUP_FRAGMENT not in err

    def test_refusal_states_the_class_of_the_passphrase_wanted(self):
        """Locally chosen here, to encrypt the key THIS command writes — the variable's
        name implies a CA secret nobody needs at this site (defect 3 of the walkthrough)."""
        err = _admin_leaf_key_no_passphrase_refusal(RENEW_SITE)
        low = err.lower()
        assert "choose" in low or "you choose" in low or "chosen" in low
        assert "encrypt" in low

    def test_paired_negative_dial_refusal_never_names_a_mint(self):
        err = _admin_key_no_passphrase_refusal("/home/op/.config/venya/admin.key")
        assert "REFUSED" in err and "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err
        assert "init-admin-ca" not in err, "at a dial a CA mint plants an CA the core rejects"
        assert ADMIN_CA_SETUP_FRAGMENT not in err
        assert "same command" in err, "the dial site routes to re-running the same command"

    def test_dial_refusal_names_match_the_stored_key_not_a_new_secret(self):
        err = _admin_key_no_passphrase_refusal("/home/op/.config/venya/admin.key")
        low = err.lower()
        assert "match" in low or "was chosen" in low or "created" in low


class Test1COperatorVisibleRefusal:
    """The renewal refusal through the command, not the helper — the bytes the owner's
    terminal shows. Reaches the #547a door by construction: paths set, session present,
    passphrase absent; nothing below the guard is ever reached (no dial, no write)."""

    def _client(self):
        client = MagicMock()
        client.config.access_token = "session-bearer-present"
        return client

    def test_renew_no_passphrase_refusal_has_no_dead_end_sentence(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)
        args = SimpleNamespace(cert_path=str(tmp_path / "a.crt"), key_path=str(tmp_path / "a.key"))
        rc = cmd_admin_cert_renew(self._client(), args)
        assert rc == 1
        err = capsys.readouterr().err
        assert "REFUSED" in err
        assert "init-admin-ca" not in err
        assert ADMIN_CA_SETUP_FRAGMENT not in err
        assert RENEW_SITE in err
        assert (
            not Path(args.cert_path).exists() and not Path(args.key_path).exists()
        ), "#547a ordering intact: the refusal still lands before ANY filesystem work"


class Test1ALoginFailureSentenceNamesTheId:
    def test_auth_error_sentence_carries_the_user_id_it_was_told(self, capsys):
        client = MagicMock()
        client.authenticate.side_effect = APIClientAuthenticationError("HTTP 401: Credential not found")
        rc = cmd_login(client, SimpleNamespace(user_id="dust-admin"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "dust-admin" in err, "the failure sentence must name the id, not only the credential outcome"
        assert "Credential not found" in err

    def test_generic_failure_sentence_names_the_id_too(self, capsys):
        client = MagicMock()
        client.authenticate.side_effect = RuntimeError("transport blew up")
        rc = cmd_login(client, SimpleNamespace(user_id="dusty-admin"))
        assert rc == 1
        assert "dusty-admin" in capsys.readouterr().err


class Test1B403GuidanceIsClientSide:
    """`venya admin list` answers HTTP 403 with ONE string for SIX server outcomes.
    Two of them — pair unset, pair expired — the operator's own machine can already
    answer. The client points at the read-local check; the server says nothing new."""

    ADMIN_403 = "Admin access requires valid client certificate"

    def _client_and_mock(self, status_code, detail):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            config_file = Path(f.name)
        client = APIClient(config_file=config_file)
        resp = MagicMock(spec=httpx2.Response)
        resp.status_code = status_code
        resp.json.return_value = {"detail": detail}
        resp.content = json.dumps({"detail": detail}).encode()
        resp.raise_for_status.side_effect = httpx2.HTTPStatusError(str(status_code), request=MagicMock(), response=resp)
        mock_http = MagicMock()
        mock_http.request.return_value = resp
        client._http = mock_http  # sanctioned test seam (test_cli_role_status_line_729.py)
        return client, config_file

    def test_admin_403_routes_to_the_read_local_check(self):
        client, config_file = self._client_and_mock(403, self.ADMIN_403)
        try:
            with pytest.raises(APIClientError) as excinfo:
                client.get("/api/v1/admin/list")
            msg = str(excinfo.value)
            assert f"HTTP 403: {self.ADMIN_403}" in msg, "the shipped server answer stays first, unchanged"
            assert "venya admin cert status" in msg, "point the operator at the read-local disambiguation"
            assert "short-lived by design" in msg
            assert "venya admin cert renew" in msg
        finally:
            client.close()
            config_file.unlink()

    def test_paired_negative_other_403s_get_no_admin_guidance(self):
        client, config_file = self._client_and_mock(403, "A different door answered")
        try:
            with pytest.raises(APIClientError) as excinfo:
                client.get("/api/v1/something")
            msg = str(excinfo.value)
            assert "venya admin cert status" not in msg, (
                "guidance is keyed to the admin-pair string only — a server that leaks "
                "which of its six sites fired is the enumeration door 1A keeps shut"
            )
        finally:
            client.close()
            config_file.unlink()

    def test_renew_confirmation_states_the_lifetime_surprise(self):
        """Where an operator FIRST meets the sixty-minute plane is the renewal
        confirmation itself, not a runbook paragraph (§1B)."""
        src = inspect.getsource(cmd_admin_cert_renew)
        assert "short-lived by design" in src
        assert "renew takes one ceremony" in src
