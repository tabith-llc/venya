# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#619 — the admin-pair file-existence refusal must not instruct the copy RF-10 forbids.

The shipped string (`api_client.py:455` at `9e4da78`, inside the `isfile` loop in
``APIClient.__init__``) read "Copy the admin cert/key from the core (see installer banner)
and retry." The installer's own RF-10 banner two lines away says the opposite —
`install-venya-core.sh:1250`: *"Do not copy that pair to a workstation. It names this
core, not a person."* So the product's error text told the operator to perform the act
the product's installer tells them not to perform, with the key whose mode bits the very
next line of code warns about (`_warn_if_loose_admin_key`).

**What pinned this refusal before this file — measured, and it corrects two claims.** A
string-grep for the full first sentence (`git grep -ln 'which does not exist' -- packages/cli/tests`) returns
ZERO files, which reads as "nothing pins this". That is wrong, and the reason is the shape of the existing
assertions: **four cells pin the raise via `pytest.raises(..., match="does not exist")`** — a shorter pattern that
the full-sentence grep cannot see:

- `test_admin_key_mode_warn.py::TestExistenceLegNotRegressed::test_missing_key_still_raises`
- `test_api_client_mtls.py::TestAdminMtlsClientCert::test_cert_path_does_not_exist_raises`
- `test_api_client_mtls.py::TestAdminMtlsClientCert::test_key_path_does_not_exist_raises`
- `test_cli_admin_local_no_ceremony_590.py::TestConstructionRaisesPreserved::test_nonexistent_cert_path_still_raises_on_local_command`

So the circulating "four existing cells pin the surrounding raise" claim **reproduces**; the lead's grep missed it
because it searched for the whole sentence, and my own §3 note here said "NO contract" before I had run the
`match=` grep. All four are green after the edit, because they match `does not exist` — the substring this fix
keeps byte-stable. What NO cell ever pinned is the SECOND sentence, which is why the wrong instruction could ship:
the four assert that the raise happens, never what it tells you to do. Those cells are untouched; this file adds
the missing half.

Truth table, both halves (the repo's law — a check that passes only the positive case is
untested):

  rejected — the refusal names no copy-from-core instruction (the shipped regression);
  rejected — the installer banner still says do-not-copy, so the two surfaces cannot
             drift apart again without a red cell;
  accepted — the first sentence survives BYTE-STABLE (the filing seat's row makes that the
             contract, and operators/scripts grep for it);
  accepted — the refusal routes to the ceremony, naming only subcommands that exist at
             this tip (`venya setup`, `venya login`, `admin cert renew` — verified at
             `cli.py:496/522` before writing).

Construction mirrors the admin-mTLS home (`test_admin_key_mode_warn.py`,
`test_api_client_mtls.py`): the load block only does `isfile`, so a path that does not
exist is the whole fixture — no TLS context is built and no dial happens.
"""

import re
from pathlib import Path

import pytest
from venya_cli.api_client import APIClient, APIClientError

# The shipped banner this refusal must agree with. Read from the git-tracked product
# source at repo root, the same file the installer serves from (venya-installer/ is
# generated output and is never the thing under test).
INSTALLER = Path(__file__).resolve().parents[3] / "install-venya-core.sh"

#: First sentence, byte-for-byte, as the filing seat's row requires it to stay stable.
FIRST_SENTENCE_STABLE = "VENYA_ADMIN_CERT points at {path!r}, which does not exist. "

_MISSING = "/no/such/dir/admin.crt"


def _refusal_text(tmp_path: Path, monkeypatch) -> str:
    """The message ``APIClient.__init__`` raises when ``VENYA_ADMIN_CERT`` is a dead path.

    The loop checks cert then key, so the CERT refusal is the one that fires — that is
    the string #619 is about. Nothing else is reachable: the raise happens inside the
    constructor, so no client exists to close and no dial is attempted.
    """
    monkeypatch.setenv("VENYA_ADMIN_CERT", _MISSING)
    monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "admin.key"))
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    with pytest.raises(APIClientError) as excinfo:
        APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
    return str(excinfo.value)


class TestRefusalNamesNoCopyInstruction:
    """The load-bearing half: the shipped sentence must be gone.

    RED at the base `9e4da78` by construction — this is the regression that ships today,
    so the negative cell is the one that proves the fix rather than a string echo of it.
    """

    def test_the_copy_instruction_is_gone(self, tmp_path, monkeypatch):
        text = _refusal_text(tmp_path, monkeypatch)
        assert "Copy the admin cert/key from the core" not in text, text
        assert "copy the admin cert" not in text.lower(), text

    def test_no_implied_copy_of_the_cores_pair(self, tmp_path, monkeypatch):
        """Paired negative on wording, not just the exact old sentence: no reading of the
        line may tell the operator to bring the core's pair onto this machine."""
        text = _refusal_text(tmp_path, monkeypatch).lower()
        for banned in ("copy the admin", "copy that pair", "from the core and retry"):
            assert banned not in text, (banned, text)


class TestRefusalRoutesToTheCeremony:
    """The positive half — and the first sentence stays byte-stable."""

    def test_first_sentence_is_byte_stable(self, tmp_path, monkeypatch):
        """the filing seat's #619 row: the first sentence is the contract operators grep for."""
        text = _refusal_text(tmp_path, monkeypatch)
        assert text.startswith(FIRST_SENTENCE_STABLE.format(path=_MISSING)), text

    def test_the_ceremony_is_named(self, tmp_path, monkeypatch):
        text = _refusal_text(tmp_path, monkeypatch)
        assert "venya setup" in text, text
        assert "venya login" in text, text
        assert "venya admin cert renew" in text, text

    def test_the_refusal_says_do_not_copy(self, tmp_path, monkeypatch):
        """The sentence must carry the prohibition itself, not merely omit the advice."""
        text = _refusal_text(tmp_path, monkeypatch).lower()
        assert "do not copy" in text, text


class TestSubcommandNamesAreReal:
    """#619 forbids inventing a subcommand — so the names are pinned against the CLI."""

    @pytest.mark.parametrize(
        "fragment",
        [
            "admin cert status",  # cli.py — the RF-8a status surface
            "admin cert renew",  # cli.py — the mint the refusal routes to
        ],
    )
    def test_named_subcommands_exist_in_the_cli_source(self, fragment):
        from venya_cli import cli

        src = Path(cli.__file__).read_text()
        assert fragment in src, fragment

    def test_setup_and_login_are_dispatched_verbs(self):
        """`venya setup <core>` / `venya login <user-id>` are the banner's own two verbs;
        they are dispatch branches, so the spelling in the message must match."""
        from venya_cli import cli

        src = Path(cli.__file__).read_text()
        assert re.search(r"add_parser\(\s*[\"']setup[\"']", src), "setup verb"
        assert re.search(r"add_parser\(\s*[\"']login[\"']", src), "login verb"


class TestBannerAndRefusalCannotDrift:
    """The reason the two surfaces disagreed at all: nothing tied them together."""

    def test_installer_banner_still_forbids_the_copy(self):
        banner = INSTALLER.read_text()
        assert "Do not copy that pair to a workstation" in banner, "RF-10 banner text moved"

    def test_refusal_and_banner_agree(self, tmp_path, monkeypatch):
        """Both halves of one rule: the installer says do-not-copy, and so does the error."""
        text = _refusal_text(tmp_path, monkeypatch).lower()
        assert "do not copy" in text, text
        assert "do not copy" in INSTALLER.read_text().lower(), "banner drifted"
