# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""HTTP client for server API.

Handles authentication, error handling, and retries for CLI-to-server
communication. Integrates with FIDO2 for WebAuthn-based authentication
and manages short-lived access tokens with transparent refresh.

Token model (per plan section 5.1):
    - Session: 15 min idle timeout (configurable)
    - Access token: 5 min lifetime, transparently refreshed
    - Tokens stored in memory only (no disk persistence)
"""

import hashlib
import importlib.util
import logging
import os
import re
import ssl
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2

from .name_resolution import dial_failure_text

logger = logging.getLogger("venya_cli.api_client")


def default_config_dir() -> Path:
    """Platform-appropriate config directory.

    macOS convention: ~/Library/Application Support/venya.
    Windows convention: %APPDATA%/venya.
    POSIX (Linux, etc.): ~/.config/venya.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "venya"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return Path(appdata or Path.home() / "AppData" / "Roaming") / "venya"
    return Path.home() / ".config" / "venya"


# Default config file location
DEFAULT_CONFIG_DIR = default_config_dir()
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"

# The URL used when nothing configured one. It is a fallback, never an answer: every
# dial site refuses plaintext, so a run that reaches this value has read no server URL
# (#247 — it must never print, or dial, in the voice of configuration).
DEFAULT_SERVER_URL = "http://localhost:8000"


def config_source_problem(config_file: Path) -> str | None:
    """Why a config path that was NAMED read as nothing — or ``None`` when it read fine.

    One wording, every caller reuses it: ``venya config show`` prints it and the
    pre-ceremony gate in ``commands.run_command`` refuses on it. The named path leads,
    because every downstream symptom of a mis-pointed ``VENYA_CONFIG`` points somewhere
    else — a plaintext-https refusal that blames the FIDO2 transport, a mode advisory
    about ``/`` — and the natural remedy (re-run the ceremony) costs a key touch and a
    single-use token for an input error (#247). The idiom is the installer's own:
    ``VENYA_HOSTS_FILE is set to '…', which is not an existing, writable regular file.``

    Reads the path itself, never a caller's state, so no caller shape can turn this into
    a false verdict.
    """
    if not config_file.exists():
        cause = "does not exist"
    elif not config_file.is_file():
        cause = "is not a regular file"
    else:
        try:
            json.loads(config_file.read_text())
        except json.JSONDecodeError:
            cause = "is not valid JSON"
        except OSError as e:
            cause = f"could not be read ({e.strerror or type(e).__name__})"
        else:
            return None
    line = (
        f"VENYA_CONFIG is set to '{config_file}', which {cause} — it must name the config "
        f"FILE (default: {default_config_dir() / 'config.json'})"
    )
    # The mistake this row was measured on is pointing the variable at the DIRECTORY,
    # because every other sentence about this state says "in ~/.config/venya". When a
    # readable config file sits right inside it, say the path to type.
    if config_file.is_dir():
        sibling = config_file / "config.json"
        if sibling.is_file():
            line = f"{line} — did you mean '{sibling}'?"
    return line


def execution_timeout() -> float:
    """Read-timeout (seconds) for the long-running command-execute call.

    Fuse ordering (source-verified 2026-09-23, ticket
    cli-execution-timeout-cold-start-default): server→executor relay 300s
    (executors.py `AsyncClient(verify=…, timeout=300)`) < nginx
    proxy_read_timeout 330s (installer site template) < this 340s default.
    The client must be the LAST fuse so the clean upstream error (relay 503
    "Executor timed out", nginx 504) reaches the operator instead of a local
    read timeout. The former 30s client default aborted the first cold-sandbox
    run (~65s sbx template pull) client-side while the server was still
    completing it correctly — and the natural retry meant a second full
    execution.

    Override: VENYA_EXECUTION_TIMEOUT (positive integer seconds). The knob was
    previously mis-wired to the executor-register transport and did nothing
    for `venya run`.
    """
    raw = os.environ.get("VENYA_EXECUTION_TIMEOUT", "340")
    try:
        value = int(raw)
    except ValueError:
        raise APIClientError(
            f"Invalid VENYA_EXECUTION_TIMEOUT value: '{raw}'. Must be a positive integer number of seconds."
        ) from None
    if value <= 0:
        raise APIClientError(
            f"Invalid VENYA_EXECUTION_TIMEOUT value: '{raw}'. Must be a positive integer number of seconds."
        )
    return float(value)


def cli_version() -> str:
    """Single-sourced CLI version (feature/version-surfaces condition 1): dist
    metadata (pyproject) is the only truth — never a string literal. Lives here
    so commands.py can compare it against server-reported versions without a
    circular import through cli.py."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("venya-cli")
    except PackageNotFoundError:
        return "unknown"


#: The two faces a stamped install can be read from. The names are the release
#: recipe's, not this layer's; ``core.version`` documents the rule it applies.
BUILD_COMMIT_ENV = "VENYA_BUILD_COMMIT"
BUILD_COMMIT_FILENAME = "BUILD_COMMIT"


def build_face() -> str:
    """Which build this install came from, or ``unknown``.

    A workstation CLI is standalone by a shipped rule (no ``core.*`` import, top-level
    or function-level, ``tests/test_capability_isolation.py``), so the answer is read
    from the places a release puts it — the ``VENYA_BUILD_COMMIT`` statement, then a
    ``BUILD_COMMIT`` beside this package's own modules, then one beside ``core``'s —
    and nothing in ``core`` is imported or executed to get it: ``find_spec`` locates a
    package, it does not load one. The own-package route is what a workstation install
    takes, where no ``core`` is present at all. Absent every route, the answer is
    ``unknown``, never a sha this layer cannot prove. Agreement across the four binaries is pinned by
    ``packages/core/tests/test_version_rendering_1196.py::test_a_stamped_face_prints_identically_on_every_binary``.
    """
    stated = (os.environ.get(BUILD_COMMIT_ENV) or "").strip()
    if stated:
        return stated.split()[0]
    locations: list[Path] = [Path(__file__).resolve().parent]
    try:
        spec = importlib.util.find_spec("core")
        if spec:
            locations.extend(Path(entry) for entry in spec.submodule_search_locations or [])
    except (ImportError, ValueError, AttributeError):
        pass
    for location in locations:
        try:
            tokens = (Path(location) / BUILD_COMMIT_FILENAME).read_text(encoding="utf-8").split()
        except (OSError, UnicodeDecodeError):
            # A stamp that cannot be read, or cannot be decoded, is not an answer and is
            # not a reason to stop the tool: `UnicodeDecodeError` is a `ValueError`, so
            # `OSError` alone would let it climb out of `--version` — and this layer
            # builds its parser for every command, so it would brick the CLI with it
            # (ticket #768, leg 1237's B1). Try the next route, then answer `unknown`.
            continue
        if tokens:
            return tokens[0]
    return "unknown"


def cli_version_line() -> str:
    """The full answer ``venya --version`` gives: the release name the plate declares,
    then the face this build came from. The version stays the FIRST token, so a caller
    that parses it reads what it always read (leg 1196's contract, R-2876).
    """
    return f"{cli_version()} (build {build_face()})"


_PRE_CANONICAL = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc"}


def version_tuple(reported: str | None) -> tuple | None:
    """Parse a PEP 440 version (``X.Y.Z`` + optional prerelease) into a
    comparable tuple; spelled-out tags (alpha/beta) canonicalize to the PEP 440
    short forms so ``alpha2`` sorts BELOW ``a13`` (the dist metadata of an
    ``0.1.0alphaNN`` pyproject reports the spelled form, heartbeat-reported
    executor versions may report either — ticket #324). Unparseable or None →
    None (callers fail closed: no version advice, never a wrong-side nudge).
    Mirrors ``server.routes.executors._version_tuple``; the CLI ships standalone
    and must not import server code."""
    if not reported:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:([a-z]+)(\d+))?$", reported.strip())
    if not m:
        return None
    pre_kind = m.group(4)
    pre_kind = _PRE_CANONICAL.get(pre_kind, pre_kind) if pre_kind else "z"
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_kind, int(m.group(5) or 0))


class APIClientError(Exception):
    """API client error."""


class APIClientAuthenticationError(APIClientError):
    """Authentication failed — requires re-auth."""


def _anchor_refusal_text(searched: str, *, transport: str = "token-bearing call") -> str:
    """The one refusal wording for a dial with no Venya trust anchor (#530).

    Kept as TEXT (not an exception) so the bearer dial and the FIDO2 ceremony
    dial (#533) raise it in their OWN error classes — one wording, two seams.
    Every path that cannot name an anchor reads the same: what was searched,
    why the host store is not the answer, and the repair. ``transport`` names
    the kind of call so the ceremony refusal says "WebAuthn ceremony".
    """
    return (
        f"Cannot dial the core: no Venya TLS trust anchor is configured — {searched}. "
        f"Venya does not fall back to the host's system trust store on a {transport}: "
        "a certificate for this hostname issued by any public CA is not proof "
        "you reached your core. Repair: run `venya setup <core>` on this workstation, "
        "or set SSL_CERT_FILE to a CA bundle you trust — a core served by a public "
        "certificate is the operator naming that bundle, never an implicit host store."
    )


def _anchor_refusal(searched: str) -> APIClientError:
    """The loud refusal for a bearer dial with no Venya trust anchor (#530).

    One wording, shared by the house builder and the resolver — see
    ``_anchor_refusal_text``.
    """
    return APIClientError(_anchor_refusal_text(searched))


def _warn_if_loose_admin_key(path: str) -> None:
    """POSIX-only mode-bit check on the admin mTLS key file: warn, never block.

    The admin key authorizes admin operations WITHOUT a security-key touch, so a
    key that group or other can read is a real exposure. This prints one line on
    stderr naming the path, the mode found, the wanted ``0600`` and that fact —
    it does NOT change the exit code, stdout, or any request the CLI makes.

    Correct modes stay silent: the trigger is the group/other READ bits
    (``mode & 0o044``), so ``0600`` and stricter (``0400``) print nothing. An
    owner-only bit above ``0600`` (e.g. the ``0700`` exec bit) is NOT flagged —
    the ruled trigger is the read-to-others class, not owner permissions.

    Windows (NTFS) has no POSIX mode bits, so the check is skipped there; we
    never print a fabricated "looks fine" — platform honesty, not a fake OK.
    """
    if os.name != "posix":
        return  # no POSIX mode bits on this platform: skip, never a fabricated OK
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return  # unstatable / raced away: the existence check at the caller owns it
    if not (mode & 0o044):
        return  # 0600-or-stricter: the correct case is silent
    print(
        f"warning: {path} is mode {mode:04o} — the admin key authorizes admin "
        "operations without a security-key touch; keep it 0600 (chmod 600), "
        "stored outside your home directory.",
        file=sys.stderr,
    )


def _admin_cert_fingerprint(cert_path: str) -> str:
    """sha256 of the admin certificate FILE BYTES — the RF-8c rebuild trigger.

    Content hash, deliberately, and not `mtime`, size, or any `stat` shortcut
    (dossier §4.3): `cp`, `rsync` and a re-download of an identical file all move
    `mtime` without moving material, and a restore that PRESERVES `mtime` would then
    fail to rebuild — silently going on to present the old, soon-to-be-dead
    certificate. Size is worse still: two certificates for one identity are the same
    length by construction. The bytes are the only cheap signal that cannot lie in
    both directions.

    Reads the CERTIFICATE only — never the private key — which is the same boundary
    `admin cert status` and the RF-8a dial guard keep.

    Unreadable is a REFUSAL, never a rebuild-and-hope and never a fall-through to the
    host trust store (dossier §4.5's spirit: never silently present a stale
    credential). A certificate this workstation can no longer read is a certificate
    it cannot confirm it is presenting.
    """
    try:
        data = Path(cert_path).read_bytes()
    except OSError as e:
        raise APIClientError(
            f"Error: the admin certificate at {cert_path!r} cannot be read ({e.__class__.__name__}: {e}) "
            "— refusing to dial rather than present a credential whose material this workstation can no "
            "longer confirm. Repair: point VENYA_ADMIN_CERT at a readable certificate, or run "
            "`venya admin cert renew` to mint a new one. Nothing was sent."
        ) from e
    if not data:
        raise APIClientError(
            f"Error: the admin certificate at {cert_path!r} is empty — refusing to dial with a credential "
            "that cannot be confirmed. Repair: run `venya admin cert renew`. Nothing was sent."
        )
    return hashlib.sha256(data).hexdigest()


def _admin_key_no_passphrase_refusal(keyfile: str) -> str:
    """#565 Part B, read door: the admin client key is encrypted and this host has no passphrase.

    Names the variable, names the file, and says nothing was sent. It is NOT the "neither
    VENYA_ADMIN_CERT nor VENYA_ADMIN_KEY is set" text — the pair IS configured; what is
    missing is the thing that opens it.

    #789/#790 (landed): the repair is per-site — never retyped from ``commands``; the two
    repair texts differ by ruling. This door says MATCH the stored key, re-run the same
    command, and keeps the renewal warning: at a dial, a renewal is a mint that overwrites
    the pair.

    #794: this door no longer interpolates ``ADMIN_CA_SETUP_FRAGMENT`` (that constant lives
    in ``commands``, which imports this module — a call-time read was the only cycle-free way to
    share it, and it is no longer shared here). The fragment's second half names the mint of a
    signing authority, and at a dial that instruction is wrong twice over: the authority
    already exists, and the value asked for here has to MATCH the key on disk rather than be
    chosen fresh. The operator-facing sentences stay CA-token-free under the shipped #794
    predicate; the warning is kept in those words. The repair is per-site now; the
    CA-precondition sites keep their own wording untouched, and the variable keeps one name
    across both admin planes (#554, shipped law — this line moves no name and splits no
    predicate).
    """
    return (
        f"REFUSED: the admin client key at {keyfile!r} is encrypted and no passphrase is\n"
        "configured, so it cannot be presented for admin mTLS. Nothing was sent.\n"
        "To fix it:\n"
        "  Set VENYA_ADMIN_CA_KEY_PASSPHRASE to the passphrase this admin client key was\n"
        "  sealed with, then re-run the same command. At a dial the value has to match the\n"
        "  key on disk, so it is not a new secret to choose here.\n"
        "  This is not a renewal: a renewal here would need a login session and one\n"
        "  ceremony, and it would overwrite the pair — and a second signing authority\n"
        "  minted at this site would carry certificates this core cannot chain to.\n"
        "  The passphrase is read from that variable at dial time.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def _admin_key_decrypt_refusal(keyfile: str) -> str:
    """#565 Part B, read door: a passphrase WAS given and the key did not open with it.

    A distinct answer from "no passphrase configured" (#572's shape: name the key, say
    what failed, point at the doc). OpenSSL's own text here is the bare ``PEM lib`` line,
    which names neither the file nor the cause, so it is carried as the underlying error
    rather than as the headline.
    """
    return (
        f"failed to decrypt the admin client key at {keyfile!r} with the provided "
        "passphrase. Nothing was sent.\n"
        "Reference: docs/cert-rotation-runbook.md (certificate rotation and key locations)."
    )


def _admin_key_password_callback(keyfile: str, offered: dict[str, bool]) -> Callable[[], bytes]:
    """The passphrase door ``load_cert_chain`` knocks on for an ADMIN client key (#565 Part B).

    OpenSSL invokes it ONLY when the key file really is encrypted, which is what makes a
    plaintext pair load exactly as it did before this change — no branch, no probe, no
    rewrite of the file. The passphrase is read through ``_admin_ca_passphrase_or_none()``,
    the ONE predicate the admin writers already use (#554's shared-helper law), so a
    blankness rule can never land on the write side and miss the read side; it is imported
    at call time because ``commands.py`` imports this module.

    Args:
        keyfile: the key this dial presents, named in every refusal.
        offered: mutated to ``{"supplied": True}`` when a passphrase actually reached
            OpenSSL. The caller reads it back to tell "wrong passphrase" apart from
            "nothing configured" — the two refusals must not collapse into one.
    """

    def _password() -> bytes:
        from .commands import _admin_ca_passphrase_or_none

        passphrase = _admin_ca_passphrase_or_none()
        if passphrase is None:
            raise APIClientError(_admin_key_no_passphrase_refusal(keyfile))
        offered["supplied"] = True
        return passphrase.encode("utf-8")

    return _password


def _configured_passphrase_opens(keyfile: str) -> bool:
    """True when the configured passphrase opens this key file ON ITS OWN.

    Asked only AFTER ``load_cert_chain`` has already failed, because OpenSSL's text for "the
    passphrase did not open the key" and for "this certificate and this key are not a pair"
    is the same bare ``PEM lib`` line — guessing from that string would send an operator to
    the wrong file. The key is opened in memory and discarded: no plaintext is written, and
    no passphrase is ever printed.
    """
    from cryptography.hazmat.primitives import serialization

    from .commands import _admin_ca_passphrase_or_none

    passphrase = _admin_ca_passphrase_or_none()
    if passphrase is None:
        return False
    try:
        data = Path(keyfile).read_bytes()
    except OSError:
        return False
    try:
        serialization.load_pem_private_key(data, password=passphrase.encode("utf-8"))
    except (ValueError, TypeError, OSError):
        return False
    return True


def _build_ssl_context(
    cafile: str | None,
    certfile: str | None,
    keyfile: str | None,
    key_password: Callable[[], bytes] | None = None,
) -> ssl.SSLContext:
    """Build the single TLS context for APIClient.

    ``key_password`` (#565) is an OPTIONAL callback handed to
    ``SSLContext.load_cert_chain`` for a client key stored in the encrypted
    at-rest envelope. OpenSSL invokes it only when the key file really is
    encrypted, so a plaintext key loads either way. The executor commands pass
    their own callback (``venya_cli/executor_key.py``); the ADMIN pair used to
    arrive with none, which is the gap #565 Part B closed — when a caller hands
    over a cert/key pair and NO callback, this builder supplies
    ``_admin_key_password_callback()``, which reads the passphrase from
    ``VENYA_ADMIN_CA_KEY_PASSPHRASE`` through the same predicate the writers use
    and refuses by name when it is absent. Every CA-only caller (``certfile=None``)
    is untouched.

    Ticket cli-admin-mtls-verify-cert-conflict (option (a)): httpx2 >= 2.12
    rejects `cert=` combined with a string `verify` — the natural admin flow
    (setup-installed config CA + VENYA_ADMIN_CERT/KEY, no SSL_CERT_FILE)
    TypeErrored on every command before any request was sent. One context
    carries both directions: the Venya anchor and, when admin mTLS is
    configured, the client cert chain.

    Ticket cli-bearer-dial-falls-back-to-host-store (#530): an absent anchor is
    a REFUSAL, never ``load_default_certs()``. The old ``else`` branch trusted
    the HOST system store, so a token-bearing request to a name-confused host
    could be satisfied by any publicly-issued certificate for that name — the
    same trust-set defect #501 closed on the server relay, on the workstation
    side. Shape mirrors the landed relay builder (#501, ``_build_relay_ssl_context``):
    a bare ``PROTOCOL_TLS_CLIENT`` context (already ``CERT_REQUIRED`` +
    ``check_hostname``) loaded with ONLY the configured anchor. The repair for a
    missing anchor is ``venya setup <core>``; for a genuinely public-CA-served core
    the operator names that bundle through ``SSL_CERT_FILE`` — still an explicit
    anchor, never an implicit host store.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not cafile:
        # Defense in depth: callers resolve the anchor first and name what they
        # searched, so a blank cafile here means no anchor was ever resolved.
        raise _anchor_refusal("no CA file was resolved for this context")
    try:
        ctx.load_verify_locations(cafile=cafile)
    except (ssl.SSLError, OSError) as e:
        # Ticket 439: the refusal is correct behaviour, but the raw OpenSSL
        # text named neither the file we tried to load nor the repair.
        # Wrap — never silence — and append the original text after the
        # guidance (production mandate: loud failure, full context).
        raise APIClientError(
            f"TLS trust file {cafile!r} is present but could not be loaded as a "
            "certificate (corrupt, empty, or not PEM). Repair: run "
            "`venya setup <core>` to reinstall the core CA, or set SSL_CERT_FILE "
            f"to a valid bundle. Underlying OpenSSL error: {e}"
        ) from e
    if certfile and keyfile:
        offered: dict[str, bool] = {}
        password = key_password or _admin_key_password_callback(keyfile, offered)
        try:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile, password=password)
        except (ssl.SSLError, OSError) as e:
            # A passphrase that reached OpenSSL and still left the load failing is a WRONG
            # passphrase — but only if the key itself opens with it. A cert/key that are not
            # a pair fails the same way with a correct passphrase, and that is the pair-load
            # answer, not a passphrase answer (asked of the key alone, because OpenSSL's own
            # text cannot tell the two apart).
            if key_password is None and offered.get("supplied") and not _configured_passphrase_opens(keyfile):
                raise APIClientError(_admin_key_decrypt_refusal(keyfile)) from e
            raise APIClientError(
                f"Failed to load the admin mTLS client cert/key pair " f"({certfile!r} / {keyfile!r}): {e}"
            ) from e
    return ctx


class Config:
    """CLI configuration manager.

    Reads/writes config from config.json in the platform config directory
    (see default_config_dir()). Keys: server_url, access_token
    """

    def __init__(self, config_file: Path | None = None) -> None:
        # True only when the OPERATOR named the path (VENYA_CONFIG); a `config_file`
        # argument is the program's own choice and is never an input error to report.
        self.named_by_operator = False
        if config_file is None:
            env = os.environ.get("VENYA_CONFIG")
            if env:
                config_file = Path(env)
                self.named_by_operator = True
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        # None while the named path read; otherwise the one sentence that says why it
        # did not (#247). `read` records that bytes were actually parsed into _data.
        self.source_error: str | None = None
        self.read = False
        self._data: dict[str, Any] = {}
        self._transient_server_url: str | None = None
        self._load()

    def _load(self) -> None:
        """Load config from disk, and record why it yielded nothing."""
        if self.config_file.exists():
            try:
                self._data = json.loads(self.config_file.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}
            else:
                self.read = True
        if self.named_by_operator and not self.read:
            self.source_error = config_source_problem(self.config_file)

    def save(self) -> None:
        """Save config to disk with owner-only permissions (0o600)."""
        from .at_rest_key import ensure_secret_dir

        self.config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(self.config_file.parent)
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.config_file.parent,
                prefix=".venya-config-",
                delete=False,
            ) as fd:
                tmp_path = fd.name
                fd.write(json.dumps(self._data).encode())
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(tmp_path, self.config_file)
        except BaseException:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    @property
    def server_url(self) -> str:
        if self._transient_server_url is not None:
            return self._transient_server_url
        return self._data.get("server_url", DEFAULT_SERVER_URL)

    @server_url.setter
    def server_url(self, value: str) -> None:
        self._transient_server_url = None
        self._data["server_url"] = value.rstrip("/")
        self.save()

    def set_server_url_transient(self, value: str) -> None:
        """One-shot server URL for this process only — no config.json write (#398).

        Stored outside _data (#423) so no later save() can persist it.
        """
        self._transient_server_url = value.rstrip("/")

    @property
    def access_token(self) -> str | None:
        return self._data.get("access_token")

    @access_token.setter
    def access_token(self, value: str | None) -> None:
        if value:
            self._data["access_token"] = value
        else:
            self._data.pop("access_token", None)
        self.save()

    @property
    def ca_path(self) -> Path:
        """CA certificate installed by `venya setup`, beside config.json."""
        return self.config_file.parent / "ca.crt"


# Lazy import json at module level when needed
import json


class APIClient:
    """HTTP client for the Venya server API.

    Handles:
    - Bearer token authentication
    - Automatic token refresh within active sessions
    - FIDO2 re-authentication on token expiry
    - Error handling with meaningful messages
    - Config file persistence (access_token; server_url only via the
      explicit setter — a constructor server_url is one-shot, in-memory)

    Usage:
        # Create client (reads config from ~/.config/venya/config.json)
        client = APIClient()

        # Authenticate via FIDO2
        client.authenticate(user_id="admin")

        # Make API calls (token auto-refreshed when needed)
        secrets = client.get("/api/v1/secrets")

        # Explicit refresh
        client.refresh_token()

        # Set custom server URL
        client.config.server_url = "https://core.example.com"
    """

    def __init__(
        self,
        server_url: str | None = None,
        access_token: str | None = None,
        config_file: Path | None = None,
        allow_missing_admin_pair: bool = False,
    ) -> None:
        """Build the API client.

        `allow_missing_admin_pair` (#667) exempts the pair EXISTENCE check only,
        for one caller: `venya admin cert renew` names VENYA_ADMIN_CERT/KEY as
        the OUTPUT paths it writes, so the constructor cannot demand files that
        only this command can create — a fresh workstation could otherwise never
        mint its first admin certificate. The exemption is keyed on the resolved
        subcommand at the single dispatch site that knows argv (`run_command`),
        is default OFF, and touches NOTHING else: the paired-set checks, the
        loose-key mode warning, `has_admin_mtls` semantics and every transport
        behavior are byte-identical when the pair exists. `cmd_admin_cert_renew`
        keeps its own guards and they still run first: named output paths, a
        login-session bearer (no cert presentation — RF-8b), and the #547a
        passphrase. A missing pair also stages nothing for presentation below,
        so an exempt client never half-presents files that are not there.
        """
        self.config = Config(config_file=config_file)
        if server_url:
            # #398: the constructor URL is the one-shot flag/env override —
            # in-memory for this process only; persistence belongs to the
            # explicit setter (setup / config set server_url).
            self.config.set_server_url_transient(server_url)
        if access_token:
            self.config.access_token = access_token

        cert_path = os.environ.get("VENYA_ADMIN_CERT")
        key_path = os.environ.get("VENYA_ADMIN_KEY")
        if cert_path and not key_path:
            raise APIClientError(
                "VENYA_ADMIN_CERT is set but VENYA_ADMIN_KEY is not. Both are required for admin mTLS."
            )
        if key_path and not cert_path:
            raise APIClientError(
                "VENYA_ADMIN_KEY is set but VENYA_ADMIN_CERT is not. Both are required for admin mTLS."
            )

        # True when both admin-mTLS env vars are set. Outside the one #667
        # exemption below, the file-existence check raises if either path is
        # invalid, so a constructed client with has_admin_mtls=True always has a
        # usable cert. run_command's headless gate reads this to exempt `admin`
        # from interactive FIDO2 — and that gate already excludes `admin cert
        # renew` (RF-8b), so the exempt-with-missing-pair state never waves a
        # ceremony through. Semantics unchanged; only the guarantee is scoped.
        self.has_admin_mtls = bool(cert_path and key_path)

        http_kwargs: dict[str, Any] = {
            "base_url": self.config.server_url,
            "timeout": httpx2.Timeout(30.0),
            "follow_redirects": True,
        }
        if cert_path and key_path:
            for p, var in ((cert_path, "VENYA_ADMIN_CERT"), (key_path, "VENYA_ADMIN_KEY")):
                if not os.path.isfile(p) and not allow_missing_admin_pair:
                    raise APIClientError(
                        f"{var} points at {p!r}, which does not exist. "
                        "Do not copy the core's admin pair here — it names the core, not a "
                        "person. Run `venya setup <core>` and `venya login <user-id>`, then "
                        "`venya admin cert renew` (see the installer banner) and retry."
                    )
            # Existence AND, on POSIX, group/other-unreadable — one legible block.
            # The KEY authorizes admin operations without a security-key touch, so
            # its mode bits matter: warn (never block) if group or other can read it.
            # The cert is public — no mode warning there.
            _warn_if_loose_admin_key(key_path)
        # Server-TLS verification precedence: SSL_CERT_FILE env wins (the
        # full-lifecycle-test.md and cert-rotation-runbook flows drive the CLI
        # that way); then the CA installed by `venya setup` beside config.json.
        # Ticket cli-bearer-dial-falls-back-to-host-store (#530) removed the
        # third historical branch — "then system trust" — so a name with no
        # Venya anchor is never resolved here and the refusal is built from
        # `searched`, which names exactly what was looked for.
        cafile, searched = self._resolve_tls_anchor()
        self._anchor = cafile
        self._anchor_searched = searched
        # The admin client cert rides the SAME context (ticket
        # cli-admin-mtls-verify-cert-conflict, option (a)): httpx2 >= 2.12
        # rejects a string verify= combined with cert=, so both directions
        # unify into one ssl.SSLContext handed over as verify=.
        # Present the pair only when the bytes are actually there. The existence
        # check above made that a guarantee for every command; the one exempt
        # case (#667 renew, paths not yet written) must stage NOTHING, so an
        # earlier dial in the process (the /health advisory) never half-presents
        # a missing file. When the pair exists, this is byte-identical to before.
        pair_present = bool(cert_path and key_path and os.path.isfile(cert_path) and os.path.isfile(key_path))
        self._admin_certfile = cert_path if pair_present else None
        self._admin_keyfile = key_path if pair_present else None
        # RF-8b: the ONE narrow, default-OFF escape from presenting the admin client
        # credential. `admin cert renew` flips this (see `use_session_only_transport`)
        # because the mint route is session-shaped by ruling — RF-6 §2.2 makes the
        # caller's existing admin certificate "not an option", and the middleware
        # fails an out-of-window forwarded cert CLOSED, so the old leaf is not a
        # credential that request wants. Nothing else in the CLI ever sets it.
        self._session_only_dial = False
        self._http_kwargs: dict[str, Any] = http_kwargs
        # #530: the transport is built on the FIRST DIAL, not here. Two reasons,
        # both load-bearing: (1) `run_command()` constructs an APIClient for
        # every command BEFORE dispatch, so an anchor check at construction would
        # make `venya setup <core>` — the very repair the refusal names —
        # unreachable on exactly the anchor-less host that needs it; (2) AC1
        # requires the refusal land "before any HTTP client is constructed", so
        # construction must not itself construct one. Tests that inject a stub
        # into `_http` still bypass the real build (the setter stores it).
        self.__http: httpx2.Client | None = None
        # RF-8c: the fingerprint OF THE MATERIAL the staged transport was built from,
        # plus the path it was read from. None means "this transport presents no admin
        # certificate, or was handed to me by a caller" — in both cases there is
        # nothing here to re-confirm, so the choke point leaves it alone.
        self._cert_fingerprint: str | None = None
        self._cert_fingerprint_path: str | None = None

    def _resolve_tls_anchor(self) -> tuple[str | None, str]:
        """The Venya trust anchor for this workstation, or None + what was searched.

        Order is the landed one (SSL_CERT_FILE, then the `venya setup` CA beside
        config.json). Nothing here ever consults the host trust store.
        """
        env_ca = os.environ.get("SSL_CERT_FILE")
        if env_ca:
            return env_ca, f"SSL_CERT_FILE={env_ca!r}"
        ca_path = self.config.ca_path
        if ca_path.exists():
            return str(ca_path), f"no SSL_CERT_FILE set and no config-dir CA at {ca_path}"
        return None, f"no SSL_CERT_FILE set and no config-dir CA at {ca_path}"

    @property
    def _http(self) -> httpx2.Client:
        """The dial transport, built once on first use (#530).

        Refuses with the loud anchor message BEFORE any HTTP client exists when
        this workstation has no Venya trust anchor — the token-bearing call is
        never made against the host system store.

        #521 site 1 (option C, the dial seam): the SAME seam also refuses a
        non-``https://`` core URL before any transport exists. The check lives
        HERE rather than in ``__init__`` because ``run_command()`` constructs an
        APIClient for every command before it dispatches: an eager raise at
        construction would brick ``venya setup`` — the very repair the anchor
        refusal names — on exactly the host that needs it, and would hide the
        repair hint behind a construction error. Landing at the build branch (and
        NOT in the setter) keeps the test seam that injects a stub usable.

        RF-8a (dossier §4.4): a third refusal joins the family here, on the same
        reasoning. When the admin mTLS pair is configured and the CERTIFICATE on
        disk is outside its own validity window, the CLI refuses at this seam
        before the transport exists — the operator gets the one helpful sentence
        naming `venya admin cert renew` instead of a TLS-layer rejection or a
        server 401 that says nothing about the cause. Because the guard runs
        inside the build branch, a single request attempt passes it EXACTLY once:
        there is no re-mint, no ceremony, no retry loop (§4.6's testable boundary),
        and nothing is ever put on the wire. The read is of the certificate file
        only — the private key is never opened to answer a lifetime question.

        RF-8c (dossier §4.3) adds the second half of this property: the branch below
        builds and caches, and a cached transport is where a renewed certificate would
        otherwise go unnoticed. `load_cert_chain` copies the chain into the OpenSSL
        context at build time, so rewriting the file under a live process changes
        nothing it will send — a long-running admin script would die at the 60-minute
        mark even after a successful `venya admin cert renew`. So before handing out a
        STAGED transport, the certificate it was built from is re-read and re-hashed,
        and a difference closes the old client and re-enters THIS build branch (one
        route, not a second builder). Byte-identical bytes rebuild NOTHING: no churn, no
        connection storm. The cost when nothing changed is one read of a ~1 KB
        certificate per request, which the dossier rules irrelevant next to the round
        trip. A certificate that cannot be read is a refusal, never a rebuild-and-hope.
        """
        if self.__http is None:
            if not self._anchor:
                raise _anchor_refusal(self._anchor_searched)
            base_url = self._http_kwargs.get("base_url", "")
            if not (isinstance(base_url, str) and base_url.startswith("https://")):
                # Deferred import: commands.py imports this module at its top, so a
                # module-level back-import would be a cycle. Same shape the landed #521
                # site 3 uses in fido2_client.py (`_https_refusal`).
                from .commands import _https_refusal

                raise APIClientError(
                    _https_refusal(
                        str(base_url),
                        site="the venya API request",
                        ticket="cli-dial-sites-missing-https-guard",
                        detail=(
                            "this transport carries your bearer token, secrets and audit calls; "
                            "the URL resolved from --core-url / --server-url (where the verb "
                            "carries them), VENYA_SERVER_URL, then config.json, and for the exec "
                            "verbs /etc/venya/executor.toml"
                        ),
                    )
                )
            # What this dial actually presents. The RF-8b session-only seam clears the
            # pair here and ONLY here, so the expiry guard and the RF-8c fingerprint
            # below are keyed on the credential IN PLAY rather than the credential
            # configured — a request that presents no certificate has no certificate to
            # refuse and no certificate to fingerprint.
            presented_certfile = None if self._session_only_dial else self._admin_certfile
            presented_keyfile = None if self._session_only_dial else self._admin_keyfile
            if presented_certfile:
                # Same deferred-import shape; only the ADMIN-pair dial is guarded,
                # because only that certificate can die inside a work session. The
                # escape for the one request class that must NOT carry the pair at all
                # (the RF-8b mint) is `use_session_only_transport`, which arrives here
                # with nothing to present — never by scoping or weakening this guard.
                from .commands import admin_cert_expiry_refusal

                refusal = admin_cert_expiry_refusal(
                    presented_certfile,
                    site="this admin request",
                )
                if refusal is not None:
                    raise APIClientError(refusal)
                # RF-8c: record the fingerprint of the bytes about to be loaded, so a
                # staged context is always described by the material it actually
                # carries. The PATH is pinned here, from this client's construction: a
                # later change to `VENYA_ADMIN_CERT` in the environment must not make a
                # live process adopt a different file behind its back (the dossier's
                # named negative case).
                self._cert_fingerprint = _admin_cert_fingerprint(presented_certfile)
                self._cert_fingerprint_path = presented_certfile
            else:
                self._cert_fingerprint = None
                self._cert_fingerprint_path = None
            verify = _build_ssl_context(
                cafile=self._anchor,
                certfile=presented_certfile,
                keyfile=presented_keyfile,
            )
            self.__http = httpx2.Client(**self._http_kwargs, verify=verify)
            return self.__http

        # Staged transport: re-confirm the material it was built from. No recorded
        # fingerprint means there is nothing to confirm — either this dial presents no
        # admin certificate (the RF-8b session-only shape) or a caller handed over a
        # transport this code never built, so it cannot vouch for what is inside it.
        if self._cert_fingerprint is not None and self._cert_fingerprint_path is not None:
            present = _admin_cert_fingerprint(self._cert_fingerprint_path)
            if present != self._cert_fingerprint:
                stale = self.__http
                self.__http = None
                self._cert_fingerprint = None
                self._cert_fingerprint_path = None
                # Close FIRST: a rebuild that leaks the superseded client is a socket
                # leak, and the next dial would then run on two contexts at once.
                stale.close()
                # Re-enter the SAME branch rather than calling a second builder: the
                # anchor rule (#530), the https rule (#521) and the expiry rule (RF-8a)
                # are properties of that branch, and a rebuild that skipped them would
                # be a new dial site with a weaker check than the first one.
                return self._http
        return self.__http

    @_http.setter
    def _http(self, value: httpx2.Client | None) -> None:
        """Set the transport — test seams inject a stub here; None forces a rebuild.

        The recorded fingerprint goes with it: this code did not build what it is being
        handed, so it cannot claim to know which bytes are inside, and a stale hash
        would either rebuild over the injected stub or vouch for material it never
        read.
        """
        self.__http = value
        self._cert_fingerprint = None
        self._cert_fingerprint_path = None

    def use_session_only_transport(self) -> None:
        """Dial this client with the LOGIN SESSION only — no admin client credential.

        RF-8b `venya admin cert renew`, and nothing else. The mint it drives
        (`POST /api/v1/admin/certs/issue`) is session-shaped by ruling: RF-6 §2.2
        says authorizing issuance with the caller's existing admin certificate is
        "not an option", `routes/admin_certs.py::_require_human_session` refuses a
        certificate-shaped caller 403, and the middleware's own cert check
        (`middleware/auth.py::_verify_forwarded_cert`) fails a certificate outside
        its validity window CLOSED. So a renewal whose old certificate already
        lapsed must not put that dead leaf on the wire — and it must not be refused
        by the RF-8a dial guard that exists to stop a dead leaf being used as a
        credential. Presenting nothing is the honest answer to both.

        What this does NOT do, stated plainly because the neighbours are security
        load-bearing:
          * it does not touch the server-TLS anchor. `_resolve_tls_anchor` and the
            anchored-or-refuse rule (#530/#533/#536) run exactly as before; there
            is no `verify=False`, no `SSL_CERT_FILE` fallback, no new TLS knob.
          * it does not weaken the RF-8a expiry guard or scope it by request path.
            The guard is keyed on presenting a certificate; with none presented it
            simply has nothing to check.
          * it is DEFAULT OFF. No other command path reads this flag, so every
            existing transport is built byte-identically (there is a cell for that
            in tests/test_cli_admin_cert_renew_rf8b.py).

        Clearing the staged transport is the point: an earlier request in the same
        process (the `/health` version advisory) may already have built a context
        that DOES carry the pair, and the bearer-only mint must not ride it.
        """
        self._session_only_dial = True
        self.__http = None  # force the next dial to rebuild without the pair

    def _get_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Get request headers including auth token."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        token = self.config.access_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the server.

        On 401, attempts automatic token refresh. If refresh fails,
        raises APIClientAuthenticationError to trigger FIDO2 re-auth.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: API path.
            json_data: Optional JSON body.
            params: Optional query parameters.
            timeout: Optional per-request timeout override (seconds); None
                keeps the client default (30s). The execute call passes
                execution_timeout() (cli-execution-timeout-cold-start-default).

        Returns:
            Parsed JSON response.

        Raises:
            APIClientError: On request failure.
            APIClientAuthenticationError: On auth failure.
        """
        headers = self._get_headers(extra_headers)
        # httpx treats an explicit timeout=None as "no timeout" — only pass the
        # override when set, so every other call keeps the client default (30s).
        request_kwargs: dict[str, Any] = {"timeout": timeout} if timeout is not None else {}

        # #530: resolved OUTSIDE the try, so the no-anchor refusal is never at
        # risk of being caught and re-worded as a connection error by the httpx
        # handlers below. No HTTP client exists yet at this line on an
        # anchor-less host — nothing has left the machine.
        http = self._http

        try:
            response = http.request(
                method,
                path,
                json=json_data,
                params=params,
                headers=headers,
                **request_kwargs,
            )
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):
                error_msg = str(e)
            # R-2701: print the HTTP status alongside the detail so a version-
            # skewed operator reads 405/404, not a bare sentence. Advisory only —
            # the 401 refresh path below is unchanged.
            error_msg = f"HTTP {e.response.status_code}: {error_msg}"

            # Leg 1361 (1B): the admin middleware answers SIX outcomes with this ONE
            # string. Two of them — the pair unset in this shell, and an expired pair —
            # the operator's own machine can already answer without asking the core, so
            # the client points at the read-local check. Deliberately keyed to this
            # exact detail: a client hint that fired on any 403 would leak which of the
            # six sites answered, the same enumeration door login/start keeps shut.
            if e.response.status_code == 403 and error_msg.endswith("Admin access requires valid client certificate"):
                error_msg += (
                    "\nTwo of the causes are answerable on this workstation without contacting "
                    "the core: run `venya admin cert status` (read-local) — admin certificates "
                    "are short-lived by design, so an expired pair is the common case; and check "
                    "that VENYA_ADMIN_CERT / VENYA_ADMIN_KEY are set in THIS shell, because unset "
                    "means no certificate was presented at all. Renewing takes one ceremony: "
                    "`venya admin cert renew`."
                )

            if e.response.status_code == 401:
                if self.config.access_token:
                    try:
                        self.refresh_token()
                        # Retry the original request with new token
                        headers = self._get_headers(extra_headers)
                        response = http.request(
                            method,
                            path,
                            json=json_data,
                            params=params,
                            headers=headers,
                            **request_kwargs,
                        )
                        response.raise_for_status()
                        return response.json() if response.content else {}
                    except APIClientAuthenticationError as refresh_error:
                        # #776: the refresh sentence names the way back; it used to be
                        # discarded here, leaving the operator only the bare 401.
                        raise APIClientAuthenticationError(f"{error_msg} — {refresh_error}") from refresh_error
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            # #633: a name that does not resolve here never reached the network, so say
            # that instead of a connection sentence; every other ConnectError (refused,
            # reset, handshake) still renders exactly as before.
            raise APIClientError(dial_failure_text(e, url=self.config.server_url, default=f"Connection failed: {e}"))
        except httpx2.TimeoutException as e:
            raise APIClientError(f"Request timed out: {e}")

        if response.content:
            return response.json()
        return {}

    def authenticate(self, user_id: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
        """Authenticate via FIDO2 WebAuthn.

        Prompts the user to touch their security key. On success,
        stores the access token in memory for subsequent requests.

        Args:
            user_id: Optional user ID to target.
            timeout: Seconds to wait for key touch.

        Returns:
            Dict with user_id, session_token, and credential_id.

        Raises:
            APIClientAuthenticationError: If FIDO2 auth fails.
        """
        from .fido2_client import (
            Fido2Auth,
            Fido2ClientError,
            Fido2NotFoundError,
            Fido2TimeoutError,
            Fido2UserInteractionRequiredError,
        )

        # Pass the setup-installed CA so the FIDO2 ceremony endpoints are
        # verified against it too (same precedence as the client above).
        fido2 = Fido2Auth(self.config.server_url, ca_path=self.config.ca_path)

        try:
            result = fido2.authenticate(user_id=user_id, timeout=timeout)
        except Fido2NotFoundError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2TimeoutError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2UserInteractionRequiredError as e:
            raise APIClientAuthenticationError(str(e)) from e
        except Fido2ClientError as e:
            raise APIClientAuthenticationError(str(e)) from e

        self.config.access_token = result["session_token"]
        logger.info("Authenticated as user: %s", result.get("user_id"))

        return result

    def refresh_token(self) -> str:
        """Refresh the current access token.

        Sends the current token to the server to get a new one.
        If the session is still active, the server issues a new token.

        Returns:
            The new access token.

        Raises:
            APIClientAuthenticationError: If refresh fails (session expired).
        """
        if not self.config.access_token:
            raise APIClientAuthenticationError("No token to refresh")

        try:
            result = self._post_raw("/api/v1/auth/refresh", {})
            self.config.access_token = result["access_token"]
            logger.debug("Token refreshed successfully")
            return self.config.access_token
        except APIClientError as e:
            # #776: a refused or transient refresh is not proof the stored credential
            # is dead, and assigning None here rewrote config.json (the setter saves).
            # The token stays on disk; the way back is the mint verb, named once here.
            raise APIClientAuthenticationError(
                f"Token refresh failed: {e} — the stored token was left in place; "
                "run `venya login <user-id>` to mint a new one (security-key ceremony)"
            ) from e

    def _post_raw(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        """Make a POST request without auto-refresh (for auth endpoints)."""
        headers = self._get_headers()
        # #530: anchor refusal resolved before the try (see _request).
        http = self._http

        try:
            response = http.request(
                "POST",
                path,
                json=json_data,
                headers=headers,
            )
            response.raise_for_status()
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):
                error_msg = str(e)
            if e.response.status_code == 401:
                raise APIClientAuthenticationError(error_msg)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            # #633: shared classifier — name-resolution only, wording otherwise unchanged.
            raise APIClientError(dial_failure_text(e, url=self.config.server_url, default=f"Connection failed: {e}"))

        if response.content:
            return response.json()
        return {}

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a GET request (timeout: per-request override, seconds)."""
        return self._request("GET", path, params=params, extra_headers=extra_headers, timeout=timeout)

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send a POST request (timeout: per-request override, seconds)."""
        return self._request("POST", path, json_data=json, params=params, extra_headers=extra_headers, timeout=timeout)

    def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a PUT request."""
        return self._request("PUT", path, json_data=json, params=params, extra_headers=extra_headers)

    def delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a DELETE request."""
        return self._request("DELETE", path, params=params, extra_headers=extra_headers)

    def patch(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a PATCH request."""
        return self._request("PATCH", path, json_data=json, params=params, extra_headers=extra_headers)

    def register_executor(
        self,
        executor_id: str,
        csr_pem: str,
        enrollment_token: str | None = None,
        ca_bundle: str | None = None,
        server_url: str | None = None,
    ) -> dict[str, Any]:
        """Register an executor with the core server.

        Always uses full TLS verification. To disable verification in
        development, set VENYA_TLS_VERIFY=false before running.

        This method is scoped to registration only. ``_request()`` and
        ``_post_raw()`` never fall back, and since #536 neither does this dial:
        ``register_executor()`` builds its own ``httpx2.Client`` on the shared
        anchor-or-refuse path (#530/#533), so a verification-enabled registration
        POST with no Venya trust anchor REFUSES instead of handing the CSR and
        the enrollment token to the host system trust store.

        Args:
            executor_id: Executor identifier.
            csr_pem: PEM-encoded Certificate Signing Request.
            enrollment_token: Optional enrollment token for bootstrap auth.
            ca_bundle: Optional path to CA bundle for TLS verification.

        Returns:
            Dict with cert_pem, ca_cert_pem, serial_number, not_after.

        Raises:
            APIClientError: On network failure or registration error.
        """
        # Validate executor_id format before sending to server
        from .executor_id import validate_executor_id

        try:
            executor_id = validate_executor_id(executor_id)
        except ValueError as e:
            raise APIClientError(str(e))

        payload: dict[str, Any] = {
            "executor_id": executor_id,
            "csr_pem": csr_pem,
        }
        if enrollment_token:
            payload["enrollment_token"] = enrollment_token

        url = f"{server_url or self.config.server_url}/api/v1/executors/register"

        # #545: the scheme rule lives at the dial, not only at the caller. This
        # path builds its OWN httpx2.Client below, so it never rides the gated
        # ``_http`` seam; without this check, any new caller — or the
        # ``or self.config.server_url`` fallback reaching a stored plaintext
        # value (config files written before #509/#497) — would dial http with
        # the CSR and the enrollment token aboard. Same shared wording as the
        # ``_http`` gate (#521): one rule, one wording, no hand-copied variant.
        # Deferred import: commands.py imports this module at its top, so a
        # module-level back-import would be a cycle.
        if not (isinstance(url, str) and url.startswith("https://")):
            from .commands import _https_refusal

            raise APIClientError(
                _https_refusal(
                    str(url),
                    site="the executor registration POST",
                    ticket="api-client-register-executor-raw-dial-missing-scheme-gate",
                    detail="this POST carries the CSR and the enrollment token",
                )
            )

        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env == "" or tls_verify_env.lower() == "true":
            tls_verify = True
        elif tls_verify_env.lower() == "false":
            tls_verify = False
            logger.warning("VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)")
        else:
            raise APIClientError(f"Invalid VENYA_TLS_VERIFY value: '{tls_verify_env}'. " "Must be 'true' or 'false'.")

        try:
            # Fixed 30s: registration is one fast CSR POST. The
            # VENYA_EXECUTION_TIMEOUT knob belongs to the execute path
            # (execution_timeout()) — it was mis-wired here and did nothing
            # for `venya run` (ticket cli-execution-timeout-cold-start-default).
            timeout = 30
            if tls_verify and ca_bundle:
                # An explicit bundle is already an anchor — unchanged (#395).
                verify_param: str | bool | ssl.SSLContext = str(ca_bundle)
            elif tls_verify:
                # #536: no bundle was handed to this call, so resolve this
                # workstation's Venya anchor through the SAME resolver the bearer
                # dial (#530) and the FIDO2 ceremony dial (#533) use, and refuse
                # loudly if none resolves. The branch this replaces passed the
                # bare bool ``verify=True``, which is httpx asking OpenSSL for
                # the HOST system store: on the POST that carries the CSR and
                # the enrollment token, any publicly-issued certificate for a
                # name-confused core would have been accepted. Same trust-set
                # defect #501 closed on the server relay and #530 closed on the
                # bearer dial, on the registration path. The refusal is raised
                # BEFORE the ``with httpx2.Client(...)`` below, so no transport
                # is ever constructed on an unanchored host; ``venya setup``
                # stays the repair because nothing here raises at import or at
                # APIClient construction.
                anchor, searched = self._resolve_tls_anchor()
                if not anchor:
                    # One wording for every anchor-less dial — the shared builder
                    # takes a transport name so this says what it is, the way
                    # #533 names the WebAuthn ceremony.
                    raise APIClientError(_anchor_refusal_text(searched, transport="registration POST")) from None
                # House builder, not a hand-rolled context: CERT_REQUIRED and
                # check_hostname stay on and the anchor is the ONLY trust file.
                verify_param = _build_ssl_context(cafile=anchor, certfile=None, keyfile=None)
            else:
                verify_param = tls_verify
            with httpx2.Client(verify=verify_param, timeout=timeout) as client:
                response = client.post(url, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx2.HTTPStatusError as e:
            error_msg = "Unknown error"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except Exception:
                error_msg = str(e)
            raise APIClientError(error_msg)
        except httpx2.ConnectError as e:
            # Determine if this is a TLS failure by inspecting the exception message
            # httpx2 wraps ssl.SSLError as ConnectError — check the message for TLS keywords
            err_str = str(e).lower()
            if any(t in err_str for t in ("ssl", "certificate", "tls", "verif")):
                raise APIClientError(
                    f"Registration failed: TLS verification error — {e}. " "Verify server CA is trusted."
                ) from e
            # #633: the TLS keyword branch above is left as it is (out of scope for this
            # row). A resolver failure carries none of those keywords, so it reaches here
            # and the shared classifier gives it the name-resolution sentence.
            raise APIClientError(dial_failure_text(e, url=str(url), default=f"Connection failed: {e}"))
        except httpx2.RequestError as e:
            raise APIClientError(f"Request failed: {e}")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        # #530: a client that never dialed never built a transport — nothing to close.
        if self.__http is not None:
            self.__http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
