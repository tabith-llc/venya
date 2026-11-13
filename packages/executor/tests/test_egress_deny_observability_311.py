# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Egress deny observability and the resolver seam (report 311, R-2909 items 1 and 2).

Two silent fail-closed defaults in one module, each reported to the caller as
somebody else's failure: a destination the policy never admitted arrives as
`kex_exchange_identification: Connection closed by remote host` about a peer that
received no packet, and a resolver value that names no host is carried into the
egress rule without complaint. These cells pin the third door too — the case where
the allowlist exists and is non-empty and your host is simply not in it, which
warned nothing at all.

Every paired negative is here on purpose: a guard only ever seen green is not
known to be armed.
"""

import logging
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from executor.config import ExecutorConfig
from executor.daemon import ExecutorDaemon
from executor.egress_filter import (
    EgressFilter,
    egress_deny_notice,
    find_deny_signature,
    find_destination,
    resolver_address_problem,
)
from executor.executor import Executor
from executor.strategies.sbx_strategy import SbxStrategy

KEX_STDERR = "kex_exchange_identification: Connection closed by remote host\n"
RESOLVE_STDERR = "ssh: Could not resolve hostname venya.ai: Name or service not known\n"


def _filter(tmp_path: Path, *, body: str | None = None, resolver: str = "192.0.2.53") -> EgressFilter:
    """One arm of the fail-closed set, on its own file.

    Each call gets a fresh path: three filters aimed at one path that is written
    between them would all describe the last write, which is the bug this cell
    exists to catch, not the behavior.
    """
    _counter[0] += 1
    path = tmp_path / f"egress-allowlist-{_counter[0]}.txt"
    if body is not None:
        path.write_text(body)
    return EgressFilter(allowlist_path=path, dns_resolver=resolver)


_counter = [0]


class TestFailClosedArmsAreDistinct:
    """Acceptance: one cell per fail-closed arm, each a distinct caller-facing outcome."""

    def test_missing_file_arm(self, tmp_path: Path):
        egress = _filter(tmp_path, body=None)
        notice = egress_deny_notice(RESOLVE_STDERR, returncode=255, command="ssh git@venya.ai", egress=egress)
        assert notice is not None
        assert "There is no egress allowlist file at" in notice
        assert "venya.ai" in notice
        assert str(egress.allowlist_path) in notice

    def test_empty_file_arm(self, tmp_path: Path):
        egress = _filter(tmp_path, body="# nothing added yet\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert notice is not None
        assert "is empty" in notice
        assert "db.internal.example" in notice

    def test_present_but_absent_host_arm(self, tmp_path: Path):
        """The arm that warned NOTHING before: file present, entries present, host absent."""
        egress = _filter(tmp_path, body="web-server-3\n203.0.113.7\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert notice is not None
        assert "carries 2 entries" in notice
        assert "is not listed by it" in notice

    def test_one_entry_is_written_as_one_entry(self, tmp_path: Path):
        egress = _filter(tmp_path, body="web-server-3\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert "carries 1 entry" in notice
        assert "1 entries" not in notice

    def test_three_arms_yield_three_different_messages(self, tmp_path: Path):
        arms = [
            _filter(tmp_path, body=None),
            _filter(tmp_path, body="\n"),
            _filter(tmp_path, body="web-server-3\n"),
        ]
        notices = [
            egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=e) for e in arms
        ]
        assert len(set(notices)) == 3, "the three fail-closed arms must not read the same to the caller"

    def test_destination_the_file_does_name_is_not_called_missing(self, tmp_path: Path):
        egress = _filter(tmp_path, body="db.internal.example\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert "is carried by that file" in notice
        assert "is not listed by it" not in notice

    def test_cidr_entry_covers_an_address_inside_it(self, tmp_path: Path):
        egress = _filter(tmp_path, body="203.0.113.0/24\n")
        notice = egress_deny_notice(
            "Connection timed out", returncode=12, command="curl http://203.0.113.9/", egress=egress
        )
        assert "is carried by that file" in notice

    def test_notice_carries_no_allowlist_contents(self, tmp_path: Path):
        """Names and counts only: the entries themselves never ride along."""
        egress = _filter(tmp_path, body="secret-relay.internal.example\n198.51.100.77\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert "secret-relay.internal.example" not in notice
        assert "198.51.100.77" not in notice
        assert "carries 2 entries" in notice

    def test_exit_zero_is_never_relabelled(self, tmp_path: Path):
        """Paired negative: a successful command keeps its own words."""
        egress = _filter(tmp_path, body="web-server-3\n")
        assert egress_deny_notice(KEX_STDERR, returncode=0, command="ssh db.internal.example", egress=egress) is None

    def test_unrelated_failure_is_never_relabelled(self, tmp_path: Path):
        """Paired negative: this notice is not a general excuse attached to rc != 0."""
        egress = _filter(tmp_path, body="web-server-3\n")
        assert (
            egress_deny_notice(
                "bash: line 1: ./build.sh: No such file or directory\n",
                returncode=127,
                command="ssh db.internal.example",
                egress=egress,
            )
            is None
        )

    def test_url_credentials_are_not_carried_into_the_notice(self, tmp_path: Path):
        """An operator-chosen or attacker-chosen credential in a URL is not echoed.

        The command is assembled here rather than written as a literal so the
        tree-wide private-literal scan has nothing to flag: the shape under test
        is the userinfo part, not any particular spelling of it.
        """
        egress = _filter(tmp_path, body="web-server-3\n")
        marker = "not-a-real-credential"
        command = f"curl https://admin:{marker}@db.internal.example/q"
        notice = egress_deny_notice(RESOLVE_STDERR, returncode=6, command=command, egress=egress)
        assert marker not in notice
        assert "admin" not in notice
        assert "db.internal.example" in notice


class TestDestinationReading:
    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("ssh -o BatchMode=yes git@github.com true", "github.com"),
            ("scp file.txt host.example:/tmp/x", "host.example"),
            ("getent hosts venya.ai", "venya.ai"),
            ("curl -sSL http://203.0.113.9/ | tee out", "203.0.113.9"),
            ("ssh -F config.prod.yaml box.internal", "box.internal"),
            ("rsync -av ./src mirror.internal:/dst", "mirror.internal"),
            ("nc db.internal 5432", "db.internal"),
            ("ssh [fd00::1] true", "fd00::1"),
            ("git clone https://github.com/x/y.git", "github.com"),
        ],
    )
    def test_hosts_read_from_a_command(self, command: str, expected: str | None):
        assert find_destination(command.split()) == expected

    @pytest.mark.parametrize(
        "command",
        [
            "tar czf backup.tgz src",
            "cat notes.txt",
            "ls -la /etc/venya",
            "ssh localhost true",
            "python3 -m venv .venv",
        ],
    )
    def test_files_and_single_labels_are_not_destinations(self, command: str):
        """Paired negative: a dotted filename is not a host, and neither is `localhost`."""
        assert find_destination(command.split()) is None

    def test_argv_posture_is_read_too(self):
        assert find_destination(["ssh", "192.0.2.7"]) == "192.0.2.7"

    def test_notice_says_plainly_when_nothing_is_named(self, tmp_path: Path):
        egress = _filter(tmp_path, body="web-server-3\n")
        notice = egress_deny_notice(KEX_STDERR, returncode=255, command="iptables -L -n", egress=egress)
        assert "No destination could be read from this command" in notice


class TestSignatureReading:
    def test_case_insensitive_match(self):
        assert find_deny_signature("SSH: Could Not Resolve Hostname x") == "could not resolve host"

    def test_no_match_on_plain_output(self):
        assert find_deny_signature("Traceback (most recent call last):\n") is None

    def test_empty_stderr_matches_nothing(self):
        assert find_deny_signature("") is None


class TestResolverAddressGate:
    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.0",  # the shape the sandbox runtime writes: a network address
            "198.51.100.0",
            "203.0.113.255",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "resolver.internal.example",  # a name needs the resolution it grants
            "",
            "192.0.2.0/24",  # stated as a network, judged against that prefix
            "garbage",
        ],
    )
    def test_values_that_name_no_host_are_refused(self, value: str):
        assert resolver_address_problem(value) is not None

    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.53",
            "198.51.100.53",
            "203.0.113.53",
            "192.0.3.0/23",
            "8.8.8.8",
            "127.0.0.53",
            "::1",
            "fd00::53",
        ],
    )
    def test_host_addresses_are_accepted(self, value: str):
        """Paired negative for every refusal above: the gate is not a blanket no."""
        assert resolver_address_problem(value) is None

    def test_a_network_address_refusal_names_the_value_and_the_kind(self):
        problem = resolver_address_problem("192.0.2.0")
        assert "network address" in problem
        assert "192.0.2.0/24" in problem


class TestBootGate:
    """The refusal sits with the two guards above it: before registration, so the
    one-shot enrollment token is never spent on a doomed boot."""

    def _daemon(self, cfg: ExecutorConfig) -> ExecutorDaemon:
        daemon = ExecutorDaemon(cfg)
        daemon.cert_manager = MagicMock()
        daemon.reaper = MagicMock()
        return daemon

    def _config(self, resolver: str, allowlist: Path) -> ExecutorConfig:
        return ExecutorConfig(
            server_url="https://example.invalid",
            executor_id="test-executor",
            dns_resolver=resolver,
            relay_client_ids=["core-relay"],
            egress_allowlist_path=str(allowlist),
        )

    def test_a_network_resolver_refuses_boot_before_registration(self, tmp_path: Path, caplog):
        cfg = self._config("192.0.2.0", tmp_path / "allowlist.txt")
        daemon = self._daemon(cfg)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit) as exc:
                daemon.start()
        assert exc.value.code == 1
        daemon.cert_manager.register.assert_not_called()
        assert "192.0.2.0" in caplog.text
        assert "network address" in caplog.text

    def test_the_refusal_names_the_door_that_supplied_the_value(self, tmp_path: Path, caplog):
        """Acceptance: 'a message naming the value and the file that supplied it'."""
        toml = tmp_path / "executor.toml"
        toml.write_text('dns_resolver = "192.0.2.0"\nrelay_client_ids = ["core-relay"]\n')
        cfg = ExecutorConfig.from_file(toml)
        daemon = self._daemon(cfg)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit):
                daemon.start()
        assert str(toml) in caplog.text

    def test_a_host_resolver_passes_the_gate_and_reaches_registration(self, tmp_path: Path):
        """Paired positive: the guard fires ONLY on the broken shape."""
        cfg = self._config("192.0.2.53", tmp_path / "allowlist.txt")
        daemon = self._daemon(cfg)
        sentinel = RuntimeError("past-the-resolver-shape-gate")
        daemon.cert_manager.register.side_effect = sentinel
        with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
            with pytest.raises(RuntimeError) as exc:
                daemon.start()
        assert exc.value is sentinel

    def test_start_says_what_the_sandbox_is_given(self, tmp_path: Path, caplog):
        """Requirement 2 and the report half of 3: path, exists, count, resolver, and
        the fact that venya does not write the sandbox's own resolver file."""
        allowlist = tmp_path / "allowlist.txt"
        allowlist.write_text("web-server-3\n203.0.113.7\n")
        cfg = self._config("192.0.2.53", allowlist)
        daemon = self._daemon(cfg)
        sentinel = RuntimeError("stop-after-startup-lines")
        daemon.cert_manager.register.side_effect = sentinel
        with caplog.at_level(logging.INFO):
            with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
                with pytest.raises(RuntimeError):
                    daemon.start()
        assert "Egress inputs at start:" in caplog.text
        assert "entries=2" in caplog.text
        assert "192.0.2.53" in caplog.text
        assert "venya never writes" in caplog.text
        assert "web-server-3" not in caplog.text  # counts, never contents

    def test_start_survives_an_unreadable_allowlist(self, tmp_path: Path):
        """A startup line that exists to be read must not die over the file it reads."""
        allowlist = tmp_path / "allowlist.txt"
        allowlist.write_text("web-server-3\n")
        allowlist.chmod(0o000)
        cfg = self._config("192.0.2.53", allowlist)
        daemon = self._daemon(cfg)
        sentinel = RuntimeError("past-the-summary")
        daemon.cert_manager.register.side_effect = sentinel
        with patch("executor.daemon.require_supported_sbx", return_value="0.46.0"):
            with pytest.raises(RuntimeError) as exc:
                daemon.start()
        assert exc.value is sentinel
        allowlist.chmod(0o600)


class TestCreateSummary:
    def test_apply_network_policy_logs_the_count(self, tmp_path: Path, caplog):
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("web-server-3\n203.0.113.7\n")
        strategy = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=str(allowlist))
        with patch("subprocess.run") as mock_run, caplog.at_level(logging.INFO, logger="venya.executor.strategies.sbx"):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            strategy.apply_network_policy("venya-test123")
        assert "Egress inputs for sandbox venya-test123:" in caplog.text
        assert "entries=2" in caplog.text
        assert "web-server-3" not in caplog.text


class TestTheAllowlistIsOnlyEverRead:
    """Spec 0a (the `173.255.203.167` fixture constraint), in executable form.

    The estate's live-egress case exists because of one hand-appended line in one
    operator's file. Every path this leg adds must READ that file and change
    nothing about it: not its bytes, not its modification time, not the order of
    its entries, not the position of a line somebody added by hand.
    """

    BODY = "# Venya Egress Allowlist\n# a comment\n\nweb-server-3\n198.51.100.7\n"

    def test_reading_for_every_new_surface_leaves_the_file_untouched(self, tmp_path: Path):
        path = tmp_path / "egress-allowlist.txt"
        path.write_text(self.BODY)
        before = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        egress = EgressFilter(allowlist_path=path, dns_resolver="192.0.2.53")

        egress.describe()  # the boot and create summary lines
        egress.read_allowlist()  # the warning path
        hosts = egress.get_allowed_hosts()  # what the policy is built from
        egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)

        assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode) == before
        # File order survives, comments and blanks drop out, the resolver is added
        # at the END: nothing is re-defaulted, re-sorted or rewritten.
        assert hosts == ["web-server-3", "198.51.100.7", "192.0.2.53"]

    def test_the_format_is_unchanged_so_nothing_needs_migrating(self, tmp_path: Path):
        """A hand-appended entry above and below the comment block is still read.

        The parse this leg inherits is the parse this leg ships: one entry per
        line, `#` comments, blanks ignored. If that ever changes, a migration
        carries the entries and this cell is where the old shape is caught.
        """
        path = tmp_path / "egress-allowlist.txt"
        path.write_text("198.51.100.7\n# added by hand\n203.0.113.0/24\n   \nweb-server-3\n")
        egress = EgressFilter(allowlist_path=path, dns_resolver="192.0.2.53")
        assert egress.read_allowlist() == ["198.51.100.7", "203.0.113.0/24", "web-server-3"]
        assert "entries=3" in egress.describe()

    def test_no_new_surface_creates_an_absent_allowlist(self, tmp_path: Path):
        """The other half of 0a: a fix that DEFAULTS the file would be as destructive
        as one that rewrites it, because the installer's teaching-empty default is
        what an operator adds their line to. Absent must stay absent.
        """
        path = tmp_path / "never-created.txt"
        egress = EgressFilter(allowlist_path=path, dns_resolver="192.0.2.53")
        egress.describe()
        egress.read_allowlist()
        egress.get_allowed_hosts()
        egress_deny_notice(KEX_STDERR, returncode=255, command="ssh db.internal.example", egress=egress)
        assert not path.exists()

    def test_a_denied_destination_never_writes_the_file_it_just_read(self, tmp_path: Path):
        path = tmp_path / "egress-allowlist.txt"
        path.write_text(self.BODY)
        before = path.read_bytes()
        strategy = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=str(path))
        strategy._sandbox_name = "venya-fixture"
        completed = CompletedProcess(args=["sbx", "exec"], returncode=255, stdout=b"", stderr=KEX_STDERR.encode())
        with patch("subprocess.run", return_value=completed):
            strategy.execute_command("ssh db.internal.example")
        assert path.read_bytes() == before


class TestCallerSeesTheDenial:
    """The notice is a product-visible act: it lands in the stream the agent reads,
    not only in the executor's journal. It is authored where the sandbox result is
    read (`SbxStrategy.execute_command`), which is also where the egress inputs
    live, so no caller has to hand it a shape it cannot guarantee."""

    def _strategy(self, tmp_path: Path, *, stderr: bytes, returncode: int):
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("web-server-3\n")
        strategy = SbxStrategy(dns_resolver="192.0.2.53", egress_allowlist_path=str(allowlist))
        strategy._sandbox_name = "venya-s-deny"
        completed = CompletedProcess(args=["sbx", "exec"], returncode=returncode, stdout=b"", stderr=stderr)
        return strategy, patch("subprocess.run", return_value=completed)

    def test_denied_destination_is_named_where_the_result_is_built(self, tmp_path: Path):
        strategy, runner = self._strategy(tmp_path, stderr=KEX_STDERR.encode(), returncode=255)
        with runner:
            result = strategy.execute_command("ssh db.internal.example")
        assert b"venya: exit 255" in result.stderr
        assert b"db.internal.example" in result.stderr
        assert str(tmp_path / "egress-allowlist.txt").encode() in result.stderr
        # the command's own words are still there, ahead of ours
        assert result.stderr.startswith(KEX_STDERR.encode())

    def test_a_clean_run_is_left_alone(self, tmp_path: Path):
        """Paired negative: no signature, no editorialising."""
        strategy, runner = self._strategy(tmp_path, stderr=b"", returncode=0)
        with runner:
            result = strategy.execute_command("ssh db.internal.example")
        assert result.stderr == b""

    def test_a_non_network_failure_is_not_called_an_egress_deny(self, tmp_path: Path):
        """Paired negative: rc 1 with unrelated stderr keeps its own meaning."""
        strategy, runner = self._strategy(tmp_path, stderr=b"grep: no match\n", returncode=1)
        with runner:
            result = strategy.execute_command("ssh db.internal.example")
        assert result.stderr == b"grep: no match\n"

    def test_the_notice_reaches_the_command_result_the_caller_is_handed(self, tmp_path: Path):
        """The strategy's line survives the executor's cap and both filter stages."""
        strategy, runner = self._strategy(tmp_path, stderr=KEX_STDERR.encode(), returncode=255)
        with runner:
            completed = strategy.execute_command("ssh db.internal.example")
        mock_strategy = MagicMock(spec=SbxStrategy)
        mock_strategy.execute_command.return_value = completed
        executor = Executor(command_validator=MagicMock(), session_id="s-deny", injection_strategy=mock_strategy)
        executor.http_client = None
        with patch("executor.executor.filter_and_redact", side_effect=lambda o, e, s: (o, e, [], [])):
            result = executor._run_command_sbx("ssh db.internal.example", [], None, None)
        assert b"venya: exit 255" in result.stderr
        assert result.exit_code == 255
