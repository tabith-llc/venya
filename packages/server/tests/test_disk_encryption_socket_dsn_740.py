# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#740 — the disk-encryption assurance runs on the DSN the installer writes.

``install-venya-core.sh`` writes the runtime DSN with an EMPTY authority and a
socket path in the query::

    VENYA_DB__DATABASE_URL=postgresql://venya_audit@/venya?host=/var/run/postgresql

Peer auth over the Unix socket carries no password, so that shape is the point
(#496's role split). The resolver here read the host by hand, got ``""``, found
it in no local list, classed the connection remote, and returned ``None`` — and
``check_disk_encryption`` then logged "Could not determine PostgreSQL data
directory path." and returned before any mount lookup. On a machine the
installer built, the assurance never ran.

Second half: the local candidate list opened with ``/var/lib/postgresql/16/main``
while the installer installs ``postgresql`` unpinned, so the major follows the
distribution and 26.04 ships ``18/main``.

The resolution order is the server-side analogue of ``venya_resolve_pg_cluster``
(``install-venya-core.sh``, issue #496 R1-R4, cells in
``test_installer_pg_cluster_resolve_496.py``): the cluster manager first, then a
probe of the running server, then a derived glob — and ambiguity is never
resolved by taking the lowest version in sort order, which is the exact failure
#496 ruled out. Both source files are read in this change (see
``TestInstallerAndServerAgreeOnOneShape``) so a third DSN shape cannot silently
re-introduce the empty-host class.

No live host, guest, or database: ``pg_lsclusters`` and ``psql`` are PATH stubs
(the #496/#491/#505/#396 precedent) and the cluster root is a ``tmp_path`` tree.
"""

import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from server.utils import disk_encryption as de
from server.utils.disk_encryption import _get_pg_data_directory, _is_local_dsn, check_disk_encryption

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE_INSTALLER = REPO_ROOT / "install-venya-core.sh"

#: Pasted verbatim from install-venya-core.sh:834 at base a788ece3 — the exact
#: bytes the shipped installer writes, not a retyping of them.
SHIPPED_SOCKET_DSN = "postgresql://venya_audit@/venya?host=/var/run/postgresql"

REMOTE_DSN = "postgresql://venya_audit@203.0.113.7:5432/venya"


def _row(ver: str, status: str, data_dir: str | None = None) -> str:
    """One ``pg_lsclusters --no-header`` row: Ver Cluster Port Status Owner Data-dir Log."""
    return f"{ver}  main  5432  {status}  postgres  {data_dir or f'/var/lib/postgresql/{ver}/main'}  /var/log/x"


class _Probes:
    """PATH stubs for the two system probes, answering from files."""

    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.tmp = tmp_path
        self.monkeypatch = monkeypatch
        self.bin = tmp_path / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.lsc_file = tmp_path / "lsc.txt"
        self.lsc_file.write_text("", encoding="utf-8")
        self.psql_file = tmp_path / "show.txt"
        self.psql_file.write_text("", encoding="utf-8")
        self.argv_file = tmp_path / "psql-argv.txt"
        self.env_file = tmp_path / "psql-env.txt"

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def install(self, *, lsc: bool = True, psql: bool = True) -> None:
        """Put the stubs on PATH — and nothing else, so an absent tool is absent."""
        if lsc:
            self._write(
                "pg_lsclusters",
                "#!/bin/bash\n"
                'for a in "$@"; do [ "$a" = "--no-header" ] && { printf \'%s\\n\' "$(<"$PG_LSC_FILE")"; exit 0; }; done\n'
                "exit 0\n",
            )
        if psql:
            # Builtins only: PATH points at the stub dir and nothing else, so a
            # stub that ran `env` or `grep` would die for the wrong reason.
            self._write(
                "psql",
                "#!/bin/bash\n"
                'printf \'%s\\n\' "$@" > "$PSQL_ARGV_FILE"\n'
                '{ set; } > "$PSQL_ENV_FILE"\n'
                'for a in "$@"; do\n'
                '  [ "$a" = "SHOW data_directory" ] || continue\n'
                '  answer=$(<"$PSQL_SHOW_FILE")\n'
                '  [ -n "$answer" ] || exit 1\n'
                "  printf '%s\\n' \"$answer\"\n"
                "  exit 0\n"
                "done\n"
                "exit 1\n",
            )
        self.monkeypatch.setenv("PATH", str(self.bin))
        self.monkeypatch.setenv("PG_LSC_FILE", str(self.lsc_file))
        self.monkeypatch.setenv("PSQL_SHOW_FILE", str(self.psql_file))
        self.monkeypatch.setenv("PSQL_ARGV_FILE", str(self.argv_file))
        self.monkeypatch.setenv("PSQL_ENV_FILE", str(self.env_file))

    def clusters(self, *rows: str) -> None:
        self.lsc_file.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8")

    def show_answer(self, value: str) -> None:
        self.psql_file.write_text(value + "\n" if value else "", encoding="utf-8")

    def argv(self) -> str:
        return self.argv_file.read_text(encoding="utf-8") if self.argv_file.exists() else ""

    def child_env(self) -> str:
        return self.env_file.read_text(encoding="utf-8") if self.env_file.exists() else ""


@pytest.fixture
def probes(tmp_path, monkeypatch):
    """PATH stubs plus a tmp cluster root, so no cell touches a live host."""
    root = tmp_path / "pgdata"
    root.mkdir()
    monkeypatch.setattr(de, "_PG_CLUSTER_ROOT", root)
    return _Probes(tmp_path, monkeypatch)


def _cluster(root: Path, ver: str) -> Path:
    """A cluster directory under the fixture root: <root>/<ver>/main."""
    path = root / ver / "main"
    path.mkdir(parents=True, exist_ok=True)
    (path / "PG_VERSION").write_text(f"{ver}\n", encoding="utf-8")
    return path


class TestTheShippedSocketDsn:
    """AC1 and AC2: the exact installer DSN comes back with a path, not None."""

    def test_verbatim_socket_dsn_resolves_a_path(self, probes):
        probes.install()
        probes.clusters(_row("18", "online"))
        result = _get_pg_data_directory(SHIPPED_SOCKET_DSN)
        assert result is not None, "the assurance short-circuited on the shipped DSN — that is #740"
        assert str(result) == "/var/lib/postgresql/18/main"

    def test_empty_authority_alone_classes_local(self):
        assert _is_local_dsn("postgresql://venya_audit@/venya") is True

    def test_socket_path_in_the_query_is_honoured(self):
        """libpq's own rule: the query's host= wins over the authority."""
        assert _is_local_dsn(SHIPPED_SOCKET_DSN) is True
        assert _is_local_dsn("postgresql:///venya?host=/var/run/postgresql") is True
        assert _is_local_dsn("postgresql://venya_audit@203.0.113.7/venya?host=/var/run/postgresql") is True

    def test_loopback_names_stay_local(self):
        for dsn in ("postgresql://venya@localhost/venya", "postgresql://venya@127.0.0.1:5432/venya"):
            assert _is_local_dsn(dsn) is True, dsn

    def test_the_resolver_never_runs_a_probe_for_a_remote_host(self, probes, monkeypatch):
        """The paired negative AC3 demands: local must not have swallowed remote."""
        probes.install()
        probes.clusters(_row("18", "online"))

        def _tripwire(*args, **kwargs):
            raise AssertionError("a remote DSN must not reach any system probe")

        monkeypatch.setattr(de.subprocess, "run", _tripwire)
        assert _get_pg_data_directory(REMOTE_DSN) is None

    def test_a_dsn_without_a_scheme_answers_nothing(self, probes):
        """A keyword DSN is not a URL this function can read — no guessing."""
        probes.install()
        probes.clusters(_row("18", "online"))
        assert _get_pg_data_directory("host=/var/run/postgresql dbname=venya") is None

    def test_no_url_still_answers_none(self):
        assert _get_pg_data_directory(None) is None


class TestInstallerAndServerAgreeOnOneShape:
    """AC5: the two carriers of this DSN are checked against each other here."""

    @staticmethod
    def _installer_dsn_lines() -> list[tuple[str, str]]:
        """(variable, value) for every runtime DSN the installer writes.

        The values come out of ``printf`` single-quoted arguments, so a trailing
        ``\\n`` in the source text is part of the format string, not of the DSN.
        """
        text = CORE_INSTALLER.read_text(encoding="utf-8")
        found: list[tuple[str, str]] = []
        for line in text.splitlines():
            for token in line.split("'"):
                for prefix in ("VENYA_DB__DATABASE_URL=", "VENYA_DB_URL="):
                    if token.startswith(prefix):
                        found.append((prefix.rstrip("="), token[len(prefix) :].removesuffix("\\n")))
        return found

    def test_the_socket_line_this_file_pastes_is_the_shipped_one(self):
        """Drift tripwire: if the installer's DSN changes, this file says so."""
        written = [value for var, value in self._installer_dsn_lines() if var == "VENYA_DB__DATABASE_URL"]
        assert written, "install-venya-core.sh no longer writes VENYA_DB__DATABASE_URL — re-anchor this cell"
        assert (
            written[0] == SHIPPED_SOCKET_DSN
        ), f"the installer now writes {written[0]!r}, and the server resolver was never shown it"

    def test_every_dsn_shape_the_installer_writes_classes_local(self, probes):
        """No shipped DSN may land in the empty-host class again."""
        probes.install()
        probes.clusters(_row("18", "online"))
        shapes = [(var, value.replace("%s", "installer-password")) for var, value in self._installer_dsn_lines()]
        assert shapes, "no DSN printf found in install-venya-core.sh — this census proves nothing"
        for var, value in shapes:
            assert _is_local_dsn(value) is True, f"{var}={value!r} is not classed local"
            assert _get_pg_data_directory(value) is not None, f"{var}={value!r} resolves to nothing"


class TestResolutionOrderFollowsRuling496:
    """The cluster manager first, then the running server, then a derived glob."""

    def test_one_online_cluster_wins_over_the_lowest_installed(self, probes):
        """The #496 bug shape, read side: 14 is installed and sorts first, 16 runs."""
        probes.install()
        probes.clusters(_row("14", "offline"), _row("16", "online"))
        assert str(_get_pg_data_directory(SHIPPED_SOCKET_DSN)) == "/var/lib/postgresql/16/main"

    def test_the_manager_beats_an_installed_cluster_at_the_same_time(self, probes, tmp_path):
        """Precedence itself, not sort order: all three sources answer at once, and the
        cluster manager's answer is the one the resolver returns.

        Every other cell here offers the resolver one source at a time — the cells that plant
        installed directories stub both probes absent, and the cells with a probe answer run
        against an empty root — so ``_from_derived_glob()`` returned None precisely whenever
        another source had something to say, and the ORDER between the sources was unobservable.
        This fixture gives each of the three a different path simultaneously: the manager's
        ``17``, the running server's ``19``, and an installed ``14/main`` under the root that the
        glob would hand back first. A resolver that consulted the glob before the probes answers
        ``14/main`` here, and that is the whole point of the cell.
        """
        probes.install()
        installed = _cluster(tmp_path / "pgdata", "14")
        probes.clusters(_row("17", "online", "/srv/cluster/17/main"))
        probes.show_answer("/srv/running-server/19/main")
        answer = _get_pg_data_directory(SHIPPED_SOCKET_DSN)
        assert str(answer) == "/srv/cluster/17/main", (
            f"the manager must win when the glob and the server also answer; got {answer}, "
            f"glob would say {installed}, server would say /srv/running-server/19/main"
        )

    def test_that_same_fixture_offers_the_glob_a_different_path(self, probes, tmp_path):
        """The discriminator for the cell above: each source, asked alone on this same
        fixture, names a DIFFERENT path.

        Without it the precedence cell could be made green by a fixture in which only one source
        ever had an answer — the exact hole the cells above have — because "the manager won" and
        "the manager was the only candidate" print identically. So assert the glob answers here at
        all, and assert it disagrees with the manager and with the resolver's final choice.
        """
        probes.install()
        installed = _cluster(tmp_path / "pgdata", "14")
        probes.clusters(_row("17", "online", "/srv/cluster/17/main"))
        probes.show_answer("/srv/running-server/19/main")
        from_glob = de._from_derived_glob()
        from_manager = de._from_cluster_manager()
        from_server = de._from_running_server(SHIPPED_SOCKET_DSN)
        assert from_glob == installed, "the fixture must give the glob source a real answer"
        assert from_manager == Path("/srv/cluster/17/main"), "and the manager a different one"
        assert from_server == Path("/srv/running-server/19/main"), "and the server a third"
        assert (
            len({from_glob, from_manager, from_server}) == 3
        ), f"three sources, three distinct paths expected, got {from_glob} / {from_manager} / {from_server}"
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == from_manager
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) != from_glob

    def test_two_online_clusters_are_not_resolved_by_guessing(self, probes):
        """R2 applied to a read: an ambiguous manager answer is no answer."""
        probes.install()
        probes.clusters(_row("14", "online"), _row("16", "online"))
        probes.show_answer("")  # the server cannot answer either
        result = _get_pg_data_directory(SHIPPED_SOCKET_DSN)
        assert str(result) == str(probes.tmp / "pgdata"), "ambiguity must fall to the root, not to a chosen cluster"

    def test_absent_cluster_manager_falls_back_to_the_running_server(self, probes):
        probes.install(lsc=False)
        probes.show_answer("/srv/pgdata")
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == Path("/srv/pgdata")

    def test_a_cluster_manager_row_without_a_path_is_not_an_answer(self, probes):
        probes.install()
        probes.clusters("18  main  5432  online  postgres  -  /var/log/x")
        probes.show_answer("/srv/pgdata")
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == Path("/srv/pgdata")

    def test_no_hardcoded_major_a_current_release_resolves(self, probes, tmp_path):
        """The second half of #740: 26.04 ships 18/main and no 16 anywhere."""
        probes.install(lsc=False, psql=False)
        installed = _cluster(tmp_path / "pgdata", "18")
        assert not (tmp_path / "pgdata" / "16").exists()
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == installed

    def test_two_installed_clusters_and_no_manager_resolve_to_the_root(self, probes, tmp_path):
        probes.install(lsc=False, psql=False)
        _cluster(tmp_path / "pgdata", "16")
        _cluster(tmp_path / "pgdata", "18")
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == tmp_path / "pgdata"

    def test_fresh_install_with_no_directories_answers_the_root(self, probes):
        probes.install(lsc=False, psql=False)
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == probes.tmp / "pgdata"

    def test_probe_failure_never_raises_out_of_the_resolver(self, probes, monkeypatch):
        """A best-effort assurance must not be able to break a startup."""

        def _boom(*args, **kwargs):
            raise OSError("the host answered with something unexpected")

        monkeypatch.setattr(de.subprocess, "run", _boom)
        assert _get_pg_data_directory(SHIPPED_SOCKET_DSN) == probes.tmp / "pgdata"


class TestCredentialStaysOutOfArgv:
    """The SHOW probe may be handed a DSN that carries a password; it must not."""

    def test_the_password_reaches_the_child_environment_not_its_command_line(self, probes):
        probes.install(lsc=False)
        probes.show_answer("/srv/pgdata")
        # A marker this cell searches the child's argv for — never a credential.
        # The question is where a DSN-borne value travels, not what it says.
        carried_value = "installer-supplied-dsn-value"
        dsn = f"postgresql://venya:{carried_value}@localhost/venya"
        assert _get_pg_data_directory(dsn) == Path("/srv/pgdata")
        assert carried_value not in probes.argv(), f"the DSN value reached the command line: {probes.argv()!r}"
        assert "PGPASSWORD" in probes.child_env(), "the probe lost the credential it was given"
        assert "PGHOST=localhost" in probes.child_env()
        assert "PGUSER=venya" in probes.child_env()
        assert "PGDATABASE=venya" in probes.child_env()

    def test_a_socket_dsn_with_no_password_sets_no_password_variable(self, probes):
        probes.install(lsc=False)
        probes.show_answer("/srv/pgdata")
        _get_pg_data_directory(SHIPPED_SOCKET_DSN)
        assert "PGPASSWORD" not in probes.child_env()
        assert f"PGHOST={Path('/var/run/postgresql')!s}" in probes.child_env()


class TestTheUndeterminableLogLine:
    """AC4: the line survives only for a case that is genuinely undeterminable."""

    UNDETERMINABLE = "Could not determine PostgreSQL data directory path."

    def _run(self, caplog, dsn: str | None):
        caplog.set_level(logging.INFO)
        with patch("server.utils.disk_encryption._find_mount_point", return_value="/"):
            with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value=None):
                with patch("server.utils.disk_encryption._find_crypt_backing_device", return_value=None):
                    check_disk_encryption(dsn)
        return [record.message for record in caplog.records]

    def test_the_socket_dsn_no_longer_logs_the_undeterminable_line(self, probes, caplog):
        probes.install()
        probes.clusters(_row("18", "online"))
        messages = self._run(caplog, SHIPPED_SOCKET_DSN)
        assert not any(self.UNDETERMINABLE in message for message in messages), messages
        assert any("No disk encryption detected" in message for message in messages), messages
        assert any(
            "/var/lib/postgresql/18/main" in message for message in messages
        ), "the warning must name the directory it actually looked at"

    def test_the_undeterminable_line_survives_for_a_remote_host(self, caplog):
        messages = self._run(caplog, REMOTE_DSN)
        assert any(self.UNDETERMINABLE in message for message in messages), messages

    def test_the_undeterminable_line_survives_for_no_url(self, caplog):
        messages = self._run(caplog, None)
        assert any(self.UNDETERMINABLE in message for message in messages), messages

    def test_the_socket_dsn_reports_encryption_when_the_mount_is_crypt_backed(self, probes, caplog):
        """Positive polarity: the assurance now RUNS, and can answer verified."""
        caplog.set_level(logging.INFO)
        probes.install()
        probes.clusters(_row("18", "online"))
        with patch("server.utils.disk_encryption._find_mount_point", return_value="/var/lib/postgresql"):
            with patch("server.utils.disk_encryption._get_fstype_via_lsblk", return_value="crypto_LUKS"):
                with patch("server.utils.disk_encryption._get_lsblk_device_for_mount", return_value="sda3"):
                    check_disk_encryption(SHIPPED_SOCKET_DSN)
        verified = [r.message for r in caplog.records if "Disk encryption verified" in r.message]
        assert verified and "sda3" in verified[0], verified
