# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#653 — the metrics scrape door: the shipped unit opens it, and it answers on loopback.

Two halves, and the second is the load-bearing one.

* **The channel is pinned end to end.** The shipped ``systemd/venya-core.service`` sets an
  ``Environment=`` variable and ``server/app.py`` reads one. The row's own warning is that
  "a row whose only test is 'port is set' can be satisfied by an install script that sets a
  variable nothing binds to", so the two spellings are compared as values READ from each side
  rather than restated here. Delete the unit line and the first cell goes red — that inversion
  is the before-state assertion: at the base face the unit carried only ``VENYA_ENV_DIR``, so
  nothing set the name and the scrape endpoint never bound.
* **The endpoint physically answers.** A real bind through the shipped helper, a real HTTP
  scrape of the real registry, and a real refused connection: dark when the variable is absent,
  answering and carrying every shipped family when it is present, bound to loopback and NOT
  reachable on the host's routable address.

The port number is read from the unit, never hardcoded, except in the cells that check that
choice is unprivileged and collides with nothing shipped. The physical cells bind an ephemeral
port, so the suite never depends on 9091 being free on the runner.
"""

import http.client
import inspect
import os
import re
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from server import app as server_app
from server import metrics as server_metrics

_ROOT = Path(__file__).resolve().parents[3]
_CORE_UNIT = _ROOT / "systemd" / "venya-core.service"
_EXECUTOR_UNIT = _ROOT / "systemd" / "venya-executor.service"
_CORE_INSTALLER = _ROOT / "install-venya-core.sh"
_RELAY_SRC = _ROOT / "packages" / "executor" / "src" / "executor" / "relay_listener.py"
_SERVER_CONFIG_SRC = _ROOT / "packages" / "server" / "src" / "server" / "config.py"
_DEPLOY_DOC = _ROOT / "docs" / "deployment-config.md"
_FIREWALL_DOC = _ROOT / "docs" / "FIREWALL.md"
_RUNBOOK_DOC = _ROOT / "docs" / "revocation-table-operations-runbook.md"

#: Every ``venya_*`` family the product ships, taken from the declared names in metrics.py —
#: the same strings the exposition emits on its ``# TYPE`` lines. Read from source so a new
#: counter is covered automatically and this file can never fall behind the registry.
_SHIPPED_FAMILIES = frozenset(
    re.findall(
        r"^[A-Z0-9_]+ = (?:Counter|Gauge|Histogram)\(\s*[\"']([^\"']+)",
        Path(server_metrics.__file__).read_text(),
        re.MULTILINE,
    )
)


def _env_names(unit_text: str) -> list[str]:
    """The variable names an ``Environment=`` line sets, in file order."""
    return re.findall(r"^Environment=([A-Za-z_][A-Za-z0-9_]*)=", unit_text, re.MULTILINE)


def _env_value(unit_text: str, name: str) -> str | None:
    """The value the unit gives ``name``, or None when the unit does not set it."""
    match = re.search(rf"^Environment={name}=(.*)$", unit_text, re.MULTILINE)
    return match.group(1).strip() if match else None


def _declared_port() -> int:
    """The scrape port the shipped unit declares, as an int."""
    raw = _env_value(_CORE_UNIT.read_text(), server_app.METRICS_PORT_ENV_VAR)
    assert raw is not None and raw.isdigit(), f"{_CORE_UNIT.name} declares no integer port, got {raw!r}"
    return int(raw)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _refused(port: int, host: str = "127.0.0.1") -> bool:
    """True when nothing answers on host:port — the observable dark state."""
    try:
        conn = socket.create_connection((host, port), timeout=1.0)
    except OSError:
        return True
    conn.close()
    return False


def _non_loopback_ipv4() -> str | None:
    """A routable local address to aim the loopback negative at; None on a loopback-only box.

    An unconnected UDP socket only asks the kernel which source address a route WOULD take, so
    no packet leaves the host and no network is required — and with no default route the lookup
    simply fails and the caller skips. The literal below is a public-range address precisely
    because the tree-wide guard in `packages/executor/tests/test_installer_no_private_literals.py`
    refuses an RFC1918 literal here.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.settimeout(1.0)
        try:
            probe.connect(("203.0.113.1", 1))  # TEST-NET-3: a route lookup, never a packet
        except OSError:
            return None
        addr = str(probe.getsockname()[0])
    return None if addr.startswith("127.") else addr


@pytest.fixture()
def scrape_door() -> Iterator[tuple[int, int, str]]:
    """Open the shipped scrape endpoint on an ephemeral port and hand back a real scrape."""
    port = _free_loopback_port()
    started = server_app.start_metrics_server(str(port))
    assert started is not None, "the shipped helper bound nothing for a configured port"
    httpd, thread = started
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode()
        yield port, resp.status, body
        conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class TestShippedChannel:
    """The unit, the installer's env file, and the code must agree on one name and one port."""

    def test_unit_sets_the_variable_the_code_reads(self):
        """AC1 + AC2(a): the unit declares a port AND the code reads that exact name.

        The cell that inverts when this row lands — at the base face nothing set the name.
        """
        unit = _CORE_UNIT.read_text()
        assert server_app.METRICS_PORT_ENV_VAR in _env_names(unit), (
            f"{_CORE_UNIT.name} sets {sorted(set(_env_names(unit)))} but server/app.py binds "
            f"{server_app.METRICS_PORT_ENV_VAR!r}: the door is dark on a default install"
        )

    def test_unit_carries_no_secret_and_the_env_file_stays_passphrase_only(self):
        """The port belongs in the unit; the 0640 EnvironmentFile must not collect it.

        /etc/venya/venya-core.env is written 0640 root:venya to hold CA passphrases. A metrics
        port there would advertise a non-secret into the file whose mode exists for keys, and
        would quietly outrank the unit line for anyone who reads only the unit.
        """
        assert set(_env_names(_CORE_UNIT.read_text())) == {
            "VENYA_ENV_DIR",
            server_app.METRICS_PORT_ENV_VAR,
        }, f"unexpected Environment= names: {sorted(_env_names(_CORE_UNIT.read_text()))}"
        installer = _CORE_INSTALLER.read_text()
        assert re.search(
            r">>?\s*/etc/venya/venya-core\.env", installer
        ), "install-venya-core.sh no longer writes /etc/venya/venya-core.env — re-read this cell"
        assert server_app.METRICS_PORT_ENV_VAR not in installer, (
            "the installer now also sets the metrics port: two carriers for one setting, and the "
            "installer scripts are owner-ok-gated — rule it in the ticket before moving the channel"
        )

    def test_declared_port_is_unprivileged(self):
        """The unit grants no CAP_NET_BIND_SERVICE, so a privileged port could never bind."""
        port = _declared_port()
        assert port >= 1024, (
            f"port {port} needs CAP_NET_BIND_SERVICE, which {_CORE_UNIT.name} does not grant "
            f"(its AmbientCapabilities line is CAP_IPC_LOCK only)"
        )
        assert port <= 65535

    def test_declared_port_collides_with_nothing_shipped(self):
        """The other shipped listeners are read from source, so this check cannot rot into a guess."""
        server_port = int(re.search(r"port: int = Field\(default=(\d+)", _SERVER_CONFIG_SRC.read_text()).group(1))
        relay_port = int(re.search(r"^RELAY_PORT = (\d+)", _RELAY_SRC.read_text(), re.MULTILINE).group(1))
        port = _declared_port()
        assert port not in {server_port, relay_port, 443, 5432}, (
            f"the scrape port {port} collides with a shipped listener "
            f"(backend {server_port}, relay {relay_port}, nginx 443, PostgreSQL 5432)"
        )

    def test_non_integer_port_value_fails_loudly(self):
        """A typo must abort startup, not leave the door quietly dark — never silence the alarm."""
        with pytest.raises(ValueError):
            server_app.start_metrics_server("9091tcp")

    def test_main_wires_the_door(self):
        """The helper is not dead code: the ``venya-server`` entry point calls it."""
        assert "start_metrics_server()" in inspect.getsource(
            server_app.main
        ), "main() no longer opens the scrape endpoint, so the unit's Environment= line binds nothing"

    def test_executor_plane_ships_no_door(self):
        """AC5 boundary pin: this row opens the CORE door only.

        The executor has no scrape endpoint at all and its unit sets no metrics port. If a
        future row opens one there, that row edits this cell deliberately — the asymmetry is
        the fact being recorded, and either direction of silent drift is what this catches.
        """
        assert server_app.METRICS_PORT_ENV_VAR not in _EXECUTOR_UNIT.read_text()
        hits = [
            str(p.relative_to(_ROOT))
            for p in (_ROOT / "packages" / "executor" / "src").rglob("*.py")
            if server_app.METRICS_PORT_ENV_VAR in p.read_text(encoding="utf-8")
        ]
        assert not hits, f"the executor plane now reads the metrics port: {hits}"


class TestScrapeEndpointAnswers:
    """AC2(b): the physical half, both directions, through the shipped helper."""

    def test_dark_when_no_port_is_configured(self, monkeypatch):
        """The pre-#653 default install, as a permanent check: no variable, no bind, refused."""
        monkeypatch.delenv(server_app.METRICS_PORT_ENV_VAR, raising=False)
        port = _free_loopback_port()
        assert _refused(port), f"probe port {port} already answers — the dark-state check would be vacuous"
        assert os.environ.get(server_app.METRICS_PORT_ENV_VAR) is None
        assert server_app.start_metrics_server() is None, "the endpoint bound with no port configured"
        assert _refused(port), "something bound a port the helper was never given"

    def test_answers_and_carries_every_shipped_family(self, scrape_door):
        """AC1: with the variable set the endpoint answers and the counters are readable."""
        _port, status, body = scrape_door
        assert status == 200
        assert _SHIPPED_FAMILIES, "no metric families parsed from metrics.py — the scrape check is vacuous"
        missing = sorted(f for f in _SHIPPED_FAMILIES if f"# TYPE {f} " not in body)
        assert not missing, f"these shipped families are not on the scrape surface: {missing}"
        assert (
            "venya_revocation_read_refusals_total" in body
        ), "the #603 refusal counter — the row this one unblocks — is not operator-readable"

    def test_bound_to_loopback_only(self, scrape_door):
        """AC3: the bind is loopback, unchanged — and physically not reachable elsewhere."""
        port, _status, _body = scrape_door
        routable = _non_loopback_ipv4()
        if routable is None:
            pytest.skip("runner has no non-loopback IPv4 — nothing to aim the loopback negative at")
        assert _refused(
            port, host=routable
        ), f"the scrape endpoint answered on {routable}:{port}; it must bind 127.0.0.1 only"

    def test_live_socket_carries_the_loopback_address(self):
        """The address is read off the bound socket, not out of the source text."""
        port = _free_loopback_port()
        started = server_app.start_metrics_server(str(port))
        assert started is not None
        httpd, thread = started
        try:
            assert httpd.server_address[0] == "127.0.0.1", f"bound on {httpd.server_address[0]}"
            assert httpd.server_address[1] == port
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)


class TestDocsNameTheOperatorPath:
    """AC4: the operator path is stated in the docs, with the port the unit actually ships."""

    def test_deployment_config_names_the_variable(self):
        assert (
            server_app.METRICS_PORT_ENV_VAR in _DEPLOY_DOC.read_text()
        ), "docs/deployment-config.md does not name the metrics port variable"

    def test_firewall_inventory_lists_the_port_as_loopback_only(self):
        port = _declared_port()
        firewall = _FIREWALL_DOC.read_text()
        assert f"{port}/tcp" in firewall, (
            f"docs/FIREWALL.md has no {port}/tcp row — a listening port missing from the port "
            "inventory is how a host survey reads 'unexplained listener'"
        )

    def test_runbook_points_at_the_scrape_path(self):
        """The #603 runbook already says 'check venya_revocation_read_refusals_total'; it must
        also say how. A runbook naming an unreachable endpoint is the same defect in text form."""
        port = _declared_port()
        assert (
            f"http://127.0.0.1:{port}/metrics" in _RUNBOOK_DOC.read_text()
        ), "the runbook names the counter but not the loopback scrape path that reads it"
