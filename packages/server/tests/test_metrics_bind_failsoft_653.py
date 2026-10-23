# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#653 follow-on — a scrape port the host refuses must not take the core down.

THE FAILURE THIS FILE PINS. ``systemd/venya-core.service`` carries ``Restart=always`` AND an
``Environment=VENYA_METRICS_PORT`` line (both added by #653). Before this leg the bind was
unguarded, so one co-tenant on that port raised out of ``main()`` and the customer got a core
that never started, restarting forever, over an observability surface. The default that shipped
(9091) is a Prometheus pushgateway's default port, which is the most likely co-tenant on
exactly the hosts that run a core.

SCOPING AN ALARM IS NOT SILENCING ONE. The refusal still fires — one ``ERROR`` line, on every
boot that hits it, naming the port, the OS cause, what the operator loses, and the drop-in that
fixes it. What must never happen again is the crash loop, and what must never happen at all is
the SILENT dark door: the reason the ``except`` below is narrow is that a wide one would swallow
a misconfiguration and leave the door quietly dark with no explanation.

TWO CELLS, AND THE SECOND IS THE LOAD-BEARING ONE. A leg that tested only the busy-port case
would pass on a change that swallows everything. ``TestMisconfigurationStillAborts`` therefore
drives the three value faults that must still raise — non-numeric (``ValueError``), out of the
0-65535 range (``OverflowError``), negative (``socket.gaierror``, which is an ``OSError``
subclass and so is the case a careless ``except OSError`` WOULD have swallowed — that is the
sharp edge of this file) — plus the privilege case that shares the fail-soft arm on purpose.

Every bind here is on ``127.0.0.1`` with an ephemeral port the test chose, so nothing depends
on the shipped default being free on the runner, and no fixture leaks a listener: the holder
socket and each started server are closed in the same ``finally`` that reports them.
"""

import errno
import logging
import re
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from server import app as server_app

_ROOT = Path(__file__).resolve().parents[3]
_CORE_UNIT = _ROOT / "systemd" / "venya-core.service"


@pytest.fixture()
def held_loopback_port() -> Iterator[tuple[int, socket.socket]]:
    """Bind and LISTEN on an ephemeral loopback port, so the port under test is truly taken."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    try:
        yield holder.getsockname()[1], holder
    finally:
        holder.close()


def _free_loopback_port() -> int:
    """A port nothing holds right now: bind, read the number, release it."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _refusals_observed(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.levelno >= logging.ERROR and r.name == "venya.server" and "metrics scrape" in r.getMessage().lower()
    ]


class TestRefusedBindKeepsTheCoreServing:
    """THE POSITIVE HALF: the host said no to the port, and the core comes up anyway."""

    def test_busy_port_returns_not_serving_instead_of_raising(
        self, held_loopback_port: tuple[int, socket.socket], caplog: pytest.LogCaptureFixture
    ) -> None:
        port, holder = held_loopback_port
        assert holder.type == socket.SOCK_STREAM
        with caplog.at_level(logging.DEBUG, logger="venya.server"):
            result = server_app.start_metrics_server(str(port))
        assert result is None, f"a refused bind must report 'not serving', got {result!r}"

    def test_busy_port_is_refused_by_the_os_reason_the_row_names(
        self, held_loopback_port: tuple[int, socket.socket]
    ) -> None:
        """The arm is keyed on errno, so prove the contention really presents as EADDRINUSE.

        Without this the fail-soft could be holding open a door that a different error walks
        through, and the next cell would be green for the wrong reason.
        """
        port, _ = held_loopback_port
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            squatter.bind(("127.0.0.1", port))
        except OSError as exc:  # expected: the holder above already owns it
            assert exc.errno == errno.EADDRINUSE, f"expected EADDRINUSE, got errno={exc.errno} ({exc})"
        else:
            pytest.fail("a second bind on a held port unexpectedly succeeded — the fixture is not testing contention")
        finally:
            squatter.close()

    def test_busy_port_logs_one_error_naming_port_cause_consequence_and_fix(
        self, held_loopback_port: tuple[int, socket.socket], caplog: pytest.LogCaptureFixture
    ) -> None:
        port, _ = held_loopback_port
        with caplog.at_level(logging.DEBUG, logger="venya.server"):
            server_app.start_metrics_server(str(port))
        refusals = _refusals_observed(caplog)
        assert len(refusals) == 1, f"exactly one ERROR line is the alarm; got {len(refusals)}"
        text = refusals[0].getMessage()
        for label, needle in (
            ("the port", str(port)),
            ("the OS cause", "Address already in use"),
            ("what is lost", "no one outside this process can read them"),
            ("the drop-in fix", "systemctl edit venya-core"),
            ("the fix's variable", server_app.METRICS_PORT_ENV_VAR),
            ("the reload+restart", "daemon-reload"),
            ("the doc pointer", "docs/deployment-config.md"),
        ):
            assert needle in text, f"the ERROR line must name {label} ({needle!r}); got: {text}"
        assert refusals[0].levelno == logging.ERROR, "a warning would read as a note, not an alarm"

    def test_refusal_is_not_latched_and_a_free_port_still_opens(
        self, held_loopback_port: tuple[int, socket.socket], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Every boot that hits it logs, and one refusal does not darken the plane for good.

        The #651 defect class this project keeps closing is a once-per-process warning with no
        way to tell later how often it fired. The recovery half matters just as much: a core
        that failed once on a busy port must still open the door on a free one.
        """
        port, _ = held_loopback_port
        for _ in range(3):
            with caplog.at_level(logging.DEBUG, logger="venya.server"):
                assert server_app.start_metrics_server(str(port)) is None
        assert len(_refusals_observed(caplog)) == 3, "the refusal was latched — the alarm fired once, not every boot"

        free = _free_loopback_port()
        started = server_app.start_metrics_server(str(free))
        assert started is not None, "a refused bind poisoned the helper for a later, free port"
        httpd, thread = started
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class TestMisconfigurationStillAborts:
    """THE PAIRED NEGATIVE, and the reason the ``except`` did not just widen."""

    @pytest.mark.parametrize(
        ("value", "expected", "case"),
        [
            ("9091tcp", ValueError, "non-numeric: int() is outside the try on purpose"),
            ("70000", OverflowError, "outside 0-65535"),
            ("-1", OSError, "negative: a gaierror, which IS an OSError — a bare `except OSError` swallows this one"),
        ],
    )
    def test_bad_value_still_raises(self, value: str, expected: type[BaseException], case: str) -> None:
        with pytest.raises(expected):
            server_app.start_metrics_server(value)
        # An OSError case must ALSO prove it did not take the fail-soft arm.
        if expected is OSError:
            with pytest.raises(OSError) as caught:
                server_app.start_metrics_server(value)
            assert (
                caught.value.errno not in server_app._METRICS_BIND_REFUSALS
            ), f"a value fault ({case}) walked into the fail-soft arm (errno={caught.value.errno})"

    def test_refusal_set_holds_exactly_the_two_host_side_errnos(self) -> None:
        """The arm's membership is the ruling, so pin it rather than let it drift open."""
        assert server_app._METRICS_BIND_REFUSALS == frozenset({errno.EADDRINUSE, errno.EACCES}), (
            "the fail-soft is scoped to EADDRINUSE (port taken) and EACCES (privileged port the "
            "unit's AmbientCapabilities cannot grant); widening it swallows misconfiguration, "
            "narrowing it re-opens the crash loop"
        )

    def test_the_unit_that_sets_the_port_still_says_restart_always(self) -> None:
        """The reason this leg exists, pinned from the shipped unit rather than from prose.

        If a future leg ever drops ``Restart=always`` the crash loop stops being the harm, but
        then the fail-soft stops being the safety net it is described as — the two facts are
        read together on purpose, from ONE file, so neither can rot alone.
        """
        unit = _CORE_UNIT.read_text()
        assert re.search(
            r"^Restart=always\s*$", unit, re.MULTILINE
        ), f"{_CORE_UNIT.name} no longer carries Restart=always; the pairing this cell pins is stale"
        assert re.search(rf"^Environment={server_app.METRICS_PORT_ENV_VAR}=\d+\s*$", unit, re.MULTILINE), (
            f"{_CORE_UNIT.name} no longer opens the door, in which case the boot path this file "
            "guards is unreachable on a default install and the cells must be re-read, not deleted"
        )

    def test_the_shipped_default_port_is_not_a_known_co_tenant_default(self) -> None:
        """The other half of the fix: the default is not a monitoring stack's own port.

        Derived, not remembered — see the port derivation in the leg report for the fetched
        IANA registry behind the band. This asserts only the shipped-tree facts: the number the
        unit ships is outside the 9090-9199 monitoring band, outside the Grafana 3000-3999
        family, unprivileged, and below the Linux ephemeral floor of 32768.
        """
        raw = re.search(
            rf"^Environment={server_app.METRICS_PORT_ENV_VAR}=(\d+)\s*$", _CORE_UNIT.read_text(), re.MULTILINE
        )
        assert raw, "the unit no longer declares the port numerically"
        port = int(raw.group(1))
        assert port >= 1024, f"port {port} needs a capability the unit does not grant"
        assert port < 32768, f"port {port} sits inside the Linux default ephemeral range"
        assert not 9090 <= port <= 9199, f"port {port} is in the Prometheus/exporter band (pushgateway is 9091)"
        assert not 3000 <= port <= 3999, f"port {port} is in the Grafana family band"
