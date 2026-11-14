# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`R-2928` cl.4 / `R-2938` cl.2 item 1 — the recorded sandbox shape face, pieces 1-3.

The fleet held no machine face at all, which is why the estate-versus-wyoming question
ran two weeks without an answer and why three lanes met a changed host key with nothing
to consult. These cells are the control that replaces the argument: a face recorded by
the product, a comparison at boot, and a difference that **names the field** and its
**direction** — because "a socket appearing where the pinned build had none" (`R-2928`
cl.4) is a different fact from "a socket disappeared", and a report that flattens the two
into ``changed`` reports nothing.

Two boundary cells sit among them, and they are the reason the split between this module
and the shipped guard is where it is. The guard's predicate, its four socket paths, its
raise and its default are `R-2923` cl.1 / `R-2928` cl.2 and NOT this leg's to move: a
shape report that could widen or narrow that refusal would trade a security control for a
telemetry feature.

Every ``sbx``/``dpkg`` call is a patched ``subprocess.run`` in this process — no cell here
touches a real sandbox, a guest, or an estate box (`R-2911`). The physical half of the
DoD is a separate run, recorded in the leg report.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from executor import sandbox_shape as shape
from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import ExecutorDaemon
from executor.strategies import sbx_strategy as sbx

CLEAN_STDOUT = "agent\n"
EXPOSED_STDOUT = "agent sudo docker\nVENYA_RT W /var/run/docker.sock\n"
PRESENT_NOT_WRITABLE = "agent\nVENYA_RT P /var/run/docker.sock\n"

# The measured test-bed face (leg 1322, docker-sbx 0.46.0) and the measured estate face
# (leg 1326, docker-sbx 0.50.1), as the two records the comparison has to tell apart. Written out as
# fixtures rather than read from a box so a unit cell is reproducible on a laptop with no
# vendor CLI at all — which is most of them.
# The 0.46.0 build sha leg 1323 read off the test-bed face, and its vendor image id. Both are
# measurements of public vendor artifacts, not credentials — flagged only because a 40-hex
# string is indistinguishable from one by entropy.
MEASURED_BUILD_SHA = "991967dc90ce0d9a440cd1df1bdf3e395c5a2693"  # pragma: allowlist secret
MEASURED_IMAGE_ID = "b178ca62ec2e"  # pragma: allowlist secret

WYOMING_TEMPLATE_LS = json.dumps(
    {
        "images": [
            {
                "id": MEASURED_IMAGE_ID,
                "repository": "docker.io/docker/sandbox-templates",
                "tag": "shell-docker",
                "flavor": "shell-docker",
                "created_at": "2026-10-21T14:08:46Z",
                "size": 711958542,
            }
        ]
    }
)
INSPECT_REFUSAL = (
    "error: 'template inspect' requires --cloud in v1; local templates are docker images; inspect them with Docker"
)

SETTINGS_JSON = json.dumps(
    [
        {
            "key": "skills.defaultMode",
            "value": "readonly",
            "default": "readonly",
            "source": "default",
            "type": "string",
        },
        {
            "key": "ssh.agentForwardingEnabled",
            "value": True,
            "default": True,
            "source": "default",
            "type": "bool",
            "requires_restart": True,
        },
        {
            "key": "ssh.agentSocketPath",
            "value": "",
            "default": "",
            "source": "default",
            "type": "string",
            "requires_restart": True,
        },
        {"key": "sandbox.disk.dockerVolume", "value": "10g", "default": "10g", "source": "default", "type": "string"},
    ]
)


def fake_run_instrument(responses: dict[str, tuple[int, str, str]], calls: list | None = None):
    """A stand-in ``run_instrument``, keyed on the argv's first two tokens.

    The collectors call this seam rather than ``subprocess.run`` directly because a face
    is written at install and read at boot, and an absent vendor CLI, a wedged sandboxd
    and a slow reply are all facts to RECORD there rather than errors to propagate. The
    seam is one level above the child process for that reason, and the unrecognised
    default answers rc 1 with a named line so a new instrument shows up in the face as an
    unread field instead of a silent zero.
    """

    def run(argv, timeout=shape.INSTRUMENT_TIMEOUT):
        if calls is not None:
            calls.append(list(argv))
        return responses.get(" ".join(argv[:2]), (1, "", f"unstubbed instrument: {argv}"))

    return run


def _face_for(probe):
    return face(**shape.sandbox_view_fields(probe))


def field(value, **extra):
    return {"value": value, "state": "ok", "instrument": "test", "rc": 0, **extra}


def face(**fields):
    return {
        "schema": 1,
        "observed_at": "2026-11-14T10:00:00+00:00",
        "written_by": "installer",
        "venya_version": "0.1.0beta3",
        "fields": fields,
    }


class TestCollectRecordsWhatWasMeasured:
    """The record carries value AND source AND instrument AND rc, per field."""

    def test_every_field_names_its_instrument_and_rc(self, tmp_path, monkeypatch):
        calls: list = []
        responses = {
            "dpkg-query -W": (0, "docker-sbx\t0.46.0-1~ubuntu.24.04~noble", ""),
            "sbx version": (0, f"sbx version: v0.46.0 {MEASURED_BUILD_SHA}\n", ""),
            "sbx template": (0, WYOMING_TEMPLATE_LS, ""),
            "sbx settings": (0, SETTINGS_JSON, ""),
        }
        monkeypatch.setattr(shape, "run_instrument", fake_run_instrument(responses, calls))
        f = shape.collect_face(with_sandbox_view=False)
        for key, row in f["fields"].items():
            assert row["instrument"], f"{key} records no instrument — a number with no command is a guess"
            assert "rc" in row, f"{key} records no rc"
        assert f["fields"]["vendor.package"]["value"] == "docker-sbx"
        assert f["fields"]["vendor.package_version"]["value"] == "0.46.0-1~ubuntu.24.04~noble"
        assert f["fields"]["sbx.build_sha"]["value"] == MEASURED_BUILD_SHA

    def test_a_setting_records_its_source_as_well_as_its_value(self, monkeypatch):
        """Leg 1325: all 32 settings read ``source=default`` and the three channel keys
        carry no ``env_var`` name. A value without its source cannot tell a customer's
        choice from a build's default, so the face stores both or neither is usable."""
        calls: list = []
        responses = {
            "dpkg-query -W": (0, "docker-sbx\t0.46.0", ""),
            "sbx version": (0, "sbx version: v0.46.0 abcdef0123456789abcdef0123456789abcdef01\n", ""),
            "sbx template": (0, WYOMING_TEMPLATE_LS, ""),
            "sbx settings": (0, SETTINGS_JSON, ""),
        }
        monkeypatch.setattr(shape, "run_instrument", fake_run_instrument(responses, calls))
        f = shape.collect_face(with_sandbox_view=False)
        row = f["fields"]["setting.ssh.agentForwardingEnabled"]
        assert row["value"] is True
        assert row["setting_source"] == "default"
        assert row["env_var"] is None, "0.46.0 prints no env_var for this key; the record must not invent one"

    def test_an_unreadable_field_is_recorded_unread_with_its_rc_never_filled_from_memory(self, monkeypatch):
        """The estate refused ``template inspect`` (rc 1, leg 1326). The face says so."""
        calls: list = []
        responses = {
            "dpkg-query -W": (0, "docker-sbx\t0.50.1-1~ubuntu.26.04~resolute", ""),
            "sbx version": (0, "sbx version: v0.50.1 ddb0268d7124b9cf98955d0b08ffd71a0dfcebe4\n", ""),
            "sbx settings": (0, SETTINGS_JSON, ""),
        }
        by_argv = {
            "sbx template ls": (0, WYOMING_TEMPLATE_LS, ""),
            "sbx template inspect": (1, "", INSPECT_REFUSAL),
        }

        def run(argv, timeout=shape.INSTRUMENT_TIMEOUT):
            calls.append(list(argv))
            key = " ".join(argv[:3])
            if key in by_argv:
                return by_argv[key]
            return responses.get(" ".join(argv[:2]), (1, "", "unstubbed"))

        monkeypatch.setattr(shape, "run_instrument", run)
        f = shape.collect_face(with_sandbox_view=False)
        digest = f["fields"]["template.digest.docker.io/docker/sandbox-templates:shell-docker"]
        assert digest["state"] == "unread"
        assert digest["rc"] == 1
        assert "--cloud" in digest["reason"], "the refusal wording travels with the field"
        # and the half that DID read is still pinned: a mutable tag is not a pin
        assert f["fields"]["template.image_ids"]["value"] == [
            f"docker.io/docker/sandbox-templates:shell-docker#{MEASURED_IMAGE_ID}"
        ]

    def test_a_missing_vendor_cli_yields_unread_fields_and_still_writes_a_face(self, monkeypatch):
        """The install-time recorder must not die because a host cannot answer."""

        def run(argv, **kwargs):
            raise OSError("no such file or directory: 'sbx'")

        monkeypatch.setattr(shape.subprocess, "run", run)
        f = shape.collect_face(with_sandbox_view=False)
        assert f["fields"]["sbx.version_line"]["state"] == "unread"
        assert f["fields"]["sbx.version_line"]["rc"] is None
        assert f["schema"] == shape.SCHEMA_VERSION


class TestCompareNamesTheFieldAndItsDirection:
    """P3: the message names the field, and a path APPEARING is not the same fact as one
    disappearing. `R-2928` cl.4 calls the first a hostile-shape signal."""

    def test_identical_faces_produce_no_difference_and_say_so_plainly(self):
        f = face(**{"runtime_sockets.writable": field([]), "sandbox.groups": field(["agent"])})
        assert shape.compare_face(f, json.loads(json.dumps(f))) == []
        assert shape.describe([], f, f) == "sandbox shape matches the recorded face"

    def test_a_writable_socket_appearing_is_reported_as_appeared(self):
        recorded = face(
            **{"runtime_sockets.writable": field([]), "runtime_sockets.absent": field(["/var/run/docker.sock"])}
        )
        observed = face(
            **{"runtime_sockets.writable": field(["/var/run/docker.sock"]), "runtime_sockets.absent": field([])}
        )
        d = shape.compare_face(recorded, observed)
        appeared = [x for x in d if x["direction"] == "appeared" and x["field"] == "runtime_sockets.writable"]
        assert [x["observed"] for x in appeared] == ["/var/run/docker.sock"]
        gone = [x for x in d if x["direction"] == "disappeared" and x["field"] == "runtime_sockets.absent"]
        assert [x["recorded"] for x in gone] == ["/var/run/docker.sock"]
        assert "runtime_sockets.writable appeared" in shape.describe(d, recorded, observed)

    def test_paired_negative_appearing_and_disappearing_are_not_the_same_report(self):
        """Invert the two faces: the same set difference must flip direction. A
        comparison that reported both as ``changed`` would pass the first cell and fail
        this one — and it would be worthless to `R-2928` cl.5, which needs the direction
        to know whether to go backwards."""
        a = face(**{"sandbox.groups": field(["agent", "docker"])})
        b = face(**{"sandbox.groups": field(["agent"])})
        forward = {(x["field"], x["direction"], x["recorded"], x["observed"]) for x in shape.compare_face(a, b)}
        backward = {(x["field"], x["direction"], x["recorded"], x["observed"]) for x in shape.compare_face(b, a)}
        assert ("sandbox.groups", "disappeared", "docker", None) in forward
        assert ("sandbox.groups", "appeared", None, "docker") in backward
        assert forward != backward

    def test_paired_negative_a_clean_face_with_unread_fields_never_says_drift(self):
        """The wording this leg ships is part of what it claims. A face where every
        readable field agrees but one was never readable at record time is NOT drift, and
        printing the count as ``drift: 0 field(s) differ`` teaches an operator that the
        alarm word applies to a normal case."""
        recorded = face(
            **{
                "sandbox.groups": field(["agent"]),
                "template.digest.x": shape.unread("sbx template inspect", 1, "refused"),
            }
        )
        observed = face(**{"sandbox.groups": field(["agent"])})
        text = shape.describe(shape.compare_face(recorded, observed), recorded, observed)
        assert "drift" not in text.lower(), text
        assert "matches" in text
        assert "no recorded answer" in text, "the unread half must still be admitted out loud"

        recorded = face(**{"setting.skills.defaultMode": field("readonly", setting_source="default")})
        observed = face(**{"setting.skills.defaultMode": field("readwrite", setting_source="default")})
        d = shape.compare_face(recorded, observed)
        assert [x["field"] for x in d if x["direction"] == "changed"] == ["setting.skills.defaultMode"]

    def test_a_source_change_at_an_unchanged_value_is_its_own_signal(self):
        """Same answer to a different question: readonly-by-default and
        readonly-because-an-operator-chose-it must not read as agreement."""
        recorded = face(**{"setting.skills.defaultMode": field("readonly", setting_source="default")})
        observed = face(**{"setting.skills.defaultMode": field("readonly", setting_source="file")})
        d = shape.compare_face(recorded, observed)
        assert [x["field"] for x in d if x["direction"] == "changed"] == ["setting.skills.defaultMode.setting_source"]
        moved = next(x for x in d if x["direction"] == "changed")
        assert (moved["recorded"], moved["observed"]) == ("default", "file")
        assert moved["signal"] is True

    def test_paired_negative_an_unchanged_source_adds_no_signal(self):
        recorded = face(**{"setting.skills.defaultMode": field("readonly", setting_source="default")})
        observed = face(**{"setting.skills.defaultMode": field("readonly", setting_source="default")})
        assert shape.compare_face(recorded, observed) == []

    def test_a_field_unread_at_record_time_is_skipped_and_claims_nothing(self):
        """Leg 1326 could not read the digest. A later boot that CAN read it must not
        report drift against a blank, and must not crash either."""
        recorded = face(
            **{
                "template.digest.x": {
                    "value": None,
                    "state": "unread",
                    "instrument": "sbx template inspect",
                    "rc": 1,
                    "reason": "refused",
                }
            }
        )
        observed = face(**{"template.digest.x": field("sha256:aaaa")})
        d = shape.compare_face(recorded, observed)
        assert [x["direction"] for x in d] == ["skipped"]
        assert shape.drifts_of(d) == [], "an unread baseline must not generate an alarm"

    def test_a_field_that_stops_answering_is_a_signal_not_a_silence(self):
        """The verb worked at install and fails now. Reporting nothing there is the
        silent-filter class: an empty result read as an all-clear."""
        recorded = face(**{"setting.skills.defaultMode": field("readonly", setting_source="default")})
        observed = face(
            **{
                "setting.skills.defaultMode": {
                    "value": None,
                    "state": "unread",
                    "instrument": "sbx settings list --json",
                    "rc": 1,
                    "reason": "gone",
                }
            }
        )
        d = shape.compare_face(recorded, observed)
        assert [(x["direction"], x["signal"]) for x in d] == [("unread-now", True)]

    def test_a_field_this_build_added_is_reported_but_not_as_drift(self):
        """Otherwise every upgrade that adds a field alarm fires on the normal case."""
        recorded = face(**{"sandbox.groups": field(["agent"])})
        observed = face(
            **{
                "sandbox.groups": field(["agent"]),
                "runtime_sockets.probed_paths": field(list(sbx.RUNTIME_SOCKET_PATHS)),
            }
        )
        d = shape.compare_face(recorded, observed)
        assert [x["direction"] for x in d] == ["unrecorded"]
        assert shape.drifts_of(d) == []


class TestRecordFileIsAnIndependentFace:
    def test_written_record_parses_with_plain_json_and_carries_the_who_and_when(self, tmp_path):
        path = tmp_path / "sandbox-shape.json"
        shape.write_record(face(**{"sandbox.groups": field(["agent"])}), str(path))
        raw = json.loads(path.read_text())
        assert raw["written_by"] == shape.WRITER_INSTALLER
        assert raw["fields"]["sandbox.groups"]["value"] == ["agent"]
        assert "observed_at" in raw and "venya_version" in raw

    def test_record_mode_is_pinned_and_no_tmp_survives_a_good_write(self, tmp_path):
        path = tmp_path / "sub" / "sandbox-shape.json"
        shape.write_record(face(), str(path))
        assert (path.stat().st_mode & 0o777) == 0o640
        assert [p.name for p in path.parent.iterdir()] == ["sandbox-shape.json"]

    def test_corrupt_bytes_are_refused_loudly_and_not_read_as_an_empty_match(self, tmp_path, caplog):
        path = tmp_path / "sandbox-shape.json"
        path.write_text("{not json")
        with caplog.at_level("ERROR", logger="venya.executor.strategies.sbx_shape"):
            assert shape.read_record(str(path)) is None
        assert any("not JSON" in r.getMessage() for r in caplog.records), "a corrupt record must be announced"

    def test_a_face_with_no_fields_block_is_refused_rather_than_compared_as_blank(self, tmp_path):
        path = tmp_path / "sandbox-shape.json"
        path.write_text(json.dumps({"schema": 1}))
        assert shape.read_record(str(path)) is None

    def test_record_path_reads_its_env_at_call_time(self, monkeypatch):
        monkeypatch.delenv(shape.RECORD_PATH_ENV, raising=False)
        assert shape.record_path() == shape.DEFAULT_RECORD_PATH
        monkeypatch.setenv(shape.RECORD_PATH_ENV, "/tmp/scratch-shape.json")
        assert shape.record_path() == "/tmp/scratch-shape.json"


class TestBootComparison:
    def test_a_match_logs_once_and_returns_nothing(self, tmp_path, caplog):
        path = tmp_path / "sandbox-shape.json"
        probe = sbx.parse_runtime_probe(CLEAN_STDOUT)
        recorded = face(**shape.sandbox_view_fields(probe))
        shape.write_record(recorded, str(path))
        with caplog.at_level("INFO", logger="venya.executor.strategies.sbx_shape"):
            assert shape.compare_with_record(probe, str(path)) == []
        assert any("matches the face recorded" in r.getMessage() for r in caplog.records)

    def test_a_mismatch_logs_the_field_and_the_direction(self, tmp_path, caplog):
        path = tmp_path / "sandbox-shape.json"
        clean = sbx.parse_runtime_probe(CLEAN_STDOUT)
        exposed = sbx.parse_runtime_probe(EXPOSED_STDOUT)
        shape.write_record(face(**shape.sandbox_view_fields(clean)), str(path))
        with caplog.at_level("WARNING", logger="venya.executor.strategies.sbx_shape"):
            drifts = shape.compare_with_record(exposed, str(path))
        msg = "\n".join(r.getMessage() for r in caplog.records)
        assert drifts, "the boot comparison went silent on a socket appearing"
        assert "runtime_sockets.writable appeared" in msg
        assert "/var/run/docker.sock" in msg
        assert "report, not a decision" in msg, "the line must not read as a new refusal"

    def test_paired_negative_no_record_means_no_comparison_and_no_write(self, tmp_path, caplog):
        """The installer is the ONLY writer. A first boot that established its own face
        would let a shape that has already moved define the baseline it is judged
        against — so the absence is a warning, and the file stays absent."""
        path = tmp_path / "sandbox-shape.json"
        probe = sbx.parse_runtime_probe(CLEAN_STDOUT)
        with caplog.at_level("WARNING", logger="venya.executor.strategies.sbx_shape"):
            assert shape.compare_with_record(probe, str(path)) == []
        assert not path.exists()
        assert any("no recorded sandbox shape" in r.getMessage() for r in caplog.records)

    def test_a_corrupt_record_does_not_crash_the_boot_path(self, tmp_path):
        path = tmp_path / "sandbox-shape.json"
        path.write_text("garbage")
        assert shape.compare_with_record(sbx.parse_runtime_probe(CLEAN_STDOUT), str(path)) == []

    def test_the_boot_entry_point_takes_only_the_probe_the_guard_hands_it(self, tmp_path, monkeypatch):
        """`check_at_boot` is the callable the daemon passes to the guard, so its signature
        IS the contract between the two: one argument, and the path comes from the env the
        rest of the module reads at call time."""
        path = tmp_path / "sandbox-shape.json"
        probe = sbx.parse_runtime_probe(CLEAN_STDOUT)
        shape.write_record(shape.face_stub(probe) if hasattr(shape, "face_stub") else _face_for(probe), str(path))
        monkeypatch.setenv(shape.RECORD_PATH_ENV, str(path))
        assert shape.check_at_boot(probe) == []
        import inspect

        assert list(inspect.signature(shape.check_at_boot).parameters) == ["probe"]


class TestBootWiring:
    """The comparison has to be reachable from a real ``daemon.start()``, not just from a
    unit call — 'tests pass' does not close a leg whose success criterion is physical, and
    the same is true one level down for the wiring that lets the boot run it at all."""

    @staticmethod
    def _daemon(tmp_path):
        cfg = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            dns_resolver="192.0.2.53",
            relay_client_ids=["core-relay"],
            mtls=MtlsConfig(
                ca_cert=str(tmp_path / "ca.crt"),
                cert=str(tmp_path / "executor.crt"),
                key=str(tmp_path / "executor.key"),
            ),
            cert_rotation=CertificateRotationConfig(rotate_before_days=3),
        )
        d = ExecutorDaemon(cfg)
        d.cert_manager = MagicMock()
        d.reaper = MagicMock()
        return d

    def test_a_boot_with_a_drifted_face_logs_the_field_without_costing_the_boot(self, tmp_path, monkeypatch, caplog):
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            res = MagicMock()
            res.returncode, res.stdout, res.stderr = 0, "", ""
            verb = cmd[1] if len(cmd) > 1 else ""
            if verb == "exec":
                res.stdout = CLEAN_STDOUT
            return res

        d = self._daemon(tmp_path)
        # A recorded face that claims the sandbox user can write a runtime socket — the
        # estate shape leg 1326 measured — against this boot's clean probe answer.
        recorded = face(
            **shape.sandbox_view_fields(sbx.parse_runtime_probe(EXPOSED_STDOUT)),
            sbx_version=field("sbx version: v0.46.0"),
        )
        path = tmp_path / "sandbox-shape.json"
        shape.write_record(recorded, str(path))
        monkeypatch.setenv(shape.RECORD_PATH_ENV, str(path))
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        sentinel = RuntimeError("past-the-guard")
        d.cert_manager.register.side_effect = sentinel
        with (
            patch("executor.daemon.require_supported_sbx", return_value="0.46.0"),
            patch.object(sbx.subprocess, "run", run),
            patch("executor.daemon.reap_orphan_sandboxes", return_value=0),
            patch("executor.daemon.sweep_workspace_base", return_value=0),
            patch.object(shape, "run_instrument", lambda argv, timeout=shape.INSTRUMENT_TIMEOUT: (1, "", "unstubbed")),
            caplog.at_level("INFO", logger="venya.executor"),
        ):
            with pytest.raises(RuntimeError) as exc:
                d.start()
        assert exc.value is sentinel, "the shape comparison cost the executor its boot"
        msgs = [r.getMessage() for r in caplog.records]
        drift = [m for m in msgs if "runtime_sockets.writable disappeared" in m]
        assert drift, f"the boot never named the field that moved: {msgs}"
        assert any("report, not a decision" in m for m in msgs)

    def test_paired_negative_a_boot_with_a_matching_face_logs_no_drift(self, tmp_path, monkeypatch, caplog):
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            res = MagicMock()
            res.returncode, res.stdout, res.stderr = 0, "", ""
            if cmd[1] == "exec":
                res.stdout = CLEAN_STDOUT
            return res

        d = self._daemon(tmp_path)
        probe = sbx.parse_runtime_probe(CLEAN_STDOUT)
        path = tmp_path / "sandbox-shape.json"
        shape.write_record(face(**shape.sandbox_view_fields(probe)), str(path))
        monkeypatch.setenv(shape.RECORD_PATH_ENV, str(path))
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        sentinel = RuntimeError("past-the-guard")
        d.cert_manager.register.side_effect = sentinel
        with (
            patch("executor.daemon.require_supported_sbx", return_value="0.46.0"),
            patch.object(sbx.subprocess, "run", run),
            patch("executor.daemon.reap_orphan_sandboxes", return_value=0),
            patch("executor.daemon.sweep_workspace_base", return_value=0),
            patch.object(shape, "run_instrument", lambda argv, timeout=shape.INSTRUMENT_TIMEOUT: (1, "", "unstubbed")),
            caplog.at_level("INFO", logger="venya.executor"),
        ):
            with pytest.raises(RuntimeError):
                d.start()
        msgs = [r.getMessage() for r in caplog.records]
        assert any("matches the face recorded" in m for m in msgs), msgs
        assert not any("drift" in m for m in msgs)


class TestTheGuardStillDecides:
    """The boundary cells. Adding a shape report to the boot guard may not move what the
    guard refuses, what it tests, or when it raises (`R-2923` cl.1, `R-2928` cl.2)."""

    def fake_sbx(self, calls, probe_stdout):
        def run(cmd, **kwargs):
            calls.append(list(cmd))
            res = MagicMock()
            res.returncode, res.stdout, res.stderr = 0, "", ""
            verb = cmd[1] if len(cmd) > 1 else ""
            if verb == "exec":
                res.stdout = probe_stdout
            return res

        return run

    def test_the_refusing_probe_reaches_the_report_AND_still_refuses(self, tmp_path, monkeypatch):
        """The refusal must not be the ONLY signal on a hostile shape.

        Measured physically on the test bed at v0.46.0 (leg 1328): the live sandbox there
        has two writable runtime sockets, so the guard refuses on every boot — which means
        a report mounted only on the pass path would never print on exactly the face
        `R-2928` cl.4 was written about. So the probe is handed over BEFORE the raise
        branch, and the refusal still refuses. Both halves are asserted here, and the
        ordering is why: if the hook were after the raise, this cell's first assertion
        could not pass.
        """
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        seen: list = []
        monkeypatch.setattr(sbx, "_report_shape", seen.append)
        with patch.object(sbx.subprocess, "run", self.fake_sbx(calls, EXPOSED_STDOUT)):
            with pytest.raises(sbx.SbxRuntimeExposureError):
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert len(seen) == 1 and seen[0].exposed is True, "the report never saw the hostile face"
        assert [c[1] for c in calls] == ["create", "exec", "rm"]

    def test_a_report_that_raises_cannot_swallow_the_refusal_on_a_hostile_face(self, tmp_path, monkeypatch):
        """PAIRED NEGATIVE, the expensive ordering: moving the hook earlier put a shape
        report INSIDE the path to the raise. An exception from it must be logged and the
        refusal must still be the thing the boot sees."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))

        def boom(_probe):
            raise RuntimeError("shape module is broken")

        calls: list = []
        with (
            patch.object(sbx.subprocess, "run", self.fake_sbx(calls, EXPOSED_STDOUT)),
            patch("executor.sandbox_shape.check_at_boot", side_effect=boom),
        ):
            with pytest.raises(sbx.SbxRuntimeExposureError):
                sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert [c[1] for c in calls] == ["create", "exec", "rm"]

    def test_a_clean_probe_still_boots_and_hands_the_report_its_probe(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []
        seen: list = []
        monkeypatch.setattr(sbx, "_report_shape", seen.append)
        with patch.object(sbx.subprocess, "run", self.fake_sbx(calls, PRESENT_NOT_WRITABLE)):
            face_line = sbx.require_runtime_isolated_sandbox(memory_mb=512)
        assert "not writable" in face_line
        assert len(seen) == 1
        assert seen[0].present == ["/var/run/docker.sock"] and seen[0].writable == []

    def test_a_shape_report_that_raises_cannot_stop_the_clean_boot_either(self, tmp_path, monkeypatch):
        """PAIRED NEGATIVE, the other direction of the same claim: a broken report must not
        turn a bootable face into a refusal either. Both outcomes are asserted, because
        `_report_shape` now sits in front of the branch that decides between them."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))

        def boom(_probe):
            raise RuntimeError("shape module is broken")

        calls: list = []
        with (
            patch.object(sbx.subprocess, "run", self.fake_sbx(calls, CLEAN_STDOUT)),
            patch("executor.sandbox_shape.check_at_boot", side_effect=boom),
        ):
            assert "no writable runtime socket" in sbx.require_runtime_isolated_sandbox(memory_mb=512)

    def test_the_guards_own_signature_is_unchanged_by_the_report(self):
        """The shipped call sites and the #312 cells must not have to know the report
        exists at all — a new required parameter here would itself be a change to the
        guard's contract, and the release page cites this file's coordinates."""
        import inspect

        sig = inspect.signature(sbx.require_runtime_isolated_sandbox)
        assert list(sig.parameters) == ["memory_mb", "timeout"], sig


class TestSandboxViewHalf:
    def test_the_absent_list_names_the_denominator_so_the_limit_is_in_the_record(self):
        probe = sbx.parse_runtime_probe(PRESENT_NOT_WRITABLE)
        v = shape.sandbox_view_fields(probe)
        assert v["runtime_sockets.probed_paths"]["value"] == list(sbx.RUNTIME_SOCKET_PATHS)
        assert "/run/docker.sock" in v["runtime_sockets.absent"]["value"]
        assert v["sandbox.groups"]["value"] == ["agent"]

    def test_the_view_uses_the_guards_own_probe_command_not_a_second_one(self, tmp_path, monkeypatch):
        """One question, asked at install and at boot. If the recorder built its own
        shell string the two halves could drift apart and the comparison would be
        measuring two different things."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            res = MagicMock()
            res.returncode, res.stderr = 0, ""
            res.stdout = CLEAN_STDOUT if cmd[1] == "exec" else ""
            return res

        monkeypatch.setattr(shape.subprocess, "run", run)
        v = shape._sandbox_view(512)
        exec_call = next(c for c in calls if c[1] == "exec")
        assert exec_call[3:] == sbx.rt_probe_argv()
        assert v["sandbox.groups"]["value"] == ["agent"]
        assert [c[1] for c in calls] == ["create", "exec", "rm"]
        assert list((tmp_path / "wsbase").iterdir()) == []

    def test_a_view_that_cannot_be_asked_records_the_half_unread(self, tmp_path, monkeypatch):
        """No Docker auth at install ⇒ no create ⇒ an unread in-sandbox half, said out
        loud with the rc, and the rest of the face still gets recorded."""
        monkeypatch.setattr(sbx, "WORKSPACE_BASE", str(tmp_path / "wsbase"))
        calls: list = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            res = MagicMock()
            res.returncode, res.stdout = 125, ""
            res.stderr = "You are not authenticated to Docker"
            return res

        monkeypatch.setattr(shape.subprocess, "run", run)
        v = shape._sandbox_view(512)
        assert v["sandbox.groups"]["state"] == "unread"
        assert v["sandbox.groups"]["rc"] == 125
        assert "authenticated" in v["sandbox.groups"]["reason"]
        assert [c[1] for c in calls] == ["create"], "no rm for a sandbox that never existed"


class TestCliIsASecondInstrument:
    """`R-2939` cl.3: a record only its own writer can read back is not a record."""

    def test_show_renders_the_written_file_without_the_collector(self, tmp_path, capsys):
        path = tmp_path / "sandbox-shape.json"
        shape.write_record(face(**{"sandbox.groups": field(["agent", "docker"])}), str(path))
        assert shape.main(["show", "--record", str(path)]) == 0
        out = capsys.readouterr().out
        assert "sandbox.groups = ['agent', 'docker']" in out
        assert "written_by installer" in out

    def test_show_on_a_missing_file_says_so_rather_than_printing_nothing(self, tmp_path, capsys):
        assert shape.main(["show", "--record", str(tmp_path / "absent.json")]) == 2
        assert "no recorded face" in capsys.readouterr().out

    def test_check_exits_one_on_drift_and_the_rc_is_the_verdict(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / "sandbox-shape.json"
        shape.write_record(face(**{"sandbox.groups": field(["agent"])}), str(path))
        monkeypatch.setattr(shape, "collect_face", lambda **kw: face(**{"sandbox.groups": field(["agent", "docker"])}))
        assert shape.main(["check", "--record", str(path), "--no-sandbox-view"]) == 1
        assert "sandbox.groups appeared" in capsys.readouterr().out

    def test_paired_negative_check_exits_zero_when_the_face_matches(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / "sandbox-shape.json"
        recorded = face(**{"sandbox.groups": field(["agent"])})
        shape.write_record(recorded, str(path))
        monkeypatch.setattr(shape, "collect_face", lambda **kw: json.loads(json.dumps(recorded)))
        assert shape.main(["check", "--record", str(path), "--no-sandbox-view"]) == 0
        assert "matches the recorded face" in capsys.readouterr().out

    def test_record_writes_what_show_reads_and_names_every_unread_field(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / "sandbox-shape.json"
        responses = {
            "dpkg-query -W": (0, "docker-sbx\t0.46.0", ""),
            "sbx version": (0, f"sbx version: v0.46.0 {MEASURED_BUILD_SHA}\n", ""),
            "sbx settings": (0, SETTINGS_JSON, ""),
        }

        def run(argv, timeout=shape.INSTRUMENT_TIMEOUT):
            if argv[:3] == ["sbx", "template", "ls"]:
                return 1, "", "You are not authenticated to Docker"
            return responses.get(" ".join(argv[:2]), (1, "", "unstubbed"))

        monkeypatch.setattr(shape, "run_instrument", run)
        assert shape.main(["record", "--out", str(path), "--no-sandbox-view"]) == 0
        printed = capsys.readouterr().out
        assert "unread: 2" in printed, "template.refs and template.image_ids both went unread and must be counted"
        assert "not authenticated" in printed
        assert json.loads(path.read_text())["written_by"] == "installer"
