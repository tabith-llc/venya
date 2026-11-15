# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The recorded sandbox shape face: capture it at install, compare it at boot.

Why this exists (`R-2928` cl.4, `R-2938` cl.2 item 1): the fleet held no machine face
at all, so two weeks of estate-versus-wyoming argument could not be settled and a moved
template would have read as vendor unfriendliness. The control is one the product can
run: ask read-only questions once, write the answers down beside the instrument that
produced them, and ask them again at boot.

A field record carries four things, and each is load-bearing:

* ``value`` — the reading. Never a default and never a memory: a read that failed
  leaves this ``None`` and ``state`` says ``unread``.
* ``instrument`` — the exact command that produced it, so a later seat re-derives the
  answer instead of trusting this one.
* ``rc`` — that instrument's exit code. An unread field records the rc of the verb that
  failed, which is how "the vendor refused this read-only" is told apart from "nobody
  asked". Leg 1326 recorded ``sbx template inspect`` rc 1 in exactly this shape.
* ``setting_source`` — for a vendor setting, the build's own answer for where the value
  came from. A value without its source cannot tell a customer's choice from a build's
  default, and leg 1325 measured all 32 settings on the 0.46.0 face reading
  ``source=default``, with no ``env_var`` name on any of the three channel keys.

A tag is not a pin. Leg 1326 measured the shipped template addressed by mutable tag
(``docker.io/docker/sandbox-templates`` tag ``shell-docker``), so this face records the
image id beside the name and keeps the digest as its own field — unread where the vendor
refuses it read-only, with the failed verb, rather than blank or inferred. The image id
is what names the bytes; the tag names an intention about them.

Out of scope, deliberately: prior-build retention and fallback-on-drift (`R-2928` cl.5)
are a later leg, and this one stubs neither. This module records, compares, and says
which field moved. It decides nothing the shipped boot refusal decides — that guard's
predicate, its four socket paths, its raise and its default are untouched here (the only
thing this module asks of it is a callback on the path where it has already chosen not to
refuse, and a failure inside this module can cost a log line and nothing more).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404 — read-only vendor CLI calls, fixed argv, no shell
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import SANDBOX_MEMORY_DEFAULT_MB

logger = logging.getLogger("venya.executor.strategies.sbx_shape")

#: Schema tag of the face file, so a reader tells a face this build wrote from one an
#: older build wrote, rather than guessing from which keys happen to be present.
SCHEMA_VERSION = 1

#: Where the recorded face lives. ``/var/lib/venya/executor`` is in the unit's
#: ReadWritePaths (systemd/venya-executor.service:48) and pinned 0750 venya:venya by the
#: installer (#380), so the installer writes it, the daemon reads it, and neither needs
#: a capability it does not already have.
DEFAULT_RECORD_PATH = "/var/lib/venya/executor/sandbox-shape.json"

#: Per-deployment override, read AT CALL TIME — the same env-at-call-time idiom as
#: ``rt_probe_timeout()``. It is also what lets a scratch physical run point the record
#: at a path it owns instead of the installed one.
RECORD_PATH_ENV = "VENYA_SANDBOX_SHAPE_FILE"

#: The vendor settings this face records, spelled as the vendor's own ``settings list``
#: prints them. Leg 1325 read all four on the 0.46.0 face and leg 1326 read three of
#: them on the 0.50.1 estate face; nothing here is a name invented for this module.
SETTING_KEYS: tuple[str, ...] = (
    "skills.defaultMode",
    "ssh.agentForwardingEnabled",
    "ssh.agentSocketPath",
    "sandbox.disk.dockerVolume",
)

#: Bound on each read-only instrument. These are local CLI calls, and the subprocess
#: timeout interlock (the #598 class, scripts/check_subprocess_timeout_census.py) wants
#: every site in ``packages/*/src`` bounded explicitly: a wedged sandboxd must not park
#: a boot, and it certainly must not park a boot that came to REPORT on the shape.
INSTRUMENT_TIMEOUT = 20.0

#: A 40-hex build sha, which is the second token of ``sbx version`` on both measured
#: faces (``v0.46.0 991967dc…`` estate-read by 1323, ``v0.50.1 ddb0268d…`` by 1326).
_SHA = re.compile(r"\b[0-9a-f]{40}\b")

#: Who wrote the record, stored IN the record. Only the installer writes one: a face
#: established automatically at boot would let a hostile shape define its own baseline,
#: which is the opposite of the control. So ``installer`` is the only value a correct
#: record carries, and the boot path's job is to compare, never to establish.
WRITER_INSTALLER = "installer"

#: Fields whose value is a set of things, compared element-wise so the DIRECTION of a
#: move survives the comparison. A socket path appearing where the recorded build had
#: none is the hostile-shape signal `R-2928` cl.4 names; a value-level "the list
#: changed" would bury it.
SET_FIELDS = frozenset(
    {
        "sandbox.groups",
        "runtime_sockets.writable",
        "runtime_sockets.present_not_writable",
        "runtime_sockets.absent",
        "template.refs",
        "template.image_ids",
    }
)

#: Directions that are drift worth a warning line. ``unrecorded`` and ``skipped`` are
#: deliberately NOT here: a field with no recorded answer has nothing to differ FROM, and
#: calling that drift would train an operator to ignore the signal that matters.
SIGNAL_DIRECTIONS = frozenset({"appeared", "disappeared", "changed", "unread-now"})


def record_path() -> str:
    """The face file's path: ``VENYA_SANDBOX_SHAPE_FILE``, else the installed default."""
    raw = os.environ.get(RECORD_PATH_ENV, "").strip()
    return raw or DEFAULT_RECORD_PATH


def field(value: Any, instrument: str, rc: int | None = 0, **extra: Any) -> dict[str, Any]:
    """One readable field."""
    out: dict[str, Any] = {"value": value, "state": "ok", "instrument": instrument, "rc": rc}
    out.update(extra)
    return out


def unread(instrument: str, rc: int | None, why: str) -> dict[str, Any]:
    """A field the instrument could not answer, recorded with the rc of what failed.

    Recorded rather than filled in. Every field this module cannot read still gets a line
    in the file naming the verb and its exit code, because the useful difference between
    "this build does not expose that" and "this lane did not look" is the whole content of
    the record.
    """
    return {"value": None, "state": "unread", "instrument": instrument, "rc": rc, "reason": why}


def run_instrument(argv: list[str], timeout: float = INSTRUMENT_TIMEOUT) -> tuple[int | None, str, str]:
    """Run one read-only instrument. Returns ``(rc, stdout, stderr)``; rc None = unrunnable.

    Never raises. The same face is written at install (where a failed read must not abort
    the install) and read at boot (where it must not cost the guard), so an absent vendor
    CLI, a wedged daemon and a slow reply are all facts to record rather than errors to
    propagate. The caller checks ``rc``.
    """
    try:
        done = subprocess.run(  # nosec B603 — fixed argv built from module literals, no shell, no caller input
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "", f"{type(exc).__name__}: {exc}"
    return done.returncode, done.stdout or "", done.stderr or ""


def _clip(text: str) -> str:
    """Shorten a vendor error line for a field's ``reason``. Structure, never a dump."""
    return (text or "").strip()[:200]


def dpkg_fields(fields: dict[str, Any]) -> None:
    """Vendor package name and version, from one ``dpkg-query`` (absent off-Debian = unread)."""
    label = "dpkg-query -W -f='${Package} ${Version}' docker-sbx"
    rc, out, err = run_instrument(["dpkg-query", "-W", "-f=${Package}\t${Version}", "docker-sbx"])
    if rc != 0:
        fields["vendor.package"] = unread(label, rc, _clip(err or out or "no answer"))
        return
    name, _, version = out.partition("\t")
    fields["vendor.package"] = field(name.strip(), label, rc)
    fields["vendor.package_version"] = field(version.strip(), label, rc)


def sbx_version_fields(fields: dict[str, Any]) -> None:
    """The vendor CLI face: the whole version line, and the build sha inside it."""
    label = "sbx version"
    rc, out, err = run_instrument(["sbx", "version"])
    line = _clip(out + err)
    if rc != 0 or not line:
        fields["sbx.version_line"] = unread(label, rc, _clip(err or out or "no answer"))
        return
    fields["sbx.version_line"] = field(line, label, rc)
    sha = _SHA.search(line)
    if sha is None:
        fields["sbx.build_sha"] = unread(label, rc, "the version line carries no 40-hex build sha")
    else:
        fields["sbx.build_sha"] = field(sha.group(0), label, rc)


def template_fields(fields: dict[str, Any]) -> None:
    """Template name, image id, and the digest the vendor may refuse.

    ``template ls --json`` answered on both measured faces; ``template inspect`` refused
    (rc 1 at the estate for leg 1326, and on 0.46.0 the CLI says it is cloud-only in v1).
    So the image id is what gets pinned here and the digest keeps its own field per ref,
    recording the refusal. Which is load-bearing: the image id, because the tag the vendor
    resolves a bare ``shell`` agent through is mutable — that resolution is where the
    engine comes from, and leg 1326 measured it happening inside the vendor, unobserved.
    """
    label = "sbx template ls --json"
    rc, out, err = run_instrument(["sbx", "template", "ls", "--json"])
    if rc != 0:
        fields["template.refs"] = unread(label, rc, _clip(err or out or "no answer"))
        fields["template.image_ids"] = unread(label, rc, _clip(err or out or "no answer"))
        return
    try:
        images = json.loads(out).get("images") or []
    except (ValueError, AttributeError):
        fields["template.refs"] = unread(label, rc, "the JSON answer did not parse")
        fields["template.image_ids"] = unread(label, rc, "the JSON answer did not parse")
        return
    refs = sorted(f"{i.get('repository', '')}:{i.get('tag', '')}" for i in images)
    fields["template.refs"] = field(refs, label, rc)
    fields["template.image_ids"] = field(
        sorted(f"{i.get('repository', '')}:{i.get('tag', '')}#{i.get('id', '')}" for i in images), label, rc
    )
    for ref in refs:
        iref_label = f"sbx template inspect {ref} --json"
        irrc, iout, ierr = run_instrument(["sbx", "template", "inspect", ref, "--json"])
        digest = _digest_of(iout) if irrc == 0 else None
        if digest is None:
            fields[f"template.digest.{ref}"] = unread(
                iref_label, irrc, _clip(ierr or iout or "no digest in the answer")
            )
        else:
            fields[f"template.digest.{ref}"] = field(digest, iref_label, irrc)


def _digest_of(stdout: str) -> str | None:
    """First digest-looking string the inspect answer carries, or None.

    Key names are tried against what the CLI might print, not asserted: this build refused
    the verb entirely (rc 1), so no face has ever shown the real shape of a success here.
    A name that does not exist is a miss, and a miss records unread — never a guess.
    """
    try:
        payload = json.loads(stdout)
    except ValueError:
        return None
    for container in _walk(payload):
        if not isinstance(container, dict):
            continue
        for key in ("digest", "Digest", "repoDigests", "RepoDigests"):
            found = container.get(key)
            if isinstance(found, str) and found:
                return found
            if isinstance(found, list):
                for item in found:
                    if isinstance(item, str) and item:
                        return item
    return None


def _walk(payload: Any):
    """Every dict in a parsed JSON document, depth-first. Bounded, no recursion blow-up."""
    stack = [payload]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def setting_fields(fields: dict[str, Any]) -> None:
    """The vendor settings, each with the build's own ``source`` beside its value."""
    label = "sbx settings list --json"
    rc, out, err = run_instrument(["sbx", "settings", "list", "--json"])
    if rc != 0:
        for key in SETTING_KEYS:
            fields[f"setting.{key}"] = unread(label, rc, _clip(err or out or "no answer"))
        return
    try:
        rows = json.loads(out)
    except ValueError:
        for key in SETTING_KEYS:
            fields[f"setting.{key}"] = unread(label, rc, "the JSON answer did not parse")
        return
    by_key = {r.get("key"): r for r in rows if isinstance(r, dict)}
    for key in SETTING_KEYS:
        row = by_key.get(key)
        if row is None:
            fields[f"setting.{key}"] = unread(label, rc, f"this build lists no setting named {key!r}")
            continue
        fields[f"setting.{key}"] = field(
            row.get("value"), label, 0, setting_source=row.get("source"), env_var=row.get("env_var")
        )


def sandbox_view_fields(probe: Any) -> dict[str, Any]:
    """The in-sandbox half of a face, from the ``RuntimeProbe`` of the sandbox view.

    Split out from ``collect_face`` because the boot path already holds this answer: the
    runtime-isolation probe creates and execs one throwaway sandbox per boot, and asking
    it again would cost a second create to learn what the first one printed.

    ``runtime_sockets.absent`` is the complement WITHIN the paths the probe asks about,
    and ``runtime_sockets.probed_paths`` records that set. So the limit of the question is
    in the record: a runtime socket at a path outside that set is invisible to this face,
    and it is invisible to the shipped guard too. Naming the denominator, per the
    instrument rule.
    """
    from .strategies.sbx_strategy import RUNTIME_SOCKET_PATHS

    probed = list(RUNTIME_SOCKET_PATHS)
    writable = sorted(probe.writable)
    present = sorted(probe.present)
    seen = set(writable) | set(present)
    return {
        "sandbox.groups": field(sorted(probe.groups), "sbx exec probe: id -Gn", 0),
        "runtime_sockets.writable": field(writable, "sbx exec probe: [ -w ]", 0),
        "runtime_sockets.present_not_writable": field(present, "sbx exec probe: [ -e ] and [ -w ]", 0),
        "runtime_sockets.absent": field(sorted(p for p in probed if p not in seen), "sbx exec probe: complement", 0),
        "runtime_sockets.probed_paths": field(probed, "RUNTIME_SOCKET_PATHS at the recorded build", 0),
    }


def collect_face(
    memory_mb: int | None = None,
    *,
    with_sandbox_view: bool = True,
    probe: Any = None,
) -> dict[str, Any]:
    """One face: the host-side reads, plus the in-sandbox view from a probe or a create.

    ``probe`` supplies the in-sandbox half from a sandbox someone else already asked (the
    boot guard). Otherwise ``with_sandbox_view`` creates one throwaway sandbox, asks it,
    and removes it — which is what the installer does, and the reason the installer's face
    is the trustworthy one: it asked on purpose, at the moment the build was chosen.
    """
    fields: dict[str, Any] = {}
    dpkg_fields(fields)
    sbx_version_fields(fields)
    template_fields(fields)
    setting_fields(fields)
    if probe is not None:
        fields.update(sandbox_view_fields(probe))
    elif with_sandbox_view:
        fields.update(_sandbox_view(memory_mb if memory_mb is not None else SANDBOX_MEMORY_DEFAULT_MB))
    return {
        "schema": SCHEMA_VERSION,
        "observed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "venya_version": venya_version(),
        "fields": fields,
    }


def venya_version() -> str:
    """The build face of this layer, written beside the readings it took.

    The version goes in the record because the vendor floors and never pins
    (``SBX_MIN_VERSION``, and leg 1325's whole point: a shape claim without its version is
    a claim about no machine). A failure to render it is recorded as unread rather than
    stopping the record — same rule the ``--version`` plate follows (#768).
    """
    try:
        from core.version import release_version

        return release_version("executor")
    except Exception as exc:
        return f"unread: {type(exc).__name__}"


def _unread_view(label: str, rc: int | None, why: str) -> dict[str, Any]:
    """The in-sandbox half when it could not be asked: one unread field, naming the verb.

    A single field rather than four, because they would all carry the same rc and the same
    reason, and the comparison reports "this half was never observed" honestly either way.
    """
    return {
        "sandbox.groups": unread(label, rc, _clip(why)),
    }


def _sandbox_view(memory_mb: int) -> dict[str, Any]:
    """Create one throwaway sandbox, ask it the read-only probe question, remove it.

    Uses the guard's own argv builder and parser (``rt_probe_argv``, ``parse_runtime_probe``)
    and the guard's own ``SANDBOX_TEMPLATE`` for the create that makes the sandbox, so the
    recorded in-sandbox view and the boot-checked in-sandbox view are literally the same
    question, not two approximations of it. Sharing the inner argv was never enough on its
    own: two different outer creates can hand the same question to different sandboxes, and
    then the record asserts a shape production does not build and every boot reads as drift.
    The sandbox name carries ``venya-`` so the boot reap collects a probe leaked by a kill
    mid-flight (#474), exactly as the guard's own ``venya-rt-probe-*`` does.
    """
    from .strategies.sbx_strategy import (
        SANDBOX_TEMPLATE,
        WORKSPACE_BASE,
        parse_runtime_probe,
        rt_probe_argv,
        rt_probe_timeout,
    )

    name = f"venya-shape-probe-{os.getpid()}"
    label = "sbx create + sbx exec probe (id -Gn and the runtime socket tests)"
    workspace: str | None = None
    created = False
    try:
        os.makedirs(WORKSPACE_BASE, mode=0o700, exist_ok=True)
        workspace = tempfile.mkdtemp(prefix="shapeview_", dir=WORKSPACE_BASE)
        bound = rt_probe_timeout()
        make_rc, _, make_err = run_instrument(
            [
                "sbx",
                "create",
                "--name",
                name,
                "--memory",
                f"{int(memory_mb)}m",
                "-t",
                SANDBOX_TEMPLATE,
                "shell",
                workspace,
            ],
            timeout=bound,
        )
        if make_rc != 0:
            return _unread_view(label, make_rc, make_err or "sbx create refused")
        created = True
        view_rc, view_out, view_err = run_instrument(["sbx", "exec", name, *rt_probe_argv()], timeout=bound)
        if view_rc != 0:
            return _unread_view(label, view_rc, view_err or view_out or "sbx exec refused")
        try:
            probe = parse_runtime_probe(view_out)
        except Exception as exc:
            return _unread_view(label, view_rc, f"{type(exc).__name__}: {exc}")
        return sandbox_view_fields(probe)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _unread_view(label, None, f"{type(exc).__name__}: {exc}")
    finally:
        if created:
            rm_rc, _, rm_err = run_instrument(["sbx", "rm", "--force", name], timeout=30.0)
            if rm_rc != 0:
                logger.warning(
                    "shape-probe sandbox %s was not removed (rc=%r: %s) — the boot reap collects every "
                    "venya-* sandbox as residue, so the next boot takes it (#474)",
                    name,
                    rm_rc,
                    _clip(rm_err),
                )
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)


def read_record(path: str | None = None) -> dict[str, Any] | None:
    """The recorded face, or None when there is none to compare against.

    Unreadable bytes are reported and answered None rather than treated as an empty
    match: a record this side of a truncated write must never read as "everything
    agrees".
    """
    target = path or record_path()
    try:
        raw = Path(target).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.error("the recorded sandbox shape at %s could not be read (%s) — nothing was compared", target, exc)
        return None
    try:
        face = json.loads(raw)
    except ValueError as exc:
        logger.error("the recorded sandbox shape at %s is not JSON (%s) — re-record it", target, exc)
        return None
    if not isinstance(face, dict) or not isinstance(face.get("fields"), dict):
        logger.error("the recorded sandbox shape at %s carries no fields block — re-record it", target)
        return None
    return face


def write_record(face: dict[str, Any], path: str | None = None, *, writer: str = WRITER_INSTALLER) -> str:
    """Write the face: its own directory, mkstemp, mode pinned, one ``os.replace``.

    The same shape every other durable executor write uses (#478, #479): a unique temp so
    a crashed writer cannot wedge the path with a stale ``.tmp``, and ``os.replace`` so a
    reader never sees half a record. Mode 0640 — the daemon must read it and the
    directory is already 0750 venya:venya, so this adds no new reach.
    """
    target = Path(path or record_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(face)
    payload["written_by"] = writer
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=target.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(tmp_name, 0o640)
        os.replace(tmp_name, target)
    except OSError:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return str(target)


def compare_face(recorded: dict[str, Any], observed: dict[str, Any]) -> list[dict[str, Any]]:
    """Every difference, one entry per field or per moved set element, stable order.

    Direction is the point (`R-2928` cl.4: "a socket appearing where the pinned build had
    none is a hostile-shape signal, not a config nuisance"). So a set-valued field is
    diffed ELEMENT-WISE and each move is its own entry — a bare "the list changed" would
    bury the one path that appeared inside a diff of four.

    ``skipped`` (no recorded answer, so nothing to differ from) and ``unrecorded`` (a field
    this build reads that the recorded build did not) are reported, not signalled: calling
    either drift would fire on every upgrade that adds a field, and an alarm that fires on
    the normal case is how an operator learns to ignore the real one.
    """
    rec: dict[str, Any] = recorded.get("fields") or {}
    obs: dict[str, Any] = observed.get("fields") or {}
    out: list[dict[str, Any]] = []
    for key in sorted(set(rec) | set(obs)):
        r, o = rec.get(key), obs.get(key)
        if r is None:
            out.append(
                {"field": key, "direction": "unrecorded", "recorded": None, "observed": _value(o), "signal": False}
            )
            continue
        if o is None:
            out.append(
                {"field": key, "direction": "unobserved", "recorded": _value(r), "observed": None, "signal": False}
            )
            continue
        if r.get("state") == "unread":
            out.append({"field": key, "direction": "skipped", "recorded": None, "observed": _value(o), "signal": False})
            continue
        if o.get("state") == "unread":
            # The verb answered at install and does not answer now. That IS a shape signal:
            # the instrument went away under the build, and silence here would read as clean.
            out.append(
                {
                    "field": key,
                    "direction": "unread-now",
                    "recorded": _value(r),
                    "observed": None,
                    "signal": True,
                    "reason": o.get("reason"),
                }
            )
            continue
        rv, ov = r.get("value"), o.get("value")
        if key in SET_FIELDS and isinstance(rv, list) and isinstance(ov, list):
            for gone in sorted(set(rv) - set(ov)):
                out.append(
                    {"field": key, "direction": "disappeared", "recorded": gone, "observed": None, "signal": True}
                )
            for added in sorted(set(ov) - set(rv)):
                out.append({"field": key, "direction": "appeared", "recorded": None, "observed": added, "signal": True})
        elif rv != ov:
            out.append({"field": key, "direction": "changed", "recorded": rv, "observed": ov, "signal": True})
        if _source_moved(r, o):
            out.append(
                {
                    "field": f"{key}.setting_source",
                    "direction": "changed",
                    "recorded": r.get("setting_source"),
                    "observed": o.get("setting_source"),
                    "signal": True,
                }
            )
    return out


def _value(field_record: dict[str, Any] | None) -> Any:
    return None if field_record is None else field_record.get("value")


def _source_moved(r: dict[str, Any], o: dict[str, Any]) -> bool:
    """True when a setting's own source changed. That is a different fact from its value:
    ``readonly`` by vendor default and ``readonly`` because an operator chose it are the
    same answer to two different questions, and leg 1325's finding was precisely that only
    the source tells them apart."""
    if "setting_source" not in r or "setting_source" not in o:
        return False
    return r.get("setting_source") != o.get("setting_source")


def drifts_of(comparison: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The comparison entries that are drift, as opposed to things nobody recorded."""
    return [d for d in comparison if d.get("signal")]


def describe(comparison: list[dict[str, Any]], recorded: dict[str, Any], observed: dict[str, Any]) -> str:
    """One line per difference, naming the field, the direction, and both faces.

    No remedy is offered, deliberately. What an operator should DO about a drift is
    retention and fallback (`R-2928` cl.5), which is a later leg and not this text's to
    pre-empt, and `R-2925` cl.2's rule stands: never write an action the measurement has
    not shown to exist on the recorded face. The interim refusal wording merged as seq 382
    is where an operator is pointed at the log today, and this line joins it there.
    """
    signals = drifts_of(comparison)
    quiet = [d for d in comparison if not d.get("signal")]
    if not signals:
        # Nothing moved. The unread fields are still worth naming on the same line, because
        # "matches" over a face where half the fields were never readable is a weaker claim
        # than the word alone suggests, and the reader should not have to know which fields
        # this build could not ask about.
        if not comparison:
            return "sandbox shape matches the recorded face"
        return (
            f"sandbox shape matches the recorded face at {recorded.get('observed_at', 'an unknown time')}"
            f" ({_sbx_of(recorded)}); no field that was readable at record time differs now"
            + (f", and {len(quiet)} field(s) have no recorded answer to be compared against" if quiet else "")
        )
    head = (
        f"sandbox shape drift: {len(signals)} field(s) differ from the face recorded at "
        f"{recorded.get('observed_at', 'an unknown time')} by {recorded.get('written_by', 'unknown writer')} "
        f"(venya {recorded.get('venya_version', 'unknown')}, {_sbx_of(recorded)}) against the observed face at "
        f"{observed.get('observed_at', 'an unknown time')} (venya {observed.get('venya_version', 'unknown')}, "
        f"{_sbx_of(observed)})"
    )
    lines = [head]
    lines += [
        f"  {d['field']} {d['direction']}: recorded={d['recorded']!r} observed={d['observed']!r}" for d in signals
    ]
    if quiet:
        lines.append(
            "  not drift: "
            + ", ".join(f"{d['field']} ({d['direction']})" for d in quiet)
            + " — no recorded answer to differ from, so no claim is made about them"
        )
    return "\n".join(lines)


def _sbx_of(face: dict[str, Any]) -> str:
    line = (face.get("fields") or {}).get("sbx.version_line") or {}
    value = line.get("value")
    return f"sbx {value}" if value else "sbx version unread"


def check_at_boot(probe: Any) -> list[dict[str, Any]]:
    """The boot entry point: compare this probe against the face at ``record_path()``.

    One parameter, because the guard hands it exactly one thing. The comparison itself is
    ``compare_with_record``, which takes the path so a test or a scratch run can aim it at
    a file it owns.
    """
    return compare_with_record(probe, record_path())


def compare_with_record(probe: Any, path: str) -> list[dict[str, Any]]:
    """Compare this boot's observed face against the face recorded at ``path``.

    Called from the boot guard BEFORE it decides whether to refuse, and it never raises:
    everything in here is a report. It adds no refusal and removes none, and it is reached on
    the refusing face too — that placement is what ``_report_shape`` documents and what
    `461bdffd` moved it to, so an operator reads the drift sentence beside the refusal
    instead of only on a boot that never happened here.

    Two things this deliberately does not do. It does not read the host-side instruments
    when there is no recorded face — with nothing to compare against, four vendor calls
    would buy one log line, and the early return is what keeps this off the cost path of
    every boot that has not been re-installed. And it never WRITES a face: the installer is
    the only writer, because a record established automatically from what the first boot
    happened to see would let a changed shape define the baseline it is judged against.
    """
    target = path
    recorded = read_record(target)
    if recorded is None:
        logger.warning(
            "no recorded sandbox shape at %s — nothing was compared. The installer records it during "
            "install-venya-executor.sh; to re-record by hand, run the same step as the executor user.",
            target,
        )
        return []
    observed = collect_face(with_sandbox_view=False, probe=probe)
    comparison = compare_face(recorded, observed)
    signals = drifts_of(comparison)
    if signals:
        logger.warning(
            "%s\n  This line is a report, not a decision: the runtime-isolation guard is unchanged by it and "
            "still refuses a sandbox that can write a runtime socket (R-2928 cl.2, #312 item 3a).",
            describe(comparison, recorded, observed),
        )
    else:
        logger.info(
            "sandbox shape matches the face recorded at %s by %s (%d field(s) compared, %d without a recorded answer)",
            recorded.get("observed_at", "an unknown time"),
            recorded.get("written_by", "unknown writer"),
            len(recorded.get("fields") or {}),
            len([d for d in comparison if d["direction"] == "skipped"]),
        )
    return signals


def cmd_record(args: argparse.Namespace) -> int:
    """Install-time record: ask every question, write the answers, print what went unread."""
    face = collect_face(memory_mb=args.memory_mb, with_sandbox_view=not args.no_sandbox_view)
    written = write_record(face, args.out, writer=WRITER_INSTALLER)
    fields = face["fields"]
    missed = sorted(k for k, v in fields.items() if v.get("state") == "unread")
    print(f"recorded the sandbox shape face at {written}")
    print(f"  venya {face['venya_version']}  {_sbx_of(face)}")
    print(f"  fields: {len(fields)}  unread: {len(missed)}")
    for key in missed:
        row = fields[key]
        print(f"    {key} unread rc={row['rc']!r} via {row['instrument']}: {row.get('reason', '')}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Re-ask the questions and print the comparison. Exit 1 on drift, 2 with no record.

    This is the second instrument for the file ``record`` wrote: a different entry point
    reading the same bytes, which is what `R-2939` cl.3 means by re-readable — a record
    only its own writer can parse is not a record.
    """
    target = args.record or record_path()
    recorded = read_record(target)
    if recorded is None:
        print(f"no recorded face at {target} — run: python -m executor.sandbox_shape record")
        return 2
    observed = collect_face(memory_mb=args.memory_mb, with_sandbox_view=not args.no_sandbox_view)
    comparison = compare_face(recorded, observed)
    print(describe(comparison, recorded, observed))
    return 1 if drifts_of(comparison) else 0


def cmd_show(args: argparse.Namespace) -> int:
    """Print the stored face as the field table it is — readable without this module."""
    recorded = read_record(args.record or record_path())
    if recorded is None:
        print("no recorded face")
        return 2
    print(
        f"face recorded at {recorded.get('observed_at')} (schema {recorded.get('schema')}, "
        f"written_by {recorded.get('written_by')}, venya {recorded.get('venya_version')})"
    )
    for key, row in sorted((recorded.get("fields") or {}).items()):
        shown = (
            row.get("value") if row.get("state") == "ok" else f"unread rc={row.get('rc')!r}: {row.get('reason', '')}"
        )
        origin = row.get("instrument")
        if row.get("setting_source"):
            origin = f"{origin}/source={row['setting_source']}"
        print(f"  {key} = {shown}  [{origin}]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m executor.sandbox_shape",
        description="Record and compare the sandbox shape face (R-2928 cl.4).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="ask the read-only questions and write the face")
    rec.add_argument("--out", default=None, help="face path (default: $VENYA_SANDBOX_SHAPE_FILE or the installed path)")
    rec.add_argument("--memory-mb", type=int, default=None, help="cap for the throwaway probe sandbox")
    rec.add_argument(
        "--no-sandbox-view",
        action="store_true",
        help="skip the in-sandbox reads; records that half as unread instead",
    )
    rec.set_defaults(func=cmd_record)

    chk = sub.add_parser("check", help="compare the current face against the recorded one (exit 1 on drift)")
    chk.add_argument("--record", default=None)
    chk.add_argument("--memory-mb", type=int, default=None)
    chk.add_argument("--no-sandbox-view", action="store_true")
    chk.set_defaults(func=cmd_check)

    sho = sub.add_parser("show", help="print the recorded face")
    sho.add_argument("--record", default=None)
    sho.set_defaults(func=cmd_show)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover - the entry point is exercised physically, not in a unit cell
    raise SystemExit(main())
