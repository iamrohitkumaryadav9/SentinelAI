"""Live read-only M3A acquisition (Phase 2A.4): IncidentContext -> ticks -> the 2A.3 pipeline -> ArtifactStore.

Host access is exactly the existing M3A collectors: collectors.resolve_target (cgroup.procs, cpuset) and
collectors.collect (probes.sample each period) through collectors.LiveReader, which reads files under /proc and
/sys only (open "rb", listdir, readlink). This module adds no reads of its own and no parser.

Refused in 2A.4, before anything is read:
  * ebpf "required": eBPF acquisition (loader attach) is out of scope; nothing is silently downgraded;
  * target interfaces: their qdisc source runs the tc command (collectors/commands/tc.py, a subprocess);
    as a second guard the reader refuses tc_qdisc outright.
Outcomes: COMPLETE / PARTIAL (some observation is a Bad state) proceed through the unchanged snapshot and M2 path;
FAILED (target unresolvable, collection error, snapshot not buildable/valid, or no usable measurement at all)
persists context.json + an AcquisitionFailure acquisition.json + events and leaves the run incomplete (no manifest):
no snapshot, no diagnosis. An M2 abstention on a valid snapshot is a diagnosis, never a failure.
Writes: only the ArtifactStore under the caller's root.
"""

from dataclasses import dataclass
from datetime import timezone
from typing import List

from ..collectors import LiveReader, SystemClock, collect, resolve_target
from ..collectors.errors import Bad, CollectorError, Status
from ..collectors.normalize import Tick
from ..diagnostic.contract import Quality, Target
from ..diagnostic.contract.serialize import canonical_bytes
from ..diagnostic.rules import UncalibratedParameters
from . import registry
from .acquisition import (FAILURE_FORMAT, AcquisitionFailed, AcquisitionFailure, CollectionInfo, bad_counts)
from .context import IncidentContext
from .events import EventLog, system_clock
from .pipeline import SnapshotInvalid, run_from_ticks, snapshot_from_ticks, validate_snapshot
from .store import ArtifactStore

USABLE = (Quality.OK, Quality.PARTIAL)


class LiveRefused(ValueError):
    """The request is outside what 2A.4 may do; refused before any host read."""


class NoCommandReader:
    """Delegates file reads to the wrapped reader; the command-backed read (tc) is refused, never executed."""

    def __init__(self, inner):
        self._inner = inner
        self.refused_commands = 0

    def read(self, path):
        return self._inner.read(path)

    def listdir(self, path):
        return self._inner.listdir(path)

    def readlink(self, path):
        return self._inner.readlink(path)

    def tc_qdisc(self, ifname):
        self.refused_commands += 1
        return Bad(Status.REFUSED, "command-backed reads are not permitted in Phase 2A.4")


@dataclass(frozen=True)
class Acquired:
    target: Target
    ticks: List[Tick]
    collection: CollectionInfo


def _wall(clock) -> str:
    return clock.wall().astimezone(timezone.utc).isoformat()


def check_live_context(context: IncidentContext) -> None:
    if not isinstance(context, IncidentContext):
        raise LiveRefused("context must be an IncidentContext")
    if context.ebpf != "disabled":
        raise LiveRefused("ebpf=required: eBPF acquisition is not part of Phase 2A.4 (pass ebpf=disabled; the run "
                          "is then reported as outside the validated configuration)")
    if context.target.ifaces:
        raise LiveRefused("target interfaces need a command-backed read (a subprocess); not permitted in Phase 2A.4")


def acquire(context: IncidentContext, params, *, reader=None, clock=None) -> Acquired:
    """Resolve the target and collect B + W ticks with the existing M3A collectors. Read-only."""
    check_live_context(context)
    inner = reader if reader is not None else LiveReader()
    rdr, clock = NoCommandReader(inner), clock or SystemClock()
    started = _wall(clock)
    spec = context.target
    try:
        target = resolve_target(rdr, spec.name, spec.cgroup_path, ())
    except CollectorError as exc:
        raise AcquisitionFailed("target", str(exc), started=started, ended=_wall(clock)) from None
    try:
        ticks, stats = collect(target, params, rdr, clock, context.period_s, None)
    except (CollectorError, UncalibratedParameters) as exc:
        raise AcquisitionFailed("collect", f"{type(exc).__name__}: {exc}", target=target, started=started,
                                ended=_wall(clock)) from None
    if rdr.refused_commands:                                  # unreachable without interfaces; never silent
        raise AcquisitionFailed("collect", "a command-backed read was attempted", target=target, ticks=ticks,
                                started=started, ended=_wall(clock))
    ended = _wall(clock)
    info = CollectionInfo(mode="live-m3a", reader=type(inner).__name__, started_wall=started, ended_wall=ended,
                          ticks=len(ticks), wall_s=float(max(stats.wall_s, 0.0)), cpu_s=float(max(stats.cpu_s, 0.0)),
                          max_rss_kb=int(stats.max_rss_kb), max_tick_read_s=float(max(stats.max_tick_read_s, 0.0)))
    return Acquired(target, ticks, info)


def check_evidence(acq: Acquired, params, context: IncidentContext) -> None:
    """FAILED unless the ticks build a valid snapshot with at least one usable measurement."""
    try:
        snap, _ = validate_snapshot(snapshot_from_ticks(acq.ticks, acq.target, params, context.period_s, False))
    except (CollectorError, UncalibratedParameters, SnapshotInvalid, ValueError, TypeError) as exc:
        raise AcquisitionFailed("snapshot", f"{type(exc).__name__}: {exc}"[:400], target=acq.target, ticks=acq.ticks,
                                started=acq.collection.started_wall, ended=acq.collection.ended_wall) from None
    if not any(m.quality in USABLE for m in snap.measurements):
        raise AcquisitionFailed("evidence", "no usable measurement: every source was missing, denied or invalid",
                                target=acq.target, ticks=acq.ticks, started=acq.collection.started_wall,
                                ended=acq.collection.ended_wall)


def _record_failure(context: IncidentContext, store: ArtifactStore, exc: AcquisitionFailed, clock_now) -> str:
    """Persist the failure (context, AcquisitionFailure, events) and leave the run incomplete. Returns its path."""
    now = clock_now()
    key = f"{now[0].astimezone(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-failed"
    run = store.create_run(context.incident_id, key)
    log = EventLog(clock_now, sink=run.append_event)
    try:
        log.emit("acquisition_started", detail=exc.started or "", incident_id=context.incident_id)
        log.emit("acquisition_failed", detail=f"{exc.stage}: {exc.reason}"[:500], incident_id=context.incident_id)
        run.write_json("context.json", context)
        run.write_bytes("acquisition.json", canonical_bytes(AcquisitionFailure(
            format=FAILURE_FORMAT, status="FAILED", stage=exc.stage, reason=exc.reason, target=exc.target,
            parameter_set_id=context.parameter_set_id, started_wall=exc.started or "", ended_wall=exc.ended or "",
            ticks=len(exc.ticks), bad_counts=bad_counts(exc.ticks))))
    finally:
        run.abandon()
    return run.path


def run_live(context: IncidentContext, store: ArtifactStore, *, code_commit: str, reader=None, clock=None,
             event_clock=None):
    """Live acquisition -> run_from_ticks. Returns (record, report, run_dir, acquisition status).
    On FAILED: the failure is persisted (incomplete run) and AcquisitionFailed is raised with .run_dir set."""
    check_live_context(context)
    if not isinstance(store, ArtifactStore):
        raise LiveRefused("store must be an ArtifactStore")
    params = registry.get(context.parameter_set_id)
    event_clock = event_clock or system_clock
    try:
        acq = acquire(context, params, reader=reader, clock=clock)
        check_evidence(acq, params, context)
    except AcquisitionFailed as exc:
        exc.run_dir = _record_failure(context, store, exc, event_clock)
        raise
    status = "PARTIAL" if bad_counts(acq.ticks) else "COMPLETE"
    record, report, run_dir = run_from_ticks(
        context, acq.ticks, acq.target, store, ebpf=False, code_commit=code_commit, clock=event_clock,
        collection=acq.collection, acquisition=f"live M3A acquisition ({status})",
        events_before=(("acquisition_started", acq.collection.started_wall),
                       ("acquisition_completed", f"{status}; {len(acq.ticks)} ticks; ended {acq.collection.ended_wall}")))
    return record, report, run_dir, status
