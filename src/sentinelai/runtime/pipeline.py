"""Pure runtime pipeline: validated snapshot -> M2 diagnose() -> DiagnosisRecord -> artifacts/report (2A.1), and
already-acquired ticks -> build_snapshot -> the same path, persisting acquisition.json + ticks.jsonl (2A.3).

No live collection here (that is 2A.4). The input snapshot is validated, hashed, handed to M2 unchanged and
checked byte-for-byte afterwards; M2 alone decides. Every failure is raised (and logged as runtime_failure),
never converted into a result; a run that fails before seal() has no manifest and is visibly incomplete.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from ..collectors import build_snapshot
from ..collectors.normalize import Tick
from ..diagnostic.contract import EvidenceSnapshot, Target
from ..diagnostic.contract.serialize import canonical_bytes
from ..diagnostic.rules import RULES_VERSION, diagnose
from . import registry
from .acquisition import FORMAT as ACQ_FORMAT, AcquisitionInvalid, AcquisitionRecord, TickStream, bad_counts, \
    collector_versions
from .context import IncidentContext
from .events import EventLog, system_clock
from .report import DiagnosisRecord, Report, build_record, build_report, sha256_bytes
from .store import ArtifactStore
from .ticks import FORMAT as TICKS_FORMAT, decode_ticks, encode_ticks


class SnapshotInvalid(ValueError):
    """The input is not a valid, canonical, measurements-only v1 snapshot."""


class SnapshotMutated(RuntimeError):
    """The input snapshot's canonical bytes changed during diagnosis."""


def validate_snapshot(snapshot: Union[EvidenceSnapshot, bytes]) -> Tuple[EvidenceSnapshot, bytes]:
    """Return (snapshot, canonical bytes). Bytes must parse, validate and already be canonical."""
    if isinstance(snapshot, bytes):
        try:
            snap = EvidenceSnapshot.model_validate_json(snapshot, strict=False)
        except ValueError as exc:
            raise SnapshotInvalid(f"snapshot does not validate: {exc}") from None
        raw = canonical_bytes(snap)
        if raw != snapshot:
            raise SnapshotInvalid("snapshot bytes are not in canonical form")
    elif isinstance(snapshot, EvidenceSnapshot):
        try:     # re-validate: model_construct() or a mutated copy must not slip through
            snap = EvidenceSnapshot.model_validate_json(canonical_bytes(snapshot), strict=False)
        except ValueError as exc:
            raise SnapshotInvalid(f"snapshot does not validate: {exc}") from None
        raw = canonical_bytes(snap)
        if raw != canonical_bytes(snapshot):
            raise SnapshotInvalid("snapshot does not round-trip canonically")
    else:
        raise SnapshotInvalid(f"expected EvidenceSnapshot or bytes, got {type(snapshot).__name__}")
    if snap.evidence_items or snap.conflicts:
        raise SnapshotInvalid("input snapshot must contain measurements only (M2 produces the evidence)")
    if snap.incident_id is not None:
        raise SnapshotInvalid("snapshot.incident_id must be None in v1")
    return snap, raw


def diagnose_snapshot(snapshot: Union[EvidenceSnapshot, bytes], *, code_commit: str,
                      events: Optional[EventLog] = None, refs: Optional[dict] = None):
    """validate -> hash -> registry params -> M2 -> immutability check -> DiagnosisRecord.
    Returns (record, input snapshot, input bytes, evaluated snapshot, params)."""
    log, refs = events or EventLog(), dict(refs or {})
    snap, raw = validate_snapshot(snapshot)
    input_sha = sha256_bytes(raw)
    log.emit("snapshot_validated", snapshot_id=snap.snapshot_id, input_snapshot_sha256=input_sha, **refs)
    params = registry.get(snap.parameter_set_id)
    log.emit("diagnosis_started", snapshot_id=snap.snapshot_id, parameter_set_id=params.parameter_set_id,
             rules_version=RULES_VERSION, **refs)
    d = diagnose(snap, params, code_commit=code_commit)
    if canonical_bytes(snap) != raw:
        raise SnapshotMutated(f"snapshot {snap.snapshot_id} changed during diagnosis")
    record = build_record(input_snapshot=snap, input_sha256=input_sha, params=params, result=d.result,
                          evaluated=d.snapshot)
    log.emit("diagnosis_completed", snapshot_id=snap.snapshot_id, diagnosis_id=record.diagnosis_id,
             decision=record.result.decision.value, **refs)
    return record, snap, raw, d.snapshot, params


def run_key(start: datetime, snapshot_id: str) -> str:
    return f"{start.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{snapshot_id}"


def _persist(context: IncidentContext, raw: bytes, snapshot_id: str, store: ArtifactStore, *, code_commit: str,
             clock, acquisition: str, before=(), events_before=()) -> Tuple[DiagnosisRecord, Report, str]:
    """Create the run, write context (+ `before` artifacts), diagnose, write the rest, seal. Abandon on failure.
    events_before: (kind, detail) pairs that happened before the run existed (live acquisition), logged first."""
    start, _ = clock()
    run = store.create_run(context.incident_id, run_key(start, snapshot_id))
    log = EventLog(clock, sink=run.append_event)
    refs = {"incident_id": context.incident_id}
    try:
        for kind, detail in events_before:
            log.emit(kind, detail=detail, **refs)
        run.write_json("context.json", context)
        for name, data in before:
            run.write_bytes(name, data)
        if before:
            log.emit("snapshot_created", snapshot_id=snapshot_id, **refs)
        record, snap, raw, evaluated, params = diagnose_snapshot(raw, code_commit=code_commit, events=log, refs=refs)
        run.write_bytes("snapshot.json", raw)
        run.write_json("parameter_set.json", params)
        run.write_json("diagnosis.json", {"record": record, "evaluated_snapshot": evaluated})
        report = build_report(record, context.incident_id)
        run.seal({"incident_id": context.incident_id, "snapshot_id": record.snapshot_id,
                  "diagnosis_id": record.diagnosis_id, "rules_version": record.rules_version,
                  "contract_version": record.contract_version, "parameter_set_id": record.parameter_set_id,
                  "code_commit": code_commit, "acquisition": acquisition})
    except BaseException as exc:
        try:
            log.emit("runtime_failure", detail=f"{type(exc).__name__}: {exc}"[:500], **refs)
        finally:
            run.abandon()
        raise
    return record, report, run.path


def run_pure(context: IncidentContext, snapshot: Union[EvidenceSnapshot, bytes], store: ArtifactStore, *,
             code_commit: str, clock=system_clock) -> Tuple[DiagnosisRecord, Report, str]:
    """Persist and diagnose an already-built snapshot. Returns (record, report, run directory)."""
    if not isinstance(context, IncidentContext):
        raise TypeError("context must be an IncidentContext")
    snap, raw = validate_snapshot(snapshot)
    if snap.parameter_set_id != context.parameter_set_id:
        raise SnapshotInvalid(f"snapshot parameter set {snap.parameter_set_id} != context "
                              f"{context.parameter_set_id}")
    return _persist(context, raw, snap.snapshot_id, store, code_commit=code_commit, clock=clock,
                    acquisition="not performed (2A.1 pure pipeline)")


def check_target(context: IncidentContext, target: Target, ebpf: bool) -> None:
    if not isinstance(target, Target):
        raise AcquisitionInvalid("target must be a resolved M1 Target")
    spec = context.target
    if (target.name, target.cgroup_path, target.ifaces) != (spec.name, spec.cgroup_path, spec.ifaces):
        raise AcquisitionInvalid("resolved target does not match the context target")
    if type(ebpf) is not bool or ebpf != (context.ebpf == "required"):
        raise AcquisitionInvalid(f"ebpf={ebpf!r} contradicts context ebpf={context.ebpf!r}")


def snapshot_from_ticks(ticks: List[Tick], target: Target, params, period_s: float, ebpf: bool) -> EvidenceSnapshot:
    """The M3A/M3B transformation, unchanged: collectors.build_snapshot (pure)."""
    return build_snapshot(ticks, target, params, period_s, ebpf)


def run_from_ticks(context: IncidentContext, ticks: List[Tick], target: Target, store: ArtifactStore, *,
                   ebpf: bool, code_commit: str, clock=system_clock, collection=None, events_before=(),
                   acquisition: str = "ticks supplied to the pure pipeline (no live acquisition)"
                   ) -> Tuple[DiagnosisRecord, Report, str]:
    """Persist already-acquired ticks (no live collection here), build the snapshot from them with the
    unchanged M3A/M3B transformation, and diagnose it. Before anything is written, the encoded tick stream is
    decoded and must rebuild the identical snapshot; otherwise nothing is persisted."""
    if not isinstance(context, IncidentContext):
        raise TypeError("context must be an IncidentContext")
    check_target(context, target, ebpf)
    params = registry.get(context.parameter_set_id)
    data = encode_ticks(ticks)
    snap, raw = validate_snapshot(snapshot_from_ticks(ticks, target, params, context.period_s, ebpf))
    if canonical_bytes(snapshot_from_ticks(decode_ticks(data), target, params, context.period_s, ebpf)) != raw:
        raise AcquisitionInvalid("the encoded tick stream does not rebuild the identical snapshot")
    counts = bad_counts(ticks)
    record = AcquisitionRecord(format=ACQ_FORMAT, status="PARTIAL" if counts else "COMPLETE", target=target,
                               ebpf=ebpf, period_s=context.period_s, parameter_set_id=context.parameter_set_id,
                               ticks=TickStream(format=TICKS_FORMAT, count=len(ticks), sha256=sha256_bytes(data)),
                               bad_counts=counts, collector_versions=collector_versions(snap), collection=collection)
    return _persist(context, raw, snap.snapshot_id, store, code_commit=code_commit, clock=clock,
                    acquisition=acquisition, events_before=events_before,
                    before=(("acquisition.json", canonical_bytes(record)), ("ticks.jsonl", data)))
