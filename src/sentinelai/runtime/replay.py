"""Snapshot replay (2A.2), raw-tick replay (2A.3) and run verification. Read-only with respect to the run.

verify_run_dir: store.verify_run (manifest, hashes, missing/extra files, completeness) plus the run-type rules:
  only registered artifact names, and every artifact of a pure run (2A.1 run_pure) present and listed.
replay_run_dir: verify, then re-read every artifact it uses and check it against the manifest hash, load the
  context, the registered parameter set (must equal parameter_set.json), the snapshot (strict, canonical) and the
  stored DiagnosisRecord; run M2 through the 2A.1 pipeline (diagnose_snapshot) with the recorded code_commit;
  compare the recomputed diagnosis.json bytes with the stored bytes. MATCH only when they are byte-identical;
  a matching diagnosis_id alone is never success.
replay_run_dir(source="ticks") additionally needs acquisition.json + ticks.jsonl: the record is checked against
  the context and bound to the stream (count, sha256, Bad counts, collector versions), the stream is decoded
  losslessly (runtime.ticks), the snapshot is rebuilt with the unchanged M3A/M3B build_snapshot and compared
  byte-for-byte with snapshot.json; the rebuilt snapshot then goes through the same M2 + diagnosis comparison.
Invalid or incomplete input raises ReplayRefused (a category and an exit code); it is never turned into an
abstention or a result. Nothing is written anywhere.
"""

import hashlib
import json
import os
import stat
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, ValidationError

from ..collectors.errors import CollectorError
from ..diagnostic.contract import EvidenceSnapshot
from ..diagnostic.contract.serialize import canonical_bytes
from ..diagnostic.contract.version import CONTRACT_VERSION
from ..diagnostic.rules import RULES_VERSION, EngineError, UncalibratedParameters
from . import registry
from .acquisition import FORMAT as ACQ_FORMAT, AcquisitionRecord, bad_counts, collector_versions
from .context import IncidentContext
from .pipeline import SnapshotInvalid, diagnose_snapshot, snapshot_from_ticks, validate_snapshot
from .report import DiagnosisRecord
from .store import ARTIFACTS, MANIFEST, StoreError, read_artifact, verify_run
from .ticks import FORMAT as TICKS_FORMAT, TickFormatError, decode_ticks

PURE_RUN = ("context.json", "snapshot.json", "parameter_set.json", "diagnosis.json", "events.jsonl", MANIFEST)
TICK_ARTIFACTS = ("acquisition.json", "ticks.jsonl")
SOURCES = ("snapshot", "ticks")

EXIT_OK, EXIT_USAGE, EXIT_SNAPSHOT, EXIT_PARAMETERS, EXIT_MISMATCH, EXIT_RUN_INVALID, EXIT_RECORD = 0, 2, 4, 5, 6, 7, 8
EXIT_TICKS, EXIT_RECONSTRUCTION = 9, 10                     # 2A.3: new codes; 0-8 keep their 2A.2 meaning
EXIT_CODES = {"USAGE": EXIT_USAGE, "RUN_INVALID": EXIT_RUN_INVALID, "RECORD_INVALID": EXIT_RECORD,
              "SNAPSHOT_INVALID": EXIT_SNAPSHOT, "PARAMETERS_REFUSED": EXIT_PARAMETERS, "M2_REFUSED": EXIT_PARAMETERS,
              "TICKS_INVALID": EXIT_TICKS, "RECONSTRUCTION_INVALID": EXIT_RECONSTRUCTION}


class ReplayRefused(Exception):
    """The run cannot be replayed as given. category is one of EXIT_CODES."""

    def __init__(self, category: str, detail: str):
        if category not in EXIT_CODES:
            raise ValueError(f"unknown category {category!r}")
        self.category, self.detail, self.exit_code = category, detail, EXIT_CODES[category]
        super().__init__(f"{category}: {detail}")


class ReplayResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    status: str                         # MATCH | MISMATCH
    source: str                         # snapshot | ticks
    mismatch_stage: Optional[str]       # snapshot (ticks source only) | diagnosis | None
    run_dir: str
    incident_id: str
    snapshot_id: str
    stored: Dict[str, str]              # diagnosis_id, decision, result_sha256
    recomputed: Dict[str, str]
    checks: Dict[str, bool]
    first_difference: Optional[str]


def check_run_dir(run_dir) -> str:
    if not isinstance(run_dir, str) or not os.path.isabs(run_dir):
        raise ReplayRefused("USAGE", f"--run-dir must be an absolute path: {run_dir!r}")
    try:
        st = os.lstat(run_dir)
    except OSError as exc:
        raise ReplayRefused("USAGE", f"--run-dir {run_dir}: {exc.strerror}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise ReplayRefused("USAGE", f"--run-dir {run_dir} is not a directory (symlinks are not followed)")
    return run_dir


def verify_run_dir(run_dir: str) -> dict:
    """store.verify_run plus pure-run rules. Returns the report with 'ok' and 'first' (first discrepancy or None)."""
    check_run_dir(run_dir)
    v = dict(verify_run(run_dir))
    names = sorted(os.listdir(run_dir))
    v["unregistered"] = [n for n in names if n not in ARTIFACTS]
    v["required_missing"] = [n for n in PURE_RUN if n not in names]
    first = None
    if not v["complete"]:
        first = v["reason"]
    elif v.get("reason"):
        first = v["reason"]
    else:
        for key, what in (("required_missing", "required artifact absent"), ("missing", "listed artifact missing"),
                          ("mismatch", "hash/size mismatch"), ("unregistered", "unregistered file"),
                          ("extra", "file not listed in manifest")):
            if v.get(key):
                first = f"{what}: {v[key][0]}"
                break
    v["ok"] = bool(v["ok"]) and first is None
    v["first"] = first
    return v


def _first_difference(a, b, path="$") -> Optional[str]:
    if type(a) is not type(b):
        return path
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k}"
            d = _first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list):
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_difference(x, y, f"{path}[{i}]")
            if d:
                return d
        return None if len(a) == len(b) else f"{path}[{min(len(a), len(b))}]"
    return None if a == b else path


def _reconstruct(data: dict, context: IncidentContext, params) -> bytes:
    """acquisition.json + ticks.jsonl -> canonical bytes of the rebuilt snapshot (refuses, never repairs)."""
    try:
        acq = AcquisitionRecord.model_validate_json(data["acquisition.json"], strict=False)
    except (ValidationError, ValueError) as exc:
        raise ReplayRefused("RECORD_INVALID", f"acquisition.json invalid: {str(exc)[:300]}") from None
    if canonical_bytes(acq) != data["acquisition.json"]:
        raise ReplayRefused("RECORD_INVALID", "acquisition.json is not canonical")
    spec = context.target
    if (acq.parameter_set_id != context.parameter_set_id or acq.period_s != context.period_s
            or acq.ebpf != (context.ebpf == "required")
            or (acq.target.name, acq.target.cgroup_path, acq.target.ifaces) != (spec.name, spec.cgroup_path, spec.ifaces)):
        raise ReplayRefused("RECORD_INVALID", "acquisition.json contradicts context.json")
    if acq.collection is not None and acq.collection.ticks != acq.ticks.count:
        raise ReplayRefused("RECORD_INVALID", "acquisition.json collection tick count differs from the stream")
    if acq.ticks.format != TICKS_FORMAT or hashlib.sha256(data["ticks.jsonl"]).hexdigest() != acq.ticks.sha256:
        raise ReplayRefused("RUN_INVALID", "ticks.jsonl is not the stream acquisition.json describes")
    try:
        ticks = decode_ticks(data["ticks.jsonl"])
    except (TickFormatError, UnicodeDecodeError) as exc:
        raise ReplayRefused("TICKS_INVALID", f"{type(exc).__name__}: {exc}"[:400]) from None
    if len(ticks) != acq.ticks.count:
        raise ReplayRefused("TICKS_INVALID", f"{len(ticks)} ticks decoded, acquisition.json records {acq.ticks.count}")
    if bad_counts(ticks) != acq.bad_counts or (acq.status == "COMPLETE") != (not acq.bad_counts):
        raise ReplayRefused("TICKS_INVALID", "Bad-state counts of the stream differ from acquisition.json")
    try:
        rebuilt = snapshot_from_ticks(ticks, acq.target, params, acq.period_s, acq.ebpf)
        rebuilt, raw = validate_snapshot(rebuilt)
    except (CollectorError, UncalibratedParameters, SnapshotInvalid, ValueError, TypeError) as exc:
        raise ReplayRefused("RECONSTRUCTION_INVALID", f"{type(exc).__name__}: {exc}"[:400]) from None
    if collector_versions(rebuilt) != acq.collector_versions:
        raise ReplayRefused("PARAMETERS_REFUSED", f"collectors {collector_versions(rebuilt)} differ from the recorded "
                            f"{acq.collector_versions}")
    return raw


def replay_run_dir(run_dir: str, source: str = "snapshot") -> ReplayResult:
    if source not in SOURCES:
        raise ReplayRefused("USAGE", f"--source must be one of {SOURCES}: {source!r}")
    v = verify_run_dir(run_dir)
    if not v["ok"]:
        raise ReplayRefused("RUN_INVALID", v["first"] or "run verification failed")
    needed = PURE_RUN[:-1] + (TICK_ARTIFACTS if source == "ticks" else ())
    present = os.listdir(run_dir)
    for name in needed:
        if name not in present:
            raise ReplayRefused("RUN_INVALID", f"{name} absent: required for --source {source}")
    try:
        files = json.loads(read_artifact(run_dir, MANIFEST))["files"]
        data = {}
        for name in needed:
            data[name] = read_artifact(run_dir, name)
            if hashlib.sha256(data[name]).hexdigest() != files[name]["sha256"]:
                raise ReplayRefused("RUN_INVALID", f"{name} changed after verification")
    except (StoreError, KeyError, ValueError) as exc:
        raise ReplayRefused("RUN_INVALID", f"cannot read run artifacts: {exc}") from None
    # context: parameter-set id first, so an unknown id is reported as such
    try:
        ctx_obj = json.loads(data["context.json"])
    except ValueError as exc:
        raise ReplayRefused("RECORD_INVALID", f"context.json is not JSON: {exc}") from None
    psid = ctx_obj.get("parameter_set_id") if isinstance(ctx_obj, dict) else None
    if psid not in registry.known():
        raise ReplayRefused("PARAMETERS_REFUSED", f"parameter set {psid!r} is not registered")
    try:
        context = IncidentContext.model_validate_json(data["context.json"])
    except ValidationError as exc:
        raise ReplayRefused("RECORD_INVALID", f"context.json invalid: {exc.errors()[0]['msg']}") from None
    if canonical_bytes(context) != data["context.json"]:
        raise ReplayRefused("RECORD_INVALID", "context.json is not canonical")

    params = registry.get(context.parameter_set_id)
    if data["parameter_set.json"] != canonical_bytes(params):
        raise ReplayRefused("PARAMETERS_REFUSED", "parameter_set.json differs from the registered parameter set")

    # stored record
    try:
        stored_obj = json.loads(data["diagnosis.json"])
        if not isinstance(stored_obj, dict) or set(stored_obj) != {"record", "evaluated_snapshot"}:
            raise ValueError("diagnosis.json must hold exactly 'record' and 'evaluated_snapshot'")
        stored = DiagnosisRecord.model_validate_json(json.dumps(stored_obj["record"]), strict=False)
        EvidenceSnapshot.model_validate_json(json.dumps(stored_obj["evaluated_snapshot"]), strict=False)
    except (ValueError, ValidationError) as exc:
        raise ReplayRefused("RECORD_INVALID", f"diagnosis.json invalid: {str(exc)[:300]}") from None
    if stored.parameter_set_id != context.parameter_set_id:
        raise ReplayRefused("PARAMETERS_REFUSED", "stored record names a different parameter set than the context")
    if stored.rules_version != RULES_VERSION or stored.contract_version != CONTRACT_VERSION:
        raise ReplayRefused("PARAMETERS_REFUSED", f"stored record was produced by rules {stored.rules_version} / "
                            f"contract {stored.contract_version}; this code has {RULES_VERSION} / {CONTRACT_VERSION}")

    snapshot_bytes, snapshot_checks, snapshot_first = data["snapshot.json"], {}, None
    if source == "ticks":
        try:
            validate_snapshot(data["snapshot.json"])            # the persisted snapshot itself must be valid
        except SnapshotInvalid as exc:
            raise ReplayRefused("SNAPSHOT_INVALID", f"snapshot.json: {exc}") from None
        snapshot_bytes = _reconstruct(data, context, params)
        snapshot_checks = {"snapshot_byte_identical": snapshot_bytes == data["snapshot.json"]}
        if not snapshot_checks["snapshot_byte_identical"]:
            snapshot_first = _first_difference(json.loads(data["snapshot.json"]), json.loads(snapshot_bytes)) \
                or "$ (bytes differ)"

    # snapshot -> M2 through the 2A.1 pipeline (validation, hashing, immutability check, DiagnosisRecord)
    try:
        record, snap, _, evaluated, _ = diagnose_snapshot(snapshot_bytes, code_commit=stored.code_commit)
    except SnapshotInvalid as exc:
        raise ReplayRefused("SNAPSHOT_INVALID", str(exc)) from None
    except (EngineError, UncalibratedParameters, registry.UnknownParameterSet) as exc:
        raise ReplayRefused("M2_REFUSED", f"{type(exc).__name__}: {exc}") from None
    if snap.parameter_set_id != context.parameter_set_id:
        raise ReplayRefused("PARAMETERS_REFUSED", "snapshot names a different parameter set than the context")

    recomputed = canonical_bytes({"record": record, "evaluated_snapshot": evaluated})
    checks = {
        **snapshot_checks,
        "diagnosis_id_equal": record.diagnosis_id == stored.diagnosis_id,
        "result_sha256_equal": record.result_sha256 == stored.result_sha256,
        "record_equal": canonical_bytes(record) == canonical_bytes(stored),
        "evaluated_snapshot_equal": canonical_bytes(evaluated) == canonical_bytes(stored_obj["evaluated_snapshot"]),
        "diagnosis_json_byte_identical": recomputed == data["diagnosis.json"],
    }
    match = all(checks.values())
    stage = None if match else ("snapshot" if snapshot_first else "diagnosis")
    first = None if match else (snapshot_first or _first_difference(stored_obj, json.loads(recomputed))
                                or "$ (bytes differ)")
    pick = lambda r: {"diagnosis_id": r.diagnosis_id, "decision": r.result.decision.value,
                      "result_sha256": r.result_sha256}
    return ReplayResult(status="MATCH" if match else "MISMATCH", source=source, mismatch_stage=stage, run_dir=run_dir, incident_id=context.incident_id,
                        snapshot_id=record.snapshot_id, stored=pick(stored), recomputed=pick(record), checks=checks,
                        first_difference=first)
