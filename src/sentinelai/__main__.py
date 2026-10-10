"""SentinelAI command line (Phase 2A.2/2A.3): read-only replay and verification of a persisted runtime run.

  python -m sentinelai diagnose --incident-id ID --target-name NAME --cgroup /CGROUP/PATH --out ABSOLUTE_ROOT \
                               --code-commit GITHASH --ebpf disabled [--parameter-set ID]
  python -m sentinelai verify --run-dir ABSOLUTE_RUN_DIRECTORY
  python -m sentinelai replay --run-dir ABSOLUTE_RUN_DIRECTORY [--source snapshot|ticks]   (default: snapshot)

--source snapshot: snapshot.json -> M2 -> diagnosis.json (2A.2). --source ticks: ticks.jsonl + acquisition.json ->
build_snapshot -> must equal snapshot.json -> M2 -> diagnosis.json (2A.3).

stdout: one canonical JSON object (deterministic for a given run). Exit codes:
  0 verified / replay MATCH      2 usage (missing or non-absolute --run-dir, not a directory)
  4 snapshot invalid             5 parameter set refused or M2 refused its input
  6 replay MISMATCH              7 run invalid or incomplete (manifest, hashes, missing/extra files)
  8 stored record (context, diagnosis or acquisition) invalid
  9 tick stream invalid (malformed, wrong count, Bad counts disagree)     10 snapshot cannot be rebuilt from the ticks
diagnose (2A.4): live read-only M3A acquisition (B + W seconds, the registered parameter set) -> ticks -> snapshot
-> M2 -> a new run under --out/<incident-id>/. --ebpf defaults to "required" (decision Q1) and is refused in 2A.4;
--iface is refused (the qdisc source would run the tc command). Progress goes to stderr. diagnose exit codes:
  0 diagnosis from a COMPLETE acquisition     11 diagnosis from a PARTIAL acquisition (some source Bad)
  2 refused before any host read (arguments, context, output root, eBPF, interfaces)
  3 acquisition FAILED (no snapshot, no diagnosis; incomplete run with acquisition.json kept)
  4 snapshot invalid     5 parameter set / M2 refused     12 output refused (run directory exists / store error)
An abstention (INSUFFICIENT_EVIDENCE) is a diagnosis: exit 0 or 11, never 3.
"""

import argparse
import os
import re
import sys

from pydantic import ValidationError

from .diagnostic.contract.serialize import canonical_json
from .diagnostic.rules import EngineError, UncalibratedParameters
from .runtime import registry
from .runtime.acquisition import AcquisitionFailed
from .runtime.context import IncidentContext, TargetSpec
from .runtime.live import LiveRefused, check_live_context, run_live
from .runtime.pipeline import SnapshotInvalid
from .runtime.store import ArtifactStore, StoreError
from .runtime.replay import (EXIT_MISMATCH, EXIT_OK, EXIT_RUN_INVALID, SOURCES, ReplayRefused, replay_run_dir,
                             verify_run_dir)


EXIT_DIAG_COMPLETE, EXIT_DIAG_PARTIAL, EXIT_ACQ_FAILED, EXIT_OUTPUT = 0, 11, 3, 12


def _diagnose(a, out, err, reader, clock, event_clock) -> int:
    emit = lambda obj: out.write(canonical_json({"command": "diagnose", "incident_id": a.incident_id, **obj}) + "\n")
    refuse = lambda code, kind, detail: (emit({"refused": kind, "detail": detail}), code)[1]
    try:
        ctx = IncidentContext(incident_id=a.incident_id, parameter_set_id=a.parameter_set, ebpf=a.ebpf,
                              target=TargetSpec(name=a.target_name, cgroup_path=a.cgroup, ifaces=tuple(a.iface)))
    except ValidationError as exc:
        return refuse(2, "USAGE", f"invalid context: {exc.errors()[0]['msg']}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.code_commit):
        return refuse(2, "USAGE", "--code-commit must be a 7-40 character lowercase git hash")
    if not os.path.isabs(a.out):
        return refuse(2, "USAGE", f"--out must be an absolute path: {a.out!r}")
    try:
        store = ArtifactStore(a.out)
        check_live_context(ctx)
    except (StoreError, LiveRefused) as exc:
        return refuse(2, "USAGE", str(exc))
    n = int(registry.get(ctx.parameter_set_id).num("B") + registry.get(ctx.parameter_set_id).num("W")) + 1
    err.write(f"sentinelai: live read-only M3A acquisition of {ctx.target.cgroup_path}: {n} ticks, "
              f"period {ctx.period_s} s\n")
    try:
        rec, rep, run_dir, status = run_live(ctx, store, code_commit=a.code_commit, reader=reader, clock=clock,
                                             event_clock=event_clock)
    except AcquisitionFailed as exc:
        emit({"run_dir": getattr(exc, "run_dir", None),
              "acquisition": {"status": "FAILED", "stage": exc.stage, "reason": exc.reason}})
        return EXIT_ACQ_FAILED
    except StoreError as exc:
        return refuse(EXIT_OUTPUT, "OUTPUT_REFUSED", str(exc))
    except SnapshotInvalid as exc:
        return refuse(4, "SNAPSHOT_INVALID", str(exc))
    except (EngineError, UncalibratedParameters, registry.UnknownParameterSet) as exc:
        return refuse(5, "M2_REFUSED", f"{type(exc).__name__}: {exc}")
    emit({"run_dir": run_dir, "acquisition": {"status": status},
          "snapshot_id": rec.snapshot_id, "diagnosis_id": rec.diagnosis_id, "decision": rep.decision,
          "contributing": list(rep.contributing), "confidence": rep.confidence, "abstained": rep.abstained,
          "abstention_reasons": list(rep.abstention_reasons), "flags": list(rep.flags),
          "validated_configuration": rec.validated_configuration.model_dump()})
    return EXIT_DIAG_COMPLETE if status == "COMPLETE" else EXIT_DIAG_PARTIAL


def main(argv=None, out=None, err=None, reader=None, clock=None, event_clock=None) -> int:
    """reader / clock / event_clock: injection points for tests (default: LiveReader, SystemClock, wall clock)."""
    out, err = out or sys.stdout, err or sys.stderr
    ap = argparse.ArgumentParser(prog="python -m sentinelai")
    sub = ap.add_subparsers(dest="command", required=True)
    dg = sub.add_parser("diagnose")
    for flag in ("--incident-id", "--target-name", "--cgroup", "--out", "--code-commit"):
        dg.add_argument(flag, required=True)
    dg.add_argument("--parameter-set", default=registry.DEFAULT_PARAMETER_SET_ID)
    dg.add_argument("--ebpf", choices=("required", "disabled"), default="required")
    dg.add_argument("--iface", action="append", default=[])
    sub.add_parser("verify").add_argument("--run-dir", required=True)
    rp = sub.add_parser("replay")
    rp.add_argument("--run-dir", required=True)
    rp.add_argument("--source", choices=SOURCES, default="snapshot")
    a = ap.parse_args(argv)
    if a.command == "diagnose":
        return _diagnose(a, out, err, reader, clock, event_clock)
    try:
        if a.command == "verify":
            v = verify_run_dir(a.run_dir)
            report = {"command": "verify", "run_dir": a.run_dir, "ok": v["ok"], "complete": v["complete"],
                      "first_discrepancy": v["first"],
                      **{k: v.get(k, []) for k in ("missing", "mismatch", "extra", "unregistered", "required_missing")}}
            out.write(canonical_json(report) + "\n")
            return EXIT_OK if v["ok"] else EXIT_RUN_INVALID
        r = replay_run_dir(a.run_dir, a.source)
        out.write(canonical_json({"command": "replay", **r.model_dump()}) + "\n")
        return EXIT_OK if r.status == "MATCH" else EXIT_MISMATCH
    except ReplayRefused as exc:
        out.write(canonical_json({"command": a.command, "run_dir": a.run_dir, "refused": exc.category,
                                  "detail": exc.detail}) + "\n")
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
