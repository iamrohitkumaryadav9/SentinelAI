#!/usr/bin/env python3
"""Phase 1C M3A real-host smoke run (READ-ONLY).

Collects a full within-run baseline (B) and window (W) from this host for two targets, validates the
EvidenceSnapshot against the contract, passes it to the M2 engine and writes the artefacts to
results/phase1c_m3a/. It does not inject faults, change the system, or require privileges.

PARAMETERS ARE UNCALIBRATED TEST VALUES (contract §6). They exist only so the pipeline can run end to
end; any decision produced here has no diagnostic meaning.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelai.collectors import LiveReader, collect_snapshot, collected_features, resolve_target  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import ParameterSet, diagnose  # noqa: E402
from sentinelai.diagnostic.rules.engine import DEV_FEATURES  # noqa: E402

NUMBERS = {   # UNCALIBRATED smoke values; same as the unit-test values, W/B at the contract defaults
    "W": 10.0, "B": 45.0, "N_BASE_MIN": 10.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
    "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
    "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
    "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
    "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5, "IMPACT_MIN": 2.0,
    "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9,
}
NUMBERS.update({f"floor[{f}]": 1e-3 for f in set(DEV_FEATURES) | set(collected_features())})
PARAMS = ParameterSet(parameter_set_id="UNCALIBRATED-m3a-smoke-test-values", numbers=NUMBERS,
                      reason_sets={"KFREE_REASONS_LOSS": ("QDISC_DROP", "CPU_BACKLOG")})


def own_cgroup():
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise SystemExit("no cgroup v2 membership")


def commit():
    """Short HEAD hash, read from .git (no subprocess)."""
    git = ROOT / ".git"
    head = (git / "HEAD").read_text().strip()
    if head.startswith("ref: "):
        ref = head[5:]
        p = git / ref
        if p.exists():
            return p.read_text().strip()[:7]
        for line in (git / "packed-refs").read_text().splitlines():
            if line.endswith(" " + ref):
                return line[:7]
    return head[:7]


def main():
    out = ROOT / "results" / "phase1c_m3a"
    out.mkdir(parents=True, exist_ok=True)
    targets = [("cron", "/system.slice/cron.service", ("enp0s31f6",)),   # interface counters: read-only sysfs
               ("self", own_cgroup(), ("enp0s31f6",))]
    summary = {"parameters": PARAMS.parameter_set_id, "note": "uncalibrated test values; no diagnostic meaning",
               "targets": {}}
    for name, cg, ifaces in targets:
        target = resolve_target(LiveReader(), name, cg, ifaces)
        snap, stats = collect_snapshot(target, PARAMS)
        EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)   # re-validate the artefact
        d = diagnose(snap, PARAMS, code_commit=commit())
        (out / f"{name}_snapshot.json").write_bytes(canonical_bytes(snap))
        (out / f"{name}_diagnosis.json").write_bytes(canonical_bytes(d.result))
        q = {}
        for m in snap.measurements:
            q[m.quality.value] = q.get(m.quality.value, 0) + 1
        summary["targets"][name] = {
            "cgroup": cg, "pids": len(target.pids), "cpuset": target.cpuset,
            "measurements": len(snap.measurements), "quality": q,
            "missing_measurements": len(snap.missing_measurements),
            "not_ok": sorted({f"{m.feature_id}@{m.scope}: {m.quality.value}" for m in snap.measurements
                              if m.quality.value != "OK"}),
            "data_quality": json.loads(canonical_bytes(snap.data_quality)),
            "decision": d.result.decision.value,
            "abstention_reasons": [r.value for r in d.result.abstention_reasons],
            "flags": [f.value for f in d.result.flags], "confidence": d.result.confidence_level.value,
            "candidates": {c.label.value: c.status.value for c in d.result.candidates},
            "perf": {"ticks": stats.ticks, "wall_s": round(stats.wall_s, 3), "cpu_s": round(stats.cpu_s, 4),
                     "cpu_pct_of_one_core": round(100 * stats.cpu_s / stats.wall_s, 3),
                     "max_rss_kb": stats.max_rss_kb, "max_tick_read_ms": round(1000 * stats.max_tick_read_s, 2)},
        }
        print(name, summary["targets"][name]["decision"], summary["targets"][name]["quality"],
              summary["targets"][name]["perf"], flush=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
