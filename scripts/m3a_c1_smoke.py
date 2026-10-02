#!/usr/bin/env python3
"""M3A-C1 real-host smoke run (READ-ONLY): qdisc evidence on virtual interfaces only.

Target: this session's cgroup, interfaces lo and docker0 (both under /sys/devices/virtual/net). The physical
NIC is never passed to the collector; the run also shows that a request for it is refused before any
command executes. Parameters are UNCALIBRATED test values (contract §6): decisions have no diagnostic meaning.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from m3a_smoke import PARAMS, commit, own_cgroup  # noqa: E402
from sentinelai.collectors import LiveReader, collect_snapshot, resolve_target  # noqa: E402
from sentinelai.collectors.commands import tc  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import diagnose  # noqa: E402

IFACES = ("lo", "docker0")


def main():
    out = ROOT / "results" / "phase1c_m3a_c1"
    out.mkdir(parents=True, exist_ok=True)
    reader = LiveReader()
    for i in IFACES:   # refuse to run at all unless every interface is virtual and unprotected
        bad = tc.physical_or_unknown(reader, i)
        if bad is not None:
            raise SystemExit(f"refusing: {bad.detail}")
    calls = []
    refused = tc.run_qdisc_show("enp0s31f6", runner=lambda *a, **k: calls.append(a))
    before = {i: reader.tc_qdisc(i) for i in IFACES}
    target = resolve_target(reader, "self", own_cgroup(), IFACES)
    snap, stats = collect_snapshot(target, PARAMS)
    after = {i: reader.tc_qdisc(i) for i in IFACES}
    EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)
    d = diagnose(snap, PARAMS, code_commit=commit())
    (out / "self_snapshot.json").write_bytes(canonical_bytes(snap))
    (out / "self_diagnosis.json").write_bytes(canonical_bytes(d.result))
    qd = [m for m in snap.measurements if m.feature_id == "net.drop.qdisc"]
    loss_items = sorted({(i.predicate_id, i.kind.value) for i in d.snapshot.evidence_items
                         if i.predicate_id.startswith(("PL.R1", "RT.R2"))})
    ident = lambda t: [{k: q[k] for k in ("kind", "handle", "root") if k in q} for q in json.loads(t)]
    summary = {
        "parameters": PARAMS.parameter_set_id, "note": "uncalibrated test values; no diagnostic meaning",
        "interfaces": list(IFACES), "command": [" ".join(tc.argv_for(i)) for i in IFACES],
        "physical_nic_request": {"status": refused.status.value, "detail": refused.detail,
                                 "commands_executed": len(calls)},
        "qdisc_configuration_unchanged": all(ident(before[i]) == ident(after[i]) for i in IFACES),
        "net.drop.qdisc": [{"scope": m.scope, "quality": m.quality.value, "value": m.value, "coverage": m.coverage,
                            "baseline": None if m.baseline is None else
                            {"median": m.baseline.median, "n": m.baseline.n, "adequate": m.baseline.adequate},
                            "source": m.provenance.source.value, "locator": m.provenance.locator,
                            "measurement_id": m.measurement_id} for m in qd],
        "measurements": len(snap.measurements),
        "quality": {q: sum(1 for m in snap.measurements if m.quality.value == q)
                    for q in sorted({m.quality.value for m in snap.measurements})},
        "data_quality": json.loads(canonical_bytes(snap.data_quality)),
        "decision": d.result.decision.value, "abstention_reasons": [r.value for r in d.result.abstention_reasons],
        "flags": [f.value for f in d.result.flags],
        "candidates": {c.label.value: c.status.value for c in d.result.candidates},
        "loss_and_rt_r2_items": [list(x) for x in loss_items],
        "perf": {"wall_s": round(stats.wall_s, 3), "cpu_s": round(stats.cpu_s, 4), "max_rss_kb": stats.max_rss_kb,
                 "max_tick_read_ms": round(1000 * stats.max_tick_read_s, 2)},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
