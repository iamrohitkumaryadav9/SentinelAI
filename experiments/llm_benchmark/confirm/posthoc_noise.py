#!/usr/bin/env python3
"""POST-HOC (not pre-registered) analysis of the kfree_skb baseline-noise flaw.

Flaw: every scenario carries baseline kernel noise kfree_skb drops_per_s=3 (NOT_SPECIFIED),
while the published label definition says packet loss is proven by "kfree_skb drops" with no
magnitude qualifier. A model may therefore cite 3/s background noise as proof of loss.

This script, identical for both models:
  1. counts 'noise-citation' errors: predicted network_packet_loss, in a scenario whose
     kfree_skb drops are baseline (<= 10/s), whose other drop counters are all zero, and whose
     EVIDENCE text cites kfree_skb;
  2. reports a SENSITIVITY re-analysis excluding scenarios where EITHER model made such an
     error (paired exclusion, so the comparison stays paired). This is not the primary result.
Output: results/posthoc_noise.json
"""

import json
from pathlib import Path

from scipy.stats import binomtest

import analyze as A
from simulator import Simulator

HERE = Path(__file__).resolve().parent


def baseline_noise_only(sc):
    s = Simulator(sc).s
    n = s["net"]
    kf = n["kfree_skb"]
    if "error" in kf or kf.get("drops_per_s", 0) > 10:
        return False
    ifs = [v for v in n["interfaces"].values() if "error" not in v]
    other = max([0] + [i.get(k, 0) for i in ifs for k in ("rx_dropped_per_s", "tx_dropped_per_s", "rx_missed_per_s", "rx_errors_per_s")])
    sn = n["softnet"].get("dropped_per_s", 0) if "error" not in n["softnet"] else 0
    return other == 0 and sn == 0 and n["conntrack"]["drops_per_s"] == 0


def main():
    out = {"note": "POST-HOC analysis, not pre-registered. Primary results are in summary.json."}
    scored = {}
    for m in A.MODELS:
        raw, _ = A.load(m)
        scored[m] = {sid: A.score(r) for sid, r in raw.items()}
        noise = [sid for sid, r in scored[m].items()
                 if r["predicted"] == "network_packet_loss" and r["expected"] != "network_packet_loss"
                 and baseline_noise_only(A.DATA[sid]) and "kfree" in (raw[sid].get("evidence_text") or "").lower()]
        out[m] = {"noise_citation_errors": len(noise), "scenarios": noise,
                  "false_packet_loss_total": sum(r["predicted"] == "network_packet_loss" and r["expected"] != "network_packet_loss"
                                                 for r in scored[m].values())}
    a, b = A.MODELS
    excl = set(out[a]["scenarios"]) | set(out[b]["scenarios"])
    ids = [s for s in A.DATA if s in scored[a] and s in scored[b] and s not in excl]
    ca = [scored[a][s]["correct"] for s in ids]
    cb = [scored[b][s]["correct"] for s in ids]
    ao = sum(x and not y for x, y in zip(ca, cb)); bo = sum(y and not x for x, y in zip(ca, cb))
    out["sensitivity_excluding_noise_scenarios"] = {
        "excluded": sorted(excl), "n": len(ids),
        a: {"correct": sum(ca), "rate": round(sum(ca) / len(ids), 3) if ids else None},
        b: {"correct": sum(cb), "rate": round(sum(cb) / len(ids), 3) if ids else None},
        "discordant": {"a_only": ao, "b_only": bo},
        "mcnemar_exact_p": round(binomtest(ao, ao + bo, 0.5).pvalue, 4) if ao + bo else 1.0}
    (A.RES / "posthoc_noise.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
