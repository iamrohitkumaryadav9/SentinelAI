#!/usr/bin/env python3
"""Pre-registered analysis for the Phase 1B confirmatory experiment (see PROTOCOL.md).

Outputs (confirm/results/): scored.csv, summary.json, tables.md
"""

import csv
import json
import math
import random
import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import ValidationError
from scipy.stats import binomtest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from schemas.models import TOOL_ARG_MODELS  # noqa: E402

PROTO = json.loads((HERE / "protocol.json").read_text())
T = PROTO["thresholds"]
DATA = {s["id"]: s for s in json.loads((HERE / "scenarios.json").read_text())["scenarios"]}
LABELS = {l.lower(): l for l in PROTO["labels"]}
INS = "INSUFFICIENT_EVIDENCE"
RES = HERE / "results"
MODELS = PROTO["run_order"]


def load(model):
    f = RES / "runs" / model.replace(":", "_").replace("/", "_") / "agent.jsonl"
    rows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()] if f.exists() else []
    last = {}
    for r in rows:                     # if a scenario was re-run, keep the LAST record (reported as deviation)
        last[r["scenario"]] = r
    return last, len(rows)


def args_valid(name, args):
    if name not in TOOL_ARG_MODELS or not isinstance(args, dict):
        return False
    try:
        TOOL_ARG_MODELS[name].model_validate_json(json.dumps(args), strict=True)
        return True
    except ValidationError:
        return False


def score(r):
    sc = DATA[r["scenario"]]
    gold = sc["gold"]
    label = LABELS.get((r.get("label_raw") or "").lower())
    called = [t["name"] for t in r["tool_trace"]]
    req = set(sc["required_any"])
    flags = {
        "hallucinated_tool": sum(n not in TOOL_ARG_MODELS for n in called),
        "invalid_arguments": sum(n in TOOL_ARG_MODELS and not args_valid(n, t["arguments"]) for n, t in zip(called, r["tool_trace"])),
        "unknown_entity_argument": sum(1 for t in r["tool_trace"] if t.get("result_error") and "unknown" in t["result_error"]
                                       and "unavailable" not in t["result_error"]),
        "run_experiment_calls": called.count("run_experiment"),
    }
    if r["status"] != "ok":
        outcome = "error"
    elif r["termination"] == "step_budget_exhausted":
        outcome = "loop_non_termination"
    elif label is None:
        outcome = "no_diagnosis"
    elif gold == INS:
        outcome = ("correct" if called else "unsupported_diagnosis") if label == INS else "insufficient_evidence_failure"
    elif label == INS:
        outcome = "over_cautious"
    elif label != gold:
        outcome = "incorrect_diagnosis"
    else:
        outcome = "correct" if (req & set(called)) else "unsupported_diagnosis"
    flags["wrong_tool"] = int(flags["run_experiment_calls"] > 0 or (gold != INS and label is not None and not (req & set(called))))
    ev = (r.get("evidence_text") or "").lower()
    grounded = None if gold == INS else any(t.lower() in ev for t in sc["diagnostic_terms"])
    return {"model": r["model"], "scenario": r["scenario"], "category": sc["category"], "subcase": sc["subcase"],
            "expected": gold, "predicted": label or (r.get("label_raw") or "—"), "outcome": outcome,
            "correct": outcome == "correct", "confidence": r.get("confidence"), "evidence_grounded": grounded,
            "evidence_cited": (r.get("evidence_text") or "")[:300], "tools": " > ".join(called),
            "tool_arguments": json.dumps([t["arguments"] for t in r["tool_trace"]]), "n_tool_calls": len(called),
            "abstained": label == INS, "abstained_correctly": label == INS and gold == INS,
            "wall_s": r["wall_s"], "prompt_tokens": r["prompt_tokens_total"], "output_tokens": r["output_tokens_total"],
            "termination": r["termination"], "conversation_tokens_est": r["conversation_tokens_est"],
            "context_overflow_risk": r["context_overflow_risk"], **flags}


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round((c - h) / d, 3), round((c + h) / d, 3))


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    i = (len(xs) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (i - lo), 2)


def model_summary(model, rows, raw):
    S = [r for r in rows]
    n = len(S)
    oc = Counter(r["outcome"] for r in S)
    k = oc["correct"]
    ins = [r for r in S if r["expected"] == INS]
    turns = [t for rr in raw.values() for t in rr["turns"]]
    walls = [r["wall_s"] for r in S]
    peak_rss = max(rr["peak_runner_rss_mib"] for rr in raw.values()) / 1024
    tot_min = sum(walls) / 60
    conf = [r["confidence"] for r in S if r["confidence"] is not None]
    cat = defaultdict(lambda: [0, 0])
    for r in S:
        cat[r["category"]][0] += r["correct"]; cat[r["category"]][1] += 1
    # systematic errors: (gold, predicted) pairs with >= min_errors and >= share of class with n >= min_class_n
    cls_n = Counter(r["expected"] for r in S)
    pairs = Counter((r["expected"], r["predicted"]) for r in S if not r["correct"] and r["predicted"] != r["expected"])
    systematic = [{"gold": g, "predicted": p, "count": c, "class_n": cls_n[g]} for (g, p), c in pairs.items()
                  if cls_n[g] >= T["rule1_systematic_min_class_n"] and c >= T["rule1_systematic_min_errors"]
                  and c / cls_n[g] >= T["rule1_systematic_min_share"]]
    g = [r for r in S if r["evidence_grounded"] is not None]
    return {
        "model": model, "n": n, "raw_records": None, "outcomes": dict(oc), "correct": k, "correct_rate": round(k / n, 4),
        "correct_wilson95": wilson(k, n),
        "multi_step_correct": sum(r["correct"] and r["n_tool_calls"] >= 2 for r in S),
        "insufficient": {"n": len(ins), "correct": sum(r["correct"] for r in ins),
                         "guessed_fault": sum(r["outcome"] == "insufficient_evidence_failure" for r in ins)},
        "over_cautious": oc["over_cautious"], "unsupported_diagnosis": oc["unsupported_diagnosis"],
        "loops": oc["loop_non_termination"], "no_diagnosis": oc["no_diagnosis"], "errors": oc["error"],
        "flags": {f: sum(r[f] for r in S) for f in ("hallucinated_tool", "invalid_arguments", "unknown_entity_argument",
                                                   "run_experiment_calls", "wrong_tool")},
        "evidence_grounded": f"{sum(r['evidence_grounded'] for r in g)}/{len(g)}",
        "confidence_mean_correct": round(st.mean([r["confidence"] for r in S if r["correct"] and r["confidence"] is not None]), 3) if any(r["correct"] and r["confidence"] is not None for r in S) else None,
        "confidence_mean_incorrect": round(st.mean([r["confidence"] for r in S if not r["correct"] and r["confidence"] is not None]), 3) if any(not r["correct"] and r["confidence"] is not None for r in S) else None,
        "confidence_reported": f"{len(conf)}/{n}",
        "by_category": {c: f"{a}/{b}" for c, (a, b) in sorted(cat.items())},
        "systematic_errors": systematic,
        "context_overflow_risk": sum(r["context_overflow_risk"] for r in S),
        "perf": {
            "scenario_wall_median_s": pct(walls, 0.5), "scenario_wall_p95_s": pct(walls, 0.95),
            "scenario_wall_total_min": round(tot_min, 1),
            "tool_calls_median": pct([r["n_tool_calls"] for r in S], 0.5),
            "turn_wall_median_s": pct([t["wall_s"] for t in turns if t["wall_s"]], 0.5),
            "turn_tok_s_median": pct([t["tokens_per_s"] for t in turns if t["tokens_per_s"]], 0.5),
            "turn_prompt_tok_s_median": pct([t["prompt_tokens_per_s"] for t in turns if t["prompt_tokens_per_s"]], 0.5),
            "ttft_median_s": pct([t["ttft_s"] for t in turns if t["ttft_s"]], 0.5),
            "peak_rss_gib": round(peak_rss, 2),
            "min_mem_available_gib": round(min(rr["min_mem_available_mib"] for rr in raw.values()) / 1024, 2),
            "max_swap_used_mib": max(rr["max_swap_used_mib"] for rr in raw.values()),
            "swap_used_mib_first_scenario_start": raw[next(iter(raw))]["swap_used_mib_start"],
            "system_cpu_pct_mean": round(st.mean([t["system_cpu_pct_mean"] for t in turns if t["system_cpu_pct_mean"] is not None]), 1),
            "runner_cpu_pct_mean": round(st.mean([t["runner_cpu_pct_mean"] for t in turns if t["runner_cpu_pct_mean"] is not None]), 1),
            "quality_per_second": round((k / n) / pct(walls, 0.5), 4) if pct(walls, 0.5) else None,
            "quality_per_gib": round((k / n) / peak_rss, 4),
            "correct_per_minute": round(k / tot_min, 3) if tot_min else None,
            "correct_per_gib": round(k / peak_rss, 2),
        },
    }


def tcp_boundary(rows):
    tcp = [r for r in rows if r["expected"] == "tcp_retransmissions"]
    out = {"n_tcp_gold": len(tcp), "correct": sum(r["predicted"] == "tcp_retransmissions" for r in tcp),
           "packet_loss_false_positive": sum(r["predicted"] == "network_packet_loss" for r in tcp),
           "abstained": sum(r["predicted"] == INS for r in tcp)}
    out["other_incorrect"] = len(tcp) - out["correct"] - out["packet_loss_false_positive"] - out["abstained"]
    for cls in ("tcp_retransmissions", "network_packet_loss"):
        tp = sum(r["predicted"] == cls and r["expected"] == cls for r in rows)
        pp = sum(r["predicted"] == cls for r in rows)
        gp = sum(r["expected"] == cls for r in rows)
        out[cls] = {"tp": tp, "predicted": pp, "gold": gp, "precision": round(tp / pp, 3) if pp else None,
                    "recall": round(tp / gp, 3) if gp else None}
    a = [r for r in rows if r["category"] == "A_tcp_vs_loss"]
    out["category_A_correct"] = f"{sum(r['correct'] for r in a)}/{len(a)}"
    out["category_A_by_subcase"] = {}
    for r in a:
        v = out["category_A_by_subcase"].setdefault(r["subcase"], [0, 0])
        v[0] += r["correct"]; v[1] += 1
    out["category_A_by_subcase"] = {k: f"{a_}/{b}" for k, (a_, b) in sorted(out["category_A_by_subcase"].items())}
    out["loss_gold_predicted_tcp"] = sum(r["expected"] == "network_packet_loss" and r["predicted"] == "tcp_retransmissions" for r in rows)
    return out


def paired(ra, rb):
    ids = sorted(set(ra) & set(rb))
    a = [ra[i]["correct"] for i in ids]
    b = [rb[i]["correct"] for i in ids]
    a_only = sum(x and not y for x, y in zip(a, b))
    b_only = sum(y and not x for x, y in zip(a, b))
    nd = a_only + b_only
    p = binomtest(a_only, nd, 0.5).pvalue if nd else 1.0
    rng = random.Random(T["rule2_bootstrap_seed"])
    diffs = []
    for _ in range(T["rule2_bootstrap_resamples"]):
        idx = [rng.randrange(len(ids)) for _ in ids]
        diffs.append(sum(a[i] for i in idx) / len(ids) - sum(b[i] for i in idx) / len(ids))
    diffs.sort()
    lo = diffs[int(0.025 * len(diffs))]
    hi = diffs[int(0.975 * len(diffs)) - 1]
    return {"n_paired": len(ids), "a_only_correct": a_only, "b_only_correct": b_only, "both_correct": sum(x and y for x, y in zip(a, b)),
            "both_wrong": sum((not x) and (not y) for x, y in zip(a, b)), "mcnemar_exact_p": round(p, 4),
            "diff_correct_rate_a_minus_b": round(sum(a) / len(ids) - sum(b) / len(ids), 4),
            "bootstrap95_ci": [round(lo, 4), round(hi, 4)],
            "robust": p < T["rule2_mcnemar_alpha"] and (lo > 0 or hi < 0),
            "discordant_scenarios": {"a_only": [i for i, x, y in zip(ids, a, b) if x and not y],
                                     "b_only": [i for i, x, y in zip(ids, a, b) if y and not x]}}


def decide(sa, sb, pr):
    A, B = sa["model"], sb["model"]
    log = []

    def adequate(s):
        return (s["correct_rate"] >= T["adequacy_min_correct_rate"]
                and s["insufficient"]["guessed_fault"] / s["insufficient"]["n"] <= T["adequacy_max_insufficient_failure_share"]
                and s["loops"] / s["n"] <= T["adequacy_max_loop_share"])
    adq = {A: adequate(sa), B: adequate(sb)}
    log.append(f"Rule 0 adequacy: {adq}")
    if not any(adq.values()):
        return {"verdict": "FAIL", "primary": None, "decided_by": "Rule 0", "log": log}

    def r1_deficits(s, o):
        d = []
        md = T["rule1_material_count_diff"]
        for key, val, oval in (("unsupported_diagnosis", s["unsupported_diagnosis"], o["unsupported_diagnosis"]),
                               ("insufficient_evidence_failure", s["insufficient"]["guessed_fault"], o["insufficient"]["guessed_fault"]),
                               ("hallucinated_tool", s["flags"]["hallucinated_tool"], o["flags"]["hallucinated_tool"]),
                               ("invalid_arguments", s["flags"]["invalid_arguments"], o["flags"]["invalid_arguments"])):
            if val - oval >= md:
                d.append(f"{key}: {val} vs {oval}")
        own = {(e["gold"], e["predicted"]) for e in s["systematic_errors"]}
        oth = {(e["gold"], e["predicted"]) for e in o["systematic_errors"]}
        for e in own - oth:
            d.append(f"systematic error {e[0]} -> {e[1]}")
        return d
    dA, dB = r1_deficits(sa, sb), r1_deficits(sb, sa)
    log.append(f"Rule 1 deficits: {A}={dA} {B}={dB}")
    if bool(dA) != bool(dB):
        win = B if dA else A
        if adq[win]:
            return {"verdict": "decided", "primary": win, "decided_by": "Rule 1 (safety/correctness)", "log": log}
    log.append(f"Rule 2: diff(A-B)={pr['diff_correct_rate_a_minus_b']} McNemar p={pr['mcnemar_exact_p']} "
               f"bootstrap95={pr['bootstrap95_ci']} robust={pr['robust']}")
    if pr["robust"]:
        win = A if pr["diff_correct_rate_a_minus_b"] > 0 else B
        if adq[win]:
            return {"verdict": "decided", "primary": win, "decided_by": "Rule 2 (robust agent-quality difference)", "log": log}
    la, lb = sa["perf"]["scenario_wall_median_s"], sb["perf"]["scenario_wall_median_s"]
    ma, mb = sa["perf"]["peak_rss_gib"], sb["perf"]["peak_rss_gib"]
    lat = "A" if lb >= la * (1 + T["rule3_latency_material_rel"]) else "B" if la >= lb * (1 + T["rule3_latency_material_rel"]) else None
    ram = "A" if mb - ma >= T["rule3_ram_material_gib"] else "B" if ma - mb >= T["rule3_ram_material_gib"] else None
    log.append(f"Rule 3: latency median {A}={la}s {B}={lb}s -> better={lat}; peak RSS {A}={ma} {B}={mb} GiB -> better={ram}")
    better = {x for x in (lat, ram) if x}
    if len(better) == 1:
        win = A if better == {"A"} else B
        if adq[win]:
            return {"verdict": "decided", "primary": win,
                    "decided_by": "Rule 3 (quality not robustly different; selected on resource efficiency)", "log": log}
    log.append("Rule 4: no rule decides")
    return {"verdict": "too_close", "primary": None, "decided_by": "Rule 4 (results too close)", "log": log}


def table(h, rows):
    return "\n".join(["| " + " | ".join(h) + " |", "|" + "---|" * len(h)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def main():
    raw, scored, summ = {}, {}, {}
    for m in MODELS:
        raw[m], nraw = load(m)
        scored[m] = {sid: score(r) for sid, r in raw[m].items()}
        if raw[m]:
            summ[m] = model_summary(m, list(scored[m].values()), raw[m])
            summ[m]["raw_records"] = nraw
            summ[m]["tcp_boundary"] = tcp_boundary(list(scored[m].values()))
    with open(RES / "scored.csv", "w", newline="") as f:
        rows = [r for m in MODELS for r in scored[m].values()]
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    out = {"protocol_version": PROTO["version"], "models": summ}
    if len(summ) == 2:
        a, b = MODELS
        out["paired"] = paired(scored[a], scored[b])
        out["paired"]["a"], out["paired"]["b"] = a, b
        out["decision"] = decide(summ[a], summ[b], out["paired"])
        # confusion matrices
        out["confusion"] = {m: {f"{g} -> {p}": c for (g, p), c in sorted(Counter((r["expected"], r["predicted"]) for r in scored[m].values()).items())}
                            for m in MODELS}
    (RES / "summary.json").write_text(json.dumps(out, indent=1) + "\n")
    # per-scenario side-by-side table
    md = []
    if len(summ) == 2:
        a, b = MODELS
        md.append(table(["Scenario", "Category / subcase", "Expected", f"{a}", f"{a} outcome", f"{a} calls", f"{a} s",
                         f"{b}", f"{b} outcome", f"{b} calls", f"{b} s"],
                        [[sid, f"{DATA[sid]['category']} / {DATA[sid]['subcase']}", DATA[sid]["gold"],
                          scored[a][sid]["predicted"], scored[a][sid]["outcome"], scored[a][sid]["n_tool_calls"], scored[a][sid]["wall_s"],
                          scored[b][sid]["predicted"], scored[b][sid]["outcome"], scored[b][sid]["n_tool_calls"], scored[b][sid]["wall_s"]]
                         for sid in DATA if sid in scored[a] and sid in scored[b]]))
    (RES / "tables.md").write_text("\n\n".join(md) + "\n")
    print(json.dumps({m: {k: summ[m][k] for k in ("correct", "correct_rate", "correct_wilson95", "outcomes")} for m in summ}, indent=1))
    if "decision" in out:
        print(json.dumps(out["paired"], indent=1)); print(json.dumps(out["decision"], indent=1))


if __name__ == "__main__":
    main()
