#!/usr/bin/env python3
"""Deterministic scorer for Phase 1B raw runs (no LLM judge).

Reads results/runs/<model>/<suite>.jsonl and writes:
  results/summary.json      all metrics per model + gates + decision
  results/summary.csv       one flat row per model
  results/item_scores.csv   every scored item (for manual audit)
  results/comparison.md     human-readable tables
"""

import csv
import json
import re
import statistics as st
import sys
from pathlib import Path

from pydantic import ValidationError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from schemas.models import INCIDENT_FIELDS, INCIDENT_TYPES, TOOL_ARG_MODELS, IncidentDiagnosis  # noqa: E402

RUNS = HERE / "results" / "runs"
OUT = HERE / "results"
P = lambda n: json.loads((HERE / "prompts" / n).read_text())
GIB_MIB = 1024

WEIGHTS = {"agent": 0.30, "tools": 0.25, "evidence": 0.15, "structured": 0.15, "knowledge": 0.10, "generation": 0.05}
GATES = {"stability_fail_rate_max": 0.05, "peak_rss_gib_max": 8.0, "gen_tok_s_min": 5.0,
         "tool_success_min": 0.75, "hallucinated_tool_max": 0.05, "constrained_schema_valid_min": 0.95,
         "evidence_norm_min": 0.60}

ITEMS = []  # (model, suite, item, score, note)


def load(model_dir, suite):
    f = model_dir / f"{suite}.jsonl"
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()] if f.exists() else []


def med(xs):
    xs = [x for x in xs if x is not None]
    return round(st.median(xs), 2) if xs else None


def concept_score(text, groups):
    t = text.lower()
    hit = sum(any(term.lower() in t for term in g) for g in groups)
    return 2 if hit == len(groups) else 1 if hit >= len(groups) / 2 else 0


def note(model, suite, item, score, why=""):
    ITEMS.append({"model": model, "suite": suite, "item": item, "score": score, "note": why})


# ------------------------------------------------------------------ suites
def score_rubric(model, rows, items, suite):
    by = {i["id"]: i for i in items}
    scores = []
    for r in rows:
        iid = r["item"].split("#")[0]
        s = concept_score(r.get("content", ""), by[iid]["groups"]) if r["status"] == "ok" else 0
        scores.append(s)
        note(model, suite, r["item"], s, r["status"])
    return {"n": len(scores), "mean": round(st.mean(scores), 3) if scores else 0.0,
            "norm": round(st.mean(scores) / 2, 3) if scores else 0.0}


def _args(call):
    a = call.get("arguments")
    if isinstance(a, str):
        try:
            a = json.loads(a) if a.strip() else {}
        except json.JSONDecodeError:
            return None
    return a if isinstance(a, dict) else ({} if a is None else None)


def validate_args(name, args):
    if args is None:
        return False
    try:
        TOOL_ARG_MODELS[name].model_validate_json(json.dumps(args), strict=True)
        return True
    except ValidationError:
        return False


def _eq(a, b):
    return str(a).strip().lower() == str(b).strip().lower() if isinstance(b, str) else a == b


def score_tools(model, rows):
    spec = {i["id"]: i for i in P("tool_tasks.json")["items"]}
    if not rows or all(r["status"] == "unsupported" for r in rows):
        for r in rows:
            note(model, "tools", r["item"], 0, "unsupported")
        return {"supported": False, "norm": 0.0}
    c = dict(n_expected=0, success=0, acceptable=0, wrong=0, missing=0, hallucinated=0, invalid_args=0,
             calls_known=0, valid_known=0, no_tool_n=0, no_tool_ok=0, text_tool_calls=0, parallel=0, failed=0)
    scores = []
    for r in rows:
        it = spec[r["item"]]
        calls = r.get("tool_calls") or []
        exp = it.get("expected")
        if r["status"] != "ok":
            c["failed"] += 1
            if exp:
                c["n_expected"] += 1
            scores.append(0); note(model, "tools", r["item"], 0, r["status"]); continue
        if exp is None:
            c["no_tool_n"] += 1
            ok = not calls
            c["no_tool_ok"] += ok
            s = 2 if ok else 0
            scores.append(s); note(model, "tools", r["item"], s, "no-call" if ok else "unnecessary call"); continue
        c["n_expected"] += 1
        if not calls:
            c["missing"] += 1
            if any(t in (r.get("content") or "") for t in TOOL_ARG_MODELS):
                c["text_tool_calls"] += 1
            scores.append(0); note(model, "tools", r["item"], 0, "missing call"); continue
        c["parallel"] += len(calls) > 1
        fn = calls[0].get("function", {})
        name, args = fn.get("name"), _args(fn)
        if name not in TOOL_ARG_MODELS:
            c["hallucinated"] += 1
            scores.append(0); note(model, "tools", r["item"], 0, f"hallucinated {name}"); continue
        c["calls_known"] += 1
        valid = validate_args(name, args)
        c["valid_known"] += valid
        if name == exp:
            match = all(_eq((args or {}).get(k), v) for k, v in it["expect_args"].items())
            s = 2 if valid and match else 1 if valid else 0
            c["success"] += s == 2
            c["invalid_args"] += not valid
            why = "ok" if s == 2 else f"arg mismatch {args}" if valid else f"invalid args {args}"
        elif name in it.get("acceptable", []):
            s = 1 if valid else 0
            c["acceptable"] += valid
            c["invalid_args"] += not valid
            why = f"acceptable alt {name}"
        else:
            s = 0
            c["wrong"] += 1
            why = f"wrong tool {name}"
        scores.append(s); note(model, "tools", r["item"], s, why)
    n = c["n_expected"] or 1
    return {"supported": True, **c,
            "tool_call_success_rate": round(c["success"] / n, 3),
            "argument_validity": round(c["valid_known"] / c["calls_known"], 3) if c["calls_known"] else 0.0,
            "wrong_tool_rate": round(c["wrong"] / n, 3),
            "missing_tool_call_rate": round(c["missing"] / n, 3),
            "hallucinated_tool_rate": round(c["hallucinated"] / n, 3),
            "no_tool_correct_rate": round(c["no_tool_ok"] / c["no_tool_n"], 3) if c["no_tool_n"] else None,
            "mean": round(st.mean(scores), 3), "norm": round(st.mean(scores) / 2, 3)}


def score_structured(model, rows, mode):
    gold = {i["id"]: i for i in P("structured.json")["items"]}
    n = len(rows)
    k = dict(valid_json=0, schema_valid=0, missing_field=0, extra_field=0, fenced=0, lenient_schema_valid=0,
             semantic_correct=0, failed=0)
    scores = []
    for r in rows:
        g = gold[r["item"]]
        txt = (r.get("content") or "").strip()
        if r["status"] != "ok":
            k["failed"] += 1; scores.append(0); note(model, f"structured_{mode}", r["item"], 0, r["status"]); continue
        obj = None
        try:
            obj = json.loads(txt)
            k["valid_json"] += isinstance(obj, dict)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", txt, re.S)
            if txt.startswith("```"):
                k["fenced"] += 1
            if m:
                try:
                    lo = json.loads(m.group(0))
                    IncidentDiagnosis.model_validate_json(json.dumps(lo), strict=True)
                    k["lenient_schema_valid"] += 1
                except (json.JSONDecodeError, ValidationError):
                    pass
        s, why = 0, "parse failure"
        if isinstance(obj, dict):
            keys = set(obj)
            k["missing_field"] += bool(set(INCIDENT_FIELDS) - keys)
            k["extra_field"] += bool(keys - set(INCIDENT_FIELDS))
            try:
                d = IncidentDiagnosis.model_validate_json(json.dumps(obj), strict=True)
                k["schema_valid"] += 1
                k["lenient_schema_valid"] += 1
                ok = d.incident_type == g["gold"] and g["sev"][0] <= d.severity <= g["sev"][1]
                k["semantic_correct"] += ok
                s, why = (2, "ok") if ok else (1, f"got {d.incident_type}/{d.severity} want {g['gold']}/{g['sev']}")
            except ValidationError as e:
                why = f"schema: {e.errors()[0]['loc']} {e.errors()[0]['type']}"
        scores.append(s); note(model, f"structured_{mode}", r["item"], s, why)
    rate = lambda x: round(x / n, 3) if n else 0.0
    return {"n": n, "valid_json_rate": rate(k["valid_json"]), "schema_valid_rate": rate(k["schema_valid"]),
            "missing_field_rate": rate(k["missing_field"]), "extra_field_rate": rate(k["extra_field"]),
            "parse_failure_rate": rate(n - k["valid_json"]), "markdown_fenced_rate": rate(k["fenced"]),
            "lenient_schema_valid_rate": rate(k["lenient_schema_valid"]),
            "semantic_correct_rate": rate(k["semantic_correct"]), "failed_requests": k["failed"],
            "mean": round(st.mean(scores), 3) if scores else 0.0, "norm": round(st.mean(scores) / 2, 3) if scores else 0.0}


NUM_UNIT = re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s|%|gib|mib|gi|mi|gb|mb|/s|x)\b", re.I)
# Rubric revision R1 (applied before any candidate model was run, after auditing
# gemma3:1b baseline output): added phrasings of abstention such as
# "data collection is required to determine the cause".
ABSTAIN = ("insufficient", "cannot be determined", "can't be determined", "undetermined", "unknown",
           "not enough", "cannot determine", "unable to determine", "required to determine",
           "needed to determine", "cannot be identified", "cannot be pinpointed", "impossible to determine",
           "not yet determined", "cannot yet", "more data", "no root cause")


def score_evidence(model, rows):
    spec = {i["id"]: i for i in P("evidence.json")["items"]}
    out = {"insufficient_n": 0, "insufficient_abstained": 0, "confident_unsupported": 0, "control_n": 0,
           "control_correct": 0, "control_overcautious": 0, "format_ok": 0, "fabricated_number_responses": 0}
    scores = []
    for r in rows:
        it = spec[r["item"]]
        txt = r.get("content") or ""
        m = re.search(r"ROOT_CAUSE:\s*(.+)", txt)
        out["format_ok"] += bool(m and "REQUIRED_EVIDENCE:" in txt)
        root = (m.group(1) if m else txt).lower()
        abst = any(a in root for a in ABSTAIN)
        prompt_nums = {x.lower().replace(" ", "") for x in NUM_UNIT.findall(r.get("prompt_text", ""))}
        fabricated = [x for x in NUM_UNIT.findall(txt) if x.lower().replace(" ", "") not in prompt_nums]
        out["fabricated_number_responses"] += bool(fabricated)
        if r["status"] != "ok":
            s, why = 0, r["status"]
        elif it["kind"] == "insufficient":
            out["insufficient_n"] += 1
            if abst:
                out["insufficient_abstained"] += 1
                hits = sum(any(t in txt.lower() for t in g) for g in it["evidence_groups"])
                s, why = (2 if hits >= 2 else 1), f"abstained, {hits} evidence groups"
            else:
                out["confident_unsupported"] += 1
                s, why = 0, f"asserted: {root[:60]}"
        else:
            out["control_n"] += 1
            if any(t in root for t in it["gold_terms"]):
                out["control_correct"] += 1; s, why = 2, "correct"
            elif abst:
                out["control_overcautious"] += 1; s, why = 1, "over-cautious"
            else:
                s, why = 0, f"wrong: {root[:60]}"
        if fabricated:
            why += f" | unprompted numbers {fabricated[:3]}"
        scores.append(s); note(model, "evidence", r["item"], s, why)
    n_i = out["insufficient_n"] or 1
    return {**out, "abstention_rate": round(out["insufficient_abstained"] / n_i, 3),
            "unsupported_claim_rate": round(out["confident_unsupported"] / n_i, 3),
            "mean": round(st.mean(scores), 3) if scores else 0.0, "norm": round(st.mean(scores) / 2, 3) if scores else 0.0}


def score_agent(model, rows):
    spec = {s["id"]: s for s in P("agent_scenarios.json")["scenarios"]}
    if not rows or all(r["status"] == "unsupported" for r in rows):
        for r in rows:
            note(model, "agent", r["item"], 0, "unsupported")
        return {"supported": False, "norm": 0.0}
    k = dict(n=0, success=0, multi_step_success=0, confident_wrong=0, no_diagnosis=0, overcautious=0,
             ambiguous_n=0, ambiguous_correct=0, failed=0, hallucinated_calls=0, invalid_arg_calls=0, total_calls=0)
    scores, walls = [], []
    valid_labels = {l.lower(): l for l in INCIDENT_TYPES}
    for r in rows:
        sc = spec[r["item"]]
        k["n"] += 1
        walls.append(r.get("wall_s"))
        trace = r.get("tool_trace") or []
        called = {t["name"] for t in trace}
        k["total_calls"] += len(trace)
        for t in trace:
            if t["name"] not in TOOL_ARG_MODELS:
                k["hallucinated_calls"] += 1
            elif not validate_args(t["name"], _args(t)):
                k["invalid_arg_calls"] += 1
        amb = sc["gold"] == "INSUFFICIENT_EVIDENCE"
        k["ambiguous_n"] += amb
        if r["status"] != "ok":
            k["failed"] += 1; scores.append(0); note(model, "agent", r["item"], 0, r["status"]); continue
        m = re.search(r"DIAGNOSIS:\s*\**\s*([A-Za-z_]+)", r.get("final_content") or "")
        label = valid_labels.get(m.group(1).lower()) if m else None
        if label is None:
            k["no_diagnosis"] += 1; scores.append(0)
            note(model, "agent", r["item"], 0, f"no parseable diagnosis: {(r.get('final_content') or '')[:60]!r}"); continue
        if amb:
            if label == "INSUFFICIENT_EVIDENCE":
                k["ambiguous_correct"] += 1
                s = 2 if called else 1
            else:
                k["confident_wrong"] += 1; s = 0
        else:
            if label == sc["gold"]:
                s = 2 if called & set(sc["required_any"]) else 1
            elif label == "INSUFFICIENT_EVIDENCE":
                k["overcautious"] += 1; s = 1 if called else 0
            else:
                k["confident_wrong"] += 1; s = 0
        k["success"] += s == 2
        k["multi_step_success"] += s == 2 and len(trace) >= 2
        scores.append(s)
        note(model, "agent", r["item"], s, f"label={label} calls={[t['name'] for t in trace]}")
    n = k["n"] or 1
    return {"supported": True, **k, "success_rate": round(k["success"] / n, 3),
            "multi_step_success_rate": round(k["multi_step_success"] / n, 3),
            "confident_wrong_rate": round(k["confident_wrong"] / n, 3),
            "mean_tool_calls": round(k["total_calls"] / n, 2), "median_scenario_wall_s": med(walls),
            "mean": round(st.mean(scores), 3), "norm": round(st.mean(scores) / 2, 3)}


def score_context(model, rows):
    out = {}
    for r in rows:
        size = r["nominal_tokens"]
        nd = r["needle"]
        txt = r.get("content") or ""
        hms = nd["time"].split("T")[1].rstrip("Z")
        s = (nd["host"] in txt) + (hms in txt)
        note(model, "context", r["item"], s, f"host={'y' if nd['host'] in txt else 'n'} time={'y' if hms in txt else 'n'}")
        e = out.setdefault(size, {"runs": []})
        e["runs"].append({"status": r["status"], "prompt_tokens": r.get("prompt_tokens"),
                          "prompt_tok_s": r.get("prompt_tokens_per_s"), "gen_tok_s": r.get("tokens_per_s"),
                          "wall_s": r.get("wall_s"), "ttft_s": r.get("ttft_s"), "peak_rss_mib": r.get("peak_runner_rss_mib"),
                          "min_mem_avail_mib": r.get("min_mem_available_mib"), "needle": s,
                          "truncated": r.get("truncated_or_short"), "num_ctx": r.get("num_ctx")})
    for size, e in out.items():
        rs = e["runs"]
        e.update({"prompt_tokens": med([x["prompt_tokens"] for x in rs]), "prompt_tok_s": med([x["prompt_tok_s"] for x in rs]),
                  "gen_tok_s": med([x["gen_tok_s"] for x in rs]), "wall_s": med([x["wall_s"] for x in rs]),
                  "ttft_s": med([x["ttft_s"] for x in rs]), "peak_rss_mib": max((x["peak_rss_mib"] or 0) for x in rs),
                  "min_mem_avail_mib": min((x["min_mem_avail_mib"] or 10**9) for x in rs),
                  "needle_mean": round(st.mean(x["needle"] for x in rs), 2),
                  "failures": sum(x["status"] != "ok" for x in rs), "truncated_any": any(x["truncated"] for x in rs)})
    return {str(k): v for k, v in sorted(out.items())}


# ----------------------------------------------------------------- per model
def score_model(md):
    model = None
    allrows = {}
    for f in sorted(md.glob("*.jsonl")):
        allrows[f.stem] = load(md, f.stem)
        if allrows[f.stem]:
            model = allrows[f.stem][0]["model"]
    if not model:
        return None
    w = allrows.get("warmup", [{}])[-1]
    gen = allrows.get("generation", [])
    res = {
        "model": model, "digest": w.get("model_digest"), "capabilities": w.get("capabilities"),
        "desktop_at_start": w.get("desktop"), "runner_cmdline": w.get("runner_cmdline"),
        "load_duration_s": w.get("load_duration_s"),
        "generation": score_rubric(model, gen, P("generation.json")["items"], "generation"),
        "knowledge": score_rubric(model, allrows.get("knowledge", []), P("knowledge.json")["items"], "knowledge"),
        "evidence": score_evidence(model, allrows.get("evidence", [])),
        "structured_prompt": score_structured(model, allrows.get("structured_prompt", []), "prompt"),
        "structured_constrained": score_structured(model, allrows.get("structured_constrained", []), "constrained"),
        "tools": score_tools(model, allrows.get("tools", [])),
        "agent": score_agent(model, allrows.get("agent", [])),
        "context": score_context(model, allrows.get("context", [])),
    }
    # performance (4K-context suites only)
    perf_rows = [r for s, rows in allrows.items() if s not in ("context", "context_calibration", "agent")
                 for r in rows if r.get("status") not in ("unsupported",)]
    agent_turns = [t for r in allrows.get("agent", []) for t in (r.get("turns") or [])]
    res["perf"] = {
        "gen_tok_s_median": med([r.get("tokens_per_s") for r in gen]),
        "gen_tok_s_min": min((r["tokens_per_s"] for r in gen if r.get("tokens_per_s")), default=None),
        "gen_tok_s_max": max((r["tokens_per_s"] for r in gen if r.get("tokens_per_s")), default=None),
        "prompt_tok_s_median": med([r.get("prompt_tokens_per_s") for r in gen]),
        "ttft_s_median": med([r.get("ttft_s") for r in gen]),
        "wall_s_median_generation": med([r.get("wall_s") for r in gen]),
        "output_tokens_median_generation": med([r.get("output_tokens") for r in gen]),
        "agent_turn_wall_s_median": med([t.get("wall_s") for t in agent_turns]),
        "peak_runner_rss_mib_4k": max([r.get("peak_runner_rss_mib") or 0 for r in perf_rows] +
                                      [t.get("peak_runner_rss_mib") or 0 for t in agent_turns]),
        "min_mem_available_mib": min([r.get("min_mem_available_mib") or 10**9 for r in perf_rows] +
                                     [t.get("min_mem_available_mib") or 10**9 for t in agent_turns]),
        "system_cpu_pct_mean_generation": med([r.get("system_cpu_pct_mean") for r in gen]),
        "system_cpu_pct_max_generation": max((r.get("system_cpu_pct_max") or 0 for r in gen), default=None),
        "runner_cpu_pct_mean_generation": med([r.get("runner_cpu_pct_mean") for r in gen]),
    }
    counted = [r for s, rows in allrows.items() if s != "warmup" for r in rows if r.get("status") != "unsupported"]
    bad = [r for r in counted if r.get("status") != "ok"]
    res["stability"] = {"requests": len(counted), "failed": len(bad),
                        "fail_rate": round(len(bad) / len(counted), 4) if counted else None,
                        "by_status": {s: sum(r.get("status") == s for r in bad) for s in {r.get("status") for r in bad}},
                        "unsupported_requests": sum(r.get("status") == "unsupported" for rows in allrows.values() for r in rows)}
    comp = {"agent": res["agent"]["norm"], "tools": res["tools"]["norm"], "evidence": res["evidence"]["norm"],
            "structured": res["structured_constrained"]["norm"], "knowledge": res["knowledge"]["norm"],
            "generation": res["generation"]["norm"]}
    res["quality_components"] = comp
    res["Q"] = round(sum(WEIGHTS[k] * v for k, v in comp.items()), 4)
    t = res["tools"]
    gates = {
        "G1_stability": (res["stability"]["fail_rate"] or 0) <= GATES["stability_fail_rate_max"],
        "G2_memory": res["perf"]["peak_runner_rss_mib_4k"] / GIB_MIB <= GATES["peak_rss_gib_max"]
                     and res["perf"]["min_mem_available_mib"] >= 2 * GIB_MIB,
        "G3_speed": (res["perf"]["gen_tok_s_median"] or 0) >= GATES["gen_tok_s_min"],
        "G4_tools": t.get("supported", False) and t["tool_call_success_rate"] >= GATES["tool_success_min"]
                    and t["hallucinated_tool_rate"] <= GATES["hallucinated_tool_max"],
        "G5_structured": res["structured_constrained"]["schema_valid_rate"] >= GATES["constrained_schema_valid_min"],
        "G6_evidence": res["evidence"]["norm"] >= GATES["evidence_norm_min"],
    }
    res["gates"] = gates
    res["eligible"] = all(gates.values())
    return res


def decide(results):
    elig = [r for r in results if r["eligible"]]
    if not elig:
        return {"primary": None, "secondary": None, "baseline": "gemma3:1b", "verdict": "FAIL",
                "reason": "no model passed all hard gates"}
    best = max(elig, key=lambda r: r["Q"])
    lat = lambda r: r["agent"].get("median_scenario_wall_s") or float("inf")
    primary, rule = best, "highest Q"
    for r in elig:
        if r is not best and best["Q"] - r["Q"] <= 0.05 and lat(r) <= 0.67 * lat(best):
            if lat(r) < lat(primary):
                primary, rule = r, f"within 0.05 Q of {best['model']} and >=1.5x faster agent loop"
    sec = [r for r in elig if r is not primary and r["Q"] >= 0.8 * primary["Q"]]
    secondary = min(sec, key=lat) if sec else None
    return {"primary": primary["model"], "primary_rule": rule, "best_Q_model": best["model"],
            "secondary": secondary["model"] if secondary else None, "baseline": "gemma3:1b", "verdict": "PASS"}


def main():
    results = [r for md in sorted(RUNS.iterdir()) if md.is_dir() and (r := score_model(md))]
    order = ["gemma3:1b", "qwen3:4b", "qwen3.5:4b", "qwen3:8b", "qwen3.5:9b"]
    results.sort(key=lambda r: order.index(r["model"]) if r["model"] in order else 99)
    decision = decide(results)
    manifest = json.loads((HERE / "model_manifest.json").read_text())["models"] if (HERE / "model_manifest.json").exists() else {}
    (OUT / "summary.json").write_text(json.dumps({"weights": WEIGHTS, "gates": GATES, "decision": decision,
                                                  "models": results}, indent=2) + "\n")
    with open(OUT / "item_scores.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["model", "suite", "item", "score", "note"]); w.writeheader(); w.writerows(ITEMS)
    flat = []
    for r in results:
        sz = manifest.get(r["model"], {}).get("size_bytes")
        flat.append({
            "model": r["model"], "size_gb": round(sz / 1e9, 2) if sz else None,
            "peak_rss_gib_4k": round(r["perf"]["peak_runner_rss_mib_4k"] / 1024, 2),
            "gen_tok_s": r["perf"]["gen_tok_s_median"], "prompt_tok_s": r["perf"]["prompt_tok_s_median"],
            "ttft_s": r["perf"]["ttft_s_median"],
            "tool_success": r["tools"].get("tool_call_success_rate"),
            "arg_validity": r["tools"].get("argument_validity"),
            "json_valid_prompt": r["structured_prompt"]["valid_json_rate"],
            "schema_valid_prompt": r["structured_prompt"]["schema_valid_rate"],
            "schema_valid_constrained": r["structured_constrained"]["schema_valid_rate"],
            "structured_semantic_constrained": r["structured_constrained"]["semantic_correct_rate"],
            "knowledge_norm": r["knowledge"]["norm"], "generation_norm": r["generation"]["norm"],
            "evidence_norm": r["evidence"]["norm"], "agent_norm": r["agent"]["norm"],
            "agent_success": r["agent"].get("success_rate"),
            "agent_median_wall_s": r["agent"].get("median_scenario_wall_s"),
            "fail_rate": r["stability"]["fail_rate"], "Q": r["Q"], "eligible": r["eligible"],
            "failed_gates": ",".join(g for g, ok in r["gates"].items() if not ok),
        })
    if flat:
        with open(OUT / "summary.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(flat[0])); w.writeheader(); w.writerows(flat)
    md = ["# Phase 1B comparison (generated by score.py)", "",
          "| " + " | ".join(flat[0]) + " |" if flat else "", "|" + "---|" * (len(flat[0]) if flat else 0)]
    md += ["| " + " | ".join(str(v) for v in row.values()) + " |" for row in flat]
    md += ["", f"**Decision:** `{json.dumps(decision)}`"]
    (OUT / "comparison.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
