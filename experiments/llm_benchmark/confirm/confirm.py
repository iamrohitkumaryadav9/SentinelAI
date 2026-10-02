#!/usr/bin/env python3
"""Phase 1B confirmatory agent experiment runner (qwen3:8b vs qwen3.5:9b only).

Reuses the Phase 1B harness (benchmark.chat, Sampler, thinking probe, warm-up, settings)
unchanged; adds an argument-respecting tool simulator and a structured final answer.
Raw records: confirm/results/runs/<model>/agent.jsonl
"""

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("BENCH_RUNS_DIR", str(HERE / "results" / "runs"))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import psutil  # noqa: E402

import benchmark as B  # noqa: E402
from simulator import Simulator, render  # noqa: E402

DATA = json.loads((HERE / "scenarios.json").read_text())
PROTO = json.loads((HERE / "protocol.json").read_text())
ALLOWED = PROTO["allowed_models"]
MAX_TOOL_CALLS = PROTO["max_tool_calls"]
NUM_PREDICT = PROTO["num_predict_per_turn"]
SYSTEM = PROTO["system_prompt"]


def parse_final(text):
    d = re.search(r"DIAGNOSIS:\s*\**\s*([A-Za-z_]+)", text or "")
    c = re.search(r"CONFIDENCE:\s*\**\s*([0-9]*\.?[0-9]+)", text or "")
    e = re.search(r"EVIDENCE:\s*(.+)", text or "", re.S)
    conf = float(c.group(1)) if c else None
    return {"label_raw": d.group(1) if d else None,
            "confidence": conf if conf is None or 0 <= conf <= 1 else None,
            "confidence_raw": c.group(1) if c else None,
            "evidence_text": e.group(1).strip()[:1000] if e else None}


def run_scenario(run, sc):
    sim = Simulator(sc)
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": sc["incident"]}]
    trace, turns, status, final, t0 = [], [], "concluded", "", time.perf_counter()
    swap0 = psutil.swap_memory().used
    for step in range(MAX_TOOL_CALLS + 1):
        rec = run.chat(msgs, tools=B.TOOLS, options={"num_predict": NUM_PREDICT})
        turns.append({k: rec.get(k) for k in ("status", "wall_s", "ttft_s", "prompt_tokens", "output_tokens", "tokens_per_s",
                                              "prompt_tokens_per_s", "peak_runner_rss_mib", "min_mem_available_mib",
                                              "max_swap_used_mib", "system_cpu_pct_mean", "runner_cpu_pct_mean", "done_reason")}
                     | {"assistant_content": (rec.get("content") or "")[:600], "n_tool_calls": len(rec.get("tool_calls") or [])})
        if rec["status"] != "ok":
            status = rec["status"]
            break
        if not rec["tool_calls"]:
            final = rec["content"]
            break
        if step == MAX_TOOL_CALLS:
            status = "step_budget_exhausted"
            break
        call = rec["tool_calls"][0]["function"]
        name, args = call.get("name"), call.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_unparseable": args}
        result = sim.call(name, args if isinstance(args, dict) else {})
        trace.append({"name": name, "arguments": args, "n_parallel_calls": len(rec["tool_calls"]),
                      "result_error": result.get("error") if isinstance(result, dict) else None,
                      "result_chars": len(render(result))})
        msgs.append({"role": "assistant", "content": rec["content"], "tool_calls": [rec["tool_calls"][0]]})
        msgs.append({"role": "tool", "tool_name": name, "content": render(result)})
    conv_tokens = sum((t["prompt_tokens"] or 0) + (t["output_tokens"] or 0) for t in turns)
    out = {
        "scenario": sc["id"], "category": sc["category"], "subcase": sc["subcase"], "expected": sc["gold"],
        "termination": status, "final_content": final, **parse_final(final),
        "tool_trace": trace, "n_tool_calls": len(trace), "n_model_calls": len(turns), "turns": turns,
        "wall_s": round(time.perf_counter() - t0, 2),
        "prompt_tokens_total": sum(t["prompt_tokens"] or 0 for t in turns),
        "output_tokens_total": sum(t["output_tokens"] or 0 for t in turns),
        "conversation_tokens_est": conv_tokens,
        "context_overflow_risk": conv_tokens + NUM_PREDICT > B.DEFAULT_CTX,
        "peak_runner_rss_mib": max((t["peak_runner_rss_mib"] or 0) for t in turns),
        "min_mem_available_mib": min((t["min_mem_available_mib"] or 10**9) for t in turns),
        "max_swap_used_mib": max((t["max_swap_used_mib"] or 0) for t in turns),
        "swap_used_mib_start": round(swap0 / 2**20), "swap_used_mib_end": round(psutil.swap_memory().used / 2**20),
        "status": "ok" if status in ("concluded", "step_budget_exhausted") else status,
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default=",".join(ALLOWED))
    a = ap.parse_args()
    for model in a.models.split(","):
        if model not in ALLOWED:
            raise SystemExit(f"REFUSED: {model} is not part of the confirmatory protocol {ALLOWED}")
    for model in a.models.split(","):
        B.wait_for_ollama()
        run = B.Run(model)
        print(f"== {model} digest={run.digest}", flush=True)
        run.warmup()
        print(f"   think mode = {run.think}", flush=True)
        if run.think is not False:
            raise SystemExit(f"STOP: {model} thinking probe returned {run.think}; protocol requires think=false for both")
        outdir = run.dir
        f = open(outdir / "agent.jsonl", "a")
        try:
            for sc in DATA["scenarios"]:
                r = run_scenario(run, sc)
                row = {"timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "model": model,
                       "model_digest": run.digest, **run.env, "think_mode": run.think,
                       "other_models_resident": [m for m in B.loaded_models() if m != model], **r}
                f.write(json.dumps(row) + "\n"); f.flush()
                print(f"  {sc['id']} {sc['gold']:22s} -> {str(r['label_raw']):22s} {r['termination']:22s} "
                      f"calls={r['n_tool_calls']} wall={r['wall_s']}s rss={r['peak_runner_rss_mib']} "
                      f"swap={r['max_swap_used_mib']} conv_tok={r['conversation_tokens_est']}", flush=True)
                if any(t["status"] == "aborted_ram" for t in r["turns"]):
                    raise SystemExit("ABORT: MemAvailable fell below the 2 GiB floor")
        finally:
            f.close()
            B.unload(model)
            print(f"   desktop at end: {B.desktop_state()}", flush=True)
    print("confirmatory run complete", flush=True)


if __name__ == "__main__":
    main()
