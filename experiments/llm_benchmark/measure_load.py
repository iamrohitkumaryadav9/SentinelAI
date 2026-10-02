#!/usr/bin/env python3
"""Cold-load measurement (post-campaign supplement).

The campaign's thinking probe runs before warm-up, so warm-up load_duration is ~0 for
thinking-capable models. This script measures cold load explicitly: unload everything,
then a 1-token request, 3 repetitions per model. Writes results/cold_load.json.
"""

import json
import time
from pathlib import Path

import httpx
import psutil

HERE = Path(__file__).resolve().parent
O = "http://127.0.0.1:11434"
MODELS = ["gemma3:1b", "qwen3:4b", "qwen3.5:4b", "qwen3:8b", "qwen3.5:9b"]


def unload_all():
    for m in httpx.get(f"{O}/api/ps").json().get("models", []):
        httpx.post(f"{O}/api/generate", json={"model": m["name"], "keep_alive": 0}, timeout=60)
    while httpx.get(f"{O}/api/ps").json().get("models"):
        time.sleep(0.5)


def runner_threads():
    for p in psutil.process_iter(["name"]):
        if p.info["name"] == "llama-server":
            return p.num_threads(), " ".join(p.cmdline())
    return None, None


out = {}
for m in MODELS:
    reps = []
    for r in range(3):
        unload_all()
        time.sleep(2)
        t0 = time.perf_counter()
        body = {"model": m, "prompt": "ok", "stream": False, "keep_alive": "1m",
                "options": {"num_predict": 1, "num_ctx": 4096, "temperature": 0}}
        res = httpx.post(f"{O}/api/generate", json=body, timeout=300).json()
        wall = time.perf_counter() - t0
        thr, cmd = runner_threads()
        reps.append({"load_duration_s": round(res.get("load_duration", 0) / 1e9, 3), "client_wall_s": round(wall, 3),
                     "runner_os_threads": thr})
    out[m] = {"reps": reps, "median_load_s": sorted(x["load_duration_s"] for x in reps)[1],
              "runner_cmdline": cmd}
    print(m, out[m]["median_load_s"], reps, flush=True)
unload_all()
(HERE / "results" / "cold_load.json").write_text(json.dumps(out, indent=2) + "\n")
