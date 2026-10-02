#!/usr/bin/env python3
"""SentinelAI Phase 1B — local LLM benchmark harness (Ollama only, no cloud).

Raw run records are written as JSONL to results/runs/<model>/<suite>.jsonl.
Scoring is done separately by score.py so raw data can be re-scored.

Usage (from ~/sentinelai with the project venv):
  .venv/bin/python experiments/llm_benchmark/benchmark.py pull --model qwen3:4b
  .venv/bin/python experiments/llm_benchmark/benchmark.py run  --model qwen3:4b [--suites tools,agent]
  .venv/bin/python experiments/llm_benchmark/benchmark.py campaign --models gemma3:1b,qwen3:4b,...
"""

import argparse
import datetime as dt
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import psutil
from pydantic import ValidationError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from schemas.models import TOOL_ARG_MODELS, IncidentDiagnosis  # noqa: E402

OLLAMA = "http://127.0.0.1:11434"
PROMPTS = HERE / "prompts"
RUNS = Path(os.environ.get("BENCH_RUNS_DIR", HERE / "results" / "runs"))
MANIFEST = HERE / "model_manifest.json"
TOOLS = json.loads((HERE / "schemas" / "tools.json").read_text())

MIN_DISK_GIB = 80          # stop downloading below this
MIN_MEM_GIB = 2.0          # abort benchmark below this
REQUEST_TIMEOUT_S = 300    # per inference request
CONTEXT_TIMEOUT_S = 900    # per long-context request
DEFAULT_CTX = 4096
THINK_BUDGET = 1024       # extra num_predict for thinking-only models (protocol deviation D1)
BASE_OPTIONS = {"temperature": 0, "seed": 42}
GIB = 1024 ** 3


class RamFloorBreached(RuntimeError):
    pass


class EarlyStop(RuntimeError):
    """Pre-registered objective early-stop condition met (see README)."""


# Pre-registered early-stop thresholds (identical for every remaining model).
ES_MIN_REQUESTS = 10          # evaluate a suite only after this many requests (agent: ES_MIN_SCENARIOS)
ES_MIN_SCENARIOS = 5
ES_MAX_INCOMPLETE = 0.50      # ES1: >50 % of requests produce no usable output
ES_MAX_MEDIAN_WALL_S = 180    # ES2: median request latency
ES_MAX_AGENT_SCENARIO_S = 900 # ES2: median agent scenario latency (evaluated after 3 scenarios)
NOT_RUN = "NOT RUN — EARLY STOP AFTER OBJECTIVE DISQUALIFICATION"
SLICE = json.loads((PROMPTS / "validation_slice.json").read_text())


def incomplete(rec):
    """A request/scenario that produced no usable output."""
    if rec.get("status") != "ok":
        return True
    if "final_content" in rec:                      # agent scenario aggregate
        return not (rec.get("final_content") or "").strip()
    return not (rec.get("content") or "").strip() and not rec.get("tool_calls")


# --------------------------------------------------------------------------- env
def ollama_version():
    return httpx.get(f"{OLLAMA}/api/version", timeout=10).json()["version"]


def environment():
    vm = psutil.virtual_memory()
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    return {
        "kernel": platform.release(),
        "cpu": cpu,
        "logical_cpus": psutil.cpu_count(),
        "ram_total_gib": round(vm.total / GIB, 2),
        "ollama_version": ollama_version(),
        "python": platform.python_version(),
    }


def desktop_state():
    groups = {"chrome": 0, "vscode_server": 0, "claude": 0, "gnome_shell": 0, "ollama_runner": 0}
    for p in psutil.process_iter(["name", "cmdline", "memory_info"]):
        try:
            name = p.info["name"] or ""
            cmd = " ".join(p.info["cmdline"] or [])
            rss = p.info["memory_info"].rss if p.info["memory_info"] else 0
        except (psutil.Error, TypeError):
            continue
        if "chrome" in name:
            groups["chrome"] += rss
        elif "claude" in name or "claude-code" in cmd:
            groups["claude"] += rss
        elif ".vscode-server" in cmd:
            groups["vscode_server"] += rss
        elif name == "gnome-shell":
            groups["gnome_shell"] += rss
        elif name == "llama-server" or (name.startswith("ollama") and "runner" in cmd):
            groups["ollama_runner"] += rss
    out = {f"{k}_rss_mib": round(v / 2**20) for k, v in groups.items()}
    out["mem_available_mib"] = round(psutil.virtual_memory().available / 2**20)
    out["swap_used_mib"] = round(psutil.swap_memory().used / 2**20)
    return out


# ---------------------------------------------------------------------- ollama
def show(model):
    return httpx.post(f"{OLLAMA}/api/show", json={"model": model}, timeout=30).json()


def loaded_models():
    return [m["name"] for m in httpx.get(f"{OLLAMA}/api/ps", timeout=10).json().get("models", [])]


def wait_for_ollama(max_wait_s=120):
    """Block until the Ollama API answers (survives a service restart)."""
    deadline = time.time() + max_wait_s
    while True:
        try:
            return httpx.get(f"{OLLAMA}/api/version", timeout=5).json()["version"]
        except httpx.HTTPError:
            if time.time() > deadline:
                raise
            time.sleep(2)


def unload(model):
    try:
        httpx.post(f"{OLLAMA}/api/generate", json={"model": model, "keep_alive": 0}, timeout=60)
    except httpx.HTTPError as e:
        print(f"   unload {model} failed: {e}", flush=True)


def unload_all_except(keep=None):
    for m in loaded_models():
        if m != keep:
            unload(m)
    deadline = time.time() + 30
    while time.time() < deadline and any(m != keep for m in loaded_models()):
        time.sleep(0.5)


def runner_processes():
    out = []
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            name = p.info["name"] or ""
            if name == "llama-server" or (name.startswith("ollama") and "runner" in " ".join(p.info["cmdline"] or [])):
                out.append(p)
        except psutil.Error:
            pass
    return out


class Sampler:
    """Samples Ollama runner RSS/CPU and system memory every 200 ms."""

    def __init__(self, interval=0.2):
        self.interval = interval
        self._stop = threading.Event()
        self.peak_runner_rss = 0
        self.min_mem_available = None
        self.cpu_samples = []
        self.runner_cpu_samples = []
        self.ram_breach = False
        self._procs = {}
        self.max_swap_used = 0

    def _tick(self):
        rss = 0
        rcpu = 0.0
        for p in runner_processes():
            try:
                if p.pid not in self._procs:
                    self._procs[p.pid] = p
                    p.cpu_percent(None)
                rss += p.memory_info().rss
                rcpu += self._procs[p.pid].cpu_percent(None)
            except psutil.Error:
                pass
        self.peak_runner_rss = max(self.peak_runner_rss, rss)
        self.max_swap_used = max(self.max_swap_used, psutil.swap_memory().used)
        avail = psutil.virtual_memory().available
        self.min_mem_available = avail if self.min_mem_available is None else min(self.min_mem_available, avail)
        if avail < MIN_MEM_GIB * GIB:
            self.ram_breach = True
        self.cpu_samples.append(psutil.cpu_percent(None))
        self.runner_cpu_samples.append(rcpu)

    def run(self):
        psutil.cpu_percent(None)
        while not self._stop.is_set():
            self._tick()
            self._stop.wait(self.interval)

    def __enter__(self):
        self._t = threading.Thread(target=self.run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *a):
        self._stop.set()
        self._t.join()

    def summary(self):
        mean = lambda xs: round(sum(xs) / len(xs), 1) if xs else None
        return {
            "peak_runner_rss_mib": round(self.peak_runner_rss / 2**20),
            "min_mem_available_mib": round((self.min_mem_available or 0) / 2**20),
            "system_cpu_pct_mean": mean(self.cpu_samples[1:]),
            "system_cpu_pct_max": max(self.cpu_samples[1:], default=None),
            "runner_cpu_pct_mean": mean(self.runner_cpu_samples[1:]),
            "ram_floor_breached": self.ram_breach,
            "max_swap_used_mib": round(self.max_swap_used / 2**20),
        }


def chat(model, messages, *, tools=None, fmt=None, options=None, think=None, timeout=REQUEST_TIMEOUT_S):
    """Streaming /api/chat. Returns content, tool_calls, Ollama timings, client TTFT."""
    body = {"model": model, "messages": messages, "stream": True, "keep_alive": "30m",
            "options": {**BASE_OPTIONS, "num_ctx": DEFAULT_CTX, **(options or {})}}
    if tools is not None:
        body["tools"] = tools
    if fmt is not None:
        body["format"] = fmt
    if think is not None:
        body["think"] = think
    rec = {"content": "", "thinking": "", "tool_calls": [], "error": None, "status": "ok",
           "ttft_s": None, "options": body["options"], "think": think}
    t0 = time.perf_counter()
    final = {}
    with Sampler() as s:
        try:
            with httpx.stream("POST", f"{OLLAMA}/api/chat", json=body,
                              timeout=httpx.Timeout(timeout, connect=10)) as r:
                if r.status_code != 200:
                    rec["status"] = "error"
                    rec["error"] = f"HTTP {r.status_code}: {r.read().decode()[:300]}"
                else:
                    for line in r.iter_lines():
                        if time.perf_counter() - t0 > timeout:
                            rec["status"], rec["error"] = "timeout", f"exceeded {timeout}s"
                            break
                        if s.ram_breach:
                            rec["status"], rec["error"] = "aborted_ram", "MemAvailable below floor"
                            break
                        if not line:
                            continue
                        ch = json.loads(line)
                        if "error" in ch:
                            rec["status"], rec["error"] = "error", ch["error"]
                            break
                        m = ch.get("message", {})
                        if rec["ttft_s"] is None and (m.get("content") or m.get("thinking") or m.get("tool_calls")):
                            rec["ttft_s"] = round(time.perf_counter() - t0, 3)
                        rec["content"] += m.get("content", "")
                        rec["thinking"] += m.get("thinking", "") or ""
                        rec["tool_calls"].extend(m.get("tool_calls") or [])
                        if ch.get("done"):
                            final = ch
        except httpx.TimeoutException as e:
            rec["status"], rec["error"] = "timeout", f"{type(e).__name__}"
        except httpx.HTTPError as e:
            rec["status"], rec["error"] = "error", f"{type(e).__name__}: {e}"
    rec["wall_s"] = round(time.perf_counter() - t0, 3)
    ns = lambda k: round(final[k] / 1e9, 4) if k in final else None
    rec.update({
        "prompt_tokens": final.get("prompt_eval_count"),
        "output_tokens": final.get("eval_count"),
        "load_duration_s": ns("load_duration"),
        "prompt_eval_duration_s": ns("prompt_eval_duration"),
        "eval_duration_s": ns("eval_duration"),
        "total_duration_s": ns("total_duration"),
        "done_reason": final.get("done_reason"),
    })
    pe, ev = final.get("prompt_eval_duration"), final.get("eval_duration")
    rec["prompt_tokens_per_s"] = round(final["prompt_eval_count"] / (pe / 1e9), 2) if pe and final.get("prompt_eval_count") else None
    rec["tokens_per_s"] = round(final["eval_count"] / (ev / 1e9), 2) if ev and final.get("eval_count") else None
    rec.update(s.summary())
    if s.ram_breach and rec["status"] == "ok":
        rec["status"] = "aborted_ram"
    return rec


# ---------------------------------------------------------------------- runner
class Run:
    def __init__(self, model):
        self.model = model
        self.info = show(model)
        self.caps = self.info.get("capabilities", [])
        self.digest = next((m["digest"] for m in httpx.get(f"{OLLAMA}/api/tags").json()["models"]
                            if m["name"] == model), None)
        self.think = False if "thinking" in self.caps else None
        self.env = environment()
        self.dir = RUNS / model.replace(":", "_").replace("/", "_")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.tag = {}
        self.track = {}
        self.completed = []

    def record(self, suite, item_id, rec, extra=None):
        others = [m for m in loaded_models() if m != self.model]
        row = {"timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "suite": suite, "item": item_id, "model": self.model, "model_digest": self.digest,
               "think_mode": self.think,
               **self.env, "other_models_resident": others, **rec, **self.tag, **(extra or {})}
        with open(self.dir / f"{suite}.jsonl", "a") as f:
            f.write(json.dumps(row) + "\n")
        status = rec.get("status")
        print(f"  [{suite}] {item_id:28s} {status:11s} wall={rec.get('wall_s')}s "
              f"pt={rec.get('prompt_tokens')} ot={rec.get('output_tokens')} "
              f"tok/s={rec.get('tokens_per_s')} rss={rec.get('peak_runner_rss_mib')}MiB", flush=True)
        if status == "aborted_ram" or rec.get("ram_floor_breached"):
            raise RamFloorBreached(f"MemAvailable fell below {MIN_MEM_GIB} GiB during {suite}/{item_id}")
        if suite in ("warmup", "context_calibration") or self.tag.get("slice") or status == "unsupported":
            return
        t = self.track.setdefault(suite, {"n": 0, "incomplete": 0, "walls": []})
        t["n"] += 1
        t["incomplete"] += incomplete(rec)
        t["walls"].append(rec.get("wall_s") or 0)
        min_n = ES_MIN_SCENARIOS if suite == "agent" else ES_MIN_REQUESTS
        med_wall = sorted(t["walls"])[len(t["walls"]) // 2]
        if t["n"] >= min_n and t["incomplete"] / t["n"] > ES_MAX_INCOMPLETE:
            raise EarlyStop(f"ES1 failure-to-complete: {t['incomplete']}/{t['n']} requests in '{suite}' "
                            f"produced no usable output (> {ES_MAX_INCOMPLETE:.0%})")
        if suite == "agent" and t["n"] >= 3 and med_wall > ES_MAX_AGENT_SCENARIO_S:
            raise EarlyStop(f"ES2 latency: median agent scenario {med_wall:.0f}s > {ES_MAX_AGENT_SCENARIO_S}s")
        if suite != "agent" and t["n"] >= ES_MIN_REQUESTS and med_wall > ES_MAX_MEDIAN_WALL_S:
            raise EarlyStop(f"ES2 latency: median request {med_wall:.0f}s in '{suite}' > {ES_MAX_MEDIAN_WALL_S}s")

    def chat(self, messages, **kw):
        if self.think:
            opts = dict(kw.pop("options", {}) or {})
            opts["num_predict"] = opts.get("num_predict", 256) + THINK_BUDGET
            kw["options"] = opts
        return chat(self.model, messages, think=self.think, **kw)

    # -- suites ---------------------------------------------------------------
    def probe_thinking(self):
        """Evidence-based thinking mode (D1): if think=false yields a direct answer, benchmark
        non-thinking; if the model reasons anyway (thinking-only), use its native thinking mode."""
        if "thinking" not in self.caps:
            self.think, self.think_probe = None, {"result": "no thinking capability"}
            return
        r = chat(self.model, [{"role": "user", "content": "What is 17*3? Answer with just the number."}],
                 think=False, options={"num_predict": 64})
        direct = r["status"] == "ok" and r["content"].strip().rstrip(".") == "51"
        self.think = False if direct else True
        self.think_probe = {"think_false_content": r["content"][:200], "output_tokens": r["output_tokens"],
                            "direct_answer": direct, "chosen_think": self.think,
                            "finetune": self.info.get("model_info", {}).get("general.finetune"),
                            "version": self.info.get("model_info", {}).get("general.version")}

    def warmup(self):
        unload_all_except(self.model)
        self.probe_thinking()
        print(f"   thinking probe: {self.think_probe}", flush=True)
        rec = self.chat([{"role": "user", "content": "Reply with the single word: ready"}],
                        options={"num_predict": 8})
        runner_cmd = [" ".join(p.cmdline()) for p in runner_processes()]
        svc_env = subprocess.run(["systemctl", "show", "ollama", "-p", "Environment"],
                                 capture_output=True, text=True).stdout.strip()
        self.record("warmup", "load", rec, {"desktop": desktop_state(), "capabilities": self.caps,
                                            "think": self.think, "think_probe": self.think_probe,
                                            "ollama_service_env": svc_env,
                                            "runner_cmdline": runner_cmd, "show_details": self.info.get("details"),
                                            "model_info_ctx": {k: v for k, v in self.info.get("model_info", {}).items()
                                                               if k.endswith((".context_length", ".block_count"))}})

    def generation(self, reps=3):
        d = json.loads((PROMPTS / "generation.json").read_text())
        for it in d["items"]:
            for r in range(reps):
                # A distinct leading run tag defeats KV prefix caching so every
                # repetition pays full prompt processing.
                msg = [{"role": "user", "content": f"[run {r}] {it['prompt']}"}]
                rec = self.chat(msg, options={"num_predict": 384})
                self.record("generation", f"{it['id']}#r{r}", rec, {"rep": r})

    def knowledge(self):
        d = json.loads((PROMPTS / "knowledge.json").read_text())
        for it in d["items"]:
            rec = self.chat([{"role": "user", "content": it["prompt"] + d["suffix"]}],
                            options={"num_predict": 256})
            self.record("knowledge", it["id"], rec)

    def evidence(self):
        d = json.loads((PROMPTS / "evidence.json").read_text())
        for it in d["items"]:
            rec = self.chat([{"role": "user", "content": it["prompt"] + d["format"]}],
                            options={"num_predict": 200})
            self.record("evidence", it["id"], rec, {"prompt_text": it["prompt"]})

    def structured(self):
        d = json.loads((PROMPTS / "structured.json").read_text())
        schema = IncidentDiagnosis.model_json_schema()
        for mode in ("prompt", "constrained"):
            for it in d["items"]:
                msg = [{"role": "user", "content": d["instruction"] + it["facts"]}]
                rec = self.chat(msg, fmt=schema if mode == "constrained" else None,
                                options={"num_predict": 320})
                self.record(f"structured_{mode}", it["id"], rec, {"mode": mode})

    def tools(self, ids=None):
        d = json.loads((PROMPTS / "tool_tasks.json").read_text())
        if ids is not None:
            d["items"] = [it for it in d["items"] if it["id"] in ids]
        if "tools" not in self.caps:
            for it in d["items"]:
                self.record("tools", it["id"], {"status": "unsupported",
                            "error": "model does not advertise the 'tools' capability"})
            return
        for it in d["items"]:
            msg = [{"role": "system", "content": d["system"]}, {"role": "user", "content": it["prompt"]}]
            rec = self.chat(msg, tools=TOOLS, options={"num_predict": 256})
            self.record("tools", it["id"], rec)

    def agent(self, ids=None):
        d = json.loads((PROMPTS / "agent_scenarios.json").read_text())
        if ids is not None:
            d["scenarios"] = [sc for sc in d["scenarios"] if sc["id"] in ids]
        if "tools" not in self.caps:
            for sc in d["scenarios"]:
                self.record("agent", sc["id"], {"status": "unsupported",
                            "error": "model does not advertise the 'tools' capability"})
            return
        for sc in d["scenarios"]:
            msgs = [{"role": "system", "content": d["system"]}, {"role": "user", "content": sc["incident"]}]
            trace, turns, t0, status, final = [], [], time.perf_counter(), "ok", ""
            for step in range(d["max_tool_calls"] + 1):
                rec = self.chat(msgs, tools=TOOLS, options={"num_predict": 320})
                turns.append({k: rec.get(k) for k in ("status", "wall_s", "prompt_tokens", "output_tokens",
                              "tokens_per_s", "prompt_tokens_per_s", "peak_runner_rss_mib",
                              "min_mem_available_mib", "ttft_s", "system_cpu_pct_mean")})
                if rec["status"] != "ok":
                    status = rec["status"]
                    break
                if not rec["tool_calls"]:
                    final = rec["content"]
                    break
                if step == d["max_tool_calls"]:
                    status = "step_budget_exhausted"
                    break
                call = rec["tool_calls"][0]["function"]
                name, args = call.get("name"), call.get("arguments")
                result = sc["tools"].get(name, {"error": f"unknown tool '{name}'"})
                trace.append({"name": name, "arguments": args, "n_parallel_calls": len(rec["tool_calls"])})
                msgs.append({"role": "assistant", "content": rec["content"],
                             "tool_calls": [rec["tool_calls"][0]]})
                msgs.append({"role": "tool", "tool_name": name, "content": json.dumps(result)})
            agg = {
                "status": status, "wall_s": round(time.perf_counter() - t0, 2),
                "n_model_calls": len(turns), "tool_trace": trace, "final_content": final, "turns": turns,
                "peak_runner_rss_mib": max((t["peak_runner_rss_mib"] or 0) for t in turns),
                "min_mem_available_mib": min((t["min_mem_available_mib"] or 10**9) for t in turns),
                "output_tokens": sum((t["output_tokens"] or 0) for t in turns),
                "prompt_tokens": sum((t["prompt_tokens"] or 0) for t in turns),
                "tokens_per_s": None,
                "ram_floor_breached": status == "aborted_ram",
            }
            self.record("agent", sc["id"], agg)

    CONTEXT_Q = ("\n\nQuestion: In the log above, exactly one line reports a NETDEV WATCHDOG transmit queue "
                 "timeout. Which host reported it and at what timestamp? Answer on the first line as "
                 "'HOST=<host> TIME=<timestamp>', then name the two most frequent ERROR message types.")

    def _context_prompt(self, size, cpt, r):
        body, needle = build_context(size, cpt)
        return f"[run {r}] Below is a service log.\n\n{body}{self.CONTEXT_Q}", needle

    def calibrate_tokens(self):
        """Measure this model's chars/token on the synthetic log (one short prefill)."""
        text, _ = self._context_prompt(1024, 2.0, 9)
        rec = self.chat([{"role": "user", "content": text}], options={"num_ctx": 8192, "num_predict": 1})
        cpt = len(text) / rec["prompt_tokens"]
        self.record("context_calibration", "cpt", rec, {"chars": len(text), "chars_per_token": round(cpt, 4)})
        return cpt

    def context(self, sizes=(1024, 2048, 4096, 8192), reps=2):
        cpt = self.calibrate_tokens()
        for size in sizes:
            num_ctx = size + 1024
            for r in range(reps):
                text, needle = self._context_prompt(size, cpt, r)
                rec = self.chat([{"role": "user", "content": text}],
                                options={"num_ctx": num_ctx, "num_predict": 128}, timeout=CONTEXT_TIMEOUT_S)
                pt = rec.get("prompt_tokens") or 0
                self.record("context", f"ctx{size}#r{r}", rec,
                            {"nominal_tokens": size, "num_ctx": num_ctx, "rep": r, "needle": needle,
                             "chars_per_token": round(cpt, 4),
                             "truncated_or_short": bool(pt and (pt < 0.85 * size or pt + 128 > num_ctx))})

    SUITES = ("generation", "knowledge", "evidence", "structured", "tools", "agent", "context")

    def slice(self):
        """Fixed validation slice (prompts/validation_slice.json), tagged slice=true."""
        if "tools" not in self.caps:
            return
        self.tag = {"slice": True}
        try:
            self.tools(SLICE["tool_selection"] + SLICE["tool_arguments"])
            self.agent(SLICE["agent_single_step"] + SLICE["agent_two_step"])
        finally:
            self.tag = {}

    def run(self, suites):
        print(f"== {self.model} digest={self.digest} caps={self.caps}", flush=True)
        self.warmup()
        print(f"   think mode = {self.think}", flush=True)
        try:
            for s in suites:
                if s == "slice":
                    self.slice()
                    continue
                getattr(self, s)()
                self.completed.append(s)
        except EarlyStop as e:
            print(f"EARLY STOP {self.model}: {e}", flush=True)
            ran_tools = any(x in self.completed for x in ("tools", "agent"))
            if not ran_tools:
                print("   running validation slice before stopping", flush=True)
                self.slice()
            write_early_stop(self.model, trigger=str(e), decided_by="automatic (pre-registered ES rules)",
                             planned=list(suites))
        finally:
            unload(self.model)


def suite_stats(model_dir):
    out = {}
    for f in sorted(model_dir.glob("*.jsonl")):
        rows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
        rows_full = [r for r in rows if not r.get("slice")]
        rows_slice = [r for r in rows if r.get("slice")]
        for label, rs in (("full", rows_full), ("slice", rows_slice)):
            if not rs:
                continue
            walls = sorted(r.get("wall_s") or 0 for r in rs)
            tps = sorted(r["tokens_per_s"] for r in rs if r.get("tokens_per_s"))
            out[f"{f.stem}" + ("" if label == "full" else "[slice]")] = {
                "n": len(rs), "ok": sum(r.get("status") == "ok" for r in rs),
                "usable_output": sum(not incomplete(r) for r in rs),
                "hit_token_budget": sum(r.get("done_reason") == "length" for r in rs),
                "median_wall_s": walls[len(walls) // 2],
                "median_tok_s": tps[len(tps) // 2] if tps else None,
                "peak_runner_rss_mib": max((r.get("peak_runner_rss_mib") or 0) for r in rs)}
    return out


def write_early_stop(model, trigger, decided_by, planned=None):
    md = RUNS / model.replace(":", "_").replace("/", "_")
    stats = suite_stats(md)
    w = json.loads((md / "warmup.jsonl").read_text().splitlines()[-1])
    expected = {"generation": 15, "knowledge": 10, "evidence": 8, "structured_prompt": 30,
                "structured_constrained": 30, "tools": 28, "agent": 12, "context": 8}
    suites = {}
    for k, n in expected.items():
        got = stats.get(k, {}).get("n", 0)
        suites[k] = "COMPLETE" if got >= n else (f"PARTIAL {got}/{n} — remainder {NOT_RUN}" if got else NOT_RUN)
    rec = {"model": model, "digest": w.get("model_digest"), "ollama_version": w.get("ollama_version"),
           "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
           "trigger": trigger, "decided_by": decided_by,
           "config": {"num_ctx": DEFAULT_CTX, "temperature": BASE_OPTIONS["temperature"], "seed": BASE_OPTIONS["seed"],
                      "think": w.get("think"), "think_probe": w.get("think_probe"),
                      "think_budget_extra_tokens": THINK_BUDGET if w.get("think") else 0,
                      "num_predict": {"generation": 384, "knowledge": 256, "evidence": 200, "structured": 320,
                                      "tools": 256, "agent_turn": 320, "context": 128},
                      "ollama_service_env": w.get("ollama_service_env")},
           "suite_status": suites, "suite_stats": stats}
    (md / "early_stop.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(json.dumps({"early_stop": model, "suite_status": suites}, indent=2), flush=True)


# --------------------------------------------------------------------- context
SERVICES = ["api", "auth", "payments", "search", "orders", "inventory", "gateway", "profile"]
HOSTS = [f"worker-{i}" for i in range(1, 9)]
ERRORS = ["upstream connect timeout", "connection reset by peer", "deadline exceeded calling inventory",
          "db pool exhausted", "TLS handshake timeout"]
INFOS = ["request completed status=200", "cache hit ratio=0.93", "health check ok", "config reloaded",
         "batch committed rows=500", "gc pause 12ms"]


def build_context(target_tokens, chars_per_token):
    """Deterministic synthetic log of ~target_tokens (total prompt) with one planted needle at 60% depth."""
    rng = random.Random(1000 + target_tokens)
    lines, n_chars, t = [], 0, dt.datetime(2026, 10, 2, 14, 0, 0)
    target_chars = int((target_tokens - 110) * chars_per_token)
    while n_chars < target_chars:
        t += dt.timedelta(milliseconds=rng.randint(50, 900))
        lvl = rng.choices(["INFO", "WARN", "ERROR"], [0.75, 0.15, 0.10])[0]
        msg = rng.choice(ERRORS if lvl == "ERROR" else INFOS if lvl == "INFO" else
                         ["slow request 840ms", "retrying request attempt=2", "queue depth 120"])
        line = f"{t.isoformat(timespec='milliseconds')}Z {rng.choice(HOSTS)} {rng.choice(SERVICES)} {lvl} {msg}"
        lines.append(line)
        n_chars += len(line) + 1
    pos = int(len(lines) * 0.6)
    nt = lines[pos].split("Z ")[0] + "Z"
    needle = {"host": "worker-7", "time": nt}
    lines.insert(pos, f"{nt} worker-7 kernel ERROR NETDEV WATCHDOG: eth0 (ixgbe): transmit queue 2 timed out")
    return "\n".join(lines), needle


# ------------------------------------------------------------------ downloads
def disk_free_gib():
    return shutil.disk_usage("/").free / GIB


def registry_size(model):
    name, tag = model.split(":")
    r = httpx.get(f"https://registry.ollama.ai/v2/library/{name}/manifests/{tag}",
                  headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"}, timeout=30)
    r.raise_for_status()
    return sum(l["size"] for l in r.json()["layers"])


def runtime_compat(model):
    """Compare the registry config's 'requires' field (minimum Ollama version) to the installed one."""
    name, tag = model.split(":")
    hdr = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
    installed = ollama_version()
    try:
        man = httpx.get(f"https://registry.ollama.ai/v2/library/{name}/manifests/{tag}", headers=hdr, timeout=30).json()
        cfg = httpx.get(f"https://registry.ollama.ai/v2/library/{name}/blobs/{man['config']['digest']}",
                        timeout=30, follow_redirects=True).json()
    except Exception as e:  # noqa: BLE001
        return {"installed": installed, "requires": None, "compatible": None, "note": f"config unreadable: {e}"}
    req = cfg.get("requires")
    v = lambda x: tuple(int(p) for p in re.findall(r"\d+", x)[:3])
    return {"installed": installed, "requires": req, "model_type": cfg.get("model_type"),
            "file_type": cfg.get("file_type"), "renderer": cfg.get("renderer"),
            "compatible": True if req is None else v(installed) >= v(req)}


def pull(model):
    have = {m["name"] for m in httpx.get(f"{OLLAMA}/api/tags").json()["models"]}
    entry = {"model": model, "ollama_tag": model}
    if model not in have:
        compat = runtime_compat(model)
        print(f"compat {model}: {compat}", flush=True)
        if compat["compatible"] is False:
            raise SystemExit(f"STOP: {model} requires Ollama >= {compat['requires']} (installed "
                             f"{compat['installed']}). Not upgrading without approval.")
        entry["runtime_compat"] = compat
        expected = registry_size(model)
        before = {"disk_free_gib": round(disk_free_gib(), 2),
                  "mem_available_mib": round(psutil.virtual_memory().available / 2**20)}
        print(f"pull {model}: expected {expected/1e9:.3f} GB, before={before}", flush=True)
        if disk_free_gib() - expected / GIB < MIN_DISK_GIB:
            raise SystemExit(f"REFUSED: pulling {model} would drop free disk below {MIN_DISK_GIB} GiB")
        t0 = time.time()
        r = subprocess.run(["ollama", "pull", model], capture_output=True, text=True, timeout=7200)
        if r.returncode != 0:
            raise SystemExit(f"PULL FAILED {model}: rc={r.returncode} {r.stderr[-500:]}")
        after = {"disk_free_gib": round(disk_free_gib(), 2),
                 "mem_available_mib": round(psutil.virtual_memory().available / 2**20)}
        entry.update({"expected_size_bytes": expected, "before": before, "after": after,
                      "download_seconds": round(time.time() - t0), "downloaded_in_phase": "1B",
                      "download_date": dt.date.today().isoformat()})
        print(f"pull {model}: done after={after}", flush=True)
    else:
        entry.update({"downloaded_in_phase": "pre-existing"})
    tag = next(m for m in httpx.get(f"{OLLAMA}/api/tags").json()["models"] if m["name"] == model)
    info = show(model)
    entry.update({"digest": tag["digest"], "size_bytes": tag["size"], "modified_at": tag["modified_at"],
                  "details": tag["details"], "capabilities": info.get("capabilities"),
                  "license_first_line": (info.get("license") or "").strip().splitlines()[0] if info.get("license") else None,
                  "ollama_version": ollama_version()})
    man = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"models": {}}
    prev = man["models"].get(model, {})
    for k in ("before", "after", "expected_size_bytes", "download_seconds", "download_date", "runtime_compat"):
        if k in prev and k not in entry:
            entry[k] = prev[k]
    if prev.get("downloaded_in_phase") == "1B":   # never downgrade a recorded Phase 1B download
        entry["downloaded_in_phase"] = "1B"
    man["models"][model] = entry
    MANIFEST.write_text(json.dumps(man, indent=2) + "\n")
    if disk_free_gib() < MIN_DISK_GIB:
        raise SystemExit(f"STOP: free disk {disk_free_gib():.1f} GiB < {MIN_DISK_GIB} GiB")
    return entry


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pull"); p.add_argument("--model", required=True)
    r = sub.add_parser("run"); r.add_argument("--model", required=True); r.add_argument("--suites", default="all")
    c = sub.add_parser("campaign"); c.add_argument("--models", required=True); c.add_argument("--suites", default="all")
    e = sub.add_parser("early-stop"); e.add_argument("--model", required=True)
    e.add_argument("--trigger", required=True); e.add_argument("--decided-by", required=True)
    a = ap.parse_args()

    if a.cmd == "early-stop":
        write_early_stop(a.model, a.trigger, a.decided_by)
        return

    if a.cmd == "pull":
        print(json.dumps(pull(a.model), indent=2))
        return
    suites = Run.SUITES if a.suites == "all" else tuple(a.suites.split(","))
    models = [a.model] if a.cmd == "run" else a.models.split(",")
    for m in models:
        wait_for_ollama()
        if a.cmd == "campaign":
            pull(m)
        try:
            Run(m).run(suites)
        except RamFloorBreached as e:
            print(f"ABORT: {e}", flush=True)
            unload_all_except(None)
            raise SystemExit(3)
    print("campaign complete", flush=True)


if __name__ == "__main__":
    main()
