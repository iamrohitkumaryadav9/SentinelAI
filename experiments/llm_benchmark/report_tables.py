#!/usr/bin/env python3
"""Render Markdown tables for PHASE_1B_EVALUATION.md from results/summary.json + model_manifest.json.

Every number in the evaluation's result tables comes from this script (no hand copying).
Output: results/report_tables.md
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
S = json.loads((HERE / "results" / "summary.json").read_text())
MAN = json.loads((HERE / "model_manifest.json").read_text())["models"]
MODELS = S["models"]


def cov(m, suite):
    return m["coverage"][suite]


def ran(m, suite):
    return not cov(m, suite).startswith("0/")


def v(m, suite, fn, fmt="{}"):
    if not ran(m, suite):
        return "NOT RUN"
    if suite in ("tools", "agent") and not m[suite].get("supported", True):
        return "unsupported"
    try:
        x = fn(m)
    except (KeyError, TypeError):
        return "—"
    return "—" if x is None else fmt.format(x)


pct = "{:.0%}"
f2 = "{:.2f}"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


sections = []

# Models + digests
rows = []
for m in MODELS:
    e = MAN.get(m["model"], {})
    d = e.get("details", {})
    rows.append([m["model"], f"`{e.get('digest', '?')}`", f"{e.get('size_bytes', 0) / 1e9:.2f} GB",
                 d.get("parameter_size"), d.get("quantization_level"), e.get("downloaded_in_phase"),
                 e.get("download_date", "pre-existing"), ", ".join(e.get("capabilities") or []),
                 e.get("license_first_line") or "—"])
sections.append("### Models and digests\n\n" + table(
    ["Model", "Digest (sha256)", "Size", "Params", "Quant", "Downloaded", "Date", "Capabilities", "License"], rows))

# Coverage / early stop
rows = []
for m in MODELS:
    es = m.get("early_stop")
    rows.append([m["model"], m["think"] if "think" in m else "—"] + [cov(m, s) for s in
                ("generation", "knowledge", "evidence", "structured_prompt", "structured_constrained", "tools", "agent", "context")]
                + [("**" + es["decided_by"].split(" ")[0] + "**: " + es["trigger"][:90]) if es else "—"])
sections.append("### Coverage and early stops\n\n" + table(
    ["Model", "think", "gen", "know", "evid", "struct-prompt", "struct-constr", "tools", "agent", "context", "Early stop"], rows))

# Performance
rows = []
for m in MODELS:
    p = m["perf"]
    rows.append([m["model"], p["gen_tok_s_median"], f"{p['gen_tok_s_min']}–{p['gen_tok_s_max']}", p["prompt_tok_s_median"],
                 p["ttft_s_median"], p["wall_s_median_generation"], p["output_tokens_median_generation"],
                 p["agent_turn_wall_s_median"], f"{p['peak_runner_rss_mib_4k'] / 1024:.2f}",
                 f"{p['min_mem_available_mib'] / 1024:.2f}", p["system_cpu_pct_mean_generation"],
                 p["runner_cpu_pct_mean_generation"], m["load_duration_s"],
                 f"{m['stability']['failed']}/{m['stability']['requests']}"])
sections.append("### Performance (4K-context suites; medians)\n\n" + table(
    ["Model", "Gen tok/s", "Gen tok/s range", "Prompt tok/s", "TTFT s", "Gen wall s", "Gen out tok",
     "Agent turn s", "Peak RSS GiB", "Min MemAvail GiB", "Sys CPU % (mean)", "Runner CPU %", "Load s",
     "Failed/requests"], rows))

# Tools
rows = []
for m in MODELS:
    t = m["tools"]
    rows.append([m["model"]] + [v(m, "tools", lambda m, k=k: m["tools"][k], fm) for k, fm in
                 (("tool_call_success_rate", pct), ("argument_validity", pct), ("wrong_tool_rate", pct),
                  ("missing_tool_call_rate", pct), ("hallucinated_tool_rate", pct), ("no_tool_correct_rate", pct),
                  ("norm", f2))])
    sl = (m.get("validation_slice") or {}).get("tools")
    if sl:
        rows.append([m["model"] + " *(slice, n=10)*"] + [pct.format(sl[k]) if k != "norm" else f2.format(sl[k]) for k in
                     ("tool_call_success_rate", "argument_validity", "wrong_tool_rate", "missing_tool_call_rate",
                      "hallucinated_tool_rate")] + ["—", f2.format(sl["norm"])])
sections.append("### Tool calling (25 tool tasks + 3 no-tool tasks)\n\n" + table(
    ["Model", "Success (score 2)", "Arg validity", "Wrong tool", "Missing call", "Hallucinated tool",
     "No-tool correct", "Norm score"], rows))

# Structured
rows = []
for m in MODELS:
    for mode in ("prompt", "constrained"):
        k = f"structured_{mode}"
        rows.append([m["model"], mode] + [v(m, k, lambda m, f=f: m[k][f], pct) for f in
                     ("valid_json_rate", "schema_valid_rate", "missing_field_rate", "extra_field_rate",
                      "parse_failure_rate", "markdown_fenced_rate", "lenient_schema_valid_rate", "semantic_correct_rate")])
sections.append("### Structured output (30 incidents per mode; Pydantic strict, extra=forbid)\n\n" + table(
    ["Model", "Mode", "Valid JSON", "Schema valid", "Missing field", "Extra field", "Parse failure",
     "Markdown fenced", "Valid after fence-strip", "Semantically correct"], rows))

# Agent
rows = []
for m in MODELS:
    rows.append([m["model"]] + [v(m, "agent", lambda m, k=k: m["agent"][k], fm) for k, fm in
                 (("success_rate", pct), ("multi_step_success_rate", pct), ("confident_wrong", "{}"),
                  ("no_diagnosis", "{}"), ("overcautious", "{}"), ("ambiguous_correct", "{}"),
                  ("mean_tool_calls", "{}"), ("median_scenario_wall_s", "{}"), ("hallucinated_calls", "{}"),
                  ("invalid_arg_calls", "{}"), ("norm", f2))] + [cov(m, "agent")])
    sl = (m.get("validation_slice") or {}).get("agent")
    if sl:
        rows.append([m["model"] + " *(slice, n=5)*", pct.format(sl["success_rate"]), pct.format(sl["multi_step_success_rate"]),
                     sl["confident_wrong"], sl["no_diagnosis"], sl["overcautious"], "—", sl["mean_tool_calls"],
                     sl["median_scenario_wall_s"], sl["hallucinated_calls"], sl["invalid_arg_calls"], f2.format(sl["norm"]), "5/5"])
sections.append("### Agent loop (12 scenarios, ≤6 tool calls; 3 ambiguous)\n\n" + table(
    ["Model", "Success", "Multi-step success", "Confident wrong", "No diagnosis", "Over-cautious",
     "Ambiguous correct (of 3)", "Mean tool calls", "Median scenario s", "Hallucinated calls", "Invalid-arg calls",
     "Norm", "Coverage"], rows))

# Evidence
rows = []
for m in MODELS:
    rows.append([m["model"]] + [v(m, "evidence", lambda m, k=k: m["evidence"][k], fm) for k, fm in
                 (("abstention_rate", pct), ("unsupported_claim_rate", pct), ("control_correct", "{}/2"),
                  ("control_overcautious", "{}"), ("format_ok", "{}/8"), ("fabricated_number_responses", "{}/8"),
                  ("norm", f2))])
sections.append("### Evidence discipline (6 insufficient-evidence + 2 sufficient controls)\n\n" + table(
    ["Model", "Abstained (insufficient)", "Unsupported root cause", "Controls correct", "Controls over-cautious",
     "Format followed", "Unprompted numbers (heuristic)", "Norm"], rows))

# Knowledge / generation
rows = [[m["model"], v(m, "knowledge", lambda m: m["knowledge"]["mean"], f2), v(m, "knowledge", lambda m: m["knowledge"]["norm"], f2),
         v(m, "generation", lambda m: m["generation"]["mean"], f2), v(m, "generation", lambda m: m["generation"]["norm"], f2)]
        for m in MODELS]
sections.append("### Technical knowledge (10) and generation (5×3)\n\n" + table(
    ["Model", "Knowledge mean (0–2)", "Knowledge norm", "Generation mean (0–2)", "Generation norm"], rows))

# Context
rows = []
for m in MODELS:
    if not m["context"]:
        rows.append([m["model"], "NOT RUN"] + [""] * 9)
        continue
    for size, c in m["context"].items():
        rows.append([m["model"], size, c["prompt_tokens"], c["num_ctx"] if "num_ctx" in c else c["runs"][0]["num_ctx"],
                     c["prompt_tok_s"], c["ttft_s"], c["wall_s"], c["gen_tok_s"], f"{c['peak_rss_mib'] / 1024:.2f}",
                     f"{c['needle_mean']}/2", f"{c['failures']} / trunc={c['truncated_any']}"])
sections.append("### Context scaling (2 reps per size; medians)\n\n" + table(
    ["Model", "Nominal", "Actual prompt tok", "num_ctx", "Prompt tok/s", "TTFT s", "Wall s", "Gen tok/s",
     "Peak RSS GiB", "Needle (0–2)", "Failures / truncated"], rows))

# Gates + Q
rows = []
for m in MODELS:
    g = m["gates"]
    rows.append([m["model"]] + ["✅" if g.get(k) else "❌" for k in
                 ("G1_stability", "G2_memory", "G3_speed", "G4_tools", "G5_structured", "G6_evidence")]
                + ["❌" if m.get("early_stop") else "✅", m["Q"], "**yes**" if m["eligible"] else "no"])
sections.append("### Gates and quality score\n\n" + table(
    ["Model", "G1 stability", "G2 memory", "G3 speed", "G4 tools", "G5 structured", "G6 evidence",
     "Not early-stopped", "Q", "Eligible"], rows))
rows = [[m["model"]] + [f2.format(m["quality_components"][k]) for k in
        ("agent", "tools", "evidence", "structured", "knowledge", "generation")] + [m["Q"]] for m in MODELS]
sections.append("### Q components (normalised 0–1; weights " + json.dumps(S["weights"]) + ")\n\n" + table(
    ["Model", "Agent", "Tools", "Evidence", "Structured (constr.)", "Knowledge", "Generation", "Q"], rows))
sections.append("### Decision (score.py)\n\n```json\n" + json.dumps(S["decision"], indent=2) + "\n```")

out = "\n\n".join(sections) + "\n"
(HERE / "results" / "report_tables.md").write_text(out)
print(out)
