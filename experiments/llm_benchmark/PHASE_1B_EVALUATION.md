# Phase 1B Evaluation: Local LLM Laboratory and Primary Model Selection

| Field | Value |
|---|---|
| Date | 2026-10-02, 13:56–18:50 IST |
| Host | iiitd-Precision-3660: i7-13700 (16C/24T), 15.3 GiB RAM, CPU-only, Ubuntu 22.04.5, kernel 6.8.0-138 |
| Runtime | Ollama 0.35.0 (local, 127.0.0.1:11434), inference through the bundled `llama-server` |
| Harness | `experiments/llm_benchmark/` (`benchmark.py`, `score.py`, `report_tables.py`, `measure_load.py`) |
| Raw data | `experiments/llm_benchmark/results/runs/<model>/*.jsonl` (one JSON record per request) |
| Derived | `results/summary.json`, `summary.csv`, `item_scores.csv`, `report_tables.md`, `cold_load.json` |
| Cloud / API keys | None used |

---

## 1. Objective

Find, by measurement, the local generative model configuration best suited to SentinelAI on this machine. The model must handle instruction following, reasoning, tool calling, structured output, technical context and agent loops, at acceptable CPU latency and RAM. The aim is the best measured trade-off, not the largest model.

## 2. Models tested

| Model | Params (reported) | Quant | Thinking mode used | Coverage | Outcome |
|---|---|---|---|---|---|
| gemma3:1b | 1.0B | Q4_K_M | n/a (no thinking capability) | all 8 suites | Baseline. No `tools` capability. |
| qwen3:4b | 4.0B (**Qwen3-4B-Thinking-2507**) | Q4_K_M | `think=true` + 1,024-token allowance (thinking-only model) | gen, know, evid complete; struct-prompt 14/30; validation slice | **Early-stopped (reviewer)**: no answer within budget |
| qwen3.5:4b | 4.7B | Q4_K_M | `think=false` (probe: direct answer) | all except agent 5/12 and context | **Early-stopped (ES1, automatic)**: never concluded an agent loop |
| qwen3:8b | 8.2B | Q4_K_M | `think=false` | all 8 suites | Eligible |
| qwen3.5:9b | 9.7B | Q4_K_M | `think=false` | all 8 suites | Eligible |

No 12B+ model was downloaded, and models were downloaded one at a time.

## 3. Exact model digests

The source of truth is `experiments/llm_benchmark/model_manifest.json`.

| Model | Digest (sha256) | Size | Downloaded | Disk free before → after | Licence |
|---|---|---|---|---|---|
| gemma3:1b | `8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc` | 0.82 GB | pre-existing | — | Gemma Terms of Use |
| qwen3:4b | `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7` | 2.50 GB | 2026-10-02 (32 s) | 139.31 → 136.99 GiB | Apache-2.0 |
| qwen3.5:4b | `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd` | 3.39 GB | 2026-10-02 (40 s) | 136.97 → 133.81 GiB | Apache-2.0 |
| qwen3:8b | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` | 5.23 GB | 2026-10-02 (resumed; 31 s) | 130.75 → 128.10 GiB ¹ | Apache-2.0 |
| qwen3.5:9b | `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7` | 6.59 GB | 2026-10-02 (65 s) | 128.08 → 121.94 GiB | Apache-2.0 |

¹ The first qwen3:8b download was interrupted when I stopped the campaign to investigate qwen3.5:4b (§16). Ollama resumed it from the partial blobs, so the "before" figure already excludes about 2 GiB.

**Compatibility.** Before every download, the registry config's `requires` field was compared with the installed Ollama. qwen3.5 requires ≥ 0.17.1 and qwen3 has no minimum; 0.35.0 satisfies both. **No upgrade was needed or performed.** Free disk went from 140 GiB to **122 GiB**, never near the 80 GiB floor.

## 4. Hardware and environment (per run)

- CPU, kernel, RAM, Ollama version and model digest are recorded **in every raw record**.
- **The desktop state was recorded at each model's warm-up.** During every valid run Chrome was **closed (0 MiB)**. VS Code server was at 0.6–1.8 GiB, Claude Code at 0.7–1.1 GiB, and gnome-shell at 0.1–0.15 GiB. I closed no applications myself.
- **The Ollama service runs with the drop-in** `/etc/systemd/system/ollama.service.d/10-sentinelai-no-prompt-cache.conf`, which sets `LLAMA_ARG_CACHE_RAM=0` (deviation D2). Every warm-up record confirms it.
- **Threads.** `llama-server` used about **800 % CPU**, roughly 8 compute threads, for every model. That is consistent with the runtime's default of one thread per P-core. System-wide CPU was about 34 % of 24 logical CPUs, leaving the E-cores mostly idle. Affinity and governor were **not changed**, so this is the natural baseline.
- **Swap.** Usage climbed during the run (884 → 1,554 → 2,048 of 2,048 MiB) as idle desktop processes were paged out. Swap was **full** when qwen3.5:9b started. Afterwards, 14.0 GiB was available with nothing loaded and memory PSI was about 0. The 2 GiB `MemAvailable` floor was **never** breached; the lowest value seen was 6.15 GiB.

## 5. Benchmark methodology

**Fixed settings** (identical for all models):
- `temperature=0`, `seed=42`, `num_ctx=4096`; other sampling parameters are the model defaults.
- `num_predict` per suite: generation 384, knowledge 256, evidence 200, structured 320, tools 256, agent turn 320, context 128.
- A per-request timeout of 300 s (900 s for the context suite).
- **One resident model at a time:** others were unloaded before warm-up, and `other_models_resident` was recorded on every request. It was empty throughout.

**Timing.** All timings come from Ollama's own fields (`load_duration`, `prompt_eval_duration`, `eval_duration`, `total_duration`, plus the token counts). TTFT is measured by the client from the streamed response. Peak runner RSS, minimum `MemAvailable` and CPU % are sampled every 200 ms by a background thread.

**Selection criterion.** Pre-registered in `experiments/llm_benchmark/README.md` and committed (`3ec3cab`) **before any candidate ran**:
- six hard gates, G1–G6;
- a quality score Q (weights: agent 0.30, tools 0.25, evidence 0.15, structured-constrained 0.15, knowledge 0.10, generation 0.05);
- a latency tie-break (within 0.05 Q *and* at least 1.5× faster agent loop);
- a secondary choice (the fastest other eligible model with Q ≥ 0.8 × primary).

The early-stop rules ES1–ES3 were pre-registered (`678d447`) before qwen3.5:4b, qwen3:8b and qwen3.5:9b ran.

**Scoring** is deterministic, with no LLM judge: each item scores 0, 1 or 2 under a rubric stored in its dataset. Strict Pydantic (`extra="forbid"`) validates tool arguments and structured output. Per-item scores, with the reason for each, are in `results/item_scores.csv`.

### Protocol deviations (all recorded and committed)

| ID | Deviation | Why | Effect on fairness |
|---|---|---|---|
| D1 | **Thinking mode chosen by probe.** If `think=false` yields a direct answer to "17×3", the model runs without thinking; otherwise it runs with `think=true` + 1,024 extra tokens | The `qwen3:4b` tag is Qwen3-4B-Thinking-2507, so `think=false` only moved its reasoning into `content`. The first qwen3:4b data is quarantined in `runs_invalid/qwen3_4b_think_false_ineffective/`. | Same rule for every model. Only qwen3:4b ended up in thinking mode. |
| D2 | **llama-server prompt RAM cache disabled** (`LLAMA_ARG_CACHE_RAM=0`) | The default 8 GiB cache inflated runner RSS (qwen3:4b reached 8.0 GiB; the log showed `cache state: 37 prompts, 5141 MiB`) and threatened the RAM floor | **All models were re-run from scratch** under this setting. Earlier runs are in `runs_invalid/cache_ram_8192/`. |
| D3 | qwen3:4b **early-stopped by reviewer decision** plus a validation slice | Objective evidence (§16). The ES rules did not exist yet. | Same slice as defined for every later early stop. Labelled `decided_by: reviewer`. |
| D4 | Early-stop rules ES1–ES3 added mid-phase | Your instruction | Pre-registered before the three remaining models ran |
| D5 | Rubric revision R1: more abstention phrasings | My scorer missed "data collection is required to determine the cause" | Applied using **baseline (gemma) data only**, before any candidate ran |
| D6 | Context-suite tokenizer calibration | A smoke test showed my chars-per-token guess silently truncated the 4K/8K prompts | Fixed before any recorded data. Truncation is now flagged per run (none occurred). |
| D7 | Harness hardening: restart tolerance, fixed fenced-rate counter | A service restart interrupted a run, now quarantined in `runs_invalid/interrupted_by_ollama_restart/`. The counter missed trailing fences. | No score changed |

## 6. Prompt dataset

All datasets are in `experiments/llm_benchmark/prompts/`, each with its rubric in `_rubric`.

| Suite | File | Items | Gold standard |
|---|---|---|---|
| Generation | `generation.json` | 5 prompts × 3 reps (simple reasoning, systems reasoning, debugging, code bug, structured analysis) | Concept groups |
| Knowledge | `knowledge.json` | 10 (sched_switch, softirq, net→sched latency, CPU throttling, cgroup, TCP retransmission, p99, PSI, tracepoint vs kprobe, K8s requests/limits) | Concept groups |
| Evidence | `evidence.json` | 6 insufficient-evidence + 2 sufficient controls | Abstain plus required-evidence groups / correct cause |
| Structured | `structured.json` | 30 incidents (4 for each of 6 fault types + 6 insufficient), run in two modes | Incident type plus severity range |
| Tools | `tool_tasks.json` + `schemas/tools.json` | 25 tool tasks + 3 no-tool tasks; 5 tools with strict schemas | Expected tool, acceptable alternatives, expected arguments |
| Agent | `agent_scenarios.json` | 12 scenarios (9 faults + 3 ambiguous), deterministic synthetic tool results, ≤ 6 tool calls | Label, plus the required evidence tool |
| Context | generated (`build_context`) | 1K/2K/4K/8K-token synthetic logs × 2 reps, one planted needle | Needle host and timestamp |
| Validation slice | `validation_slice.json` | 5 tool-selection + 5 tool-argument tasks + 3 single-step + 2 two-step agent scenarios | Same as the full suites |

## 7. Tool-calling results

| Model | Success (score 2) | Arg validity | Wrong tool | Missing call | Invented tool | No-tool correct |
|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | — | — | — | — | — |
| qwen3:4b (slice, n=10) | 40 % | 100 % | 0 % | **50 %** | 0 % | — |
| qwen3.5:4b | **100 %** (25/25) | 100 % | 0 % | 0 % | 0 % | 3/3 |
| qwen3:8b | 96 % (24/25) | 100 % | 0 % | 4 % (T01) | 0 % | 3/3 |
| qwen3.5:9b | **100 %** (25/25) | 100 % | 0 % | 0 % | 0 % | 3/3 |

qwen3:4b's 5 misses were all budget exhaustion: about 5,500 characters of thinking and 73 s, with no call emitted. Every call it did emit was valid.

## 8. Structured-output results

30 incidents per mode, validated with strict Pydantic.

| Model | Prompt-only: schema-valid | Prompt-only: fenced | Constrained (`format=schema`): schema-valid | Constrained: semantically correct |
|---|---|---|---|---|
| gemma3:1b | 0 % | 100 % (80 % valid after stripping) | 100 % | 40 % |
| qwen3:4b | 0 % (14/14 hit the budget, no output) | 0 % | NOT RUN | NOT RUN |
| qwen3.5:4b | 60 % | 40 % (trailing ```` ``` ````; 93 % valid after stripping) | 100 % | 80 % |
| qwen3:8b | **100 %** | 0 % | 100 % | **80 %** |
| qwen3.5:9b | **100 %** | 0 % | 100 % | 70 % |

There were no missing or extra fields in any model's parsed output. **Constrained decoding makes JSON validity a non-issue (100 % for every model that ran it). Semantic correctness is the real differentiator.** qwen3.5:9b's 9 semantic misses were 5 severity over-estimates and 4 type errors, 3 of which labelled TCP retransmissions as `network_packet_loss`.

## 9. Technical reasoning results

| Model | Knowledge (0–2) | Generation (0–2) | Notes |
|---|---|---|---|
| gemma3:1b | 1.10 | 0.80 | Factual errors I checked by hand: called softirq "a scheduler"; "p99 = 99 ms… in video games"; missed the mutable-default bug |
| qwen3:4b | **1.80** | 0.13 | Knows the material (short answers), but 12/15 generation prompts hit the budget with no answer |
| qwen3.5:4b | 1.60 | **1.67** | — |
| qwen3:8b | 1.70 | 1.47 | — |
| qwen3.5:9b | **1.80** | 1.60 | — |

## 10. Evidence-discipline results

6 insufficient-evidence items and 2 controls.

| Model | Abstained when evidence insufficient | Asserted unsupported root cause | Controls correct | Format followed | Unprompted numbers (heuristic) |
|---|---|---|---|---|---|
| gemma3:1b | 1/6 | **5/6** | 2/2 | 8/8 | 1/8 |
| qwen3:4b | 1/6 | 5/6 ² | 0/2 | 1/8 | 0/8 |
| qwen3.5:4b | **6/6** | 0/6 | 1/2 (1 over-cautious) | 8/8 | 0/8 |
| qwen3:8b | **6/6** | 0/6 | 1/2 (1 over-cautious) | 8/8 | 0/8 |
| qwen3.5:9b | **6/6** | 0/6 | **2/2** | 8/8 | 0/8 |

² qwen3:4b's "assertions" are mostly budget exhaustion with no `ROOT_CAUSE` line, which the rubric scores as non-abstention. That reflects a failure to answer, not confident invention.

**The 1B baseline invents root causes in 5 of 6 under-determined incidents. That confirms a small model is unsafe as the reasoning core.** All three Qwen models with usable output abstained every time.

## 11. Agent-loop results

12 scenarios, at most 6 tool calls each.

| Model | Correct (score 2) | Confident wrong | No diagnosis | Ambiguous → INSUFFICIENT_EVIDENCE | Mean tool calls | Median scenario | Invalid / invented calls |
|---|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | — | — | — | — | — | — |
| qwen3:4b (slice, n=5) | 2/5 | 0 | **3/5** (budget exhausted on the first turn) | — | 0.4 | 78.9 s | 1 / 0 |
| qwen3.5:4b | **0/5** | 0 | **5/5** (6-call budget exhausted every time) | — | 6.0 | 30.7 s | 0 / 0 |
| qwen3:8b | **11/12 (92 %)** | 1 (S10 conntrack → `tcp_retransmissions`) | 0 | **3/3** | 3.75 | **28.1 s** | 0 / 0 |
| qwen3.5:9b | 10/12 (83 %) | 2 (S05, S11 TCP retx → `network_packet_loss`) | 0 | **3/3** | 2.67 | 39.3 s | 0 / 0 |

**qwen3.5:4b's failure is specifically non-termination.** Its single-step tool use was perfect (28/28), every agent call was valid with sensible arguments, and it saw the tool results. A replay test confirmed it correctly quoted `31.7` from a result. But it kept re-querying, including calling `run_experiment` after being told experiments were refused, and never declared a diagnosis within 6 calls. A controlled replay with three tool-message formats ruled out a harness or message-format bug.

**Multi-step success** means correct after 2 or more tool calls: qwen3:8b 92 %, qwen3.5:9b 83 %.

## 12. Context-scaling results

Medians of 2 reps. Token counts are actual, after per-model tokenizer calibration. No truncation and no failures occurred.

| Model | Size | Actual prompt tok | Prompt tok/s | TTFT | Total | Gen tok/s | Peak RSS | Needle (0–2) |
|---|---|---|---|---|---|---|---|---|
| qwen3:8b | 1K | 1,118 | 50.3 | 24.1 s | 29.3 s | 9.9 | 6.28 GiB | 2/2 |
| qwen3:8b | 2K | 2,227 | 48.5 | 47.8 s | 54.0 s | 9.4 | 5.48 GiB | 2/2 |
| qwen3:8b | 4K | 4,433 | 44.9 | **100.7 s** | 106.5 s | 7.3 | 5.86 GiB | 2/2 |
| qwen3:8b | 8K | 8,745 | 39.5 | **223.4 s** | 235.9 s | 5.1 | 6.43 GiB | 2/2 |
| qwen3.5:9b | 1K | 1,115 | 49.1 | 25.2 s | 29.9 s | 9.6 | 6.91 GiB | 2/2 |
| qwen3.5:9b | 2K | 2,224 | 48.9 | 47.9 s | 52.7 s | 9.5 | 6.67 GiB | 1/2 (wrong host) |
| qwen3.5:9b | 4K | 4,430 | 47.2 | **96.5 s** | 101.4 s | 9.0 | 6.82 GiB | 2/2 |
| qwen3.5:9b | 8K | 8,742 | 45.5 | **194.5 s** | 200.3 s | 8.2 | 6.96 GiB | 1/2 (wrong host) |
| gemma3:1b | 8K | 8,745 | 283.6 | 31.4 s | 31.7 s | 54.2 | 1.04 GiB | 0/2 |

**How much context can SentinelAI practically afford?** For 8–9B models, **fresh-prompt prefill costs about 45–50 tokens/s, so a 4K prompt has about 100 s TTFT and an 8K prompt about 200–225 s**. Memory and stability are fine at 8K; latency is the limit. The practical policy:
- at most **about 2K tokens of new context per agent turn** (≈ 50 s);
- **4K as the ceiling** for a one-off offline analysis;
- **8K is technically possible but impractical inside a loop.**

Agent turns are much cheaper than fresh prompts (median turn 5.0 s for qwen3:8b, 9.3 s for qwen3.5:9b, against cumulative prompts of about 2.5–5K tokens). That's because llama-server's in-slot KV cache reuses the shared prefix. Conversations should therefore grow incrementally rather than being rebuilt each turn.

qwen3.5:9b holds its decode speed better as context grows (8.2 tok/s at 8K, against qwen3:8b's 5.1), but its needle accuracy at 2K and 8K was lower: it named the wrong host in 4 of 8 runs.

## 13. Latency

All medians are from the 4K-context suites.

| Model | TTFT | Generation request (median 220–266 out tok) | Agent turn | Agent scenario | Cold load ³ |
|---|---|---|---|---|---|
| gemma3:1b | 0.29 s | 4.3 s | — | — | 1.08 s |
| qwen3:4b | 0.76 s | 77.1 s (1,408 tok, budget hit) | 77.8 s | 78.9 s (slice) | 2.04 s |
| qwen3.5:4b | 0.92 s | 16.6 s | 3.8 s | 30.7 s (never concluded) | 2.81 s |
| qwen3:8b | 1.54 s | 22.1 s | 5.0 s | **28.1 s** | 4.55 s |
| qwen3.5:9b | 1.67 s | 28.1 s | 9.3 s | 39.3 s | 5.06 s |

³ Cold load was measured separately after the campaign (`measure_load.py`; full unload, 3 reps, median). The warm-up's `load_duration` is about 0 for thinking-capable models because the thinking probe loads the model first.

## 14. Throughput

| Model | Generation tok/s (median, range) | Prompt tok/s (short prompts) | Prompt tok/s (8K) |
|---|---|---|---|
| gemma3:1b | 56.6 (52.6–60.9) | 294 | 284 |
| qwen3:4b | 18.4 (18.1–19.7) | 102 | NOT RUN |
| qwen3.5:4b | 16.7 (16.3–17.7) | 86 | NOT RUN |
| qwen3:8b | 10.6 (10.4–11.0) | 53 | 40 |
| qwen3.5:9b | 9.7 (9.5–9.9) | 46 | 46 |

Throughput was very stable across repetitions, within −7.1 % / +7.5 % of the median for every model (widest: gemma3:1b; narrowest: qwen3.5:9b at −2.5 % / +1.9 %). These rates are bandwidth-bound and consistent with the Phase 0 extrapolation (8–10 tok/s for 8B).

## 15. RAM

| Model | Peak runner RSS (4K suites) | Peak RSS (8K) | Min system `MemAvailable` during run | 2 GiB floor |
|---|---|---|---|---|
| gemma3:1b | 0.94 GiB | 1.04 GiB | 10.96 GiB | never breached |
| qwen3:4b | 3.04 GiB | — | 8.80 GiB | never breached |
| qwen3.5:4b | 4.30 GiB | — | 7.66 GiB | never breached |
| qwen3:8b | **5.62 GiB** | 6.43 GiB | 6.85 GiB | never breached |
| qwen3.5:9b | **7.15 GiB** | 6.96 GiB | 6.15 GiB | never breached |

With the prompt cache disabled (D2), RSS stayed flat across requests. Before D2, qwen3:4b had grown to 8.0 GiB. **qwen3:8b needs about 1.5 GiB less than qwen3.5:9b.** On this box that matters: swap filled completely during the campaign, even with Chrome closed.

## 16. Failures and timeouts

**Infrastructure failures:** 0 timeouts, 0 HTTP errors and 0 RAM-floor aborts across all valid runs (gemma 0/102, qwen3:4b 0/62, qwen3:8b 0/142, qwen3.5:9b 0/142). qwen3.5:4b recorded 5/126 `step_budget_exhausted`. Those are behavioural failures, not infrastructure ones.

**Model failures, in chronological order:**

1. **qwen3:4b, early-stopped by reviewer decision (D3).**
   - **Evidence:** 12/15 generation, 7/8 evidence and 14/14 structured-prompt requests hit the token budget (`num_predict` + 1,024 thinking tokens) with **no answer**, at 66–77 s per request.
   - **Validation slice** (the same one defined for all early stops): tools 4/10 fully correct, 5/10 never emitted a call; agent 2/5 correct, 3/5 no diagnosis.
   - The failure pattern carries over to the agent workflow, so the model was stopped completely.
   - **NOT RUN — EARLY STOP AFTER OBJECTIVE DISQUALIFICATION:** structured_prompt (remaining 16/30), structured_constrained, tools (full), agent (full), context.
   - Record: `results/runs/qwen3_4b/early_stop.json`.
2. **qwen3.5:4b, early-stopped automatically by ES1.**
   - 5/5 agent scenarios produced no diagnosis within the 6-tool-call budget.
   - **NOT RUN — EARLY STOP AFTER OBJECTIVE DISQUALIFICATION:** agent (remaining 7/12), context.
   - More testing could not reasonably change its classification. Even a perfect score on the 7 remaining scenarios gives an agent score of 7/12 (0.58) and Q ≤ 0.6474 + 0.30 × 0.583 = **0.822**, still below both eligible models (≥ 0.904).
   - Record: `results/runs/qwen3.5_4b/early_stop.json`.
3. **gemma3:1b has no tool-calling capability.** Its tools and agent suites are recorded as `unsupported`, not as failures.

**Quarantined runs, kept but excluded:**
- `runs_invalid/qwen3_4b_think_false_ineffective/` (D1)
- `runs_invalid/cache_ram_8192/{gemma3_1b,qwen3_4b}/` (D2)
- `runs_invalid/interrupted_by_ollama_restart/gemma3_1b/` (service restart during the D2 change)

## 17. Raw comparison

| Model | Size | Peak RSS | Gen tok/s | Prompt tok/s | Tool success | Constrained JSON | Struct. semantic | Knowledge | Evidence | Agent | Agent scenario | Q | Eligible |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | 0.82 GB | 0.94 GiB | 56.6 | 294 | unsupported | 100 % | 40 % | 0.55 | 0.38 | unsupported | — | 0.236 | no (G4, G6) |
| qwen3:4b | 2.50 GB | 3.04 GiB | 18.4 | 102 | NOT RUN (slice 40 %) | NOT RUN | NOT RUN | 0.90 | 0.12 | NOT RUN (slice 2/5) | 78.9 s (slice) | 0.112 (partial) | no (early stop, G4, G5, G6) |
| qwen3.5:4b | 3.39 GB | 4.30 GiB | 16.7 | 86 | **100 %** | 100 % | 80 % | 0.80 | 0.94 | **0/5** | 30.7 s | 0.647 (partial) | no (early stop) |
| **qwen3:8b** | 5.23 GB | **5.62 GiB** | **10.6** | **53** | 96 % | 100 % | **80 %** | 0.85 | 0.88 | **11/12** | **28.1 s** | **0.904** | **yes** |
| **qwen3.5:9b** | 6.59 GB | 7.15 GiB | 9.7 | 46 | **100 %** | 100 % | 70 % | **0.90** | **1.00** | 10/12 | 39.3 s | **0.907** | **yes** |

**Gates** (pass/fail per model):

| Gate | gemma3:1b | qwen3:4b | qwen3.5:4b | qwen3:8b | qwen3.5:9b |
|---|---|---|---|---|---|
| G1 stability | ✅ | ✅ | ✅ | ✅ | ✅ |
| G2 memory | ✅ | ✅ | ✅ | ✅ | ✅ |
| G3 speed | ✅ | ✅ | ✅ | ✅ | ✅ |
| G4 tools | ❌ | ❌ | ✅ | ✅ | ✅ |
| G5 structured | ✅ | ❌ | ✅ | ✅ | ✅ |
| G6 evidence | ❌ | ❌ | ✅ | ✅ | ✅ |
| Not early-stopped | ✅ | ❌ | ❌ | ✅ | ✅ |

The full machine-generated tables are in the Appendix and in `results/report_tables.md`.

## 18. Primary model selection

| Role | Model | Basis |
|---|---|---|
| **Primary** | **qwen3.5:9b** (`6488c96f…93ea7`, Q4_K_M, `think=false`) | Pre-registered rule: highest Q among eligible models (0.9074) |
| **Secondary** | **qwen3:8b** (`500a1f06…b8b41`, Q4_K_M, `think=false`) | Pre-registered rule: fastest other eligible model with Q ≥ 0.8 × primary |
| **Baseline** | gemma3:1b | Always retained. Not eligible (no tools, and it invents root causes). |

Only one generative model is resident at a time. The secondary is a swap-in alternative, not a concurrent second model.

## 19. Why the selected model was chosen, and how robust that is

**Following the registered rule.** qwen3.5:9b and qwen3:8b are the only models that passed every gate and ran every suite. qwen3.5:9b has the higher Q (0.9074 against 0.9040). Its strengths are perfect tool selection and arguments (25/25), perfect evidence discipline (6/6 abstentions, 2/2 controls), the best knowledge score, and decode speed that holds at 8K. The latency tie-break requires the faster model to be at least 1.5× faster. qwen3:8b's agent loop is 1.40× faster (28.1 s against 39.3 s), so the tie-break does not fire.

**The pick is not robust.** Stated plainly:

1. **The Q gap is 0.0034.** Flipping a single agent scenario changes Q by 0.025, 7× more than the gap. **On this dataset the two models are statistically indistinguishable on quality.**
2. **The winner depends on the weights.** Under five reasonable weightings, qwen3.5:9b wins three: pre-registered, equal, and reliability-heavy. qwen3:8b wins two: agent-heavy, and tools/agent/evidence/structured only.
3. **On the hardware dimensions you emphasised** (latency × RAM × agent usability), **qwen3:8b is better on every measured axis:**
   - 1.40× faster agent loop;
   - 1.5 GiB less peak RSS;
   - 9 % faster decode;
   - 0.5 s faster cold load;
   - 11/12 against 10/12 agent success;
   - perfect needle retrieval (8/8 against 4/8 fully correct);
   - Q per second 0.032 against 0.023, and Q per GiB 0.161 against 0.127.
4. **qwen3.5:9b has a systematic label-boundary weakness:** it mislabels TCP retransmissions as packet loss in 2/2 agent scenarios and 3/4 structured items. qwen3:8b's single agent miss (S10) is an isolated confusion in the opposite direction.

I have **not** overridden the pre-registered decision on these grounds, because that would be choosing the winner after seeing the data. Instead, confirming the primary is a **Phase 1C condition** (§ Gate).

## 20. Limitations

1. **Small samples.** 12 agent scenarios, 25 tool tasks and 8 evidence items mean differences of one item fall below resolution (§19). Confidence intervals were not computed.
2. **Synthetic tools ignore their arguments.** A request for p50 returns the canned p99 payload. This plausibly encouraged qwen3.5:4b's repeated queries in S03. It applies equally to all models, but it's less realistic than live tools.
3. **The keyword rubrics are crude.** I spot-checked the low scores by hand (gemma: K2, K7, G4, E02). One false negative was fixed as revision R1, on baseline data only. Some partially correct answers may still be misjudged.
4. **Thinking modes were not evaluated** for hybrid models (`think=false` throughout). For thinking-only qwen3:4b, a 1,024-token allowance may be too small for its reasoning style, but larger budgets are incompatible with agent latency on this CPU.
5. **The agent harness has no forced-conclusion turn.** qwen3.5:4b's non-termination might be fixable by an orchestrator that forces a final answer when the step budget runs out. That's untested here, and testing it would change the methodology.
6. **Single runtime and quantisation:** Ollama 0.35.0 / llama.cpp, Q4_K_M only. No thread tuning (about 8 threads by default), no CPU pinning, and the performance governor left as found.
7. **Context was tested only up to 8K**, with one needle type (host and timestamp lookup), and only for gemma3:1b, qwen3:8b and qwen3.5:9b.
8. **System state:** VS Code and the GNOME desktop stayed resident, and swap was full by the end. The absolute RAM headroom figures are specific to this desktop state.
9. **Timing realism:** agent-turn latency benefits from in-slot prefix reuse. That's realistic for SentinelAI, but it differs from fresh-prompt latency (§12).

---

## Objective evaluation

**"Have we experimentally identified a local LLM suitable for SentinelAI?"** → **PASS WITH CONSTRAINTS**

**Evidence for a pass:**
- Two models passed every pre-registered gate on this exact machine, CPU-only:
  - 0 infrastructure failures in 142/142 requests each;
  - peak RSS ≤ 7.15 GiB;
  - ≥ 9.7 tok/s;
  - ≥ 96 % tool success with 100 % valid arguments and 0 invented tools;
  - 100 % schema-valid constrained JSON;
  - 6/6 abstention on insufficient evidence;
  - ≥ 83 % agent-loop success, including 3/3 correct `INSUFFICIENT_EVIDENCE` on the ambiguous cases.
- Both models are Apache-2.0 and need no cloud services or keys.

**The constraints:**
1. **Latency.** An agent investigation takes about 28–40 s per scenario. Fresh prefill is about 45–50 tok/s, so new context per turn should stay around 2K tokens or less, with 4K as the ceiling.
2. **RAM.** The primary needs about 7.2 GiB, which leaves little headroom for RAG, Prometheus and the workloads (Phase 0 budget). Swap was exhausted.
3. **Model choice.** The primary and secondary are statistically tied on quality. The pre-registered choice (qwen3.5:9b) is the slower and larger of the two.
4. **Label boundaries.** Both models confuse closely related fault classes (TCP retransmissions against packet loss), which points to explicit label definitions or deterministic pre-classification.
5. **Loop control.** Loop termination is not guaranteed, as qwen3.5:4b shows. The SentinelAI orchestrator must enforce step budgets and a final-answer turn.

## PHASE 1B GATE

### **GO WITH CONDITIONS**

- **Selected primary:** qwen3.5:9b (pre-registered rule).
- **Secondary:** qwen3:8b.
- **Baseline:** gemma3:1b.

**Unresolved issues, to be closed before or at the start of Phase 1C:**

1. **Confirm the primary model (reviewer decision required).** Quality is tied (§19). Choose one:
   - **(a)** accept the pre-registered result, qwen3.5:9b;
   - **(b)** run a short confirmatory agent evaluation, about 40 or more new scenarios including TCP-retransmission versus packet-loss boundary cases, on qwen3.5:9b and qwen3:8b only;
   - **(c)** adopt qwen3:8b for its measured latency and RAM advantage, recorded as a reviewer override.
   - My recommendation is **(b)**.
2. **RAM headroom.** About 7.2 GiB for the primary and full swap mean the Phase 1C RAM budget must be re-planned against measured numbers. Options needing your approval: enlarge swap or enable zram, keep the desktop session lighter, or choose qwen3:8b to save 1.5 GiB.
3. **Ollama configuration.** Keep the `LLAMA_ARG_CACHE_RAM=0` drop-in (reversible), or replace it with a small explicit cap. It must not return to the 8 GiB default.
4. **Context budget for RAG.** At most about 2K new tokens per agent turn, compact pre-aggregated tool output, and incremental conversations.
5. **Orchestrator requirements** for the later agent phase: a hard step budget, a forced-conclusion turn, explicit label definitions, and `INSUFFICIENT_EVIDENCE` as a first-class outcome.
6. **Disk clean-up decision.** The disqualified models qwen3:4b (2.5 GB) and qwen3.5:4b (3.4 GB) are still installed. Deleting them needs your approval. Free disk is 122 GiB.

Phase 1C has **not** been started. No RAG, MCP, Kubernetes, LangGraph or agent infrastructure was installed. I'm waiting for your review.

---

## Appendix: machine-generated tables (`results/report_tables.md`, from `report_tables.py`)

### Models and digests

| Model | Digest (sha256) | Size | Params | Quant | Downloaded | Date | Capabilities | License |
|---|---|---|---|---|---|---|---|---|
| gemma3:1b | `8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc` | 0.82 GB | 999.89M | Q4_K_M | pre-existing | pre-existing | completion | Gemma Terms of Use  |
| qwen3:4b | `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7` | 2.50 GB | 4.0B | Q4_K_M | 1B | 2026-10-02 | completion, tools, thinking | Apache License |
| qwen3.5:4b | `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd` | 3.39 GB | 4.7B | Q4_K_M | 1B | 2026-10-02 | completion, vision, tools, thinking | Apache License |
| qwen3:8b | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` | 5.23 GB | 8.2B | Q4_K_M | 1B | 2026-10-02 | completion, tools, thinking | Apache License |
| qwen3.5:9b | `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7` | 6.59 GB | 9.7B | Q4_K_M | 1B | 2026-10-02 | completion, vision, tools, thinking | Apache License |

### Coverage and early stops

| Model | think | gen | know | evid | struct-prompt | struct-constr | tools | agent | context | Early stop |
|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | None | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |
| qwen3:4b | True | 15/15 | 10/10 | 8/8 | 14/30 | 0/30 | 0/28 | 0/12 | 0/8 | **reviewer**: Reviewer stop on objective evidence: generation 12/15, evidence 7/8, structured_prompt 14/ |
| qwen3.5:4b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 5/12 | 0/8 | **automatic**: ES1 failure-to-complete: 5/5 requests in 'agent' produced no usable output (> 50%) |
| qwen3:8b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |
| qwen3.5:9b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |

### Performance (4K-context suites; medians)

| Model | Gen tok/s | Gen tok/s range | Prompt tok/s | TTFT s | Gen wall s | Gen out tok | Agent turn s | Peak RSS GiB | Min MemAvail GiB | Sys CPU % (mean) | Runner CPU % | Load s | Failed/requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | 56.59 | 52.56–60.86 | 294.1 | 0.29 | 4.3 | 220 | None | 0.94 | 10.96 | 34.4 | 800.3 | 1.0564 | 0/102 |
| qwen3:4b | 18.41 | 18.06–19.65 | 101.9 | 0.76 | 77.12 | 1408 | 77.83 | 3.04 | 8.80 | 34.3 | 800.2 | 0.0011 | 0/62 |
| qwen3.5:4b | 16.73 | 16.31–17.69 | 85.74 | 0.92 | 16.59 | 266 | 3.81 | 4.30 | 7.66 | 34.3 | 800.1 | 0.0088 | 5/126 |
| qwen3:8b | 10.57 | 10.43–10.95 | 53.32 | 1.54 | 22.14 | 220 | 5.03 | 5.62 | 6.85 | 34.3 | 800.0 | 0.0088 | 0/142 |
| qwen3.5:9b | 9.69 | 9.45–9.87 | 46.38 | 1.67 | 28.05 | 259 | 9.25 | 7.15 | 6.15 | 34.3 | 800.0 | 0.0014 | 0/142 |

### Tool calling (25 tool tasks + 3 no-tool tasks)

| Model | Success (score 2) | Arg validity | Wrong tool | Missing call | Hallucinated tool | No-tool correct | Norm score |
|---|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported |
| qwen3:4b | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| qwen3:4b *(slice, n=10)* | 40% | 100% | 0% | 50% | 0% | — | 0.45 |
| qwen3.5:4b | 100% | 100% | 0% | 0% | 0% | 100% | 1.00 |
| qwen3:8b | 96% | 100% | 0% | 4% | 0% | 100% | 0.96 |
| qwen3.5:9b | 100% | 100% | 0% | 0% | 0% | 100% | 1.00 |

### Structured output (30 incidents per mode; Pydantic strict, extra=forbid)

| Model | Mode | Valid JSON | Schema valid | Missing field | Extra field | Parse failure | Markdown fenced | Valid after fence-strip | Semantically correct |
|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | prompt | 0% | 0% | 0% | 0% | 100% | 100% | 80% | 0% |
| gemma3:1b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 40% |
| qwen3:4b | prompt | 0% | 0% | 0% | 0% | 100% | 0% | 0% | 0% |
| qwen3:4b | constrained | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| qwen3.5:4b | prompt | 60% | 60% | 0% | 0% | 40% | 40% | 93% | 50% |
| qwen3.5:4b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3:8b | prompt | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3:8b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3.5:9b | prompt | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 70% |
| qwen3.5:9b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 70% |

### Agent loop (12 scenarios, ≤6 tool calls; 3 ambiguous)

| Model | Success | Multi-step success | Confident wrong | No diagnosis | Over-cautious | Ambiguous correct (of 3) | Mean tool calls | Median scenario s | Hallucinated calls | Invalid-arg calls | Norm | Coverage |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | 12/12 |
| qwen3:4b | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 0/12 |
| qwen3:4b *(slice, n=5)* | 40% | 0% | 0 | 3 | 0 | — | 0.4 | 78.89 | 0 | 1 | 0.40 | 5/5 |
| qwen3.5:4b | 0% | 0% | 0 | 0 | 0 | 0 | 6.0 | 30.72 | 0 | 0 | 0.00 | 5/12 |
| qwen3:8b | 92% | 92% | 1 | 0 | 0 | 3 | 3.75 | 28.05 | 0 | 0 | 0.92 | 12/12 |
| qwen3.5:9b | 83% | 83% | 2 | 0 | 0 | 3 | 2.67 | 39.25 | 0 | 0 | 0.83 | 12/12 |

### Evidence discipline (6 insufficient-evidence + 2 sufficient controls)

| Model | Abstained (insufficient) | Unsupported root cause | Controls correct | Controls over-cautious | Format followed | Unprompted numbers (heuristic) | Norm |
|---|---|---|---|---|---|---|---|
| gemma3:1b | 17% | 83% | 2/2 | 0 | 8/8 | 1/8 | 0.38 |
| qwen3:4b | 17% | 83% | 0/2 | 0 | 1/8 | 0/8 | 0.12 |
| qwen3.5:4b | 100% | 0% | 1/2 | 1 | 8/8 | 0/8 | 0.94 |
| qwen3:8b | 100% | 0% | 1/2 | 1 | 8/8 | 0/8 | 0.88 |
| qwen3.5:9b | 100% | 0% | 2/2 | 0 | 8/8 | 0/8 | 1.00 |

### Technical knowledge (10) and generation (5×3)

| Model | Knowledge mean (0–2) | Knowledge norm | Generation mean (0–2) | Generation norm |
|---|---|---|---|---|
| gemma3:1b | 1.10 | 0.55 | 0.80 | 0.40 |
| qwen3:4b | 1.80 | 0.90 | 0.13 | 0.07 |
| qwen3.5:4b | 1.60 | 0.80 | 1.67 | 0.83 |
| qwen3:8b | 1.70 | 0.85 | 1.47 | 0.73 |
| qwen3.5:9b | 1.80 | 0.90 | 1.60 | 0.80 |

### Context scaling (2 reps per size; medians)

| Model | Nominal | Actual prompt tok | num_ctx | Prompt tok/s | TTFT s | Wall s | Gen tok/s | Peak RSS GiB | Needle (0–2) | Failures / truncated |
|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | 1024 | 1120.0 | 2048 | 296.55 | 4.37 | 5.03 | 55.08 | 1.01 | 1/2 | 0 / trunc=False |
| gemma3:1b | 2048 | 2235.0 | 3072 | 299.11 | 8.06 | 8.79 | 54.53 | 0.92 | 1/2 | 0 / trunc=False |
| gemma3:1b | 4096 | 4451.0 | 5120 | 294.06 | 15.73 | 17.1 | 53.7 | 1.01 | 0/2 | 0 / trunc=False |
| gemma3:1b | 8192 | 8745.0 | 9216 | 283.56 | 31.44 | 31.69 | 54.16 | 1.04 | 0/2 | 0 / trunc=False |
| qwen3:4b | NOT RUN |  |  |  |  |  |  |  |  |  |
| qwen3.5:4b | NOT RUN |  |  |  |  |  |  |  |  |  |
| qwen3:8b | 1024 | 1118.0 | 2048 | 50.28 | 24.13 | 29.27 | 9.91 | 6.28 | 2/2 | 0 / trunc=False |
| qwen3:8b | 2048 | 2227.0 | 3072 | 48.52 | 47.78 | 54.04 | 9.36 | 5.48 | 2/2 | 0 / trunc=False |
| qwen3:8b | 4096 | 4433.0 | 5120 | 44.92 | 100.7 | 106.47 | 7.28 | 5.86 | 2/2 | 0 / trunc=False |
| qwen3:8b | 8192 | 8745.0 | 9216 | 39.52 | 223.44 | 235.85 | 5.08 | 6.43 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 1024 | 1115.0 | 2048 | 49.14 | 25.23 | 29.92 | 9.6 | 6.91 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 2048 | 2224.0 | 3072 | 48.92 | 47.87 | 52.72 | 9.48 | 6.67 | 1/2 | 0 / trunc=False |
| qwen3.5:9b | 4096 | 4430.0 | 5120 | 47.17 | 96.47 | 101.44 | 9.04 | 6.82 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 8192 | 8742.0 | 9216 | 45.52 | 194.47 | 200.27 | 8.19 | 6.96 | 1/2 | 0 / trunc=False |

### Gates and quality score

| Model | G1 stability | G2 memory | G3 speed | G4 tools | G5 structured | G6 evidence | Not early-stopped | Q | Eligible |
|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | 0.2363 | no |
| qwen3:4b | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 0.1121 | no |
| qwen3.5:4b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 0.6474 | no |
| qwen3:8b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 0.904 | **yes** |
| qwen3.5:9b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 0.9074 | **yes** |

### Q components (normalised 0–1; weights {"agent": 0.3, "tools": 0.25, "evidence": 0.15, "structured": 0.15, "knowledge": 0.1, "generation": 0.05})

| Model | Agent | Tools | Evidence | Structured (constr.) | Knowledge | Generation | Q |
|---|---|---|---|---|---|---|---|
| gemma3:1b | 0.00 | 0.00 | 0.38 | 0.70 | 0.55 | 0.40 | 0.2363 |
| qwen3:4b | 0.00 | 0.00 | 0.12 | 0.00 | 0.90 | 0.07 | 0.1121 |
| qwen3.5:4b | 0.00 | 1.00 | 0.94 | 0.90 | 0.80 | 0.83 | 0.6474 |
| qwen3:8b | 0.92 | 0.96 | 0.88 | 0.90 | 0.85 | 0.73 | 0.904 |
| qwen3.5:9b | 0.83 | 1.00 | 1.00 | 0.85 | 0.90 | 0.80 | 0.9074 |

### Decision (score.py)

```json
{
  "primary": "qwen3.5:9b",
  "primary_rule": "highest Q",
  "best_Q_model": "qwen3.5:9b",
  "secondary": "qwen3:8b",
  "baseline": "gemma3:1b",
  "verdict": "PASS"
}
```
