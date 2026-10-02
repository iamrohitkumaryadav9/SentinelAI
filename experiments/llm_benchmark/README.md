# LLM benchmark (Phase 1B)

This harness selects SentinelAI's local generative model on this machine: i7-13700, 15.3 GiB RAM, CPU-only. It talks to local Ollama only (127.0.0.1:11434), with no cloud APIs and no API keys.

## Layout

| Path | Content |
|---|---|
| `benchmark.py` | Runner. `pull` (disk-gated download plus manifest), `run`, `campaign` (pull → run, one model at a time) |
| `score.py` | Deterministic scorer. Turns raw JSONL into `results/summary.json`, `results/summary.csv` and `results/comparison.md` |
| `schemas/models.py` | Pydantic schemas (`extra="forbid"`) for tool arguments and the incident diagnosis |
| `schemas/tools.json` | The 5 synthetic tool definitions passed to Ollama |
| `prompts/*.json` | Fixed gold datasets, each with its rubric in `_rubric` |
| `results/runs/<model>/<suite>.jsonl` | Raw per-request records, one JSON object per line |
| `model_manifest.json` | Name, tag, digest, size, download date and Ollama version for every model |

Run from `~/sentinelai`:

```bash
PYTHONNOUSERSITE=1 .venv/bin/python experiments/llm_benchmark/benchmark.py campaign \
    --models gemma3:1b,qwen3:4b,qwen3.5:4b,qwen3:8b,qwen3.5:9b
PYTHONNOUSERSITE=1 .venv/bin/python experiments/llm_benchmark/score.py
```

## Fixed settings

These are identical for every model.

| Setting | Value |
|---|---|
| Decoding | `temperature=0`, `seed=42`; other sampling parameters are the model's Ollama defaults |
| Context | `num_ctx=4096`, except the context suite, which uses `nominal + 1024` |
| Thinking | `think=false` for models advertising the `thinking` capability. Agent loops multiply latency, and thinking traces on CPU cost hundreds of tokens per turn. This is an explicit limitation; the thinking mode is not evaluated here. |
| Hardware | No CPU pinning, governor change or thread override (natural baseline) |
| Residency | Exactly one model resident. Others are unloaded before warm-up, and `other_models_resident` is recorded per request. |
| Safety | Request timeout 300 s (context suite 900 s). Abort if `MemAvailable` < 2 GiB. Refuse a download if free disk would fall below 80 GiB. |
| Caching | Generation and context repetitions start with a distinct `[run N]` tag so the KV prefix cache cannot hide prompt processing. Tool and agent suites share a system and tool prefix, so caching applies there, as it would in production. |

## Suites

| Suite | Items | Measures |
|---|---|---|
| generation | 5 prompts × 3 reps | Throughput, latency, rubric score |
| knowledge | 10 | Linux/eBPF/K8s concepts (rubric) |
| evidence | 6 insufficient-evidence items + 2 controls | Abstention versus invented root causes |
| structured_prompt / structured_constrained | 30 + 30 | JSON/schema validity without and with Ollama `format=<schema>` |
| tools | 25 tool tasks + 3 no-tool tasks | Native tool-call selection and argument validity |
| agent | 12 scenarios, ≤ 6 tool calls each | Multi-step loop with synthetic tool results; final `DIAGNOSIS:` label |
| context | 1K/2K/4K/8K × 2 reps | Prefill cost, RAM, needle retrieval. Sizes are calibrated per model's tokenizer, and truncation is flagged. |

## Scoring rubric (deterministic, no LLM judge)

Every item scores 0, 1 or 2. Each dataset's exact rule is in its `_rubric` field. In summary:

- **Concept rubric** (generation, knowledge): each item lists concept groups, and a group counts if any of its terms appears. 2 = all groups present, 1 = at least half, 0 = fewer.
- **Tools:**
  - 2 = the correct tool, with schema-valid arguments that match the expected values.
  - 1 = an acceptable alternative tool, or the correct tool with a valid but non-matching argument value.
  - 0 = a wrong tool, no call, an invented tool name, or invalid arguments.
  - On the no-tool tasks, any call scores 0.
- **Structured:** 2 = schema-valid and the type and severity are correct, 1 = schema-valid but semantically wrong, 0 = invalid.
- **Agent:**
  - Real fault: 2 = the correct label, reached after consulting the required evidence. 1 = the correct label without that evidence, or an over-cautious `INSUFFICIENT_EVIDENCE`. 0 = a confident wrong label.
  - Ambiguous scenario: 2 = `INSUFFICIENT_EVIDENCE` after calling at least one tool, 1 = `INSUFFICIENT_EVIDENCE` without calling any tool, 0 = any confident label.
- **Evidence:** abstaining while naming at least 2 kinds of required evidence scores 2. Asserting an unsupported root cause scores 0. The control items reward the correct cause, so blanket refusal is not rewarded.

## Selection criterion (pre-registered before any candidate was benchmarked)

**Hard gates.** A model must pass all of them to be eligible as primary:

| Gate | Threshold |
|---|---|
| G1 Stability | Failed, timed-out or aborted requests ≤ 5 % |
| G2 Memory | Peak runner RSS ≤ 8.0 GiB on the 4K-context suites, and the 2 GiB RAM floor never breached |
| G3 Speed | Median generation throughput ≥ 5 tok/s |
| G4 Tool calling | Single-step tool success (score = 2) ≥ 75 %, and invented-tool-name rate ≤ 5 % |
| G5 Structured output | Constrained-mode schema-valid ≥ 95 % |
| G6 Evidence discipline | Normalised evidence score ≥ 0.60 |

**Quality score** Q ∈ [0, 1] is a weighted mean of normalised suite scores (mean item score ÷ 2):

| Component | Weight | Why |
|---|---|---|
| Agent loop | 0.30 | The closest proxy for SentinelAI's core task |
| Tool calling | 0.25 | Every action goes through tools |
| Evidence discipline | 0.15 | Reliability: not inventing causes |
| Structured (constrained) | 0.15 | Machine-consumable output |
| Knowledge | 0.10 | Domain grounding |
| Generation | 0.05 | General explanation quality |

**Decision rule:**
1. The **primary** is the eligible model with the highest Q.
2. If another eligible model has Q within 0.05 of the best and a median agent-scenario wall time ≤ 0.67× that of the best (at least 1.5× faster), choose the faster one. Agent loops multiply latency, so speed wins near-ties.
3. The **secondary** is the fastest other eligible model with Q ≥ 0.80 × Q(primary), for low-latency sub-tasks. Only one model is resident at a time.
4. The **baseline** is `gemma3:1b`, always reported, whether or not it is eligible.
5. If no model passes every gate, the result is **FAIL**. No winner is forced.

Raw metrics are always reported next to Q; Q never replaces them.

## Early-stop rules (pre-registered 2026-10-02 16:10, before qwen3.5:4b / qwen3:8b / qwen3.5:9b ran)

A model may be stopped early **only** when one of these objective conditions holds. The harness evaluates them automatically after every request, and the rules are identical for every model. Validation-slice requests are excluded.

| Rule | Condition |
|---|---|
| ES1 Failure to complete | More than 50 % of requests in a suite produce no usable output (status not `ok`, or empty content with no tool call). Evaluated once the suite has at least 10 requests, or at least 5 agent scenarios. |
| ES2 Latency | Median request latency above 180 s in a suite (after at least 10 requests), or median agent-scenario latency above 900 s (after at least 3 scenarios) |
| ES3 Resources | `MemAvailable` below 2 GiB. This is the existing hard abort. |

When a rule triggers:
1. Every completed result is kept.
2. If the tools and agent suites have not run yet, the fixed **validation slice** (`prompts/validation_slice.json`) runs, using the same prompts, budgets and scoring: 5 tool-selection tasks, 5 tool-argument tasks, 3 single-step agent scenarios and 2 two-step agent scenarios.
3. `results/runs/<model>/early_stop.json` records the trigger, the configuration, per-suite statistics, and every suite that did not run, labelled `NOT RUN — EARLY STOP AFTER OBJECTIVE DISQUALIFICATION`.
4. No scores are invented for suites that did not run, and an early-stopped model is never eligible as primary.

**qwen3:4b** was stopped by reviewer decision before these rules existed. The evidence was 12/15 generation, 7/8 evidence and 14/14 structured-prompt requests hitting the token budget without an answer. It then ran the same validation slice. Its record is labelled `decided_by: reviewer`.

**Compatibility check:** before every download, the registry config's `requires` field (minimum Ollama version) is compared with the installed version. A mismatch stops the campaign; Ollama is never upgraded without approval.
