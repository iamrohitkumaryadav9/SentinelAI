# Phase 1B Confirmatory Evaluation: qwen3:8b vs qwen3.5:9b

| Field | Value |
|---|---|
| Date | 2026-10-02, run 19:19–20:59 IST |
| Models | qwen3:8b `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`; qwen3.5:9b `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7` |
| Pre-registration | Commit `d60132e`, made before either model ran. SHA-256 hashes are in `experiments/llm_benchmark/confirm/PREREG_SHA256.txt`; the protocol is in `confirm/PROTOCOL.md` and `protocol.json`. |
| Code / data | `experiments/llm_benchmark/confirm/` (`scenario_gen.py`, `scenarios.json`, `simulator.py`, `confirm.py`, `analyze.py`, `posthoc_noise.py`) |
| Raw records | `confirm/results/runs/<model>/agent.jsonl`: 48 per model, no re-runs |
| Derived | `confirm/results/summary.json`, `scored.csv`, `tables.md`, `posthoc_noise.json` |
| Environment | Unchanged from Phase 1B: Ollama 0.35.0 with `LLAMA_ARG_CACHE_RAM=0`, swap and zram as found, Chrome closed, nothing installed |

---

## 1. Executive summary

- **Neither model is adequate as an autonomous diagnostician on this larger, harder, more targeted evaluation.**
  - **qwen3:8b got 18/48 correct (37.5 %, Wilson 95 % CI 25.2–51.6 %).**
  - **qwen3.5:9b got 21/48 correct (43.8 %, CI 30.7–57.7 %).**
  - The pre-registered adequacy bar was 70 %. Both fail it, so the pre-registered decision procedure returns **FAIL** at Rule 0.
- **The difference between the models is not robust.** qwen3.5:9b is 6.3 points ahead (discordant pairs 7 against 4), but the exact McNemar p = 0.55 and the paired bootstrap 95 % CI is −18.8 to +6.3 points (qwen3:8b minus qwen3.5:9b). The Phase 1B ranking is **not confirmed and not reversed**.
- **Neither model handles the boundary between TCP retransmission and proven packet loss.** Each correctly identified **1 of 6** retransmission-driven incidents, and **0 of 3** congestion cases.
- **Evidence discipline collapsed relative to Phase 1B.**
  - qwen3:8b abstained correctly in **3/13** ambiguous scenarios and qwen3.5:9b in **1/13**. Both guessed a fault in 9/13.
  - The main sink was the new label `application_bottleneck`: 6/13 for qwen3:8b and **8/13** for qwen3.5:9b. qwen3.5:9b's rate meets the pre-registered "systematic error" criterion.
  - **Self-reported confidence carries no information:** mean 0.93 when correct and 0.92–0.93 when wrong, for both models.
- **Tool mechanics remain excellent:** 0 invented tools, 0 schema-invalid arguments, and 0 unknown-entity arguments across 96 scenarios and 474 tool calls (209 for qwen3:8b, 265 for qwen3.5:9b).
- **On resources, qwen3:8b is materially better:**
  - median scenario 45 s against 78 s (1.73×);
  - p95 59 s against 102 s;
  - peak RSS 5.62 against 7.00 GiB;
  - 0.49 against 0.33 correct diagnoses per minute.
- **Two flaws in my own design** (§10), quantified post hoc, depress the absolute scores. Neither changes the conclusion: under the most generous combined sensitivity, qwen3:8b reaches at most 55.8 %. qwen3.5:9b reaches 70.8–72.1 % only if its two characteristic failure modes are forgiven.

## 2. Experimental design

| Item | Value (identical for both models) |
|---|---|
| Decoding | `temperature=0`, `seed=42`, `num_ctx=4096`, `num_predict=320` per turn, `think=false` (probe-verified for both) |
| Harness | Phase 1B `benchmark.chat`, `Sampler` and warm-up, unchanged. Maximum swap used was added (measurement only). |
| Tools | `schemas/tools.json`, unchanged |
| Step budget | 6 tool calls, no forced-conclusion turn (as in Phase 1B) |
| Order | qwen3:8b (19:19–19:55), then qwen3.5:9b (19:56–20:59). One resident model; `other_models_resident` was empty on every record. |
| Changes against the Phase 1B agent suite, applied to both | (1) **explicit label definitions**, including the retransmission/loss rule; (2) a new label `application_bottleneck`; (3) a structured final answer `DIAGNOSIS / CONFIDENCE / EVIDENCE`; (4) **tools that respect their arguments** (`simulator.py`); (5) 48 new scenarios, none reused |

**Argument-respecting tools.** Interface, CPU, percentile, log-level and limit filters are honoured. An unknown host, interface, service or CPU returns an error, and so does unavailable data. That fixes the Phase 1B limitation where tools ignored their arguments. Window arguments are echoed but don't change values; that's a remaining limitation.

**Statistics.** Wilson intervals, an exact McNemar test (binomial on discordant pairs), and a paired bootstrap (10,000 resamples, seed 12345). No weighted score was computed.

**Deviations after registration** (none affects any outcome, score or decision):
- **C1.** The runner's conversation-length estimate summed `prompt_eval_count` across turns. Ollama reports the *full* prompt each turn, so the sum over-counts. The analysis now uses the maximum per-turn prompt plus output. Real conversations peaked well under 4,096 tokens: 0 scenarios at risk, and llama-server logged `truncated = 0`.
- **C2.** The numpy-to-float/bool cast for JSON output.
- **Post-hoc analyses**, all labelled as such: the `kfree_skb` noise analysis (`posthoc_noise.py`) and the upper-bound sensitivity in §11.
- **Integrity check:** `sha256sum -c PREREG_SHA256.txt` shows `scenarios.json`, `protocol.json`, `simulator.py` and `confirm.py` unchanged since pre-registration. `analyze.py` differs **only** by C1 and C2 (`git diff d60132e -- confirm/analyze.py`); neither touches scoring, outcomes or the decision rules.

## 3. New scenario taxonomy

48 scenarios, generated deterministically. Every gold label is machine-checked against the label definitions, and 7 deliberate gold-label mutations were all rejected by the validator.

| Category | n | Gold labels |
|---|---|---|
| A: TCP retransmission vs packet loss | 18 | 6 `tcp_retransmissions` (sub-cases 1 and 6), 6 `network_packet_loss` (sub-cases 2, 3, 7), 1 `application_bottleneck` (4), 5 `INSUFFICIENT_EVIDENCE` (4, 5, 8) |
| B: CPU scheduling / throttling | 7 | 4 `cpu_contention` (run queue, affinity hotspot, context-switch storm, steal), 3 `cpu_throttling` |
| C: Network / softirq overload | 6 | 4 `softirq_overload`, 1 `network_packet_loss` (softirq with proven drops), 1 `INSUFFICIENT_EVIDENCE` |
| D: Memory pressure | 5 | 4 `memory_pressure` (reclaim, swap, OOM, allocation stalls), 1 `cpu_contention` (page-cache distractor) |
| E: Application bottleneck | 5 | 5 `application_bottleneck` (DB pool, lock, slow dependency, worker pool with a CPU-92 % distractor, work queue) |
| F: Insufficient / ambiguous | 7 | 7 `INSUFFICIENT_EVIDENCE` |

Totals: **13 `INSUFFICIENT_EVIDENCE` (27 %)**, 6 TCP retransmission, 7 packet loss, 6 application, 5 contention, 3 throttling, 4 softirq, 4 memory. 21 scenarios contain distractor evidence.

## 4. Raw results

The full per-scenario table, with expected and predicted label, outcome, tool calls and latency for both models, is in the Appendix and in `confirm/results/tables.md`. Every scenario's model root cause, confidence, cited evidence, tools, tool arguments, call count, abstention, latency, token counts and termination reason are in `confirm/results/scored.csv`. The raw transcripts, including each turn's assistant text, are in `agent.jsonl`.

| Outcome | qwen3:8b | qwen3.5:9b |
|---|---|---|
| correct | **18** | **21** |
| incorrect diagnosis | 18 | 11 |
| insufficient-evidence failure (guessed a fault) | 9 | 9 |
| unsupported diagnosis | 0 | 0 |
| over-cautious | 1 | 0 |
| no diagnosis | 0 | **5** ¹ |
| loop / non-termination | 2 | 2 |
| error / timeout | 0 | 0 |
| Per-call flags: hallucinated tool / invalid args / unknown entity / `run_experiment` | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Concluded without the required tool | 2 | 0 |

¹ All 5 hit `num_predict=320` (`done_reason=length`) while writing a prose analysis, before emitting the `DIAGNOSIS:` line.

## 5. TCP retransmission vs packet-loss analysis

| Metric | qwen3:8b | qwen3.5:9b |
|---|---|---|
| Gold `tcp_retransmissions` scenarios | 6 | 6 |
| Correctly classified | **1** (A02) | **1** (A02) |
| Packet-loss false positives | 2 (A01, A06) | 1 (A06) |
| Other incorrect | 3 (`cpu_contention` A03; `application_bottleneck` A04, A05) | 4 (`cpu_contention` A03; `application_bottleneck` A05; no label A01, A04 ²) |
| Abstentions | 0 | 0 |
| `tcp_retransmissions`: precision / recall | 1.00 (1/1) / **0.17** (1/6) | 1.00 (1/1) / **0.17** (1/6) |
| `network_packet_loss`: precision / recall | **0.45** (5/11) / 0.71 (5/7) | **0.83** (5/6) / 0.71 (5/7) |
| Gold loss predicted as `tcp_retransmissions` | 0 | 0 |
| Category A total | 6/18 | 7/18 |
| Congestion (sub-case 6) | **0/3** | **0/3** |
| Cannot distinguish → abstain (sub-case 8) | 0/2 | 0/2 |
| Proven loss (sub-cases 2 and 7) | 4/4 | 4/4 |

² Step budget exhausted.

**Interpretation.** Both models recognise *proven* packet loss reliably: 4/4 on the unambiguous loss cases, and 5/7 overall, where the two misses (A10, C05) were labelled softirq. But **neither model treats "retransmissions without proven drops" as a diagnosis**. They used the label `tcp_retransmissions` only once each across 48 scenarios, despite its explicit definition. The Phase 1B concern about qwen3.5:9b, its retransmission → packet-loss confusion, is **not borne out as a model-specific weakness here**. qwen3:8b made *more* packet-loss false positives: 2 among the TCP cases and 6 in total, against 1 and 1. The real finding is that **both models under-use the retransmission class**.

## 6. Agent success comparison

| Metric | qwen3:8b | qwen3.5:9b |
|---|---|---|
| Correct | 18/48 = **37.5 %** (CI 25.2–51.6) | 21/48 = **43.8 %** (CI 30.7–57.7) |
| Multi-step correct (≥ 2 tool calls) | 18 | 21 |
| By category: A / B / C / D / E / F | 6/18, 3/7, 2/6, 2/5, 2/5, 3/7 | 7/18, **6/7**, 2/6, 2/5, 3/5, **1/7** |
| Median tool calls | 4 | **6** (the budget ceiling) |
| Paired (both / 8b only / 9b only / neither) | 14 / 4 / 7 / 23 | |
| 8b-only correct | C04, D05, F04, F05 | |
| 9b-only correct | | A13, B02, B06, B07, C01, D04, E02 |

qwen3.5:9b is clearly better on CPU throttling (2/3 against **0/3**; qwen3:8b called all three "contention"). qwen3:8b is better at abstaining (F 3/7 against 1/7). Almost half the scenarios (23/48) defeated both models.

## 7. Evidence-discipline comparison

| Metric | qwen3:8b | qwen3.5:9b |
|---|---|---|
| Ambiguous scenarios correctly answered `INSUFFICIENT_EVIDENCE` | **3/13** (F02, F04, F05) | **1/13** (F02) |
| Guessed a fault on an ambiguous scenario | 9/13 | 9/13 |
| …of which `application_bottleneck` | 6 | **8** (meets the Rule-1 "systematic error" criterion: ≥ 3 and ≥ 50 % of a class with n ≥ 4) |
| Over-cautious on a real fault | 1 (E02) | 0 |
| `EVIDENCE` names a diagnostic term (fault scenarios) | 28/35 | 31/35 |
| Mean confidence when correct / incorrect | 0.925 / 0.930 | 0.936 / 0.915 |
| Confidence reported | 46/48 | 41/48 |

**Mechanism.** In every one of the 14 ambiguous → `application_bottleneck` answers, the model *had* called `get_recent_logs` and received normal or symptom-only lines. It then reasoned by elimination ("kernel looks normal, therefore application"), although the definition requires logs that *show* the bottleneck. Phase 1B had no such residual label, and there both models abstained 3/3. **A plausible catch-all class defeats abstention for both models.** **Self-reported confidence is uninformative** (about 0.93 whether right or wrong) and must not be used as a gate.

## 8. Latency comparison

| Metric | qwen3:8b | qwen3.5:9b | Ratio |
|---|---|---|---|
| Median scenario latency | **45.3 s** | 78.3 s | 1.73× |
| p95 scenario latency | **58.8 s** | 102.4 s | 1.74× |
| Total for 48 scenarios | 37.0 min | 63.5 min | — |
| Median tool calls | 4 | 6 | — |
| Median turn latency | 9.0 s | 11.9 s | — |
| Median generation rate (per turn) | 9.9 tok/s | 9.5 tok/s | — |
| Median TTFT per turn | 4.7 s | 7.9 s | — |
| Correct diagnoses per minute | **0.49** | 0.33 | 1.47× |
| Quality per second (correct rate ÷ median s) | **0.0083** | 0.0056 | — |

Agent-turn prompt rates (about 620–770 tok/s) reflect in-slot prefix reuse and are not fresh-prefill throughput. Fresh-prefill figures come from Phase 1B §12.

## 9. RAM comparison

| Metric | qwen3:8b | qwen3.5:9b |
|---|---|---|
| Peak runner RSS | **5.62 GiB** | 7.00 GiB |
| Minimum system `MemAvailable` | 7.17 GiB | 5.80 GiB |
| Maximum swap used | 1,565 MiB (start 1,565) | 1,560 MiB (start 1,556) |
| Swap growth during run | none | none |
| CPU (system mean / runner) | 34.3 % / about 800 % | 34.3 % / about 800 % |
| Quality per GiB / correct per GiB | **0.067 / 3.20** | 0.063 / 3.00 |
| 2 GiB floor | never breached | never breached |

Swap did not grow in this run. It stayed at about 1.55 GiB, left over from Phase 1B. qwen3.5:9b leaves about 1.4 GiB less headroom for everything else SentinelAI must run.

## 10. Failure analysis

**Per-model error patterns**, from the confusion matrices in `summary.json`:

| Pattern | qwen3:8b | qwen3.5:9b |
|---|---|---|
| Ambiguous → `application_bottleneck` (elimination guessing) | 6 | 8 |
| Over-predicts `cpu_contention` (wrong predictions by gold: 8b throttling 3, softirq 2, memory 2, TCP 1, app 1, ambiguous 1; 9b softirq 2, TCP 1, app 1, ambiguous 1) | **14 predictions, 4 correct** | 9 predictions, 4 correct |
| Throttling → contention | 3/3 | 0/3 |
| Proven drops + softirq → `softirq_overload` (A10, C05) | 2 | 2 |
| Memory → `application_bottleneck` (D01, D02) | 1 | 2 |
| Format failure (no `DIAGNOSIS` line, out of tokens) | 0 | 5 |
| Step budget exhausted | 2 (B02, F03) | 2 (A01, A04) |

**Flaws in my own design** (found during the run, not fixed mid-run, quantified post hoc):

- **F1: baseline `kfree_skb` noise.** Every scenario carries realistic background noise (`kfree_skb drops_per_s=3`, reason `NOT_SPECIFIED`). The definition of `network_packet_loss` lists "kfree_skb drops" **without a magnitude qualifier**.
  - qwen3:8b cited this noise as proof of loss in **5** errors (A01, A06, A13, A14, E03). qwen3.5:9b did so in **1** (A06).
  - The flaw affected qwen3:8b more. It is a protocol defect, although ignoring baseline noise is also a real-world requirement.
- **F2: an elimination sink.** Adding `application_bottleneck` gave the models a residual label. The definition requires positive log evidence, but both models used it by elimination. This is a real behavioural finding, but its size depends on the label design.
- **Remaining design limits.** Window arguments are not modelled. Scenarios are single-host. Diagnostic-term matching for "evidence grounded" is lexical.

## 11. Robustness analysis

| Analysis | qwen3:8b | qwen3.5:9b | Paired test |
|---|---|---|---|
| **Primary (pre-registered)** | 18/48 = 37.5 % | 21/48 = 43.8 % | McNemar p = **0.55**; bootstrap CI of 8b − 9b: [−0.188, +0.063]; **not robust** |
| Post hoc: exclude the 5 noise-affected scenarios (paired) | 18/43 = 41.9 % | 20/43 = 46.5 % | McNemar p = 0.75 |
| Post-hoc upper bound: also count every "no diagnosis" and every ambiguous → app answer as correct | 24/48 = 50.0 % | 34/48 = 70.8 % | — |
| …and exclude the noise scenarios | 24/43 = 55.8 % | 31/43 = 72.1 % | — |

- **Conclusion (primary):** both models are inadequate (< 70 %), and the difference between them is not robust.
- **Sensitivity:** qwen3:8b stays below the bar under every sensitivity. qwen3.5:9b crosses it only in the upper bound, which forgives exactly its two characteristic failure modes: format truncation and elimination guessing. Those are plausibly addressable by orchestration (constrained-JSON final answers, a forced-conclusion turn, label design), but that is **untested** and would need its own pre-registered evaluation.
- **Wording:** the observed quality difference is smaller than the resolution of this 48-scenario evaluation, so the ranking between the two models is not robust to individual scenario outcomes.

## 12. Final model-selection rationale

Applying the pre-registered hierarchy:

- **Rule 0, adequacy: both models fail** (37.5 % and 43.8 % against ≥ 70 %; ambiguous-case guessing 69 % for both against ≤ 25 %). **The procedure stops here: verdict FAIL, no primary.**
- The remaining rules were evaluated *for information only*, without deciding:
  - **Rule 1 (safety / correctness).** qwen3.5:9b has a systematic error qwen3:8b lacks (ambiguous → `application_bottleneck`, 8/13). qwen3:8b is just below the same threshold (6/13 = 46 %, against the 50 % criterion), so this distinction is fragile. qwen3:8b has more noise-driven false packet-loss claims (6 against 1 overall). Neither model invents tools or produces invalid arguments.
  - **Rule 2 (agent quality).** Not robust (p = 0.55).
  - **Rule 3 (resources).** qwen3:8b is materially better on both latency (−42 %) and RAM (−1.4 GiB).
  - **Rule 4.** No genuine quality winner.

So the trade-off is real and unresolved. **qwen3.5:9b** is slightly better on raw correctness (not robust), on packet-loss precision and on throttling. **qwen3:8b** is materially faster and lighter, with fewer format failures, and abstained in 3 cases against 1. **Neither should be trusted to produce the final root cause on its own.**

## 13. Limitations

1. **Synthetic, single-host telemetry** generated by me. Gold labels follow my definitions; the validator only ensures internal consistency.
2. **48 scenarios.** Confidence intervals are about ±13 points, so differences under about 15 points cannot be resolved.
3. **Flaws F1 and F2** (§10).
4. **Fixed budgets.** `num_predict=320` (as in Phase 1B) truncated qwen3.5:9b's verbose answers. A larger budget or constrained JSON output might change its results; that was not tested.
5. **No forced-conclusion turn**, and the harness is the same as in Phase 1B. Window arguments are not modelled.
6. **One run per model** at `temperature=0`. Run-to-run variance was not measured.
7. The absolute numbers are **not comparable** with the Phase 1B agent suite: there are new labels, definitions and scenarios.

## 14. Recommendation for Phase 1C

**Do not build Phase 1C on the assumption that a local 8–9B LLM can autonomously produce the root-cause label.** The evidence supports these changes to the architecture:

1. **Deterministic, evidence-first classification.** Extract features from eBPF and metrics (drop counters relative to baseline, retransmission/RTT ratios, run-queue delay, throttled-period ratio, PSI, softirq hotspots), and use a rule or ML classifier with explicit abstention. The LLM selects tools, explains, and checks consistency; it does not decide alone.
2. **Constrained-JSON final answers** (Phase 1B showed 100 % schema validity), a **forced-conclusion turn**, and a hard step budget. This removes the format and loop failures.
3. **Label design without residual sinks.** `application_bottleneck` must require positive evidence, checked by code, and `INSUFFICIENT_EVIDENCE` must be the default whenever no rule fires.
4. **Baseline-relative evidence in tool output.** For example `kfree_skb_drops_per_s` with a baseline and ratio, so noise is not mistaken for loss.
5. **Never use the model's self-reported confidence as a gate.**
6. **Re-evaluate the hybrid design with a pre-registered v2 of this experiment**: the corrected F1 and F2 plus constrained output and a forced conclusion, on both models. Only then lock the primary model.

### Phase 1B Final Verdict

`FAIL`

The pre-registered confirmatory adequacy test failed for both models. This supersedes the provisional "PASS WITH CONSTRAINTS" in `PHASE_1B_EVALUATION.md`, *for the role of autonomous diagnostician*. Both models remain verified as reliable tool callers and structured-output generators.

### Primary Model

`NO FINAL PRIMARY — RESULTS TOO CLOSE`

Neither model met the adequacy bar, and the difference between them is not robust (p = 0.55).

### Secondary Model

None selected.

For reference only, not a selection: qwen3:8b is materially more resource-efficient (1.73× faster, 1.4 GiB lighter), and qwen3.5:9b is non-robustly ahead on raw correctness (+6.3 points).

### GO / NO-GO FOR PHASE 1C

`NO-GO`

**What blocks progress:**
1. No local model is adequate as the autonomous root-cause decider: 37.5 % and 43.8 % correct, and 69 % guessing on ambiguous cases.
2. The architecture must change before Phase 1C components (RAG, agents, MCP) are built: deterministic evidence-first classification with explicit abstention, and the LLM as orchestrator and explainer (§14).
3. The primary model can only be chosen after a pre-registered **v2 evaluation of that hybrid design** on both models, with flaws F1 and F2 corrected, constrained-JSON final answers and a forced-conclusion turn. That needs your approval, because it changes the methodology for both models identically.

The known constraints from Phase 1B stay in force for any future phase, and nothing here contradicts them:
- one resident generative model;
- ≤ 2K new context tokens per agent turn, with a 4K ceiling for one-off analysis;
- a hard step budget plus a forced final-conclusion mechanism;
- `INSUFFICIENT_EVIDENCE` as a first-class outcome;
- explicit, **magnitude- and baseline-qualified** TCP-retransmission versus packet-loss definitions;
- compact tool outputs and strict structured schemas;
- no 8 GiB Ollama prompt cache;
- careful RAM budgeting (qwen3:8b about 5.6 GiB, qwen3.5:9b about 7.0 GiB).

Nothing from Phase 1C has been installed or started. I'm waiting for your review.

---

## Appendix: per-scenario results (`confirm/results/tables.md`)

| Scenario | Category / subcase | Expected | qwen3:8b | qwen3:8b outcome | qwen3:8b calls | qwen3:8b s | qwen3.5:9b | qwen3.5:9b outcome | qwen3.5:9b calls | qwen3.5:9b s |
|---|---|---|---|---|---|---|---|---|---|---|
| A01 | A_tcp_vs_loss / 1_retx_high_no_drops | tcp_retransmissions | network_packet_loss | incorrect_diagnosis | 5 | 57.05 | — | loop_non_termination | 6 | 81.58 |
| A02 | A_tcp_vs_loss / 1_retx_high_no_drops | tcp_retransmissions | tcp_retransmissions | correct | 4 | 42.36 | tcp_retransmissions | correct | 6 | 82.41 |
| A03 | A_tcp_vs_loss / 1_retx_high_no_drops | tcp_retransmissions | cpu_contention | incorrect_diagnosis | 4 | 47.24 | cpu_contention | incorrect_diagnosis | 6 | 78.08 |
| A04 | A_tcp_vs_loss / 6_congestion | tcp_retransmissions | application_bottleneck | incorrect_diagnosis | 4 | 43.93 | — | loop_non_termination | 6 | 68.59 |
| A05 | A_tcp_vs_loss / 6_congestion | tcp_retransmissions | application_bottleneck | incorrect_diagnosis | 4 | 53.42 | application_bottleneck | incorrect_diagnosis | 6 | 79.38 |
| A06 | A_tcp_vs_loss / 6_congestion | tcp_retransmissions | network_packet_loss | incorrect_diagnosis | 5 | 51.39 | network_packet_loss | incorrect_diagnosis | 5 | 77.99 |
| A07 | A_tcp_vs_loss / 2_drops_high_retx_low | network_packet_loss | network_packet_loss | correct | 5 | 44.13 | network_packet_loss | correct | 6 | 96.81 |
| A08 | A_tcp_vs_loss / 2_drops_high_retx_low | network_packet_loss | network_packet_loss | correct | 5 | 46.85 | network_packet_loss | correct | 6 | 84.58 |
| A09 | A_tcp_vs_loss / 3_both_high | network_packet_loss | network_packet_loss | correct | 4 | 39.06 | network_packet_loss | correct | 6 | 81.67 |
| A10 | A_tcp_vs_loss / 3_both_high | network_packet_loss | softirq_overload | incorrect_diagnosis | 4 | 44.59 | softirq_overload | incorrect_diagnosis | 6 | 76.95 |
| A11 | A_tcp_vs_loss / 7_kernel_proven_loss | network_packet_loss | network_packet_loss | correct | 5 | 43.34 | network_packet_loss | correct | 6 | 81.09 |
| A12 | A_tcp_vs_loss / 7_kernel_proven_loss | network_packet_loss | network_packet_loss | correct | 4 | 45.77 | network_packet_loss | correct | 6 | 79.25 |
| A13 | A_tcp_vs_loss / 4_neither_high | application_bottleneck | network_packet_loss | incorrect_diagnosis | 3 | 41.17 | application_bottleneck | correct | 5 | 72.36 |
| A14 | A_tcp_vs_loss / 4_neither_high | INSUFFICIENT_EVIDENCE | network_packet_loss | insufficient_evidence_failure | 3 | 41.29 | — | no_diagnosis | 6 | 127.57 |
| A15 | A_tcp_vs_loss / 5_insufficient | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 4 | 39.39 | application_bottleneck | insufficient_evidence_failure | 6 | 70.85 |
| A16 | A_tcp_vs_loss / 5_insufficient | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 4 | 40.7 | application_bottleneck | insufficient_evidence_failure | 6 | 76.42 |
| A17 | A_tcp_vs_loss / 8_cannot_distinguish | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 5 | 42.03 | application_bottleneck | insufficient_evidence_failure | 6 | 74.77 |
| A18 | A_tcp_vs_loss / 8_cannot_distinguish | INSUFFICIENT_EVIDENCE | network_packet_loss | insufficient_evidence_failure | 5 | 45.32 | — | no_diagnosis | 6 | 96.14 |
| B01 | B_cpu / runqueue_contention | cpu_contention | cpu_contention | correct | 4 | 43.59 | cpu_contention | correct | 6 | 85.71 |
| B02 | B_cpu / affinity_hotspot | cpu_contention | — | loop_non_termination | 6 | 43.82 | cpu_contention | correct | 6 | 82.03 |
| B03 | B_cpu / context_switch_storm | cpu_contention | cpu_contention | correct | 4 | 42.36 | cpu_contention | correct | 6 | 83.78 |
| B04 | B_cpu / hypervisor_steal | cpu_contention | cpu_contention | correct | 4 | 50.54 | cpu_contention | correct | 5 | 72.23 |
| B05 | B_cpu / cgroup_throttling | cpu_throttling | cpu_contention | incorrect_diagnosis | 5 | 59.64 | — | no_diagnosis | 6 | 99.9 |
| B06 | B_cpu / cgroup_throttling | cpu_throttling | cpu_contention | incorrect_diagnosis | 4 | 50.78 | cpu_throttling | correct | 6 | 82.47 |
| B07 | B_cpu / cgroup_throttling | cpu_throttling | cpu_contention | incorrect_diagnosis | 5 | 69.0 | cpu_throttling | correct | 5 | 74.9 |
| C01 | C_softirq / single_queue_net_rx | softirq_overload | cpu_contention | incorrect_diagnosis | 4 | 42.34 | softirq_overload | correct | 4 | 62.17 |
| C02 | C_softirq / irq_affinity | softirq_overload | cpu_contention | incorrect_diagnosis | 4 | 42.15 | cpu_contention | incorrect_diagnosis | 5 | 77.06 |
| C03 | C_softirq / napi_busy | softirq_overload | softirq_overload | correct | 4 | 50.06 | softirq_overload | correct | 6 | 84.43 |
| C04 | C_softirq / small_packet_flood | softirq_overload | softirq_overload | correct | 5 | 50.82 | cpu_contention | incorrect_diagnosis | 6 | 91.67 |
| C05 | C_softirq / softirq_with_drops | network_packet_loss | softirq_overload | incorrect_diagnosis | 4 | 45.17 | softirq_overload | incorrect_diagnosis | 5 | 69.88 |
| C06 | C_softirq / weak_softirq_signal | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 4 | 47.49 | application_bottleneck | insufficient_evidence_failure | 6 | 78.51 |
| D01 | D_memory / reclaim | memory_pressure | cpu_contention | incorrect_diagnosis | 4 | 54.17 | application_bottleneck | incorrect_diagnosis | 6 | 75.7 |
| D02 | D_memory / swapping | memory_pressure | application_bottleneck | incorrect_diagnosis | 4 | 46.96 | application_bottleneck | incorrect_diagnosis | 6 | 79.86 |
| D03 | D_memory / oom_kills | memory_pressure | memory_pressure | correct | 3 | 47.35 | memory_pressure | correct | 3 | 58.46 |
| D04 | D_memory / allocation_stalls | memory_pressure | cpu_contention | incorrect_diagnosis | 5 | 49.6 | memory_pressure | correct | 5 | 69.33 |
| D05 | D_memory / page_cache_distractor | cpu_contention | cpu_contention | correct | 4 | 57.81 | memory_pressure | incorrect_diagnosis | 5 | 79.45 |
| E01 | E_application / db_pool | application_bottleneck | application_bottleneck | correct | 5 | 50.4 | application_bottleneck | correct | 4 | 57.59 |
| E02 | E_application / lock_contention | application_bottleneck | INSUFFICIENT_EVIDENCE | over_cautious | 5 | 44.43 | application_bottleneck | correct | 5 | 68.01 |
| E03 | E_application / slow_dependency | application_bottleneck | network_packet_loss | incorrect_diagnosis | 3 | 36.13 | — | no_diagnosis | 4 | 103.71 |
| E04 | E_application / thread_pool | application_bottleneck | cpu_contention | incorrect_diagnosis | 5 | 50.02 | cpu_contention | incorrect_diagnosis | 4 | 68.01 |
| E05 | E_application / request_queue | application_bottleneck | application_bottleneck | correct | 4 | 43.83 | application_bottleneck | correct | 5 | 70.37 |
| F01 | F_insufficient / all_normal | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 5 | 46.59 | application_bottleneck | insufficient_evidence_failure | 6 | 75.14 |
| F02 | F_insufficient / data_missing | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE | correct | 4 | 25.04 | INSUFFICIENT_EVIDENCE | correct | 5 | 64.74 |
| F03 | F_insufficient / weak_conflicting | INSUFFICIENT_EVIDENCE | — | loop_non_termination | 6 | 43.36 | application_bottleneck | insufficient_evidence_failure | 6 | 78.53 |
| F04 | F_insufficient / outside_retention | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE | correct | 5 | 50.26 | — | no_diagnosis | 6 | 119.53 |
| F05 | F_insufficient / logs_only_generic | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE | correct | 4 | 24.19 | application_bottleneck | insufficient_evidence_failure | 6 | 60.57 |
| F06 | F_insufficient / multiple_moderate | INSUFFICIENT_EVIDENCE | cpu_contention | insufficient_evidence_failure | 5 | 59.31 | cpu_contention | insufficient_evidence_failure | 6 | 84.78 |
| F07 | F_insufficient / irrelevant_interface_drops | INSUFFICIENT_EVIDENCE | application_bottleneck | insufficient_evidence_failure | 4 | 43.14 | application_bottleneck | insufficient_evidence_failure | 5 | 66.74 |
