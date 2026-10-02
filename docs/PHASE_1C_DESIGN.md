# Phase 1C Design: Evidence & Diagnostic Core

| Field | Value |
|---|---|
| Status | **DESIGN ONLY.** Nothing here is implemented. |
| Date | 2026-10-02 |
| Normative companion | [EVIDENCE_CONTRACT.md](EVIDENCE_CONTRACT.md) v0.1.0-draft |
| Supersedes | The Phase 1C plan implied in `PHASE_1B_EVALUATION.md` (an LLM-centred design) |
| Motivation | [PHASE_1B_CONFIRMATORY_EVALUATION.md](PHASE_1B_CONFIRMATORY_EVALUATION.md): no local LLM was adequate as the root-cause classifier |

---

## 1. Goal and non-goals

**Goal.** A reproducible, LLM-independent diagnostic engine that turns raw telemetry into:
- normalised, baseline-relative measurements;
- typed evidence items;
- candidate root causes, each with supporting and contradicting evidence;
- a single decision, with confidence and **explicit abstention**.

It is validated on controlled, reproducible fault experiments.

**Non-goals for Phase 1C:**
- an LLM in the decision path;
- RAG, GraphRAG, MCP, LangGraph, agents;
- Kubernetes;
- a Prometheus production stack;
- automated mitigation;
- multi-host diagnosis.

## 2. Architecture

```
            ┌─────────────────────────────────────────────────────────────┐
 Telemetry  │ C1 Collectors (unprivileged: /proc, /sys, cgroupfs, tc, ss; │
            │    optional privileged eBPF; FaultLab app metrics)          │
            └──────────────┬──────────────────────────────────────────────┘
                           │ raw samples (JSONL, 1 Hz, with provenance)
            ┌──────────────▼──────────────┐
            │ C2 Feature extraction       │  counters→rates, derived features, quality flags
            └──────────────┬──────────────┘
            ┌──────────────▼──────────────┐
            │ C3 Evidence normalisation   │  baseline stats, deviation, Measurement objects
            └──────────────┬──────────────┘
                           │ EvidenceSnapshot (measurements only)
            ┌──────────────▼──────────────┐          ┌──────────────────────────────┐
            │ C4 Rule engine (contract)   │          │ C5 ML model (advisory)        │
            │ predicates → evidence items │          │ feature vector → calibrated   │
            │ → candidates → precedence   │          │ probabilities                 │
            └──────────────┬──────────────┘          └──────────────┬───────────────┘
                           └───────────────┬────────────────────────┘
                            ┌──────────────▼──────────────┐
                            │ C6 Decision & abstention    │  contract gate, agreement check
                            └──────────────┬──────────────┘
                                           ▼
                                 DiagnosticResult (Pydantic, strict)
```

- **Separability.** C4 and C5 share only the `EvidenceSnapshot` input and are independently testable.
- C4 alone **is** a complete diagnostic engine.
- C5 cannot change C4's decision except as specified in §5.4.
- No component calls an LLM.

### Repository layout (planned)

```
src/sentinelai/diagnostic/
  contract/registry.json        # feature registry (contract §4), machine-readable
  contract/labels.json          # label contracts + precedence table (contract §8–9)
  contract/params.calibrated.json   # produced by calibration (contract §6); hashed
  schema.py                     # Pydantic models (contract §10)
  collect/                      # C1: proc.py, cgroup.py, netns.py, tc.py, ss.py, app.py, ebpf_optional.py
  features.py                   # C2
  normalize.py                  # C3
  rules.py                      # C4
  ml/                           # C5: features_ml.py, train.py, calibrate.py, predict.py
  decide.py                     # C6
  cli.py                        # `sentinel-diag snapshot|diagnose|explain`
experiments/faultlab/
  docker/Dockerfile, docker/workload.py, docker/loadgen.py
  scenarios/*.json              # scenario definitions (§6.2)
  topology.py, inject.py, run.py, verify.py
datasets/faultlab/v1/            # manifest.json, raw/<run_id>/, features.csv
tests/evidence/  tests/rules/  tests/classifier/
```

## 3. Telemetry collection (C1)

- **Sampling.**
  - 1 Hz sampling of all `A` sources in contract §4.
  - Collectors read files directly; no daemons are added.
  - Each sample records `{feature_raw, value, scope, monotonic_ts, wall_ts, locator}`.
- **Container namespaces.**
  - Network namespace counters of a lab container are read either through `/proc/<pid>/net/{snmp,netstat}` and `/sys` within that namespace, or through `docker exec`.
  - The `/proc/<pid>/net` path is listable from the host (verified). Reading `snmp` that way is **pilot item PI-1**.
  - `tc -s -j qdisc` and `ss -tin` run through `docker exec` inside the target namespace (`ss` verified).
- **Privileged eBPF** (`kfree_skb` by reason, run-queue latency histograms):
  - an optional collector, started only by an explicit `sudo` command from the operator;
  - never required by any gate;
  - absent: its features are `MISSING` (contract E1).
- **Access.**
  - Lab orchestration needs Docker access. Campaigns run from a fresh login (`docker` group) or under `sg docker -c`.
  - No collector needs root.
- **Overhead budget.** Collector CPU ≤ 2 % of one core at 1 Hz, measured in pilot PI-6. Collectors are pinned to a P-core outside the lab cpusets.

## 4. Feature extraction and normalisation (C2, C3)

1. **Rates.** Counters become rates over each 1 s sample. A negative delta marks the sample `INVALID`.
2. **Derived features.** Computed exactly as the registry defines, for example:
   - `sched.run_delay_excess.target = max(0, run_delay_rate − throttle.time_rate)`;
   - `tcp.retrans_frac`;
   - `softirq.relevant_cpu_max`.
3. **Windowing.** The analysis window is `W` seconds and the baseline window is `B` seconds immediately before the incident window (contract §5).
   - In FaultLab, the incident window is the fault phase **excluding** a transition margin `T_TRANS` after injection, which is a parameter.
4. **Baseline.** Median, MAD, p99 and n per feature and scope come from the baseline window, with adequacy flags.
5. **Deviation.** `ratio`, `delta` and `robust_z` use the per-feature `floor_f`.
6. **Output.** An `EvidenceSnapshot` with `measurements`, `missing_measurements` and `data_quality`. `evidence_items` is filled by C4.

## 5. Decision layers

### 5.1 Rule engine (C4)

This is a deterministic evaluation of the contract. The algorithm is fixed:

1. **Data-quality gate** (contract §10.8). If it fails, the decision is `INSUFFICIENT_EVIDENCE` (`DATA_QUALITY`).
2. **Evaluate every predicate** referenced by `labels.json`. Each produces one `EvidenceItem` (kind, strength, threshold, measurement IDs).
3. **Impact gate** (contract §7).
4. **Per label:** evaluate the Required clauses with three-valued logic. Then set the candidate status:
   - `ASSERTED` if all Required clauses are TRUE;
   - `NOT_EVALUABLE` if any is MISSING and none is FALSE;
   - `NOT_SUPPORTED` if any is FALSE;
   - `SUPPORTED_NOT_SUFFICIENT` if POSITIVE supporting items exist but Required is not met.

   The contradictory and supporting items are attached.
5. **Precedence** (contract §9) among ASSERTED candidates gives one primary plus CONTRIBUTING candidates, or `CONFLICT_UNRESOLVED`.
6. **Special abstentions:**
   - `LOSS_VS_RETRANS_UNDECIDABLE` (contract §8.5);
   - `CONFOUNDER_NOT_EVALUATED` (§8.7);
   - `REQUIRED_EVIDENCE_MISSING`: the only non-unsupported candidate is NOT_EVALUABLE.
7. **Confidence level** (contract §10.9) and the invariant check (contract §10.7). If an invariant is violated, the engine raises an error; it never outputs.

**Rule table.** Every Required clause in contract §8 is one rule. Each rule's record in `labels.json` holds:
- `rule_id` (for example `PL.R1`);
- `required_features`;
- `parameters` (thresholds by name);
- `rationale`;
- `output_label`;
- `confidence_contribution`;
- `contradicted_by` (rule IDs);
- `missing_behaviour`.

There is no other logic: **no hidden heuristics, no learned weights, no free text.**

### 5.2 ML classifier (C5): inputs

- **Feature vector.** For each registry feature and canonical scope, three columns: `robust_z`, `log(ratio)` and the absolute value. That is `value_abs` for bounded quantities such as `throttle.ratio`, and `log1p(value)` for rates.
- **Missing values.** Each feature gets a missing-indicator column. Missing values are filled with neutral constants (`z = 0`, `log ratio = 0`), **never** imputed from other runs.
- **Excluded columns** (leakage): scenario ID, family, intensity, injection timestamps, container names, cpuset IDs, seed, run order, wall-clock time, anything derived from FaultLab ground truth, and the rule engine's decision.
- **Labels:** the ground-truth **primary** label of the window (§6.5). Overlap families with an acceptable-set ground truth (§6.4) are **excluded from training** and used only for robustness evaluation.

### 5.3 ML classifier (C5): models, calibration, abstention

- **Models,** in order, stopping at the simplest that meets the gates:
  1. multinomial logistic regression (standardised, L2, `class_weight="balanced"`);
  2. random forest (`n_estimators` ≤ 500, `min_samples_leaf` tuned);
  3. scikit-learn `HistGradientBoostingClassifier`, only if (1) and (2) miss the gates on validation.

  XGBoost is not installed. Adding it requires a written justification and approval. No deep learning.
- **Hyperparameters:** tuned with `GroupKFold` (groups = `run_id`) on the training split only.
- **Calibration:** `CalibratedClassifierCV` with sigmoid (Platt), switching to isotonic only if the training split has at least 1,000 windows, both fitted with GroupKFold on the training split. Reported metrics:
  - Brier score;
  - expected calibration error (ECE: 10 equal-mass bins, top-label);
  - a reliability diagram.
- **Abstention:** the output is `INSUFFICIENT_EVIDENCE` if either condition holds:
  - (a) the maximum calibrated probability is below `τ_ML`, which is tuned on validation for a target risk; or
  - (b) the **contract gate** fails: the predicted label's Required clauses are not all TRUE.

  Both the raw-ML and the gated-ML results are reported.
- **Feature importance:** permutation importance on the test split (grouped), plus logistic-regression coefficients. Reported, not used for decisions.

### 5.4 Combination policy (C6, fixed in advance)

1. The **decision of record** is the rule engine's decision.
2. ML is **advisory**. `ml.agrees_with_rules` is recorded.
   - If ML disagrees with calibrated probability ≥ `τ_DISAGREE`, a `ML_DISAGREEMENT` flag is added and confidence is lowered by one level, never below MEDIUM for an asserted decision.
   - ML **cannot** assert a label the rules did not assert. That would violate contract P1.
3. Phase 1C evaluates three systems: rules alone, ML alone (gated), and the combined policy. Rules-alone is the system under the primary gate.

## 6. Dataset design: FaultLab

### 6.1 Topology and components (design; not implemented)

- **Image** `sentinelai/faultlab:<tag>`. It is built from `experiments/faultlab/docker/Dockerfile` (python:3.10-slim plus iproute2, iperf3, procps, stress-ng), and its digest is recorded per run.
- **Target workload** (`workload.py`, to be written):
  - an HTTP service with a bounded worker pool (size `P`) and a bounded admission queue (`Q`);
  - per-request CPU work (`cpu_us`), an optional instrumented lock (`lock_hold_us`) and an optional downstream dependency call (to container B);
  - it exposes `/metrics.json` (contract §4.7: latency histogram, queue wait, pool utilisation, rejections, lock wait, dependency latency, error rate, throughput);
  - it emits **closed-set** structured events, and optionally **free-text** distractor log lines (§6.4).
- **Load generator** (`loadgen.py`): a fixed-rate open-loop client in container L. It records client-side latency, used for ground-truth sanity checks only, never as a feature.
- **Network topology** (dedicated Docker bridge networks named `sl_faultlab_*`):
  - **A** (target + workload, `NET_ADMIN`) — `net1` — **R** (router, `NET_ADMIN`, `ip_forward=1`) — `net2` — **B** (dependency/bulk peer).
  - L reaches A on `net1`.
  - The **observation scope** is A plus the host. R and B counters are never collected.
- **CPU placement:**
  - lab containers are pinned to E-cores 16–23 (`--cpuset-cpus`);
  - collectors run on a P-core;
  - the desktop/SSH session keeps the remaining P-cores.

### 6.2 Scenario format (JSON, validated by Pydantic)

```json
{
  "scenario_id": "PL-QDISC-I2",
  "family": "network_packet_loss/local_qdisc",
  "expected": {"primary": "network_packet_loss", "contributing": ["tcp_retransmissions"],
               "acceptable": null},
  "intensity_level": "I2",
  "topology": "A-R-B",
  "target": {"container": "A", "cpuset": "20-21", "cpus_quota": null, "memory_max": "512m"},
  "workload": {"rps": 200, "pool": 16, "queue": 64, "cpu_us": 800, "dependency": "B"},
  "faults": [{"type": "netem", "where": "A:eth0:egress", "params": {"loss_pct": 2.0},
              "start_s": 60, "stop_s": 150}],
  "distractors": [],
  "collectors": {"disable": []},
  "phases": {"warmup_s": 15, "baseline_s": 45, "fault_s": 90, "cooldown_s": 20},
  "seed": 1013,
  "split": "test"
}
```

`split` is assigned **when the matrix is generated**, before any data is collected (§6.6).

### 6.3 Fault injectors (all inside lab containers or namespaces)

| Class | Injection (mechanism) | Intensity levels | Injection verification (ground-truth side) |
|---|---|---|---|
| `cpu_contention` | Competitor container `stress-ng --cpu k` on the **same** cpuset as A, no quota | k ∈ {I1, I2, I3} | `docker inspect` cpuset; competitor running |
| `cpu_throttling` | `docker update --cpus q` on A (CFS quota) while the workload demands > q | q ∈ {I1, I2, I3} | `cpu.max` reads the configured quota |
| `softirq_overload` | Small-packet UDP flood (`iperf3 -u -l 64`) between lab containers on the same cpuset/CPUs as A | pps ∈ {I1, I2, I3} | iperf3 report; flood processes alive |
| `network_packet_loss` | netem `loss p%` on **A** egress; tc ingress `police … drop` on A | p ∈ {I1, I2, I3} | `tc qdisc/filter show` in A |
| `tcp_retransmissions` | netem `loss p%` on **R** egress toward B (path loss); netem `rate`/queue limit on R (congestion) | p, rate ∈ {I1, I2, I3} | `tc qdisc show` in R |
| `memory_pressure` | A `--memory M --memory-swap M`; the workload's working set (anon + file churn) above M; separate OOM variant | M ∈ {I1, I2, I3} | `memory.max`; `memory.events` (for the record only) |
| `application_bottleneck` | Workload reconfiguration at run time: pool shrink, lock-hold increase, slow dependency (B sleep) | 3 levels | Workload config echo (`/config.json`) |

**Intensities.** I1–I3 are fixed in the scenario matrix **before** collection. They are chosen in the pilot (§10, PI-4) as clearly detectable levels **by injection magnitude**, not by looking at diagnostic features.

**Swap.** Swap-based memory scenarios are **excluded**: the host's 2 GiB swap is about 76 % used and must not be enlarged. The swap features remain in the contract and stay MISSING or NEGATIVE.

**NIC errors.** NIC CRC errors cannot be produced on veth. `net.err.iface` stays in the contract, untested in FaultLab, and this is reported as a coverage gap.

### 6.4 Families: clean, single-fault, overlap, distractor, insufficient

| Family | Construction | Expected (a priori) |
|---|---|---|
| CTRL | No fault, normal load | `INSUFFICIENT_EVIDENCE` (`NO_IMPACT_OBSERVED` or `NO_CANDIDATE`) |
| Single-fault × 7 | §6.3 at I1–I3 | That class |
| OV-1 | Network bulk load (iperf3 A→B, no loss) + CPU contention | `cpu_contention` |
| OV-2 | Local qdisc drops ⇒ retransmissions | primary `network_packet_loss`, contributing `tcp_retransmissions` |
| OV-3 | CPU throttling + high host utilisation (stress on other lab CPUs) | `cpu_throttling` |
| OV-4 | Softirq increase **below** overload (moderate pps, A on other CPUs) | `INSUFFICIENT_EVIDENCE` |
| OV-5 | High memory utilisation, no pressure (page-cache fill, then idle) | `INSUFFICIENT_EVIDENCE` |
| OV-6 | CPU contention + free-text "slow request" log lines from the workload | `cpu_contention` (never `application_bottleneck`) |
| OV-7 | Throttling **and** contention injected together | **Acceptable set:** {`INSUFFICIENT_EVIDENCE`, `cpu_throttling` with `cpu_contention` contributing, `cpu_contention` with `cpu_throttling` contributing} |
| OV-8 | Path loss in R with drop collectors **disabled** in A | `INSUFFICIENT_EVIDENCE` (`LOSS_VS_RETRANS_UNDECIDABLE`) |
| OV-9 | Pool shrink with app metrics **disabled** | `INSUFFICIENT_EVIDENCE` (no elimination) |
| OV-10 | Normal kernel + generic free-text application logs, no closed-set events | `INSUFFICIENT_EVIDENCE` |
| OV-11 | Softirq overload with backlog drops (if achievable, PI-4) | primary `softirq_overload`, contributing `network_packet_loss` (PR-2) |
| SENS | Each class at a sub-detection intensity I0 | **Not gated.** Reported as detection curves. |

### 6.5 Ground truth (independent of the diagnostic model)

- **Ground truth is the scenario declaration plus injection verification.** It is never derived from the features or from either model.
- Per run, the runner records the scenario JSON, the injection events with timestamps, the verification outputs, the image digest, and the outcome (`verified`, `failed_injection`, or `aborted`).
- Runs with failed injection verification are excluded and **counted** in the report.
- A window's label is the scenario's expected primary for windows inside [fault_start + `T_TRANS`, fault_stop), and `INSUFFICIENT_EVIDENCE` for CTRL windows. Baseline, transition and cooldown windows are unlabelled and not scored.
- **No LLM is involved** in ground truth.

### 6.6 Splits and leakage control

- **Unit of independence:** the run. All windows of a run belong to the same split.
- **Assignment** (deterministic, at matrix generation):
  - for each family × intensity, seeds are allocated to `train` and `test`;
  - **intensity I2 of every single-fault family is test-only** (an unseen-intensity interpolation test);
  - an extra **OOD set** (different cpuset size and RPS) is reported separately.
- **Everything is fitted on train runs only:**
  - calibration of contract parameters (§7.4);
  - ML hyperparameter search;
  - probability calibration;
  - `τ_ML`.
- **Baselines** are within-run, so no cross-run information enters the features.
- **Test scenarios are never inspected** before the final evaluation. The evaluation script refuses to run on test data unless `params.calibrated.json` and the model artefact are already committed. Their hashes are recorded.

### 6.7 Size and runtime budget

| Set | Runs |
|---|---|
| Single-fault, train | 7 classes × {I1, I3} × 4 seeds = 56 |
| Single-fault, test | 7 classes × {I1: 3, I2: 4, I3: 3 seeds} = **10 per class** = 70 |
| Overlap/distractor | 11 families × 4 seeds (2 train / 2 test) = 44 |
| CTRL | 20 (10 / 10) |
| SENS | 7 × 2 = 14 |
| OOD | 7 × 2 = 14 |
| **Total** | **≈ 218 runs** |

Each run is about 3 min (warm-up 15 s, baseline 45 s, fault 90 s, cooldown 20 s, plus setup and teardown). Total wall time is **about 11 h**, split across 2–3 sessions; the runs resume by `run_id`.

## 7. Evaluation

### 7.1 Systems evaluated
1. Rules alone (primary).
2. ML alone, raw and contract-gated.
3. The combined policy (§5.4).

All three are evaluated on the identical test runs.

### 7.2 Metrics
- **Run-level decision** (primary): the modal decision over the run's scored windows. Ties go to `INSUFFICIENT_EVIDENCE`.
- **Window-level:** secondary.
- **Per system, reported:**
  - macro F1 over the 8 outcomes;
  - per-class precision, recall and F1, each with a Wilson 95 % CI;
  - the confusion matrix;
  - explicitly, the counts of `tcp_retransmissions → network_packet_loss`, `network_packet_loss → tcp_retransmissions` and `cpu_throttling → cpu_contention`;
  - abstention: abstention rate on INS-expected runs, false-assertion rate on INS-expected runs, coverage on fault runs, selective accuracy and the risk–coverage curve;
  - calibration (ML only): Brier, ECE, reliability diagram;
  - robustness: OV families, scored against the a-priori expected label or acceptable set;
  - OOD, reported separately.

### 7.3 Adversarial tests (expected behaviour)

Each class is tested at two levels:
- **(U) unit:** hand-built `EvidenceSnapshot` fixtures in `tests/rules/`, run with explicit test parameter values;
- **(F) FaultLab family**, where one exists.

| # | Phase 1B failure mode | Fixture / family | Expected behaviour |
|---|---|---|---|
| ADV-1 | `kfree_skb` noise read as packet loss | U: kfree_skb 3/s `NOT_SPECIFIED` at baseline, all other drop sources 0 | Not `network_packet_loss`. The item is NEGATIVE or WEAK supporting only. `NO_CANDIDATE` if nothing else. |
| ADV-2 | TCP retransmission evidence ignored | U + F (path loss in R) | `tcp_retransmissions` asserted, RT.R1/R2 POSITIVE/FALSE as specified |
| ADV-3 | Retransmission mistaken for packet loss | U + F (path loss, congestion) | `tcp_retransmissions`; **never** `network_packet_loss` while `LOSS.LOCAL` is FALSE |
| ADV-3b | Retransmissions with drop counters missing | U + F (OV-8) | `INSUFFICIENT_EVIDENCE` (`LOSS_VS_RETRANS_UNDECIDABLE`) |
| ADV-4 | Throttling mistaken for contention | U + F (throttling, OV-3) | `cpu_throttling`. With excess run delay ≈ 0, `cpu_contention` is NOT_SUPPORTED. |
| ADV-5 | Utilisation alone gives a CPU diagnosis | U: `cpu.util.*` = 0.95, run delay and throttling at baseline | Neither CPU label; `NO_CANDIDATE` |
| ADV-6 | Weak softirq gives a softirq diagnosis | U + F (OV-4) | Not `softirq_overload`; `INSUFFICIENT_EVIDENCE` if nothing else |
| ADV-7 | High memory usage read as pressure | U + F (OV-5) | Not `memory_pressure`; a NEGATIVE item recorded |
| ADV-8 | Application bottleneck by elimination | U + F (OV-9, OV-10): normal kernel, generic logs, app metrics missing or normal | **Never** `application_bottleneck`. `INSUFFICIENT_EVIDENCE` (`NO_CANDIDATE` or `REQUIRED_EVIDENCE_MISSING`). |
| ADV-8b | Positive application evidence | U + F (app single-fault) | `application_bottleneck` with AB.R1–R3 satisfied |
| ADV-9 | Conflicting evidence | U: throttling and excess delay of equal magnitude; softirq + qdisc drops (PR-2b) | `INSUFFICIENT_EVIDENCE` (`CONFLICT_UNRESOLVED`), both candidates listed |
| ADV-10 | Insufficient evidence | U: impact high, all families MISSING; F: CTRL | `INSUFFICIENT_EVIDENCE` with the correct reason code |

Further unit suites:
- **tests/evidence:** schema validation; invariants I1–I7; deterministic IDs; byte-identical serialisation; counter-reset handling; missing-data propagation (Kleene logic).
- **tests/classifier:** no leakage columns (a schema check of the feature matrix); a group split with no run overlap; seed reproducibility; calibration-pipeline smoke tests; abstention threshold behaviour.

### 7.4 Calibration protocol for contract parameters
1. **Noise floors** `floor_f`: the p99 of per-window values in **train** CTRL runs.
2. **Bands and thresholds:**
   - each threshold is set on **train** runs by a declared, monotone search;
   - for example, `DROP_ABS_MIN` is the smallest value with ≤ 1 % false positives on train CTRL plus non-network single-fault windows, while keeping recall ≥ 0.9 on train loss windows;
   - each parameter's objective is written in `params.calibration.md` **before** calibration runs.
3. The output is `params.calibrated.json`, which is hashed and committed **before** any test evaluation.

### 7.5 Success criteria (fixed before implementation)

| Gate | Criterion | Applies to | Meaningfulness rule |
|---|---|---|---|
| G-E1 | 100 % of emitted snapshots and results schema-valid; invariants I1–I7 hold | Evidence layer | — |
| G-E2 | Byte-identical output for identical input (3 repeats) | Evidence + rules | — |
| G-E3 | Explicit missing-data behaviour: every MISSING path is covered by a test | Evidence + rules | — |
| G-R1 | Every label has explicit rules, and every rule has at least one positive and one negative unit test | Rules | — |
| G-R2 | **All** adversarial tests ADV-1 … ADV-10 pass (unit level) | Rules | Critical: any failure fails Phase 1C |
| G-R3 | No elimination path to `application_bottleneck` (ADV-8 unit and FaultLab) | Rules | Critical |
| G-Q1 | Macro F1 ≥ 0.80 (run-level, test split) | Rules alone (primary); ML gated (secondary) | Valid only if ≥ 10 test runs per class. Otherwise reported with CIs and marked *not gate-valid*. |
| G-Q2 | Per-class recall ≥ 0.70 for each of the 7 fault classes | Same | As G-Q1; the Wilson lower bound is reported alongside |
| G-Q3 | INS-expected test runs: abstention ≥ 0.90, false assertion ≤ 0.10 | Rules; ML gated | ≥ 20 INS-expected test runs |
| G-Q4 | Coverage on fault runs ≥ 0.80 (abstention cannot hide errors) | Rules; ML gated | — |
| G-C1 | ML calibration: ECE ≤ 0.10 **and** calibrated Brier < uncalibrated Brier | ML | ≥ 200 test windows. Otherwise reported only. |
| G-F1 | Zero fabricated evidence: every evidence item's measurements resolve to retained raw samples | All | — |
| G-L1 | No leakage: feature-matrix column audit; no run in both splits; test untouched before artefacts are committed (hash log) | ML | Critical |
| G-P1 | A fresh `make phase1c` from a clean checkout regenerates the features, parameters, model and metrics byte-identically from the retained raw data | All | — |

**Revising a target:** any revision is documented in this file, with its reason, **before** test evaluation. After evaluation, targets are frozen.

## 8. Reproducibility

- **IDs:**
  - `experiment_id = fl-v1-<UTCdate>-<shortsha>`;
  - `run_id = <scenario_id>-s<seed>`;
  - `snapshot_id` and `measurement_id` are deterministic hashes (contract §10).
- **Recorded per run:**
  - scenario JSON;
  - Git commit;
  - image digest;
  - Docker and kernel version;
  - CPU governor, cpusets and `MemAvailable`/swap at start;
  - Ollama state (no model loaded);
  - collector versions.
- **Seeds:**
  - the scenario seed drives load-generator jitter and workload random choices;
  - the ML seed is fixed (`random_state=20261002`);
  - bootstrap seeds are fixed.
- **Data:**
  - raw samples are kept as `datasets/faultlab/v1/raw/<run_id>/*.jsonl.gz` (append-only, never edited);
  - derived data is `features.csv` plus `manifest.json` (SHA-256 of every raw file);
  - the dataset version is the manifest hash.
- **Artefacts:**
  - `params.calibrated.json`;
  - `model.joblib` with `model_card.json` (training runs, hyperparameters, calibration, metrics);
  - all of them hashed in `artifacts.lock`.
- **Commands:**
  - `make faultlab-run MATRIX=v1` (collection, resumable);
  - `make features`;
  - `make calibrate`;
  - `make train`;
  - `make evaluate` (refuses unless the artefacts are locked);
  - `make report`.

## 9. Resource budget and safety

| Item | Budget |
|---|---|
| RAM | Lab containers ≤ 2.5 GiB total, enforced with `--memory`; collectors < 200 MiB; **no LLM loaded** (Ollama idle) |
| Free RAM | Run abort if `MemAvailable` < 2 GiB (existing floor) |
| CPU | Lab on E-cores 16–23; collectors on one P-core; all stress bounded by cpuset and duration |
| Disk | < 2 GiB for the image plus raw data |
| Runtime | About 11 h, resumable |
| Network | Faults only on lab container interfaces in dedicated Docker networks. **`enp0s31f6` is never touched.** `safety_check.sh` runs before and after every run, and the campaign aborts on any failure. No `--privileged`, no host networking. `NET_ADMIN` is granted only to lab containers A and R. |
| Cleanup | Everything is labelled `sentinelai.faultlab=1`. After every run: `docker rm -f` by label and `docker network rm sl_faultlab_*`. A verify step checks that nothing is left. |
| Services | Nothing persistent is added. No Prometheus, databases or Kubernetes. |

## 10. Pilot (precedes the full matrix; separately approved)

| ID | Question | Pass criterion |
|---|---|---|
| PI-1 | Can the host read A's `/proc/<pid>/net/snmp` and `netstat`, or must it use `docker exec`? | One works at 1 Hz |
| PI-2 | Does the A–R–B routed topology work, with R netem invisible from A's counters? | A shows retransmissions while A's qdisc and interface drops stay at 0 |
| PI-3 | Does `run_delay ≈ throttled time` hold for pure throttling across quota levels? | Ratio within ±10 % across I1–I3 |
| PI-4 | Choose intensities I1–I3 by injection magnitude, and check whether softirq overload (and OV-11 backlog drops) is achievable on E-cores | Softirq hotspot fraction clearly above the CTRL range; else softirq is reported as *not reproducible* and its gate is waived **in advance** |
| PI-5 | Memory reclaim without OOM at the chosen M | PSI memory > CTRL range without `oom_kill` |
| PI-6 | Collector overhead and sample coverage | ≤ 2 % CPU, coverage ≥ 0.99 |

The pilot runs no evaluation and fits nothing. Its outputs are intensity choices and feasibility verdicts, recorded before the matrix is generated.

## 11. Future LLM interface (definition only; not built in Phase 1C)

- **Input to the LLM:** the incident summary; `EvidenceSnapshot` and `DiagnosticResult` as strict JSON; the candidate list with statuses; contradictions; missing measurements; and the available tools (Phase 1B schemas plus collector re-query tools).
- **Allowed LLM actions:**
  - request additional measurements or tool calls;
  - state whether the evidence is sufficient;
  - challenge the decision by naming specific contract predicates;
  - produce the explanation.
- **Constraints:**
  - the LLM **cannot** set `decision`;
  - a challenge triggers re-collection and re-evaluation **by the engine**;
  - an override is possible only if the re-evaluated snapshot changes the rule outcome.

## 12. Implementation plan (after the design gate)

Each milestone is its own commit:
- **M1:** contract JSON (registry, labels, precedence) plus `schema.py` plus `tests/evidence`.
- **M2:** rule engine plus `tests/rules`, with all ADV unit tests (runnable before any FaultLab data exists).
- **M3:** collectors plus features/normalisation (against live host data).
- **M4:** FaultLab workload, load generator, topology, injectors, verifier, safety hooks.
- **M5:** the pilot (PI-1 … PI-6), followed by **review**.
- **M6:** matrix generation (splits fixed) and collection.
- **M7:** calibration, then ML training (train only), then artefact lock.
- **M8:** test evaluation and `PHASE_1C_EVALUATION.md`.
