# Phase 1C M7 calibration report

Status: **contract parameters calibrated on the train split.** The ML stage follows in the same milestone (§5).
The artefact is `datasets/faultlab/v1/m7/calibration_report.json` (SHA-256
`0b93e27c8a42fafeee5c2db693fcae76fd72cf97f87f03f8a0ff01ed5b544d53`), produced once by
`experiments/faultlab/m7.py calibrate` at `cb77c9b`. It applies the objectives in
`docs/PHASE_1C_M7_CALIBRATION_OBJECTIVES.md` (C7-1 … C7-20, committed before the run). Only train SF (48) and train
CTRL (10) runs were read. No test, SENS or PI-3 run was read.

These are train-split numbers. They are in-sample for the thresholds and are no estimate of test performance; G-Q1 …
G-Q4 are judged in M8 only.

## 1. Parameters

| Parameter | Value | Rule | Train FP | Train recall |
|---|---|---|---|---|
| `COV_MIN`, `N_BASE_MIN` | 0.99, 45 | C7-4 | — | — |
| `W`, `B` | 24 s, 45 s | fixed | — | — |
| `Z_MODERATE`, `Z_STRONG` | 0.4762, 0.9992 | C7-2 | — | — |
| `R_MODERATE`, `R_STRONG` | 1.0, 1.0547 | C7-2 | — | — |
| `SEG_MIN` | 969.17 segs/s | C7-4 | — | — |
| `DROP_ABS_MIN` | 4.625 pkts/s | C7-1 | 0 | 1.0 |
| `DROP_FRAC_MIN` | 0.002353 | C7-1 | 0 | 1.0 |
| `RT_FRAC_MIN` | 8.734 × 10⁻⁵ | C7-1 | 0.0079 | 0.625 (short of 0.90) |
| `RT_RATE_MIN` (not read by the engine) | 0.0833 | C7-1 | 0.0079 | 0.625 |
| `THR_RATIO_MIN` | **0.5, declared** | C7-17 | — | (train ratio is 1.0 in all 24 windows) |
| `THR_TIME_MIN` (not read) | 0.7996 | C7-1 | 0 | 1.0 |
| `RDX_MIN` (not read by any contract version) | 6.424 | C7-1 | 0.0067 | 0.0 |
| `SAT_MIN` | 0.7362 | C7-1 | 0.0067 | 1.0 |
| `PSI_MEM_MIN` | 0.0350 | C7-1 | 0 | 1.0 |
| `RECLAIM_MIN` | 60 240 | C7-1 | 0 | 1.0 |
| `REFAULT_MIN` (not read) | 60 237 | C7-1 | 0 | 1.0 |
| `APP_WAIT_MIN` | 25.6 ms | C7-12 (negatives CTRL only) | 0 | 0.417 (short of 0.90) |
| `APP_SHARE_MIN` | 0.5 | C7-16 (no negatives) | not measurable | 1.0 |
| `SI_ABS_MIN`, `SI_RATIO_MIN`, `SI_SHARE_MIN` | 0.01896, 6.452, 0.009438 | C7-7 (zero firing) | — | — |
| `IMPACT_MIN` | 1.0 (just above) | C7-8 | 0 of 30 CTRL | — |
| `DOM_RATIO` | 3.0 | C7-8 (all grid values tie at 0.7002; tie to the larger) | — | — |
| `KFREE_REASONS_LOSS` | {QDISC_DROP, TC_INGRESS} | C7-5 | — | — |
| `τ_DISAGREE` | set by the ML stage | C7-8 | — | — |

37 features had no train CTRL value above 0 and received the minimum floor (10⁻⁶), as listed in the report.

## 2. Train evaluation (rules alone, run level, 58 runs)

| Class | Runs | Precision | Recall | F1 |
|---|---|---|---|---|
| cpu_contention | 8 | 1.00 | 1.00 | 1.00 |
| cpu_throttling | 8 | 1.00 | 1.00 | 1.00 |
| network_packet_loss | 8 | 1.00 | 0.875 | 0.933 |
| tcp_retransmissions | 8 | 1.00 | 0.375 | 0.545 |
| memory_pressure | 8 | 1.00 | 0.125 | 0.222 |
| application_bottleneck | 8 | 0.50 | 0.625 | 0.556 |
| INSUFFICIENT_EVIDENCE (CTRL) | 10 | 0.476 | 1.00 | 0.645 |

**Macro F1: 0.700.**

**Abstentions.** 11 of 48 fault runs abstain:

| Class | Runs abstaining | Windows abstaining |
|---|---|---|
| memory | 7 | 18 |
| application | 3 | 9 |
| loss | 1 | 5 |
| retransmissions | 0 | 2 |

All 10 CTRL runs (30 windows) abstain.

**Cross-class false positives.** 5 runs (15 windows), all of them `tcp_retransmissions → application_bottleneck`.
No other fault class is decided as another. There are no `retransmissions ↔ loss` and no
`throttling → contention` errors.

## 3. Findings and limitations (owner decisions C7-17 … C7-20)

- **`THR_RATIO_MIN` declared (C7-17).** `throttle.ratio` is 1.0 in every train throttling tick: 8 threads on one CPU
  with a demand of 0.18–0.28 cores, against quotas of 0.2 and 0.075 cores. With no negative windows the objective
  cannot discriminate. 0.5 is an engineering value, "a majority of enforcement periods throttled"; it changes no train
  decision.
- **`APP_SHARE_MIN` (C7-18).** The application metrics are log2 histogram buckets (3.2 · 2^k ms), so the share takes
  values near 0.5 or 1.0. The threshold fires in 101 of the 111 train windows where the share is defined, in every
  fault class. AB.R2 therefore separates fault windows from CTRL, not classes from each other. Any θ in (0, 0.5] gives
  the same train decisions.
- **Retransmission → application (C7-19).**
  - In the five runs, AB.R1 holds through pool rejections and the closed-set events (POOL_EXHAUSTED, QUEUE_FULL).
  - AB.R3 is not blocked:
    - in four runs `tcp.out_segs_rate` falls below `SEG_MIN`, so RT is not evaluable;
    - rate limiting at I3 (`netem_rate_r`) delays without retransmitting;
    - one run (I1) has the thin signal accepted under C7-14.
  - Any negative set beyond CTRL removes these errors only by making the application class undiagnosable (train app
    recall 0, macro F1 0.598).
  - No contract change before M8.
- **Memory (C7-13).** 7 of 8 memory runs abstain (`NO_IMPACT_OBSERVED`), as accepted.
- **D-6 (C7-20): an invalid contract assumption.** `sched.run_delay.target` sums run delay over threads, while
  `throttle.time_rate` is the per-cgroup throttled wall time.
  - Each runnable thread accrues about that wall time while throttled: 0.895 s/s against 0.800 at I1, 0.96 against
    0.925 at I3.
  - So the derived `sched.run_delay_excess.target` is 4.07–6.42 under throttling, above contention (0.31–4.03).
  - The 2026-10-02 equality came from the one-thread R2-C/R2-D target. The collector implements the registry
    definitions exactly.
  - Caveat: on OV-7 (quota + contender) PR-3 decides "contention primary, throttling contributing" from the inflated
    excess. That outcome is in OV-7's acceptable set, but it should not be read as a measured dominance.
  - The per-thread revision is deferred.
- **`RDX_MIN`.** No clause, predicate or precedence rule of any contract version reads it (M2 report I-14). It is
  calibrated and recorded only, and its recall of 0 reflects D-6.

## 4. Reproduction

`.venv/bin/python experiments/faultlab/m7.py calibrate --out <dir>` at `cb77c9b` on the committed dataset writes
this report. The procedure is deterministic: nearest-rank percentiles, sorted candidates, no random choice. A
byte-identical re-run (G-P1) was not repeated here, because calibration was run once by instruction.

## 5. ML stage

See `datasets/faultlab/v1/m7/training_report.json` and §6 below. The ML is advisory; the rule engine's decision is
the decision of record (design §5.4).
