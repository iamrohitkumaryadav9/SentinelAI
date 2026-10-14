# Phase 1C M8 evaluation protocol

Status: **committed before any test outcome is read.**

Basis:
- owner authorisation C7-21 (`d154eab`) and integrity amendment AMD-32 (`d446274`);
- design §5.3–5.4, §6.6, §7.1–7.2 and §7.5;
- the M7 lock `afdde9a` (`datasets/faultlab/v1/m7/lock.json`).

This document fixes how the design's evaluation is executed. Where the design leaves a choice open, the choice is
made here (M8-1 … M8-12), before the evaluation runs. Nothing below may change after test outcomes are read.

## M8-0 Pre-execution checks

`experiments/faultlab/m8.py` refuses before it opens any test run's raw file unless every check holds:
1. HEAD descends from the lock commit `afdde9a`.
2. `lock.json` and the six paths it locks are unchanged since `afdde9a`, and each file's SHA-256 equals the lock.
3. There is no tracked modification in the working tree, and no untracked file in the integrity tree scope (`src`,
   `ebpf`, `contract`, `scripts`, `tests`, `datasets`).
4. `datasets/faultlab/v1/m8/evaluation.json` does not exist and has never been committed. This is the one run.
5. The test split is the matrix's `split = "test"` runs: 106 runs (72 SF, 14 CTRL, 20 overlap). No run ID appears
   in two splits, and every test run's raw files are listed in the manifest.
6. The model's columns pass the G-L1 closed-set column audit.

Each raw file's SHA-256 is verified again when it is unpacked, before any diagnosis. The tool reads raw evidence
from temporary unpacked copies. It never writes to `datasets/faultlab/v1/raw`, the manifest, the matrix or the M7
artefacts.

## M8-1 Populations

| Name | Runs | Used for |
|---|---|---|
| **P** (primary) | test SF (72: 6 classes × 12) + test CTRL (14) = 86 | G-Q1, G-Q2, G-Q4, G-C1, all per-class tables |
| **INS** | test CTRL (14) + test overlap runs whose expected primary is `INSUFFICIENT_EVIDENCE` without an acceptable set (OV-4, 5, 8, 9, 10: 10) = 24 | G-Q3 |
| **R** (robustness) | all 20 test overlap runs (OV-1 … OV-10) | robustness, not gated |

SENS, PI-3 and train runs are not read. OOD is deferred (P-4) and not evaluated.

## M8-2 Windows and decisions

- **Windows:** three scored windows per run (AMD-8), built from the run's committed ticks with the engine values of
  `params.calibrated.json` under contract 0.6.0-draft.
- **Run decision:** the mode of the three window decisions; a tie goes to `INSUFFICIENT_EVIDENCE` (design §7.2).
- **Label:** a run's expected label is its ground-truth primary label (CTRL: `INSUFFICIENT_EVIDENCE`).

## M8-3 Systems (design §7.1)

1. **Rules alone (primary):** the rule engine's decision.
2. **ML alone, raw:** the argmax of the locked model's calibrated probabilities (`model.json`, evaluated by
   `m7.predict_proba_json`).
3. **ML alone, gated:** `INSUFFICIENT_EVIDENCE` when the maximum probability is below `τ_ML` (0.0), or when a
   Required clause of the predicted label is not TRUE in that window (design §5.3, ML-7).
4. **Combined policy (design §5.4):** the rules' result with an `MLAdvisory` attached.
   - The advisory holds the raw calibrated probabilities, and `agrees_with_rules` = (ML argmax = rule decision).
   - `ML_DISAGREEMENT` is added when ML disagrees with probability ≥ `τ_DISAGREE` (0.9). Confidence is then lowered
     one level: HIGH to MEDIUM; MEDIUM to LOW only for an abstention, because an asserted decision never goes below
     MEDIUM.
   - The decision is never changed.
   - Every combined result is re-validated by the contract model (`DiagnosticResult`) and by
     `validate_against_snapshot`.

## M8-4 Metrics (design §7.2), per system, on P unless stated

- **F1:** macro F1 over the **7** outcomes present (6 fault classes + `INSUFFICIENT_EVIDENCE`). The design's "8
  outcomes" includes `softirq_overload`, which is not in the matrix (R2-E: not feasible); this is a recorded
  deviation, and it is not counted as a zero.
- **Per class:** precision, recall and F1, each with a Wilson 95 % interval (z = 1.96); the run-level confusion matrix;
  the counts of `tcp_retransmissions → network_packet_loss`, `network_packet_loss → tcp_retransmissions` and
  `cpu_throttling → cpu_contention`.
- **Abstention:**
  - on INS: the abstention rate and the false-assertion rate (any fault label);
  - on P's fault runs: coverage (share with a fault label) and selective accuracy (share correct among those
    asserted);
  - risk–coverage: for ML, over every threshold on the maximum probability (window level); for rules, the single
    operating point.
- **Window level:** the same macro F1 and the window confusion matrix (secondary).
- **Calibration (ML only):** Brier, ECE (10 equal-mass bins, top label) and the reliability bins, on P's windows. The
  uncalibrated reference is the locked forest's own `predict_proba`.
- **Robustness (R):**
  - a run is correct when its primary equals the expected primary, or is one of the acceptable primaries (OV-7);
  - contributing labels are reported (OV-2 expects `tcp_retransmissions` contributing);
  - per family.
- **Disagreement policy:** agreement rate, flag counts and the confidence distribution before and after the policy.
- **Feature importance (design §5.3):** grouped permutation importance of the raw model on P's test windows. For each
  column key, its four columns are permuted between runs as whole runs; 5 repeats with seed 20261002; the drop in
  window macro F1 is measured. It is reported, never used for a decision. Logistic-regression coefficients do not
  apply, because the locked model is a random forest.

## M8-5 Gates (design §7.5)

| Gate | Criterion | System | Population | Valid if |
|---|---|---|---|---|
| G-Q1 | macro F1 ≥ 0.80 (run level) | rules alone (primary); ML gated (secondary) | P | ≥ 10 test runs per class (12) |
| G-Q2 | recall ≥ 0.70 for each of the 6 fault classes (Wilson lower bound reported) | same | P | as G-Q1 |
| G-Q3 | abstention ≥ 0.90 and false assertion ≤ 0.10 | rules; ML gated | INS | ≥ 20 runs (24) |
| G-Q4 | coverage on fault runs ≥ 0.80 | rules; ML gated | P | — |
| G-C1 | ECE ≤ 0.10 and calibrated Brier < uncalibrated Brier | ML | P windows | ≥ 200 windows (258) |
| G-L1 | column audit, no run in two splits, artefacts committed and hashed before the evaluation | ML | — | critical |
| G-E1 | every test snapshot and result is schema-valid, with invariants I1–I7 (`validate_against_snapshot`) | evidence + rules + combined | all test windows | — |
| G-E2 | byte-identical rule result for identical input, 3 repeats | rules | all test windows | — |

G-R1 … G-R3 and G-F1 are unit-level and are reported from the test suite at the evaluation commit. G-P1 (fresh
regeneration from a clean checkout) is not executed in M8 and is recorded as not verified.

## M8-6 One run, everything kept

- The evaluation is a single invocation of `m8.py evaluate`.
- It writes `datasets/faultlab/v1/m8/evaluation.json` (add-only). That file holds every window's rule result
  summary, ML probabilities, gated output and combined result, every metric and every gate. It is committed
  unchanged, whatever the outcome.
- If the run fails after reading test data, its log is kept. A re-run is a protocol deviation and is reported as
  such. Nothing locked (model, thresholds, parameters, contract, collector, features, criteria) changes after
  evaluation.

## M8-7 Rehearsal

Before the test run, the same code path runs once in **rehearsal mode** on the **train** split into a scratch
directory (`m8.py evaluate --rehearsal-train --out <scratch>`). It exercises every computation without reading a
test run. Rehearsal outputs are never committed and are not test results.
