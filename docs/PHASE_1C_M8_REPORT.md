# Phase 1C M8 report: one-time test evaluation

Status: **evaluated once and complete.**
- **G-Q1 fails** for the primary system (rules alone): macro F1 0.765 < 0.80. It passes for ML gated, the secondary
  system (0.861).
- **G-Q2 fails** for both systems.
- G-Q3, G-Q4, G-C1, G-E1, G-E2 and G-L1 pass.

Every result is kept as produced, in `datasets/faultlab/v1/m8/evaluation.json`.

## 1. Provenance

| Item | Value |
|---|---|
| Authorisation | C7-21 (`d154eab`), owner, 2026-10-14 |
| Integrity amendment | AMD-32 (`d446274`) |
| Protocol | `docs/PHASE_1C_M8_EVALUATION_PROTOCOL.md`, committed in `d156cb1` before any test outcome was read |
| Evaluation code commit | `d156cb1c6e389c02aefc287cf9faf29a9cbea5bb` (descends from the lock `afdde9a`) |
| Command | `.venv/bin/python experiments/faultlab/m8.py evaluate` (one invocation, exit 0) |
| Result | `datasets/faultlab/v1/m8/evaluation.json`, SHA-256 `6f9437923b9c2e6c4e0ba7e3573ce378bf9b2fc3b2ed6c440fa8cd48975ae0b4` |

Locked artefacts. Their SHA-256 matched the lock before the run, and they are unchanged since `afdde9a`:

| File | SHA-256 |
|---|---|
| `m7/calibration_report.json` | `0b93e27c8a42fafeee5c2db693fcae76fd72cf97f87f03f8a0ff01ed5b544d53` |
| `m7/params.calibrated.json` | `8df190715fa5d5df56e6e84a4cf75c3dad9f87f02928c0a1e84b05a440402e7a` |
| `m7/model.json` | `6b45c8c08f8e2ce73f30a35b4a9ec79e40024f398a094d6487c9fb9c122a068c` |
| `m7/training_report.json` | `9a13f232d89738c81f3194e65fdc0d648876c7628c3c0146a8bf57ca11e6ac19` |
| `matrix.json` | `5e4df932cd79c17754e7539cf5c7f45faf89a33b3714f6bff5512dabe785b560` |
| `manifest.json` | `2bf04b630d676581a1dcc0209b5e237685346d3f49704ec7704037bb01698054` |

**Pre-execution checks (M8-0), all passed before any test raw file was opened:**
- HEAD descends from the lock;
- the locked paths are unchanged and their hashes match;
- no tracked modification, and no untracked file in the integrity tree scope;
- the output was absent and had never been committed;
- run IDs are unique across splits;
- the test split has the expected composition (72 SF, 14 CTRL, 20 overlap);
- every test run is in the manifest;
- the model passes the column audit;
- the matrix is the locked matrix.

Each raw file was verified against the manifest again before unpacking.

**Before the test run:**
- a train-only rehearsal (M8-7, scratch) reproduced the committed M7 rules-alone train result exactly (macro F1
  0.7002, same confusion matrix);
- the full suite passed at `d156cb1` (1576 tests, 1 skip).

**Populations (M8-1):**
- P: 86 runs (72 SF, 12 per class, + 14 CTRL), 258 windows.
- INS: 24 runs.
- R: 20 overlap runs.

No train, SENS or PI-3 run was read for the evaluation.

## 2. Gates (design §7.5; thresholds fixed before evaluation)

| Gate | Rules alone (primary) | ML gated (secondary) | Valid |
|---|---|---|---|
| **G-Q1** macro F1 ≥ 0.80 | **0.765: FAIL** | 0.861: pass | yes (12 runs per class) |
| **G-Q2** recall ≥ 0.70 for every fault class | **FAIL**: application 0.583, memory 0.417, retransmissions 0.417 | **FAIL**: application 0.583, retransmissions 0.417 | yes |
| G-Q3 INS abstention ≥ 0.90, false assertion ≤ 0.10 | 1.00 / 0.00: pass | 1.00 / 0.00: pass | yes (24 runs) |
| G-Q4 coverage on fault runs ≥ 0.80 | 0.819: pass | 0.833: pass | — |
| G-C1 ECE ≤ 0.10 and calibrated Brier < uncalibrated | — | ECE 0.046; Brier 0.0051 < 0.0258: pass | yes (258 windows) |
| G-E1 schema-valid results, invariants I1–I7 | 318 / 318 windows (rules and combined): pass | | — |
| G-E2 byte-identical output, 3 repeats | 318 / 318: pass | | — |
| G-L1 no leakage | column audit pass; no run in two splits; artefacts committed and hashed before the evaluation: pass | | critical |

Not evaluated in M8:
- G-R1 … G-R3 and G-F1 are unit-level gates and are covered by the test suite at the evaluation commit;
- G-P1 (fresh regeneration from a clean checkout) was **not verified**.

## 3. Results on P (run level)

**Rules alone (primary).** Macro F1 0.765; window-level macro F1 0.761.

| Class | Runs | Precision [Wilson 95 %] | Recall [Wilson 95 %] | F1 |
|---|---|---|---|---|
| cpu_contention | 12 | 1.00 [0.76, 1.00] | 1.00 [0.76, 1.00] | 1.00 |
| cpu_throttling | 12 | 1.00 [0.76, 1.00] | 1.00 [0.76, 1.00] | 1.00 |
| network_packet_loss | 12 | 1.00 [0.74, 1.00] | 0.917 [0.65, 0.99] | 0.957 |
| tcp_retransmissions | 12 | 1.00 [0.57, 1.00] | **0.417** [0.19, 0.68] | 0.588 |
| memory_pressure | 12 | 1.00 [0.57, 1.00] | **0.417** [0.19, 0.68] | 0.588 |
| application_bottleneck | 12 | 0.50 [0.27, 0.73] | **0.583** [0.32, 0.81] | 0.538 |
| INSUFFICIENT_EVIDENCE | 14 | 0.519 [0.34, 0.69] | 1.00 [0.79, 1.00] | 0.683 |

- **Confusion:**
  - every contention, throttling and CTRL run is correct;
  - loss: 11 correct, 1 abstains;
  - retransmissions: 5 correct, **7 decided application_bottleneck**;
  - memory: 5 correct, 7 abstain;
  - application: 7 correct, 5 abstain.
- **Cross-class errors:** 7 runs, all `tcp_retransmissions → application_bottleneck`.
  - The named confusions are all 0: `tcp_retransmissions → network_packet_loss`, `network_packet_loss →
    tcp_retransmissions`, `cpu_throttling → cpu_contention`.
- **Abstentions:** 13 of 72 fault runs (memory 7, application 5, loss 1); all 14 CTRL runs abstain.
- **Coverage and selective accuracy:** coverage on fault runs 0.819, selective accuracy 0.881.

**ML gated (secondary).** Macro F1 0.861.
- Recall is 1.0 for contention, throttling, loss and memory, 0.583 for application and 0.417 for retransmissions.
- Precision is 1.0 for every fault class.
- It makes no cross-class error; the 7 retransmission runs and 5 application runs abstain.
- Coverage 0.833.

**ML raw.** Macro F1 1.000: every one of the 86 runs and 258 windows is correct, with risk 0 at every coverage.

**Combined policy.**
- Decisions are identical to rules alone (0 of 258 windows changed), so all of its metrics equal the rules'.
- ML agrees with the rules in 197 of 258 windows, and `ML_DISAGREEMENT` is raised in 50.
- Confidence moves from HIGH 125 / MEDIUM 52 / LOW 81 to HIGH 104 / MEDIUM 73 / LOW 81.
- Every combined result passed the contract model and `validate_against_snapshot`.

**Calibration (ML, 258 windows).**
- Brier 0.0051 (uncalibrated 0.0258); ECE 0.046 (uncalibrated 0.076).
- Every reliability bin has accuracy 1.00 at confidence 0.89–0.97: the model is under-confident.
- `τ_ML` = 0.0, so confidence never abstains.

**Robustness (R, 20 overlap runs, not gated).** All four systems are correct on 20/20 runs (OV-1 … OV-10).
- On OV-7 (quota + contender, acceptable set), rules decide `cpu_contention` and ML decides `cpu_throttling`; both are
  acceptable.
- The rules' choice rests on the D-6 inflated run-delay excess (C7-20 caveat).

**Permutation importance (raw ML, grouped by run).** The baseline window macro F1 is 1.0. The largest mean drop is
0.003 (`app.latency_ms` P50); every other key is ≈ 0. The model's evidence is redundant across feature groups, and
no single group carries it. This is reported only, and was not used for any decision.

## 4. Breakdown by intensity and mechanism (rules alone, descriptive)

| Class | I1 | I2 (unseen in training) | I3 | Single level |
|---|---|---|---|---|
| contention | 4/4 | 4/4 | 4/4 | |
| throttling | 4/4 | 4/4 | 4/4 | |
| loss | 3/4 | 4/4 | 4/4 | |
| retransmissions | 3/4 | 2/4 | **0/4** | |
| application | 0/3 | 1/3 | 2/2 | pool 4/4 |
| memory | | | | 5/12 |

- **Retransmissions.** Path loss (`netem_loss_r_egress`) is correct at I1 and I2 (4/4) and fails at I3 (0/2). Rate
  limiting (`netem_rate_r`) is correct in 1 of 6 runs. Every miss is decided `application_bottleneck`. This is the
  mechanism recorded in C7-19: TCP falls below `SEG_MIN`, or rate limiting does not retransmit, and AB.R3 is then not
  blocked.
- **Application.** The 5 misses are dependency delay at I1 (2) and lock hold at I1/I2 (3), and all of them abstain.
- **Memory.** The 16 abstaining windows give `NO_IMPACT_OBSERVED` (C7-13) and 3 give `CONFLICT_UNRESOLVED`.

## 5. Comparison with training and validation

| Quantity | Train / validation (M7) | Test (M8) | Gap |
|---|---|---|---|
| Rules alone macro F1 (SF + CTRL) | 0.700 (train, in-sample thresholds) | 0.765 | +0.065 |
| Rules retransmission recall | 0.375 | 0.417 | ≈ |
| Rules memory recall | 0.125 | 0.417 | +0.29 |
| Rules application precision / recall | 0.50 / 0.625 | 0.50 / 0.583 | ≈ |
| Rules retransmission → application runs | 5 / 8 | 7 / 12 | ≈ |
| ML gated run macro F1 | 0.878 (validation) | 0.861 | −0.017 |
| ML gated retransmission recall | 0.38 | 0.417 | ≈ |
| ML raw run macro F1 | 0.945 (validation) | 1.000 | +0.055 |
| ML ECE | 0.059 (validation) | 0.046 | ≈ |

- **No adverse generalisation gap.** The test results are at or above the train and validation figures. The two
  failing gates fail on test for the same structural reasons already visible on train (C7-13, C7-19).
- **The unseen I2 intensity** is handled as well as I1/I3 for contention, throttling and loss.
- **Retransmission recall gets worse with intensity:** 3/4 at I1, 2/4 at I2, 0/4 at I3. Stronger impairment pushes TCP
  below `SEG_MIN`.
- **ML raw is perfect on test**, higher than on validation. The column audit and split checks pass. The likely reason
  is that FaultLab's fault signatures are highly separable. OOD generalisation is deferred and untested, so this must
  not be read as field accuracy.

## 6. Failed gates, limitations and deviations

**Failed gates**
- G-Q1 for rules alone.
- G-Q2 for rules alone (application, memory, retransmissions) and for ML gated (application, retransmissions).

**Known limitations**

| Limitation | Decision |
|---|---|
| Memory abstains when no user-visible impact is observed | C7-13 |
| Retransmissions are diagnosed as application under TCP collapse or rate limiting | C7-19 |
| Application metrics are histogram-quantised | C7-18 |
| `THR_RATIO_MIN` is a declared value | C7-17 |
| The run-delay excess assumes one runnable thread; OV-7 PR-3 reading caveat | D-6, C7-20 |
| The ML model was used although it missed G-Q2 on validation | ML-6 |
| OOD not evaluated | P-4 |
| G-P1 not verified | — |

**Deviations and interpretations, all fixed before evaluation**
- Macro F1 is over 7 outcomes: `softirq_overload` is not in the matrix (R2-E).
- The populations P, INS and R are defined in M8-1.
- The combined policy is implemented in the evaluation tool, since no runtime implementation existed, and its
  results are validated by the contract.
- The disagreement test uses the raw ML label (ML-8).

**Protocol conduct**
- The test evaluation ran once, and nothing was re-run.
- No model, threshold, parameter, contract, collector, feature or criterion was changed after test outcomes were
  read.
