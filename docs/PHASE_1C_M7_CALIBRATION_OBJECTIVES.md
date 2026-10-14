# Phase 1C M7 calibration objectives

Status: **committed before any calibration** (amended before any calibration: §2 steps 5–6, where `τ_DISAGREE` is set;
amended after a train-only dry run and before any calibration artefact: C7-11 … C7-14, §3 and §5; amended after a
second train-only dry run and before re-running it: C7-16, §3 "No negatives" and §3 "Train evaluation"; amended
after the training-only investigation and before the calibration run and ML training: C7-17 … C7-20, §3 "ML
interpretations", §5) (design §7.4 "each parameter's objective is written in
`params.calibration.md` before calibration runs"; this file is that document). No calibration has been run and no
M6 window has been evaluated by the rule engine when this file is committed.

Basis: `FZ-M7-PLAN` (C7-1 … C7-10, owner, 2026-10-14), contract §6, design §5.2–5.4, §6.6, §7.4; windows AMD-6,
AMD-8, `FZ-TTRANS` (T_TRANS 16 s, W 24 s).

## 1. Data

- **Only the train split** of `datasets/faultlab/v1/matrix.json` is read: train single-fault (SF) runs and train CTRL
  runs for calibration (C7-9). Test, SENS and PI-3 runs are never read in M7 before the artefact lock. The tool refuses
  a run whose matrix split is not `train`.
- Every run used passed its pipeline checks (M6: all did). Its raw files are unpacked from the committed dataset and
  verified against the manifest before use.
- **Windows (C7-10):** per run, the baseline is the 45 s before fault onset (AMD-6) and the scored windows are three
  tumbling 24 s windows starting at onset + 16 s (AMD-8): ticks [61, 85), [85, 109), [109, 133) of the 136-tick
  collection (onset at tick 45). CTRL runs use the identical schedule. One snapshot is built per scored window from
  the run's committed ticks.
- A window's class is its run's class (CTRL windows: none). A measurement that is MISSING, INVALID or below coverage in
  a window is left out of that parameter's counts, and the count left out is reported.

## 2. Order (each stage uses only the stages before it)

1. **Data quality (C7-4)** from tick coverage: `COV_MIN`, `N_BASE_MIN`; then the window snapshots are built.
2. **Noise floors (C7-3)** and **deviation bands (C7-2)** from train CTRL windows.
3. **`SEG_MIN` (C7-4)**, **class thresholds (C7-1)**, **softirq parameters (C7-7)**, **`IMPACT_MIN` (C7-8)**.
4. **`DOM_RATIO` (C7-8)** with every other parameter fixed.
5. `datasets/faultlab/v1/m7/calibration_report.json`, holding every rule-engine parameter of stages 1–4, is
   committed (add-only) before ML training reads any engine output.
6. ML (design §5.2–5.3) with `τ_ML` and `τ_DISAGREE` (C7-8). `τ_DISAGREE` belongs to the combination policy
   (design §5.4) and is not read by the rule engine, so it can only be set here; while stages 1–4 run the engine with
   a placeholder for it. `params.calibrated.json` is then written with exactly the committed engine values of the
   report plus `τ_DISAGREE` (the tool refuses if any engine value differs), with the model, and the lock (`lock.json`:
   hashes of the parameters, the model, the matrix and the dataset manifest) is committed before any test run is read
   (M8).

## 3. Objectives per parameter

| Parameter | Statistic and data | Rule |
|---|---|---|
| `W`, `B` | — | Fixed: 24 s, 45 s (`FZ-TTRANS`, AMD-7) |
| `COV_MIN` | Per measurement, its coverage in the window, over every feature in every train window | The largest value ≤ 0.99 with ≥ 99 % of those measurements at or above it (C7-4) |
| `N_BASE_MIN` | Per measurement, its baseline sample count, over the same set | The largest value with ≥ 99 % of baselines at or above it (C7-4) |
| `floor[f]` (every feature) | The feature's per-window value in train CTRL windows | 99th percentile (nearest rank); a feature with no CTRL value gets the smallest positive value of its unit (C7-3) |
| `Z_MODERATE`, `R_MODERATE` | `robust_z` and `ratio` of every feature in train CTRL windows | 99th percentile (C7-2) |
| `Z_STRONG`, `R_STRONG` | Same | 99.9th percentile; never below the moderate band (C7-2) |
| `SEG_MIN` | `tcp.out_segs_rate` in train CTRL windows | 1st percentile (C7-4) |
| `KFREE_REASONS_LOSS` | — | Declared: {`QDISC_DROP`, `TC_INGRESS`} (C7-5) |

**Class thresholds (C7-1).** For a threshold θ on a feature x (TRUE when x ≥ θ), with **positives** = the train
windows of its own class and **negatives** = the train windows of CTRL and of the other classes:
FP(θ) = share of negatives with x ≥ θ, recall(θ) = share of positives with x ≥ θ. Candidates are the observed values
of x (plus 0). **θ = the smallest candidate with FP(θ) ≤ 0.01.** If recall(θ) < 0.90 the false-positive limit still
holds and the shortfall is reported.

**No negatives (C7-16).** If a class threshold has **no negative window with a defined value**, FP(θ) = 0 for every θ
and the rule above returns 0, so it would bound nothing. The second dry run hit this for `THR_RATIO_MIN` (the ratio
exists only under a quota) and `APP_SHARE_MIN` (CTRL latency does not rise). For such a threshold instead:

- **Percentile.** θ = the 1st percentile of the positives by nearest rank. Sort the n positive values ascending,
  keeping duplicates; k = ⌈0.01 · n⌉; θ = the k-th value. For n ≤ 100, k = 1 and θ is the smallest positive value.
- **Undefined values.** A window's value is undefined, and the window is neither positive nor negative, when the
  statistic cannot be computed. That is: the measurement is absent, MISSING or INVALID, or below `COV_MIN`; or, for
  the wait share, the P99 latency or every wait component lacks an adequate baseline, or the latency did not rise
  (Δ ≤ 0). The engine judges AB.R2 FALSE there, whatever θ is. Undefined windows are counted and reported separately
  for own-class and other windows.
- **Ties.** A window fires when x ≥ θ, so every positive equal to θ fires; recall(θ) ≥ (n − k + 1) / n, which is 1 for
  n ≤ 100. θ is a single order statistic, so no tie-break between candidates is needed.
- **No positives.** If there is also no positive window with a defined value, calibration is refused.
- **Stop rule.** If θ ≤ 0, calibration stops for owner review. Nothing is written under `datasets/faultlab/v1/m7/`:
  the report is written only to a scratch output, marked stopped, and the tool exits non-zero. No other value is
  substituted. θ ≤ 0 makes the clause effectively unconditional. `throttle.ratio` lies in [0, 1], so CT.R3 (and CC.X1)
  would hold wherever a ratio exists. A share ≤ 0 admits windows whose app-level wait did not rise, so AB.R2 would no
  longer require any app-level wait.
- **Limitation.** With no negatives, such a threshold is bounded by the positives only. Its false-positive rate
  cannot be measured on the train split; the report states this, and M8 is where it is first tested.

| Parameter | Feature x | Own class | Note |
|---|---|---|---|
| `DROP_ABS_MIN` | each local drop source's rate (pkts/s): `net.drop.qdisc`, `net.drop.iface_rx`, `net.drop.iface_tx`, `net.err.iface`, `net.drop.softnet`, `net.drop.socket`, `net.drop.kfree_skb` (reasons in `KFREE_REASONS_LOSS`); per window the largest | `network_packet_loss` | |
| `DROP_FRAC_MIN` | drops / (packets + drops) of the interface sources | `network_packet_loss` | |
| `RT_FRAC_MIN` | `tcp.retrans_frac` | `tcp_retransmissions` | windows of `network_packet_loss` are neither positive nor negative: local loss causes retransmissions by mechanism (contract PR-1) |
| `RT_RATE_MIN` | `tcp.retrans_rate` | `tcp_retransmissions` | as above; not read by the current engine, recorded |
| `THR_RATIO_MIN` | — | `cpu_throttling` | **declared 0.5, not calibrated (C7-17)**; read by CT.R3 without a baseline (C7-11) and by CC.X1 |
| `THR_TIME_MIN` | `throttle.time_rate` | `cpu_throttling` | not read by the current engine, recorded |
| `RDX_MIN` | `sched.run_delay.target` minus the throttled time rate (excess waiting-cores) | `cpu_contention` | not read by the engine: no clause, predicate or precedence rule of any contract version references it (CC.R1 is `DEV(sched.run_delay_excess.target)` since v0.1.0; M2 report I-14); calibrated and recorded only |
| `SAT_MIN` | `cpu.util.cpuset` | `cpu_contention` | CC.R2 is its only required use |
| `PSI_MEM_MIN` | `psi.mem.some.target` | `memory_pressure` | |
| `RECLAIM_MIN` | `mem.reclaim.target` (MP.R1 alternative A3) | `memory_pressure` | |
| `REFAULT_MIN` | `mem.refault.target` | `memory_pressure` | not read by the current engine, recorded |
| `APP_WAIT_MIN` | the largest of the app wait features (`app.queue_wait_ms`, `app.lock_wait_ms`, `app.dependency_latency_ms` P99) | `application_bottleneck` | negatives are train CTRL windows only (C7-12) |
| `APP_SHARE_MIN` | the share of the latency increase explained by app-level wait (engine AB.R2 share: largest wait increase / P99 latency increase) | `application_bottleneck` | negatives are train CTRL windows only (C7-12) |

**Declared value (C7-17).** `THR_RATIO_MIN` = 0.5 is an engineering value, not a calibrated optimum.
- On the train split `throttle.ratio` is 1.0 in every tick of every throttling run: 8 threads on one CPU, an unthrottled
  demand of 0.18–0.28 cores, against quotas of 0.2 and 0.075 cores, so every enforcement period is throttled.
- Without a binding quota the ratio is undefined, or 0 for a non-binding quota (R2-D Q0).
- With no negatives the objective cannot discriminate; any value in (0, 1] separates the train data equally.
- 0.5 reads as "a majority of enforcement periods throttled", tolerating windows with unthrottled periods.
- It changes no train decision.
- Tested: 0.99 satisfies CT.R3, 0.0 does not.
- The report records the observed train distribution next to the declared value.

**Train evaluation (reported with the calibration, for owner review; train split only).** With every engine
parameter fixed at its calibrated value, each train SF and CTRL run is diagnosed in its three windows. The run
decision is the mode, with ties to `INSUFFICIENT_EVIDENCE` (AMD-8). Reported:
- per class (the six classes and `INSUFFICIENT_EVIDENCE`): precision, recall and F1 at run level, and the macro F1
  (as for `DOM_RATIO`);
- abstentions: runs and windows decided `INSUFFICIENT_EVIDENCE`, by true class;
- cross-class false positives: runs and windows of a fault class or CTRL decided as a different fault class, as a
  confusion matrix;
- for each threshold set under C7-16: the share of all train windows with a defined value in which it fires.

No test, SENS or PI-3 run is read.

**Softirq (C7-7).** `SI_ABS_MIN`, `SI_RATIO_MIN`, `SI_SHARE_MIN`: the smallest value with **zero** windows at or
above it over all train windows (the class is waived; no positives exist).

**`IMPACT_MIN` (C7-8).** The smallest value of `app.latency_ms` P99 deviation ratio with ≤ 1 % of train CTRL windows
at or above it.

**`DOM_RATIO` (C7-8).** With every other parameter fixed: the value in {1.25, 1.5, 2, 3} with the highest run-level
macro F1 of the rule engine over train SF and CTRL runs (run decision = mode of the three windows, ties to
`INSUFFICIENT_EVIDENCE`); a tie goes to the larger value (fewer dominance overrides).

**ML (C7-8, C7-9; design §5.2–5.3).** Training windows: train SF, CTRL and overlap runs except OV-7. Models in the
design's order (multinomial logistic regression, then random forest, then histogram gradient boosting), `GroupKFold`
(5 folds, groups = run) for hyperparameters and Platt calibration. `τ_ML` = the smallest probability threshold with
selective risk ≤ 10 % pooled over the folds' held-out windows; `τ_DISAGREE` = the value in {0.6, 0.7, 0.8, 0.9} with
the highest train macro F1 of the combined policy (design §5.4), a tie to the larger.

## 4. Fractions above 1 (C7-6)

`mem.util.target` and `psi.cpu.some.target` lose 1–2 W ticks when saturation makes the reading a hair above 1 (M6:
16 runs). This is a documented limitation; the collector is unchanged and the affected measurements follow the
`COV_MIN` / `PARTIAL` rules like any other.

## 5. Revisions after the train-only dry run (C7-11 … C7-14)

A dry run of stages 1–4 on the train split (no artefact written or committed; no test, SENS or PI-3 run read)
showed two defects and two findings. The owner decided (`FZ-M7-PLAN` revisions, `e6dc3e9`):

- **C7-11 (1A).** Throttling was never asserted, because v0.5.0 CT.R2 needed a baseline for `throttle.ratio`, which
  does not exist before the quota is applied. Contract v0.6.0-draft splits it (`docs/PHASE_1C_M7_CONTRACT_REVISION.md`).
- **C7-12 (2A).** App waits rise under every fault, so FP against other classes pushed `APP_WAIT_MIN` and
  `APP_SHARE_MIN` above every app window. Their negatives are CTRL windows only, like the C7-1 exception for
  retransmissions; separation from infrastructure classes is AB.R2/AB.R3's job.
- **C7-13 (3A).** Memory pressure without user-visible latency impact abstains by contract (`NO_IMPACT_OBSERVED`);
  accepted as a finding, and the memory recall is reported as it comes out, not tuned.
- **C7-14 (4A).** The thin retransmission signal at the weakest levels is accepted as recorded under R-4.
- **C7-16 (2A, `7a0b73d`).** A second train-only dry run, at contract v0.6.0 with C7-12 (scratch only), gave
  `THR_RATIO_MIN` = 0 and `APP_SHARE_MIN` = 0, both with no negatives. They now follow the no-negatives rule of §3,
  including its stop rule.

The objectives in §3 are otherwise unchanged. The dry-run numbers are not used: calibration is re-run from scratch.

- **C7-17 … C7-20 (owner, `f9d8c00`),** after a training-only investigation of the third dry run:
  - **C7-17:** `THR_RATIO_MIN` is declared (above).
  - **C7-18:** `APP_SHARE_MIN` = 0.5 (C7-16) is accepted. Limitations:
    - The application metrics are log2 histogram buckets (3.2 · 2^k ms), so the share takes values near 0.5 and 1.0.
    - Any θ in (0, 0.5] gives the same train decisions.
    - AB.R2 fires in every fault class where latency rose (contention 24/24, throttling 24/24, retransmissions
      19/22, loss 12/19, memory 7/7, application 15/15 defined windows).
    - It separates fault windows from CTRL, not classes from each other; class separation rests on AB.R3 (PR-4).
  - **C7-19:** C7-12 is kept. Five train `tcp_retransmissions` runs are decided `application_bottleneck`:
    - AB.R1 holds there through pool rejections and the closed-set events, not through the wait floor.
    - AB.R3 is not blocked: in four runs `tcp.out_segs_rate` is below `SEG_MIN`, so RT is not evaluable.
    - Rate limiting (`netem_rate_r`) at I3 delays without retransmitting.
    - Any negative set beyond CTRL removes the errors only by making the application class undiagnosable (train
      app recall 0).
    - No contract v0.7.0 before M8.
  - **C7-20:** D-6 is a finding, an invalid contract assumption:
    - `sched.run_delay.target` sums per-thread run delay (waiting-cores), while `throttle.time_rate` is the
      per-cgroup throttled wall time.
    - Each runnable thread accrues about that wall time while throttled. On the train split the run delay is 6.1–8.0
      × the throttled time (6–8 waiting threads), so `sched.run_delay_excess.target` grows with the number of
      runnable threads.
    - The 2026-10-02 equality came from the one-thread R2-C/R2-D target.
    - Caveat: PR-3 results on OV-7 (quota + contender) rest on the inflated excess.
    - The per-thread collector/contract revision is deferred.

**ML interpretations (written before training; design §5.2–5.4, C7-8, C7-9).**
- **ML-0 Data.** Windows of the train SF, CTRL and overlap runs; a run with an acceptable-set ground truth (OV-7) is
  excluded. The label is the run's ground-truth primary label (CTRL: `INSUFFICIENT_EVIDENCE`) for each of its three
  windows. The windows are built with the committed calibration report's engine values.
- **ML-1 Canonical scope.** A column key is (feature, scope kind, qualifier, aggregation). It never carries a scope
  ID, cpuset, path or name; the column audit (G-L1) rejects any column naming one.
- **ML-2 Values.**
  - Per key, from usable measurements only:
    - `z` = sign(z) · log1p(|z|), so very small floors cannot make z unbounded;
    - `log ratio` = log(max(ratio, 10⁻⁶));
    - the absolute value is the value for a fraction-unit feature and sign · log1p(|value|) otherwise.
  - Several instances of a key (per CPU) contribute the largest value of each column.
- **ML-3 Columns.**
  - Four per key: `z`, `log ratio`, `abs`, and a missing indicator.
  - A missing key is filled with 0 and its indicator set to 1, never imputed from other runs.
  - The keys are those usable in at least one training window, sorted.
- **ML-4 Model fitting and selection.**
  - Grids, tried in this order, with ties going to the earlier value:
    - LR: C ∈ {0.01, 0.1, 1, 10};
    - RF: 500 trees, `min_samples_leaf` ∈ {10, 5, 2, 1};
    - HGB: (learning rate, leaves) ∈ {(0.05, 7), (0.1, 7), (0.05, 15), (0.1, 15)}.
  - All three models use balanced class weights and seed 20261002.
  - Validation: outer `GroupKFold` with 5 folds (groups = run), with the inner `GroupKFold` (4 folds) choosing the
    hyperparameter by window-level macro F1 and fitting the Platt calibration.
  - The final model: hyperparameter by `GroupKFold` (5) on all training windows; Platt calibration with
    `GroupKFold` (5); `ensemble=False`.
- **ML-5 Gates on validation.** Computed on the pooled held-out windows:
  - G-Q1: gated run-level macro F1 ≥ 0.80;
  - G-Q2: gated run-level recall ≥ 0.70 for each fault class;
  - G-C1: ECE ≤ 0.10 and calibrated Brier < uncalibrated Brier.

  Models are tried in the design order; the first that meets every gate is used.
- **ML-6 No model meets the gates.** The kind with the highest validation gated run macro F1 is used (a tie goes to
  the simpler). The miss is reported, not tuned away.
- **ML-7 Abstention.**
  - `τ_ML` is the smallest threshold with selective risk ≤ 10 % on the pooled held-out calibrated probabilities. Risk
    is the error rate among the windows kept (max p ≥ τ).
  - The gated output also abstains when a Required clause of the predicted label is not TRUE in that window.
- **ML-8 `τ_DISAGREE`.** The combined policy keeps the rules' decision of record (design §5.4), so its macro F1 is the
  same for every grid value and the tie rule gives 0.9. The flag counts are reported.
- **Artefacts (add-only, AMD-30).** `params.calibrated.json` holds exactly the committed engine values plus
  `τ_DISAGREE`. `model.json` is a JSON re-implementation of the fitted calibrated model, checked to reproduce
  scikit-learn's probabilities within 10⁻⁹ with the same argmax on every training window. `training_report.json`
  and `lock.json` (SHA-256 of the artefacts, the matrix and the manifest) complete the set, and the lock is
  committed before any test run is read (M8).

## 6. Determinism

Percentiles are nearest-rank; candidate sets are sorted; no random choice enters calibration. ML uses fixed seeds.
Re-running the tool on the same commit and dataset regenerates every artefact byte-identically (G-P1).
