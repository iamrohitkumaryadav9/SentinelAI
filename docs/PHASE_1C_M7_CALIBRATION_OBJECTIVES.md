# Phase 1C M7 calibration objectives

Status: **committed before any calibration** (design §7.4 "each parameter's objective is written in
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
5. The parameter set `datasets/faultlab/v1/m7/params.calibrated.json` and its report are committed (add-only) before
   ML training reads any engine output.
6. ML (design §5.2–5.3) with `τ_ML` and `τ_DISAGREE` (C7-8), then the lock (`lock.json`: hashes of the parameters,
   the model, the matrix and the dataset manifest) before any test run is read (M8).

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

| Parameter | Feature x | Own class | Note |
|---|---|---|---|
| `DROP_ABS_MIN` | each local drop source's rate (pkts/s): `net.drop.qdisc`, `net.drop.iface_rx`, `net.drop.iface_tx`, `net.err.iface`, `net.drop.softnet`, `net.drop.socket`, `net.drop.kfree_skb` (reasons in `KFREE_REASONS_LOSS`); per window the largest | `network_packet_loss` | |
| `DROP_FRAC_MIN` | drops / (packets + drops) of the interface sources | `network_packet_loss` | |
| `RT_FRAC_MIN` | `tcp.retrans_frac` | `tcp_retransmissions` | windows of `network_packet_loss` are neither positive nor negative: local loss causes retransmissions by mechanism (contract PR-1) |
| `RT_RATE_MIN` | `tcp.retrans_rate` | `tcp_retransmissions` | as above; not read by the current engine, recorded |
| `THR_RATIO_MIN` | `throttle.ratio` | `cpu_throttling` | |
| `THR_TIME_MIN` | `throttle.time_rate` | `cpu_throttling` | not read by the current engine, recorded |
| `RDX_MIN` | `sched.run_delay.target` minus the throttled time rate (excess waiting-cores) | `cpu_contention` | not read by the current engine, recorded |
| `SAT_MIN` | `cpu.util.cpuset` | `cpu_contention` | CC.R2 is its only required use |
| `PSI_MEM_MIN` | `psi.mem.some.target` | `memory_pressure` | |
| `RECLAIM_MIN` | `mem.reclaim.target` (MP.R1 alternative A3) | `memory_pressure` | |
| `REFAULT_MIN` | `mem.refault.target` | `memory_pressure` | not read by the current engine, recorded |
| `APP_WAIT_MIN` | the largest of the app wait features (`app.queue_wait_ms`, `app.lock_wait_ms`, `app.dependency_latency_ms` P99) | `application_bottleneck` | |
| `APP_SHARE_MIN` | the share of the latency increase explained by app-level wait (engine AB.R2 share: largest wait increase / P99 latency increase) | `application_bottleneck` | |

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

## 5. Determinism

Percentiles are nearest-rank; candidate sets are sorted; no random choice enters calibration. ML uses fixed seeds.
Re-running the tool on the same commit and dataset regenerates every artefact byte-identically (G-P1).
