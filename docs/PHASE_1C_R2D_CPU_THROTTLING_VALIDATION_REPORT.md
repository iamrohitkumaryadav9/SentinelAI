# Phase 1C — R2-D Controlled CPU-Throttling Validation Report

| | |
|---|---|
| Gate | **R2-D RUNTIME VALIDATION: PASS WITH DOCUMENTED LIMITATION** — **R2-D CLOSED** |
| Limitation (§7) | `throttle.quota_saturation` (supporting metric) was **not validated under binding throttling**: it was MISSING in all 9 throttled runs |
| Authoritative run | `results/phase1c_r2d/20261003T191737Z/` (2026-10-03 19:17:37 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2d_validate.sh`; 15/15 runs OK, no aborts |
| Code under test | HEAD `7354f40` plus the R2-C tooling (unchanged since R2-C closeout) and the R2-D tooling, committed with this report: `scripts/r2d_cpu.py` (sha256 `07ebe5e4…`), `scripts/r2d_driver.py` (`7dcb730d…`), `scripts/r2d_validate.sh` (`ece26f36…`), `tests/faultlab/test_r2d.py` (`21b52a2a…`) |
| Preserved earlier attempt | `results/phase1c_r2d/20261003T184854Z/` — runtime attempt 1, **T1-1 = ABORT** (§3); unmodified, fingerprint `cfcac7e9f7af41defb8d694003d1701207f2d71085cae8a0ce7a6deb98988503` |

| Step | Result |
|---|---|
| Design | PASS |
| Implementation | PASS |
| Pre-runtime gate | GO |
| Runtime attempt 1 (`20261003T184854Z`) | FAIL — T1-1 ABORT (metric gate) |
| Gate revision (Option 1) | PASS |
| Fresh pre-runtime gate | GO |
| Runtime validation (`20261003T191737Z`) | **PASS WITH DOCUMENTED LIMITATION** |
| Closeout | PASS |

## 1. Phase boundary

R2-D validates the observation pipeline and the unchanged M2 against controlled CPU throttling (a CFS bandwidth
quota on the target cgroup), and the contention-versus-throttling precedence (PR-3) when both are present. No change
to M2, PR-3, G4, the global contract, M3A (including range checking), M3B, COV_MIN, SAT_MIN, THR_RATIO_MIN or
DOM_RATIO. R2-C files are byte-identical to the R2-C closeout. Not performed: memory pressure, softirq load, network
impairment, application faults, mitigation, any `cpu.max` outside the target leaf.

## 2. Design (approved)

- **Boundary:** R2-C's `/sys/fs/cgroup/sentinel-r2c/{target,contender}`, target on CPU 18, driver on CPUs 0–15,
  CPU 21 (NIC IRQ) excluded. The only writable quota file is `/sys/fs/cgroup/sentinel-r2c/target/cpu.max`; parent
  and contender `cpu.max` must read `max 100000` at every observation.
- **Quota values:** Q_B `100000 100000` (1.0 core, non-binding), T1 `15000 100000` (0.15 core), T2 `7500 100000`
  (0.075 core), MAX `max 100000`. Every write: allowlist check → path must resolve to itself (no symlink) →
  read-before equals the expected previous value → logged intent → write → read-after equals the value → logged
  result; any mismatch aborts.
- **Schedule:** Q_B before tick 0 → Q_W in the window callback (after tick NB is collected, before tick NB+1) → MAX
  after tick NB+NW is collected → MAX re-verified in cleanup before `cgroup.kill`/`rmdir`. W counter deltas run from
  tick NB to NB+NW; the first W gauge (tick NB) still reads Q_B (the documented M3A dilution).
- **Matrix (15 + calibration):** E0-open, Q0 ×2 (Q_B only), C1 ×2 (Q_B + R2-C E1 contender on CPU 18),
  T1 ×3, T2 ×3, TC ×3 (T1 + the E1 contender), E0-close. Calibration is runtime step 0, provenance only.
- **Ground truth** (kernel files, never the collector): R2-C G1, G2, G3 (applied to C1/TC), G4 (recorded only), G6
  (precise `/proc/schedstat` `rq_cpu_time`), G7; plus GQ (quota at every observation, index-exact, write order and
  timing), GT (`cpu.stat` `nr_periods`/`nr_throttled`/`throttled_usec`: no throttling in B; throttling in W for
  T1/T2/TC, none in W otherwise), GD (strict: B usage > W quota and W usage < B usage), GR (quota restored, host
  comparison identical).
- **Metric gate (as revised, §3):** 9 REQUIRED metrics — `sched.run_delay_excess.target` RATE, `cpu.util.cpuset`
  MEAN, `cpu.steal.cpuset` MEAN, `sched.latency_hist.target` P50 and P99, `throttle.time_rate` RATE,
  `throttle.quota_limited` GAUGE (1.0 with a quota, 0.0 in E0), `throttle.ratio` RATIO (usable with baseline under a
  quota, MISSING in E0), `softirq.frac.percpu` on CPU 18. Any one absent, MISSING, INVALID, STALE or with an
  inadequate baseline aborts. 2 SUPPORTING metrics only — `throttle.quota_saturation`, `throttle.quota_cores` — whose
  records are kept in `run.json` under `metric_gate.supporting`.
- **Validation parameter set:** R2-B NUMBERS (`r2c-validation-uncalibrated`): COV_MIN 0.8, N_BASE_MIN 5, SAT_MIN 0.9,
  THR_RATIO_MIN 0.3, DOM_RATIO 2.0.

## 3. Runtime attempt 1 and the gate revision

Attempt 1 (`20261003T184854Z`): calibration, E0-open, Q0 ×2 and C1 ×2 OK; **T1-1 ABORTED** and the run stopped
(`throttle.quota_saturation [None] != predicted 0.6401…`). Cause: `quota_saturation` (usage / quota) is registered as
a 0–1 fraction and M3A rejects per-interval values above 1.0; under a binding quota the per-second ratio read
1.0006–1.0022 in 4 of 10 W intervals, so coverage fell to 0.6 < COV_MIN and the metric was MISSING — and the
original R2-D gate required it. All T1-1 ground truth (100 throttled periods, 8.41 s throttled), M2
(`cpu_throttling`) and the quota restore were valid. **T1-1 remains ABORT; that evidence is preserved and not
relabelled.**

Approved gate revision (Option 1): `quota_saturation` moved from REQUIRED to SUPPORTING with explicit rules — OK
with coverage 1.0 must equal the pre-registered diluted prediction `usage_W / ((Q_B + (NW−1)·Q_W)/NW)` within
relative 1e-9, else ABORT (also ABORT if no prediction is possible); PARTIAL is recorded, not compared; MISSING /
INVALID are recorded with their reason; emitted during E0 → ABORT; not emitted while a quota is in force → ABORT.
There is no generic "supporting metrics are lenient" path. Verified: 54 R2-D tests, 66/66 mutants killed, full suite
730 OK (1 known root-only skip), dry-run 120/120 simulated cleanups, zero host mutation. A fresh pre-runtime gate
(root BPF baseline `/tmp/r2d_gate_20261003T191507Z`: 22 programs, 6 maps, 1 link, all system-owned, stable 60 s)
returned GO.

## 4. Results (authoritative run `20261003T191737Z`)

Calibration: 5196 iterations, provenance only. Every run: G1, G2, G3, G6, G7, GQ, GT, GD, GR true; metric gate OK;
no abort; BPF objects released; snapshot round-trip and rebuild identical; snapshot unchanged by M2.

| Run | Quota W | GT B throttled | GT W throttled / periods | Throttled time W | GD usage B → W (core) | G3 idle W | M2 | Confidence |
|---|---|---|---|---|---|---|---|---|
| E0-open | none | 0 | 0 / 0 | 0 | — | 0.788 | INSUFFICIENT_EVIDENCE | LOW |
| Q0-1, Q0-2 | 1.0 | 0 | 0 / 100 | 0 | — | 0.749–0.788 | INSUFFICIENT_EVIDENCE | LOW |
| C1-1, C1-2 | 1.0 | 0 | 0 / 100 | 0 | — | 0.001 | cpu_contention | MEDIUM |
| T1-1..3 | 0.15 | 0 | 99–100 / 100 | 8.31–8.39 s | 0.211–0.219 → 0.151–0.152 | 0.848 | **cpu_throttling** | MEDIUM |
| T2-1..3 | 0.075 | 0 | 100 / 100 | 9.16–9.19 s | 0.212–0.215 → 0.0758 | 0.923 | **cpu_throttling** | MEDIUM |
| TC-1..3 | 0.15 | 0 | 99 / 100 | 6.85–6.87 s | 0.212–0.214 → 0.150–0.151 | 0.002–0.006 | **cpu_throttling** | MEDIUM |
| E0-close | none | 0 | 0 / 0 | 0 | — | 0.786 | INSUFFICIENT_EVIDENCE | LOW |

G6 foreign busy time on CPU 18 between −0.0051 and +0.0014 core in B and W in every run (threshold 0.05); the `/proc/stat` tick
diagnostic again swung between about −0.21 and +0.29 core. G7 swap 0 pages/s everywhere. Contender iterations in W:
C1 1.40e8, TC 1.43–1.50e8.

M2 clause items:

| Runs | CT.R1 (quota_limited) | CT.R2 (ratio + time_rate) | CC.R1 | CC.R2 | CC.X1 (ratio ≥ 0.3) |
|---|---|---|---|---|---|
| E0 | NEGATIVE | NEGATIVE | NEGATIVE | NEGATIVE | MISSING (no quota) |
| Q0 | POSITIVE | NEGATIVE | NEGATIVE | NEGATIVE | NEGATIVE |
| C1 | POSITIVE | NEGATIVE | POSITIVE | POSITIVE | NEGATIVE |
| T1, T2 | POSITIVE | POSITIVE | NEGATIVE | NEGATIVE | POSITIVE |
| TC | POSITIVE | POSITIVE | POSITIVE | POSITIVE | POSITIVE |

**TC tie-break (PR-3, unchanged).** In TC both throttling and contention clauses are assertable. PR-3 compared
`throttle.time_rate` with `sched.run_delay_excess.target` under DOM_RATIO 2.0:

| Run | throttle time_rate | run_delay_excess | ratio | PR-3 result | M2 |
|---|---|---|---|---|---|
| TC-1 | 0.6861 | 0.1505 | 4.56 | cpu_throttling | cpu_throttling |
| TC-2 | 0.6866 | 0.1504 | 4.57 | cpu_throttling | cpu_throttling |
| TC-3 | 0.6853 | 0.1512 | 4.53 | cpu_throttling | cpu_throttling |

Throttle time ≈ 0.686 against run-delay excess ≈ 0.151 (ratio > 2.0), so the existing PR-3 dominance rule selected
throttling in 3/3, consistent with the recomputed expectation.

## 5. Validated

- Controlled CPU throttling can be generated on CPU 18 by a quota on the target leaf only, with the quota schedule
  observed index-exactly (GQ) and every write read back; writes took 30–49 µs.
- Throttling established by independent ground truth (GT, GD) in 9/9 T1/T2/TC runs; M2 diagnosed `cpu_throttling`
  in 9/9.
- Negative controls: a non-binding quota (Q0) produced zero throttled periods and no diagnosis; E0 produced no quota
  evidence (`throttle.ratio` MISSING, `quota_limited` 0); M2 abstained in all E0/Q0 runs.
- CPU contention under a non-binding quota (C1): CPU 18 saturated (idle ≤ 0.0015), zero throttled periods,
  contention clauses positive, throttling clauses negative, M2 `cpu_contention` 2/2 — throttling is not confused
  with contention.
- Combined fault (TC): PR-3 resolved contention-versus-throttling to `cpu_throttling` 3/3 as the dominance rule
  prescribes.
- Safety: no abort; quota restored (GR) and every driver/wrapper host comparison identical in all 15 runs; final host
  snapshot identical to the baseline (BPF compared); no `sentinel*` cgroup and no finite `cpu.max` afterwards.

## 6. Reproducibility

Verified offline from the preserved directory only (no rerun):

- 244 files; 15 run directories plus `calibration/`; all 15 run `*.err` files and `calibration.err` are empty.
- Each run directory holds `run.json` (observations, quota writes, ground truth, metric gate, M2), `snapshot.json`,
  `raw_ebpf.jsonl` (22 lines), `ops.jsonl` + `ops.jsonl.cleanup` (operation and quota logs), `host_before`,
  `host_after`, `host_wrapper_after`, `host_compare.json`, target output. Wrapper-level: `host_baseline`,
  `host_final`, `host_final_compare.json`, `final_cleanup.json`, `environment.txt`, `summary.json`.
- For all 15 runs: snapshot ids recompute and canonical bytes are identical; `diagnose()` reproduces the full M2
  record (decision, confidence, clauses, PR-3 record); `metric_gate()` reproduces the recorded gate including the
  supporting records; GQ, GT and GD recompute exactly from the saved observations and quota writes; the quota log
  (`ops.jsonl`) matches the recorded writes (Q0/C1: 2 writes, T/TC: 3, E0: none; cleanup restore a verified no-op).
- Limitation: G1, G2, G3, G6 and G7 are preserved as computed at runtime and their raw observations are saved, but
  the per-observation placement expectations they also take as input are not persisted, so they were not recomputed
  offline.
- Evidence fingerprint (sha256 of the sorted per-file sha256 list) of `20261003T191737Z`:
  `d131740996276d49a17dd946724b2db92e2fe85e36913821a2ac8a825427b0dd`.

## 7. Limitation: `throttle.quota_saturation` under binding throttling

| Runs | quota_saturation | Coverage | Compared with prediction |
|---|---|---|---|
| Q0-1 / Q0-2 | OK, 0.2122 / 0.2514 | 1.0 | yes — equal to the prediction |
| C1-1 / C1-2 | OK, 0.2087 / 0.2094 | 1.0 | yes — equal to the prediction |
| T1, T2, TC (9 runs) | **MISSING** | 0.5–0.7 (`coverage … below COV_MIN`) | **no** |
| E0 | not emitted | — | — (emission would abort) |

`quota_saturation` is validated for complete, prediction-consistent behaviour when the quota does not bind.
**Its behaviour during binding throttling, including possible values above 1.0, remains unvalidated.** It was never
compared against the prediction in a throttled run. This is a supporting-evidence limitation permitted by the revised
gate; it is not a failure of the mandatory R2-D evidence or ground-truth gate, and it does not affect the diagnosis:
all 9 required metrics and every ground-truth check were valid in all 15 runs. `throttle.quota_cores` was OK in every
quota run (1.0 / 0.15 / 0.075) and absent in E0.

## 8. Deferred study (Option 2 — not implemented)

Evaluate whether `throttle.quota_saturation` should support values above 1.0 during binding throttling. This requires
a separate contract / M3A study and is not part of R2-D. No global contract, M3A range-semantics, COV_MIN, SAT_MIN,
THR_RATIO_MIN, DOM_RATIO, M2 or PR-3 change was made, and R2-D is not reopened for it.

## 9. Other limitations

1. M2 confidence is limited to MEDIUM by IMPACT_NOT_MEASURED (no application metrics).
2. Thresholds are engineering / safety values, not statistically calibrated (parameter set uncalibrated).
3. `cpu.util.cpuset` keeps its documented `/proc/stat` tick-accounting bias (R2-C §8).
4. G4 is recorded only in R2-D.
5. The host must keep `openvpn-server@server.service` disabled (R2-C §4).
6. If the wrapper itself is SIGKILLed its trap cannot run; the manual recovery is
   `sudo .venv/bin/python scripts/r2d_cpu.py cleanup <OUT>` (quota restored first). Not exercised.

## 10. Reproduction

`sudo bash scripts/r2d_validate.sh` (root via sudo from uid 1000; refuses on a dirty tracked tree, a failed preflight,
existing lab state or a loader not linked to libbpf 1.4). Offline verification uses only the saved run directory
(snapshot validation and id recomputation, `diagnose()` with the validation parameter set, `metric_gate()`,
`evaluate_gq/gt/gd()` on the saved observations and quota writes).

```text
R2-D RUNTIME VALIDATION: PASS WITH DOCUMENTED LIMITATION
R2-D CLOSEOUT: PASS
```
