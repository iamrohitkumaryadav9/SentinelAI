# Phase 1C — R2-C Controlled CPU-Contention Validation Report

| | |
|---|---|
| Gate | **R2-C RUNTIME VALIDATION: PASS** — **R2-C CLOSED** |
| Authoritative run | `results/phase1c_r2c/20261003T175532Z/` (2026-10-03 17:55:32 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2c_validate.sh`; all 12 runs OK, no aborts |
| Code under test | HEAD `7354f40` plus the uncommitted R2-C tooling: `scripts/r2c_cpu.py`, `scripts/r2c_driver.py`, `scripts/r2c_target.py`, `scripts/r2c_validate.sh`, `tests/faultlab/test_r2c.py` |
| Preserved earlier attempts | `20261003T121620Z` (stopped after calibration: host noise), `20261003T121632Z` (E0-open: tick-accounting artefact + BPF teardown race), `20261003T125105Z` (11/12 OK, E0-close: host noise) |

## 1. Phase boundary

R2-C validates the observation pipeline and M2 against controlled CPU contention only. No change to M2, G4, the
contract, M3A or M3B. Not performed: CPU quota/throttling, memory pressure, softirq load, network impairment,
application faults, mitigation.

## 2. Design (approved, unchanged)

- **Boundary:** `/sys/fs/cgroup/sentinel-r2c/{target,contender}`, controllers `cpuset cpu memory pids`, `cpu.max`
  = `max` everywhere (no quota). One workload PID per cgroup; the `timeout -s KILL 60` wrapper stays outside.
- **CPUs:** target 18 (E-core, no SMT); contender 18 (E1, E2), 23 (N1, other L2 cluster), 19 (N2, same L2 cluster);
  driver/collector/loader on 0–15; CPU 21 (NIC IRQ) excluded.
- **Target:** one process, 2 ms absolute-deadline period, fixed iterations per cycle (calibrated once per invocation
  on CPU 18, provenance only), private interface-less netns.
- **Contender:** one SCHED_OTHER `python3 -c` busy loop; level = contender `cpu.weight` (E1 100, E2 400).
- **Timeline per run:** warm-up 10 s, B 10 s, W 10 s (contender in W only), recovery 10 s.
- **Matrix:** calibration, E0-open, N1 ×2, N2 ×2, E1 ×3, E2 ×3, E0-close.
- **Ground truth G1–G7** read directly from kernel files, never through the collector. Approved criteria (engineering /
  safety criteria, not calibrated thresholds): G4 = EXPERIMENTAL HEURISTIC (median lateness: n ≥ 4000 per window,
  med_W ≥ 1.5·med_B, med_W − med_B ≥ 50 µs, target PSI W > B); G7 softirq |f_W − f_B| ≤ 0.01 (SAFETY THRESHOLD,
  repository-informed); memory PSI ΔW > 0 aborts (REPOSITORY-SUPPORTED); swap > 25 pages/s aborts (SAFETY THRESHOLD,
  repository-informed); host PSI / slice PSI (SAFETY THRESHOLD).

## 3. Measurement fixes made after runtime attempt 1 (approved)

- **G6 / G3 source.** `/proc/stat` per-CPU busy time is tick-sampled on this kernel (`CONFIG_HZ=1000`, NO_HZ, no
  nohz_full CPU) while idle is precise; the 2 ms periodic target was charged a full tick per wake-up (busy 0.50 vs
  real 0.25 core; total 1246 jiffies in 10 s). G6 and G3 now use `/proc/schedstat` v15 cpu18 field 7 (`rq_cpu_time`,
  ns) through R2-C's own strict parser; thresholds unchanged (0.05). The tick values are kept as diagnostics only.
- **BPF teardown.** The kernel frees the loader's maps asynchronously; the driver now polls `bpftool` (100 ms, max
  5 s) until no run-owned `sn_*` / `sentinel.*` object remains, then takes the authoritative snapshot (exact equality
  unchanged; timeout or unreadable output aborts).

## 4. Host-noise resolution (external, not SentinelAI)

Attempts `121620Z` and `125105Z` aborted on the exact cgroup/BPF comparison because
`openvpn-server@server.service` was crash-looping (≈ every 5.25 s since 2026-09-29; `server.conf` binds
`local 192.168.192.179`, the host has `192.168.192.151`; each start briefly created its cgroup, an unnamed
`cgroup_device` BPF program and `tun0`). With explicit authorisation the unit was disabled
(`systemctl disable --now openvpn-server@server.service`, 2026-10-03 23:07:52 IST). A 120 s observation showed no
restart, no transient cgroup, no `tun0`, no `10.8.0.1`, no BPF churn. Side effects of that one command: a systemd
reload re-created 19 BPF programs (identical tags, new IDs) and the empty OpenVPN slice lost its delegated
controllers. A fresh pre-runtime gate (root BPF baseline, 60 s stable) then passed. The unit remains
disabled/inactive. R2-C did not cause this noise; the exact comparisons were not weakened.

## 5. Results (authoritative run `20261003T175532Z`)

Calibration: 5424 iterations (median 1.844 ms per 20,000), provenance only.

| Run | G1 | G2 contender (core) | G3 idle W | G5 | G6 B/W (core) | G7 | G4 | Established | M2 |
|---|---|---|---|---|---|---|---|---|---|
| E0-open | T | 0 | 0.777 | T | 0.000/0.000 | T | F | no | INSUFFICIENT_EVIDENCE |
| N1 ×2 | T | 0.998–0.999 (CPU 23) | ≈0.78 | T | ≤0.001 | T | F | no | INSUFFICIENT_EVIDENCE |
| N2 ×2 | T | 0.998–0.999 (CPU 19) | ≈0.78 | T | 0.000 | T | F | no | INSUFFICIENT_EVIDENCE |
| E1 ×3 | T | 0.777–0.781 (CPU 18) | 0.001–0.002 | T | ≤0.000 | T | **F** | **no** | **cpu_contention** |
| E2 ×3 | T | 0.799 (CPU 18) | 0.001 | T | ≤0.000 | T | T | yes | cpu_contention |
| E0-close | T | 0 | 0.778 | T | 0.000/0.000 | T | F | no | INSUFFICIENT_EVIDENCE |

| Run | Median lateness B→W | p99 lateness B→W | Missed (of 5000) | Target PSI µs B→W | run_delay_excess | Latency P50 / P99 | cpu.util.cpuset |
|---|---|---|---|---|---|---|---|
| E0, N | ≈53.5→53.5 µs | ≈66→54–66 µs | 0–1 | flat | 0–0.0003 | 0.7 µs / 1–4 µs | 0.03–0.39 (tick bias) |
| E1 | 53.2–53.6→53.7–53.8 µs | 66→3,365–3,715 µs | 1,092–1,147 | 6–7k→2.18–2.22M | 0.218–0.221 | 0.7 µs / 3.4–3.7 ms | 0.998–0.999 |
| E2 | 53.5→397–545 ms | 67 µs→773–1,030 ms | 4,995 | 7–13k→7.97–7.98M | 0.797–0.798 | 3.1 ms / 3.7–3.8 ms | 0.999 |

M2 clause items: E1/E2 CC.R1 POSITIVE, CC.R2 POSITIVE, CC.X1 MISSING (no quota, by design), CC.X2 NEGATIVE,
confidence MEDIUM (IMPACT_NOT_MEASURED); E0/N CC.R1 and CC.R2 NEGATIVE, confidence LOW, REQUIRED_EVIDENCE_MISSING.
`cpu.steal.cpuset` 0 and `throttle.ratio` MISSING in every run.

Safety: no abort. Every driver and wrapper host comparison identical; BPF objects released in 0.103 s (2 polls) in all
13 driver runs; cleanup OK everywhere; final host snapshot identical to the fresh baseline.

## 6. Validated

- Controlled CPU contention can be generated on target CPU 18 inside a bounded cgroup without quota or throttling.
- Strong contention (E2) established by independent ground truth in 3/3; M2 diagnosed `cpu_contention` in 3/3.
- Negative controls N1/N2 (a full core of CPU work on CPU 23 / 19) produced no target-side contention evidence; M2
  abstained in all E0/N1/N2 runs.
- The precise schedstat-based G3/G6 measurement worked (G6 ≤ 0.001 core); the `/proc/stat` tick bias was demonstrated
  empirically (diagnostic G6 swinging between about −0.22 and +0.28 core).
- The BPF release wait worked in every run.
- All 12 runs of the final runtime completed without a safety abort; protected host state remained identical.
- EvidenceSnapshots round-trip identically and their ids recompute; snapshot rebuild was verified at runtime; M2
  decisions and ground truth reproduce exactly offline from the saved evidence.

## 7. Recorded finding: E1 ground-truth / M2 disagreement

E1 (contender weight 100 on CPU 18) produced strong target-side degradation: p99 lateness about 51–56× higher, about
1,100 of 5,000 deadlines missed, target PSI about 300× higher, `run_delay_excess` about 0.22 waiting cores. M2
diagnosed `cpu_contention` in 3/3. The pre-approved G4 median-lateness criterion stayed FALSE (median moved
≤ 0.5 µs), so under the approved definition contention was **not established** in E1. This is a recorded
disagreement and limitation, not a failed runtime gate. G4 and M2 were not changed and E1 is not reinterpreted.

## 8. Limitations

1. E1 / G4 moderate-contention disagreement (§7); G4 is an experimental heuristic.
2. `cpu.util.cpuset` (repository metric, unchanged) has a tick-accounting bias when CPU 18 is partly busy.
3. M2 confidence is limited to MEDIUM by IMPACT_NOT_MEASURED (no application metrics).
4. Thresholds are engineering / safety values, not statistically calibrated.
5. The calibrated iteration count differs between wrapper invocations (5097 / 5436 / 5341 / 5424).
6. The host must keep `openvpn-server@server.service` disabled (or its configuration corrected) to avoid the
   documented host noise.

## 9. Reproduction

`sudo bash scripts/r2c_validate.sh` (root via sudo from uid 1000; refuses on a dirty tracked tree, failed preflight
or existing lab state). Offline verification uses only the saved run directory (snapshot validation, id recomputation,
`diagnose()` with the r2c validation parameter set, `evaluate_ground_truth()` on the saved observations).

```text
R2-C RUNTIME VALIDATION: PASS
R2-C CLOSEOUT: PASS
```
