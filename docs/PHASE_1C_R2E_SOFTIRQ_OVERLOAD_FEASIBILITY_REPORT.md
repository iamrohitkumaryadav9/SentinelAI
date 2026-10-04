# Phase 1C — R2-E Controlled Softirq-Overload Feasibility Report

| | |
|---|---|
| Classification | **R2-E: NOT FEASIBLE UNDER THE REGISTERED EXPERIMENTAL DESIGN** — **R2-E CLOSED** |
| Meaning | The registered calibration stopping condition fired: no loss-free traffic rate produced the softirq load S2 requires. Not a PASS (no softirq-overload validation exists), not a FAIL (no evidence run contradicted ground truth or M2), not an implementation or safety failure |
| Authoritative run | `results/phase1c_r2e/20261004T055509Z/` (2026-10-04 05:55:09 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2e_validate.sh`; fingerprint `d5fe88043ad31e4814e37bfd9fe6a178b07a2ac1f7c12902aa6e65c0ac9e1ddd` (61 files; none modified after the run) |
| Code under test | HEAD `d11e755` plus the uncommitted R2-E tooling: `scripts/r2e_softirq.py`, `scripts/r2e_driver.py`, `scripts/r2e_validate.sh`, `tests/faultlab/test_r2e.py` (106 tests) |
| Preserved earlier attempts | `20261004T040939Z` (fingerprint `76921257…`) and `20261004T041003Z` (`625e8da9…`): both stopped safely at the lab check (`b_veth`) before any RPS write or traffic (§6) |

## 1. Scope

R2-E set out to validate the unchanged M2 against controlled softirq overload: NET_RX processing steered onto the
target CPU while no userspace contender runs there. No change to M1, M2, M3A, M3B, the contract, any threshold, or
R2-A/B/C/D. Not performed: memory pressure, application faults, mitigation, physical-NIC or host-RPS changes.

## 2. Registered design (approved: design gate, D1–D6, single-queue veth, cleanup-order fix, lab-settle fix)

- **Mechanism:** UDP, 64-byte payload, `iperf3` 3.9. Clients in `sentinel-lab-a` on CPUs 20 and 22, servers in
  `sentinel-lab-b` on CPU 23. Packets cross the R2-A topology (`sentlab-a0` ↔ `sentlab-b0`, 10.199.0.0/24, no default
  route), created by R2-E with one TX and one RX queue per end. RPS on `sentlab-b0` rx-0 steers NET_RX to CPU 18.
- **The only new mutation:** `sentinel-lab-b:/sys/class/net/sentlab-b0/queues/rx-0/rps_cpus` ∈ {`40000`, `80000`,
  `0`}: read before, written, read back, logged; reset to 0 and verified before the lab namespaces are deleted.
- **Target:** the R2-C periodic probe on CPU 18 (private netns). **Matrix:** E0-open, S1 ×2, S2 ×3, S3 ×3, N1 ×2
  (R2-C E2 contender), N2 ×2 (RPS → CPU 19), E0-close.
- **Calibration (provenance only):** step 0a, the R2-C target iteration count. Step 0b, a UDP rate ladder of 10k,
  20k, 40k, … 1.28M pps total, doubling, 5 s per step with a 4 s steady-state measurement, stopping at the first
  loss. δ = max |`/proc/stat` softirq fraction − eBPF softirq| over the loss-free steps. S1 = highest loss-free rate
  with both measures < SI_ABS_MIN − δ. S2 = lowest loss-free rate with eBPF NET_RX(18) ≥ SI_ABS_MIN + δ. S3 =
  highest loss-free rate above S2. **No S2 ⇒ R2-E NOT FEASIBLE**, and no threshold may be changed.
- **Ground truth** GP GN GS GV GI G0 G6′ GL GC G7 GR from saved raw inputs; validation parameters SI_ABS_MIN 0.5,
  SI_RATIO_MIN 3.0, SI_SHARE_MIN 0.5, RDX_MIN 0.05 (unchanged, uncalibrated).

## 3. Runtime result

| Step | Result |
|---|---|
| Wrapper preflight, host baseline | OK |
| 0a target calibration | OK, 5384 iterations |
| 0b lab creation and settle | Settled on attempt 1 (0.105 s), §6 |
| 0b RPS write | `40000`: before `000000`, after `040000` |
| 0b ladder | **NOT FEASIBLE**: "S2 not reachable without loss" |
| Evidence runs (14) | **Not executed** — the registered stop applies before E0-open |
| Cleanup, GR, host comparison | OK (§8) |

### Ladder (CPU 18; 4.01–4.02 s steady-state interval per step)

| Rate (pps, total) | Achieved pps | eBPF NET_RX (cores) | eBPF all vectors | `/proc/stat` softirq fraction | sentlab-b0 rx | softnet processed (CPU 18) | Δ | Loss |
|---|---|---|---|---|---|---|---|---|
| 10k | 9,999 | 0.0135 | 0.0136 | 0.0000 | 40,152 | 40,156 | +4 | none |
| 20k | 19,996 | 0.0253 | 0.0256 | 0.0000 | 80,280 | 80,290 | +10 | none |
| 40k | 40,003 | 0.0230 | 0.0231 | 0.0000 | 160,601 | 160,589 | −12 | none |
| 80k | 79,975 | 0.0455 | 0.0456 | 0.0000 | 321,120 | 321,126 | +6 | none |
| 160k | 159,993 | 0.0802 | 0.0803 | 0.0000 | 642,080 | 642,084 | +4 | none |
| **320k** | 319,982 | **0.1660** | 0.1661 | 0.0000 | 1,284,163 | 1,284,189 | +26 | **none** |
| 640k | 640,057 | 0.3269 | 0.3270 | 0.5307 | 2,569,484 | 2,569,278 | −206 | **≈22 %** (577,485 of 3,199,822 sent) |

δ = 0.1661 (from the 320k step). S1 = 320k pps. S2 needs ≥ 0.5 + 0.1661 = **0.666 cores** of NET_RX without loss;
the highest loss-free value was **0.166 cores**, so S2 is unreachable and S3 is undefined. The ladder stopped at the
first lossy step (640k), as registered. The 14 evidence runs were correctly not executed. The thresholds were not
changed.

## 4. Feasibility boundary and receiver bottleneck

At 640k pps the loss was at the receiving sockets, not on the softirq path:

- lab-b UDP `RcvbufErrors` +462,966 (`InErrors` +462,966); `iperf3` lost 310,343 + 267,142 = 577,485;
- CPU 18 `softnet_stat` dropped 0, `time_squeeze` 0; `sentlab-a0` tx_dropped 0, `sentlab-b0` rx_dropped 0;
- CPU 18 NET_RX was 0.327 cores at that point, so CPU 18 was far from saturated.

The two `iperf3` receivers (both on CPU 23) became the bottleneck before CPU 18 could reach the registered
softirq-overload threshold. NET_RX cost was about 0.5 µs per packet. The loss-free load would have had to rise about
fourfold to reach S2.

**Accounting caveat (recorded, not corrected in the evidence):** the ladder's `udp` loss figure (925,932) adds
`InErrors` and `RcvbufErrors`, which overlap (receive-buffer errors are also counted in `InErrors`). Any loss ends
the ladder, so the outcome is unaffected.

## 5. Measurement finding: `/proc/stat` vs eBPF softirq time

At every loss-free step the tick-sampled `/proc/stat` softirq fraction of CPU 18 (the input of `softirq.frac.percpu`,
`softirq.relevant_cpu_max` and SI.R1) read **0.0000**, while the eBPF `softirq_entry`/`softirq_exit` time
(`softirq.exec_time.percpu`) measured up to **0.166 cores**. At 640k it read **0.5307** against eBPF **0.3269**.

Interpretation, recorded as an observed limitation: this kernel has no `CONFIG_IRQ_TIME_ACCOUNTING`, so softirq time
in `/proc/stat` is tick-sampled. During the ladder CPU 18 was otherwise idle under NO_HZ, so short softirq bursts
were rarely or never sampled by a tick; under heavy load the sampling became biased the other way. The ladder ran
without the target probe on CPU 18, so δ was measured in a condition that differs from the evidence runs. SI.R1, M2
and M3A are **not** changed on the basis of this result. It is a limitation and future-work item (§10).

## 6. Lab-settle race: validated at runtime

| Attempt | t (s) | `sentlab-b0` flags | operstate | Verdict |
|---|---|---|---|---|
| 0 | 0.000 | NO-CARRIER, BROADCAST, MULTICAST, UP, LOWER_UP | DOWN | fail (`b_veth`) |
| 1 | 0.105 | BROADCAST, MULTICAST, UP, LOWER_UP | UP | pass — settled |

Both observations were saved before evaluation, and offline replay reproduces both verdicts and the settling attempt.
This strongly supports the timing-race explanation of the two earlier aborts (`20261004T040939Z`,
`20261004T041003Z`), which checked once at t = 0. Those runs did not save their failing observation (the gap the
lab-settle fix closed), so the explanation cannot be proven for them retroactively. The single-queue veth worked:
one TX and one RX queue per end, GRO off on `sentlab-b0`, netdev backlog 1000.

## 7. softnet "processed": corroborated at runtime

CPU 18's `softnet_stat` processed count matched the packets `sentlab-b0` received within 26 at every loss-free step
(+4, +10, −12, +6, +4, +26), and within 206 at the lossy 640k step, below the netdev backlog of 1000. This is runtime
corroboration of the registered interpretation (processed counts packets handled on the RPS CPU, so RPS steering to
CPU 18 was complete). No telemetry semantics were changed.

## 8. Safety and cleanup

- **RPS:** written `40000` (before `000000`, after `040000`); restored `0` (before `040000`, after `000000`). The
  verified reset is logged before both namespace deletions (GR `rps_reset_before_netns_deletion`).
- **Order (op log):** traffic leaf killed → RPS 0 read back → eBPF loader closed → BPF objects released (1 poll,
  1.2 ms) → cgroup kill, leaves and parent removed → `ip netns del` lab-a, lab-b.
- **GR OK**, cleanup OK. Run host comparison identical, BPF included. Wrapper host comparison, final wrapper cleanup
  and final host comparison OK; not unsafe/incomplete.
- No protected interface touched: `enp0s31f6`, `docker0`, host routes, qdiscs, sysctls, IRQ affinity (IRQ 134 on
  CPU 21), root cpuset and controllers all identical. OpenVPN inactive. No unexpected network or BPF state. No
  `iperf3`, loader or SentinelAI process remains.
- **Memory / swap:** swap was about 99 % full before and after the run (not caused by SentinelAI, not changed).
  G7 is evaluated only inside evidence windows; none ran, so **R2-E makes no claim about memory-safety behaviour
  during the experiment matrix**.

## 9. Reproducibility

Verified offline from the saved directory only (`r2e_softirq.py evaluate <run>/ladder`):

- every ladder step recomputes from the saved raw observation pair and `iperf3` JSON, and the selected levels
  (δ, S1, S2 = none, S3 = none, NOT FEASIBLE) reproduce exactly;
- both lab-settle observations replay to the recorded verdicts and settling attempt;
- the RPS write, read-backs and restoration are in `ladder/ops.jsonl` and `run.json`; the cleanup record, BPF-release
  record, GR and the host snapshots/comparisons (run, wrapper, final) are preserved.

## 10. Limitations

1. **No softirq-overload validation exists.** R2-E does not count as a validated fault class; the M2 decision path for
   `softirq_overload` (SI.R1, SI.R2, PR-5) has no runtime evidence. `softirq_overload` stays unvalidated.
2. UDP feasibility is negative under the registered receiver design (two `iperf3` receivers on CPU 23).
3. `/proc/stat` softirq time is tick-sampled on this kernel and disagreed strongly with eBPF (§5). Future work only.
4. δ was measured without the target probe on CPU 18.
5. The ladder's `udp` loss figure double-counts overlapping SNMP counters (§4).
6. The cause of the two earlier `b_veth` aborts is strongly supported but not proven for those runs (§6).
7. No G7 / memory evaluation occurred (§8). Thresholds remain engineering/validation values, not calibrated.

## 11. Decision: no redesign now

R2-E is closed as a completed, methodologically valid feasibility study. A future redesign could investigate faster
or multiple receivers or a different traffic generator. That would be a **new experimental design** requiring its
own design review and gates. Nothing of the kind is implemented or proposed here.

```text
R2-E: NOT FEASIBLE UNDER THE REGISTERED EXPERIMENTAL DESIGN
R2-E CLOSED
```
