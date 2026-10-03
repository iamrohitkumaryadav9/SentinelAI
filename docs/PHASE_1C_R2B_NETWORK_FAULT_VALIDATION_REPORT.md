# Phase 1C — R2-B Controlled Network Fault Validation Report

| | |
|---|---|
| Gate | **R2-B NETWORK FAULT VALIDATION GATE: GO** |
| Authoritative run | `results/phase1c_r2b/20261003T103454Z/` (2026-10-03 10:34:54 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2b_validate.sh`; exit 0 |
| Failed attempt (preserved) | `results/phase1c_r2b/20261003T100833Z/`: stopped at E0 on a defect in the R2-B **driver**, not in SentinelAI (§18) |

## 1. Phase boundary

R2-B validates the observation pipeline against controlled packet loss only. Not performed, and not authorised: CPU contention or throttling, memory pressure, application faults, delay, reordering, corruption, duplication, mitigation, K1–K4, and any change to M2, the contract or M3B.

## 2. Baseline commit

`3f1eb40` docs(ebpf): record M3B R1 runtime validation (approved), followed by R2-A tooling `683d87a`. No file under `src/` or `ebpf/` changed between `3f1eb40` and the checkout used.

## 3. Candidate commit

The runs used checkout `683d87af0f60d803f01c393b479b4b0b111029e2` plus the R2-B tooling, which was **uncommitted** during the runs, as the commit policy requires. The runner's candidate check accepted it: HEAD descends from `683d87a`, no committed change outside the R2-B tooling, no modified tracked file. The R2-B commit made after this gate contains only R2-B tooling, tests, this report and the R2-B evidence (§25).

## 4. Authorisation boundary (enforced in code, tested)

- **The only executable fault:** `tc -n sentinel-lab-a qdisc add dev sentlab-a0 root netem loss {1%|5%}`. It is built by `scripts/r2b_fault.py` and re-validated against an exact allowlist immediately before its single execution site (list argv, `shell=False`).
- **Refused:** protected interface names (an independent check), the other namespace or interface, `qdisc change`/`replace`, any other netem parameter (delay, reorder, corrupt, duplicate, rate, …) and any other loss level.
- **Wrapper:** creates and destroys only the R2-A lab objects, and reads host state.
- **Driver:** runs inside `sentinel-lab-a`, removes the fault right after the window and again on any failure path, and refuses to run elsewhere.
- **One authorised addition beyond R2-A:** `ip netns exec` gives the driver a private (slave) mount namespace with the lab's sysfs, where the cgroup v2 hierarchy is not mounted. The wrapper mounts cgroup2 **read-only** there (`-o ro,nosuid,nodev,noexec`). The mount cannot propagate to the host, it is gone when the driver exits, and no cgroup is changed. The host mount table was compared before and after every run (§20).

## 5. Preflight

| Check | Result |
|---|---|
| HEAD / tree | `683d87a`; untracked only R2-A report/evidence, FaultLab, R2-B tooling |
| R2-A tooling | present (`scripts/r2a_lab.py`, `scripts/r2a_lab_validate.sh`) |
| Tests before R2-B tooling | 586 run, 585 passed, 0 failed, 1 skipped |
| M2 / M3B / contract | no diff under `src/` or `ebpf/` since `3f1eb40` |
| Protected interfaces | `enp0s31f6` (UP, 192.168.192.151/20, `fq_codel`), `docker0` (DOWN, 172.17.0.1/16, `noqueue`) present |
| Stale lab objects | none (`/run/netns` empty; no `sentlab-*`) |

## 6. FaultLab topology (R2-A, recreated for every run)

```text
netns sentinel-lab-a [lo, sentlab-a0 10.199.0.1/24]  <== veth ==>  [sentlab-b0 10.199.0.2/24, lo] netns sentinel-lab-b
no default route; netem (when present) = root qdisc of sentlab-a0 = egress of the sender
```

Before every run the R2-A lab checks passed (27/27 per run): lab-only routes, no external path (`route get 8.8.8.8` → `Network is unreachable`), loopback and peer ping 0 % loss, TCP echo OK.

**Workload:** a paced TCP stream from A (10.199.0.1) to B (10.199.0.2:5201). 1,448-byte writes, 4,000 per second, `TCP_NODELAY`, in the driver (netns A); receiver in netns B.

**Collection:** M3A + M3B for target `laba` (the driver pid in netns A, interface `sentlab-a0`). Baseline window B = 10 ticks and incident window W = 10 ticks at 1 s. The fault is applied right after the last B tick and removed right after the last W tick.

**Attribution:** a second eBPF loader targets netns B over the same ticks.

## 7. Exact fault configurations

Each is read back from the kernel (`tc -n sentinel-lab-a qdisc show dev sentlab-a0`) at installation and before removal:

| Run | Configured | Kernel readback |
|---|---|---|
| E0 | none | `noqueue` throughout |
| E1 | loss 1 % | `qdisc netem 8002: root refcnt 25 limit 1000 loss 1%` |
| E2 rep2 | loss 1 % | `qdisc netem 8003: root refcnt 25 limit 1000 loss 1%` |
| E2 rep3 | loss 1 % | `qdisc netem 8004: root refcnt 25 limit 1000 loss 1%` |
| E3 | loss 5 % | `qdisc netem 8005: root refcnt 25 limit 1000 loss 5%` |
| E3 rep2 | loss 5 % | `qdisc netem 8006: root refcnt 25 limit 1000 loss 5%` |

Only `loss` was present: the readback check rejects any other impairment. Every add and delete returned rc 0.

## 8. Experiment matrix

| Run | W (UTC, 10 s) | Fault in W | Purpose |
|---|---|---|---|
| E0-baseline | 10:35:15.488–10:35:25.488 | none | clean baseline |
| E1-loss1 | 10:35:54.023–10:36:04.023 | netem loss 1 % | controlled loss |
| E2-loss1-rep2 | 10:36:32.554–10:36:42.554 | netem loss 1 % | repeatability |
| E2-loss1-rep3 | 10:37:11.089–10:37:21.090 | netem loss 1 % | repeatability |
| E3-loss5 | 10:37:49.604–10:37:59.604 | netem loss 5 % | second level |
| E3-loss5-rep2 | 10:38:28.125–10:38:38.125 | netem loss 5 % | second level, repeat |

## 9. Clean baseline (E0)

| Measurement (scope; source; aggregation) | Ground truth over W | SentinelAI value |
|---|---|---|
| `net.drop.qdisc` (`iface:laba/sentlab-a0`; TC; RATE) | qdisc `noqueue`, 0 drops | **0.0** packets/s (baseline median 0.0) |
| `tcp.retrans_skb_rate` (`netns:laba`; EBPF; RATE) | `tcpi_total_retrans` Δ 0; `RetransSegs` Δ 0 | **0.0** events/s |
| `tcp.retrans_rate` (`netns:laba`; PROC; RATE) | `RetransSegs` Δ 0 | 0.0 segments/s |
| `tcp.out_segs_rate` (`netns:laba`; PROC; RATE) | `OutSegs` Δ 40,002 | 3,999.94 segments/s |
| `net.pkts.iface` (`iface:laba/sentlab-a0`; SYSFS; RATE) | data + ACKs | 8,000.1 packets/s |
| `net.drop.kfree_skb` (`netns:laba`; EBPF; RATE) | 1 `NOT_SPECIFIED` free in netns A during W | `NOT_SPECIFIED` 0.1 packets/s; no `QDISC_DROP` |
| Workload | 128,725,752 bytes sent = received | – |

There was no intentional loss, no retransmission and no qdisc drop, and the eBPF and /proc views agree.

## 10. 1 % loss results (E1, plus repeats in §11)

E1, W = 10.0000 s:

| Quantity | Ground truth | SentinelAI (unit; source) |
|---|---|---|
| netem drops (kernel counter, fault lifetime) | **385** of 40,387 segments offered (sent 40,002) = 0.953 % | M3A `net.drop.qdisc` = **38.500** packets/s (385 in W; TC) |
| Dropped skbs attributed to netns A | – | eBPF `kfree_skb` reason `QDISC_DROP` = **385** in W; `net.drop.kfree_skb[QDISC_DROP]` 38.500 packets/s (EBPF) |
| Retransmitted segments (connection) | `tcpi_total_retrans` Δ **387**; `RetransSegs` Δ 387 | `tcp.retrans_rate` 38.70 segments/s (PROC) |
| Retransmitted skbs | – | `tcp.retrans_skb_rate` **38.50** events/s = 385 skbs (EBPF) |
| Retransmission fraction | 387 / 40,000 OutSegs | `tcp.retrans_frac` 0.009675 (PROC) |

## 11. Repeatability (1 %)

| Run | netem drops / segments offered | `net.drop.qdisc` (pkt/s) | eBPF QDISC_DROP (A) | eBPF retrans skbs (A) | `RetransSegs` Δ = `tcpi_total_retrans` Δ | `tcp.retrans_frac` | M2 |
|---|---|---|---|---|---|---|---|
| E1 | 385 / 40,387 (0.953 %) | 38.500 | 385 | 385 | 387 | 0.009675 | `network_packet_loss` |
| E2 rep2 | 388 / 40,387 (0.961 %) | 38.800 | 388 | 388 | 388 | 0.009700 | `network_packet_loss` |
| E2 rep3 | 415 / 40,419 (1.027 %) | 41.496 | 415 | 415 | 418 | 0.010449 | `network_packet_loss` (+ `tcp_retransmissions` CONTRIBUTING) |

- **Drop counts:** mean 396, sd 16.5. Binomial expectation for about 40,400 segments at p = 0.01 is about 404 ± 20, so the variance is consistent with random loss.
- **Exact agreement in every run:** qdisc counter = eBPF `QDISC_DROP` attributed to netns A. Retransmitted skbs ≈ retransmitted segments (385/387, 388/388, 415/418), as expected when the sender is not congestion-limited.
- **Why only rep3 shows `tcp_retransmissions`:** its retransmission fraction (0.010449) crossed `RT_FRAC_MIN` = 0.01 (RT.R1), while E1 and rep2 (0.009675, 0.009700) did not. 1 % loss sits on that validation threshold.

## 12. Second loss level (5 %)

| Run | Offered segments/s (`tcp.out_segs_rate`) | netem drops / segments sent | `net.drop.qdisc` (pkt/s) | eBPF QDISC_DROP (A) | eBPF retrans skbs | `RetransSegs` Δ = `tcpi_total_retrans` Δ | `tcp.retrans_frac` | M2 |
|---|---|---|---|---|---|---|---|---|
| E3 | 2,492.58 (B: 3,999.96) | 953 / 24,911 | 95.299 | 953 | 1,000 | 1,325 | 0.053157 | `network_packet_loss` + `tcp_retransmissions` CONTRIBUTING |
| E3 rep2 | 3,532.00 (B: 4,000.00) | 1,441 / 35,302 | 144.100 | 1,441 | 1,523 | 2,065 | 0.058465 | `network_packet_loss` + `tcp_retransmissions` CONTRIBUTING |

**Comparison by loss level:**

| Level | qdisc drops/s | eBPF retrans skbs/s | `RetransSegs`/s |
|---|---|---|---|
| 0 % | 0 | 0 | 0 |
| 1 % | 38.5–41.5 | 38.5–41.5 | 38.7–41.8 |
| 5 % | 95.3–144.1 | 100.0–152.3 | 132.5–206.5 |

The telemetry rises with the configured loss. The 5 % repetitions differ substantially because TCP's congestion response reduced the offered load differently in each run (2,493 vs 3,532 segments/s). No causal claim is made beyond these measurements.

**Ground truth vs configured 5 %:** the segment-level drop fractions are 3.68 % (953 / 25,864) and 3.92 % (1,441 / 36,743), below 5 %. This is explained by units, not by a measurement error:
- netem's packet counter equals the sender's `OutSegs` exactly (24,911 vs 24,914; 35,302 vs 35,302), so it counts **segments**;
- each drop removes one **skb**, since every drop matches exactly one `kfree_skb QDISC_DROP`;
- under congestion, TCP coalesces segments into multi-segment skbs. Retransmitted skbs alone averaged 1,325/1,000 = 1.33 and 2,065/1,523 = 1.36 segments;
- dropping 5 % of skbs therefore removes fewer than 5 % of segments. The implied skbs offered (953/0.05 ≈ 19,060; 1,441/0.05 ≈ 28,820) give 1.36 and 1.27 segments per skb, consistent with the retransmission ratio. This figure is an estimate: the count of skbs offered to netem was not measured directly.

This is the skb/segment distinction that M3B-C0 built into the contract: `tcp.retrans_skb_rate` (skbs) and `tcp.retrans_rate` (segments) were kept separate and never converted.

## 13. Netns filtering results

Both loaders read the same ticks; A targets netns 4026532647 (sender, faulted) and B targets netns 4026532828 (receiver).

| Run | A target `QDISC_DROP` | B target `QDISC_DROP` | A target retrans | B target retrans | B `retrans_other_netns` | A `kfree_other_netns` | unattributed (both) |
|---|---|---|---|---|---|---|---|
| E0 | 0 | 0 | 0 | 0 | 0 | 404 | 344 |
| E1 | 385 | 0 | 385 | 0 | 385 | 402 | 344 |
| E2 rep2 | 388 | 0 | 388 | 0 | 388 | 415 | 344 |
| E2 rep3 | 415 | 0 | 415 | 0 | 415 | 372 | 344 |
| E3 | 953 | 0 | 1,000 | 0 | 1,000 | 354 | 344 |
| E3 rep2 | 1,441 | 0 | 1,523 | 0 | 1,526 | 356 | 354 |

- **Target traffic is attributed to the target:** every netem drop appears as a `QDISC_DROP` free in netns A, and every retransmission is attributed to A.
- **The other namespace is not credited:** B sees 0 target `QDISC_DROP` and 0 target retransmissions in every run, and counts A's retransmissions only as `retrans_other_netns`. In E3 rep2, B's other-netns count exceeds A's target count by 3: retransmissions from outside the lab (host), which A correctly excluded too (A `retrans_other_netns` = 3).
- **Unrelated host traffic is excluded:** host and other-netns frees (354–415 per W) are counted as `kfree_other_netns` and never as A evidence. A's target frees are only `QDISC_DROP` plus at most one `NOT_SPECIFIED` per W.
- **Unattributed frees stay excluded:** skbs with neither a device nor a socket netns (344–354 per W) are counted separately and never reported as target evidence.
- The automated attribution checks passed in all 6 runs (6–7 checks each).

## 14. qdisc ground truth

| Run | netem lifetime: sent pkts / bytes / drops | M3A `net.drop.qdisc` count in W | after removal |
|---|---|---|---|
| E1 | 40,002 / 60,561,584 / 385 | 385 | `noqueue` (clean) |
| E2 rep2 | 39,999 / 60,558,486 / 388 | 388 | `noqueue` |
| E2 rep3 | 40,004 / 60,564,612 / 415 | 415 | `noqueue` |
| E3 | 24,911 / 37,713,810 / 953 | 953 | `noqueue` |
| E3 rep2 | 35,302 / 53,445,784 / 1,441 | 1,441 | `noqueue` |

The configured loss is recorded from the kernel readback (§7), never inferred from SentinelAI. The qdisc counter over W equals netem's lifetime drop count in every run. netem was installed only between the last B tick and the last W tick, and its start counters were 4–6 packets and 0–1 drops at installation.

## 15. eBPF observations

- Both loaders started in every run (`loader_start` null = available).
- `tcp.retrans_skb_rate` (EBPF, events/s, `netns:laba`): 0.0 / 38.50 / 38.80 / 41.50 / 100.00 / 152.30.
- `net.drop.kfree_skb` (EBPF, packets/s, `netns:laba`, `reason` qualifier):
  - `QDISC_DROP` 38.50 / 38.80 / 41.50 / 95.30 / 144.10 in the faulted runs, absent in E0;
  - `NOT_SPECIFIED` 0.1 in E0 and E3 rep2 (one event each), 0.0 elsewhere.
- No reason was invented for unseen reasons, and `NOT_SPECIFIED` was never treated as loss.

## 16. EvidenceSnapshot results

Every run produced a contract-valid snapshot:
- 458 measurements in E0 and 459 in the faulted runs (244/245 EBPF; the extra one is the `QDISC_DROP` kfree measurement);
- `gate_passed: true`, `privileged_sources_unavailable: []`;
- Pydantic round trip and deterministic rebuild both byte-identical;
- the snapshot was byte-identical after the M2 call (M2 does not mutate it).

The measurements relevant to loss were all quality OK, coverage 1.0, baseline medians 0 (§9–§12).

## 17. M2 results (unchanged engine; validation-only uncalibrated parameters)

Parameters: `DROP_ABS_MIN` 10, `DROP_FRAC_MIN` 0.001, `RT_FRAC_MIN` 0.01, `SEG_MIN` 100, `KFREE_REASONS_LOSS` = {QDISC_DROP, CPU_BACKLOG, NETFILTER_DROP}, floors 1e-3. The prediction was computed and saved before each M2 call.

| Run | Prediction | M2 decision | Contributing | Confidence / flags | Supporting `network_packet_loss` | Missing / contradicting | Matches ground truth |
|---|---|---|---|---|---|---|---|
| E0 | INSUFFICIENT_EVIDENCE | **INSUFFICIENT_EVIDENCE** (abstained: REQUIRED_EVIDENCE_MISSING) | – | LOW / IMPACT_NOT_MEASURED | (WEAK `DEV[net.drop.kfree_skb]` only, §24) | PL.R1 not met (all `LOSS.LOCAL` sources NEGATIVE); RT.R1 NEGATIVE | yes: no fault |
| E1 | network_packet_loss | **network_packet_loss** (ASSERTED, PL.R1) | – | MEDIUM / IMPACT_NOT_MEASURED | `PL.R1/LOSS.LOCAL[net.drop.qdisc]` 38.50, `PL.R1/LOSS.LOCAL[net.drop.kfree_skb]` 38.50, `DEV[tcp.retrans_frac]` | `tcp_retransmissions`: RT.R1 (0.009675 < 0.01) and RT.R2 FALSE (local loss proven) | yes: local qdisc loss |
| E2 rep2 | network_packet_loss | **network_packet_loss** | – | MEDIUM / IMPACT_NOT_MEASURED | qdisc 38.80, kfree 38.80, DEV retrans_frac | RT.R1 (0.0097), RT.R2 FALSE | yes |
| E2 rep3 | network_packet_loss | **network_packet_loss** | tcp_retransmissions (CONTRIBUTING, PR-1) | MEDIUM / IMPACT_NOT_MEASURED | qdisc 41.50, kfree 41.50, DEV retrans_frac | RT.R2 FALSE | yes |
| E3 | network_packet_loss | **network_packet_loss** | tcp_retransmissions | MEDIUM / IMPACT_NOT_MEASURED | qdisc 95.30, kfree 95.30, DEV retrans_frac | RT.R2 FALSE | yes |
| E3 rep2 | network_packet_loss | **network_packet_loss** | tcp_retransmissions | MEDIUM / IMPACT_NOT_MEASURED | qdisc 144.10, kfree 144.10, DEV retrans_frac, WEAK DEV kfree | RT.R2 FALSE | yes |

- M2 matched the prediction in **6/6** runs.
- With proven local (qdisc) loss, M2 never made `tcp_retransmissions` the decision. It was CONTRIBUTING when RT.R0 and RT.R1 held, which is the C-1/PR-1 behaviour.
- Confidence is capped at MEDIUM because application impact is not measured (no application metrics in the lab).
- **M2 is unchanged:** `src/sentinelai/diagnostic/` has no diff.

## 18. Discrepancies

1. **Failed attempt `20261003T100833Z`.**
   - **Cause:** the driver called `diagnose(..., code_commit="r2b")`, and M2's `EngineInfo` correctly rejected the non-hash commit (pydantic `code_commit must be a git hash`). Up to that call the E0 run had worked: snapshot valid, attribution 6/6, lab restored, host identical.
   - **Classification:** an R2-B tooling defect, not a FaultLab, kernel/eBPF, attribution, normalisation, snapshot or M2 problem.
   - **Fix (tooling only):** the wrapper passes the checkout's HEAD (`--commit "$HEAD"`), and the driver refuses non-hash values. Regression tests were added (§21).
2. **Configured 5 % vs observed 3.7–3.9 % segment-level drop fraction:** explained by netem counting segments while dropping skbs under TCP coalescing (§12). It is not a contradiction of ground truth.
3. **No unexplained discrepancy remains.**

## 19. Cleanup verification

| After every run | Result (6/6) |
|---|---|
| Fault removed | `fault_removed` rc 0 in every faulted run; no failure-path removal was needed |
| Lab qdisc restored | `qdisc_restored_clean: true` (single root `noqueue`) |
| Lab restored vs the clean lab before the run | `lab_restore_compare` ok (12 checks per run: links, addresses, IPv4/IPv6 routes, qdiscs, no netem, both sides) |
| Lab removed | `ip netns del` both namespaces, rc 0 (72 logged lab operations, all rc 0) |

**Final state:** `/run/netns` empty, host interfaces `lo`, `enp0s31f6`, `docker0`, no `sentlab-*` interface.

## 20. Host safety comparison

Baseline vs after each run, and baseline vs final, all `ok: true`:
- `enp0s31f6_identical`, `docker0_identical`, `interfaces_identical`;
- `addresses_identical`, `routes_identical` (IPv4 and IPv6);
- `qdiscs_identical`, `protected_qdiscs_identical` (`enp0s31f6` fq_codel, `docker0` noqueue, `lo` noqueue);
- namespaces as expected (none added or removed after cleanup), `sysctls_identical` (10 sysctls);
- BPF programs, links and maps identical (22 pre-existing programs);
- no lab interface in the host;
- **host mount table** (72 entries) identical after every run and at the end, so the read-only cgroup2 mount never reached the host.

No traffic left the lab: workload, probes and the receiver all used 10.199.0.0/24 inside the lab namespaces, which have no default route.

## 21. Tests

| Suite | Result |
|---|---|
| R2-B (`tests/faultlab/test_r2b.py`) | 23/23 |
| R2-A (`tests/faultlab/test_r2a_lab.py`) | 12/12 |
| M3B (`tests/ebpf`) | 114/114 |
| M3A (`tests/collectors`) | 111/111 |
| M3A-C1 (`test_tc.py`) | 38/38 |
| M2 (`tests/rules`) | 97/97 |
| M1 (`tests/evidence`) | 228/228 |
| **Full suite** | **609 run, 608 passed, 0 failed, 1 skipped** (pre-existing root-only bpftrace test) |

The R2-B tests cover:
- protected-interface rejection (including the independent check), Docker bridge rejection, lab-only interface and namespace validation;
- exact fault command construction and refusal of unapproved fault types and levels;
- execution only after validation and never through a shell;
- qdisc parsing determinism, clean-state recognition, netem readback (wrong level, extra impairment, missing loss);
- lab restoration (counter-only changes allowed, leftovers detected);
- attribution checks, M2 prediction, wrapper and driver static safety (lab-only mutations, `tc` only `show`, the single read-only cgroup mount inside the lab netns, the order validate → driver → restore check → destroy → host compare, failure-path fault removal, netns refusal);
- fault timing (applied once, right after the last baseline tick);
- the M2 call with a git hash (and refusal of a label);
- M2 leaving the snapshot unchanged;
- the candidate allowlist.

## 22. Mutation results

27 mutants of the safety-critical guards and scripts were run, each in a fresh scratch copy against the R2-A/R2-B tests. **27/27 killed**, both before and after the driver fix. Mutants covered:
- **Guard module:** widened loss levels, removed level, fault-type or protected-interface checks, removed allowlist, execution without validation or through a shell, fault on netns B, removal without explicit netns, any single qdisc treated as clean, netem level mismatch or extra impairment accepted, the B qdisc-drop leak check removed, unbounded tolerance, lab restoration ignoring qdiscs, the prediction ignoring `DROP_ABS_MIN`, candidate bypass.
- **Wrapper:** driver run in the host netns, cgroup mount read-write, restoration or host compare skipped, no stop on failure, an extra host route.
- **Driver:** failure-path removal dropped, fault one tick late, netns check removed, hand-built `tc` command.

In the first campaign the protected-interface check survived, because the exact allowlist already rejects such commands. It got its own test and is now killed.

## 23. Limitations

1. **Validation parameters are uncalibrated.** At 1 % loss the retransmission fraction sits on `RT_FRAC_MIN` = 0.01, so `tcp_retransmissions` CONTRIBUTING appeared in 1 of 3 repeats. That reflects the threshold, not a nondeterminism in the pipeline.
2. **Only netem egress loss on the lab veth was validated.** Ingress loss, loss elsewhere in the stack, and other fault types are not.
3. **5 % runs are TCP-dynamics dependent** (offered load fell to 2,493 and 3,532 segments/s). The per-skb loss rate is estimated from drops and the configured fraction, not measured directly.
4. **Application impact was not measured** (no application metrics), so confidence is MEDIUM at most.
5. **Two namespaces, one flow:** attribution was validated for this topology (target A sender, B receiver) and host background traffic, not for many concurrent namespaces.

## 24. Anomalies

1. **WEAK `NOT_SPECIFIED` support.** In E0 and E3 rep2, a single `NOT_SPECIFIED` free in netns A during W (0.1 packets/s, baseline 0) produced a WEAK supporting item `DEV[net.drop.kfree_skb]` for `network_packet_loss`, because the validation floor is 1e-3. M2 treated it exactly as the contract requires (WEAK support only, never proof). In E0 the decision stayed `INSUFFICIENT_EVIDENCE`. This is a calibration observation for later floor calibration, not a defect.
2. **Unattributed frees are constant** at 344 per 10 s (354 in E3 rep2) in both loaders across runs. They are independent of the lab and excluded as designed.
3. Nothing else.

## 25. Final gate

| Criterion | Status |
|---|---|
| Ground truth recorded from the kernel | yes: netem readback and counters |
| Observations match ground truth | yes: qdisc drops = eBPF `QDISC_DROP` (A) exactly in 5/5 faulted runs; skbs ≤ segments for retransmissions; zero everywhere at baseline |
| Telemetry responds to increasing loss | yes: 0 → 38.5–41.5 → 95.3–144.1 drops/s |
| Netns attribution correct | yes: B never credited; host and unattributed excluded |
| EvidenceSnapshot valid; M2 result matches ground truth and prediction | yes: 6/6 |
| Restoration and cleanup | yes: lab and host back to baseline after every run and at the end |
| Protected host state | unchanged (`enp0s31f6`, `docker0`, routes, addresses, qdiscs, sysctls, BPF, mounts) |
| M2 / contract / M3B unchanged | yes |
| Tests / mutation | 609 run, 0 failed; 27/27 killed |

```text
R2-B NETWORK FAULT VALIDATION GATE: GO
```

**Commit:** a single focused R2-B commit containing `scripts/r2b_fault.py`, `scripts/r2b_driver.py`, `scripts/r2b_validate.sh`, `tests/faultlab/test_r2b.py`, this report and `results/phase1c_r2b/` (both attempts). Its SHA is given in the gate response.

**STOP.** CPU contention or throttling, memory pressure, application bottlenecks, delay or reordering, mitigation, K1–K4 and M2 redesign require separate authorisation.
