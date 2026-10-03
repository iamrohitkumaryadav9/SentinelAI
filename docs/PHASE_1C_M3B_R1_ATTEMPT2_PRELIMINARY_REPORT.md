# Phase 1C — M3B R1 Attempt 2, PRELIMINARY run 20261003T075732Z (candidate f18e9fc, tooling uncommitted) — superseded as evidence by PHASE_1C_M3B_R1_RUNTIME_VALIDATION_REPORT.md (run 20261003T081232Z, committed tooling c2ac7e5)

| | |
|---|---|
| Commit under test | `f18e9fc1f44ad4966f731dcc45adc16b15f3d72a` (R1.1 verifier fix, parent `118ee6d`) |
| Run | `results/phase1c_m3b_r1/20261003T075732Z/` (2026-10-03 07:57:32 UTC), executed by the user: `sudo bash scripts/m3b_r1_validate.sh`; driver exit code 0 |
| Attempt 1 | `118ee6d`, run `20261003T072203Z`: NO-GO (`sn_sched_switch` rejected by the verifier). Record preserved in `docs/PHASE_1C_M3B_R1_ATTEMPT1_REPORT.md`; evidence unmodified |
| Gate | **M3B R1 RUNTIME GATE: GO** |

## 1. Executive summary

On the running 6.8.0-138 kernel, all seven M3B programs passed the verifier, loaded, and attached to their seven approved tracepoints. They produced real kernel observations that went through the loader, the process boundary, the collector and the M3A normalisation into contract-valid `EvidenceSnapshot`s, which M2 accepted.

Results:
- Across three consecutive 10 s windows, every eBPF value matched an independent recomputation from the raw loader lines exactly.
- eBPF softirq execution counts matched `/proc/softirqs` exactly: 0 of 8,902 NET_RX executions differed in windows 0–1, and 1 of 4,452 in window 2.
- Restart, kill-mid-window and clean exit all behaved as specified, and the kernel released every M3B object.
- Overhead under the baseline workload was not distinguishable from noise: host CPU change −0.0025 ± 0.0069 cores, loader CPU ≤ 0.00067 cores, and workload throughput unchanged.
- No protected interface, route, address, namespace or sysctl changed.

Limits (§18): retransmissions were zero in the clean baseline, so the tracepoint was attached but never observed firing. The netns and cgroup filters could not be exercised against a second namespace or a negative-control cgroup without operations R1 forbids.

## 2. Commit and environment

| Item | Value |
|---|---|
| Kernel | `Linux 6.8.0-138-generic #138~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC` x86_64, 24 possible CPUs |
| Loader | `ebpf/build/sentinel_loader`, sha256 `0c70a600…` (the R1.1 build, unchanged since the R1.1 gate). `--version`: libbpf compiled 1.4 = linked 1.4 |
| Object | `ebpf/build/sentinel.bpf.o`, sha256 `b0495486…` (R1.1 gate) |
| Host state (read-only) | lockdown `none`; `unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_stats_enabled=0`, `bpf_jit_enable=1`, `ip_forward=1` |
| Target | cgroup `/user.slice/user-1000.slice/session-136.scope` (kernfs id 2129446, level 3; the script's own session; 46 pids), host netns (inum 4026531840), no interfaces (so the M3A qdisc read, i.e. `tc`, never runs) |
| Contract / schema / rules | `0.5.0-draft` / `0.2.0` / `m2-1.1.0` |

## 3. Runtime authorisation boundary

Authorised: loading, attaching and inspection by interactive `sudo`.

The tooling (`scripts/m3b_r1_validate.{sh,py}`, `scripts/m3b_r1_compare.py`; uncommitted) refuses to run unless HEAD is `f18e9fc` with no tracked modifications and the loader reports libbpf 1.4.

Baseline activity was local and light: two threads waking every 1 ms, one `/bin/true` per second, and an 8 MB/s TCP stream on 127.0.0.1 (`lo`). Nothing was run against `enp0s31f6`/`docker0`. There was no tc, netem, namespace, veth, sysctl write, cgroup write, fault or contention.

## 4. Preflight results

| Check | Result |
|---|---|
| HEAD / status | `f18e9fc`; tracked tree clean; untracked: R1 tooling, R1 evidence, FaultLab |
| `git diff --check` | clean |
| Tests (working tree) | 567 run, 566 passed, 0 failed, 1 skipped (pre-existing) |
| Artifacts | Loader and object are the R1.1-gate builds (hashes above). The histogram write uses one register (`r2 = 527; if r2 > r1 …; r1 = 527; r1 <<= 3; r0 += r1`). |

## 5. BPF verifier result

```text
Verifier: PASS (all 7 programs)
```

The loader's stderr was **empty** (libbpf prints a verifier log only on failure). It printed its `meta` line only after `sentinel_bpf__load` and `sentinel_bpf__attach` succeeded, and it exited 0 on `q`.

All seven programs are present in the kernel as `tracing` programs, which requires verifier acceptance:

| Program (kernel name) | Prog id | Type | xlated bytes | JITed bytes |
|---|---|---|---|---|
| sn_sched_wakeup | 68330 | tracing | 1064 | 590 |
| sn_sched_wakeup_new | 68332 | tracing | 1152 | 640 |
| sn_sched_switch | 68333 | tracing | 1456 | 827 |
| sn_softirq_entry | 68334 | tracing | 376 | 219 |
| sn_softirq_exit | 68335 | tracing | 832 | 486 |
| sn_tcp_retransmit_skb | 68336 | tracing | 416 | 231 |
| sn_kfree_skb | 68337 | tracing | 920 | 523 |

This bpftool build does not report `verified_insns` (the field is absent), so no instruction counts are given.

## 6. Program attachment table

Attachment proof is twofold:
- bpftool `link show`;
- the loader's **own kernel file descriptors** (`/proc/<pid>/fdinfo`), where the kernel reports each link's type, program id and tracepoint name.

| Program | Load | Attach | Link (id, type, kernel `tp_name`) | Fired in 3 s of baseline activity |
|---|---|---|---|---|
| sched_wakeup | PASS | PASS | 2, raw_tracepoint, `sched_wakeup` | yes: 9,567 target wakeups recorded |
| sched_wakeup_new | PASS | PASS | 3, raw_tracepoint, `sched_wakeup_new` | yes: 41 new tasks recorded |
| sched_switch | PASS | PASS | 4, raw_tracepoint, `sched_switch` | yes: 9,607 latencies recorded, 41 migrated, 1 running-task wakeup cancelled |
| softirq_entry | PASS | PASS | 5, raw_tracepoint, `softirq_entry` | yes: 13,189 matched pairs |
| softirq_exit | PASS | PASS | 6, raw_tracepoint, `softirq_exit` | yes (same pairs) |
| tcp_retransmit_skb | PASS | PASS | 7, raw_tracepoint, `tcp_retransmit_skb` | no event (0 target, 0 other netns, 0 unattributed); clean baseline |
| kfree_skb | PASS | PASS | 8, raw_tracepoint, `kfree_skb` | yes: 111 target-netns, 172 unattributed |

Each link's program id matches the program table, and each tracepoint name is the approved one. The firing figures come from the loader's in-kernel self-observation counters, read twice 3 s apart.

## 7. Map / runtime status

| Map | Type | max_entries | memlock bytes |
|---|---|---|---|
| sn_wake | lru_hash | 16384 | 1,443,520 |
| sn_hist | percpu_array | 1 | 101,768 |
| sn_stats | percpu_array | 22 | 4,784 |
| sn_sirq_start | percpu_array | 1 | 776 |
| sn_sirq_acc | percpu_array | 10 | 4,304 |
| sn_retrans | percpu_array | 1 | 584 |
| sn_kfree | percpu_array | 129 | 26,184 |
| sentinel.rodata | array | 1 | 8,192 |
| **Total** | | | **1,590,112** (identical in all 5 overhead trials) |

The `.rodata` configuration reached the kernel: the loader's `meta` line echoes cgroup id 2129446, level 3, netns 4026531840, latency stale cut-off 10 s and softirq stale cut-off 1 s.

## 8. Scheduler validation (`sched.latency_hist.target`)

| Window | Samples in W | P50 (ms) | P99 (ms) | Quality | lat_negative / lat_stale | migrated |
|---|---|---|---|---|---|---|
| B0 | 32,899 | 0.000383 | 0.013823 | OK, coverage 1.0 | 0 / 0 | 17 |
| B1 | 31,666 | 0.000383 | 0.013823 | OK, 1.0 | 0 / 0 | 11 |
| B2 | 32,304 | 0.000383 | 0.013823 | OK, 1.0 | 0 / 0 | 12 |

- P50 and P99 are two measurements with distinct IDs in every snapshot, aggregations preserved. Each value equals the nearest-rank quantile recomputed independently from the raw cumulative histograms at the W boundaries.
- The values are the inclusive upper edges of buckets: 0.000383 ms = 383 ns (bucket 368–383 ns) and 0.013823 ms (bucket 13,312–13,823 ns).
- No negative or stale latency occurred, and no invalid histogram state was seen (counters monotonic across 63 samples).
- **Scope:**
  - target samples were 3,167–3,290 per second, i.e. 42.8–43.0 % of the host's context switches in the same windows (M3A `sched.ctxt.host`: 7,367–7,674/s);
  - the script's session cgroup carried most of the activity on an otherwise quiet host;
  - M3A's independent `sched.run_delay.target` for the same cgroup was 0.00016–0.00021 waiting-cores;
  - no negative control (a non-target cgroup) was run (§18).
- No value is interpreted as throttling or contention; the M2 decision on these snapshots was `INSUFFICIENT_EVIDENCE`.

## 9. Softirq validation (`softirq.exec_time.percpu`)

- Every snapshot has 240 softirq measurements (24 CPUs × 10 vectors), each with its own `cpu:N` scope and `vector` qualifier.
- **Entry/exit accounting against the kernel's own counter.** eBPF matched entry→exit pairs compared with `/proc/softirqs` over the same W interval:

| Window | NET_RX eBPF / proc | NET_TX | TIMER | RCU |
|---|---|---|---|---|
| B0 | 4,464 / 4,464 | 2 / 2 | 3,791 / 3,791 | 22,087 / 22,087 |
| B1 | 4,448 / 4,448 | 2 / 2 | 3,731 / 3,731 | 18,064 / 18,064 |
| B2 | 4,451 / 4,452 | 2 / 2 | 3,720 / 3,720 | 19,234 / 19,234 |

  The single difference (B2 NET_RX) is one execution straddling the moment the two counters were read.
- **Rates:** every per-CPU, per-vector value equals Σ(exit − entry) / Δt recomputed from the raw lines (0 mismatches).
  - NET_RX was concentrated on CPU 21: 0.00540 / 0.00497 / 0.00503 cores, i.e. about 0.5 % of a CPU in softirq for the loopback stream.
  - NET_TX is measured separately (e.g. CPU 16, 4.2×10⁻⁸ cores).
  - Non-network vectors (TIMER, RCU, …) are separate measurements and are never added to network time.
- No unmatched exit, mismatch, overwritten entry, invalid vector, negative or stale duration occurred in any window.

## 10. TCP retransmission validation (`tcp.retrans_skb_rate`)

- The program was attached (§6). In the clean baseline it recorded 0 target, 0 other-netns and 0 unattributed events. `/proc/net/snmp` RetransSegs in the same windows (M3A `tcp.retrans_rate`) was also 0.0 segments/s.
- In each window the measurement is `tcp.retrans_skb_rate`, `netns:r1`, unit `events_per_second`, aggregation RATE, value **0.0**, quality OK (an observed zero from an attached program). It is a measurement separate from `tcp.retrans_rate` (PROC, segments/s); no segment conversion exists.
- A non-zero runtime value was neither expected nor manufactured (R1 §19). Firing of this tracepoint at runtime remains unobserved (§18).

## 11. kfree_skb validation (`net.drop.kfree_skb`)

| Window | Reasons observed (packets/s) | Unattributed (no dev/sk netns) |
|---|---|---|
| B0 | NOT_SPECIFIED 34.20, QUEUE_PURGE 0.20 | 344 in W |
| B1 | NOT_SPECIFIED 35.50, QUEUE_PURGE 0.20 | 344 |
| B2 | NOT_SPECIFIED 32.70, QUEUE_PURGE 0.20, OTHERHOST 0.20, NO_SOCKET 0.10 | 344 |

- Kernel reasons are preserved as qualifiers, with names from the running kernel's BTF. A measurement exists only for reasons seen in the run: B2 has four, and B0/B1 have two. No zero-valued measurement was created for unseen reasons.
- Rates equal the recomputation from raw slot counts.
- `NOT_SPECIFIED` stays an observed kernel reason. With the validation parameter set (`KFREE_REASONS_LOSS = {QDISC_DROP}`, uncalibrated), M2 decided `INSUFFICIENT_EVIDENCE`, so no packet-loss claim followed.
- Scope is the target netns, which here is the host netns. Unattributable skbs are counted separately and never reported as target evidence.

## 12. End-to-end EvidenceSnapshot validation

The path was exercised end to end: kernel tracepoint → per-CPU map → libbpf loader → `ProcessEbpfSource` (one request per tick) → strict protocol parser → M3A normalisation → `EvidenceSnapshot` → M2 `diagnose`.

| Check (every window B0–B2 and C) | Result |
|---|---|
| eBPF measurements per snapshot | 245 / 245 / 247 / 247 (453 total measurements in B0, M3A included) |
| Data-quality problems (feature, source EBPF, unit, scope, qualifier, aggregation, collector version `m3b-1.0.0`, privileged, deterministic id, finite and non-negative, window, provenance) | 0 |
| Duplicate measurement ids | 0 |
| Canonical round trip through the Pydantic models | byte-identical |
| Deterministic rebuild from the same ticks | byte-identical |
| Independent recomputation from raw lines | 0 mismatches |
| `privileged_sources_unavailable` | `[]` (EBPF available) |
| M2 | accepted every snapshot (decision `INSUFFICIENT_EVIDENCE`, validation-only uncalibrated parameters) |
| Collection latency | eBPF request median 0.50 ms, max 0.90 ms (63 requests); slowest whole tick read, M3A included, 0.024 s |

## 13. Repeated-window validation

- **Three consecutive windows on one loader** (63 samples): sequence numbers strictly increasing; every cumulative counter monotonic. Each window's values come from its own W-boundary deltas, and the values are stable across windows (latency quantiles identical; NET_RX CPU 21 0.0054/0.0050/0.0050 cores; kfree NOT_SPECIFIED 34.2/35.5/32.7/s). No double counting or leakage: recomputation matches each window exactly.
- **Restart (phase C):** a new loader's first sample is seq 1 with 95 latency samples and 289 total stat events, i.e. counters start from zero in the new maps. Its snapshot is valid (247 measurements, 0 problems, 0 mismatches). A snapshot never mixes streams, because one source serves one collection.
- **Kill mid-window (phase D):** at 15 s the loader received `SIGKILL` (exit −9). Later samples became Bad observations. The eBPF measurements are **MISSING** (coverage 0.4 < `COV_MIN` 0.8; no value fabricated), and `privileged_sources_unavailable = ["EBPF"]`. The snapshot is still contract-valid (0 problems).

## 14. Cleanup validation

```text
BPF cleanup: PASS
```

| Moment | M3B links / programs / maps in the kernel |
|---|---|
| During load (phase A) | 7 / 7 / 8 |
| Immediately after a clean exit (0 s; phases B, C, E) | **0** / 7 / 8 |
| 1 s after a clean exit (phase A) | 0 / 0 / 0 |
| 1 s after `SIGKILL` (phase D) | 0 / 0 / 0 |
| Final, after all phases (wrapper) | 0 / 0 / 0 (`sn_programs_left: []`) |

Links are detached at process exit. Program and map memory is released by the kernel asynchronously, within 1 s. Host-wide BPF program, link and map ids are identical before and after the run (22 pre-existing programs unchanged). Nothing was pinned, and no instrumentation remains.

## 15. Overhead measurements

Five alternating 15 s trials of baseline vs enabled. Enabled means attached, plus one sample per second. Same workload in both modes.

| Trial | Host busy cores, baseline | Host busy cores, enabled | Δ | Loader CPU (s / 15 s) | Loader RSS / HWM (kB) | Sample median (ms) |
|---|---|---|---|---|---|---|
| 0 | 0.0513 | 0.0520 | +0.0006 | 0.01 | 2,840 / 14,868 | 0.60 |
| 1 | 0.0500 | 0.0433 | −0.0067 | 0.01 | 2,880 / 14,660 | 0.54 |
| 2 | 0.0433 | 0.0460 | +0.0027 | 0.01 | 2,872 / 14,852 | 0.58 |
| 3 | 0.0480 | 0.0353 | −0.0127 | 0.00 | 2,884 / 14,784 | 0.53 |
| 4 | 0.0446 | 0.0480 | +0.0033 | 0.00 | 2,804 / 14,608 | 0.83 |

- **Host CPU:** baseline 0.0475 ± 0.0031 cores, enabled 0.0449 ± 0.0056. Paired difference mean −0.0025 cores (sd 0.0069, n = 5); the one-sided 95 % upper bound of the mean difference is +0.0041 cores.
- **Conclusion: no increase is detectable.** Measurement noise (≈ ±0.007 cores) is larger than any effect. Within that precision, overhead under this workload is below 0.006 cores (< 1 % of one core), against the < 5 % target. This is **not** a measurement of overhead at high event rates.
- **Loader process:** ≤ 0.01 s CPU per 15 s (≤ 0.00067 cores; resolution is one 10 ms clock tick). RSS 2.8 MB steady. The 14.6–14.9 MB high-water mark comes from parsing kernel BTF at load.
- **BPF maps:** 1.59 MB memlock.
- **Workload throughput unchanged:** wakeups 1,896–1,899/s baseline vs 1,896–1,900/s enabled; TCP 8.07–8.12 vs 8.09–8.11 MB/s.
- **In-kernel run time** per program was **not measured**: it needs `kernel.bpf_stats_enabled=1`, a sysctl change R1 forbids. Its cost is contained in the host busy figure above. Event rates during measurement were about 3.2k target latency samples/s, about 4.4k softirq pairs/s (NET_RX) plus TIMER/RCU, and about 35 target kfree events/s.

## 16. Failures and anomalies

1. **Attempt 1 (superseded):** verifier rejection of `sn_sched_switch` in `118ee6d`. It was fixed by R1.1 (`f18e9fc`) and is not reproduced here. Record: `docs/PHASE_1C_M3B_R1_ATTEMPT1_REPORT.md`, evidence `20261003T072203Z/`.
2. **Deferred kernel release:** programs and maps are still listed for a moment after the loader exits (links are already gone), and are freed within 1 s (§14). This is expected kernel behaviour, not a leak.
3. **No new anomaly.** The comparison-tool fix (R1.1) worked: `docker0` compares identical, with the four bridge timers ignored as documented.

## 17. Safety confirmation

From `host_compare.txt` (before vs after, read-only):

| Check | Result |
|---|---|
| `interfaces_identical`, `enp0s31f6_identical`, `docker0_identical` | true; `interfaces_differing: []` |
| Addresses, IPv4/IPv6 routes, `/run/netns` | identical |
| Sysctls | identical |
| BPF progs / links / maps | identical; no `sn_` program left |

- No tc, netem, namespace, veth, qdisc, cgroup or sysctl change. No fault injection or deliberate contention. No traffic on `enp0s31f6`/`docker0`.
- No FaultLab action or file change (`experiments/faultlab/` hashes unchanged).
- M2 (`src/sentinelai/diagnostic/`) and the contract are unchanged. No M3B source was modified in R1.

## 18. Known limitations

1. **Retransmission tracepoint firing is unobserved:** attached, but zero events occurred in the clean baseline. The collection path is validated through its zero semantics. Non-zero evidence belongs to the isolated FaultLab phase.
2. **Netns filter not exercised against another namespace:** target netns = host netns and no other namespace carried traffic, so the other-netns branches stayed at 0. Testing them needs a namespace, which R1 forbids.
3. **No cgroup negative control:** target selection is evidenced by the 43 % share of host switches and by the fixture-tested filter logic, but no run targeted an idle or other cgroup.
4. **In-kernel BPF run time not measured** (`bpf_stats_enabled` left at 0). Overhead was measured at one light workload only; high-rate behaviour is unmeasured.
5. **Validation parameters are uncalibrated** (used only to run collection and confirm M2 accepts the snapshots); the M2 decisions carry no diagnostic meaning.
6. **`verified_insns` is unavailable** from this bpftool, so verifier acceptance is proven by successful load, not by instruction counts.

## 19. Evidence artifacts and commands

| Artifact (`results/phase1c_m3b_r1/20261003T075732Z/`) | Content |
|---|---|
| `r1.json` | All phases: load/attach (meta line, stderr, return code, bpftool state, fdinfo attach targets, firing counters), windows (checks, cross-checks, measurements), restart, kill, overhead trials |
| `snapshot_B0.json`, `snapshot_B1.json`, `snapshot_B2.json`, `snapshot_C.json` | Canonical runtime EvidenceSnapshots |
| `raw_B.jsonl` | The 64 raw loader lines of phase B (meta + 63 samples) |
| `environment.txt` | Commit, kernel, loader version, artifact hashes |
| `host_before/`, `host_after/`, `host_compare.txt` | Read-only host state and comparison |
| `driver.log` | Phase progress |

Command (user, interactive): `sudo bash scripts/m3b_r1_validate.sh`.

Analysis commands: reading `r1.json` and the snapshots with Python, plus a read-only `/proc/schedstat` probe. The probe was unusable: scheduler statistics are disabled, so `ttwu_count` stays 0. The M3A `sched.ctxt.host` measurement from the same snapshots was used instead.

## 20. Gate decision

| Criterion | Status |
|---|---|
| Verifier acceptance proven | yes: 7/7 loaded, empty libbpf log |
| Approved programs attach | yes: 7/7 links on the 7 approved tracepoints, from the loader's kernel fds |
| Runtime observation occurs | yes: 6/7 programs fired under baseline activity; retransmission had no event |
| Four feature paths validated (as far as safe baseline allows) | yes: latency, softirq, kfree non-zero; retransmission via observed zero |
| Observations reach the contract layer | yes: 4 runtime snapshots, 0 problems, M2 accepted |
| No contract violations | none found |
| Repeated collection correct | yes: 3 windows exact; restart; kill fails closed |
| Cleanup succeeds | yes: all M3B objects released within 1 s; host BPF state identical |
| Overhead measured | yes: no detectable increase (Δ −0.0025 ± 0.0069 cores; loader ≤ 0.00067 cores) |
| No protected interface or network mutation | yes: all comparisons identical |
| M2 unchanged | yes |

```text
M3B R1 RUNTIME GATE: GO
```

**STOP.** FaultLab, namespaces, veth, tc/netem, fault injection, K1–K4 and mitigation work wait for explicit authorisation.
